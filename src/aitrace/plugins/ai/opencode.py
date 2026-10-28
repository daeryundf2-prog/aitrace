from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_unix_ms
from aitrace.fs.base import EntryRef, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase
from aitrace.plugins.common.sqlite import has_table, open_sqlite, table_columns

TOOL = "OpenCode"

_BASE = ".local/share/opencode"
_HOME_GLOBS: tuple[tuple[str, str], ...] = (
    ("db", f"{_BASE}/opencode.db"),
    ("legacy", f"{_BASE}/storage/session/**/*.json"),
    ("config", ".config/opencode/opencode.json"),
    ("config", ".config/opencode/opencode.jsonc"),
    ("auth", f"{_BASE}/auth.json"),
)
_ROLE_ACTORS: dict[str, Actor] = {
    "user": Actor.HUMAN,
    "assistant": Actor.AI,
    "system": Actor.SYSTEM,
    "tool": Actor.SYSTEM,
}
_FILE_TOOLS = frozenset({"write", "edit", "patch", "multiedit", "apply_patch"})
_FETCH = 500

_Part = tuple[str, Any, dict[str, Any], EntryRef | None]


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _ms(value: Any) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return from_unix_ms(value)


def _basis(ts: datetime | None) -> str:
    return "unknown" if ts is None else "native_utc"


def _summary(text: str) -> str:
    stripped = text.strip()
    return stripped.splitlines()[0][:120] if stripped else ""


def _iso(ts: datetime) -> str:
    return ts.isoformat().replace("+00:00", "Z")


def _os_of(cand: Candidate) -> OsFamily:
    return cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN


def _json_object(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if not isinstance(raw, str):
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _jsonc(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(ch)
        i += 1
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))


class Plugin(PluginBase):
    name = "opencode"
    version = "1.0"
    description = "OpenCode sessions (SQLite and legacy JSON storage), config and credential presence"

    def locate(self, fs: Any) -> Iterator[Candidate]:
        for user in fs.users():
            for role, pattern in _HOME_GLOBS:
                for ref in user_glob(fs, user, pattern):
                    yield Candidate(ref=ref, role=role, user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        match cand.role:
            case "db":
                yield from self._database(ctx, cand)
            case "legacy":
                yield from self._legacy(ctx, cand)
            case "config":
                yield from self._config(ctx, cand)
            case "auth":
                yield from self._auth(ctx, cand)
            case _:
                raise ValueError(f"unknown opencode candidate role {cand.role!r}")

    def _presence(
        self,
        ctx: ParseContext,
        cand: Candidate,
        kind: str,
        status: str,
        detail: str,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
    ) -> Artifact:
        data: dict[str, Any] = {"tool": TOOL, "kind": kind, "status": status, "detail": detail}
        if first_seen is not None:
            data["first_seen"] = _iso(first_seen)
        if last_seen is not None:
            data["last_seen"] = _iso(last_seen)
        return self.artifact(ctx, cand, ArtifactKind.AI_APP_PRESENCE, data, locator="presence")

    def _message(
        self,
        ctx: ParseContext,
        cand: Candidate,
        session: dict[str, Any],
        msg_id: str,
        msg_ms: Any,
        msg: dict[str, Any],
        parts: list[_Part],
        ref: EntryRef | None,
        os_family: OsFamily,
    ) -> Iterator[Artifact | Event]:
        ts = _ms(msg_ms)
        raw_role = msg.get("role")
        role: str = raw_role if isinstance(raw_role, str) else "unknown"
        texts = [
            p[2]["text"] for p in parts if p[2].get("type") == "text" and isinstance(p[2].get("text"), str)
        ]
        text = "\n".join(texts)
        session_id = _str_or_none(session.get("id"))
        if text:
            data: dict[str, Any] = {
                "tool": TOOL,
                "session_id": session_id,
                "role": role,
                "text": text,
                "fragment": False,
                "recovered_from": "sqlite" if ref is None else "json",
            }
            title = _str_or_none(session.get("title"))
            if title is not None:
                data["title"] = title
            directory = _str_or_none(session.get("directory"))
            if directory is not None:
                data["workspace"] = normalize(directory, os_family)
            model = self._model(msg, session)
            if model is not None:
                data["model"] = model
            if session.get("parent_id"):
                data["extra"] = {"subagent": True, "parent_id": session["parent_id"]}
            artifact = self.artifact(
                ctx, cand, ArtifactKind.AI_CHAT_MESSAGE, data, locator=f"message:{msg_id}", ref=ref
            )
            yield artifact
            yield self.event(
                artifact,
                ts,
                "message",
                EventCategory.AI_ACTIVITY,
                _ROLE_ACTORS.get(role, Actor.UNKNOWN),
                _summary(text),
                ts_basis=_basis(ts),
            )
        for pid, part_ms, part, part_ref in parts:
            yield from self._part(ctx, cand, session_id, pid, part_ms, part, part_ref or ref, ts, os_family)

    @staticmethod
    def _model(msg: dict[str, Any], session: dict[str, Any]) -> str | None:
        direct = _str_or_none(msg.get("modelID"))
        if direct is not None:
            return direct
        nested = msg.get("model")
        if isinstance(nested, dict) and _str_or_none(nested.get("modelID")) is not None:
            return str(nested["modelID"])
        fallback = session.get("model")
        if isinstance(fallback, dict):
            return _str_or_none(fallback.get("id")) or _str_or_none(fallback.get("modelID"))
        return _str_or_none(fallback)

    def _part(
        self,
        ctx: ParseContext,
        cand: Candidate,
        session_id: str | None,
        pid: str,
        part_ms: Any,
        part: dict[str, Any],
        ref: EntryRef | None,
        msg_ts: datetime | None,
        os_family: OsFamily,
    ) -> Iterator[Artifact | Event]:
        kind = part.get("type")
        ts = _ms(part_ms) or msg_ts
        if kind == "tool":
            raw_state = part.get("state")
            state: dict[str, Any] = raw_state if isinstance(raw_state, dict) else {}
            raw_time = state.get("time")
            started = raw_time.get("start") if isinstance(raw_time, dict) else None
            call_name = part.get("tool")
            arguments = state.get("input")
            if not isinstance(call_name, str):
                return
            data: dict[str, Any] = {
                "tool": TOOL,
                "session_id": session_id,
                "call_name": call_name,
                "input": arguments if isinstance(arguments, dict) else {},
            }
            args = data["input"]
            if call_name.lower() in _FILE_TOOLS:
                raw_path = _str_or_none(args.get("filePath")) or _str_or_none(args.get("path"))
                if raw_path is not None:
                    data["file_path"] = normalize(raw_path, os_family)
                    if data["file_path"] != raw_path:
                        data["raw_path"] = raw_path
            content = args.get("content")
            if not isinstance(content, str):
                content = args.get("newString") if call_name.lower() in _FILE_TOOLS else None
            if isinstance(content, str):
                data["content"] = content
            command = args.get("command")
            if isinstance(command, str):
                data["command"] = command
            yield from self._call(ctx, cand, f"part:{pid}", data, _ms(started) or ts, ref)
        elif kind == "file":
            filename = _str_or_none(part.get("filename")) or _str_or_none(part.get("url")) or ""
            data = {
                "tool": TOOL,
                "session_id": session_id,
                "call_name": "attach_file",
                "input": {k: part[k] for k in ("filename", "url", "mime") if isinstance(part.get(k), str)},
            }
            url = _str_or_none(part.get("url"))
            if url is not None and url.startswith("file://"):
                data["file_path"] = normalize(url[len("file://") :], os_family)
            elif filename and "/" in filename:
                data["file_path"] = normalize(filename, os_family)
            yield from self._call(ctx, cand, f"part:{pid}", data, ts, ref)
        elif kind == "patch":
            files = part.get("files")
            for index, raw_path in enumerate(files if isinstance(files, list) else []):
                if not isinstance(raw_path, str):
                    continue
                data = {
                    "tool": TOOL,
                    "session_id": session_id,
                    "call_name": "patch",
                    "input": {"files": files, "hash": part.get("hash")},
                    "file_path": normalize(raw_path, os_family),
                }
                if data["file_path"] != raw_path:
                    data["raw_path"] = raw_path
                yield from self._call(ctx, cand, f"part:{pid}:file:{index}", data, ts, ref)

    def _call(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        data: dict[str, Any],
        ts: datetime | None,
        ref: EntryRef | None,
    ) -> Iterator[Artifact | Event]:
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_TOOL_CALL, data, locator=locator, ref=ref)
        yield artifact
        target = data.get("file_path")
        yield self.event(
            artifact,
            ts,
            "tool_call",
            EventCategory.AI_ACTIVITY,
            Actor.AI,
            f"{TOOL} tool call: {data['call_name']}",
            ts_basis=_basis(ts),
            subject=target if isinstance(target, str) else None,
        )

    def _database(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            with open_sqlite(ctx.fs, cand.ref) as conn:
                yield from self._stream(ctx, cand, conn)
        except (sqlite3.Error, OSError) as exc:
            yield self.warning(ctx, cand, f"schema_mismatch: not decoded: {type(exc).__name__}: {exc}")
            yield self._presence(ctx, cand, "store", "present", f"{cand.ref.path} present but not decoded")

    def _stream(self, ctx: ParseContext, cand: Candidate, conn: sqlite3.Connection) -> Iterator[Artifact | Event]:
        required = {
            "session": {"id"},
            "message": {"id", "session_id", "time_created", "data"},
            "part": {"id", "message_id", "time_created", "data"},
        }
        for table, columns in required.items():
            missing = columns - table_columns(conn, table) if has_table(conn, table) else columns
            if missing:
                yield self.warning(
                    ctx, cand, f"schema_mismatch: not decoded: table {table} lacks {', '.join(sorted(missing))}"
                )
                yield self._presence(ctx, cand, "store", "unsupported", f"{cand.ref.path}: unexpected schema")
                return
        os_family = _os_of(cand)
        session_cols = table_columns(conn, "session")
        wanted = [c for c in ("id", "directory", "title", "parent_id", "model") if c in session_cols]
        sessions: dict[str, dict[str, Any]] = {}
        for row in conn.execute(f"SELECT {', '.join(wanted)} FROM session"):
            record = dict(zip(wanted, row, strict=True))
            model = _json_object(record.get("model"))
            if model is not None:
                record["model"] = model
            sessions[str(record["id"])] = record
        parts_cursor = conn.cursor()
        bad = 0
        count = 0
        stamps: list[datetime] = []
        cursor = conn.execute("SELECT id, session_id, time_created, data FROM message ORDER BY time_created, id")
        while rows := cursor.fetchmany(_FETCH):
            for msg_id, session_id, created, raw in rows:
                msg = _json_object(raw)
                if msg is None:
                    bad += 1
                    continue
                parts: list[_Part] = []
                for pid, part_ms, part_raw in parts_cursor.execute(
                    "SELECT id, time_created, data FROM part WHERE message_id = ? ORDER BY id", (msg_id,)
                ):
                    part = _json_object(part_raw)
                    if part is None:
                        bad += 1
                        continue
                    parts.append((str(pid), part_ms, part, None))
                session = sessions.get(str(session_id), {"id": session_id})
                ts = _ms(created)
                if ts is not None:
                    stamps.append(ts)
                count += 1
                yield from self._message(ctx, cand, session, str(msg_id), created, msg, parts, None, os_family)
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{count} message(s) in {len(sessions)} session(s) in {cand.ref.path}",
            min(stamps) if stamps else None,
            max(stamps) if stamps else None,
        )

    def _read_json(self, ctx: ParseContext, ref: EntryRef) -> dict[str, Any] | None:
        return _json_object(ctx.fs.read_bytes(ref))

    def _legacy(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        session = self._read_json(ctx, cand.ref)
        if session is None or not isinstance(session.get("id"), str):
            yield self.warning(ctx, cand, "schema_mismatch: not decoded: legacy session file is not a session object")
            return
        record: dict[str, Any] = {
            "id": session["id"],
            "directory": session.get("directory"),
            "title": session.get("title"),
            "parent_id": session.get("parentID"),
        }
        root, _, _ = cand.ref.path.partition("/storage/session/")
        volume = cand.ref.volume
        os_family = _os_of(cand)
        message_dir = EntryRef(volume, f"{root}/storage/message/{session['id']}")
        bad = 0
        count = 0
        stamps: list[datetime] = []
        messages: list[tuple[Any, str, dict[str, Any], EntryRef]] = []
        if ctx.fs.exists(message_dir) and ctx.fs.is_dir(message_dir):
            for ref in ctx.fs.listdir(message_dir):
                if not ref.path.endswith(".json"):
                    continue
                msg = self._read_json(ctx, ref)
                if msg is None or not isinstance(msg.get("id"), str):
                    bad += 1
                    continue
                created = msg.get("time", {}).get("created") if isinstance(msg.get("time"), dict) else None
                messages.append((created if isinstance(created, int | float) else 0, msg["id"], msg, ref))
        messages.sort(key=lambda m: (m[0], m[1]))
        for created, msg_id, msg, ref in messages:
            parts: list[_Part] = []
            part_dir = EntryRef(volume, f"{root}/storage/part/{msg_id}")
            if ctx.fs.exists(part_dir) and ctx.fs.is_dir(part_dir):
                for part_ref in ctx.fs.listdir(part_dir):
                    if not part_ref.path.endswith(".json"):
                        continue
                    part = self._read_json(ctx, part_ref)
                    if part is None:
                        bad += 1
                        continue
                    parts.append((str(part.get("id", part_ref.path)), None, part, part_ref))
            ts = _ms(created)
            if ts is not None:
                stamps.append(ts)
            count += 1
            yield from self._message(ctx, cand, record, msg_id, created, msg, parts, ref, os_family)
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{count} message(s) in legacy session {session['id']}",
            min(stamps) if stamps else None,
            max(stamps) if stamps else None,
        )

    def _config(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        try:
            doc = _jsonc(text)
        except json.JSONDecodeError as exc:
            yield self.warning(ctx, cand, f"invalid JSON: {exc.msg} (line {exc.lineno})")
            yield self._presence(ctx, cand, "config", "present", f"{cand.ref.path} present but not parsed")
            return
        if not isinstance(doc, dict):
            yield self.warning(ctx, cand, "unexpected JSON shape: expected an object")
            yield self._presence(ctx, cand, "config", "present", f"{cand.ref.path} present but not parsed")
            return
        detail = f"{cand.ref.path}: {len(doc)} top-level key(s)"
        model = _str_or_none(doc.get("model"))
        if model is not None:
            detail += f", model {model}"
        small = _str_or_none(doc.get("small_model"))
        if small is not None:
            detail += f", small_model {small}"
        providers = doc.get("provider")
        if isinstance(providers, dict) and providers:
            detail += ", providers " + ", ".join(sorted(str(k) for k in providers))
        yield self._presence(ctx, cand, "config", "parsed", detail)

    def _auth(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            yield self.warning(ctx, cand, f"invalid JSON: {exc.msg} (line {exc.lineno})")
            return
        if not isinstance(doc, dict):
            yield self.warning(ctx, cand, "unexpected JSON shape: expected an object")
            return
        for provider in sorted(str(k) for k in doc):
            data = {"tool": TOOL, "provider": provider, "redacted": "present (value not read)"}
            yield self.artifact(ctx, cand, ArtifactKind.AI_CREDENTIAL, data, locator=f"provider:{provider}")


PLUGIN = Plugin()
