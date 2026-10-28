from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from aitrace.core.catalog import SECRET_PATTERNS, redact
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_iso, from_unix, from_unix_ms
from aitrace.fs.base import user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

TOOL = "Hermes Agent"

# Hermes home is ~/.hermes (macOS/Linux) or %LOCALAPPDATA%/hermes (Windows); named profiles live in
# <home>/profiles/<name>/ with their own state.db, config and memory files.
_ROOTS: tuple[str, ...] = (
    ".hermes",
    ".hermes/profiles/*",
    "AppData/Local/hermes",
    "AppData/Local/hermes/profiles/*",
)
_ROLE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("state_db", "state.db"),
    ("legacy", "sessions/**/*.jsonl"),
    ("memory", "MEMORY.md"),
    ("memory", "USER.md"),
    ("memory", "memories/MEMORY.md"),
    ("memory", "memories/USER.md"),
    ("config", "config.yaml"),
    ("env", ".env"),
)

# Column-name heuristics (first hit wins). The documented schema (hermes_state_common.SCHEMA_SQL) is
# sessions(id, source, user_id, model, started_at REAL, title, ...) and
# messages(id, session_id, role, content, tool_calls, tool_name, timestamp REAL, ...).
_SESSION_COLUMNS: dict[str, tuple[str, ...]] = {
    "id": ("id", "session_id", "uuid"),
    "source": ("source", "platform"),
    "title": ("title", "name"),
    "model": ("model", "model_name"),
    "started": ("started_at", "created_at", "start_time", "created", "started"),
    "user_id": ("user_id",),
    "parent": ("parent_session_id",),
    "workspace": ("cwd", "workspace"),
}
_MESSAGE_COLUMNS: dict[str, tuple[str, ...]] = {
    "session": ("session_id", "session", "conversation_id", "chat_id"),
    "role": ("role", "author", "sender"),
    "content": ("content", "text", "body", "message"),
    "tool_calls": ("tool_calls", "tool_call", "function_calls"),
    "tool_name": ("tool_name",),
    "timestamp": ("timestamp", "created_at", "ts", "time", "created"),
    "active": ("active",),
}

_ROLES: dict[str, str] = {
    "user": "user",
    "human": "user",
    "assistant": "assistant",
    "model": "assistant",
    "system": "system",
    "developer": "system",
    "tool": "tool",
    "function": "tool",
}
_ACTORS: dict[str, Actor] = {
    "user": Actor.HUMAN,
    "assistant": Actor.AI,
    "system": Actor.SYSTEM,
    "tool": Actor.SYSTEM,
}
_WRITE_HINTS = ("write", "patch", "edit", "create", "append")
_PATH_KEYS = ("file_path", "path", "filepath", "target_file", "file")
_CONTENT_KEYS = ("content", "new_string", "text", "file_text")
_TEXT_PART_TYPES = frozenset({"input_text", "output_text", "text"})


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _os_of(cand: Candidate) -> OsFamily:
    return cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN


def _basis(ts: datetime | None) -> str:
    return "unknown" if ts is None else "native_utc"


def _summary(text: str) -> str:
    stripped = text.strip()
    return stripped.splitlines()[0][:120] if stripped else ""


def _iso(ts: datetime) -> str:
    return ts.isoformat().replace("+00:00", "Z")


def _ts(value: Any) -> datetime | None:
    """Epoch seconds (documented), epoch milliseconds, or an ISO-8601 string with offset."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return from_unix_ms(value) if value > 1e11 else from_unix(value)
    if isinstance(value, str):
        parsed = from_iso(value)
        if parsed is not None:
            return parsed
        try:
            return _ts(float(value))
        except ValueError:
            return None
    return None


def _pick(columns: list[str], names: tuple[str, ...]) -> str | None:
    lowered = {c.lower(): c for c in columns}
    for name in names:
        if name in lowered:
            return lowered[name]
    return None


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            item["text"]
            for item in content
            if isinstance(item, dict) and item.get("type") in _TEXT_PART_TYPES and isinstance(item.get("text"), str)
        )
    return ""


def _json_value(raw: Any) -> Any:
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _secrets(line: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for provider, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(line):
            if provider == "DeepSeek":
                secret = match.group(0).split("=", 1)[1]
            elif provider == "generic":
                secret = match.group(2)
                provider = match.group(1).title()
            else:
                secret = match.group(0)
            secret = secret.strip().strip("'\",;")
            if len(secret) >= 8 and not any(secret in known or known in secret for _, known in found):
                found.append((provider, secret))
    return found


class Plugin(PluginBase):
    name = "hermes"
    version = "1.0"
    description = "Hermes Agent (Nous Research) state.db sessions, legacy JSONL, memory files, config and .env"

    def locate(self, fs: Any) -> Iterator[Candidate]:
        for user in fs.users():
            seen: set[str] = set()
            for root in _ROOTS:
                for role, rel in _ROLE_PATTERNS:
                    for ref in user_glob(fs, user, f"{root}/{rel}"):
                        if ref.path in seen:
                            continue
                        seen.add(ref.path)
                        yield Candidate(ref=ref, role=role, user=user, extra={"profile": _profile_of(ref.path)})

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        match cand.role:
            case "state_db":
                yield from self._state_db(ctx, cand)
            case "legacy":
                yield from self._legacy(ctx, cand)
            case "memory":
                yield from self._memory(ctx, cand)
            case "config" | "env":
                yield from self._config(ctx, cand)
            case _:
                raise ValueError(f"unknown hermes candidate role {cand.role!r}")

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
        locator: str,
        row: dict[str, Any],
        ts: datetime | None,
    ) -> Iterator[Artifact | Event]:
        role = _ROLES.get(str(row["role"]).lower(), "unknown")
        text = _content_text(row["content"])
        extra = dict(row["extra"])
        profile = cand.extra.get("profile")
        if profile is not None:
            extra["profile"] = profile
        if text or not row["tool_calls"]:
            data: dict[str, Any] = {
                "tool": TOOL,
                "session_id": row["session_id"],
                "role": role,
                "text": text,
                "fragment": False,
                "recovered_from": row["recovered_from"],
            }
            for key in ("model", "title", "workspace"):
                if row.get(key) is not None:
                    data[key] = row[key]
            if extra:
                data["extra"] = extra
            artifact = self.artifact(ctx, cand, ArtifactKind.AI_CHAT_MESSAGE, data, locator=locator)
            yield artifact
            yield self.event(
                artifact,
                ts,
                "message",
                EventCategory.AI_ACTIVITY,
                _ACTORS.get(role, Actor.UNKNOWN),
                _summary(text),
                ts_basis=_basis(ts),
            )
        calls = row["tool_calls"]
        if isinstance(calls, list):
            for index, call in enumerate(calls):
                yield from self._tool_call(ctx, cand, f"{locator}:tool:{index}", row["session_id"], call, ts)

    def _tool_call(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        session_id: str | None,
        call: Any,
        ts: datetime | None,
    ) -> Iterator[Artifact | Event]:
        if not isinstance(call, dict):
            return
        nested = call.get("function")
        function: dict[str, Any] = nested if isinstance(nested, dict) else call
        call_name = _str_or_none(function.get("name"))
        arguments = _json_value(function.get("arguments", function.get("input")))
        if call_name is None:
            return
        if not isinstance(arguments, dict):
            arguments = {} if arguments is None else {"value": arguments}
        data: dict[str, Any] = {"tool": TOOL, "session_id": session_id, "call_name": call_name, "input": arguments}
        if any(hint in call_name.lower() for hint in _WRITE_HINTS):
            raw_path = next((arguments[k] for k in _PATH_KEYS if isinstance(arguments.get(k), str)), None)
            if raw_path is not None:
                data["file_path"] = normalize(raw_path, _os_of(cand))
                if data["file_path"] != raw_path:
                    data["raw_path"] = raw_path
                content = next((arguments[k] for k in _CONTENT_KEYS if isinstance(arguments.get(k), str)), None)
                if content is not None:
                    data["content"] = content
        command = arguments.get("command")
        if isinstance(command, str):
            data["command"] = command
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_TOOL_CALL, data, locator=locator)
        yield artifact
        target = data.get("file_path")
        yield self.event(
            artifact,
            ts,
            "tool_call",
            EventCategory.AI_ACTIVITY,
            Actor.AI,
            f"{TOOL} tool call: {call_name}",
            ts_basis=_basis(ts),
            subject=target if isinstance(target, str) else None,
        )

    def _state_db(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        data = ctx.fs.read_bytes(cand.ref)
        conn = sqlite3.connect(":memory:")
        try:
            try:
                conn.deserialize(data)
                tables = self._tables(conn)
            except sqlite3.DatabaseError as exc:
                yield self.warning(ctx, cand, f"cannot read SQLite database: {exc}")
                yield self._presence(ctx, cand, "store", "present", f"{cand.ref.path} present but not parsed")
                return
            messages_table = self._find_table(tables, "messages", ("session", "role", "content"))
            if messages_table is None:
                yield self.warning(ctx, cand, "schema_mismatch: no messages table found")
                yield self._presence(ctx, cand, "store", "present", f"{cand.ref.path} present but not parsed")
                return
            sessions_table = self._find_table(tables, "sessions", ("id",), exclude=messages_table)
            try:
                yield from self._read_db(ctx, cand, conn, tables, sessions_table, messages_table)
            except sqlite3.DatabaseError as exc:
                yield self.warning(ctx, cand, f"database read failed: {exc}")
                yield self._presence(ctx, cand, "store", "present", f"{cand.ref.path} present but not parsed")
        finally:
            conn.close()

    @staticmethod
    def _tables(conn: sqlite3.Connection) -> dict[str, list[str]]:
        names = [
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        ]
        return {n: [str(c[1]) for c in conn.execute(f"PRAGMA table_info({_quote(n)})")] for n in names}

    @staticmethod
    def _find_table(
        tables: dict[str, list[str]], name: str, required: tuple[str, ...], exclude: str | None = None
    ) -> str | None:
        for table in tables:
            if table.lower() == name and table != exclude:
                return table
        needed = _MESSAGE_COLUMNS if name == "messages" else _SESSION_COLUMNS
        for table, columns in tables.items():
            if table == exclude or "fts" in table.lower():
                continue
            if all(_pick(columns, needed[key]) for key in required):
                return table
        return None

    def _read_db(
        self,
        ctx: ParseContext,
        cand: Candidate,
        conn: sqlite3.Connection,
        tables: dict[str, list[str]],
        sessions_table: str | None,
        messages_table: str,
    ) -> Iterator[Artifact | Event]:
        sessions: dict[str, dict[str, Any]] = {}
        if sessions_table is not None:
            scols = {k: _pick(tables[sessions_table], v) for k, v in _SESSION_COLUMNS.items()}
            if scols["id"] is not None:
                selected = [(k, c) for k, c in scols.items() if c is not None]
                sql = "SELECT " + ", ".join(_quote(c) for _, c in selected) + f" FROM {_quote(sessions_table)}"
                for values in conn.execute(sql):
                    rec = {k: v for (k, _), v in zip(selected, values, strict=True)}
                    sessions[str(rec["id"])] = rec
        mcols = {k: _pick(tables[messages_table], v) for k, v in _MESSAGE_COLUMNS.items()}
        selected = [(k, c) for k, c in mcols.items() if c is not None]
        sql = (
            "SELECT rowid, "
            + ", ".join(_quote(c) for _, c in selected)
            + f" FROM {_quote(messages_table)} ORDER BY rowid"
        )
        stamps: list[datetime] = []
        models: dict[str, None] = {}
        count = 0
        bad = 0
        os_family = _os_of(cand)
        for values in conn.execute(sql):
            rowid, rec = values[0], {k: v for (k, _), v in zip(selected, values[1:], strict=True)}
            role = rec.get("role")
            if not isinstance(role, str):
                bad += 1
                continue
            session_id = None if rec.get("session") is None else str(rec["session"])
            meta = sessions.get(session_id or "", {})
            ts = _ts(rec.get("timestamp"))
            if ts is not None:
                stamps.append(ts)
            extra: dict[str, Any] = {}
            if meta.get("source") is not None:
                extra["platform"] = str(meta["source"])
            if meta.get("user_id"):
                extra["user_id"] = str(meta["user_id"])
            if meta.get("parent"):
                extra["parent_session_id"] = str(meta["parent"])
            if rec.get("active") is not None and not rec["active"]:
                extra["archived_generation"] = True
            if rec.get("tool_name"):
                extra["tool_name"] = str(rec["tool_name"])
            model = _str_or_none(meta.get("model"))
            if model:
                models[model] = None
            workspace = _str_or_none(meta.get("workspace"))
            row = {
                "role": role,
                "content": rec.get("content"),
                "session_id": session_id,
                "tool_calls": self._calls(rec.get("tool_calls")),
                "model": model or None,
                "title": _str_or_none(meta.get("title")),
                "workspace": normalize(workspace, os_family) if workspace else None,
                "extra": extra,
                "recovered_from": "sqlite",
            }
            count += 1
            yield from self._message(ctx, cand, f"row:{messages_table}.rowid={rowid}", row, ts)
        for model in models:
            yield self.artifact(
                ctx,
                cand,
                ArtifactKind.AI_MODEL,
                {"tool": TOOL, "model_name": model},
                locator=f"model:{model}",
            )
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")
        started = [t for t in (_ts(s.get("started")) for s in sessions.values()) if t is not None]
        stamps.extend(started)
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{count} message(s) in {len(sessions)} session(s) in {cand.ref.path}",
            min(stamps) if stamps else None,
            max(stamps) if stamps else None,
        )

    @staticmethod
    def _calls(raw: Any) -> list[Any] | None:
        parsed = _json_value(raw)
        return parsed if isinstance(parsed, list) else None

    def _legacy(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        session_id = cand.ref.path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        model: str | None = None
        stamps: list[datetime] = []
        bad = 0
        count = 0
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if not isinstance(rec, dict) or not isinstance(rec.get("role"), str):
                bad += 1
                continue
            if rec["role"] == "session_meta":
                model = _str_or_none(rec.get("model")) or model
                continue
            ts = _ts(rec.get("timestamp"))
            if ts is not None:
                stamps.append(ts)
            row = {
                "role": rec["role"],
                "content": rec.get("content"),
                "session_id": _str_or_none(rec.get("session_id")) or session_id,
                "tool_calls": self._calls(rec.get("tool_calls")),
                "model": _str_or_none(rec.get("model")) or model,
                "extra": {"platform": rec["platform"]} if isinstance(rec.get("platform"), str) else {},
                "recovered_from": "jsonl",
            }
            count += 1
            yield from self._message(ctx, cand, f"line:{number}", row, ts)
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{count} message(s) in legacy session {cand.ref.path}",
            min(stamps) if stamps else None,
            max(stamps) if stamps else None,
        )

    def _stat_detail(self, ctx: ParseContext, cand: Candidate) -> tuple[str, datetime | None]:
        st = ctx.fs.stat(cand.ref)
        mtime = st.mtime
        detail = f"{cand.ref.path}: {st.size if st.size is not None else 'unknown'} bytes"
        if mtime is not None:
            detail += f", mtime {_iso(mtime)}"
        return detail, mtime

    def _memory(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        detail, mtime = self._stat_detail(ctx, cand)
        yield self._presence(ctx, cand, "store", "present", detail, last_seen=mtime)

    def _config(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        detail, mtime = self._stat_detail(ctx, cand)
        yield self._presence(ctx, cand, "config", "present", detail, last_seen=mtime)
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            for provider, secret in _secrets(line):
                redacted = redact(secret)
                yield self.artifact(
                    ctx,
                    cand,
                    ArtifactKind.AI_CREDENTIAL,
                    {"tool": TOOL, "provider": provider, "redacted": redacted, "line": number},
                    locator=f"line:{number}:{redacted}",
                )


def _profile_of(path: str) -> str | None:
    parts = path.split("/")
    if "profiles" in parts:
        index = parts.index("profiles")
        if index + 1 < len(parts) - 1:
            return parts[index + 1]
    return None


PLUGIN = Plugin()
