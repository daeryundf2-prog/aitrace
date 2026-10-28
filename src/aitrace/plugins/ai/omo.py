from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_iso, from_unix_ms
from aitrace.fs.base import EntryRef, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

TOOL = "omo"

_HOME_GLOBS: tuple[tuple[str, str], ...] = (
    ("session", ".omo/agent/sessions/*/*.jsonl"),
    ("thread", ".omo/desktop/userdata/omo-sessions/*/*.jsonl"),
    ("config", ".omo/omo.jsonc"),
    ("config", ".omo/agent/*.json"),
    ("config", ".omo/agent/*.jsonc"),
)
_MEMORY_GLOB = ".omo/memory/**/*.md"
_TRANSCRIPT_ROLES = frozenset({"session", "thread"})
# credential stores are never opened, only skipped
_SKIP_CONFIG_MARKERS = ("auth", "credential", "oauth", "token", "secret")
_ROLE_MAP = {"user": "user", "assistant": "assistant", "toolResult": "tool"}
_ROLE_ACTORS: dict[str, Actor] = {
    "user": Actor.HUMAN,
    "assistant": Actor.AI,
    "tool": Actor.SYSTEM,
}
_FILE_TOOLS = frozenset({"write", "edit", "multiedit", "apply_patch", "create", "str_replace_editor"})
_SHELL_TOOLS = frozenset({"bash", "shell", "sh", "zsh", "exec", "terminal", "powershell", "run_command"})
_MODEL_KEYS = frozenset({"model", "modelid", "defaultmodel", "models"})
_PROVIDER_KEYS = frozenset({"provider", "providers", "defaultprovider"})


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


def _blocks(content: Any) -> list[dict[str, Any]]:
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, list):
        return [item for item in content if isinstance(item, dict)]
    return []


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _strip_jsonc(text: str) -> str:
    """Drop // and /* */ comments and trailing commas outside string literals."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
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
    cleaned = "".join(out)
    result: list[str] = []
    in_str = False
    for idx, ch in enumerate(cleaned):
        if in_str:
            result.append(ch)
            if ch == "\\":
                continue
            if ch == '"' and (idx == 0 or cleaned[idx - 1] != "\\"):
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == ",":
            rest = cleaned[idx + 1 :].lstrip()
            if rest[:1] in ("}", "]"):
                continue
        result.append(ch)
    return "".join(result)


def _collect_names(node: Any, models: set[str], providers: set[str]) -> None:
    """Gather model/provider names only; every other value (keys, urls, tokens) is ignored."""
    if isinstance(node, dict):
        for key, value in node.items():
            lowered = str(key).lower()
            target = models if lowered in _MODEL_KEYS else providers if lowered in _PROVIDER_KEYS else None
            if target is not None:
                if isinstance(value, str):
                    target.add(value)
                elif isinstance(value, list):
                    target.update(v for v in value if isinstance(v, str))
            _collect_names(value, models, providers)
    elif isinstance(node, list):
        for item in node:
            _collect_names(item, models, providers)


class Plugin(PluginBase):
    name = "omo"
    version = "1.0"
    description = "omo (OmO desktop / senpi agent) sessions, desktop threads, memory store and config"

    def locate(self, fs: Any) -> Iterator[Candidate]:
        for user in fs.users():
            for role, pattern in _HOME_GLOBS:
                for ref in user_glob(fs, user, pattern):
                    name = _basename(ref.path)
                    if role == "thread" and not name.startswith("thread-"):
                        continue
                    if role == "config" and any(m in name.lower() for m in _SKIP_CONFIG_MARKERS):
                        continue
                    yield Candidate(ref=ref, role=role, user=user)
            notes = [r for r in user_glob(fs, user, _MEMORY_GLOB)]
            if notes:
                newest: datetime | None = None
                for note in notes:
                    mtime = fs.stat(note).mtime
                    if mtime is not None and (newest is None or mtime > newest):
                        newest = mtime
                extra: dict[str, Any] = {"count": len(notes)}
                if newest is not None:
                    extra["newest"] = _iso(newest)
                yield Candidate(ref=notes[0], role="memory", user=user, extra=extra)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        match cand.role:
            case "session" | "thread":
                yield from self._transcript(ctx, cand)
            case "memory":
                yield from self._memory(ctx, cand)
            case "config":
                yield from self._config(ctx, cand)
            case _:
                raise ValueError(f"unknown omo candidate role {cand.role!r}")

    def _lines(self, ctx: ParseContext, cand: Candidate) -> tuple[list[tuple[int, dict[str, Any]]], int]:
        records: list[tuple[int, dict[str, Any]]] = []
        malformed = 0
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if isinstance(value, dict):
                records.append((number, value))
            else:
                malformed += 1
        return records, malformed

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

    def _transcript(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        records, bad = self._lines(ctx, cand)
        os_family = _os_of(cand)
        session_id: str | None = None
        workspace: str | None = None
        current_model: str | None = None
        stamps: list[datetime] = []
        messages = 0
        for number, rec in records:
            kind = rec.get("type")
            if kind == "session":
                session_id = _str_or_none(rec.get("id")) or session_id
                cwd = _str_or_none(rec.get("cwd"))
                if cwd is not None:
                    workspace = normalize(cwd, os_family)
                continue
            if kind == "model_change":
                current_model = _str_or_none(rec.get("modelId")) or current_model
                continue
            if kind != "message":
                continue
            message = rec.get("message")
            role = _ROLE_MAP.get(str(message.get("role"))) if isinstance(message, dict) else None
            if not isinstance(message, dict) or role is None or message.get("content") is None:
                bad += 1
                continue
            ts = from_iso(_str_or_none(rec.get("timestamp")))
            if ts is None:
                stamp = message.get("timestamp")
                if isinstance(stamp, int | float) and not isinstance(stamp, bool):
                    ts = from_unix_ms(stamp)
            if ts is not None:
                stamps.append(ts)
            blocks = _blocks(message["content"])
            text = "\n".join(
                b["text"] for b in blocks if b.get("type") == "text" and isinstance(b.get("text"), str)
            )
            if text.strip():
                data: dict[str, Any] = {
                    "tool": TOOL,
                    "session_id": session_id,
                    "role": role,
                    "text": text,
                    "fragment": False,
                    "recovered_from": "jsonl",
                }
                model = _str_or_none(message.get("model")) or (current_model if role == "assistant" else None)
                if model is not None:
                    data["model"] = model
                if workspace is not None:
                    data["workspace"] = workspace
                messages += 1
                yield from self._chat(ctx, cand, f"line:{number}", data, ts)
            if role != "assistant":
                continue
            for index, block in enumerate(blocks):
                if block.get("type") != "toolCall":
                    continue
                call = self._tool_call(
                    ctx, cand, f"line:{number}:tool:{index}", session_id, block, ts, os_family
                )
                if call is None:
                    bad += 1
                    continue
                yield from call
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")
        detail = f"{messages} message(s) in {cand.ref.path}"
        if cand.role == "thread":
            detail += f", {self._artifact_count(ctx, cand)} artifact(s)"
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            detail,
            min(stamps) if stamps else None,
            max(stamps) if stamps else None,
        )

    @staticmethod
    def _artifact_count(ctx: ParseContext, cand: Candidate) -> int:
        folder = EntryRef(cand.ref.volume, cand.ref.path.removesuffix(".jsonl") + "-artifacts")
        if not ctx.fs.is_dir(folder):
            return 0
        return sum(1 for _ in ctx.fs.walk(folder))

    def _chat(
        self, ctx: ParseContext, cand: Candidate, locator: str, data: dict[str, Any], ts: datetime | None
    ) -> Iterator[Artifact | Event]:
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_CHAT_MESSAGE, data, locator=locator)
        yield artifact
        yield self.event(
            artifact,
            ts,
            "message",
            EventCategory.AI_ACTIVITY,
            _ROLE_ACTORS.get(str(data["role"]), Actor.UNKNOWN),
            _summary(str(data["text"])),
            ts_basis=_basis(ts),
        )

    def _tool_call(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        session_id: str | None,
        block: dict[str, Any],
        ts: datetime | None,
        os_family: OsFamily,
    ) -> Iterator[Artifact | Event] | None:
        call_name = block.get("name")
        arguments = block.get("arguments")
        if not isinstance(call_name, str) or not isinstance(arguments, dict):
            return None
        data: dict[str, Any] = {
            "tool": TOOL,
            "session_id": session_id,
            "call_name": call_name,
            "input": arguments,
        }
        lowered = call_name.lower()
        if lowered in _FILE_TOOLS:
            raw_path = _str_or_none(arguments.get("path")) or _str_or_none(arguments.get("file_path"))
            if raw_path is not None:
                data["file_path"] = normalize(raw_path, os_family)
                if data["file_path"] != raw_path:
                    data["raw_path"] = raw_path
            content = self._written_content(lowered, arguments)
            if content is not None:
                data["content"] = content
        command = arguments.get("command")
        if isinstance(command, str) and (lowered in _SHELL_TOOLS or lowered not in _FILE_TOOLS):
            data["command"] = command
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_TOOL_CALL, data, locator=locator)
        target = data.get("file_path")
        return iter(
            (
                artifact,
                self.event(
                    artifact,
                    ts,
                    "tool_call",
                    EventCategory.AI_ACTIVITY,
                    Actor.AI,
                    f"{TOOL} tool call: {call_name}",
                    ts_basis=_basis(ts),
                    subject=target if isinstance(target, str) else None,
                ),
            )
        )

    @staticmethod
    def _written_content(lowered: str, arguments: dict[str, Any]) -> str | None:
        if lowered in ("write", "create"):
            return _str_or_none(arguments.get("content")) or _str_or_none(arguments.get("file_text"))
        if lowered == "apply_patch":
            return _str_or_none(arguments.get("patch")) or _str_or_none(arguments.get("input"))
        single = _str_or_none(arguments.get("new_string")) or _str_or_none(arguments.get("newText"))
        if single is not None:
            return single
        edits = arguments.get("edits")
        if not isinstance(edits, list):
            return None
        parts = [
            v
            for e in edits
            if isinstance(e, dict)
            for v in (_str_or_none(e.get("newText")) or _str_or_none(e.get("new_string")),)
            if v is not None
        ]
        return "\n".join(parts) if parts else None

    def _memory(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        count = int(cand.extra.get("count", 0))
        newest = from_iso(_str_or_none(cand.extra.get("newest")))
        yield self._presence(
            ctx, cand, "store", "present", f"{count} markdown note(s) under .omo/memory", None, newest
        )

    def _config(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        try:
            doc = json.loads(_strip_jsonc(text))
        except json.JSONDecodeError as exc:
            yield self.warning(ctx, cand, f"invalid JSON: {exc.msg} (line {exc.lineno})")
            yield self._presence(ctx, cand, "config", "present", f"{cand.ref.path} present but not parsed")
            return
        models: set[str] = set()
        providers: set[str] = set()
        _collect_names(doc, models, providers)
        detail = f"{cand.ref.path}: models={sorted(models)[:20]} providers={sorted(providers)[:20]}"
        yield self._presence(ctx, cand, "config", "parsed", detail)


PLUGIN = Plugin()
