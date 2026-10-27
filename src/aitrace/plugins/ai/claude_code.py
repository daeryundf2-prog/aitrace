from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_iso, from_unix_ms
from aitrace.fs.base import user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

TOOL = "Claude Code"

_HOME_GLOBS: tuple[tuple[str, str], ...] = (
    ("session", ".claude/projects/*/*.jsonl"),
    ("subagent", ".claude/projects/*/*/subagents/*.jsonl"),
    ("history", ".claude/history.jsonl"),
    ("config", ".claude.json"),
    ("settings", ".claude/settings.json"),
)
_TRANSCRIPT_ROLES = frozenset({"session", "subagent"})
_ROLE_ACTORS: dict[str, Actor] = {
    "user": Actor.HUMAN,
    "assistant": Actor.AI,
    "tool": Actor.SYSTEM,
}
_FILE_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit"})


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _os_of(cand: Candidate) -> OsFamily:
    return cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN


def _basis(ts: datetime | None) -> str:
    return "unknown" if ts is None else "native_utc"


def _summary(text: str) -> str:
    stripped = text.strip()
    return stripped.splitlines()[0][:120] if stripped else ""


def _blocks(content: Any) -> list[dict[str, Any]]:
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, list):
        return [item for item in content if isinstance(item, dict)]
    return []


def _result_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            item["text"] for item in content if isinstance(item, dict) and isinstance(item.get("text"), str)
        )
    return ""


class Plugin(PluginBase):
    name = "claude_code"
    version = "1.0"
    description = "Claude Code session transcripts, prompt history, config and settings"

    def locate(self, fs: Any) -> Iterator[Candidate]:
        for user in fs.users():
            for role, pattern in _HOME_GLOBS:
                for ref in user_glob(fs, user, pattern):
                    yield Candidate(ref=ref, role=role, user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        match cand.role:
            case "session" | "subagent":
                yield from self._transcript(ctx, cand)
            case "history":
                yield from self._history(ctx, cand)
            case "config" | "settings":
                yield from self._config(ctx, cand)
            case _:
                raise ValueError(f"unknown claude_code candidate role {cand.role!r}")

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
            data["first_seen"] = first_seen.isoformat().replace("+00:00", "Z")
        if last_seen is not None:
            data["last_seen"] = last_seen.isoformat().replace("+00:00", "Z")
        return self.artifact(ctx, cand, ArtifactKind.AI_APP_PRESENCE, data, locator="presence")

    def _chat(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        data: dict[str, Any],
        ts: datetime | None,
    ) -> Iterator[Artifact | Event]:
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_CHAT_MESSAGE, data, locator=locator)
        yield artifact
        role = str(data["role"])
        yield self.event(
            artifact,
            ts,
            "message",
            EventCategory.AI_ACTIVITY,
            _ROLE_ACTORS.get(role, Actor.UNKNOWN),
            _summary(str(data["text"])),
            ts_basis=_basis(ts),
        )

    def _transcript(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        records, bad = self._lines(ctx, cand)
        os_family = _os_of(cand)
        stamps: list[datetime] = []
        messages = 0
        for number, rec in records:
            kind = rec.get("type")
            if kind not in ("user", "assistant"):
                continue
            message = rec.get("message")
            if not isinstance(message, dict) or message.get("content") is None:
                bad += 1
                continue
            blocks = _blocks(message["content"])
            ts = from_iso(_str_or_none(rec.get("timestamp")))
            if ts is not None:
                stamps.append(ts)
            texts = [b["text"] for b in blocks if b.get("type") == "text" and isinstance(b.get("text"), str)]
            results = [b for b in blocks if b.get("type") == "tool_result"]
            role = str(kind)
            if kind == "user" and results and not texts:
                role = "tool"
                texts = [_result_text(b.get("content")) for b in results]
            data: dict[str, Any] = {
                "tool": TOOL,
                "session_id": _str_or_none(rec.get("sessionId")),
                "role": role,
                "text": "\n".join(texts),
                "fragment": False,
                "recovered_from": "jsonl",
            }
            model = _str_or_none(message.get("model"))
            if model is not None:
                data["model"] = model
            cwd = _str_or_none(rec.get("cwd"))
            if cwd is not None:
                data["workspace"] = normalize(cwd, os_family)
            if cand.role == "subagent":
                data["extra"] = {"subagent": True}
            messages += 1
            yield from self._chat(ctx, cand, f"line:{number}", data, ts)
            if kind == "assistant":
                for index, block in enumerate(blocks):
                    if block.get("type") != "tool_use":
                        continue
                    call = self._tool_call(ctx, cand, f"line:{number}:tool:{index}", rec, block, ts, os_family)
                    if call is None:
                        bad += 1
                        continue
                    yield from call
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{messages} message(s) in {cand.ref.path}",
            min(stamps) if stamps else None,
            max(stamps) if stamps else None,
        )

    def _tool_call(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        rec: dict[str, Any],
        block: dict[str, Any],
        ts: datetime | None,
        os_family: OsFamily,
    ) -> Iterator[Artifact | Event] | None:
        call_name = block.get("name")
        arguments = block.get("input")
        if not isinstance(call_name, str) or not isinstance(arguments, dict):
            return None
        data: dict[str, Any] = {
            "tool": TOOL,
            "session_id": _str_or_none(rec.get("sessionId")),
            "call_name": call_name,
            "input": arguments,
        }
        if call_name in _FILE_WRITE_TOOLS:
            raw_path = _str_or_none(arguments.get("file_path"))
            if raw_path is not None:
                data["file_path"] = normalize(raw_path, os_family)
                if data["file_path"] != raw_path:
                    data["raw_path"] = raw_path
            content = self._written_content(call_name, arguments)
            if content is not None:
                data["content"] = content
        command = arguments.get("command")
        if isinstance(command, str):
            data["command"] = command
        return self._emit_tool_call(ctx, cand, locator, data, call_name, ts)

    @staticmethod
    def _written_content(call_name: str, arguments: dict[str, Any]) -> str | None:
        if call_name == "Write":
            return _str_or_none(arguments.get("content"))
        if call_name == "Edit":
            return _str_or_none(arguments.get("new_string"))
        edits = arguments.get("edits")
        if not isinstance(edits, list):
            return None
        parts = [e["new_string"] for e in edits if isinstance(e, dict) and isinstance(e.get("new_string"), str)]
        return "\n".join(parts) if parts else None

    def _emit_tool_call(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        data: dict[str, Any],
        call_name: str,
        ts: datetime | None,
    ) -> Iterator[Artifact | Event]:
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

    def _history(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        records, bad = self._lines(ctx, cand)
        os_family = _os_of(cand)
        stamps: list[datetime] = []
        count = 0
        for number, rec in records:
            display = rec.get("display")
            if not isinstance(display, str):
                bad += 1
                continue
            stamp = rec.get("timestamp")
            ts = from_unix_ms(stamp) if isinstance(stamp, int | float) and not isinstance(stamp, bool) else None
            if ts is not None:
                stamps.append(ts)
            data: dict[str, Any] = {
                "tool": TOOL,
                "session_id": _str_or_none(rec.get("sessionId")),
                "role": "user",
                "text": display,
                "fragment": False,
                "recovered_from": "jsonl",
            }
            project = _str_or_none(rec.get("project"))
            if project is not None:
                data["workspace"] = normalize(project, os_family)
            count += 1
            yield from self._chat(ctx, cand, f"line:{number}", data, ts)
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{count} prompt(s) in history",
            min(stamps) if stamps else None,
            max(stamps) if stamps else None,
        )

    def _config(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            yield self.warning(ctx, cand, f"invalid JSON: {exc.msg} (line {exc.lineno})")
            yield self._presence(ctx, cand, "config", "present", f"{cand.ref.path} present but not parsed")
            return
        if not isinstance(doc, dict):
            yield self.warning(ctx, cand, "unexpected JSON shape: expected an object")
            yield self._presence(ctx, cand, "config", "present", f"{cand.ref.path} present but not parsed")
            return
        detail = f"{cand.ref.path}: {len(doc)} top-level key(s)"
        projects = doc.get("projects")
        if isinstance(projects, dict):
            detail += f", {len(projects)} project(s)"
        yield self._presence(ctx, cand, "config", "parsed", detail)


PLUGIN = Plugin()
