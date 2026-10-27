from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_iso, from_local_naive, from_unix
from aitrace.fs.base import EntryRef, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

TOOL_CODEX = "Codex CLI"
TOOL_GEMINI = "Gemini CLI"
TOOL_AIDER = "Aider"
TOOL_COPILOT = "GitHub Copilot CLI"
TOOL_CONTINUE = "Continue"

_HOME_GLOBS: tuple[tuple[str, str], ...] = (
    ("codex_rollout", ".codex/sessions/**/rollout-*.jsonl"),
    ("codex_history", ".codex/history.jsonl"),
    ("gemini_logs", ".gemini/tmp/*/logs.json"),
    ("gemini_chat", ".gemini/tmp/*/chats/*.json"),
    ("copilot_session", ".copilot/session-state/*.jsonl"),
    ("continue_session", ".continue/sessions/*.json"),
)
_AIDER_FILES: dict[str, str] = {
    ".aider.chat.history.md": "aider_md",
    ".aider.input.history": "aider_input",
}
_AIDER_DEPTH = 6
_WALK_SKIP = frozenset({"node_modules", ".git", ".Trash", "Library", "AppData"})

_ROLE_MAP: dict[str, str] = {
    "user": "user",
    "assistant": "assistant",
    "model": "assistant",
    "gemini": "assistant",
    "system": "system",
    "developer": "system",
    "tool": "tool",
}
_ACTORS: dict[str, Actor] = {
    "user": Actor.HUMAN,
    "assistant": Actor.AI,
    "system": Actor.SYSTEM,
    "tool": Actor.SYSTEM,
}
_TEXT_PART_TYPES = frozenset({"input_text", "output_text", "text"})
_AIDER_START = re.compile(r"^# aider chat started at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$")
_AIDER_INPUT_HEADER = re.compile(r"^# (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)$")


def _role(raw: str) -> str:
    return _ROLE_MAP.get(raw, "unknown")


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _os_of(cand: Candidate) -> OsFamily:
    return cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN


def _stem(cand: Candidate) -> str:
    return cand.ref.path.rsplit("/", 1)[-1].rsplit(".", 1)[0]


def _read_text(ctx: ParseContext, cand: Candidate) -> str:
    return ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")


def _read_jsonl(ctx: ParseContext, cand: Candidate) -> tuple[list[tuple[int, dict[str, Any]]], int]:
    records: list[tuple[int, dict[str, Any]]] = []
    malformed = 0
    for number, line in enumerate(_read_text(ctx, cand).splitlines(), start=1):
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


def _load_json(text: str) -> tuple[Any, str | None]:
    try:
        return json.loads(text), None
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON: {exc.msg} (line {exc.lineno})"


def _content_text(content: Any) -> str | None:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return None
    parts = [
        item["text"]
        for item in content
        if isinstance(item, dict) and item.get("type") in _TEXT_PART_TYPES and isinstance(item.get("text"), str)
    ]
    return "\n".join(parts)


def _arguments(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _parse_naive(text: str) -> datetime | None:
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _basis(ts: datetime | None, basis: str) -> str:
    return "unknown" if ts is None else basis


def _summary(text: str) -> str:
    stripped = text.strip()
    return stripped.splitlines()[0][:120] if stripped else ""


class Plugin(PluginBase):
    name = "cli_agents"
    version = "1.0"
    description = "Session and prompt logs of CLI coding agents: Codex, Gemini CLI, Aider, Copilot CLI, Continue"

    def locate(self, fs: Any) -> Iterator[Candidate]:
        for user in fs.users():
            for role, pattern in _HOME_GLOBS:
                for ref in user_glob(fs, user, pattern):
                    yield Candidate(ref=ref, role=role, user=user)
            for ref in fs.walk(EntryRef(user.volume, user.home), max_depth=_AIDER_DEPTH, skip_names=_WALK_SKIP):
                role = _AIDER_FILES.get(ref.path.rsplit("/", 1)[-1])
                if role is not None:
                    yield Candidate(ref=ref, role=role, user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        match cand.role:
            case "codex_rollout":
                yield from self._codex_rollout(ctx, cand)
            case "codex_history":
                yield from self._codex_history(ctx, cand)
            case "gemini_logs":
                yield from self._gemini_logs(ctx, cand)
            case "gemini_chat":
                yield from self._gemini_chat(ctx, cand)
            case "aider_md":
                yield from self._aider_md(ctx, cand)
            case "aider_input":
                yield from self._aider_input(ctx, cand)
            case "copilot_session":
                yield from self._copilot_session(ctx, cand)
            case "continue_session":
                yield from self._continue_session(ctx, cand)
            case _:
                raise ValueError(f"unknown cli_agents candidate role {cand.role!r}")

    def _chat(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        *,
        tool: str,
        role: str,
        text: str,
        session_id: str | None,
        ts: datetime | None,
        ts_basis: str = "native_utc",
        workspace: str | None = None,
        recovered_from: str | None = None,
    ) -> Iterator[Artifact | Event]:
        data: dict[str, Any] = {
            "tool": tool,
            "session_id": session_id,
            "role": role,
            "text": text,
            "fragment": False,
        }
        if workspace is not None:
            data["workspace"] = workspace
        if recovered_from is not None:
            data["recovered_from"] = recovered_from
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_CHAT_MESSAGE, data, locator=locator)
        yield artifact
        yield self.event(
            artifact,
            ts,
            "message",
            EventCategory.AI_ACTIVITY,
            _ACTORS.get(role, Actor.UNKNOWN),
            _summary(text),
            ts_basis=_basis(ts, ts_basis),
        )

    def _tool_call(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        *,
        tool: str,
        session_id: str | None,
        call_name: str,
        arguments: dict[str, Any],
        ts: datetime | None,
    ) -> Iterator[Artifact | Event]:
        data: dict[str, Any] = {
            "tool": tool,
            "session_id": session_id,
            "call_name": call_name,
            "input": arguments,
        }
        command = arguments.get("command")
        if isinstance(command, str):
            data["command"] = command
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_TOOL_CALL, data, locator=locator)
        yield artifact
        yield self.event(
            artifact,
            ts,
            "tool_call",
            EventCategory.AI_ACTIVITY,
            Actor.AI,
            f"{tool} tool call: {call_name}",
            ts_basis=_basis(ts, "native_utc"),
        )

    def _codex_rollout(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        records, malformed = _read_jsonl(ctx, cand)
        bad = malformed
        session_id: str | None = None
        workspace: str | None = None
        for number, rec in records:
            kind = rec.get("type")
            payload = rec.get("payload")
            if kind == "session_meta":
                if not isinstance(payload, dict):
                    bad += 1
                    continue
                session_id = _str_or_none(payload.get("id"))
                cwd = payload.get("cwd")
                workspace = normalize(cwd, _os_of(cand)) if isinstance(cwd, str) else None
                continue
            if kind != "response_item":
                continue
            if not isinstance(payload, dict):
                bad += 1
                continue
            ts = from_iso(_str_or_none(rec.get("timestamp")))
            locator = f"line:{number}"
            match payload.get("type"):
                case "message":
                    role = payload.get("role")
                    text = _content_text(payload.get("content"))
                    if not isinstance(role, str) or text is None:
                        bad += 1
                        continue
                    yield from self._chat(
                        ctx,
                        cand,
                        locator,
                        tool=TOOL_CODEX,
                        role=_role(role),
                        text=text,
                        session_id=session_id,
                        ts=ts,
                        workspace=workspace,
                    )
                case "function_call":
                    name = payload.get("name")
                    arguments = _arguments(payload.get("arguments"))
                    if not isinstance(name, str) or arguments is None:
                        bad += 1
                        continue
                    yield from self._tool_call(
                        ctx,
                        cand,
                        locator,
                        tool=TOOL_CODEX,
                        session_id=session_id,
                        call_name=name,
                        arguments=arguments,
                        ts=ts,
                    )
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")

    def _codex_history(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        records, bad = _read_jsonl(ctx, cand)
        for number, rec in records:
            text = rec.get("text")
            stamp = rec.get("ts")
            if not isinstance(text, str) or not isinstance(stamp, int | float) or isinstance(stamp, bool):
                bad += 1
                continue
            yield from self._chat(
                ctx,
                cand,
                f"line:{number}",
                tool=TOOL_CODEX,
                role="user",
                text=text,
                session_id=_str_or_none(rec.get("session_id")),
                ts=from_unix(stamp),
                recovered_from="jsonl",
            )
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")

    def _gemini_logs(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        doc, error = _load_json(_read_text(ctx, cand))
        if error is not None:
            yield self.warning(ctx, cand, error)
            return
        if not isinstance(doc, list):
            yield self.warning(ctx, cand, "unexpected JSON shape: expected a list of prompts")
            return
        bad = 0
        for index, entry in enumerate(doc):
            if not isinstance(entry, dict) or entry.get("type") != "user" or not isinstance(entry.get("message"), str):
                bad += 1
                continue
            yield from self._chat(
                ctx,
                cand,
                f"index:{index}",
                tool=TOOL_GEMINI,
                role="user",
                text=entry["message"],
                session_id=_str_or_none(entry.get("sessionId")),
                ts=from_iso(_str_or_none(entry.get("timestamp"))),
                recovered_from="json",
            )
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")

    def _gemini_chat(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        doc, error = _load_json(_read_text(ctx, cand))
        if error is not None:
            yield self.warning(ctx, cand, error)
            return
        messages = doc.get("messages") if isinstance(doc, dict) else None
        if not isinstance(messages, list):
            yield self.warning(ctx, cand, "unexpected JSON shape: expected an object with a messages list")
            return
        session_id = _str_or_none(doc.get("sessionId")) or _stem(cand)
        bad = 0
        for index, msg in enumerate(messages):
            if (
                not isinstance(msg, dict)
                or msg.get("type") not in ("user", "gemini")
                or not isinstance(msg.get("content"), str)
            ):
                bad += 1
                continue
            yield from self._chat(
                ctx,
                cand,
                f"index:{index}",
                tool=TOOL_GEMINI,
                role=_role(msg["type"]),
                text=msg["content"],
                session_id=session_id,
                ts=from_iso(_str_or_none(msg.get("timestamp"))),
                recovered_from="json",
            )
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")

    def _aider_md(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        workspace = normalize(cand.ref.path.rsplit("/", 1)[0] or "/", _os_of(cand))
        started: datetime | None = None
        session: str | None = None
        bad = 0
        pending: list[str] = []
        pending_line = 0
        messages: list[tuple[int, str, str]] = []

        def flush() -> None:
            body = "\n".join(pending).strip()
            if body:
                messages.append((pending_line, "assistant", body))
            pending.clear()

        for number, line in enumerate(_read_text(ctx, cand).splitlines(), start=1):
            header = _AIDER_START.match(line)
            if header is not None:
                flush()
                session = header.group(1)
                started = _parse_naive(header.group(1))
                if started is None:
                    bad += 1
            elif line.startswith("#### "):
                flush()
                messages.append((number, "user", line[5:].strip()))
            else:
                if not pending:
                    pending_line = number
                pending.append(line)
        flush()
        ts = from_local_naive(started, ctx.tz) if started is not None else None
        for number, role, body in messages:
            yield from self._chat(
                ctx,
                cand,
                f"line:{number}",
                tool=TOOL_AIDER,
                role=role,
                text=body,
                session_id=session,
                ts=ts,
                ts_basis=f"assumed:{ctx.tz}",
                workspace=workspace,
                recovered_from="markdown",
            )
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")

    def _aider_input(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        header_ts: datetime | None = None
        pending: list[str] = []
        pending_line = 0
        pending_ts: datetime | None = None
        bad = 0
        prompts: list[tuple[int, datetime | None, str]] = []

        def flush() -> None:
            body = "\n".join(pending).strip()
            if body:
                prompts.append((pending_line, pending_ts, body))
            pending.clear()

        for number, line in enumerate(_read_text(ctx, cand).splitlines(), start=1):
            header = _AIDER_INPUT_HEADER.match(line)
            if header is not None:
                flush()
                naive = _parse_naive(header.group(1))
                if naive is None:
                    bad += 1
                    header_ts = None
                else:
                    header_ts = from_local_naive(naive, ctx.tz)
                pending_ts = header_ts
            elif line.startswith("+"):
                if not pending:
                    pending_line = number
                    pending_ts = header_ts
                pending.append(line[1:])
            elif not line.strip():
                flush()
            else:
                bad += 1
        flush()
        for number, ts, body in prompts:
            yield from self._chat(
                ctx,
                cand,
                f"line:{number}",
                tool=TOOL_AIDER,
                role="user",
                text=body,
                session_id=None,
                ts=ts,
                ts_basis=f"assumed:{ctx.tz}",
            )
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")

    def _copilot_session(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        records, bad = _read_jsonl(ctx, cand)
        session = _stem(cand)
        for number, rec in records:
            role = rec.get("role")
            text = _content_text(rec.get("content"))
            if not isinstance(role, str) or text is None:
                bad += 1
                continue
            yield from self._chat(
                ctx,
                cand,
                f"line:{number}",
                tool=TOOL_COPILOT,
                role=_role(role),
                text=text,
                session_id=session,
                ts=from_iso(_str_or_none(rec.get("timestamp"))),
                recovered_from="jsonl",
            )
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")

    def _continue_session(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        doc, error = _load_json(_read_text(ctx, cand))
        if error is not None:
            yield self.warning(ctx, cand, error)
            return
        history = doc.get("history") if isinstance(doc, dict) else None
        if not isinstance(history, list):
            yield self.warning(ctx, cand, "unexpected JSON shape: expected an object with a history list")
            return
        session = _stem(cand)
        bad = 0
        for index, item in enumerate(history):
            message = item.get("message") if isinstance(item, dict) else None
            if not isinstance(message, dict) or not isinstance(message.get("role"), str):
                bad += 1
                continue
            text = _content_text(message.get("content"))
            if text is None:
                bad += 1
                continue
            yield from self._chat(
                ctx,
                cand,
                f"index:{index}",
                tool=TOOL_CONTINUE,
                role=_role(message["role"]),
                text=text,
                session_id=session,
                ts=None,
            )
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")


PLUGIN = Plugin()
