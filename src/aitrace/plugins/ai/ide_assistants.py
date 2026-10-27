from __future__ import annotations

import json
import posixpath
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_unix_ms
from aitrace.fs.base import EntryRef, EvidenceFS, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase
from aitrace.plugins.common.sqlite import has_table, open_sqlite

_APPS: dict[str, str] = {
    "Cursor": "Cursor",
    "Code": "VS Code",
    "Code - Insiders": "VS Code Insiders",
    "Windsurf": "Windsurf",
    "VSCodium": "VSCodium",
}
_ROOTS: dict[OsFamily, str] = {
    OsFamily.MACOS: "Library/Application Support",
    OsFamily.WINDOWS: "AppData/Roaming",
    OsFamily.LINUX: ".config",
}
_TABLES = ("ItemTable", "cursorDiskKV")
_EXACT_KEYS = ("aiService.prompts", "aiService.generations", "workbench.panel.aichat.view.aichat.chatdata")
_LIKE_KEYS = ("composerData:%", "bubbleId:%")
_ROLES: dict[object, str] = {1: "user", 2: "assistant", "user": "user", "ai": "assistant", "assistant": "assistant"}
_ACTORS: dict[str, Actor] = {"user": Actor.HUMAN, "assistant": Actor.AI, "system": Actor.SYSTEM}


@dataclass(frozen=True, slots=True)
class _Message:
    locator: str
    role: str
    text: str
    created_ms: float | None


@dataclass(frozen=True, slots=True)
class _Session:
    session_id: str | None
    title: str | None
    messages: list[_Message]


def _files(fs: EvidenceFS, user: Any, pattern: str) -> Iterator[EntryRef]:
    return (ref for ref in user_glob(fs, user, pattern) if not fs.is_dir(ref))


def _json(raw: object) -> Any:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if not isinstance(raw, str):
        raise TypeError("value is not text")
    return json.loads(raw)


def _json_object(raw: object) -> dict[str, Any]:
    value = _json(raw)
    if not isinstance(value, dict):
        raise TypeError("expected a JSON object")
    return value


def _dict_list(value: object, where: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{where} is not a list of objects")
    return value


def _millis(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _role(value: object) -> str:
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return _ROLES.get(value, "unknown")
    return "unknown"


def _message(
    locator: str,
    role: str,
    item: dict[str, Any],
    text_key: str,
    ts_key: str | None,
    fallback_ms: float | None = None,
) -> _Message | None:
    text = item.get(text_key)
    if not isinstance(text, str) or not text:
        return None
    created_ms = _millis(item.get(ts_key)) if ts_key else None
    if created_ms is None:
        created_ms = fallback_ms
    return _Message(locator, role, text, created_ms)


def _messages(
    items: list[dict[str, Any]], prefix: str, role: str, text_key: str, ts_key: str | None
) -> list[_Message]:
    found = (_message(f"{prefix}:{i}", role, item, text_key, ts_key) for i, item in enumerate(items))
    return [message for message in found if message is not None]


def _composer_session(composer: dict[str, Any], raw_bubbles: dict[str, object]) -> _Session:
    composer_id = composer.get("composerId")
    if not isinstance(composer_id, str) or not composer_id:
        raise ValueError("composerData has no composerId")
    composer_ms = _millis(composer.get("createdAt"))
    conversation = composer.get("conversation")
    entries: list[Any]
    if isinstance(conversation, list):
        entries = conversation
    else:
        headers = _dict_list(composer.get("fullConversationHeadersOnly", []), "fullConversationHeadersOnly")
        entries = []
        for header in headers:
            raw = raw_bubbles.get(f"bubbleId:{composer_id}:{header.get('bubbleId')}")
            entries.append(None if raw is None else _json_object(raw))
    messages: list[_Message] = []
    for index, entry in enumerate(entries):
        if entry is None:
            continue
        if not isinstance(entry, dict):
            raise TypeError(f"composer {composer_id}: bubble {index} is not an object")
        message = _message(
            f"composer:{composer_id}:{index}",
            _role(entry.get("type")),
            entry,
            "text",
            "createdAt",
            composer_ms,
        )
        if message is not None:
            messages.append(message)
    name = composer.get("name")
    return _Session(composer_id, name if isinstance(name, str) else None, messages)


def _chat_tabs(data: dict[str, Any]) -> list[_Session]:
    sessions: list[_Session] = []
    for tab_index, tab in enumerate(_dict_list(data.get("tabs", []), "tabs")):
        bubbles = _dict_list(tab.get("bubbles", []), "bubbles")
        messages: list[_Message] = []
        for index, bubble in enumerate(bubbles):
            message = _message(f"chat:{tab_index}:{index}", _role(bubble.get("type")), bubble, "text", None)
            if message is not None:
                messages.append(message)
        tab_id, title = tab.get("tabId"), tab.get("chatTitle")
        sessions.append(
            _Session(
                tab_id if isinstance(tab_id, str) else None,
                title if isinstance(title, str) else None,
                messages,
            )
        )
    return sessions


def _sessions_for(key: str, raw: object, raw_bubbles: dict[str, object]) -> list[_Session]:
    if key.startswith("composerData:"):
        return [_composer_session(_json_object(raw), raw_bubbles)]
    if key == "aiService.prompts":
        items = _dict_list(_json(raw), key)
        return [_Session(None, None, _messages(items, "prompt", "user", "text", None))]
    if key == "aiService.generations":
        items = _dict_list(_json(raw), key)
        return [_Session(None, None, _messages(items, "generation", "unknown", "textDescription", "unixMs"))]
    if key == "workbench.panel.aichat.view.aichat.chatdata":
        return _chat_tabs(_json_object(raw))
    return []


def _read_state(fs: EvidenceFS, ref: EntryRef) -> dict[str, object]:
    kv: dict[str, object] = {}
    with open_sqlite(fs, ref) as conn:
        for table in _TABLES:
            if not has_table(conn, table):
                continue
            rows = conn.execute(
                f'SELECT key, value FROM "{table}" WHERE key IN (?, ?, ?) OR key LIKE ? OR key LIKE ?',
                (*_EXACT_KEYS, *_LIKE_KEYS),
            ).fetchall()
            kv.update({row["key"]: row["value"] for row in rows})
    return kv


def _workspace_dir(cand: Candidate) -> str | None:
    if cand.role == "workspace_state":
        return posixpath.dirname(cand.ref.path)
    if cand.role == "chat_session":
        return posixpath.dirname(posixpath.dirname(cand.ref.path))
    return None


def _workspace_folder(fs: EvidenceFS, volume: int, ws_dir: str, os_family: OsFamily) -> str | None:
    ref = EntryRef(volume, posixpath.join(ws_dir, "workspace.json"))
    if not fs.exists(ref):
        return None
    folder = _json_object(fs.read_bytes(ref)).get("folder")
    if not isinstance(folder, str):
        return None
    return normalize(unquote(urlsplit(folder).path).lstrip("/"), os_family)


def _vscode_session(data: dict[str, Any]) -> _Session:
    session_id, title = data.get("sessionId"), data.get("customTitle")
    messages: list[_Message] = []
    for index, request in enumerate(_dict_list(data.get("requests", []), "requests")):
        stamp = _millis(request.get("timestamp"))
        prompt = request.get("message")
        if not isinstance(prompt, dict):
            raise TypeError(f"request {index} has no message object")
        user_message = _message(f"request:{index}:prompt", "user", prompt, "text", None, stamp)
        if user_message is not None:
            messages.append(user_message)
        reply = "".join(
            part["value"]
            for part in _dict_list(request.get("response", []), "response")
            if isinstance(part.get("value"), str)
        )
        if reply:
            messages.append(_Message(f"request:{index}:reply", "assistant", reply, stamp))
    return _Session(
        session_id if isinstance(session_id, str) else None,
        title if isinstance(title, str) else None,
        messages,
    )


def _transcript_message(index: int, entry: dict[str, Any]) -> _Message | None:
    body = entry.get("message")
    content = body.get("content") if isinstance(body, dict) else None
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        text = "".join(
            part["text"] for part in _dict_list(content, "content") if isinstance(part.get("text"), str)
        )
    else:
        raise TypeError("transcript line has no message content")
    if not text:
        return None
    return _Message(f"line:{index + 1}", _role(entry.get("role")), text, None)


class Plugin(PluginBase):
    name = "ide_assistants"
    version = "1.0"
    description = "Cursor, VS Code Copilot Chat, Windsurf and VSCodium chat state and Cursor agent transcripts"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for user in fs.users():
            root = _ROOTS.get(user.os_family)
            if root is not None:
                for app, tool in _APPS.items():
                    base = f"{root}/{app}/User"
                    for ref in _files(fs, user, f"{base}/globalStorage/state.vscdb"):
                        yield Candidate(ref, "global_state", user, {"tool": tool})
                    for ref in _files(fs, user, f"{base}/workspaceStorage/*/state.vscdb"):
                        yield Candidate(ref, "workspace_state", user, {"tool": tool})
                    for ref in _files(fs, user, f"{base}/workspaceStorage/*/chatSessions/*.json"):
                        yield Candidate(ref, "chat_session", user, {"tool": tool})
            for ref in _files(fs, user, ".cursor/projects/*/agent-transcripts/*.jsonl"):
                yield Candidate(ref, "agent_transcript", user, {"tool": "Cursor"})

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        tool = str(cand.extra["tool"])
        os_family = cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN
        workspace: str | None = None
        ws_dir = _workspace_dir(cand)
        if ws_dir is not None:
            try:
                workspace = _workspace_folder(ctx.fs, cand.ref.volume, ws_dir, os_family)
            except (ValueError, TypeError) as exc:
                yield self.warning(ctx, cand, f"workspace.json: {exc}")

        if cand.role == "agent_transcript":
            try:
                lines = ctx.fs.read_bytes(cand.ref).decode("utf-8").splitlines()
            except ValueError as exc:
                yield self.warning(ctx, cand, f"transcript is not UTF-8: {exc}")
                return
            messages: list[_Message] = []
            skipped = 0
            for index, line in enumerate(lines):
                if not line.strip():
                    continue
                try:
                    message = _transcript_message(index, _json_object(line))
                except (ValueError, TypeError):
                    skipped += 1
                    continue
                if message is not None:
                    messages.append(message)
            session_id = posixpath.splitext(posixpath.basename(cand.ref.path))[0]
            yield from self._emit(
                ctx,
                cand,
                [_Session(session_id, None, messages)],
                tool=tool,
                recovered_from="jsonl",
                workspace=workspace,
            )
            if skipped:
                yield self.warning(ctx, cand, f"{skipped} transcript lines were not parseable and were skipped")
            return

        if cand.role == "chat_session":
            try:
                sessions = [_vscode_session(_json_object(ctx.fs.read_bytes(cand.ref)))]
            except (ValueError, TypeError) as exc:
                yield self.warning(ctx, cand, f"chat session: {exc}")
                return
            yield from self._emit(ctx, cand, sessions, tool=tool, recovered_from="json", workspace=workspace)
            return

        try:
            kv = _read_state(ctx.fs, cand.ref)
        except sqlite3.DatabaseError as exc:
            yield self.warning(ctx, cand, f"cannot read state database: {exc}")
            return
        raw_bubbles = {key: value for key, value in kv.items() if key.startswith("bubbleId:")}
        for key in sorted(kv):
            try:
                sessions = _sessions_for(key, kv[key], raw_bubbles)
            except (ValueError, TypeError) as exc:
                yield self.warning(ctx, cand, f"{key}: {exc}")
                continue
            yield from self._emit(ctx, cand, sessions, tool=tool, recovered_from="sqlite", workspace=workspace)

    def _emit(
        self,
        ctx: ParseContext,
        cand: Candidate,
        sessions: list[_Session],
        *,
        tool: str,
        recovered_from: str,
        workspace: str | None,
    ) -> Iterator[Artifact | Event]:
        for session in sessions:
            for message in session.messages:
                data: dict[str, Any] = {
                    "tool": tool,
                    "session_id": session.session_id,
                    "role": message.role,
                    "text": message.text,
                    "fragment": False,
                    "recovered_from": recovered_from,
                }
                if workspace is not None:
                    data["workspace"] = workspace
                if session.title is not None:
                    data["title"] = session.title
                artifact = self.artifact(ctx, cand, ArtifactKind.AI_CHAT_MESSAGE, data, locator=message.locator)
                yield artifact
                ts = from_unix_ms(message.created_ms)
                yield self.event(
                    artifact,
                    ts,
                    "created" if ts is not None else "unknown",
                    EventCategory.AI_ACTIVITY,
                    _ACTORS.get(message.role, Actor.UNKNOWN),
                    f"{tool} {message.role}: {message.text[:80]}",
                    ts_basis="native_utc" if ts is not None else "unknown",
                )


PLUGIN = Plugin()
