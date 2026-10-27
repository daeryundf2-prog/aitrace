"""AI desktop applications: ChatGPT, Claude, Microsoft Copilot and Perplexity desktop clients.

Recovers what the apps leave behind: install-directory presence, LevelDB/IndexedDB chat remnants,
ChatGPT macOS v1 plaintext conversations, counts of encrypted (v2/v3) conversation stores, Claude
logs and the Claude Desktop MCP server configuration.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import basename
from aitrace.core.time import from_iso, from_local_naive, from_unix
from aitrace.fs.base import EntryRef, EvidenceFS, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase
from aitrace.plugins.common.leveldb import extract_text, iter_leveldb_records

CHATGPT = "ChatGPT Desktop"
CLAUDE = "Claude Desktop"
COPILOT = "Microsoft Copilot"
PERPLEXITY = "Perplexity"

_MAC_CHATGPT = "Library/Application Support/com.openai.chat"
_MAC_CLAUDE = "Library/Application Support/Claude"
_WIN_CHATGPT = "AppData/Local/Packages/OpenAI.ChatGPT-Desktop_*"
_WIN_CLAUDE = "AppData/Roaming/Claude"

APP_DIRS: tuple[tuple[str, str], ...] = (
    (CHATGPT, _WIN_CHATGPT),
    (CHATGPT, _MAC_CHATGPT),
    (CLAUDE, _WIN_CLAUDE),
    (CLAUDE, "AppData/Local/AnthropicClaude"),
    (CLAUDE, _MAC_CLAUDE),
    (COPILOT, "AppData/Local/Packages/Microsoft.Copilot_*"),
    (PERPLEXITY, "AppData/Local/Perplexity"),
    (PERPLEXITY, "AppData/Roaming/Perplexity"),
    (PERPLEXITY, "Library/Application Support/Perplexity"),
)

LEVELDB_DIRS: tuple[tuple[str, str], ...] = (
    (CHATGPT, _WIN_CHATGPT + "/LocalCache/Roaming/ChatGPT/IndexedDB/https_chatgpt.com_0.indexeddb.leveldb"),
    (CLAUDE, _WIN_CLAUDE + "/IndexedDB"),
    (CLAUDE, _WIN_CLAUDE + "/IndexedDB/*.leveldb"),
    (CLAUDE, _WIN_CLAUDE + "/Local Storage/leveldb"),
    (CLAUDE, _MAC_CLAUDE + "/IndexedDB"),
    (CLAUDE, _MAC_CLAUDE + "/IndexedDB/*.leveldb"),
    (CLAUDE, _MAC_CLAUDE + "/Local Storage/leveldb"),
)

V1_JSON_PATTERN = _MAC_CHATGPT + "/conversations-*/*.json"
ENCRYPTED_DIR_PATTERNS: tuple[str, ...] = (
    _MAC_CHATGPT + "/conversations-v2-*",
    _MAC_CHATGPT + "/conversations-v3-*",
)
LOG_PATTERNS: tuple[str, ...] = ("Library/Logs/Claude/*.log", _WIN_CLAUDE + "/logs/*.log")
CONFIG_PATTERNS: tuple[str, ...] = (
    _MAC_CLAUDE + "/claude_desktop_config.json",
    _WIN_CLAUDE + "/claude_desktop_config.json",
)

MIN_FRAGMENT_LEN = 40
CHAT_KEYS = ('"role"', '"author"', '"content"', '"parts"', '"conversation_id"')
_ROLE_ALIASES = {"human": "user", "ai": "assistant", "model": "assistant"}
_KNOWN_ROLES = frozenset({"user", "assistant", "system", "tool"})
_ACTOR_BY_ROLE = {
    "user": Actor.HUMAN,
    "assistant": Actor.AI,
    "system": Actor.SYSTEM,
    "tool": Actor.SYSTEM,
}
_LOG_TS = re.compile(r"^\[?(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
_CONFIDENCE_NOTE = (
    "text recovered heuristically from raw LevelDB values; ordering, completeness and "
    "authorship of the surrounding conversation are not guaranteed"
)
_FRAGMENT_NOTE = "unstructured text run containing a chat key; role could not be determined"


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _flatten(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(part for part in (_flatten(item) for item in content) if part)
    if isinstance(content, dict):
        for key in ("text", "parts", "content"):
            if key in content:
                return _flatten(content[key])
    return ""


def _normalize_role(raw: Any) -> str:
    if not isinstance(raw, str):
        return "unknown"
    lowered = _ROLE_ALIASES.get(raw.lower(), raw.lower())
    return lowered if lowered in _KNOWN_ROLES else "unknown"


def _role_and_text(obj: dict[str, Any]) -> tuple[str, str] | None:
    """(role, text) when `obj` looks like a chat message (role/author + content/parts)."""
    raw_role = obj.get("role")
    if raw_role is None:
        author = obj.get("author")
        raw_role = author.get("role") if isinstance(author, dict) else author
    content = obj.get("content", obj.get("parts"))
    if raw_role is None or content is None:
        return None
    text = _flatten(content)
    if not text.strip():
        return None
    return _normalize_role(raw_role), text


def _messages_in(obj: Any) -> Iterator[tuple[str, str]]:
    if isinstance(obj, list):
        for item in obj:
            yield from _messages_in(item)
    elif isinstance(obj, dict):
        found = _role_and_text(obj)
        if found is not None:
            yield found
            return
        for key in ("messages", "message"):
            if key in obj:
                yield from _messages_in(obj[key])


def _load_json(text: str) -> Any | None:
    """Parse `text` as JSON, tolerating binary framing bytes around one object/array."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start, end = text.find(opener), text.rfind(closer)
        if 0 <= start < end:
            try:
                return json.loads(text[start : end + 1])
            except ValueError:
                continue
    return None


def _log_timestamp(line: str, tz: str) -> tuple[datetime, str] | None:
    match = _LOG_TS.match(line)
    if match is None:
        return None
    day, clock, _, zone = match.groups()
    if zone is not None:
        parsed = from_iso(f"{day}T{clock}{'+00:00' if zone == 'Z' else zone}")
        return (parsed, "native_utc") if parsed is not None else None
    local = from_local_naive(datetime.fromisoformat(f"{day}T{clock}"), tz)
    return (local, f"assumed:{tz}") if local is not None else None


class Plugin(PluginBase):
    name = "ai.desktop_apps"
    version = "1.0"
    description = "ChatGPT, Claude, Copilot and Perplexity desktop apps: presence, chats, logs, MCP config"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        seen: set[tuple[str, str]] = set()

        def emit(ref: EntryRef, role: str, user: Any, tool: str) -> Iterator[Candidate]:
            key = (role, ref.path.casefold())
            if key not in seen:
                seen.add(key)
                yield Candidate(ref=ref, role=role, user=user, extra={"tool": tool})

        for user in fs.users():
            for tool, pattern in APP_DIRS:
                for ref in user_glob(fs, user, pattern):
                    if fs.is_dir(ref):
                        yield from emit(ref, "app_dir", user, tool)
            for tool, pattern in LEVELDB_DIRS:
                for ref in user_glob(fs, user, pattern):
                    if fs.is_dir(ref):
                        yield from emit(ref, "leveldb", user, tool)
            for ref in user_glob(fs, user, V1_JSON_PATTERN):
                if not fs.is_dir(ref):
                    yield from emit(ref, "v1_json", user, CHATGPT)
            for pattern in ENCRYPTED_DIR_PATTERNS:
                for ref in user_glob(fs, user, pattern):
                    if fs.is_dir(ref):
                        yield from emit(ref, "encrypted_store", user, CHATGPT)
            for pattern in LOG_PATTERNS:
                for ref in user_glob(fs, user, pattern):
                    if not fs.is_dir(ref):
                        yield from emit(ref, "log", user, CLAUDE)
            for pattern in CONFIG_PATTERNS:
                for ref in user_glob(fs, user, pattern):
                    if not fs.is_dir(ref):
                        yield from emit(ref, "config", user, CLAUDE)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        handlers = {
            "app_dir": self._parse_app_dir,
            "leveldb": self._parse_leveldb,
            "v1_json": self._parse_v1_json,
            "encrypted_store": self._parse_encrypted_store,
            "log": self._parse_log,
            "config": self._parse_config,
        }
        handler = handlers.get(cand.role)
        if handler is None:
            yield self.warning(ctx, cand, f"unknown candidate role {cand.role!r}")
            return
        try:
            yield from handler(ctx, cand)
        except OSError as exc:
            yield self.warning(ctx, cand, f"{cand.role} read failed: {exc}")

    def _presence(
        self,
        ctx: ParseContext,
        cand: Candidate,
        kind: str,
        status: str,
        detail: str,
        *,
        first: datetime | None = None,
        last: datetime | None = None,
        extra: dict[str, Any] | None = None,
        locator: str | None = None,
    ) -> Artifact:
        data: dict[str, Any] = {"tool": cand.extra["tool"], "kind": kind, "status": status, "detail": detail}
        if first is not None:
            data["first_seen"] = _iso(first)
        if last is not None:
            data["last_seen"] = _iso(last)
        if extra:
            data["extra"] = extra
        return self.artifact(ctx, cand, ArtifactKind.AI_APP_PRESENCE, data, locator=locator)

    def _parse_app_dir(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        yield self._presence(ctx, cand, "app", "present", f"application data directory {cand.ref.path}")

    def _chat(
        self,
        ctx: ParseContext,
        cand: Candidate,
        *,
        role: str,
        text: str,
        locator: str,
        recovered_from: str,
        session_id: str | None = None,
        title: str | None = None,
        fragment: bool = False,
        extra: dict[str, Any] | None = None,
        ts: datetime | None = None,
    ) -> Iterator[Artifact | Event]:
        data: dict[str, Any] = {
            "tool": cand.extra["tool"],
            "session_id": session_id,
            "role": role,
            "text": text,
            "fragment": fragment,
            "recovered_from": recovered_from,
        }
        if title:
            data["title"] = title
        if extra:
            data["extra"] = extra
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_CHAT_MESSAGE, data, locator=locator)
        yield artifact
        snippet = text if len(text) <= 80 else text[:77] + "..."
        yield self.event(
            artifact,
            ts,
            "message_created" if ts is not None else "unknown",
            EventCategory.AI_ACTIVITY,
            _ACTOR_BY_ROLE.get(role, Actor.UNKNOWN),
            f"{cand.extra['tool']} {role} message: {snippet}",
            ts_basis="native_utc" if ts is not None else "unknown",
        )

    def _parse_leveldb(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        seen: set[tuple[str, str, bool]] = set()
        for name, _key, value, seq in iter_leveldb_records(ctx.fs, cand.ref):
            for index, text in enumerate(extract_text(value)):
                loaded = _load_json(text)
                messages = list(_messages_in(loaded)) if loaded is not None else []
                locator = f"{name}:seq={seq}:{index}"
                if messages:
                    for sub, (role, body) in enumerate(messages):
                        if (role, body, False) in seen:
                            continue
                        seen.add((role, body, False))
                        yield from self._chat(
                            ctx,
                            cand,
                            role=role,
                            text=body,
                            locator=f"{locator}:{sub}",
                            recovered_from="leveldb",
                            extra={"confidence": "low", "note": _CONFIDENCE_NOTE},
                        )
                elif len(text) >= MIN_FRAGMENT_LEN and any(key in text for key in CHAT_KEYS):
                    if ("unknown", text, True) in seen:
                        continue
                    seen.add(("unknown", text, True))
                    yield from self._chat(
                        ctx,
                        cand,
                        role="unknown",
                        text=text,
                        locator=locator,
                        recovered_from="leveldb",
                        fragment=True,
                        extra={"confidence": "low", "note": _FRAGMENT_NOTE},
                    )

    def _parse_v1_json(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            doc = json.loads(ctx.fs.read_bytes(cand.ref).decode("utf-8"))
        except ValueError as exc:  # UnicodeDecodeError and JSONDecodeError are both ValueError
            yield self.warning(ctx, cand, f"ChatGPT v1 conversation is not valid JSON: {exc}")
            return
        mapping = doc.get("mapping") if isinstance(doc, dict) else None
        if not isinstance(mapping, dict):
            yield self.warning(ctx, cand, "ChatGPT v1 conversation has no 'mapping' object")
            return
        title = doc.get("title") if isinstance(doc.get("title"), str) else None
        session_id = basename(cand.ref.path).rsplit(".", 1)[0]
        rows: list[tuple[float | None, int, str, str, str, datetime | None]] = []
        for position, (node_id, node) in enumerate(mapping.items()):
            message = node.get("message") if isinstance(node, dict) else None
            if not isinstance(message, dict):
                continue
            found = _role_and_text(message)
            if found is None:
                continue
            created = message.get("create_time")
            stamp = float(created) if isinstance(created, int | float) else None
            rows.append((stamp, position, str(node_id), found[0], found[1], from_unix(stamp)))
        rows.sort(key=lambda row: (row[0] is None, row[0] if row[0] is not None else 0.0, row[1]))
        for _stamp, _position, node_id, role, text, ts in rows:
            yield from self._chat(
                ctx,
                cand,
                role=role,
                text=text,
                locator=f"node:{node_id}",
                recovered_from="json",
                session_id=session_id,
                title=title,
                ts=ts,
            )

    def _parse_encrypted_store(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        mtimes: list[datetime] = []
        count = 0
        for child in ctx.fs.listdir(cand.ref):
            if ctx.fs.is_dir(child):
                continue
            count += 1
            mtime = ctx.fs.stat(child).mtime
            if mtime is not None:
                mtimes.append(mtime)
        mtimes.sort()
        yield self._presence(
            ctx,
            cand,
            "store",
            "encrypted_not_decoded",
            f"{count} encrypted conversation file(s) in {basename(cand.ref.path)}; content not decoded",
            first=mtimes[0] if mtimes else None,
            last=mtimes[-1] if mtimes else None,
            extra={"count": count, "mtimes": [_iso(m) for m in mtimes]},
        )

    def _parse_log(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        stamps: list[tuple[datetime, str]] = []
        for line in text.splitlines():
            stamp = _log_timestamp(line, ctx.tz)
            if stamp is not None:
                stamps.append(stamp)
        if not stamps:
            yield self._presence(ctx, cand, "log", "present", f"{basename(cand.ref.path)}: no timestamped lines")
            return
        (first, first_basis), (last, last_basis) = stamps[0], stamps[-1]
        artifact = self._presence(
            ctx,
            cand,
            "log",
            "parsed",
            f"{basename(cand.ref.path)}: {len(stamps)} timestamped line(s)",
            first=first,
            last=last,
        )
        yield artifact
        tool = cand.extra["tool"]
        yield self.event(
            artifact, first, "log_first", EventCategory.AI_ACTIVITY, Actor.SYSTEM,
            f"{tool} log first entry", ts_basis=first_basis, index=0,
        )
        yield self.event(
            artifact, last, "log_last", EventCategory.AI_ACTIVITY, Actor.SYSTEM,
            f"{tool} log last entry", ts_basis=last_basis, index=1,
        )

    def _parse_config(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            doc = json.loads(ctx.fs.read_bytes(cand.ref).decode("utf-8"))
        except ValueError as exc:
            yield self.warning(ctx, cand, f"claude_desktop_config.json is not valid JSON: {exc}")
            return
        servers = doc.get("mcpServers") if isinstance(doc, dict) else None
        if not isinstance(servers, dict):
            yield self._presence(ctx, cand, "config", "present", "claude_desktop_config.json without mcpServers")
            return
        summary: dict[str, dict[str, Any]] = {}
        for server_name, spec in servers.items():
            entry = spec if isinstance(spec, dict) else {}
            # environment variables are deliberately dropped: they commonly carry API keys
            summary[str(server_name)] = {
                "command": entry.get("command"),
                "args": entry.get("args") if isinstance(entry.get("args"), list) else [],
            }
        names = ", ".join(summary) or "none"
        yield self._presence(
            ctx, cand, "config", "parsed", f"{len(summary)} MCP server(s): {names}",
            extra={"mcp_servers": summary},
        )


PLUGIN = Plugin()
