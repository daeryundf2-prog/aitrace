from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import basename, normalize
from aitrace.core.time import from_local_naive, from_unix_ms
from aitrace.fs.base import EvidenceFS, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

OLLAMA = "Ollama"
LM_STUDIO = "LM Studio"
JAN = "Jan"
GPT4ALL = "GPT4All"

USER_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("ollama_history", OLLAMA, ".ollama/history"),
    ("ollama_log", OLLAMA, ".ollama/logs/server*.log"),
    ("ollama_log", OLLAMA, "AppData/Local/Ollama/*.log"),
    ("ollama_manifest", OLLAMA, ".ollama/models/manifests/**"),
    ("lmstudio", LM_STUDIO, ".lmstudio/conversations/*.conversation.json"),
    ("lmstudio", LM_STUDIO, ".cache/lm-studio/conversations/**/*.json"),
    ("jan", JAN, "jan/threads/*/messages.jsonl"),
    ("jan", JAN, "Library/Application Support/Jan/data/threads/*/messages.jsonl"),
    ("gpt4all", GPT4ALL, "Library/Application Support/nomic.ai/GPT4All/*.gguf"),
    ("gpt4all", GPT4ALL, "AppData/Local/nomic.ai/GPT4All/*.gguf"),
    ("gpt4all", GPT4ALL, ".local/share/nomic.ai/GPT4All/*.gguf"),
)

SYSTEM_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("ollama_log", OLLAMA, "/usr/share/ollama/.ollama/logs/server*.log"),
    ("ollama_manifest", OLLAMA, "/usr/share/ollama/.ollama/models/manifests/**"),
)

_GIN_LINE = re.compile(
    r"\[GIN\] (\d{4}/\d{2}/\d{2}) - (\d{2}:\d{2}:\d{2}) \| (\d{3}) \|[^|]*\|\s*([^|\s]+)\s*\|"
    r'\s*(\w+)\s+"([^"]+)"'
)
_ROLES = frozenset({"user", "assistant", "system", "tool"})
_ACTORS: dict[str, Actor] = {
    "user": Actor.HUMAN,
    "assistant": Actor.AI,
    "system": Actor.SYSTEM,
    "tool": Actor.SYSTEM,
}


def _read_text(ctx: ParseContext, cand: Candidate) -> str:
    return ctx.fs.read_bytes(cand.ref).decode("utf-8")


def _role(value: object) -> str:
    return value if isinstance(value, str) and value in _ROLES else "unknown"


def _actor(role: str) -> Actor:
    return _ACTORS.get(role, Actor.UNKNOWN)


def _basis(ts: datetime | None, basis: str) -> str:
    return basis if ts is not None else "unknown"


def _epoch_ms(value: object) -> datetime | None:
    return from_unix_ms(float(value)) if isinstance(value, int | float) else None


def _jan_text(content: object) -> str | None:
    if not isinstance(content, list):
        return None
    parts: list[str] = []
    for item in content:
        if isinstance(item, dict) and isinstance(item.get("text"), dict):
            value = item["text"].get("value")
            if isinstance(value, str):
                parts.append(value)
    return "\n".join(parts)


def _lmstudio_message(message: dict[str, Any]) -> tuple[str, str] | None:
    selected: dict[str, Any] = message
    versions = message.get("versions")
    if isinstance(versions, list) and versions:
        index = message.get("currentlySelected")
        pick = index if isinstance(index, int) and 0 <= index < len(versions) else 0
        if isinstance(versions[pick], dict):
            selected = versions[pick]
    content = selected.get("content")
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        text = "\n".join(
            part["text"]
            for part in content
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str)
        )
    else:
        return None
    return _role(selected.get("role", message.get("role"))), text


class Plugin(PluginBase):
    name = "local_llm"
    version = "1.0"
    description = "Ollama, LM Studio, Jan and GPT4All: prompt history, server logs, models, conversations"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for user in fs.users():
            for role, tool, pattern in USER_PATTERNS:
                for ref in user_glob(fs, user, pattern):
                    if not fs.is_dir(ref):
                        yield Candidate(ref=ref, role=role, user=user, extra={"tool": tool})
        for volume in fs.volumes():
            for role, tool, pattern in SYSTEM_PATTERNS:
                for ref in fs.glob(volume.index, pattern):
                    if not fs.is_dir(ref):
                        yield Candidate(ref=ref, role=role, extra={"tool": tool})

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        handlers = {
            "ollama_history": self._history,
            "ollama_log": self._log,
            "ollama_manifest": self._manifest,
            "lmstudio": self._lmstudio,
            "jan": self._jan,
            "gpt4all": self._gpt4all,
        }
        handler = handlers.get(cand.role)
        if handler is None:
            yield self.warning(ctx, cand, f"unknown candidate role {cand.role!r}")
            return
        try:
            yield from handler(ctx, cand)
        except OSError as exc:
            yield self.warning(ctx, cand, f"{cand.role} read failed: {exc}")

    def _chat(
        self,
        ctx: ParseContext,
        cand: Candidate,
        *,
        locator: str,
        tool: str,
        role: str,
        text: str,
        session_id: str | None,
        ts: datetime | None,
        ts_basis: str,
        title: str | None = None,
    ) -> Iterator[Artifact | Event]:
        data: dict[str, Any] = {
            "tool": tool,
            "session_id": session_id,
            "role": role,
            "text": text,
            "fragment": False,
        }
        if title is not None:
            data["title"] = title
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_CHAT_MESSAGE, data, locator=locator)
        yield artifact
        summary = f"{tool} {role}: {text[:80]}"
        yield self.event(
            artifact, ts, "message", EventCategory.AI_ACTIVITY, _actor(role), summary, ts_basis=ts_basis
        )

    def _history(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            text = _read_text(ctx, cand)
        except UnicodeDecodeError as exc:
            yield self.warning(ctx, cand, f"history is not UTF-8: {exc}")
            return
        for number, line in enumerate(text.splitlines(), start=1):
            prompt = line.strip()
            if prompt:
                yield from self._chat(
                    ctx,
                    cand,
                    locator=f"line:{number}",
                    tool=OLLAMA,
                    role="user",
                    text=prompt,
                    session_id=None,
                    ts=None,
                    ts_basis="unknown",
                )

    def _log(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            text = _read_text(ctx, cand)
        except UnicodeDecodeError as exc:
            yield self.warning(ctx, cand, f"log is not UTF-8: {exc}")
            return
        presence = {
            "tool": cand.extra["tool"],
            "kind": "log",
            "status": "present",
            "path": normalize(cand.ref.path, OsFamily.UNKNOWN),
        }
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_APP_PRESENCE, presence, locator="log")
        yield artifact
        for number, line in enumerate(text.splitlines(), start=1):
            match = _GIN_LINE.search(line)
            if match is None:
                continue
            date, clock, status, client, method, endpoint = match.groups()
            try:
                naive = datetime.strptime(f"{date} {clock}", "%Y/%m/%d %H:%M:%S")
            except ValueError as exc:
                yield self.warning(ctx, cand, f"log line {number}: invalid timestamp: {exc}")
                continue
            ts = from_local_naive(naive, ctx.tz)
            yield self.event(
                artifact,
                ts,
                "request",
                EventCategory.AI_ACTIVITY,
                Actor.UNKNOWN,
                f"{method} {endpoint} -> {status} from {client}",
                ts_basis=_basis(ts, f"assumed:{ctx.tz}"),
                subject=endpoint,
                data={"status": status, "method": method, "endpoint": endpoint, "client": client},
                index=number,
            )

    def _model(
        self, ctx: ParseContext, cand: Candidate, name: str, size: int | None
    ) -> Iterator[Artifact | Event]:
        data: dict[str, Any] = {"tool": cand.extra["tool"], "model_name": name}
        if size is not None:
            data["size"] = size
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_MODEL, data)
        yield artifact
        mtime = ctx.fs.stat(cand.ref).mtime
        if mtime is not None:
            yield self.event(
                artifact,
                mtime,
                "mtime",
                EventCategory.AI_ACTIVITY,
                Actor.UNKNOWN,
                f"{name} model file last modified",
                ts_basis="native_utc",
            )

    def _manifest(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            manifest = json.loads(ctx.fs.read_bytes(cand.ref))
        except ValueError as exc:
            yield self.warning(ctx, cand, f"corrupt manifest JSON: {exc}")
            return
        layers = manifest.get("layers") if isinstance(manifest, dict) else None
        if not isinstance(layers, list):
            yield self.warning(ctx, cand, "schema_mismatch: manifest has no layers list")
            return
        _, _, relative = cand.ref.path.partition("/manifests/")
        parts = relative.split("/")
        if len(parts) != 4:
            yield self.warning(ctx, cand, f"unexpected manifest path layout: {relative!r}")
            return
        _registry, namespace, model, tag = parts
        name = f"{model}:{tag}" if namespace == "library" else f"{namespace}/{model}:{tag}"
        sizes = [
            layer["size"] for layer in layers if isinstance(layer, dict) and isinstance(layer.get("size"), int)
        ]
        yield from self._model(ctx, cand, name, sum(sizes) if sizes else None)

    def _gpt4all(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        yield from self._model(ctx, cand, basename(cand.ref.path), ctx.fs.stat(cand.ref).size)

    def _lmstudio(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            conversation = json.loads(ctx.fs.read_bytes(cand.ref))
        except ValueError as exc:
            yield self.warning(ctx, cand, f"corrupt conversation JSON: {exc}")
            return
        messages = conversation.get("messages") if isinstance(conversation, dict) else None
        if not isinstance(messages, list):
            yield self.warning(ctx, cand, "schema_mismatch: conversation has no messages list")
            return
        title = conversation.get("name")
        session = basename(cand.ref.path)
        for index, message in enumerate(messages):
            parsed = _lmstudio_message(message) if isinstance(message, dict) else None
            if parsed is None:
                yield self.warning(ctx, cand, f"schema_mismatch: message {index} has no readable content")
                continue
            role, text = parsed
            yield from self._chat(
                ctx,
                cand,
                locator=f"message:{index}",
                tool=LM_STUDIO,
                role=role,
                text=text,
                session_id=session,
                ts=None,
                ts_basis="unknown",
                title=title if isinstance(title, str) else None,
            )

    def _jan(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            text = _read_text(ctx, cand)
        except UnicodeDecodeError as exc:
            yield self.warning(ctx, cand, f"thread is not UTF-8: {exc}")
            return
        session = cand.ref.path.split("/")[-2]
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError as exc:
                yield self.warning(ctx, cand, f"corrupt JSON at line {number}: {exc}")
                continue
            if not isinstance(entry, dict):
                yield self.warning(ctx, cand, f"schema_mismatch: line {number} is not an object")
                continue
            role = entry.get("role")
            body = _jan_text(entry.get("content"))
            if not isinstance(role, str) or body is None:
                yield self.warning(ctx, cand, f"schema_mismatch: line {number} lacks role or content")
                continue
            if not body.strip():
                continue
            ts = _epoch_ms(entry.get("created_at"))
            yield from self._chat(
                ctx,
                cand,
                locator=f"line:{number}",
                tool=JAN,
                role=_role(role),
                text=body,
                session_id=session,
                ts=ts,
                ts_basis=_basis(ts, "native_utc"),
            )


PLUGIN = Plugin()
