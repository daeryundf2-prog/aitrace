"""Extracted Hermes Agent material copied into an arbitrary directory tree.

Inputs are found by file name and a cheap first-line content signature anywhere in the tree, never by a
user-home layout: prompt export markdown, A2A conversation JSONL, kanban.db, cron job files and stores,
instruction files (SOUL/RULES/AGENTS/MEMORY/skills/templates), shell histories and credential files.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import posixpath
import re
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from aitrace.core.catalog import redact
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.time import from_iso, from_local_naive, from_unix, from_unix_ms
from aitrace.fs.base import EntryRef, EvidenceFS
from aitrace.plugins.ai.hermes import _secrets
from aitrace.plugins.base import Candidate, ParseContext, PluginBase
from aitrace.plugins.shell import history

TOOL = "Hermes Agent"
EXPORT_TZ = "Asia/Seoul"
EXPORT_TZ_ENV = "AITRACE_EXPORT_TZ"
MAX_OPEN_BYTES = 64 * 1024 * 1024
MAX_TEXT_CHARS = 400_000
_SNIFF_BYTES = 1024
_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__"})
_WAL_VERSIONS = b"\x02\x02"
_LEGACY_VERSIONS = b"\x01\x01"

_USER_EXPORT = re.compile(r"^# \[(?P<machine>[^\]]+)\] .*사용자 직접 입력 프롬프트")
_SYSTEM_EXPORT = re.compile(r"^# \[(?P<machine>[^\]]+)\] 시스템 프롬프트")
_USER_ENTRY = re.compile(
    r"^### \[(?P<num>\d+)\] `(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)` \| 세션 `(?P<sid>[^`]*)` \| "
    r"채널 `(?P<ch>[^`]*)` \| 메시지ID `(?P<mid>[^`]*)` \(`(?P<n>[\d,]+)자`\)\s*$"
)
_SYSTEM_ENTRY = re.compile(
    r"^## \[(?P<num>\d+)\] 해시 `(?P<hash>[^`]*)` \(글자수: `(?P<n>[\d,]+)자`, 세션수: `(?P<k>[\d,]+)회`, "
    r"기간: `(?P<a>[^`]*)` ~ `(?P<b>[^`]*)`\)\s*$"
)
_USER_ENTRY_START = "### ["
_SYSTEM_ENTRY_START = "## ["
_MODEL_LINE = re.compile(r"^- \*\*사용 모델\*\*: `(?P<model>[^`]*)`")
_ORIGIN_LINE = re.compile(r"^- \*\*원본 DB\*\*: `(?P<db>[^`]*)`")
_FENCE = re.compile(r"^(?P<fence>`{3,}|~{3,})[^`]*$")
_OOB_OPEN = "[OUT-OF-BAND USER MESSAGE"
_OOB_CLOSE = "[/OUT-OF-BAND USER MESSAGE]"
_GATEWAY_LINE = "Gateway message origin (JSON"
_GATEWAY_KEYS = ("platform", "chat_type")

_TS_FULL = re.compile(r"(?<!\d)(\d{8})_(\d{6})(?!\d)")
_TS_MINUTE = re.compile(r"(?<!\d)(\d{8})_(\d{4})(?!\d)")
_TS_DATE = re.compile(r"(?<!\d)(20\d{6})(?!\d)")

_SOUL = re.compile(r"^(?:.*[_.])?SOUL(?:\.[^/]*)?\.md(?:\.bak.*)?$")
_TEMPLATE = re.compile(r"^.+\.md\.tmpl(?:\.bak.*)?$")
_CRON_JOBS = re.compile(r"^(?:jobs\.json(?:\.bak.*)?|.+_jobs\.json)$")
_CRON_PROMPT = re.compile(r"^prompt_.*\.txt$")
_GATEWAY_RECEIPTS = re.compile(r"^telegram_update_receipts_.*\.json$")
_A2A_NOTES = re.compile(r"^_?a2a_.*\.md$")
_HERMES_DIRS = frozenset({"hermes_dot", ".hermes", "hermes_root"})
_HISTORY_SHELLS = {".bash_history": "bash", ".zsh_history": "zsh", ".python_history": "python"}

_A2A_ROLES = {
    "user": "user",
    "human": "user",
    "assistant": "assistant",
    "agent": "assistant",
    "system": "system",
}
_ACTORS = {"user": Actor.HUMAN, "assistant": Actor.AI, "system": Actor.SYSTEM}
_HUMAN_AUTHORS = frozenset({"user", "human"})
_EXECUTION_COLUMNS = ("id", "job_id", "status", "source", "started_at", "claimed_at", "finished_at")
_TASK_COLUMNS = (
    "id",
    "title",
    "body",
    "assignee",
    "status",
    "created_by",
    "created_at",
    "completed_at",
    "result",
    "model_override",
    "session_id",
)


def export_tz() -> str:
    """Zone of the export wall-clock times; AITRACE_EXPORT_TZ overrides the Asia/Seoul default."""
    return os.environ.get(EXPORT_TZ_ENV) or EXPORT_TZ


def scrub(text: str) -> str:
    for _, secret in _secrets(text):
        text = text.replace(secret, redact(secret))
    return text


def _summary(text: str) -> str:
    stripped = text.strip()
    return stripped.splitlines()[0][:120] if stripped else ""


def _iso(ts: datetime | None) -> str | None:
    return None if ts is None else ts.isoformat().replace("+00:00", "Z")


def _local(text: str, tz: str) -> datetime | None:
    try:
        naive = datetime.strptime(text.strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return from_local_naive(naive, tz)


def _name_ts(name: str, tz: str) -> datetime | None:
    """Wall time embedded in a backup/version file name, read in the export zone."""
    for pattern, fmt in ((_TS_FULL, "%Y%m%d%H%M%S"), (_TS_MINUTE, "%Y%m%d%H%M")):
        match = pattern.search(name)
        if match is not None:
            try:
                return from_local_naive(datetime.strptime(match.group(1) + match.group(2), fmt), tz)
            except ValueError:
                continue
    match = _TS_DATE.search(name)
    if match is not None:
        try:
            return from_local_naive(datetime.strptime(match.group(1), "%Y%m%d"), tz)
        except ValueError:
            return None
    return None


def _epoch(value: Any) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return from_unix_ms(value) if value > 1e11 else from_unix(value)


def _text_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _count(text: str) -> int:
    return int(text.replace(",", ""))


def _instruction_kind(path: str) -> str | None:
    name = posixpath.basename(path)
    parts = path.split("/")
    if _SOUL.match(name):
        return "persona"
    if name == "RULES.yaml":
        return "rules"
    if name in ("MEMORY.md", "USER.md"):
        return "memory"
    if name in ("AGENTS.md", "CLAUDE.md") or name.endswith(("__AGENTS.md", "__CLAUDE.md")):
        return "workspace_instruction"
    if name == "SKILL.md" and "skills" in parts[:-1]:
        return "skill"
    if _TEMPLATE.match(name):
        return "template"
    return None


def _layout_kind(parts: list[str], name: str) -> str | None:
    dirs = parts[:-1]
    if name in ("channel_directory.json", "gateway_state.json") or _GATEWAY_RECEIPTS.match(name):
        return "gateway_state"
    if _A2A_NOTES.match(name) and any(d in _HERMES_DIRS for d in dirs):
        return "a2a_notes"
    if "soul_repo" in dirs:
        if dirs[-1] == "machines" and (name.endswith(".yaml") or ".yaml.bak" in name):
            return "soul_machine_config"
        if name.endswith(".py"):
            return "soul_build_script"
    return None


def _is_backup(name: str) -> bool:
    return ".bak" in name


@dataclass(slots=True)
class _Found:
    singles: list[Candidate] = field(default_factory=list)
    instructions: list[EntryRef] = field(default_factory=list)
    cron_jobs: list[EntryRef] = field(default_factory=list)
    secrets: list[Candidate] = field(default_factory=list)


class _HistoryEmitter(history.Plugin):
    name = "hermes_export"


class Plugin(PluginBase):
    name = "hermes_export"
    version = "1.0"
    description = (
        "Extracted Hermes Agent material anywhere in a tree: prompt exports, A2A JSONL, kanban, cron, "
        "instruction files, shell histories"
    )

    def __init__(self) -> None:
        self._shell = _HistoryEmitter()
        self._shell.version = self.version

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for volume in fs.volumes():
            found = _Found()
            for ref in fs.walk(EntryRef(volume.index, "/"), skip_names=_SKIP_DIRS):
                self._classify(fs, ref, found)
            yield from found.singles
            if found.instructions:
                yield Candidate(
                    ref=found.instructions[0], role="instructions", extra={"refs": found.instructions}
                )
            if found.cron_jobs:
                yield Candidate(ref=found.cron_jobs[0], role="cron_jobs", extra={"refs": found.cron_jobs})
            if found.singles or found.instructions or found.cron_jobs:
                yield from found.secrets

    def _classify(self, fs: EvidenceFS, ref: EntryRef, found: _Found) -> None:
        path = ref.path
        name = posixpath.basename(path)
        parts = path.split("/")
        if name in ("kanban.db", "executions.db", "deliveries.db"):
            role = {
                "kanban.db": "kanban",
                "executions.db": "cron_executions",
                "deliveries.db": "cron_deliveries",
            }
            found.singles.append(Candidate(ref=ref, role=role[name]))
            return
        if name in _HISTORY_SHELLS:
            found.singles.append(Candidate(ref=ref, role="shell", extra={"shell": _HISTORY_SHELLS[name]}))
            return
        if name in ("auth.json", ".env", "config.yaml"):
            found.secrets.append(Candidate(ref=ref, role="auth" if name == "auth.json" else "config"))
            return
        layout = _layout_kind(parts, name)
        if layout is not None:
            found.singles.append(Candidate(ref=ref, role="layout_file", extra={"source_kind": layout}))
            return
        kind = _instruction_kind(path)
        if kind is not None:
            if self._small(fs, ref):
                found.instructions.append(ref)
            return
        if _CRON_JOBS.match(name):
            if self._small(fs, ref):
                found.cron_jobs.append(ref)
            return
        if _CRON_PROMPT.match(name) and "output" in parts and "cron" in parts:
            if self._small(fs, ref):
                found.singles.append(Candidate(ref=ref, role="cron_prompt"))
            return
        lowered = name.lower()
        if lowered.endswith(".jsonl"):
            is_a2a = "a2a_conversations" in parts[:-1] or self._sniff_a2a(fs, ref)
            if is_a2a and self._small(fs, ref):
                found.singles.append(Candidate(ref=ref, role="a2a"))
            return
        if lowered.endswith(".md") and self._small(fs, ref):
            first = self._first_line(fs, ref)
            if _USER_EXPORT.match(first):
                found.singles.append(Candidate(ref=ref, role="export_user"))
            elif _SYSTEM_EXPORT.match(first):
                found.singles.append(Candidate(ref=ref, role="export_system"))

    @staticmethod
    def _small(fs: EvidenceFS, ref: EntryRef) -> bool:
        size = fs.stat(ref).size
        return size is not None and 0 < size <= MAX_OPEN_BYTES

    @staticmethod
    def _first_line(fs: EvidenceFS, ref: EntryRef) -> str:
        head = fs.read_bytes(ref, _SNIFF_BYTES)
        return head.split(b"\n", 1)[0].decode("utf-8", errors="replace").lstrip("\ufeff").rstrip("\r")

    def _sniff_a2a(self, fs: EvidenceFS, ref: EntryRef) -> bool:
        if not self._small(fs, ref):
            return False
        try:
            rec = json.loads(self._first_line(fs, ref))
        except json.JSONDecodeError:
            return False
        return (
            isinstance(rec, dict)
            and isinstance(rec.get("ts"), int | float)
            and isinstance(rec.get("role"), str)
            and isinstance(rec.get("text"), str)
        )

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        match cand.role:
            case "export_user":
                yield from self._export_user(ctx, cand)
            case "export_system":
                yield from self._export_system(ctx, cand)
            case "a2a":
                yield from self._a2a(ctx, cand)
            case "kanban":
                yield from self._kanban(ctx, cand)
            case "cron_jobs":
                yield from self._cron_jobs(ctx, cand)
            case "cron_executions":
                yield from self._cron_executions(ctx, cand)
            case "cron_deliveries":
                yield from self._cron_deliveries(ctx, cand)
            case "cron_prompt":
                yield from self._cron_prompt(ctx, cand)
            case "instructions":
                yield from self._instructions(ctx, cand)
            case "shell":
                yield from self._shell_history(ctx, cand)
            case "layout_file":
                yield from self._layout_file(ctx, cand)
            case "auth":
                yield from self._auth(ctx, cand)
            case "config":
                yield from self._config(ctx, cand)
            case _:
                raise ValueError(f"unknown hermes_export candidate role {cand.role!r}")

    def _message(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        *,
        role: str,
        text: str,
        session_id: str | None,
        ts: datetime | None,
        ts_basis: str,
        extra: dict[str, Any],
        model: str | None = None,
        title: str | None = None,
        recovered_from: str | None = None,
        ref: EntryRef | None = None,
        ts_kind: str = "message",
    ) -> Iterator[Artifact | Event]:
        data: dict[str, Any] = {
            "tool": TOOL,
            "session_id": session_id,
            "role": role,
            "text": scrub(text),
            "fragment": False,
        }
        if model:
            data["model"] = model
        if title:
            data["title"] = scrub(title)
        if recovered_from is not None:
            data["recovered_from"] = recovered_from
        data["extra"] = extra
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_CHAT_MESSAGE, data, locator=locator, ref=ref)
        yield artifact
        yield self.event(
            artifact,
            ts,
            ts_kind,
            EventCategory.AI_ACTIVITY,
            _ACTORS.get(role, Actor.UNKNOWN),
            _summary(data["text"]),
            ts_basis=ts_basis if ts is not None else "unknown",
        )

    def _presence(
        self,
        ctx: ParseContext,
        cand: Candidate,
        kind: str,
        status: str,
        detail: str,
        stamps: Iterable[datetime] = (),
        extra: dict[str, Any] | None = None,
    ) -> Artifact:
        data: dict[str, Any] = {"tool": TOOL, "kind": kind, "status": status, "detail": detail}
        ordered = sorted(stamps)
        if ordered:
            data["first_seen"] = _iso(ordered[0])
            data["last_seen"] = _iso(ordered[-1])
        if extra:
            data["extra"] = extra
        return self.artifact(ctx, cand, ArtifactKind.AI_APP_PRESENCE, data, locator="presence")

    def _instruction(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        *,
        kind: str,
        text: str,
        ts: datetime | None,
        ts_kind: str,
        ts_basis: str,
        extra: dict[str, Any],
    ) -> Iterator[Artifact | Event]:
        scrubbed = scrub(text)
        data: dict[str, Any] = {
            "tool": TOOL,
            "kind": kind,
            "status": "parsed",
            "detail": f"{extra['source_kind']}: {cand.ref.path}",
            "text": scrubbed,
            "session_id": None,
            "extra": {"role": "system", **extra},
        }
        if ts is not None:
            data["first_seen"] = _iso(ts)
        artifact = self.artifact(ctx, cand, ArtifactKind.AI_APP_PRESENCE, data, locator=locator)
        yield artifact
        yield self.event(
            artifact,
            ts,
            ts_kind,
            EventCategory.AI_ACTIVITY,
            Actor.SYSTEM,
            f"{TOOL} {extra['source_kind']}: {_summary(scrubbed)}",
            ts_basis=ts_basis if ts is not None else "unknown",
        )

    def _file_presence(
        self, ctx: ParseContext, cand: Candidate, kind: str, detail: str, extra: dict[str, Any]
    ) -> Iterator[Artifact | Event]:
        mtime = ctx.fs.stat(cand.ref).mtime
        artifact = self._presence(
            ctx,
            cand,
            kind,
            "present",
            detail,
            [mtime] if mtime is not None else [],
            {**extra, "ts_kind": "file_mtime"},
        )
        yield artifact
        yield self.event(
            artifact,
            mtime,
            "file_mtime",
            EventCategory.CONFIG,
            Actor.SYSTEM,
            f"{TOOL} {extra['source_kind']}: {posixpath.basename(cand.ref.path)}",
            ts_basis="native_utc" if mtime is not None else "unknown",
        )

    def _layout_file(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        source_kind: str = cand.extra["source_kind"]
        st = ctx.fs.stat(cand.ref)
        kind = "config" if source_kind == "soul_machine_config" else "store"
        yield from self._file_presence(
            ctx, cand, kind, f"{cand.ref.path}: {st.size} bytes", {"source_kind": source_kind}
        )

    def _lines(self, ctx: ParseContext, cand: Candidate) -> Iterator[tuple[int, str]]:
        with ctx.fs.open(cand.ref) as raw, io.TextIOWrapper(raw, encoding="utf-8", errors="replace") as text:
            for number, line in enumerate(text, start=1):
                yield number, line.rstrip("\n").rstrip("\r")

    def _fenced_entries(
        self, ctx: ParseContext, cand: Candidate, header: re.Pattern[str], start: str
    ) -> Iterator[tuple[str, Any, int, str | None, str | None]]:
        lines = self._lines(ctx, cand)
        current: re.Match[str] | None = None
        current_line = 0
        model: str | None = None
        origin: str | None = None
        for number, line in lines:
            if number == 1:
                continue
            if current is None:
                if line.startswith(start):
                    current = header.match(line)
                    current_line = number
                    model = None
                    if current is None:
                        yield "bad", "malformed entry header", number, None, None
                elif origin is None:
                    origin_match = _ORIGIN_LINE.match(line)
                    if origin_match is not None:
                        origin = origin_match.group("db")
                        yield "origin", origin, number, None, None
                continue
            model_match = _MODEL_LINE.match(line)
            if model_match is not None:
                model = model_match.group("model")
                continue
            fence = _FENCE.match(line)
            if fence is None:
                if line.startswith(start):
                    yield "bad", "entry without fenced text block", current_line, None, None
                    current = header.match(line)
                    current_line = number
                    model = None
                    if current is None:
                        yield "bad", "malformed entry header", number, None, None
                continue
            marker = fence.group("fence")
            body: list[str] = []
            closed = False
            for _, inner in lines:
                if inner.rstrip() == marker:
                    closed = True
                    break
                body.append(inner)
            if not closed:
                yield "bad", "unterminated fenced block", current_line, None, None
                return
            yield "entry", current, current_line, model, "\n".join(body)
            current = None

    def _export_user(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        tz = export_tz()
        machine = _USER_EXPORT.match(self._first_line(ctx.fs, cand.ref))
        machine_name = machine.group("machine") if machine is not None else None
        origin: str | None = None
        count = 0
        bad: list[tuple[int, str]] = []
        stamps: list[datetime] = []
        for kind, value, number, _, text in self._fenced_entries(ctx, cand, _USER_ENTRY, _USER_ENTRY_START):
            if kind == "origin":
                origin = value
                continue
            if kind == "bad":
                bad.append((number, value))
                continue
            entry: re.Match[str] = value
            body = text or ""
            ts = _local(entry.group("ts"), tz)
            if ts is not None:
                stamps.append(ts)
            extra: dict[str, Any] = {
                "source_kind": "export_user_prompt",
                "machine": machine_name,
                "channel": entry.group("ch"),
                "message_id": entry.group("mid"),
                "entry": entry.group("num"),
                "declared_chars": _count(entry.group("n")),
                "ts_assumed_tz": tz,
            }
            if origin is not None:
                extra["origin_db"] = origin
            inner, gateway, wrapped = _unwrap_oob(body)
            if wrapped:
                extra["raw_chars"] = len(body)
                extra["out_of_band"] = True
                if gateway is not None:
                    extra["gateway"] = gateway
            count += 1
            yield from self._message(
                ctx,
                cand,
                f"entry:{entry.group('num')}:line:{number}",
                role="user",
                text=inner,
                session_id=entry.group("sid") or None,
                ts=ts,
                ts_basis=f"assumed:{tz}",
                extra=extra,
                recovered_from="markdown",
            )
        yield from self._bad_entries(ctx, cand, bad)
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{count} user prompt(s) in export {cand.ref.path}",
            stamps,
            {"source_kind": "export_user_prompt", "machine": machine_name, "messages": count},
        )

    def _export_system(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        tz = export_tz()
        machine = _SYSTEM_EXPORT.match(self._first_line(ctx.fs, cand.ref))
        machine_name = machine.group("machine") if machine is not None else None
        origin: str | None = None
        count = 0
        bad: list[tuple[int, str]] = []
        stamps: list[datetime] = []
        entries = self._fenced_entries(ctx, cand, _SYSTEM_ENTRY, _SYSTEM_ENTRY_START)
        for kind, value, number, model, text in entries:
            if kind == "origin":
                origin = value
                continue
            if kind == "bad":
                bad.append((number, value))
                continue
            entry: re.Match[str] = value
            ts = _local(entry.group("a"), tz)
            end = _local(entry.group("b"), tz)
            if ts is not None:
                stamps.append(ts)
            extra: dict[str, Any] = {
                "source_kind": "export_system_prompt",
                "machine": machine_name,
                "hash": entry.group("hash"),
                "entry": entry.group("num"),
                "declared_chars": _count(entry.group("n")),
                "sessions": _count(entry.group("k")),
                "period_end": _iso(end),
                "ts_assumed_tz": tz,
            }
            if origin is not None:
                extra["origin_db"] = origin
            if model:
                extra["model"] = model
            count += 1
            yield from self._instruction(
                ctx,
                cand,
                f"entry:{entry.group('num')}:line:{number}",
                kind="instruction",
                text=text or "",
                ts=ts,
                ts_kind="first_seen",
                ts_basis=f"assumed:{tz}",
                extra=extra,
            )
        yield from self._bad_entries(ctx, cand, bad)
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{count} system prompt(s) in export {cand.ref.path}",
            stamps,
            {"source_kind": "export_system_prompt", "machine": machine_name, "messages": count},
        )

    def _bad_entries(
        self, ctx: ParseContext, cand: Candidate, bad: list[tuple[int, str]]
    ) -> Iterator[Artifact]:
        if bad:
            lines = ", ".join(str(n) for n, _ in bad[:10])
            kinds = sorted({m for _, m in bad})
            yield self.warning(
                ctx, cand, f"skipped {len(bad)} malformed entr(ies) ({'; '.join(kinds)}) at line(s) {lines}"
            )

    def _a2a(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        session_id = posixpath.basename(cand.ref.path).rsplit(".", 1)[0]
        bad = 0
        count = 0
        stamps: list[datetime] = []
        for number, line in self._lines(ctx, cand):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if (
                not isinstance(rec, dict)
                or not isinstance(rec.get("role"), str)
                or not isinstance(rec.get("text"), str)
            ):
                bad += 1
                continue
            raw_role = rec["role"]
            role = _A2A_ROLES.get(raw_role.lower(), "unknown")
            ts = _epoch(rec.get("ts"))
            if ts is not None:
                stamps.append(ts)
            extra: dict[str, Any] = {"source_kind": "a2a", "channel": "a2a"}
            if role != raw_role:
                extra["raw_role"] = raw_role
            if rec.get("task_id") is not None:
                extra["task_id"] = str(rec["task_id"])
            count += 1
            yield from self._message(
                ctx,
                cand,
                f"line:{number}",
                role=role,
                text=rec["text"],
                session_id=session_id,
                ts=ts,
                ts_basis="native_utc",
                extra=extra,
                recovered_from="jsonl",
            )
        if bad:
            yield self.warning(ctx, cand, f"skipped {bad} malformed record(s)")
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{count} A2A message(s) in {cand.ref.path}",
            stamps,
            {"source_kind": "a2a", "messages": count},
        )

    def _open_db(self, ctx: ParseContext, cand: Candidate) -> sqlite3.Connection | None:
        data = ctx.fs.read_bytes(cand.ref)
        if not data:
            return None
        if data[18:20] == _WAL_VERSIONS:
            # sqlite3 deserialize cannot open a WAL-mode image; header bytes 18-19 = 1 selects rollback mode.
            data = data[:18] + _LEGACY_VERSIONS + data[20:]
        conn = sqlite3.connect(":memory:")
        conn.deserialize(data)
        return conn

    def _db_tables(self, conn: sqlite3.Connection) -> dict[str, list[str]]:
        names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        return {n: [str(c[1]) for c in conn.execute(f'PRAGMA table_info("{n}")')] for n in names}

    def _db_failed(self, ctx: ParseContext, cand: Candidate, exc: Exception, kind: str) -> Iterator[Artifact]:
        yield self.warning(ctx, cand, f"cannot read SQLite database: {exc}")
        yield self._presence(
            ctx,
            cand,
            "store",
            "present",
            f"{cand.ref.path} present but not parsed",
            extra={"source_kind": kind},
        )

    def _kanban(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            conn = self._open_db(ctx, cand)
            if conn is None:
                yield self._presence(ctx, cand, "store", "present", f"{cand.ref.path} is empty")
                return
        except sqlite3.DatabaseError as exc:
            yield from self._db_failed(ctx, cand, exc, "kanban")
            return
        try:
            try:
                tables = self._db_tables(conn)
                rows = list(self._kanban_rows(conn, tables))
            except sqlite3.DatabaseError as exc:
                yield from self._db_failed(ctx, cand, exc, "kanban")
                return
        finally:
            conn.close()
        if "tasks" not in tables:
            yield self.warning(ctx, cand, "schema_mismatch: no tasks table found")
            yield self._presence(ctx, cand, "store", "present", f"{cand.ref.path} present but not parsed")
            return
        counts: dict[str, int] = {}
        stamps: list[datetime] = []
        for row in rows:
            counts[row["record"]] = counts.get(row["record"], 0) + 1
            if row["ts"] is not None:
                stamps.append(row["ts"])
            yield from self._message(
                ctx,
                cand,
                row["locator"],
                role=row["role"],
                text=row["text"],
                session_id=row["session"],
                ts=row["ts"],
                ts_basis="native_utc",
                extra={"source_kind": "kanban", "kanban_record": row["record"], **row["extra"]},
                model=row["model"],
                title=row["title"],
                recovered_from="sqlite",
            )
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"kanban board {cand.ref.path}: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())),
            stamps,
            {"source_kind": "kanban", "counts": counts},
        )

    @staticmethod
    def _kanban_rows(conn: sqlite3.Connection, tables: dict[str, list[str]]) -> Iterator[dict[str, Any]]:
        def select(table: str, wanted: tuple[str, ...]) -> Iterator[dict[str, Any]]:
            cols = [c for c in wanted if c in tables.get(table, [])]
            if not cols:
                return
            sql = "SELECT " + ", ".join(f'"{c}"' for c in cols) + f' FROM "{table}" ORDER BY rowid'
            for values in conn.execute(sql):
                yield dict(zip(cols, values, strict=True))

        for task in select("tasks", _TASK_COLUMNS):
            tid = str(task.get("id"))
            extra: dict[str, Any] = {
                "task_id": tid,
                "assignee": task.get("assignee"),
                "created_by": task.get("created_by"),
                "status": task.get("status"),
            }
            if task.get("session_id"):
                extra["hermes_session_id"] = str(task["session_id"])
            title = _text_or_none(task.get("title"))
            model = _text_or_none(task.get("model_override"))
            base = {"session": tid, "model": model, "title": title}
            yield base | {
                "locator": f"row:tasks.id={tid}:body",
                "record": "task",
                "role": "user",
                "text": _text_or_none(task.get("body")) or title or "",
                "ts": _epoch(task.get("created_at")),
                "extra": extra,
            }
            result = _text_or_none(task.get("result"))
            if result is not None:
                yield base | {
                    "locator": f"row:tasks.id={tid}:result",
                    "record": "task_result",
                    "role": "assistant",
                    "text": result,
                    "ts": _epoch(task.get("completed_at")),
                    "extra": dict(extra),
                }
        for comment in select("task_comments", ("id", "task_id", "author", "body", "created_at")):
            author = str(comment.get("author") or "")
            task_id = str(comment.get("task_id"))
            yield {
                "locator": f"row:task_comments.id={comment.get('id')}",
                "record": "comment",
                "role": "user" if author.lower() in _HUMAN_AUTHORS else "assistant",
                "text": _text_or_none(comment.get("body")) or "",
                "ts": _epoch(comment.get("created_at")),
                "session": task_id,
                "extra": {"task_id": task_id, "author": author},
                "model": None,
                "title": None,
            }
        for run in select(
            "task_runs", ("id", "task_id", "profile", "status", "outcome", "summary", "ended_at")
        ):
            summary = _text_or_none(run.get("summary"))
            if summary is None:
                continue
            task_id = str(run.get("task_id"))
            yield {
                "locator": f"row:task_runs.id={run.get('id')}",
                "record": "run_summary",
                "role": "assistant",
                "text": summary,
                "ts": _epoch(run.get("ended_at")),
                "session": task_id,
                "extra": {
                    "task_id": task_id,
                    "profile": run.get("profile"),
                    "status": run.get("status"),
                    "outcome": run.get("outcome"),
                },
                "model": None,
                "title": None,
            }

    def _version_ts(self, ctx: ParseContext, ref: EntryRef, tz: str) -> tuple[datetime | None, str, str]:
        """(ts, ts_kind, ts_basis): backup-name wall time in the export zone, else the file mtime."""
        named = _name_ts(posixpath.basename(ref.path), tz)
        if named is not None:
            return named, "file_name_version", f"assumed:{tz}"
        return ctx.fs.stat(ref).mtime, "file_mtime", "native_utc"

    def _cron_jobs(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        tz = export_tz()
        refs: list[EntryRef] = cand.extra["refs"]
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        files = 0
        for ref in refs:
            try:
                doc = json.loads(ctx.fs.read_bytes(ref).decode("utf-8", errors="replace"))
            except json.JSONDecodeError as exc:
                yield self.warning(
                    ctx, Candidate(ref=ref, role=cand.role), f"cannot parse cron jobs file: {exc}"
                )
                continue
            jobs = doc.get("jobs") if isinstance(doc, dict) else doc
            if not isinstance(jobs, list):
                yield self.warning(ctx, Candidate(ref=ref, role=cand.role), "schema_mismatch: no jobs list")
                continue
            files += 1
            ts, ts_kind, basis = self._version_ts(ctx, ref, tz)
            for job in jobs:
                if (
                    not isinstance(job, dict)
                    or not isinstance(job.get("prompt"), str)
                    or not job["prompt"].strip()
                ):
                    continue
                key = (str(job.get("id")), job["prompt"])
                entry = grouped.setdefault(key, {"versions": []})
                entry["versions"].append((ts, posixpath.basename(ref.path), ref, ts_kind, basis, job))
        for (job_id, prompt), entry in grouped.items():
            versions = sorted(entry["versions"], key=lambda v: (v[0] is None, v[0] or datetime.max, v[1]))
            ts, _, ref, ts_kind, basis, _ = versions[0]
            job = versions[-1][5]
            extra: dict[str, Any] = {
                "source_kind": "cron_job",
                "job_id": job_id,
                "name": job.get("name"),
                "schedule": job.get("schedule_display"),
                "enabled": job.get("enabled"),
                "model": job.get("model"),
                "script": job.get("script"),
                "no_agent": job.get("no_agent"),
                "version_file": posixpath.basename(ref.path),
                "versions": [v[1] for v in versions],
                "ts_kind": ts_kind,
            }
            if basis.startswith("assumed:"):
                extra["ts_assumed_tz"] = tz
            digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
            yield from self._message(
                ctx,
                Candidate(ref=ref, role=cand.role),
                f"job:{job_id}:{digest}",
                role="user",
                text=prompt,
                session_id=f"cron:{job_id}",
                ts=ts,
                ts_basis=basis,
                extra=extra,
                model=job.get("model") if isinstance(job.get("model"), str) else None,
                title=job.get("name") if isinstance(job.get("name"), str) else None,
                recovered_from="json",
                ts_kind=ts_kind,
            )
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{len(grouped)} distinct cron job prompt(s) across {files} jobs file version(s)",
            extra={"source_kind": "cron_job", "files": files, "distinct_prompts": len(grouped)},
        )

    def _cron_executions(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            conn = self._open_db(ctx, cand)
            if conn is None:
                yield self._presence(ctx, cand, "store", "present", f"{cand.ref.path} is empty")
                return
        except sqlite3.DatabaseError as exc:
            yield from self._db_failed(ctx, cand, exc, "cron_executions")
            return
        try:
            try:
                tables = self._db_tables(conn)
                present = tables.get("executions", [])
                cols = [c for c in _EXECUTION_COLUMNS if c in present]
                if "job_id" not in cols:
                    yield self.warning(ctx, cand, "schema_mismatch: no executions table found")
                    yield self._presence(
                        ctx, cand, "store", "present", f"{cand.ref.path} present but not parsed"
                    )
                    return
                sql = "SELECT " + ", ".join(f'"{c}"' for c in cols) + ' FROM "executions" ORDER BY rowid'
                rows = [dict(zip(cols, values, strict=True)) for values in conn.execute(sql)]
            except sqlite3.DatabaseError as exc:
                yield from self._db_failed(ctx, cand, exc, "cron_executions")
                return
        finally:
            conn.close()
        statuses: dict[str, int] = {}
        stamps: list[datetime] = []
        parsed: list[tuple[dict[str, Any], datetime | None]] = []
        for row in rows:
            status = str(row.get("status"))
            statuses[status] = statuses.get(status, 0) + 1
            raw = row.get("started_at") or row.get("claimed_at")
            ts = from_iso(raw) if isinstance(raw, str) else _epoch(raw)
            if ts is not None:
                stamps.append(ts)
            parsed.append((row, ts))
        summary = self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{len(rows)} cron execution(s) in {cand.ref.path}",
            stamps,
            {"source_kind": "cron_executions", "executions": len(rows), "statuses": statuses},
        )
        yield summary
        for index, (row, ts) in enumerate(parsed):
            yield self.event(
                summary,
                ts,
                "cron_execution",
                EventCategory.OTHER,
                Actor.SYSTEM,
                f"cron execution {row.get('job_id')} {row.get('status')}",
                ts_basis="native_utc" if ts is not None else "unknown",
                subject=str(row.get("job_id")),
                data={k: row.get(k) for k in ("id", "job_id", "status", "source", "finished_at")},
                index=index,
            )

    def _cron_deliveries(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            conn = self._open_db(ctx, cand)
            if conn is None:
                yield self._presence(ctx, cand, "store", "present", f"{cand.ref.path} is empty")
                return
        except sqlite3.DatabaseError as exc:
            yield from self._db_failed(ctx, cand, exc, "cron_deliveries")
            return
        try:
            try:
                tables = self._db_tables(conn)
                if "status" not in tables.get("deliveries", []):
                    yield self.warning(ctx, cand, "schema_mismatch: no deliveries table found")
                    yield self._presence(
                        ctx, cand, "store", "present", f"{cand.ref.path} present but not parsed"
                    )
                    return
                statuses = {
                    str(s): n for s, n in conn.execute('SELECT status, COUNT(*) FROM "deliveries" GROUP BY 1')
                }
            except sqlite3.DatabaseError as exc:
                yield from self._db_failed(ctx, cand, exc, "cron_deliveries")
                return
        finally:
            conn.close()
        total = sum(statuses.values())
        yield self._presence(
            ctx,
            cand,
            "store",
            "parsed",
            f"{total} cron deliver(ies) in {cand.ref.path}",
            extra={"source_kind": "cron_deliveries", "deliveries": total, "statuses": statuses},
        )

    def _cron_prompt(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        tz = export_tz()
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        ts, ts_kind, basis = self._version_ts(ctx, cand.ref, tz)
        job_id = posixpath.basename(posixpath.dirname(cand.ref.path))
        extra: dict[str, Any] = {"source_kind": "cron_output_prompt", "job_id": job_id, "ts_kind": ts_kind}
        if basis.startswith("assumed:"):
            extra["ts_assumed_tz"] = tz
        yield from self._message(
            ctx,
            cand,
            "file",
            role="user",
            text=text,
            session_id=f"cron:{job_id}",
            ts=ts,
            ts_basis=basis,
            extra=extra,
            ts_kind=ts_kind,
        )

    def _instructions(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        tz = export_tz()
        refs: list[EntryRef] = cand.extra["refs"]
        groups: dict[str, list[tuple[EntryRef, bytes]]] = {}
        for ref in refs:
            data = ctx.fs.read_bytes(ref)
            groups.setdefault(hashlib.sha256(data).hexdigest(), []).append((ref, data))
        for digest, members in groups.items():
            members.sort(key=lambda m: (_is_backup(posixpath.basename(m[0].path)), len(m[0].path), m[0].path))
            ref, data = members[0]
            kind = _instruction_kind(ref.path) or "workspace_instruction"
            text = data.decode("utf-8", errors="replace")
            name = posixpath.basename(ref.path)
            if _is_backup(name):
                ts, ts_kind, basis = self._version_ts(ctx, ref, tz)
            else:
                ts, ts_kind, basis = ctx.fs.stat(ref).mtime, "file_mtime", "native_utc"
            extra: dict[str, Any] = {
                "source_kind": kind,
                "file_name": name,
                "sha256": digest,
                "chars": len(text),
                "duplicate_paths": [m[0].path for m in members[1:]],
                "ts_kind": ts_kind,
            }
            if ts_kind == "file_name_version":
                extra["version_ts"] = _iso(ts)
                extra["ts_assumed_tz"] = tz
            if "__" in name:
                extra["workspace"] = name.rsplit("__", 1)[0].replace("__", "/")
            if len(text) > MAX_TEXT_CHARS:
                text = text[:MAX_TEXT_CHARS]
                extra["truncated"] = True
            yield from self._instruction(
                ctx,
                Candidate(ref=ref, role=cand.role),
                f"instruction:{digest[:16]}",
                kind="persona" if kind == "persona" else "instruction",
                text=text,
                ts=ts,
                ts_kind=ts_kind,
                ts_basis=basis,
                extra=extra,
            )

    def _shell_history(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        shell: str = cand.extra["shell"]
        raw = ctx.fs.read_bytes(cand.ref)
        data = history.unmetafy(raw) if shell == "zsh" else raw
        text = data.decode("utf-8", errors="replace")
        if history._looks_binary(raw, text):
            yield self.warning(ctx, cand, "history file is not text (binary content); skipped")
            return
        lines = text.replace("\r\n", "\n").split("\n")
        parser = history._PARSERS.get(shell, history._parse_powershell)
        shell_cand = Candidate(ref=cand.ref, role=shell)
        for command in parser(lines):
            scrubbed = history._Command(command.line, scrub(command.text), command.epoch)
            yield from self._shell._emit(ctx, shell_cand, scrubbed, OsFamily.LINUX, None)

    def _auth(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        st = ctx.fs.stat(cand.ref)
        yield from self._file_presence(
            ctx,
            cand,
            "config",
            f"{cand.ref.path}: {st.size} bytes (credential store; values not extracted)",
            {"source_kind": "auth_json"},
        )
        try:
            doc = json.loads(ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            yield self.warning(ctx, cand, f"cannot parse auth.json: {exc.msg}")
            return
        if not isinstance(doc, dict):
            return
        for section in ("providers", "credential_pool"):
            pool = doc.get(section)
            if not isinstance(pool, dict):
                continue
            for provider, entries in pool.items():
                if not entries:
                    continue
                n = len(entries) if isinstance(entries, list | dict) else 1
                yield self.artifact(
                    ctx,
                    cand,
                    ArtifactKind.AI_CREDENTIAL,
                    {
                        "tool": TOOL,
                        "provider": str(provider),
                        "redacted": "present (value not extracted)",
                        "extra": {"source_kind": "auth_json", "section": section, "entries": n},
                    },
                    locator=f"auth:{section}:{provider}",
                )

    def _config(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        st = ctx.fs.stat(cand.ref)
        yield from self._file_presence(
            ctx, cand, "config", f"{cand.ref.path}: {st.size} bytes", {"source_kind": "config"}
        )
        if st.size is None or st.size > MAX_OPEN_BYTES:
            return
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


def _unwrap_oob(text: str) -> tuple[str, dict[str, Any] | None, bool]:
    """(inner user text, gateway origin with platform/chat_type only, wrapped?) for a gateway wrapper."""
    stripped = text.strip()
    if not stripped.startswith(_OOB_OPEN):
        return text, None, False
    body = stripped.split("\n", 1)[1] if "\n" in stripped else ""
    end = body.rfind(_OOB_CLOSE)
    if end != -1:
        body = body[:end]
    gateway: dict[str, Any] | None = None
    marker = body.find(_GATEWAY_LINE)
    if marker != -1:
        after = body[marker:].split("\n", 1)[1] if "\n" in body[marker:] else ""
        rest = after.lstrip()
        try:
            origin, consumed = json.JSONDecoder().raw_decode(rest)
        except json.JSONDecodeError:
            body = after
        else:
            if isinstance(origin, dict):
                gateway = {k: origin[k] for k in _GATEWAY_KEYS if k in origin}
            body = rest[consumed:]
    return body.strip(), gateway, True


PLUGIN = Plugin()
