"""AI tool inventory, session grouping, task classification and query findings (plan Appendix A.9).

The tool name of an artifact is ``data.tool``, else ``data.ai_service`` (browser artifacts),
else ``data.ai_tool`` (executions). AI credentials use ``data.tool`` or ``data.provider``.
Artifact presence shows that a tool was on the evidence, not who ran it, so every finding
carries that limitation.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from aitrace.core import catalog
from aitrace.core.ids import make_id
from aitrace.core.kinds import ArtifactKind, FindingCategory, Severity, band_for
from aitrace.core.model import Artifact, Attribution, Event, Finding, format_utc

if TYPE_CHECKING:
    from aitrace.db.store import CaseStore

SESSION_GAP = timedelta(minutes=30)
TITLE_CHARS = 80
INVENTORY_CONFIDENCE = 1.0
QUERY_CONFIDENCE = 0.6
MAX_COVERAGE_IDS = 50
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

_WEB_KINDS = frozenset({ArtifactKind.BROWSER_VISIT, ArtifactKind.BROWSER_DOWNLOAD, ArtifactKind.DOWNLOAD_ORIGIN})
_SOURCE_KINDS = (
    ArtifactKind.AI_CHAT_MESSAGE,
    ArtifactKind.AI_TOOL_CALL,
    ArtifactKind.AI_APP_PRESENCE,
    ArtifactKind.AI_CREDENTIAL,
    ArtifactKind.AI_MODEL,
    ArtifactKind.EXECUTION,
    *_WEB_KINDS,
)
_CLI_TOOLS = frozenset({"Claude Code", "Codex CLI", "Gemini CLI", "Aider", "GitHub Copilot CLI"})
_APP_PRESENCE_KINDS = {"app": "app", "sdk": "sdk"}

_USAGE_LIMITATIONS = (
    "Artifacts show a tool was present or used on this evidence; they do not establish which person ran it.",
    "Inventory timestamps are the recorded event times and inherit any clock or timezone limits of their source.",
)
_QUERY_LIMITATIONS = (
    "Prompt text is shown as recovered; sessions without a session_id are split by a 30-minute gap rule.",
    "Task classification is keyword-based and heuristic; it does not establish intent.",
)


@dataclass(slots=True)
class _Message:
    artifact: Artifact
    tool: str
    user: str
    session_id: str | None
    ts: datetime | None
    event_ids: tuple[str, ...]


def _malformed(artifact: Artifact) -> bool:
    """True when the artifact data violates the Appendix A.10 shape this analyzer relies on."""
    data = artifact.data
    for name in ("tool", "ai_service", "ai_tool", "provider"):
        value = data.get(name)
        if value is not None and not isinstance(value, str):
            return True
    if artifact.kind is ArtifactKind.AI_CHAT_MESSAGE:
        session_id = data.get("session_id")
        return (
            not isinstance(data.get("role"), str)
            or not isinstance(data.get("text"), str)
            or not (session_id is None or isinstance(session_id, str))
        )
    return False


def _coverage_finding(analyzer: str, artifact_ids: list[str]) -> Finding:
    ids = sorted(artifact_ids)[:MAX_COVERAGE_IDS]
    count = len(artifact_ids)
    return Finding(
        id=make_id("finding", "coverage", analyzer, "malformed"),
        category=FindingCategory.COVERAGE,
        severity=Severity.LOW,
        title=f"{analyzer}: skipped {count} malformed artifacts",
        narrative=f"{count} artifact(s) violated the expected data shape and were excluded from {analyzer} analysis.",
        artifact_ids=tuple(ids),
        event_ids=(),
        confidence=1.0,
        band=band_for(1.0),
        rule_id="COVERAGE-MALFORMED",
        limitations=("Skipped artifacts contributed nothing to this analyzer's results.",),
        data={"analyzer": analyzer, "skipped_count": count, "artifact_ids": ids},
    )


def _tool_of(artifact: Artifact) -> str | None:
    data = artifact.data
    if artifact.kind is ArtifactKind.AI_CREDENTIAL:
        candidates = (data.get("tool"), data.get("provider"))
    else:
        candidates = (data.get("tool"), data.get("ai_service"), data.get("ai_tool"))
    for value in candidates:
        if value:
            return str(value)
    return None


def _kind_of(artifact: Artifact, tool: str) -> str:
    kind = artifact.kind
    if kind is ArtifactKind.AI_CREDENTIAL:
        return "credential"
    if kind is ArtifactKind.AI_MODEL:
        return "local_llm"
    if kind in _WEB_KINDS:
        return "web"
    if kind is ArtifactKind.EXECUTION:
        return "app"
    if kind is ArtifactKind.AI_APP_PRESENCE:
        return _APP_PRESENCE_KINDS.get(str(artifact.data.get("kind")), "cli")
    is_cli = tool in _CLI_TOOLS
    if kind is ArtifactKind.AI_TOOL_CALL:
        return "cli" if is_cli else "ide"
    return "cli" if is_cli else "app"


def _iso(ts: datetime | None) -> str | None:
    return format_utc(ts) if ts is not None else None


def _usage_finding(tagged: list[tuple[str, Artifact]], events: dict[str, list[Event]]) -> Finding:
    by_tool: dict[str, list[Artifact]] = {}
    for tool, artifact in tagged:
        by_tool.setdefault(tool, []).append(artifact)

    rows: list[dict[str, Any]] = []
    for tool in sorted(by_tool):
        members = by_tool[tool]
        kinds = Counter(_kind_of(a, tool) for a in members)
        kind = min(kinds.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        stamps = [e.ts_utc for a in members for e in events.get(a.id, []) if e.ts_utc is not None]
        rows.append(
            {
                "tool": tool,
                "kind": kind,
                "users": sorted({a.user for a in members if a.user}),
                "first_seen": _iso(min(stamps, default=None)),
                "last_seen": _iso(max(stamps, default=None)),
                "evidence_count": len(members),
                "artifact_ids": sorted(a.id for a in members),
            }
        )

    artifacts = [a for _, a in tagged]
    tools = sorted(by_tool)
    return Finding(
        id=make_id("ai_sessions", "AI_TOOL_USAGE"),
        category=FindingCategory.AI_TOOL_USAGE,
        severity=Severity.INFO,
        title=f"AI tools observed: {len(tools)}",
        narrative=f"{len(tools)} AI tool(s) found across {len(artifacts)} artifact(s): {', '.join(tools)}.",
        artifact_ids=tuple(sorted(a.id for a in artifacts)),
        event_ids=tuple(sorted(e.id for a in artifacts for e in events.get(a.id, []))),
        confidence=INVENTORY_CONFIDENCE,
        band=band_for(INVENTORY_CONFIDENCE),
        rule_id=None,
        limitations=_USAGE_LIMITATIONS,
        data={"providers": tools, "inventory": rows},
    )


def _msg_order(msg: _Message) -> tuple[bool, datetime, str]:
    return (msg.ts is None, msg.ts or _EPOCH, msg.artifact.id)


def _starts_new_session(prev: _Message, cur: _Message) -> bool:
    return prev.ts is not None and cur.ts is not None and cur.ts - prev.ts > SESSION_GAP


def _build_sessions(messages: Iterable[_Message]) -> list[list[_Message]]:
    explicit: dict[tuple[str, str, str], list[_Message]] = {}
    implicit: dict[tuple[str, str], list[_Message]] = {}
    for msg in sorted(messages, key=_msg_order):
        if msg.session_id is not None:
            explicit.setdefault((msg.tool, msg.user, msg.session_id), []).append(msg)
        else:
            implicit.setdefault((msg.tool, msg.user), []).append(msg)

    sessions = list(explicit.values())
    for stream in implicit.values():
        current: list[_Message] = []
        for msg in stream:
            if current and _starts_new_session(current[-1], msg):
                sessions.append(current)
                current = []
            current.append(msg)
        if current:
            sessions.append(current)
    return sorted(sessions, key=lambda s: _msg_order(s[0]))


def _query_finding(session: list[_Message]) -> Finding | None:
    prompts = [
        (msg, text)
        for msg in session
        if msg.artifact.data.get("role") == "user"
        and (text := " ".join(str(msg.artifact.data.get("text", "")).split()))
    ]
    if not prompts:
        return None

    first = session[0]
    tasks = sorted({rule_id for _, text in prompts for rule_id, pattern in catalog.TASK_RULES if pattern.search(text)})
    stamps = [msg.ts for msg in session if msg.ts is not None]
    key = first.session_id or first.artifact.id
    return Finding(
        id=make_id("ai_sessions", "AI_QUERY", first.tool, first.user, key),
        category=FindingCategory.AI_QUERY,
        severity=Severity.INFO,
        title=prompts[0][1][:TITLE_CHARS],
        narrative=(
            f"{first.tool} session ({first.user or 'unknown user'}): {len(prompts)} prompt(s); "
            f"tasks: {', '.join(tasks) or 'none matched'}."
        ),
        artifact_ids=tuple(sorted(msg.artifact.id for msg in session)),
        event_ids=tuple(sorted(eid for msg in session for eid in msg.event_ids)),
        confidence=QUERY_CONFIDENCE,
        band=band_for(QUERY_CONFIDENCE),
        rule_id=None,
        limitations=_QUERY_LIMITATIONS,
        data={
            "tool": first.tool,
            "user": first.user or None,
            "session_id": first.session_id,
            "prompt_count": len(prompts),
            "tasks": tasks,
            "first_seen": _iso(min(stamps, default=None)),
            "last_seen": _iso(max(stamps, default=None)),
        },
    )


class AiSessionsAnalyzer:
    name = "ai_sessions"
    version = "1.0"

    def run(self, store: CaseStore, tz: str) -> Iterator[Finding | Attribution]:
        tagged: list[tuple[str, Artifact]] = []
        skipped: list[str] = []
        for a in store.artifacts(kinds=_SOURCE_KINDS):
            if _malformed(a):
                skipped.append(a.id)
            elif tool := _tool_of(a):
                tagged.append((tool, a))
        yield from self._analyze(tagged, store)
        if skipped:
            yield _coverage_finding(self.name, skipped)

    @staticmethod
    def _analyze(tagged: list[tuple[str, Artifact]], store: CaseStore) -> Iterator[Finding]:
        if not tagged:
            return

        wanted = {a.id for _, a in tagged}
        events: dict[str, list[Event]] = {}
        for event in store.events():
            if event.artifact_id in wanted:
                events.setdefault(event.artifact_id, []).append(event)

        yield _usage_finding(tagged, events)

        messages: list[_Message] = []
        for tool, artifact in tagged:
            if artifact.kind is not ArtifactKind.AI_CHAT_MESSAGE:
                continue
            artifact_events = events.get(artifact.id, [])
            stamps = [e.ts_utc for e in artifact_events if e.ts_utc is not None]
            messages.append(
                _Message(
                    artifact=artifact,
                    tool=tool,
                    user=artifact.user or "",
                    session_id=artifact.data.get("session_id") or None,
                    ts=min(stamps, default=None),
                    event_ids=tuple(e.id for e in artifact_events),
                )
            )

        for session in _build_sessions(messages):
            finding = _query_finding(session)
            if finding is not None:
                yield finding


ANALYZER = AiSessionsAnalyzer()
