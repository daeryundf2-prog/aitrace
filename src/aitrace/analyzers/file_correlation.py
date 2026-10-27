"""File lifecycle correlation: links FILE_* events to AI sessions and emits FILE_LIFECYCLE findings.

Link kinds: ``agent_write`` (AI write/edit call on the same path), ``mentioned`` (path or basename in
a chat message), ``ai_download`` (download recorded with an AI service), and ``time_proximity`` (file
created or modified within 10 minutes after an assistant message of the same user; weak coincidence).
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from aitrace.core.ids import make_id
from aitrace.core.kinds import ArtifactKind, EventCategory, FindingCategory, OsFamily, Severity, band_for
from aitrace.core.model import Finding, format_utc
from aitrace.core.paths import basename, normalize
from aitrace.core.time import from_iso

if TYPE_CHECKING:
    from aitrace.db.store import CaseStore

PROXIMITY_WINDOW = timedelta(minutes=10)
MIN_BASENAME_LENGTH = 3
WRITE_CALLS = frozenset({"write", "edit", "multiedit", "apply_patch"})
LIFECYCLE_LABELS: dict[EventCategory, str] = {
    EventCategory.FILE_CREATED: "created",
    EventCategory.FILE_MODIFIED: "modified",
    EventCategory.FILE_RENAMED: "renamed",
    EventCategory.FILE_DELETED: "deleted",
}
TEMPORAL_LABELS = frozenset({"created", "modified"})
DELETED_LABELS = frozenset({"deleted", "recycled"})
LINK_CONFIDENCE: dict[str, float] = {
    "agent_write": 0.9,
    "ai_download": 0.75,
    "mentioned": 0.6,
    "time_proximity": 0.3,
}
LIMITATION = "Links show association with AI activity, not authorship; time_proximity alone is a weak coincidence."


@dataclass(frozen=True, slots=True)
class _Step:
    ts: datetime
    label: str
    artifact_id: str
    user: str | None
    event_id: str | None


@dataclass(frozen=True, slots=True)
class _Message:
    artifact_id: str
    role: str
    user: str | None
    ts: datetime | None
    text: str


@dataclass(frozen=True, slots=True)
class _Link:
    kind: str
    artifact_id: str


@dataclass(slots=True)
class _File:
    path: str
    steps: list[_Step] = field(default_factory=list)
    artifact_ids: set[str] = field(default_factory=set)
    links: set[_Link] = field(default_factory=set)


def _key(path: str) -> str:
    return normalize(path, OsFamily.UNKNOWN).casefold()


def _path(path: str) -> str:
    return normalize(path, OsFamily.UNKNOWN)


def _mentions(text: str, file: _File) -> bool:
    """``text`` is already casefolded. Basenames must stand alone, not be a fragment of a longer name."""
    if file.path.casefold() in text:
        return True
    name = basename(file.path).casefold()
    if len(name) < MIN_BASENAME_LENGTH:
        return False
    return re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w-])", text) is not None


def _proximity_link(file: _File, messages: list[_Message]) -> _Link | None:
    for step in file.steps:
        if step.label not in TEMPORAL_LABELS:
            continue
        for message in messages:
            if message.role != "assistant" or message.ts is None or message.user != step.user:
                continue
            if timedelta(0) <= step.ts - message.ts <= PROXIMITY_WINDOW:
                return _Link("time_proximity", message.artifact_id)
    return None


class FileCorrelationAnalyzer:
    name = "file_correlation"
    version = "1.0"

    def run(self, store: CaseStore, tz: str) -> Iterator[Finding]:
        ts_by_artifact: dict[str, datetime] = {}
        files: dict[str, _File] = {}
        for event in store.events():
            if event.ts_utc is None:
                continue
            ts_by_artifact.setdefault(event.artifact_id, event.ts_utc)
            label = LIFECYCLE_LABELS.get(event.category)
            if label is None or not event.subject:
                continue
            file = files.setdefault(_key(event.subject), _File(path=_path(event.subject)))
            file.steps.append(_Step(event.ts_utc, label, event.artifact_id, event.user, event.id))

        writes: defaultdict[str, set[str]] = defaultdict(set)
        downloads: defaultdict[str, set[str]] = defaultdict(set)
        messages: list[_Message] = []
        for art in store.artifacts():
            data = art.data
            if art.kind is ArtifactKind.AI_TOOL_CALL:
                file_path = data.get("file_path")
                if file_path and str(data.get("call_name", "")).casefold() in WRITE_CALLS:
                    writes[_key(file_path)].add(art.id)
            elif art.kind is ArtifactKind.AI_CHAT_MESSAGE:
                text = data.get("text")
                if data.get("role") in ("user", "assistant") and isinstance(text, str):
                    messages.append(
                        _Message(art.id, str(data["role"]), art.user, ts_by_artifact.get(art.id), text.casefold())
                    )
            elif art.kind in (ArtifactKind.BROWSER_DOWNLOAD, ArtifactKind.DOWNLOAD_ORIGIN):
                target = data.get("target_path")
                if target and data.get("ai_service"):
                    downloads[_key(target)].add(art.id)
            elif art.kind is ArtifactKind.RECYCLED_FILE:
                original = data.get("original_path")
                deleted = from_iso(data.get("deleted_utc"))
                if original and deleted is not None:
                    files.setdefault(_key(original), _File(path=_path(original))).steps.append(
                        _Step(deleted, "recycled", art.id, art.user, None)
                    )

        for key, file in files.items():
            file.artifact_ids.update(step.artifact_id for step in file.steps)
            file.links.update(_Link("agent_write", aid) for aid in writes.get(key, ()))
            file.links.update(_Link("ai_download", aid) for aid in downloads.get(key, ()))
            file.links.update(_Link("mentioned", msg.artifact_id) for msg in messages if _mentions(msg.text, file))
            proximity = _proximity_link(file, messages)
            if proximity is not None:
                file.links.add(proximity)

        for key in sorted(files, key=lambda k: files[k].path):
            file = files[key]
            deleted = any(step.label in DELETED_LABELS for step in file.steps)
            if not file.links and not deleted:
                continue
            yield self._finding(file, deleted)

    @staticmethod
    def _finding(file: _File, deleted: bool) -> Finding:
        steps = sorted(file.steps, key=lambda s: (s.ts, s.label))
        links = sorted(file.links, key=lambda link: (link.kind, link.artifact_id))
        confidence = max((LINK_CONFIDENCE[link.kind] for link in links), default=0.0)
        severity = Severity.MEDIUM if deleted and links else Severity.LOW
        order = " -> ".join(step.label for step in steps)
        link_text = ", ".join(f"{link.kind} ({LINK_CONFIDENCE[link.kind]:.2f})" for link in links) or "no AI link"
        return Finding(
            id=make_id("finding", "file_lifecycle", file.path),
            category=FindingCategory.FILE_LIFECYCLE,
            severity=severity,
            title=f"File lifecycle: {file.path}",
            narrative=f"{order}. Links: {link_text}.",
            artifact_ids=tuple(sorted({*file.artifact_ids, *(link.artifact_id for link in links)})),
            event_ids=tuple(step.event_id for step in steps if step.event_id),
            confidence=confidence,
            band=band_for(confidence),
            rule_id="FILE-LIFECYCLE",
            limitations=(LIMITATION,),
            data={
                "path": file.path,
                "lifecycle": [
                    {"ts": format_utc(step.ts), "event": step.label, "artifact_id": step.artifact_id}
                    for step in steps
                ],
                "links": [
                    {"kind": link.kind, "artifact_id": link.artifact_id, "confidence": LINK_CONFIDENCE[link.kind]}
                    for link in links
                ],
            },
        )


ANALYZER = FileCorrelationAnalyzer()
