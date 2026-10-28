"""Human-vs-AI attribution analyzer implementing the Appendix A.8 rubric.

Subjects are files (keyed by case-insensitive normalized path) and VCS commits
(``<repo_path>@<sha>``) that carry at least one signal. Files without any signal
are never attributed. Absence of AI signals never yields ``human_authored``.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_left
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from aitrace.core import catalog
from aitrace.core.ids import make_id
from aitrace.core.kinds import (
    SIGNAL_CAPS,
    SIGNAL_DIRECTION,
    Actor,
    ArtifactKind,
    EventCategory,
    FindingCategory,
    OsFamily,
    Severity,
    SignalType,
    Verdict,
    band_for,
)
from aitrace.core.model import Artifact, Attribution, Finding, Signal
from aitrace.core.paths import normalize
from aitrace.core.time import from_iso

if TYPE_CHECKING:
    from aitrace.db.store import CaseStore

SHINGLE_WORDS = 8
JACCARD_THRESHOLD = 0.5
HUMAN_EDIT_GRACE = timedelta(seconds=60)
TIME_PROXIMITY_WINDOW = timedelta(seconds=120)
AI_SCORE_CAP = 0.95
EXTRA_SIGNAL_BONUS = 0.05
INEXACT_WRITE_FACTOR = 0.6
WRITE_CALLS = frozenset({"write", "edit", "multiedit"})
# Signal types a media/document plugin may report; anything else is ignored by design.
_MEDIA_TYPES = frozenset(
    {
        SignalType.C2PA,
        SignalType.IPTC_DIGITAL_SOURCE,
        SignalType.SD_PARAMETERS,
        SignalType.AI_FILENAME_PATTERN,
    }
)
_WORD_RE = re.compile(r"\S+")
MAX_COVERAGE_IDS = 50


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _opt_str(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _malformed(art: Artifact) -> bool:
    """True when the artifact data violates the Appendix A.10 shape this analyzer relies on."""
    data = art.data
    kind = art.kind
    if kind is ArtifactKind.FILE_RECORD:
        return not _is_str(data.get("path")) or not _opt_str(data.get("text_sample"))
    if kind is ArtifactKind.AI_TOOL_CALL:
        return not _opt_str(data.get("file_path")) or not _opt_str(data.get("call_name"))
    if kind is ArtifactKind.MEDIA_PROVENANCE:
        signals = data.get("signals", [])
        return not _is_str(data.get("path")) or not (
            isinstance(signals, list) and all(isinstance(s, dict) for s in signals)
        )
    if kind is ArtifactKind.DOC_METADATA:
        hints = data.get("hints")
        return not _is_str(data.get("path")) or not (
            hints is None or (isinstance(hints, list) and all(isinstance(h, dict) for h in hints))
        )
    if kind is ArtifactKind.VCS_COMMIT:
        return not _is_str(data.get("repo_path")) or not _is_str(data.get("sha"))
    if kind in (ArtifactKind.BROWSER_DOWNLOAD, ArtifactKind.DOWNLOAD_ORIGIN):
        return not _opt_str(data.get("target_path")) or not _opt_str(data.get("ai_service"))
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


@dataclass(slots=True)
class _Sig:
    weight: float
    artifact_ids: set[str]
    note: str


@dataclass(slots=True)
class _Subject:
    path: str
    artifact_ids: set[str] = field(default_factory=set)
    signals: dict[SignalType, _Sig] = field(default_factory=dict)

    def add(self, stype: SignalType, weight: float, artifact_ids: Iterable[str], note: str) -> None:
        ids = set(artifact_ids)
        self.artifact_ids |= ids
        current = self.signals.get(stype)
        if current is None:
            self.signals[stype] = _Sig(weight, ids, note)
            return
        current.artifact_ids |= ids
        if weight > current.weight:
            current.weight = weight
            current.note = note


@dataclass(slots=True)
class _FileInfo:
    path: str
    artifact_ids: set[str] = field(default_factory=set)
    sha256: str | None = None
    mtime: datetime | None = None
    btime: datetime | None = None
    sample: str | None = None


@dataclass(frozen=True, slots=True)
class _ToolWrite:
    artifact_id: str
    path: str
    ts: datetime | None
    content_sha256: str | None
    content: str | None


TEXT_SAMPLE_LIMIT = 64 * 1024


def _lf(text: str) -> str:
    return text.replace("\r\n", "\n")


def _key(path: str) -> str:
    return "f:" + normalize(path, OsFamily.UNKNOWN).casefold()


def _path(path: str) -> str:
    return normalize(path, OsFamily.UNKNOWN)


def _shingles(text: str) -> frozenset[tuple[str, ...]]:
    words = [w.casefold() for w in _WORD_RE.findall(text)]
    if len(words) < SHINGLE_WORDS:
        return frozenset()
    return frozenset(tuple(words[i : i + SHINGLE_WORDS]) for i in range(len(words) - SHINGLE_WORDS + 1))


def jaccard(a: frozenset[tuple[str, ...]], b: frozenset[tuple[str, ...]]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _limitation_texts(signal_types: Iterable[SignalType]) -> tuple[str, ...]:
    texts: list[str] = []
    for stype in sorted(signal_types, key=lambda s: s.value):
        entry = catalog.LIMITATIONS[stype]
        if isinstance(entry, dict):
            texts.append(entry["en"])
    global_entries = catalog.LIMITATIONS["GLOBAL"]
    assert isinstance(global_entries, list)
    texts.append(global_entries[-1]["en"])  # "absence of AI traces does not prove human authorship"
    return tuple(texts)


def decide(signals: Sequence[Signal]) -> tuple[Verdict, float]:
    """Rubric A.8 steps 2, 3 and 5 over already-weighted signals (one per type)."""
    ai = sorted((s for s in signals if s.direction == "ai"), key=lambda s: s.weight, reverse=True)
    human = [s for s in signals if s.direction == "human"]
    ai_score = 0.0
    if ai:
        ai_score = min(AI_SCORE_CAP, ai[0].weight + EXTRA_SIGNAL_BONUS * (len({s.type for s in ai}) - 1))
    human_score = max((s.weight for s in human), default=0.0)
    has_edit = any(s.type is SignalType.HUMAN_EDIT_AFTER for s in signals)
    has_human_evidence = any(s.type in (SignalType.HUMAN_EDIT_AFTER, SignalType.HUMAN_PROCESS) for s in signals)
    if ai_score >= 0.5:
        if has_edit:
            return Verdict.AI_ASSISTED, min(ai_score, 0.75)
        return Verdict.AI_GENERATED, ai_score
    if human_score >= 0.5 and ai_score < 0.2 and has_human_evidence:
        return Verdict.HUMAN_AUTHORED, human_score
    return Verdict.UNDETERMINED, max(ai_score, human_score)


class AttributionAnalyzer:
    name = "attribution"
    version = "1.0"

    def run(self, store: CaseStore, tz: str) -> Iterator[Finding | Attribution]:
        subjects: dict[str, _Subject] = {}
        files: dict[str, _FileInfo] = {}
        writes: dict[str, list[_ToolWrite]] = {}
        assistant_texts: list[tuple[str, frozenset[tuple[str, ...]]]] = []
        ai_times: list[datetime] = []
        skipped: list[str] = []

        ts_by_artifact: dict[str, datetime] = {}
        for event in store.events():
            if event.ts_utc is None:
                continue
            ts_by_artifact.setdefault(event.artifact_id, event.ts_utc)
            if event.category is EventCategory.AI_ACTIVITY and event.actor is Actor.AI:
                ai_times.append(event.ts_utc)
        ai_times.sort()

        def subject(key: str, path: str) -> _Subject:
            return subjects.setdefault(key, _Subject(path=path))

        for art in store.artifacts():
            if _malformed(art):
                skipped.append(art.id)
                continue
            data = art.data
            kind = art.kind
            if kind is ArtifactKind.FILE_RECORD:
                self._collect_file_record(art, files)
            elif kind is ArtifactKind.AI_TOOL_CALL:
                self._collect_tool_call(art, data, ts_by_artifact, writes)
            elif kind is ArtifactKind.AI_CHAT_MESSAGE:
                if data.get("role") == "assistant" and isinstance(data.get("text"), str):
                    shingles = _shingles(data["text"])
                    if shingles:
                        assistant_texts.append((art.id, shingles))
            elif kind in (ArtifactKind.MEDIA_PROVENANCE, ArtifactKind.DOC_METADATA):
                self._collect_provenance(art, data, subject)
            elif kind is ArtifactKind.VCS_COMMIT:
                tool = data.get("ai_trailer")
                if tool:
                    label = f"{data['repo_path']}@{data['sha']}"
                    subject("v:" + label, label).add(
                        SignalType.VCS_AI_TRAILER,
                        SIGNAL_CAPS[SignalType.VCS_AI_TRAILER],
                        [art.id],
                        f"commit trailer names {tool}",
                    )
            elif kind in (ArtifactKind.BROWSER_DOWNLOAD, ArtifactKind.DOWNLOAD_ORIGIN):
                target = data.get("target_path")
                service = data.get("ai_service")
                if target and service:
                    subject(_key(target), _path(target)).add(
                        SignalType.AI_DOWNLOAD_ORIGIN,
                        SIGNAL_CAPS[SignalType.AI_DOWNLOAD_ORIGIN],
                        [art.id],
                        f"downloaded from {service}",
                    )

        for key, calls in writes.items():
            info = files.get(key)
            subj = subject(key, info.path if info else calls[0].path)
            self._agent_write_signals(subj, calls, info)

        self._content_match_signals(subject, files, writes, assistant_texts)
        self._time_proximity_signals(subject, files, subjects, ai_times)

        for key in sorted(subjects, key=lambda k: (subjects[k].path, k)):
            subj = subjects[key]
            if not subj.signals:
                continue
            if key in files:
                subj.artifact_ids |= files[key].artifact_ids
            attribution = self._attribute(subj)
            yield attribution
            yield self._finding(attribution)

        if skipped:
            yield _coverage_finding(self.name, skipped)

    @staticmethod
    def _collect_file_record(art: Artifact, files: dict[str, _FileInfo]) -> None:
        path = art.data.get("path")
        if not path or art.data.get("is_dir"):
            return
        info = files.setdefault(_key(path), _FileInfo(path=_path(path)))
        info.artifact_ids.add(art.id)
        sha = art.data.get("content_sha256")
        if sha and info.sha256 is None:
            info.sha256 = str(sha).lower()
        sample = art.data.get("text_sample")
        if sample and info.sample is None:
            info.sample = sample
        for field_name, attr in (("mtime", "mtime"), ("btime", "btime")):
            raw = art.data.get(field_name)
            parsed = from_iso(raw) if isinstance(raw, str) else None
            current = getattr(info, attr)
            if parsed is not None and (current is None or parsed > current):
                setattr(info, attr, parsed)

    @staticmethod
    def _collect_tool_call(
        art: Artifact,
        data: dict[str, Any],
        ts_by_artifact: dict[str, datetime],
        writes: dict[str, list[_ToolWrite]],
    ) -> None:
        file_path = data.get("file_path")
        call_name = str(data.get("call_name", "")).casefold()
        if not file_path or call_name not in WRITE_CALLS:
            return
        content = data.get("content")
        has_content = isinstance(content, str)
        writes.setdefault(_key(file_path), []).append(
            _ToolWrite(
                artifact_id=art.id,
                path=_path(file_path),
                ts=ts_by_artifact.get(art.id),
                content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest() if has_content else None,
                content=content if has_content else None,
            )
        )

    @staticmethod
    def _collect_provenance(art: Artifact, data: dict[str, Any], subject: Any) -> None:
        path = data.get("path")
        if not path:
            return
        if art.kind is ArtifactKind.MEDIA_PROVENANCE:
            for sig in data.get("signals", []):
                try:
                    stype = SignalType(sig.get("type"))
                except ValueError:
                    continue
                if stype in _MEDIA_TYPES:
                    subject(_key(path), _path(path)).add(
                        stype, SIGNAL_CAPS[stype], [art.id], f"{stype.value}: {sig.get('value', '')}"
                    )
        elif data.get("hints"):
            values = ", ".join(str(h.get("value", "")) for h in data["hints"])
            subject(_key(path), _path(path)).add(
                SignalType.METADATA_HINT, SIGNAL_CAPS[SignalType.METADATA_HINT], [art.id], f"metadata hint: {values}"
            )

    @staticmethod
    def _agent_write_signals(subj: _Subject, calls: list[_ToolWrite], info: _FileInfo | None) -> None:
        cap = SIGNAL_CAPS[SignalType.AGENT_TOOL_WRITE]
        ids = [c.artifact_id for c in calls]
        content_calls = [c for c in calls if c.content_sha256 is not None]
        file_sha = info.sha256 if info else None
        exact = file_sha is not None and any(c.content_sha256 == file_sha for c in content_calls)
        if not exact and info is not None and info.sample is not None:
            # Same text with CRLF vs LF line endings (e.g. a Windows checkout or editor) is the same content.
            sample = _lf(info.sample)
            exact = any(
                c.content is not None and len(c.content) < TEXT_SAMPLE_LIMIT and _lf(c.content) == sample
                for c in content_calls
            )
        if exact:
            subj.add(SignalType.AGENT_TOOL_WRITE, cap, ids, "file content sha256 equals agent tool-call content")
        else:
            subj.add(
                SignalType.AGENT_TOOL_WRITE,
                INEXACT_WRITE_FACTOR * cap,
                ids,
                "path matches an agent write/edit call; content not proven identical",
            )
        if exact or file_sha is None or info is None or info.mtime is None or not content_calls:
            return
        timed = [(c.ts, c) for c in content_calls if c.ts is not None]
        if not timed:
            return
        last_ts, last = max(timed, key=lambda pair: pair[0])
        if info.mtime > last_ts + HUMAN_EDIT_GRACE:
            subj.add(
                SignalType.HUMAN_EDIT_AFTER,
                SIGNAL_CAPS[SignalType.HUMAN_EDIT_AFTER],
                [last.artifact_id, *info.artifact_ids],
                "file content differs from the last tool-call content and mtime is later",
            )

    @staticmethod
    def _content_match_signals(
        subject: Any,
        files: dict[str, _FileInfo],
        writes: dict[str, list[_ToolWrite]],
        assistant_texts: list[tuple[str, frozenset[tuple[str, ...]]]],
    ) -> None:
        sources: list[tuple[str, str | None, frozenset[tuple[str, ...]]]] = [
            (aid, None, sh) for aid, sh in assistant_texts
        ]
        for key, calls in writes.items():
            for call in calls:
                if call.content:
                    sh = _shingles(call.content)
                    if sh:
                        sources.append((call.artifact_id, key, sh))
        cap = SIGNAL_CAPS[SignalType.CONTENT_MATCH]
        for key, info in files.items():
            if not info.sample:
                continue
            sample = _shingles(info.sample)
            if not sample:
                continue
            best: tuple[float, str] | None = None
            for aid, source_key, sh in sources:
                if source_key == key:
                    continue  # same-path tool writes are scored as AGENT_TOOL_WRITE
                score = jaccard(sample, sh)
                if score >= JACCARD_THRESHOLD and (best is None or score > best[0]):
                    best = (score, aid)
            if best is not None:
                subject(key, info.path).add(
                    SignalType.CONTENT_MATCH,
                    cap * max(best[0], 0.5),
                    [best[1]],
                    f"{SHINGLE_WORDS}-word shingle Jaccard {best[0]:.2f} with AI-produced text",
                )

    @staticmethod
    def _time_proximity_signals(
        subject: Any,
        files: dict[str, _FileInfo],
        subjects: dict[str, _Subject],
        ai_times: list[datetime],
    ) -> None:
        if not ai_times:
            return
        for key, info in files.items():
            if subjects.get(key) is not None and subjects[key].signals:
                continue  # only files that carry no other signal are attributed by proximity alone
            for stamp in (info.btime, info.mtime):
                if stamp is None:
                    continue
                idx = bisect_left(ai_times, stamp - TIME_PROXIMITY_WINDOW)
                if idx < len(ai_times) and ai_times[idx] <= stamp:
                    subject(key, info.path).add(
                        SignalType.TIME_PROXIMITY,
                        SIGNAL_CAPS[SignalType.TIME_PROXIMITY],
                        info.artifact_ids,
                        f"file time within {int(TIME_PROXIMITY_WINDOW.total_seconds())}s after AI activity",
                    )
                    break

    @staticmethod
    def _attribute(subj: _Subject) -> Attribution:
        signals = tuple(
            Signal(
                type=stype,
                direction=SIGNAL_DIRECTION[stype],
                weight=round(sig.weight, 4),
                artifact_ids=tuple(sorted(sig.artifact_ids)),
                note=sig.note,
            )
            for stype, sig in sorted(subj.signals.items(), key=lambda kv: kv[0].value)
        )
        verdict, confidence = decide(signals)
        confidence = round(confidence, 4)
        rationale = "; ".join(f"{s.type.value} ({s.weight:.2f}): {s.note}" for s in signals)
        return Attribution(
            id=make_id("attribution", subj.path),
            subject=subj.path,
            subject_artifact_ids=tuple(sorted(subj.artifact_ids)),
            verdict=verdict,
            confidence=confidence,
            band=band_for(confidence),
            signals=signals,
            rationale=rationale,
            limitations=_limitation_texts(s.type for s in signals),
        )

    @staticmethod
    def _finding(att: Attribution) -> Finding:
        severity = Severity.INFO if att.verdict is Verdict.UNDETERMINED else Severity.LOW
        return Finding(
            id=make_id("finding", "attribution", att.subject),
            category=FindingCategory.ATTRIBUTION,
            severity=severity,
            title=f"Attribution: {att.subject} -> {att.verdict.value}",
            narrative=f"{att.verdict.value} ({att.band.value}, {att.confidence:.2f}). {att.rationale}",
            artifact_ids=att.subject_artifact_ids,
            event_ids=(),
            confidence=att.confidence,
            band=att.band,
            rule_id=f"ATTR-{att.verdict.value}",
            limitations=att.limitations,
            data={"subject": att.subject, "verdict": att.verdict.value},
        )


ANALYZER = AttributionAnalyzer()
