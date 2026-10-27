from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aitrace.analyzers.file_correlation import ANALYZER
from aitrace.core.ids import make_id
from aitrace.core.kinds import (
    Actor,
    ArtifactKind,
    ConfidenceBand,
    EventCategory,
    FindingCategory,
    Severity,
)
from aitrace.core.model import Artifact, Event, Finding, Provenance
from aitrace.db.store import CaseStore

T0 = datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC)
DOC = "/Users/kim/work/report.docx"
SCRATCH = "/Users/kim/tmp/scratch.log"


def _art(aid: str, kind: ArtifactKind, data: dict[str, Any], user: str | None = "kim") -> Artifact:
    return Artifact(
        id=aid,
        kind=kind,
        provenance=Provenance(evidence_id="ev", volume=0, source_path="/src", plugin="p", plugin_version="1.0"),
        data=data,
        user=user,
    )


def _event(aid: str, ts: datetime, category: EventCategory, subject: str | None = None) -> Event:
    return Event(
        id=make_id("e", aid, category.value),
        artifact_id=aid,
        ts_utc=ts,
        ts_kind="k",
        ts_basis="native_utc",
        category=category,
        actor=Actor.AI if category is EventCategory.AI_ACTIVITY else Actor.SYSTEM,
        user="kim",
        summary="s",
        subject=subject,
    )


def _write_call(aid: str, path: str, ts: datetime) -> list[Artifact | Event]:
    data: dict[str, Any] = {
        "tool": "Claude Code",
        "session_id": "s",
        "call_name": "Write",
        "input": {},
        "file_path": path,
    }
    return [_art(aid, ArtifactKind.AI_TOOL_CALL, data), _event(aid, ts, EventCategory.AI_ACTIVITY)]


def _chat(aid: str, role: str, text: str, ts: datetime) -> list[Artifact | Event]:
    data: dict[str, Any] = {"tool": "Claude Code", "session_id": "s", "role": role, "text": text}
    return [_art(aid, ArtifactKind.AI_CHAT_MESSAGE, data), _event(aid, ts, EventCategory.AI_ACTIVITY)]


def _download(aid: str, target: str, ts: datetime) -> list[Artifact | Event]:
    data: dict[str, Any] = {
        "browser": "chrome",
        "url": "https://files.example/report.docx",
        "target_path": target,
        "ai_service": "chatgpt.com",
    }
    return [_art(aid, ArtifactKind.BROWSER_DOWNLOAD, data), _event(aid, ts, EventCategory.DOWNLOAD)]


def _file_event(aid: str, category: EventCategory, path: str, ts: datetime) -> list[Artifact | Event]:
    record = {"path": path, "size": 1, "is_dir": False, "in_use": False}
    return [_art(aid, ArtifactKind.FILE_RECORD, record), _event(aid, ts, category, subject=path)]


@pytest.fixture
def store(tmp_path: Path) -> Iterator[CaseStore]:
    s = CaseStore(tmp_path / "case.sqlite")
    yield s
    s.close()


def _by_path(store: CaseStore) -> dict[str, Finding]:
    return {f.data["path"]: f for f in ANALYZER.run(store, "UTC")}


def _kinds(finding: Finding) -> set[str]:
    return {link["kind"] for link in finding.data["links"]}


def test_agent_write_links_file_created_at_same_path(store: CaseStore) -> None:
    store.add(
        [
            *_write_call("w1", DOC, T0),
            *_file_event("c1", EventCategory.FILE_CREATED, DOC, T0 + timedelta(seconds=5)),
        ]
    )
    finding = _by_path(store)[DOC]
    assert finding.category is FindingCategory.FILE_LIFECYCLE
    assert _kinds(finding) == {"agent_write"}
    assert finding.confidence == pytest.approx(0.9)
    assert finding.severity is Severity.LOW
    assert [step["event"] for step in finding.data["lifecycle"]] == ["created"]


def test_unrelated_file_two_hours_after_ai_activity_has_no_link(store: CaseStore) -> None:
    store.add(
        [
            *_write_call("w1", "/Users/kim/work/other.txt", T0),
            *_chat("a1", "assistant", "done", T0),
            *_file_event("c1", EventCategory.FILE_CREATED, DOC, T0 + timedelta(hours=2)),
        ]
    )
    assert DOC not in _by_path(store)


def test_mentioned_basename_in_user_prompt_links(store: CaseStore) -> None:
    store.add(
        [
            *_chat("u1", "user", "please summarize report.docx for me", T0),
            *_file_event("c1", EventCategory.FILE_CREATED, DOC, T0 + timedelta(hours=1)),
        ]
    )
    finding = _by_path(store)[DOC]
    assert _kinds(finding) == {"mentioned"}
    assert finding.confidence == pytest.approx(0.6)


def test_basename_fragment_is_not_a_mention(store: CaseStore) -> None:
    store.add(
        [
            *_chat("u1", "user", "the myreport.docx draft is ready", T0),
            *_file_event("c1", EventCategory.FILE_CREATED, DOC, T0 + timedelta(hours=1)),
        ]
    )
    assert DOC not in _by_path(store)


def test_ai_service_download_links_target_path(store: CaseStore) -> None:
    store.add(
        [
            *_download("d1", DOC, T0),
            *_file_event("c1", EventCategory.FILE_CREATED, DOC, T0 + timedelta(seconds=1)),
        ]
    )
    finding = _by_path(store)[DOC]
    assert _kinds(finding) == {"ai_download"}
    assert finding.band is ConfidenceBand.STRONG


def test_time_proximity_after_assistant_message_is_low_and_weak(store: CaseStore) -> None:
    store.add(
        [
            *_chat("a1", "assistant", "saved the file", T0),
            *_file_event("c1", EventCategory.FILE_MODIFIED, DOC, T0 + timedelta(minutes=5)),
        ]
    )
    finding = _by_path(store)[DOC]
    assert _kinds(finding) == {"time_proximity"}
    assert finding.confidence == pytest.approx(0.3)
    assert finding.band is ConfidenceBand.WEAK
    assert finding.severity is Severity.LOW


def test_deleted_file_linked_to_ai_is_medium(store: CaseStore) -> None:
    store.add(
        [
            *_write_call("w1", DOC, T0),
            *_file_event("c1", EventCategory.FILE_CREATED, DOC, T0 + timedelta(seconds=1)),
            *_file_event("d1", EventCategory.FILE_DELETED, DOC, T0 + timedelta(hours=1)),
        ]
    )
    finding = _by_path(store)[DOC]
    assert finding.severity is Severity.MEDIUM
    assert [step["event"] for step in finding.data["lifecycle"]] == ["created", "deleted"]


def test_deleted_file_without_ai_link_is_low_but_still_reported(store: CaseStore) -> None:
    store.add(_file_event("d1", EventCategory.FILE_DELETED, SCRATCH, T0))
    finding = _by_path(store)[SCRATCH]
    assert finding.severity is Severity.LOW
    assert finding.data["links"] == []
    assert finding.narrative.endswith("Links: no AI link.")


def test_recycled_file_counts_as_deleted(store: CaseStore) -> None:
    recycled: dict[str, Any] = {"original_path": SCRATCH, "deleted_utc": "2026-10-01T02:00:00Z", "size": 1}
    store.add([_art("r1", ArtifactKind.RECYCLED_FILE, recycled)])
    finding = _by_path(store)[SCRATCH]
    assert finding.severity is Severity.LOW
    assert [step["event"] for step in finding.data["lifecycle"]] == ["recycled"]


def _good_records() -> list[Artifact | Event]:
    return [
        *_write_call("w1", DOC, T0),
        *_file_event("c1", EventCategory.FILE_CREATED, DOC, T0 + timedelta(seconds=5)),
    ]


def _bad_records() -> list[Artifact | Event]:
    wrong_type: dict[str, Any] = {"tool": "Claude Code", "call_name": "Write", "input": {}, "file_path": 123}
    missing_key: dict[str, Any] = {"original_path": SCRATCH, "size": 1}
    return [
        _art("bad-type", ArtifactKind.AI_TOOL_CALL, wrong_type),
        _art("bad-missing", ArtifactKind.RECYCLED_FILE, missing_key),
    ]



def test_malformed_artifacts_are_skipped_and_reported(store: CaseStore) -> None:
    store.add(_good_records())
    baseline = list(ANALYZER.run(store, "UTC"))
    assert not [f for f in baseline if isinstance(f, Finding) and f.category is FindingCategory.COVERAGE]

    store.add(_bad_records())
    result = list(ANALYZER.run(store, "UTC"))  # must not raise

    coverage = [f for f in result if isinstance(f, Finding) and f.category is FindingCategory.COVERAGE]
    assert [item for item in result if item not in coverage] == baseline
    assert len(coverage) == 1
    assert coverage[0].severity is Severity.LOW
    assert coverage[0].title == "file_correlation: skipped 2 malformed artifacts"
    assert coverage[0].data["artifact_ids"] == ["bad-missing", "bad-type"]
