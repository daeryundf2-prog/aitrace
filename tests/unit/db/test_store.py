from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aitrace.core.kinds import (
    Actor,
    ArtifactKind,
    ConfidenceBand,
    EventCategory,
    FindingCategory,
    OsFamily,
    Severity,
    Verdict,
)
from aitrace.core.model import Artifact, Attribution, Case, Event, Evidence, Finding, Provenance
from aitrace.db.store import CaseStore
from aitrace.plugins.base import PluginRunResult

T0 = datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)


def _artifact(id: str, kind: ArtifactKind = ArtifactKind.SHELL_COMMAND, source_path: str = "/h") -> Artifact:
    return Artifact(
        id=id,
        kind=kind,
        provenance=Provenance(
            evidence_id="ev", volume=0, source_path=source_path, plugin="p", plugin_version="1.0"
        ),
        data={"command": "ls"},
        user="kim",
    )


def _event(id: str, ts: datetime | None, category: EventCategory = EventCategory.EXECUTION) -> Event:
    return Event(
        id=id,
        artifact_id="a0",
        ts_utc=ts,
        ts_kind="k",
        ts_basis="native_utc",
        category=category,
        actor=Actor.HUMAN,
        user="kim",
        summary=id,
    )


@pytest.fixture
def store(tmp_path: Path) -> Iterator[CaseStore]:
    s = CaseStore(tmp_path / "case.sqlite")
    yield s
    s.close()


def test_add_ten_thousand_events_in_one_call_is_idempotent(store: CaseStore) -> None:
    records: list[Artifact | Event] = [_artifact("a0")]
    records += [_event(f"e{i:05d}", T0 + timedelta(seconds=i)) for i in range(10_000)]
    assert store.add(records) == 10_001
    assert store.add(records) == 0
    assert store.counts()["events"] == 10_000
    assert sum(1 for _ in store.events()) == 10_000


def test_events_order_ts_nulls_last_then_id(store: CaseStore) -> None:
    store.add(
        [
            _event("z-null", None),
            _event("b", T0 + timedelta(seconds=1)),
            _event("a-null", None),
            _event("c", T0 + timedelta(seconds=1)),
            _event("a", T0 + timedelta(seconds=1, microseconds=500)),
            _event("d", T0),
        ]
    )
    assert [e.id for e in store.events()] == ["d", "b", "c", "a", "a-null", "z-null"]


def test_events_filters(store: CaseStore) -> None:
    store.add(
        [
            _event("x", T0, EventCategory.BROWSING),
            _event("y", T0 + timedelta(hours=1)),
            _event("z", None, EventCategory.BROWSING),
        ]
    )
    assert [e.id for e in store.events(category=EventCategory.BROWSING)] == ["x", "z"]
    assert [e.id for e in store.events(start=T0 + timedelta(minutes=1))] == ["y"]
    assert [e.id for e in store.events(start=T0, end=T0)] == ["x"]


def test_artifacts_round_trip_and_counts(store: CaseStore) -> None:
    store.add(
        [
            _artifact("b", ArtifactKind.BROWSER_VISIT),
            _artifact("a", ArtifactKind.SHELL_COMMAND),
            _artifact("c", ArtifactKind.SHELL_COMMAND),
            _event("e1", T0),
        ]
    )
    assert [a.id for a in store.artifacts()] == ["a", "b", "c"]
    assert [a.id for a in store.artifacts(kind=ArtifactKind.SHELL_COMMAND)] == ["a", "c"]
    assert [a.id for a in store.artifacts(kinds=[ArtifactKind.BROWSER_VISIT])] == ["b"]
    assert store.artifact("a") == _artifact("a")
    assert store.artifact("missing") is None
    counts = store.counts()
    assert counts["shell_command"] == 2
    assert counts["browser_visit"] == 1
    assert counts["file_record"] == 0
    assert (counts["events"], counts["findings"], counts["attributions"]) == (1, 0, 0)


def test_add_rejects_empty_source_path(store: CaseStore) -> None:
    with pytest.raises(ValueError, match="source_path"):
        store.add([_artifact("bad", source_path="")])
    assert store.counts()["shell_command"] == 0


def test_add_rejects_empty_plugin_version(store: CaseStore) -> None:
    art = _artifact("bad")
    art = dataclasses.replace(art, provenance=dataclasses.replace(art.provenance, plugin_version=""))
    with pytest.raises(ValueError, match="plugin_version"):
        store.add([art])


def _finding(id: str, category: FindingCategory, severity: Severity) -> Finding:
    return Finding(
        id=id,
        category=category,
        severity=severity,
        title=id,
        narrative="n",
        artifact_ids=(),
        event_ids=(),
        confidence=0.5,
        band=ConfidenceBand.MODERATE,
        rule_id=None,
        limitations=(),
    )


def _attribution(id: str, subject: str) -> Attribution:
    return Attribution(
        id=id,
        subject=subject,
        subject_artifact_ids=(),
        verdict=Verdict.UNDETERMINED,
        confidence=0.1,
        band=ConfidenceBand.UNDETERMINED,
        signals=(),
        rationale="",
        limitations=("absence of AI traces does not prove human authorship",),
    )


def test_results_ordering(store: CaseStore) -> None:
    store.add_results(
        [
            _finding("f3", FindingCategory.EXFIL_CHANNEL, Severity.LOW),
            _finding("f1", FindingCategory.EXFIL_CHANNEL, Severity.HIGH),
            _finding("f2", FindingCategory.AI_QUERY, Severity.INFO),
            _finding("f0", FindingCategory.EXFIL_CHANNEL, Severity.MEDIUM),
            _attribution("t2", "/b"),
            _attribution("t1", "/b"),
            _attribution("t3", "/a"),
        ]
    )
    assert [f.id for f in store.findings()] == ["f2", "f1", "f0", "f3"]
    assert [f.id for f in store.findings(FindingCategory.AI_QUERY)] == ["f2"]
    assert [a.id for a in store.attributions()] == ["t3", "t1", "t2"]
    assert store.counts()["findings"] == 4 and store.counts()["attributions"] == 3


def test_case_evidence_plugin_runs_exports(store: CaseStore) -> None:
    case = Case(
        id="c1",
        name="n",
        number="1",
        examiner="e",
        organisation="o",
        created_utc=T0,
        timezone="Asia/Seoul",
        lang="ko",
        tool_version="0.1.0",
    )
    store.init_case(case)
    assert store.case() == case
    evidence = Evidence(
        id="ev",
        kind="dir",
        path="/x",
        segments=(),
        size=None,
        acquisition_hashes={},
        segment_hashes={},
        media_sha256=None,
        verification_status="unverified",
    )
    store.put_evidence(evidence)
    assert store.evidences() == [evidence]
    run = PluginRunResult(
        evidence_id="ev",
        name="p",
        version="1.0",
        status="ok",
        records=3,
        warnings=0,
        error=None,
        started_utc=T0,
        finished_utc=T0 + timedelta(seconds=2),
    )
    store.record_plugin_run(run)
    store.record_plugin_run(run)
    assert store.plugin_runs() == [run]
    entry = {
        "export_path": "export/files/a.txt",
        "sha256": "00",
        "size": 1,
        "source_volume": 0,
        "source_path": "/a.txt",
        "inode": None,
        "artifact_ids": ["a1", "a2"],
        "deleted": False,
        "note": "",
    }
    store.add_exports([entry])
    assert store.exports() == [entry]
    with pytest.raises(ValueError):
        store.add_exports([{"export_path": "x"}])
    store.finalize()


def test_reopen_keeps_data(tmp_path: Path) -> None:
    path = tmp_path / "case.sqlite"
    first = CaseStore(path)
    first.add([_artifact("a")])
    first.finalize()
    first.close()
    second = CaseStore(path)
    assert [a.id for a in second.artifacts()] == ["a"]
    second.close()


def test_unsupported_record_type(store: CaseStore) -> None:
    with pytest.raises(TypeError):
        store.add([OsFamily.LINUX])  # type: ignore[list-item]
