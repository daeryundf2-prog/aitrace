from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from aitrace.core.ids import NAMESPACE, make_id
from aitrace.core.kinds import (
    SIGNAL_CAPS,
    SIGNAL_DIRECTION,
    Actor,
    ArtifactKind,
    ConfidenceBand,
    EventCategory,
    FindingCategory,
    OsFamily,
    Severity,
    SignalType,
    Verdict,
    band_for,
)
from aitrace.core.model import (
    Artifact,
    Attribution,
    Case,
    Event,
    Evidence,
    Finding,
    Provenance,
    Signal,
    UserProfile,
    VolumeInfo,
)

TS = datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC)


def _user() -> UserProfile:
    return UserProfile(name="kim", home="/Users/kim", volume=0, os_family=OsFamily.WINDOWS, sid="S-1-5-21-1")


def _volume() -> VolumeInfo:
    return VolumeInfo(index=0, fs_type="NtfsFilesystem", label="WINFIX", size=1024, os_family=OsFamily.WINDOWS)


def _provenance() -> Provenance:
    return Provenance(
        evidence_id="ev1",
        volume=0,
        source_path="/Users/kim/.claude/projects/x.jsonl",
        plugin="claude_code",
        plugin_version="1.0",
        inode=42,
        sha256="ab" * 32,
        deleted=True,
        record_locator="line:12",
    )


def _signal() -> Signal:
    return Signal(type=SignalType.C2PA, direction="ai", weight=0.9, artifact_ids=("a1", "a2"), note="c2pa")


SAMPLES = [
    _user(),
    _volume(),
    Evidence(
        id="ev1",
        kind="e01",
        path="/cases/x.E01",
        segments=("/cases/x.E01", "/cases/x.E02"),
        size=2048,
        acquisition_hashes={"md5": "00"},
        segment_hashes={"/cases/x.E01": {"sha256": "11"}},
        media_sha256=None,
        verification_status="unverified",
        volumes=(_volume(),),
        users=(_user(),),
        limitations=("stored hash unreadable",),
    ),
    Case(
        id=make_id("case", "2026-001"),
        name="test",
        number="2026-001",
        examiner="examiner",
        organisation="org",
        created_utc=TS,
        timezone="Asia/Seoul",
        lang="ko",
        tool_version="0.1.0",
    ),
    _provenance(),
    Artifact(
        id="a1",
        kind=ArtifactKind.AI_CHAT_MESSAGE,
        provenance=_provenance(),
        data={"tool": "Claude Code", "role": "user", "text": "요약해줘", "fragment": False},
        user="kim",
        warnings=("truncated",),
    ),
    Event(
        id="e1",
        artifact_id="a1",
        ts_utc=TS,
        ts_kind="message",
        ts_basis="native_utc",
        category=EventCategory.AI_ACTIVITY,
        actor=Actor.HUMAN,
        user="kim",
        summary="prompt",
        subject="/Users/kim/work/proposal.md",
        data={"k": 1},
    ),
    Event(
        id="e2",
        artifact_id="a1",
        ts_utc=None,
        ts_kind="unknown",
        ts_basis="unknown",
        category=EventCategory.OTHER,
        actor=Actor.UNKNOWN,
        user=None,
        summary="no time",
    ),
    _signal(),
    Attribution(
        id="at1",
        subject="/Users/kim/work/proposal.md",
        subject_artifact_ids=("a1",),
        verdict=Verdict.AI_GENERATED,
        confidence=0.9,
        band=ConfidenceBand.STRONG,
        signals=(_signal(),),
        rationale="c2pa 0.90",
        limitations=("absence of AI traces does not prove human authorship",),
    ),
    Finding(
        id="f1",
        category=FindingCategory.EXFIL_CHANNEL,
        severity=Severity.HIGH,
        title="scp",
        narrative="scp to 203.0.113.10",
        artifact_ids=("a1",),
        event_ids=("e1",),
        confidence=0.8,
        band=ConfidenceBand.STRONG,
        rule_id="TR-SCP",
        limitations=(),
        data={"destination": "203.0.113.10"},
    ),
]


@pytest.mark.parametrize("obj", SAMPLES, ids=lambda o: type(o).__name__)
def test_round_trip_through_json(obj: object) -> None:
    encoded = obj.to_dict()  # type: ignore[attr-defined]
    decoded = type(obj).from_dict(json.loads(json.dumps(encoded)))  # type: ignore[attr-defined]
    assert decoded == obj
    assert decoded.to_dict() == encoded


def test_every_model_dataclass_is_covered() -> None:
    covered = {type(o) for o in SAMPLES}
    assert covered == {
        UserProfile,
        VolumeInfo,
        Evidence,
        Case,
        Provenance,
        Artifact,
        Event,
        Signal,
        Attribution,
        Finding,
    }


def test_serialization_formats() -> None:
    case = next(o for o in SAMPLES if isinstance(o, Case))
    artifact = next(o for o in SAMPLES if isinstance(o, Artifact))
    assert case.to_dict()["created_utc"] == "2026-10-01T01:00:00Z"
    encoded = artifact.to_dict()
    assert encoded["kind"] == "ai_chat_message"
    assert encoded["warnings"] == ["truncated"]
    assert encoded["provenance"]["record_locator"] == "line:12"


def test_datetimes_are_converted_to_utc() -> None:
    from datetime import timedelta, timezone

    kst = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone(timedelta(hours=9)))
    event = Event(
        id="e",
        artifact_id="a",
        ts_utc=kst,
        ts_kind="k",
        ts_basis="native_utc",
        category=EventCategory.OTHER,
        actor=Actor.SYSTEM,
        user=None,
        summary="s",
    )
    assert event.to_dict()["ts_utc"] == "2026-10-01T01:00:00Z"


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValueError):
        Event(
            id="e",
            artifact_id="a",
            ts_utc=datetime(2026, 10, 1),
            ts_kind="k",
            ts_basis="native_utc",
            category=EventCategory.OTHER,
            actor=Actor.SYSTEM,
            user=None,
            summary="s",
        )


def test_attribution_requires_limitations() -> None:
    with pytest.raises(ValueError):
        Attribution(
            id="x",
            subject="/a",
            subject_artifact_ids=(),
            verdict=Verdict.UNDETERMINED,
            confidence=0.0,
            band=ConfidenceBand.UNDETERMINED,
            signals=(),
            rationale="",
            limitations=(),
        )


def test_models_are_frozen_and_kw_only() -> None:
    user = _user()
    with pytest.raises(AttributeError):
        user.name = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        UserProfile("kim", "/Users/kim", 0, OsFamily.WINDOWS)  # type: ignore[misc]


def test_make_id_is_deterministic_uuid5() -> None:
    parts = ("ev1", "claude_code", 0, "/Users/kim/x.jsonl", "line:1", ArtifactKind.AI_CHAT_MESSAGE)
    first = make_id(*parts)
    assert first == make_id(*parts)
    assert first == uuid.uuid5(NAMESPACE, "\x1f".join(str(p) for p in parts)).hex
    assert len(first) == 32
    assert make_id("a", "b") != make_id("ab")
    assert str(NAMESPACE) == "7f6c2a52-6a0e-4c1b-9a51-2b5f5e0f9a11"


@pytest.mark.parametrize(
    ("conf", "band"),
    [
        (0.0, ConfidenceBand.UNDETERMINED),
        (0.19, ConfidenceBand.UNDETERMINED),
        (0.2, ConfidenceBand.WEAK),
        (0.49, ConfidenceBand.WEAK),
        (0.5, ConfidenceBand.MODERATE),
        (0.74, ConfidenceBand.MODERATE),
        (0.75, ConfidenceBand.STRONG),
        (0.95, ConfidenceBand.STRONG),
    ],
)
def test_band_for(conf: float, band: ConfidenceBand) -> None:
    assert band_for(conf) is band


def test_signal_tables_cover_every_signal() -> None:
    assert set(SIGNAL_CAPS) == set(SignalType)
    assert SIGNAL_CAPS[SignalType.AGENT_TOOL_WRITE] == 0.90
    assert SIGNAL_CAPS[SignalType.TIME_PROXIMITY] == 0.40
    assert {s for s, d in SIGNAL_DIRECTION.items() if d == "human"} == {
        SignalType.HUMAN_EDIT_AFTER,
        SignalType.HUMAN_PROCESS,
    }
    assert set(SIGNAL_DIRECTION) == set(SignalType)
