from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from aitrace.core.kinds import ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.remote.remote_tools import PLUGIN

FIXTURES = (
    Path(__file__).resolve().parents[2] / "fixtures" / "files" / "third_party" / "dissect" / "plugins" / "apps" / "remoteaccess"
)
WIN_HOME = "/Users/kim"
ANYDESK_TRANSFER = f"{WIN_HOME}/AppData/Roaming/AnyDesk/file_transfer_trace.txt"


def _run(fs: MemoryFS) -> list[Artifact | Event]:
    ctx = ParseContext(fs=fs, evidence_id=fs.evidence_id, tz="UTC", log=logging.getLogger("test.remote_tools"))
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _artifacts(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def test_anydesk_sample_yields_file_transfers() -> None:
    raw = (FIXTURES / "anydesk" / "file_transfer_trace.txt").read_bytes()
    fs = MemoryFS({ANYDESK_TRANSFER: raw}, volume_os=OsFamily.WINDOWS)

    records = _run(fs)
    transfers = _artifacts(records, ArtifactKind.FILE_TRANSFER)
    events = [r for r in records if isinstance(r, Event)]

    assert transfers
    assert "download" in {t.data["direction"] for t in transfers}
    assert "malware.exe" in {t.data["extra"]["file_name"] for t in transfers}
    assert {e.category for e in events} == {EventCategory.DOWNLOAD}


def test_empty_anydesk_file_yields_nothing() -> None:
    fs = MemoryFS({ANYDESK_TRANSFER: b""}, volume_os=OsFamily.WINDOWS)

    assert _run(fs) == []


def test_malformed_anydesk_row_becomes_parse_warning() -> None:
    row = b"Clipboard\t\tnot-a-date\tstart \tdownload\t'x.exe'\n"
    fs = MemoryFS({ANYDESK_TRANSFER: row}, volume_os=OsFamily.WINDOWS)

    records = _run(fs)

    assert _artifacts(records, ArtifactKind.FILE_TRANSFER) == []
    warnings = _artifacts(records, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 1
    assert warnings[0].data["plugin"] == "remote_tools"


def test_teamviewer_incoming_row_yields_session_with_start_and_end() -> None:
    row = "123456789\tAlice-PC\t11-11-2021 12:34:56\t11-11-2021 12:40:00\tbob\tincoming\t42\n"
    fs = MemoryFS(
        {"/Program Files (x86)/TeamViewer/Connections_incoming.txt": row.encode()},
        volume_os=OsFamily.WINDOWS,
    )

    records = _run(fs)
    sessions = _artifacts(records, ArtifactKind.REMOTE_SESSION)
    events = [r for r in records if isinstance(r, Event)]

    assert len(sessions) == 1
    assert sessions[0].data["protocol"] == "teamviewer"
    assert sessions[0].data["direction"] == "inbound"
    assert sessions[0].data["remote_host"] == "123456789"
    assert sessions[0].data["account"] == "bob"
    assert [(e.ts_kind, e.ts_utc) for e in events] == [
        ("session_start", datetime(2021, 11, 11, 12, 34, 56, tzinfo=UTC)),
        ("session_end", datetime(2021, 11, 11, 12, 40, 0, tzinfo=UTC)),
    ]


def test_saved_rdp_file_yields_outbound_remote_session() -> None:
    content = b"full address:s:10.1.2.3:3389\r\nusername:s:kim\r\nprompt for credentials:i:0\r\n"
    fs = MemoryFS({f"{WIN_HOME}/Documents/Default.rdp": content}, volume_os=OsFamily.WINDOWS)

    sessions = _artifacts(_run(fs), ArtifactKind.REMOTE_SESSION)

    assert len(sessions) == 1
    assert sessions[0].data["protocol"] == "rdp"
    assert sessions[0].data["direction"] == "outbound"
    assert sessions[0].data["remote_host"] == "10.1.2.3:3389"
    assert sessions[0].data["account"] == "kim"
