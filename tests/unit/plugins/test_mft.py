from __future__ import annotations

import logging
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aitrace.core.kinds import ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.windows.mft import PLUGIN, RECORD_SIZE, TS_DELETED, MftRow, parse_mft_stream

LOG = logging.getLogger("tests.mft")
SAMPLE = Path("third_party/dissect/plugins/filesystem/ntfs/mft/mft.raw")
FLAGS_OFFSET = 0x16  # FILE_RECORD_SEGMENT_HEADER.Flags, outside the fixup positions at 510/1022


@pytest.fixture
def sample(samples_dir: Path) -> bytes:
    return (samples_dir / SAMPLE).read_bytes()


def _mark_deleted(data: bytes, entry: int) -> bytes:
    buf = bytearray(data)
    buf[entry * RECORD_SIZE + FLAGS_OFFSET] &= 0xFE
    return bytes(buf)


def _by_path(rows: list[MftRow]) -> dict[str, MftRow]:
    return {row.path: row for row in rows}


class _NtfsFS(MemoryFS):
    def __init__(self, mft: bytes) -> None:
        super().__init__({"/placeholder": b""}, volume_os=OsFamily.WINDOWS, evidence_id="ev-1")
        self._ntfs = SimpleNamespace(mft=SimpleNamespace(get=lambda _n: SimpleNamespace(open=lambda: BytesIO(mft))))

    def raw_ntfs(self, volume: int) -> Any | None:
        return self._ntfs


def _run(mft: bytes) -> list[Artifact | Event]:
    fs = _NtfsFS(mft)
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="UTC", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def test_sample_unfiltered_yields_many_rows_and_resolves_paths(sample: bytes) -> None:
    scan = parse_mft_stream(BytesIO(sample), 0, apply_filter=False)
    assert scan.warnings == []
    assert len(scan.rows) > 10
    rows = _by_path(scan.rows)
    tracking = rows["/System Volume Information/tracking.log"]
    assert tracking.size == 20480
    assert tracking.in_use and not tracking.is_dir
    assert tracking.si_btime is not None and tracking.fn_btime is not None
    assert rows["/NamelessDirectory/totally_normal.txt"].resolved
    assert rows["/Food For Thought"].is_dir


def test_sample_filter_keeps_only_interesting_names(sample: bytes) -> None:
    scan = parse_mft_stream(BytesIO(sample), 0)
    paths = {row.path for row in scan.rows}
    assert paths == {
        "/System Volume Information/tracking.log",
        "/text_document.txt",
        "/NamelessDirectory/totally_normal.txt",
    }


def test_deleted_record_is_kept_by_filter_and_flagged(sample: bytes) -> None:
    scan = parse_mft_stream(BytesIO(_mark_deleted(sample, 37)), 0)
    deleted = [row for row in scan.rows if not row.in_use]
    assert [row.path for row in deleted] == ["/System Volume Information/WPSettings.dat"]
    assert deleted[0].entry == 37


def test_truncated_one_kib_stream_warns_without_rows(sample: bytes) -> None:
    scan = parse_mft_stream(BytesIO(sample[:1024]), 0)
    assert scan.rows == []
    assert len(scan.warnings) == 1
    assert "truncated" in scan.warnings[0]


def test_garbage_stream_becomes_warnings_not_exceptions() -> None:
    scan = parse_mft_stream(BytesIO(b"\xab" * (RECORD_SIZE * 20 + 7)), 0)
    assert scan.rows == []
    assert any("unparsable" in w for w in scan.warnings)
    assert any("truncated" in w for w in scan.warnings)


def test_locate_requires_raw_ntfs() -> None:
    assert list(PLUGIN.locate(MemoryFS({"/a": b"x"}, volume_os=OsFamily.WINDOWS))) == []
    cands = list(PLUGIN.locate(_NtfsFS(b"")))
    assert [(c.ref.volume, c.ref.path, c.role) for c in cands] == [(0, "/$MFT", "mft")]


def test_plugin_emits_file_records_and_events(sample: bytes) -> None:
    records = _run(sample)
    files = [r for r in records if isinstance(r, Artifact) and r.kind == ArtifactKind.FILE_RECORD]
    assert len(files) == 3
    tracking = next(a for a in files if a.data["path"].endswith("tracking.log"))
    assert tracking.data["source"] == "mft"
    assert tracking.data["in_use"] is True
    assert tracking.data["extra"]["mft_entry"] == 38
    assert tracking.provenance.inode == 38
    assert tracking.provenance.mft_seq == 1
    assert tracking.provenance.deleted is False
    events = [r for r in records if isinstance(r, Event)]
    assert {e.category for e in events} == {EventCategory.FILE_CREATED, EventCategory.FILE_MODIFIED}
    assert all(e.ts_utc is not None for e in events)


def test_plugin_marks_deleted_records(sample: bytes) -> None:
    records = _run(_mark_deleted(sample, 37))
    deleted_art = next(
        r for r in records if isinstance(r, Artifact) and r.data.get("path", "").endswith("WPSettings.dat")
    )
    assert deleted_art.provenance.deleted is True
    assert deleted_art.data["in_use"] is False
    deleted_events = [
        r for r in records if isinstance(r, Event) and r.artifact_id == deleted_art.id and r.category == EventCategory.FILE_DELETED
    ]
    assert len(deleted_events) == 1
    event = deleted_events[0]
    assert event.ts_kind == TS_DELETED
    assert event.data["deleted"] is True
    assert event.ts_utc is not None and event.ts_utc.isoformat().startswith(deleted_art.data["mtime"][:19])


def test_plugin_truncated_stream_yields_only_warning(sample: bytes) -> None:
    records = _run(sample[:1024])
    assert len(records) == 1
    only = records[0]
    assert isinstance(only, Artifact) and only.kind == ArtifactKind.PARSE_WARNING
