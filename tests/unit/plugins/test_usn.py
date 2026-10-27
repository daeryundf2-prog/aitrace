from __future__ import annotations

import io
import logging
import struct
from pathlib import Path

import pytest
from dissect.ntfs.exceptions import Error as NtfsError

from aitrace.core.kinds import ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.windows.usn import PLUGIN, USN_PATH, category_for, decode_reasons, parse_usn_stream

LOG = logging.getLogger("tests.usn")
SAMPLE = Path(__file__).resolve().parents[2] / (
    "fixtures/files/third_party/dissect/plugins/filesystem/ntfs/usnjrnl/usnjrnl.bin"
)
FILETIME_2021 = 132_750_000_000_000_000


def _record(usn: int, name: str, reason: int, *, major: int = 2, filetime: int = FILETIME_2021) -> bytes:
    raw = name.encode("utf-16-le")
    length = (60 + len(raw) + 7) // 8 * 8
    head = struct.pack("<IHH", length, major, 0)
    body = struct.pack("<QQqQIIIIHH", 0x30 | (1 << 48), 0x29 | (1 << 48), usn, filetime, reason, 0, 0, 0x20, len(raw), 60)
    return (head + body + raw).ljust(length, b"\x00")


def _run(files: dict[str, bytes]) -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=OsFamily.WINDOWS)
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="UTC", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def test_decode_reasons_and_category_mapping() -> None:
    assert decode_reasons(0x100 | 0x80000000) == ("FILE_CREATE", "CLOSE")
    assert decode_reasons(0x8) == ("UNKNOWN_0x00000008",)
    assert category_for(("FILE_CREATE", "CLOSE")) == EventCategory.FILE_CREATED
    assert category_for(("FILE_DELETE", "CLOSE")) == EventCategory.FILE_DELETED
    assert category_for(("RENAME_NEW_NAME",)) == EventCategory.FILE_RENAMED
    assert category_for(("DATA_EXTEND", "CLOSE")) == EventCategory.FILE_MODIFIED
    assert category_for(("SECURITY_CHANGE",)) == EventCategory.OTHER


def test_parse_skips_sparse_zero_pages_and_non_v2() -> None:
    page1 = (_record(0, "a.txt", 0x100) + _record(96, "b.txt", 0x200)).ljust(4096, b"\x00")
    sparse = b"\x00" * 8192
    page4 = (_record(500, "skip.txt", 0x100, major=3) + _record(900, "c.txt", 0x2000)).ljust(4096, b"\x00")
    records = list(parse_usn_stream(io.BytesIO(page1 + sparse + page4)))
    assert [(r.usn, r.filename) for r in records] == [(0, "a.txt"), (96, "b.txt"), (900, "c.txt")]
    assert records[0].reasons == ("FILE_CREATE",)
    assert records[0].file_ref & 0xFFFFFFFFFFFF == 0x30
    assert records[0].parent_ref & 0xFFFFFFFFFFFF == 0x29


def test_all_zero_buffer_yields_no_records_and_no_error() -> None:
    errors: list[str] = []
    assert list(parse_usn_stream(io.BytesIO(b"\x00" * 65536), errors)) == []
    assert errors == []
    assert list(parse_usn_stream(io.BytesIO(b""))) == []


def test_corrupt_header_is_reported_not_raised() -> None:
    corrupt = struct.pack("<IHH", 12, 2, 0) + b"\xff" * 64
    errors: list[str] = []
    assert list(parse_usn_stream(io.BytesIO(corrupt.ljust(4096, b"\x00")), errors)) == []
    assert len(errors) == 1 and "invalid USN record header" in errors[0]


def test_sample_journal_matches_dissect() -> None:
    if not SAMPLE.exists():
        pytest.skip(f"store absent: {SAMPLE}")
    from dissect.ntfs.usnjrnl import UsnJrnl

    with SAMPLE.open("rb") as fh:
        expected = [(r.Usn, r.filename) for r in UsnJrnl(fh).records()]
    with SAMPLE.open("rb") as fh:
        records = list(parse_usn_stream(fh))
    assert len(records) == len(expected) > 0
    assert [(r.usn, r.filename) for r in records] == expected
    assert records[0].filename == "$I1WERQN"
    assert records[0].reasons == ("FILE_CREATE",)


def test_plugin_emits_journal_artifacts_and_events() -> None:
    stream = (
        _record(0, "new.docx", 0x100)
        + _record(96, "old.txt", 0x200 | 0x80000000)
        + _record(192, "to.txt", 0x2000)
        + _record(288, "data.csv", 0x2)
        + _record(384, "acl.bin", 0x800)
    ).ljust(4096, b"\x00")
    records = _run({USN_PATH: stream})
    artifacts = [r for r in records if isinstance(r, Artifact)]
    events = [r for r in records if isinstance(r, Event)]
    assert [a.kind for a in artifacts] == [ArtifactKind.FILE_JOURNAL] * 5
    assert artifacts[0].data["source"] == "usn"
    assert artifacts[0].data["path"] == "/$UNRESOLVED/41/new.docx"
    assert artifacts[0].data["extra"]["path_resolved"] is False
    assert artifacts[0].data["extra"]["filename"] == "new.docx"
    assert artifacts[1].data["reasons"] == ["FILE_DELETE", "CLOSE"]
    assert artifacts[0].provenance.record_locator == "usn:0"
    assert [e.category for e in events] == [
        EventCategory.FILE_CREATED,
        EventCategory.FILE_DELETED,
        EventCategory.FILE_RENAMED,
        EventCategory.FILE_MODIFIED,
        EventCategory.OTHER,
    ]
    assert events[0].ts_utc is not None and events[0].ts_utc.year == 2021


class _FakeRecord:
    def __init__(self, path: str | None) -> None:
        self._path = path

    def full_path(self, ignore_dos: bool = False) -> str | None:
        return self._path


class _FakeMft:
    def __init__(self, dirs: dict[int, str]) -> None:
        self.dirs = dirs
        self.calls: list[int] = []

    def get(self, segment: int) -> _FakeRecord:
        self.calls.append(segment)
        if segment not in self.dirs:
            raise NtfsError(f"no record {segment}")
        return _FakeRecord(self.dirs[segment])


class _FakeNtfs:
    def __init__(self, mft: _FakeMft) -> None:
        self.mft = mft


def test_plugin_resolves_parent_path_through_mft_and_caches() -> None:
    stream = (_record(0, "doc.txt", 0x100) + _record(96, "other.txt", 0x100)).ljust(4096, b"\x00")
    mft = _FakeMft({0x29: "/Users/kim"})
    fs = MemoryFS({USN_PATH: stream}, volume_os=OsFamily.WINDOWS)
    fs.raw_ntfs = lambda volume: _FakeNtfs(mft)  # type: ignore[method-assign]
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="UTC", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    artifacts = [r for r in records if isinstance(r, Artifact)]
    assert [a.data["path"] for a in artifacts] == ["/Users/kim/doc.txt", "/Users/kim/other.txt"]
    assert artifacts[0].data["extra"]["path_resolved"] is True
    assert artifacts[0].data["extra"]["filename"] == "doc.txt"
    assert mft.calls == [0x29]


def test_plugin_unresolvable_parent_falls_back_to_unresolved_form() -> None:
    stream = _record(0, "doc.txt", 0x100).ljust(4096, b"\x00")
    fs = MemoryFS({USN_PATH: stream}, volume_os=OsFamily.WINDOWS)
    fs.raw_ntfs = lambda volume: _FakeNtfs(_FakeMft({}))  # type: ignore[method-assign]
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="UTC", log=LOG)
    artifact = next(r for cand in PLUGIN.locate(fs) for r in PLUGIN.parse(ctx, cand) if isinstance(r, Artifact))
    assert artifact.data["path"] == "/$UNRESOLVED/41/doc.txt"
    assert artifact.data["extra"]["path_resolved"] is False


def test_plugin_all_zero_journal_yields_nothing_and_no_candidate_without_file() -> None:
    assert _run({USN_PATH: b"\x00" * 16384}) == []
    assert _run({"/Users/kim/a.txt": b"x"}) == []


def test_plugin_corrupt_journal_becomes_parse_warning() -> None:
    corrupt = (struct.pack("<IHH", 12, 2, 0) + b"\xff" * 64).ljust(4096, b"\x00")
    records = _run({USN_PATH: corrupt})
    assert [r.kind for r in records if isinstance(r, Artifact)] == [ArtifactKind.PARSE_WARNING]
