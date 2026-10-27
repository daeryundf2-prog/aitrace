from __future__ import annotations

import logging
import struct
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from aitrace.core.kinds import ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.windows.recycle_lnk_jumplist import PLUGIN, parse_recycle_i

LOG = logging.getLogger("tests.recycle_lnk_jumplist")
SID = "S-1-5-21-1000-1000-1000-1001"
RECENT = "/Users/kim/AppData/Roaming/Microsoft/Windows/Recent"
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
DELETED = datetime(2026, 10, 1, 2, 0, 0, tzinfo=UTC)
ORIGINAL = "C:\\Users\\kim\\Documents\\old_report.docx"
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD


def _filetime(ts: datetime) -> int:
    return (ts - FILETIME_EPOCH) // timedelta(microseconds=1) * 10


def _i_v2(path: str = ORIGINAL, size: int = 12345, deleted: datetime = DELETED) -> bytes:
    encoded = (path + "\x00").encode("utf-16-le")
    return struct.pack("<QQQI", 2, size, _filetime(deleted), len(encoded) // 2) + encoded


def _i_v1(path: str = ORIGINAL, size: int = 777, deleted: datetime = DELETED) -> bytes:
    encoded = (path + "\x00").encode("utf-16-le").ljust(520, b"\x00")
    return struct.pack("<QQQ", 1, size, _filetime(deleted)) + encoded


def build_lnk(
    target: str = "C:\\Users\\kim\\work\\proposal.md",
    *,
    serial: int = 0xDEADBEEF,
    machine: bytes = b"kim-pc",
    created: datetime = datetime(2026, 9, 1, tzinfo=UTC),
    accessed: datetime = datetime(2026, 10, 1, 1, 30, tzinfo=UTC),
    modified: datetime = datetime(2026, 10, 1, 1, 0, tzinfo=UTC),
) -> bytes:
    flags = 0x2 | 0x80
    header = (
        struct.pack("<I", 0x4C)
        + uuid.UUID("00021401-0000-0000-c000-000000000046").bytes_le
        + struct.pack("<II", flags, 0x20)
        + struct.pack("<QQQ", _filetime(created), _filetime(accessed), _filetime(modified))
        + struct.pack("<III", 4096, 0, 1)
        + struct.pack("<HHII", 0, 0, 0, 0)
    )
    label = b"WINFIX\x00"
    volume_id = struct.pack("<IIII", 16 + len(label), 3, serial, 16) + label
    base = target.encode("cp1252") + b"\x00"
    suffix = b"\x00"
    header_size = 28
    volume_offset = header_size
    base_offset = volume_offset + len(volume_id)
    suffix_offset = base_offset + len(base)
    info_size = suffix_offset + len(suffix)
    info = (
        struct.pack("<IIIIIII", info_size, header_size, 1, volume_offset, base_offset, 0, suffix_offset)
        + volume_id
        + base
        + suffix
    )
    tracker = (
        struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0)
        + machine.ljust(16, b"\x00")
        + b"\x01" * 16 * 4
    )
    return header + info + tracker + struct.pack("<I", 0)


def build_ole(streams: dict[str, tuple[bytes, datetime | None]]) -> bytes:
    sector = 512
    names = list(streams)
    sectors_per = [max(1, -(-len(streams[n][0]) // sector)) for n in names]
    fat = [FATSECT, ENDOFCHAIN, ENDOFCHAIN]
    starts: list[int] = []
    for count in sectors_per:
        start = len(fat)
        starts.append(start)
        fat.extend(list(range(start + 1, start + count)) + [ENDOFCHAIN])
    fat_sector = b"".join(struct.pack("<I", v) for v in fat).ljust(sector, b"\xff")

    def entry(name: str, kind: int, left: int, right: int, child: int, start: int, size: int, mtime: int) -> bytes:
        raw = (name + "\x00").encode("utf-16-le")
        return (
            raw.ljust(64, b"\x00")
            + struct.pack("<HBBIII", len(raw), kind, 1, left, right, child)
            + b"\x00" * 16
            + struct.pack("<IQQIQ", 0, 0, mtime, start, size)
        )

    entries = [entry("Root Entry", 5, FREESECT, FREESECT, 1 if names else FREESECT, ENDOFCHAIN, 0, 0)]
    for index, name in enumerate(names):
        stamp = streams[name][1]
        right = index + 2 if index + 1 < len(names) else FREESECT
        entries.append(
            entry(name, 2, FREESECT, right, FREESECT, starts[index], len(streams[name][0]),
                  _filetime(stamp) if stamp else 0)
        )
    directory = b"".join(entries).ljust(sector, b"\x00")
    header = (
        bytes.fromhex("d0cf11e0a1b11ae1")
        + b"\x00" * 16
        + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6)
        + b"\x00" * 6
        + struct.pack("<IIIIIIIII", 0, 1, 1, 0, 0, 2, 1, ENDOFCHAIN, 0)
        + struct.pack("<I", 0)
        + struct.pack("<I", FREESECT) * 108
    )
    body = b"".join(streams[n][0].ljust(c * sector, b"\x00") for n, c in zip(names, sectors_per, strict=True))
    minifat = b"\xff" * sector
    return header.ljust(sector, b"\x00") + fat_sector + directory + minifat + body


def _run(files: dict[str, bytes]) -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=OsFamily.WINDOWS)
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="Asia/Seoul", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _events(records: list[Artifact | Event]) -> list[Event]:
    return [r for r in records if isinstance(r, Event)]


def _warnings(records: list[Artifact | Event]) -> list[str]:
    return [str(r.data["message"]) for r in _kind(records, ArtifactKind.PARSE_WARNING)]


def test_parse_recycle_i_v1_and_v2() -> None:
    assert parse_recycle_i(_i_v1()) == (1, 777, _filetime(DELETED), ORIGINAL)
    assert parse_recycle_i(_i_v2()) == (2, 12345, _filetime(DELETED), ORIGINAL)


def test_recycle_v2_yields_path_time_and_pair() -> None:
    records = _run(
        {
            f"/$Recycle.Bin/{SID}/$IABC123.txt": _i_v2(),
            f"/$Recycle.Bin/{SID}/$RABC123.txt": b"payload",
        }
    )
    (artifact,) = _kind(records, ArtifactKind.RECYCLED_FILE)
    assert artifact.data["original_path"] == "/Users/kim/Documents/old_report.docx"
    assert artifact.data["raw_path"] == ORIGINAL
    assert artifact.data["deleted_utc"] == "2026-10-01T02:00:00Z"
    assert artifact.data["size"] == 12345
    assert artifact.data["extra"]["r_file_present"] is True
    assert artifact.data["extra"]["sid"] == SID
    (event,) = _events(records)
    assert event.category == EventCategory.FILE_DELETED
    assert event.ts_utc == DELETED
    assert event.artifact_id == artifact.id


def test_recycle_v1_without_r_file() -> None:
    records = _run({f"/$Recycle.Bin/{SID}/$IZZZ999.doc": _i_v1()})
    (artifact,) = _kind(records, ArtifactKind.RECYCLED_FILE)
    assert artifact.data["extra"]["version"] == 1
    assert artifact.data["extra"]["r_file_present"] is False
    assert artifact.data["size"] == 777


def test_short_i_file_warns() -> None:
    records = _run({f"/$Recycle.Bin/{SID}/$ISHORT.txt": b"0123456789"})
    assert not _kind(records, ArtifactKind.RECYCLED_FILE)
    assert not _events(records)
    assert any("too short" in message for message in _warnings(records))


def test_bad_version_and_overlong_name_warn() -> None:
    bad_version = struct.pack("<QQQ", 9, 0, 0) + b"\x00" * 8
    overlong = struct.pack("<QQQI", 2, 1, _filetime(DELETED), 5000) + b"a\x00"
    records = _run(
        {
            f"/$Recycle.Bin/{SID}/$IBADVER": bad_version,
            f"/$Recycle.Bin/{SID}/$IOVERLONG": overlong,
        }
    )
    assert len(_warnings(records)) == 2
    assert not _kind(records, ArtifactKind.RECYCLED_FILE)


def test_lnk_in_recent_and_desktop() -> None:
    records = _run(
        {
            f"{RECENT}/proposal.md.lnk": build_lnk(),
            "/Users/kim/Desktop/docs.lnk": build_lnk("C:\\Users\\kim\\Documents"),
        }
    )
    shortcuts = _kind(records, ArtifactKind.SHORTCUT)
    assert sorted(s.data["target_path"] for s in shortcuts) == [
        "/Users/kim/Documents",
        "/Users/kim/work/proposal.md",
    ]
    proposal = next(s for s in shortcuts if s.data["target_path"].endswith("proposal.md"))
    assert proposal.data["source"] == "lnk"
    assert proposal.data["raw_path"] == "C:\\Users\\kim\\work\\proposal.md"
    extra = proposal.data["extra"]
    assert extra["volume_serial"] == "DEADBEEF"
    assert extra["machine_id"] == "kim-pc"
    assert extra["target_created"] == "2026-09-01T00:00:00Z"
    assert extra["target_accessed"] == "2026-10-01T01:30:00Z"
    assert extra["target_modified"] == "2026-10-01T01:00:00Z"
    assert not _events(records)
    assert not _warnings(records)


def test_garbage_lnk_warns() -> None:
    records = _run({f"{RECENT}/bad.lnk": b"not a shortcut at all" * 5})
    assert not _kind(records, ArtifactKind.SHORTCUT)
    assert len(_warnings(records)) == 1


def test_automatic_destinations_jumplist() -> None:
    stamp = datetime(2026, 10, 1, 3, 0, tzinfo=UTC)
    ole = build_ole(
        {
            "1": (build_lnk("C:\\Users\\kim\\work\\proposal.md"), stamp),
            "2a": (build_lnk("C:\\Users\\kim\\work\\edited.md"), None),
            "DestList": (b"\x00" * 64, None),
        }
    )
    records = _run({f"{RECENT}/AutomaticDestinations/5f7b5f1e01b83767.automaticDestinations-ms": ole})
    shortcuts = _kind(records, ArtifactKind.SHORTCUT)
    assert sorted(s.data["target_path"] for s in shortcuts) == [
        "/Users/kim/work/edited.md",
        "/Users/kim/work/proposal.md",
    ]
    assert all(s.data["source"] == "jumplist" for s in shortcuts)
    events = {e.subject: e for e in _events(records)}
    assert all(e.category == EventCategory.FILE_ACCESSED for e in events.values())
    assert events["/Users/kim/work/proposal.md"].ts_utc == stamp
    assert events["/Users/kim/work/edited.md"].ts_utc == datetime(2026, 10, 1, 1, 30, tzinfo=UTC)
    assert not _warnings(records)


def test_corrupt_automatic_destinations_warns() -> None:
    records = _run({f"{RECENT}/AutomaticDestinations/bad.automaticDestinations-ms": b"junk" * 200})
    assert len(_warnings(records)) == 1
    assert not _kind(records, ArtifactKind.SHORTCUT)


def test_custom_destinations_jumplist() -> None:
    blob = (
        b"\x00" * 8
        + build_lnk("C:\\Users\\kim\\work\\a.txt")
        + build_lnk("C:\\Users\\kim\\work\\b.txt")
        + bytes.fromhex("abfbbfba")
    )
    records = _run({f"{RECENT}/CustomDestinations/abc.customDestinations-ms": blob})
    shortcuts = _kind(records, ArtifactKind.SHORTCUT)
    assert sorted(s.data["target_path"] for s in shortcuts) == ["/Users/kim/work/a.txt", "/Users/kim/work/b.txt"]
    assert len(_events(records)) == 2
    assert not _warnings(records)


def test_custom_destinations_without_lnk_warns() -> None:
    records = _run({f"{RECENT}/CustomDestinations/empty.customDestinations-ms": b"\x00" * 32})
    assert len(_warnings(records)) == 1


def test_locate_roles() -> None:
    fs = MemoryFS(
        {
            f"/$Recycle.Bin/{SID}/$IABC.txt": _i_v2(),
            f"/$Recycle.Bin/{SID}/$RABC.txt": b"x",
            f"{RECENT}/a.lnk": build_lnk(),
            "/Users/kim/Desktop/d.lnk": build_lnk(),
            f"{RECENT}/AutomaticDestinations/x.automaticDestinations-ms": b"",
            f"{RECENT}/CustomDestinations/y.customDestinations-ms": b"",
        },
        volume_os=OsFamily.WINDOWS,
    )
    roles = sorted(c.role for c in PLUGIN.locate(fs))
    assert roles == ["automatic_destinations", "custom_destinations", "lnk", "lnk", "recycle_i"]


@pytest.mark.parametrize("data", [b"", b"\x01" * 25])
def test_parse_recycle_i_rejects_garbage(data: bytes) -> None:
    with pytest.raises(ValueError):
        parse_recycle_i(data)
