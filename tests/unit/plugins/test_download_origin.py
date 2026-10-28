from __future__ import annotations

import logging
import plistlib
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.dir_fs import host_xattrs
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.fsmeta.download_origin import PLUGIN, QUARANTINE, WHERE_FROMS, ZONE_STREAM

LOG = logging.getLogger("tests.download_origin")
MAC_HOME = "/Users/kim"
WIN_HOME = "/Users/lee"
MTIME = datetime(2026, 10, 1, 2, 0, 0, tzinfo=UTC)
QUARANTINE_TS = datetime(2026, 10, 1, 1, 30, 0, tzinfo=UTC)
ZONE = (
    b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://chatgpt.com/c/abc\r\n"
    b"HostUrl=https://files.oaiusercontent.com/file-1/report.docx\r\n"
)


def _where_froms(*urls: str) -> bytes:
    return plistlib.dumps(list(urls), fmt=plistlib.FMT_BINARY)


def _quarantine(ts: datetime = QUARANTINE_TS, agent: str = "Safari") -> bytes:
    return f"0083;{int(ts.timestamp()):08x};{agent};4C2E1B9A-0000-4000-8000-000000000001".encode()


def _run(fs: MemoryFS) -> list[Artifact | Event]:
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="Asia/Seoul", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _events(records: list[Artifact | Event]) -> list[Event]:
    return [r for r in records if isinstance(r, Event)]


def _mac_fs(xattrs: dict[str, dict[str, bytes]], extra_files: tuple[str, ...] = ()) -> MemoryFS:
    files = {path: b"data" for path in (*xattrs, *extra_files)}
    files[f"{MAC_HOME}/Library/Preferences/x.plist"] = b""
    return MemoryFS(files, volume_os=OsFamily.MACOS, mtimes={p: MTIME for p in files}, xattrs=xattrs)


def test_zone_identifier_yields_origin_with_ai_service_and_mtime_event() -> None:
    target = f"{WIN_HOME}/Downloads/report.docx"
    fs = MemoryFS(
        {target: b"PK", f"{WIN_HOME}/AppData/Roaming/x": b""},
        volume_os=OsFamily.WINDOWS,
        mtimes={target: MTIME},
        streams={target: {ZONE_STREAM: ZONE}},
    )
    records = _run(fs)
    [origin] = _kind(records, ArtifactKind.DOWNLOAD_ORIGIN)
    assert origin.data == {
        "url": "https://files.oaiusercontent.com/file-1/report.docx",
        "origin_url": "https://chatgpt.com/c/abc",
        "agent": "",
        "target_path": target,
        "ai_service": "ChatGPT",
        "extra": {"source": "zone_identifier", "zone_id": 3},
    }
    assert origin.user == "lee"
    assert origin.provenance.source_path == target
    assert origin.provenance.record_locator == "ads:Zone.Identifier"
    [event] = _events(records)
    assert event.category is EventCategory.DOWNLOAD
    assert event.actor is Actor.HUMAN
    assert (event.ts_utc, event.ts_kind, event.subject) == (MTIME, "mtime", target)
    assert not _kind(records, ArtifactKind.PARSE_WARNING)


def test_utf16_zone_identifier_without_urls_keeps_zone_id_only() -> None:
    target = f"{WIN_HOME}/Downloads/tool.exe"
    raw = "\ufeff[ZoneTransfer]\r\nZoneId=3\r\n".encode("utf-16-le")
    fs = MemoryFS({target: b"MZ"}, volume_os=OsFamily.WINDOWS, streams={target: {ZONE_STREAM: raw}})
    records = _run(fs)
    [origin] = _kind(records, ArtifactKind.DOWNLOAD_ORIGIN)
    assert origin.data["url"] == "" and origin.data["origin_url"] == ""
    assert "ai_service" not in origin.data
    assert origin.data["extra"] == {"source": "zone_identifier", "zone_id": 3}
    [event] = _events(records)
    assert (event.ts_utc, event.ts_kind, event.ts_basis) == (None, "unknown", "unknown")


def test_malformed_zone_identifier_is_parse_warning() -> None:
    target = f"{WIN_HOME}/Downloads/a.zip"
    fs = MemoryFS({target: b"PK"}, volume_os=OsFamily.WINDOWS, streams={target: {ZONE_STREAM: b"garbage"}})
    records = _run(fs)
    assert not _kind(records, ArtifactKind.DOWNLOAD_ORIGIN)
    [warning] = _kind(records, ArtifactKind.PARSE_WARNING)
    assert warning.data["plugin"] == "download_origin"
    assert warning.data["message"].startswith("malformed Zone.Identifier stream")


def test_where_froms_and_quarantine_combine_with_quarantine_time() -> None:
    target = f"{MAC_HOME}/Downloads/logo.png"
    fs = _mac_fs(
        {
            target: {
                WHERE_FROMS: _where_froms("https://cdn.example.net/logo.png", "https://claude.ai/chat/1"),
                QUARANTINE: _quarantine(),
            }
        }
    )
    records = _run(fs)
    [origin] = _kind(records, ArtifactKind.DOWNLOAD_ORIGIN)
    assert origin.data == {
        "url": "https://cdn.example.net/logo.png",
        "origin_url": "https://claude.ai/chat/1",
        "agent": "Safari",
        "target_path": target,
        "ai_service": "Claude",
        "extra": {
            "source": "kMDItemWhereFroms",
            "quarantine_flags": "0083",
            "quarantine_uuid": "4C2E1B9A-0000-4000-8000-000000000001",
        },
    }
    [event] = _events(records)
    assert (event.ts_utc, event.ts_kind, event.ts_basis) == (QUARANTINE_TS, "quarantine_time", "native_utc")
    assert event.data == {"ai_service": "Claude", "source": "kMDItemWhereFroms"}


def test_xml_where_froms_without_quarantine_uses_mtime_and_no_ai_service() -> None:
    target = f"{MAC_HOME}/Documents/paper.pdf"
    fs = _mac_fs({target: {WHERE_FROMS: plistlib.dumps(["https://example.com/paper.pdf"])}})
    records = _run(fs)
    [origin] = _kind(records, ArtifactKind.DOWNLOAD_ORIGIN)
    assert origin.data["url"] == "https://example.com/paper.pdf"
    assert origin.data["origin_url"] == "" and origin.data["agent"] == ""
    assert "ai_service" not in origin.data
    [event] = _events(records)
    assert (event.ts_utc, event.ts_kind) == (MTIME, "mtime")


def test_corrupt_where_froms_plist_warns_and_quarantine_still_emits() -> None:
    target = f"{MAC_HOME}/Downloads/setup.dmg"
    fs = _mac_fs({target: {WHERE_FROMS: b"bplist00\xff\xff corrupt", QUARANTINE: _quarantine(agent="Google Chrome")}})
    records = _run(fs)
    [warning] = _kind(records, ArtifactKind.PARSE_WARNING)
    assert warning.data["message"].startswith(f"malformed {WHERE_FROMS} xattr: corrupt plist")
    [origin] = _kind(records, ArtifactKind.DOWNLOAD_ORIGIN)
    assert origin.data["url"] == "" and origin.data["agent"] == "Google Chrome"
    assert origin.data["extra"]["source"] == "quarantine"


def test_non_list_plist_and_bad_quarantine_time_only_warn() -> None:
    target = f"{MAC_HOME}/Downloads/x.bin"
    fs = _mac_fs({target: {WHERE_FROMS: plistlib.dumps({"a": 1}), QUARANTINE: b"0083;zzzz;Safari;u"}})
    records = _run(fs)
    assert not _kind(records, ArtifactKind.DOWNLOAD_ORIGIN)
    messages = sorted(w.data["message"] for w in _kind(records, ArtifactKind.PARSE_WARNING))
    assert messages == [
        f"malformed {WHERE_FROMS} xattr: expected a plist array, got dict",
        f"malformed {QUARANTINE} xattr: quarantine time is not hexadecimal: 'zzzz'",
    ]


def test_skipped_dirs_depth_limit_and_unrelated_xattrs() -> None:
    tagged = {WHERE_FROMS: _where_froms("https://chatgpt.com/x")}
    kept = f"{MAC_HOME}/a/b/c/d/e/f.txt"
    fs = _mac_fs(
        {
            kept: tagged,
            f"{MAC_HOME}/a/b/c/d/e/f/too_deep.txt": tagged,
            f"{MAC_HOME}/Library/Caches/com.x/cached.bin": tagged,
            f"{MAC_HOME}/proj/node_modules/pkg/index.js": tagged,
            f"{MAC_HOME}/proj/.git/objects/blob": tagged,
            f"{MAC_HOME}/proj/.venv/lib/x.py": tagged,
            f"{MAC_HOME}/Desktop/notes.txt": {"com.apple.provenance": b"\x01\x02"},
        }
    )
    origins = _kind(_run(fs), ArtifactKind.DOWNLOAD_ORIGIN)
    assert [o.data["target_path"] for o in origins] == [kept]


def test_windows_temp_dir_is_skipped() -> None:
    target = f"{WIN_HOME}/AppData/Local/Temp/x.exe"
    fs = MemoryFS({target: b"MZ"}, volume_os=OsFamily.WINDOWS, streams={target: {ZONE_STREAM: ZONE}})
    assert _run(fs) == []


@pytest.mark.realdata
def test_host_download_xattrs_parse_when_present() -> None:
    downloads = Path.home() / "Downloads"
    if sys.platform != "darwin" or not downloads.is_dir():
        pytest.skip(f"store absent: {downloads}")
    tagged: dict[str, dict[str, bytes]] = {}
    for path in sorted(downloads.iterdir(), key=lambda p: p.lstat().st_mtime, reverse=True)[:200]:
        if path.is_symlink() or not path.is_file():
            continue
        try:
            attrs = host_xattrs(str(path))
        except PermissionError:
            continue
        wanted = {k: v for k, v in attrs.items() if k in (WHERE_FROMS, QUARANTINE)}
        if wanted:
            tagged[f"/Users/examiner/Downloads/{path.name}"] = wanted
    if not tagged:
        pytest.skip(f"store absent: {downloads} (no WhereFroms/quarantine xattrs)")
    fs = MemoryFS({p: b"" for p in tagged}, volume_os=OsFamily.MACOS, xattrs=tagged)
    records = _run(fs)
    origins = _kind(records, ArtifactKind.DOWNLOAD_ORIGIN)
    warnings = _kind(records, ArtifactKind.PARSE_WARNING)
    print(f"realdata download_origin: files={len(tagged)} origins={len(origins)} warnings={len(warnings)}")
    assert origins
    assert all(w.data["message"].startswith("malformed") for w in warnings)
