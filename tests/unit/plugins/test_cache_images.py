from __future__ import annotations

import logging
import sqlite3
import struct
import zlib
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.browser.cache_images import PLUGIN

LOG = logging.getLogger("tests.cache_images")
HOME = "/Users/kim"
CHROME_CACHE = f"{HOME}/Library/Caches/Google/Chrome/Default/Cache/Cache_Data"
FIREFOX_ENTRIES = f"{HOME}/Library/Caches/Firefox/Profiles/abc.default/cache2/entries"
SAFARI_DIR = f"{HOME}/Library/Caches/com.apple.Safari"
SEEN_AT = datetime(2026, 10, 3, 4, 5, 6, tzinfo=UTC)
AI_URL = "https://files.oaiusercontent.com/file-abc/cat.png"


def _chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def _png(c2pa: bool = False) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    parts = [b"\x89PNG\r\n\x1a\n", _chunk(b"IHDR", ihdr)]
    if c2pa:
        parts.append(_chunk(b"caBX", b"\x00\x00\x00\x20jumb\x00\x00\x00\x18jumdc2pa"))
    parts.append(_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")))
    parts.append(_chunk(b"IEND", b""))
    return b"".join(parts)


def _simple_entry(
    key: str, body: bytes, headers: bytes = b"HTTP/1.1 200\x00content-type: image/png\x00\x00"
) -> bytes:
    raw_key = key.encode()
    head = struct.pack("<QIIII", 0xFCFB6D1BA7725C30, 5, len(raw_key), 0, 0)
    eof = 0xF4FA6F45970D41D8
    return (
        head
        + raw_key
        + body
        + struct.pack("<QIIII", eof, 1, 0, len(body), 0)
        + headers
        + struct.pack("<QIIII", eof, 1, 0, len(headers), 0)
    )


def _firefox_entry(url: str, body: bytes, prefix: str = "a,:") -> bytes:
    meta = (
        struct.pack(">I", 0)
        + struct.pack(">IIIIIII", 3, 1, 0, 0, 0, 0, len(prefix + url))
        + (prefix + url).encode()
        + b"\x00response-head\x00HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\x00"
    )
    return body + meta + struct.pack(">I", len(body))


def _run(files: dict[str, bytes], mtimes: dict[str, datetime] | None = None) -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=OsFamily.MACOS, mtimes=mtimes)
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="Asia/Seoul", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _events(records: list[Artifact | Event]) -> list[Event]:
    return [r for r in records if isinstance(r, Event)]


def test_simple_cache_ai_image_yields_provenance_and_browsing_event() -> None:
    key = f"1/0/_dk_https://chatgpt.com https://chatgpt.com {AI_URL}?sig=SECRETVALUE123&x=1"
    path = f"{CHROME_CACHE}/0123456789abcdef_0"
    body = _png(c2pa=True)
    records = _run({path: _simple_entry(key, body)}, {path: SEEN_AT})

    [art] = _kind(records, ArtifactKind.MEDIA_PROVENANCE)
    assert art.data["path"] == path
    assert art.data["extra"]["recovered_from"] == "browser_cache"
    assert art.data["extra"]["browser"] == "Chrome"
    assert art.data["extra"]["url"].startswith(f"{AI_URL}?sig=")
    assert "SECRETVALUE123" not in art.data["extra"]["url"]
    assert {k: art.data["extra"][k] for k in ("body_offset", "body_size", "content_type")} == {
        "body_offset": 24 + len(key.encode()),
        "body_size": len(body),
        "content_type": "image/png",
    }
    signals = {(s["type"], s["value"]) for s in art.data["signals"]}
    assert ("ai_download_origin", f"browser cache: {art.data['extra']['url']}") in signals
    assert any(t == "c2pa" for t, _ in signals)
    assert art.user == "kim"

    [event] = _events(records)
    assert event.category == EventCategory.BROWSING
    assert event.actor == Actor.HUMAN
    assert event.ts_kind == "file_mtime"
    assert event.ts_utc == SEEN_AT
    assert event.summary == f"AI image viewed (cache): {art.data['extra']['url']}"
    assert not _kind(records, ArtifactKind.PARSE_WARNING)


def test_simple_cache_stream0_key_hash_flag_is_honoured() -> None:
    eof = 0xF4FA6F45970D41D8
    body = _png()
    headers = b"HTTP/1.1 200\x00content-type: image/webp\x00\x00"
    raw_key = AI_URL.encode()
    data = (
        struct.pack("<QIIII", 0xFCFB6D1BA7725C30, 5, len(raw_key), 0, 0)
        + raw_key
        + body
        + struct.pack("<QIIII", eof, 1, 0, len(body), 0)
        + headers
        + b"\x11" * 32
        + struct.pack("<QIIII", eof, 3, 0, len(headers), 0)
    )
    [art] = _kind(_run({f"{CHROME_CACHE}/aaaaaaaaaaaaaaaa_0": data}), ArtifactKind.MEDIA_PROVENANCE)
    assert art.data["extra"]["content_type"] == "image/webp"
    assert art.data["extra"]["body_size"] == len(body)


def test_non_ai_host_image_is_ignored() -> None:
    entry = _simple_entry("1/0/_dk_https://example.com https://example.com https://example.com/a.png", _png())
    firefox = _firefox_entry("https://example.com/b.png", _png())
    records = _run(
        {
            f"{CHROME_CACHE}/0123456789abcdef_0": entry,
            f"{FIREFOX_ENTRIES}/{'A' * 40}": firefox,
        }
    )
    assert records == []


def test_ai_host_non_image_body_is_ignored() -> None:
    entry = _simple_entry("https://chatgpt.com/backend-api/conversation", b'{"ok": true}')
    assert _run({f"{CHROME_CACHE}/0123456789abcdef_0": entry}) == []


def test_corrupt_simple_entries_yield_parse_warnings() -> None:
    good = _simple_entry(f"1/0/_dk_https://chatgpt.com https://chatgpt.com {AI_URL}", _png())
    records = _run(
        {
            f"{CHROME_CACHE}/0000000000000001_0": good[:-5],
            f"{CHROME_CACHE}/0000000000000002_0": b"\x00" * 64,
            f"{CHROME_CACHE}/0000000000000003_0": b"short",
        }
    )
    warnings = _kind(records, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 3
    assert all(w.data["message"].startswith("corrupt simple cache entry") for w in warnings)
    assert not _kind(records, ArtifactKind.MEDIA_PROVENANCE)


def test_firefox_cache2_entry_yields_provenance() -> None:
    jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 40
    url = "https://claude.ai/api/files/abc/preview.jpg"
    path = f"{FIREFOX_ENTRIES}/{'0F' * 20}"
    records = _run({path: _firefox_entry(url, jpeg)}, {path: SEEN_AT})
    [art] = _kind(records, ArtifactKind.MEDIA_PROVENANCE)
    assert art.data["extra"]["browser"] == "Firefox"
    assert art.data["extra"]["url"] == url
    assert {k: art.data["extra"][k] for k in ("body_offset", "body_size", "content_type")} == {
        "body_offset": 0,
        "body_size": len(jpeg),
        "content_type": "image/jpeg",
    }
    assert art.data["extra"]["recovered_from"] == "browser_cache"
    assert [e.ts_utc for e in _events(records)] == [SEEN_AT]


def test_firefox_partitioned_key_and_corrupt_metadata() -> None:
    png = _png()
    partitioned = _firefox_entry(
        "https://chatgpt.com/img.png", png, prefix="O^partitionKey=%28https%2Cexample.com%29,:"
    )
    broken_offset = png + struct.pack(">I", 99999)
    no_key = png + b"\x00" * 30 + struct.pack(">I", len(png))
    records = _run(
        {
            f"{FIREFOX_ENTRIES}/{'1' * 40}": partitioned,
            f"{FIREFOX_ENTRIES}/{'2' * 40}": broken_offset,
            f"{FIREFOX_ENTRIES}/{'3' * 40}": no_key,
        }
    )
    assert len(_kind(records, ArtifactKind.MEDIA_PROVENANCE)) == 1
    assert len(_kind(records, ArtifactKind.PARSE_WARNING)) == 2


def test_safari_cache_db_with_fs_cached_data(tmp_path: Path) -> None:
    db_file = tmp_path / "Cache.db"
    with closing(sqlite3.connect(db_file)) as conn:
        conn.executescript(
            "CREATE TABLE cfurl_cache_response (entry_ID INTEGER PRIMARY KEY, request_key TEXT);"
            "CREATE TABLE cfurl_cache_receiver_data (entry_ID INTEGER PRIMARY KEY, isDataOnFS INTEGER, receiver_data BLOB);"
        )
        conn.execute("INSERT INTO cfurl_cache_response VALUES (1, ?)", (AI_URL,))
        conn.execute("INSERT INTO cfurl_cache_receiver_data VALUES (1, 1, ?)", (b"UUID-1",))
        conn.execute("INSERT INTO cfurl_cache_response VALUES (2, 'https://chatgpt.com/inline.png')")
        conn.execute("INSERT INTO cfurl_cache_receiver_data VALUES (2, 0, ?)", (_png(),))
        conn.execute("INSERT INTO cfurl_cache_response VALUES (3, 'https://example.com/x.png')")
        conn.execute("INSERT INTO cfurl_cache_receiver_data VALUES (3, 0, ?)", (_png(),))
        conn.commit()
    records = _run(
        {f"{SAFARI_DIR}/Cache.db": db_file.read_bytes(), f"{SAFARI_DIR}/fsCachedData/UUID-1": _png()}
    )
    arts = _kind(records, ArtifactKind.MEDIA_PROVENANCE)
    assert [a.data["extra"]["url"] for a in arts] == [AI_URL, "https://chatgpt.com/inline.png"]
    assert {a.data["extra"]["browser"] for a in arts} == {"Safari"}
    assert [a.provenance.record_locator for a in arts] == ["row:1", "row:2"]


def test_blockfile_cache_records_presence() -> None:
    index = b"\xc3\xca\x03\xc1" + b"\x00" * 60
    data_1 = b"\x00" * 16 + AI_URL.encode() + b"\x00" * 8 + _png() + b"\x00" * 8
    records = _run(
        {
            f"{CHROME_CACHE}/index": index,
            f"{CHROME_CACHE}/data_1": data_1,
            f"{CHROME_CACHE}/f_000001": _png(),
        }
    )
    [presence] = _kind(records, ArtifactKind.AI_APP_PRESENCE)
    assert presence.data["status"] == "present"
    assert "png" in presence.data["detail"]
    assert presence.data["extra"]["ai_urls"] == [AI_URL]


def test_simple_cache_index_file_is_not_a_blockfile() -> None:
    assert _run({f"{CHROME_CACHE}/index": b"E\x6f\x79\x20" + b"\x00" * 60}) == []


@pytest.mark.realdata
def test_host_chrome_cache_parses_when_present() -> None:
    home = Path.home()
    cache_root = home / "Library/Caches/Google/Chrome"
    entries = (
        sorted(
            (
                p
                for p in cache_root.glob("*/Cache/Cache_Data/*_0")
                if p.is_file() and p.stat().st_size < 5_000_000
            ),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:300]
        if cache_root.is_dir()
        else []
    )
    if not entries:
        pytest.skip(f"store absent: {cache_root}/*/Cache/Cache_Data/*_0")
    fs = MemoryFS(
        {f"/Users/examiner/{p.relative_to(home).as_posix()}": p.read_bytes() for p in entries},
        volume_os=OsFamily.MACOS,
    )
    ctx = ParseContext(fs, "real", "Asia/Seoul", logging.getLogger("t"))
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    messages = [a.data["message"] for a in _kind(records, ArtifactKind.PARSE_WARNING)]
    assert all(m.startswith("corrupt simple cache entry") for m in messages), messages
    for art in _kind(records, ArtifactKind.MEDIA_PROVENANCE):
        assert art.data["extra"]["recovered_from"] == "browser_cache"
