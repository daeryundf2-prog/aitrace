from __future__ import annotations

import gzip
import logging
import plistlib
import sqlite3
import struct
from datetime import UTC, datetime

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.macos.activity import PLUGIN

QUARANTINE = "/Users/lee/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
KNOWLEDGE = "/Users/lee/Library/Application Support/Knowledge/knowledgeC.db"
TCC = "/Library/Application Support/com.apple.TCC/TCC.db"
FSEVENTS_PAGE = "/.fseventsd/0000000000a1b2c3"


def _cocoa(ts: datetime) -> float:
    return (ts - datetime(2001, 1, 1, tzinfo=UTC)).total_seconds()


def _db(script: str) -> bytes:
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(script)
        return conn.serialize()
    finally:
        conn.close()


def _run(fs: MemoryFS) -> list[Artifact | Event]:
    ctx = ParseContext(fs=fs, evidence_id=fs.evidence_id, tz="Asia/Seoul", log=logging.getLogger("test"))
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _artifacts(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _events(records: list[Artifact | Event]) -> list[Event]:
    return [r for r in records if isinstance(r, Event)]


def _fsevents_page(magic: bytes, records: list[tuple[str, int, int, int]]) -> bytes:
    body = magic
    for path, event_id, flags, node_id in records:
        body += path.encode() + b"\x00" + struct.pack("<QIQ", event_id, flags, node_id)
    return gzip.compress(body)


def test_quarantine_plist_yields_download_origin_and_ai_tagged_event() -> None:
    when = datetime(2026, 10, 2, 2, 5, tzinfo=UTC)
    store = {
        "LSQuarantineEvents": [
            {
                "LSQuarantineTimeStamp": _cocoa(when),
                "LSQuarantineAgentBundleIdentifier": "com.apple.Safari",
                "LSQuarantineAgentName": "Safari",
                "LSQuarantineDataURLString": "https://gemini.google.com/app/image.png",
                "LSQuarantineOriginURLString": "https://gemini.google.com/",
            },
            {
                "LSQuarantineTimeStamp": _cocoa(when),
                "LSQuarantineAgentName": "Chrome",
                "LSQuarantineDataURLString": "https://example.com/setup.dmg",
                "LSQuarantineOriginURLString": "https://example.com/",
            },
        ]
    }
    fs = MemoryFS({QUARANTINE: plistlib.dumps(store)}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    downloads = _artifacts(records, ArtifactKind.DOWNLOAD_ORIGIN)
    assert [a.data["ai_service"] for a in downloads] == ["Gemini", None]
    assert all(a.user == "lee" for a in downloads)
    tagged = [e for e in _events(records) if e.category is EventCategory.DOWNLOAD and e.data["ai_service"] == "Gemini"]
    assert len(tagged) == 1
    assert tagged[0].ts_utc == when
    assert tagged[0].ts_basis == "native_utc"
    assert tagged[0].actor is Actor.HUMAN


def test_quarantine_sqlite_store_is_read_as_well() -> None:
    when = datetime(2026, 10, 2, 2, 5, tzinfo=UTC)
    store = _db(
        "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY, "
        "LSQuarantineTimeStamp REAL, LSQuarantineAgentBundleIdentifier TEXT, LSQuarantineAgentName TEXT, "
        "LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT);"
        f"INSERT INTO LSQuarantineEvent VALUES ('e1', {_cocoa(when)}, 'com.apple.Safari', 'Safari', "
        "'https://claude.ai/files/report.pdf', 'https://claude.ai/');"
    )
    fs = MemoryFS({QUARANTINE: store}, volume_os=OsFamily.MACOS)

    downloads = _artifacts(_run(fs), ArtifactKind.DOWNLOAD_ORIGIN)

    assert len(downloads) == 1
    assert downloads[0].data["ai_service"] == "Claude"
    assert downloads[0].data["url"] == "https://claude.ai/files/report.pdf"


def test_knowledgec_keeps_only_ai_program_usage() -> None:
    start = datetime(2026, 10, 2, 1, 0, tzinfo=UTC)
    begin = _cocoa(start)
    store = _db(
        "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR, "
        "ZSTARTDATE REAL, ZENDDATE REAL);"
        f"INSERT INTO ZOBJECT VALUES (1, '/app/inFocus', 'com.openai.chat', {begin}, {begin + 600});"
        f"INSERT INTO ZOBJECT VALUES (2, '/app/usage', 'com.apple.Safari', {begin}, {begin + 60});"
        f"INSERT INTO ZOBJECT VALUES (3, '/app/usage', 'com.todesktop.230313mzl4w4u92', {begin + 900}, {begin + 990});"
    )
    fs = MemoryFS({KNOWLEDGE: store}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    executions = _artifacts(records, ArtifactKind.EXECUTION)
    assert [e.data["ai_tool"] for e in executions] == ["ChatGPT Desktop", "Cursor"]
    assert all(e.data["source"] == "knowledgec" for e in executions)
    first = next(e for e in _events(records) if e.category is EventCategory.EXECUTION)
    assert first.ts_utc == start
    assert first.user == "lee"


def test_tcc_grants_are_reported_only_for_ai_clients() -> None:
    when = datetime(2026, 10, 1, 3, 0, tzinfo=UTC)
    store = _db(
        "CREATE TABLE access (service TEXT, client TEXT, auth_value INTEGER, last_modified INTEGER);"
        f"INSERT INTO access VALUES ('kTCCServiceScreenCapture', 'com.openai.chat', 2, {int(when.timestamp())});"
        f"INSERT INTO access VALUES ('kTCCServiceAddressBook', 'com.apple.Contacts', 2, {int(when.timestamp())});"
    )
    fs = MemoryFS({TCC: store}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    grants = _artifacts(records, ArtifactKind.PERMISSION_GRANT)
    assert len(grants) == 1
    assert grants[0].data["service"] == "kTCCServiceScreenCapture"
    assert grants[0].data["ai_tool"] == "ChatGPT Desktop"
    assert grants[0].data["auth_value"] == 2
    grant_event = next(e for e in _events(records) if e.category is EventCategory.AUTH)
    assert grant_event.ts_utc == when


def test_fsevents_page_decodes_flags_with_page_mtime_bound() -> None:
    page_mtime = datetime(2026, 10, 2, 6, 0, tzinfo=UTC)
    page = _fsevents_page(
        b"2SLD",
        [
            ("/Users/lee/proj/parser.py", 11, 0x100, 501),
            ("/Users/lee/Documents/secret_plan.txt", 12, 0x200, 502),
        ],
    )
    fs = MemoryFS({FSEVENTS_PAGE: page}, volume_os=OsFamily.MACOS, mtimes={FSEVENTS_PAGE: page_mtime})

    records = _run(fs)

    journals = _artifacts(records, ArtifactKind.FILE_JOURNAL)
    assert [j.data["reasons"] for j in journals] == [["Created"], ["Removed"]]
    assert [j.data["path"] for j in journals] == ["/Users/lee/proj/parser.py", "/Users/lee/Documents/secret_plan.txt"]
    assert journals[0].data["page_mtime"] == "2026-10-02T06:00:00Z"
    assert journals[0].data["extra"]["node_id"] == 501
    events = _events(records)
    assert [e.category for e in events] == [EventCategory.FILE_CREATED, EventCategory.FILE_DELETED]
    assert all(e.ts_utc is None for e in events)
    assert all(e.ts_basis == "fsevents_page_mtime_bound" for e in events)


def test_fsevents_bad_magic_yields_parse_warning() -> None:
    page = _fsevents_page(b"9SLD", [("/Users/lee/proj/parser.py", 11, 0x100, 501)])
    fs = MemoryFS({FSEVENTS_PAGE: page}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    assert _artifacts(records, ArtifactKind.FILE_JOURNAL) == []
    warnings = _artifacts(records, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 1
    assert "bad FSEvents magic" in warnings[0].data["message"]
