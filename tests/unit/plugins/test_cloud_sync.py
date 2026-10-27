from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime

from aitrace.core.kinds import ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.remote.cloud_sync import PLUGIN

WIN_HOME = "/Users/kim"
DRIVEFS_DB = f"{WIN_HOME}/AppData/Local/Google/DriveFS/acct-7f3a/metadata_sqlite_db"
MODIFIED_MS = 1_700_000_000_000
MODIFIED = datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)


def _run(files: dict[str, bytes], volume_os: OsFamily) -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=volume_os)
    ctx = ParseContext(fs=fs, evidence_id="ev-test", tz="UTC", log=logging.getLogger("test.cloud_sync"))
    return [item for cand in PLUGIN.locate(fs) for item in PLUGIN.parse(ctx, cand)]


def _artifacts(items: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [item for item in items if isinstance(item, Artifact) and item.kind is kind]


def _drivefs_db(rows: list[tuple[str, str | None, int | None, int]]) -> bytes:
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE items (id TEXT PRIMARY KEY, local_title TEXT, modified_date INTEGER, trashed INTEGER)")
        conn.executemany("INSERT INTO items VALUES (?, ?, ?, ?)", rows)
        conn.commit()
        return conn.serialize()
    finally:
        conn.close()


def test_drivefs_items_yield_one_cloud_sync_and_event_per_item() -> None:
    db = _drivefs_db(
        [
            ("1", "report.docx", MODIFIED_MS, 0),
            ("2", "old-notes.txt", MODIFIED_MS + 100_000, 1),
        ]
    )

    items = _run({DRIVEFS_DB: db}, OsFamily.WINDOWS)
    cloud = _artifacts(items, ArtifactKind.CLOUD_SYNC)
    events = [item for item in items if isinstance(item, Event)]

    assert [c.data["extra"]["title"] for c in cloud] == ["report.docx", "old-notes.txt"]
    assert {c.data["service"] for c in cloud} == {"Google Drive"}
    assert {c.data["account"] for c in cloud} == {"acct-7f3a"}
    assert [c.data["extra"]["trashed"] for c in cloud] == [False, True]
    assert [(e.category, e.ts_utc) for e in events] == [
        (EventCategory.FILE_MODIFIED, MODIFIED),
        (EventCategory.FILE_MODIFIED, datetime(2023, 11, 14, 22, 15, 0, tzinfo=UTC)),
    ]
    assert all(c.provenance.source_path == DRIVEFS_DB for c in cloud)


def test_drivefs_database_without_items_table_yields_warning() -> None:
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE other (id TEXT)")
        db = conn.serialize()
    finally:
        conn.close()

    items = _run({DRIVEFS_DB: db}, OsFamily.WINDOWS)

    assert _artifacts(items, ArtifactKind.CLOUD_SYNC) == []
    warnings = _artifacts(items, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 1
    assert warnings[0].data["plugin"] == "cloud_sync"
    assert "items table" in warnings[0].data["message"]


def test_corrupt_drivefs_database_yields_warning() -> None:
    items = _run({DRIVEFS_DB: b"this is not a sqlite database" * 64}, OsFamily.WINDOWS)

    assert _artifacts(items, ArtifactKind.CLOUD_SYNC) == []
    assert len(_artifacts(items, ArtifactKind.PARSE_WARNING)) == 1


def test_dropbox_info_yields_one_cloud_sync_per_account_with_normalized_paths() -> None:
    info = {
        "personal": {"path": "C:\\Users\\kim\\Dropbox", "host": 1},
        "business": {"path": "D:\\Work\\Dropbox (Acme)", "host": 2},
    }
    files = {f"{WIN_HOME}/AppData/Local/Dropbox/info.json": json.dumps(info).encode()}

    cloud = _artifacts(_run(files, OsFamily.WINDOWS), ArtifactKind.CLOUD_SYNC)

    assert [(c.data["account"], c.data["item_path"]) for c in cloud] == [
        ("personal", "/Users/kim/Dropbox"),
        ("business", "/Work/Dropbox (Acme)"),
    ]
    assert {c.data["service"] for c in cloud} == {"Dropbox"}


def test_corrupt_dropbox_info_yields_warning() -> None:
    files = {f"{WIN_HOME}/AppData/Local/Dropbox/info.json": b"{not json"}

    items = _run(files, OsFamily.WINDOWS)

    assert _artifacts(items, ArtifactKind.CLOUD_SYNC) == []
    assert len(_artifacts(items, ArtifactKind.PARSE_WARNING)) == 1


def test_onedrive_settings_and_icloud_folder_yield_presence() -> None:
    files = {
        f"{WIN_HOME}/AppData/Local/Microsoft/OneDrive/settings/Personal/9a1c.ini": b"",
        f"{WIN_HOME}/Library/Mobile Documents/com~apple~CloudDocs/draft.txt": b"",
    }

    cloud = _artifacts(_run(files, OsFamily.MACOS), ArtifactKind.CLOUD_SYNC)

    assert {c.data["service"] for c in cloud} == {"OneDrive", "iCloud Drive"}
    assert all(c.data["account"] is None and c.data["item_path"] is None for c in cloud)
