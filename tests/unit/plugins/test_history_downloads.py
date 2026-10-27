from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from aitrace.core.catalog import LIMITATIONS
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.browser.history_downloads import PLUGIN

MAC_CHROME = "/Users/lee/Library/Application Support/Google/Chrome/Default"
WIN_EDGE = "/Users/kim/AppData/Local/Microsoft/Edge/User Data/Default"
VISIT_AT = datetime(2026, 10, 2, 1, 0, tzinfo=UTC)
WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _webkit(dt: datetime) -> int:
    return int((dt - WEBKIT_EPOCH).total_seconds() * 1_000_000)


def _sample(samples_dir: Path, rel: str) -> bytes:
    return (samples_dir / "third_party/dissect/plugins/apps/browser" / rel).read_bytes()


def _run(fs: MemoryFS) -> list[Artifact | Event]:
    ctx = ParseContext(fs=fs, evidence_id="ev-test", tz="UTC", log=logging.getLogger("test.history_downloads"))
    return [item for cand in PLUGIN.locate(fs) for item in PLUGIN.parse(ctx, cand)]


def _artifacts(items: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [item for item in items if isinstance(item, Artifact) and item.kind is kind]


def _events(items: list[Artifact | Event], category: EventCategory) -> list[Event]:
    return [item for item in items if isinstance(item, Event) and item.category is category]


def _constructed_history(tmp_path: Path, *, with_downloads: bool) -> bytes:
    db_file = tmp_path / "History"
    with closing(sqlite3.connect(db_file)) as conn:
        conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER)")
        conn.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
        conn.execute("INSERT INTO urls VALUES (1, 'https://chatgpt.com/c/abc', 'ChatGPT', ?)", (_webkit(VISIT_AT),))
        conn.execute("INSERT INTO urls VALUES (2, 'https://example.org/', 'Example', ?)", (_webkit(VISIT_AT),))
        conn.execute("INSERT INTO visits VALUES (1, 1, ?)", (_webkit(VISIT_AT),))
        conn.execute("INSERT INTO visits VALUES (2, 2, ?)", (_webkit(VISIT_AT),))
        if with_downloads:
            conn.execute(
                "CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, start_time INTEGER, "
                "received_bytes INTEGER, referrer TEXT, tab_url TEXT)"
            )
            conn.execute("CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT)")
            conn.execute(
                "INSERT INTO downloads VALUES (7, '/Users/lee/Downloads/chart.png', ?, 2048, "
                "'https://chatgpt.com/', 'https://chatgpt.com/c/abc')",
                (_webkit(VISIT_AT),),
            )
            conn.execute(
                "INSERT INTO downloads_url_chains VALUES (7, 0, 'https://files.oaiusercontent.com/file-1/chart.png')"
            )
        conn.commit()
    return db_file.read_bytes()


def test_chrome_sample_yields_visits_and_download(samples_dir: Path) -> None:
    fs = MemoryFS({MAC_CHROME + "/History": _sample(samples_dir, "chrome/generic/History")}, volume_os=OsFamily.MACOS)

    items = _run(fs)

    visits = _artifacts(items, ArtifactKind.BROWSER_VISIT)
    assert len(visits) == 5
    assert all(v.data["browser"] == "Chrome" for v in visits)
    assert len(_events(items, EventCategory.BROWSING)) == 5
    downloads = _artifacts(items, ArtifactKind.BROWSER_DOWNLOAD)
    assert len(downloads) == 1
    assert downloads[0].data["target_path"] == "/Users/John/Downloads/dissect-main (2).zip"
    assert downloads[0].data["raw_path"] == "C:\\Users\\John\\Downloads\\dissect-main (2).zip"
    assert downloads[0].data["url"].startswith("http")
    assert downloads[0].data["referrer"] == "https://github.com/fox-it/dissect"
    assert downloads[0].data["tab_url"] == "https://github.com/fox-it/dissect"
    assert len(_events(items, EventCategory.DOWNLOAD)) == 1
    assert not _artifacts(items, ArtifactKind.PARSE_WARNING)


def test_firefox_sample_yields_visits_and_annotation_downloads(samples_dir: Path) -> None:
    path = "/Users/lee/Library/Application Support/Firefox/Profiles/abc.default/places.sqlite"
    fs = MemoryFS({path: _sample(samples_dir, "firefox/generic/places.sqlite")}, volume_os=OsFamily.MACOS)

    items = _run(fs)

    assert len(_artifacts(items, ArtifactKind.BROWSER_VISIT)) == 24
    downloads = _artifacts(items, ArtifactKind.BROWSER_DOWNLOAD)
    assert downloads
    assert downloads[0].data["target_path"] == "/Users/Administrator/Downloads/ChromeSetup.exe"
    assert downloads[0].data["received_bytes"] == 1341272
    assert all(d.data["browser"] == "Firefox" for d in downloads)


def test_safari_sample_yields_visits(samples_dir: Path) -> None:
    fs = MemoryFS(
        {"/Users/lee/Library/Safari/History.db": _sample(samples_dir, "safari/generic/History.db")},
        volume_os=OsFamily.MACOS,
    )

    items = _run(fs)

    visits = _artifacts(items, ArtifactKind.BROWSER_VISIT)
    assert len(visits) == 5
    assert all(v.data["browser"] == "Safari" for v in visits)
    assert any(e.ts_utc is not None for e in _events(items, EventCategory.BROWSING))


def test_chatgpt_visit_and_oaiusercontent_download_are_tagged(tmp_path: Path) -> None:
    fs = MemoryFS(
        {WIN_EDGE + "/History": _constructed_history(tmp_path, with_downloads=True)}, volume_os=OsFamily.WINDOWS
    )

    items = _run(fs)

    visits = {v.data["url"]: v for v in _artifacts(items, ArtifactKind.BROWSER_VISIT)}
    assert visits["https://chatgpt.com/c/abc"].data["ai_service"] == "ChatGPT"
    assert "ai_service" not in visits["https://example.org/"].data
    assert visits["https://chatgpt.com/c/abc"].data["browser"] == "Edge"
    event = next(e for e in _events(items, EventCategory.BROWSING) if e.subject == "https://chatgpt.com/c/abc")
    assert event.ts_utc == VISIT_AT
    assert event.actor is Actor.HUMAN
    (download,) = _artifacts(items, ArtifactKind.BROWSER_DOWNLOAD)
    assert download.data["ai_service"] == "ChatGPT"
    assert download.data["url"] == "https://files.oaiusercontent.com/file-1/chart.png"
    assert download.data["target_path"] == "/Users/lee/Downloads/chart.png"
    assert download.data["received_bytes"] == 2048
    assert _events(items, EventCategory.DOWNLOAD)[0].ts_utc == VISIT_AT


def test_history_without_downloads_table_still_yields_visits(tmp_path: Path) -> None:
    fs = MemoryFS(
        {MAC_CHROME + "/History": _constructed_history(tmp_path, with_downloads=False)}, volume_os=OsFamily.MACOS
    )

    items = _run(fs)

    assert len(_artifacts(items, ArtifactKind.BROWSER_VISIT)) == 2
    assert not _artifacts(items, ArtifactKind.BROWSER_DOWNLOAD)
    assert not _artifacts(items, ArtifactKind.PARSE_WARNING)


def test_corrupt_history_becomes_parse_warning() -> None:
    fs = MemoryFS({MAC_CHROME + "/History": b"this is not sqlite" * 50}, volume_os=OsFamily.MACOS)

    items = _run(fs)

    assert len(_artifacts(items, ArtifactKind.PARSE_WARNING)) == 1
    assert not _artifacts(items, ArtifactKind.BROWSER_VISIT)


def test_last_dir_preference_is_a_hint_never_an_upload() -> None:
    mtime = datetime(2026, 10, 3, 4, 5, tzinfo=UTC)
    prefs_path = WIN_EDGE + "/Preferences"
    prefs = json.dumps({"selectfile": {"last_directory": "C:\\Users\\kim\\Documents\\secret"}})
    fs = MemoryFS({prefs_path: prefs.encode()}, volume_os=OsFamily.WINDOWS, mtimes={prefs_path: mtime})

    items = _run(fs)

    (transfer,) = _artifacts(items, ArtifactKind.FILE_TRANSFER)
    assert transfer.data["channel"] == "browser_file_dialog_last_dir"
    assert transfer.data["direction"] == "unknown"
    assert transfer.data["local_paths"] == ["/Users/kim/Documents/secret"]
    limitation = LIMITATIONS["BROWSER_LAST_DIR"]
    assert isinstance(limitation, dict)
    assert limitation["en"] in transfer.warnings[0]
    (event,) = [i for i in items if isinstance(i, Event)]
    assert event.category is EventCategory.OTHER
    assert event.category is not EventCategory.UPLOAD
    assert event.ts_utc == mtime
    assert event.ts_kind == "file_mtime"


def test_preferences_without_last_directory_emits_nothing() -> None:
    fs = MemoryFS({WIN_EDGE + "/Preferences": b"{}"}, volume_os=OsFamily.WINDOWS)

    assert _run(fs) == []
