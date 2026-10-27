from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from aitrace.core.kinds import Actor, ArtifactKind, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.ai.ide_assistants import PLUGIN
from aitrace.plugins.base import ParseContext

WS_DIR = "/Users/lee/Library/Application Support/Cursor/User/workspaceStorage/abc123"
WS_STATE = WS_DIR + "/state.vscdb"
CREATED = datetime(2026, 10, 2, 1, 0, tzinfo=UTC)
CREATED_MS = int(CREATED.timestamp() * 1000)


def _vscdb(tmp_path: Path, rows: dict[str, str]) -> bytes:
    db_file = tmp_path / "state.vscdb"
    with closing(sqlite3.connect(db_file)) as conn:
        conn.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB)")
        conn.execute("CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB)")
        conn.executemany("INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)", rows.items())
        conn.commit()
    return db_file.read_bytes()


def _run(fs: MemoryFS) -> list[Artifact | Event]:
    ctx = ParseContext(fs=fs, evidence_id="ev-test", tz="UTC", log=logging.getLogger("test.ide_assistants"))
    return [item for cand in PLUGIN.locate(fs) for item in PLUGIN.parse(ctx, cand)]


def _artifacts(items: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [item for item in items if isinstance(item, Artifact) and item.kind is kind]


def test_composer_with_two_bubbles_yields_two_chat_messages(tmp_path: Path) -> None:
    composer = {
        "composerId": "c1",
        "name": "refactor",
        "createdAt": CREATED_MS,
        "conversation": [
            {"type": 1, "text": "이 함수 리팩터링해줘", "bubbleId": "b1"},
            {"type": 2, "text": "리팩터링한 코드입니다", "bubbleId": "b2"},
        ],
    }
    db = _vscdb(tmp_path, {"composerData:c1": json.dumps(composer)})
    workspace_json = json.dumps({"folder": "file:///Users/lee/proj"})
    fs = MemoryFS(
        {WS_STATE: db, WS_DIR + "/workspace.json": workspace_json.encode()},
        volume_os=OsFamily.MACOS,
    )

    items = _run(fs)

    messages = _artifacts(items, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(m.data["role"], m.data["text"]) for m in messages] == [
        ("user", "이 함수 리팩터링해줘"),
        ("assistant", "리팩터링한 코드입니다"),
    ]
    assert {m.data["workspace"] for m in messages} == {"/Users/lee/proj"}
    assert {m.data["tool"] for m in messages} == {"Cursor"}
    assert _artifacts(items, ArtifactKind.PARSE_WARNING) == []
    events = [item for item in items if isinstance(item, Event)]
    assert [event.actor for event in events] == [Actor.HUMAN, Actor.AI]
    assert {event.ts_utc for event in events} == {CREATED}


def test_value_that_is_not_json_is_skipped_with_warning(tmp_path: Path) -> None:
    good = {"composerId": "c2", "conversation": [{"type": 1, "text": "남은 질문"}]}
    db = _vscdb(tmp_path, {"composerData:bad": "{not json", "composerData:c2": json.dumps(good)})
    fs = MemoryFS({WS_STATE: db}, volume_os=OsFamily.MACOS)

    items = _run(fs)

    warnings = _artifacts(items, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 1
    assert warnings[0].data["plugin"] == "ide_assistants"
    assert "composerData:bad" in warnings[0].data["message"]
    assert [m.data["text"] for m in _artifacts(items, ArtifactKind.AI_CHAT_MESSAGE)] == ["남은 질문"]


def test_unreadable_state_database_becomes_warning() -> None:
    fs = MemoryFS({WS_STATE: b"this is not a sqlite database" * 8}, volume_os=OsFamily.MACOS)

    warnings = _artifacts(_run(fs), ArtifactKind.PARSE_WARNING)

    assert len(warnings) == 1
    assert "cannot read state database" in warnings[0].data["message"]


def test_locate_finds_windsurf_global_state_under_windows_profile() -> None:
    path = "/Users/kim/AppData/Roaming/Windsurf/User/globalStorage/state.vscdb"
    fs = MemoryFS({path: b"placeholder"}, volume_os=OsFamily.UNKNOWN)

    candidates = list(PLUGIN.locate(fs))

    assert [(c.role, c.extra["tool"], c.user.name if c.user else None) for c in candidates] == [
        ("global_state", "Windsurf", "kim")
    ]
