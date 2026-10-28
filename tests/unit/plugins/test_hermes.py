from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.ai.hermes import PLUGIN
from aitrace.plugins.base import ParseContext

LOG = logging.getLogger("tests.hermes")
HOME = "/Users/kim"
DB = f"{HOME}/.hermes/state.db"
KEY = "sk-proj-" + "a1B2c3D4" * 4

# Schema source: Hermes docs, developer-guide/session-storage ("SQLite Schema": sessions and messages
# CREATE TABLE statements, abridged), schema version 31. Timestamps are Unix epoch floats.
DOC_SCHEMA = """
CREATE TABLE sessions (
    id TEXT PRIMARY KEY, source TEXT NOT NULL, user_id TEXT, model TEXT, model_config TEXT,
    system_prompt TEXT, parent_session_id TEXT, started_at REAL NOT NULL, ended_at REAL,
    end_reason TEXT, message_count INTEGER DEFAULT 0, title TEXT, cwd TEXT
);
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL REFERENCES sessions(id),
    role TEXT NOT NULL, content TEXT, tool_call_id TEXT, tool_calls TEXT, tool_name TEXT,
    timestamp REAL NOT NULL, token_count INTEGER, finish_reason TEXT, reasoning TEXT, active INTEGER DEFAULT 1
);
CREATE VIRTUAL TABLE messages_fts USING fts5(content, tool_name, tool_calls, content='messages', content_rowid='id');
"""
T0 = datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC).timestamp()


def _doc_db() -> bytes:
    conn = sqlite3.connect(":memory:")
    conn.executescript(DOC_SCHEMA)
    conn.execute(
        "INSERT INTO sessions (id, source, user_id, model, started_at, title, cwd) VALUES (?,?,?,?,?,?,?)",
        ("sess_cli", "cli", None, "anthropic/claude-sonnet-4.6", T0, "Fix Docker Build", "/Users/kim/work"),
    )
    conn.execute(
        "INSERT INTO sessions (id, source, user_id, model, started_at) VALUES (?,?,?,?,?)",
        ("sess_tg", "telegram", "tg:42", "nous/hermes-4", T0 + 100),
    )
    write_call = [
        {
            "id": "call_1",
            "type": "function",
            "function": {
                "name": "write_file",
                "arguments": json.dumps({"path": "/Users/kim/work/notes.md", "content": "# Notes"}),
            },
        },
        {
            "id": "call_2",
            "function": {"name": "terminal", "arguments": json.dumps({"command": "ls -la"})},
        },
        {"id": "call_3", "function": {"name": "read_file", "arguments": json.dumps({"path": "/etc/hosts"})}},
    ]
    rows = [
        ("sess_cli", "user", "write notes", None, None, T0 + 1, 1),
        ("sess_cli", "assistant", "", json.dumps(write_call), None, T0 + 2, 1),
        ("sess_cli", "tool", "ok", None, "write_file", T0 + 3, 1),
        ("sess_cli", "assistant", "archived copy", None, None, T0 + 4, 0),
        ("sess_tg", "user", "hello from telegram", None, None, T0 + 101, 1),
    ]
    conn.executemany(
        "INSERT INTO messages (session_id, role, content, tool_calls, tool_name, timestamp, active) VALUES (?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    blob = conn.serialize()
    conn.close()
    return bytes(blob)


def _run(files: dict[str, bytes], os_family: OsFamily = OsFamily.MACOS, mtimes: dict[str, datetime] | None = None):
    fs = MemoryFS(files, volume_os=os_family, mtimes=mtimes)
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="Asia/Seoul", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _events(records: list[Artifact | Event]) -> list[Event]:
    return [r for r in records if isinstance(r, Event)]


def test_locate_yields_default_and_profile_sources() -> None:
    fs = MemoryFS(
        {
            DB: b"",
            f"{HOME}/.hermes/profiles/coder/state.db": b"",
            f"{HOME}/.hermes/sessions/2026/s1.jsonl": b"",
            f"{HOME}/.hermes/memories/MEMORY.md": b"x",
            f"{HOME}/.hermes/memories/USER.md": b"x",
            f"{HOME}/.hermes/config.yaml": b"x",
            f"{HOME}/.hermes/.env": b"x",
            f"{HOME}/.hermes/other.txt": b"",
        },
        volume_os=OsFamily.MACOS,
    )
    cands = list(PLUGIN.locate(fs))
    assert sorted(c.role for c in cands) == ["config", "env", "legacy", "memory", "memory", "state_db", "state_db"]
    profiles = {c.ref.path: c.extra["profile"] for c in cands if c.role == "state_db"}
    assert profiles == {DB: None, f"{HOME}/.hermes/profiles/coder/state.db": "coder"}


def test_documented_schema_yields_messages_tool_calls_models_and_events() -> None:
    records = _run({DB: _doc_db()})
    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(m.data["role"], m.data["text"]) for m in messages] == [
        ("user", "write notes"),
        ("tool", "ok"),
        ("assistant", "archived copy"),
        ("user", "hello from telegram"),
    ]
    first = messages[0].data
    assert first["tool"] == "Hermes Agent"
    assert first["session_id"] == "sess_cli"
    assert first["model"] == "anthropic/claude-sonnet-4.6"
    assert first["title"] == "Fix Docker Build"
    assert first["workspace"] == "/Users/kim/work"
    assert first["recovered_from"] == "sqlite"
    assert first["extra"]["platform"] == "cli"
    assert messages[1].data["extra"]["tool_name"] == "write_file"
    assert messages[2].data["extra"]["archived_generation"] is True
    assert messages[3].data["extra"] == {"platform": "telegram", "user_id": "tg:42"}
    assert messages[0].user == "kim"
    assert messages[0].provenance.record_locator == "row:messages.rowid=1"

    calls = _kind(records, ArtifactKind.AI_TOOL_CALL)
    assert [c.data["call_name"] for c in calls] == ["write_file", "terminal", "read_file"]
    assert calls[0].data["file_path"] == "/Users/kim/work/notes.md"
    assert calls[0].data["content"] == "# Notes"
    assert calls[1].data["command"] == "ls -la"
    assert "file_path" not in calls[2].data
    assert len({c.id for c in calls}) == 3

    assert {m.data["model_name"] for m in _kind(records, ArtifactKind.AI_MODEL)} == {
        "anthropic/claude-sonnet-4.6",
        "nous/hermes-4",
    }
    events = _events(records)
    assert all(e.category == EventCategory.AI_ACTIVITY for e in events)
    assert [e.actor for e in events[:3]] == [Actor.HUMAN, Actor.AI, Actor.AI]
    assert events[0].ts_utc == datetime(2026, 10, 1, 1, 0, 1, tzinfo=UTC)
    assert not _kind(records, ArtifactKind.PARSE_WARNING)
    presence = _kind(records, ArtifactKind.AI_APP_PRESENCE)[0].data
    assert presence["status"] == "parsed"
    assert presence["detail"].startswith("5 message(s) in 2 session(s)")
    assert presence["first_seen"] == "2026-10-01T01:00:00Z"


def test_profile_state_db_marks_profile_in_extra() -> None:
    records = _run({f"{HOME}/.hermes/profiles/coder/state.db": _doc_db()})
    message = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)[0]
    assert message.data["extra"]["profile"] == "coder"


def test_unknown_schema_is_mapped_by_column_name_heuristics() -> None:
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE chats (uuid TEXT, platform TEXT, name TEXT, model_name TEXT, created_at TEXT);
        CREATE TABLE turns (conversation_id TEXT, author TEXT, body TEXT, created_at TEXT);
        INSERT INTO chats VALUES ('c1', 'discord', 'T', 'm-1', '2026-10-01T01:00:00+00:00');
        INSERT INTO turns VALUES ('c1', 'human', 'hi there', '2026-10-01T01:00:05+00:00');
        INSERT INTO turns VALUES ('c1', 'model', 'hello', '2026-10-01T01:00:06+00:00');
        """
    )
    blob = bytes(conn.serialize())
    conn.close()
    records = _run({DB: blob})
    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(m.data["role"], m.data["text"]) for m in messages] == [("user", "hi there"), ("assistant", "hello")]
    assert messages[0].data["extra"]["platform"] == "discord"
    assert messages[0].data["model"] == "m-1"
    assert _events(records)[0].ts_utc == datetime(2026, 10, 1, 1, 0, 5, tzinfo=UTC)


def test_corrupt_and_schemaless_databases_yield_parse_warning() -> None:
    corrupt = _run({DB: b"this is definitely not an sqlite database" * 50})
    warnings = _kind(corrupt, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 1
    assert "cannot read SQLite database" in warnings[0].data["message"]
    assert _kind(corrupt, ArtifactKind.AI_APP_PRESENCE)[0].data["status"] == "present"
    assert not _kind(corrupt, ArtifactKind.AI_CHAT_MESSAGE)

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE unrelated (a INTEGER)")
    blob = bytes(conn.serialize())
    conn.close()
    mismatch = _run({DB: blob})
    assert _kind(mismatch, ArtifactKind.PARSE_WARNING)[0].data["message"].startswith("schema_mismatch")


def test_legacy_jsonl_yields_messages_and_counts_malformed_lines() -> None:
    raw = (
        json.dumps({"role": "session_meta", "model": "hermes-3"}).encode()
        + b"\n"
        + json.dumps({"role": "user", "content": "legacy hi", "timestamp": "2026-10-01T01:00:00+00:00"}).encode()
        + b"\n"
        + json.dumps(
            {
                "role": "assistant",
                "content": [{"type": "text", "text": "legacy reply"}],
                "timestamp": T0 + 5,
                "tool_calls": [{"function": {"name": "terminal", "arguments": {"command": "pwd"}}}],
            }
        ).encode()
        + b"\n{not json\n[1]\n"
    )
    records = _run({f"{HOME}/.hermes/sessions/20261001_010000_abc.jsonl": raw})
    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(m.data["role"], m.data["text"]) for m in messages] == [("user", "legacy hi"), ("assistant", "legacy reply")]
    assert messages[0].data["session_id"] == "20261001_010000_abc"
    assert messages[0].data["model"] == "hermes-3"
    assert messages[0].data["recovered_from"] == "jsonl"
    assert _kind(records, ArtifactKind.AI_TOOL_CALL)[0].data["command"] == "pwd"
    assert _kind(records, ArtifactKind.PARSE_WARNING)[0].data["message"] == "skipped 2 malformed record(s)"


def test_memory_files_are_presence_only_without_content() -> None:
    mtime = datetime(2026, 10, 2, 3, 4, 5, tzinfo=UTC)
    path = f"{HOME}/.hermes/memories/MEMORY.md"
    records = _run({path: b"user's secret preference text"}, mtimes={path: mtime})
    presence = _kind(records, ArtifactKind.AI_APP_PRESENCE)
    assert len(presence) == 1
    data = presence[0].data
    assert data["kind"] == "store"
    assert data["detail"] == f"{path}: 29 bytes, mtime 2026-10-02T03:04:05Z"
    assert data["last_seen"] == "2026-10-02T03:04:05Z"
    assert "secret preference" not in json.dumps([r.data for r in records if isinstance(r, Artifact)])


def test_config_and_env_yield_presence_and_redacted_credentials() -> None:
    records = _run(
        {
            f"{HOME}/.hermes/config.yaml": f"model:\n  api_key: {KEY}\n".encode(),
            f"{HOME}/.hermes/.env": b"OPENAI_API_KEY=" + KEY.encode() + b"\nEDITOR=vim\n",
        }
    )
    presence = _kind(records, ArtifactKind.AI_APP_PRESENCE)
    assert {p.data["kind"] for p in presence} == {"config"}
    creds = _kind(records, ArtifactKind.AI_CREDENTIAL)
    assert len(creds) == 2
    assert {c.data["tool"] for c in creds} == {"Hermes Agent"}
    assert all(KEY not in json.dumps(c.data) and "sha256:" in c.data["redacted"] for c in creds)
    assert all(KEY not in json.dumps(c.provenance.record_locator) for c in creds)
    assert sorted(c.data["line"] for c in creds) == [1, 2]


@pytest.mark.realdata
def test_host_hermes_store_parses_when_present() -> None:
    home = Path.home()
    db = home / ".hermes" / "state.db"
    if not db.is_file():
        pytest.skip(f"store absent: {db}")
    fs = MemoryFS({"/Users/examiner/.hermes/state.db": db.read_bytes()}, volume_os=OsFamily.MACOS)
    ctx = ParseContext(fs, "real", "Asia/Seoul", logging.getLogger("t"))
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    print(f"hermes host messages: {len(messages)}")
    assert messages
    bad = [a.data["message"] for a in _kind(records, ArtifactKind.PARSE_WARNING)]
    assert all(m.startswith(("skipped", "schema_mismatch")) for m in bad), bad
