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
from aitrace.plugins.ai.opencode import PLUGIN
from aitrace.plugins.base import ParseContext

LOG = logging.getLogger("tests.opencode")
HOME = "/Users/kim"
DB_PATH = f"{HOME}/.local/share/opencode/opencode.db"
SCHEMA = """
CREATE TABLE session (id text PRIMARY KEY, project_id text, parent_id text, slug text, directory text,
    title text, version text, time_created integer, time_updated integer, agent text, model text);
CREATE TABLE message (id text PRIMARY KEY, session_id text, time_created integer, time_updated integer, data text);
CREATE TABLE part (id text PRIMARY KEY, message_id text, session_id text, time_created integer,
    time_updated integer, data text);
"""
T0 = int(datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC).timestamp() * 1000)


def _run(files: dict[str, bytes], os_family: OsFamily = OsFamily.MACOS) -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=os_family)
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="Asia/Seoul", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _events(records: list[Artifact | Event]) -> list[Event]:
    return [r for r in records if isinstance(r, Event)]


def _build_db(path: Path, rows: list[tuple[str, tuple[object, ...]]]) -> bytes:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    for sql, args in rows:
        conn.execute(sql, args)
    conn.commit()
    conn.close()
    return path.read_bytes()


def _msg(mid: str, offset: int, data: object) -> tuple[str, tuple[object, ...]]:
    raw = data if isinstance(data, str) else json.dumps(data)
    return ("INSERT INTO message VALUES (?,?,?,?,?)", (mid, "ses_1", T0 + offset, T0 + offset, raw))


def _part(pid: str, mid: str, offset: int, data: object) -> tuple[str, tuple[object, ...]]:
    raw = data if isinstance(data, str) else json.dumps(data)
    return ("INSERT INTO part VALUES (?,?,?,?,?,?)", (pid, mid, "ses_1", T0 + offset, T0 + offset, raw))


def _sample_rows() -> list[tuple[str, tuple[object, ...]]]:
    write_input = {"filePath": "/Users/kim/work/a.md", "content": "# A"}
    return [
        (
            "INSERT INTO session VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("ses_1", "p", None, "slug", "/Users/kim/work", "Fix bug", "1.0", T0, T0, "build",
             json.dumps({"id": "m-model", "providerID": "openrouter"})),
        ),
        _msg("msg_1", 0, {"role": "user", "time": {"created": T0}, "model": {"providerID": "x", "modelID": "user-model"}}),
        _part("prt_1", "msg_1", 1, {"type": "text", "text": "write a.md"}),
        _part("prt_2", "msg_1", 2, {"type": "file", "filename": "spec.pdf", "mime": "application/pdf", "url": "file:///Users/kim/spec.pdf"}),
        _msg("msg_2", 5000, {"role": "assistant", "modelID": "claude-x", "providerID": "anthropic", "time": {"created": T0 + 5000}}),
        _part("prt_3", "msg_2", 5001, {"type": "text", "text": "Writing."}),
        _part("prt_4", "msg_2", 5002, {"type": "text", "text": "Done."}),
        _part(
            "prt_5",
            "msg_2",
            5003,
            {"type": "tool", "tool": "write", "callID": "c1",
             "state": {"status": "completed", "input": write_input, "output": "ok", "time": {"start": T0 + 6000}}},
        ),
        _part(
            "prt_6",
            "msg_2",
            5004,
            {"type": "tool", "tool": "bash", "callID": "c2",
             "state": {"status": "completed", "input": {"command": "ls -la"}, "output": "x"}},
        ),
        _part("prt_7", "msg_2", 5005, {"type": "patch", "hash": "h", "files": ["/Users/kim/work/b.py", "/Users/kim/work/c.py"]}),
        _part("prt_8", "msg_2", 5006, {"type": "step-start"}),
        _part("prt_9", "msg_2", 5007, {"type": "reasoning", "text": "thinking"}),
    ]


def test_locate_yields_every_source() -> None:
    fs = MemoryFS(
        {
            DB_PATH: b"",
            f"{HOME}/.local/share/opencode/storage/session/proj/ses_1.json": b"{}",
            f"{HOME}/.config/opencode/opencode.json": b"{}",
            f"{HOME}/.config/opencode/opencode.jsonc": b"{}",
            f"{HOME}/.local/share/opencode/auth.json": b"{}",
            f"{HOME}/.local/share/opencode/other.txt": b"",
        },
        volume_os=OsFamily.MACOS,
    )
    assert sorted(c.role for c in PLUGIN.locate(fs)) == ["auth", "config", "config", "db", "legacy"]


def test_database_yields_messages_tool_calls_and_attachments(tmp_path: Path) -> None:
    records = _run({DB_PATH: _build_db(tmp_path / "o.db", _sample_rows())})
    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(m.data["role"], m.data["text"]) for m in messages] == [
        ("user", "write a.md"),
        ("assistant", "Writing.\nDone."),
    ]
    first = messages[0].data
    assert first["session_id"] == "ses_1"
    assert first["title"] == "Fix bug"
    assert first["workspace"] == "/Users/kim/work"
    assert first["model"] == "user-model"
    assert first["recovered_from"] == "sqlite"
    assert messages[1].data["model"] == "claude-x"
    assert messages[0].user == "kim"
    assert messages[0].provenance.record_locator == "message:msg_1"

    calls = {str(c.provenance.record_locator): c for c in _kind(records, ArtifactKind.AI_TOOL_CALL)}
    assert sorted(calls) == ["part:prt_2", "part:prt_5", "part:prt_6", "part:prt_7:file:0", "part:prt_7:file:1"]
    write = calls["part:prt_5"].data
    assert (write["call_name"], write["file_path"], write["content"]) == ("write", "/Users/kim/work/a.md", "# A")
    assert write["input"] == {"filePath": "/Users/kim/work/a.md", "content": "# A"}
    assert calls["part:prt_6"].data["command"] == "ls -la"
    attach = calls["part:prt_2"].data
    assert attach["call_name"] == "attach_file"
    assert attach["input"]["filename"] == "spec.pdf"
    assert calls["part:prt_7:file:1"].data["file_path"] == "/Users/kim/work/c.py"
    assert all(c.data["tool"] == "OpenCode" for c in calls.values())

    events = _events(records)
    assert all(e.category == EventCategory.AI_ACTIVITY for e in events)
    assert events[0].actor == Actor.HUMAN
    assert events[0].ts_utc == datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC)
    assert events[1].actor == Actor.AI
    assert not _kind(records, ArtifactKind.PARSE_WARNING)
    presence = _kind(records, ArtifactKind.AI_APP_PRESENCE)[0]
    assert presence.data["status"] == "parsed"
    assert presence.data["last_seen"] == "2026-10-01T01:00:05Z"


def test_database_messages_stream_in_time_order(tmp_path: Path) -> None:
    rows = _sample_rows()
    rows.append(_msg("msg_0", -1000, {"role": "user"}))
    rows.append(_part("prt_0", "msg_0", -999, {"type": "text", "text": "earliest"}))
    records = _run({DB_PATH: _build_db(tmp_path / "o.db", rows)})
    texts = [m.data["text"] for m in _kind(records, ArtifactKind.AI_CHAT_MESSAGE)]
    assert texts[0] == "earliest"


def test_malformed_json_rows_counted_in_single_warning(tmp_path: Path) -> None:
    rows = _sample_rows()
    rows.append(_msg("msg_bad", 9000, "{not json"))
    rows.append(_part("prt_bad", "msg_1", 9001, "[1]"))
    records = _run({DB_PATH: _build_db(tmp_path / "o.db", rows)})
    warnings = _kind(records, ArtifactKind.PARSE_WARNING)
    assert [w.data["message"] for w in warnings] == ["skipped 2 malformed record(s)"]
    assert len(_kind(records, ArtifactKind.AI_CHAT_MESSAGE)) == 2


def test_corrupt_database_yields_schema_mismatch_warning() -> None:
    records = _run({DB_PATH: b"this is not a sqlite database" * 20})
    warnings = _kind(records, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 1
    assert warnings[0].data["message"].startswith("schema_mismatch: not decoded:")
    assert _kind(records, ArtifactKind.AI_APP_PRESENCE)[0].data["status"] == "present"


def test_database_missing_tables_yields_schema_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "x.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE unrelated (a)")
    conn.commit()
    conn.close()
    records = _run({DB_PATH: path.read_bytes()})
    warnings = _kind(records, ArtifactKind.PARSE_WARNING)
    assert warnings[0].data["message"].startswith("schema_mismatch: not decoded: table session")
    assert _kind(records, ArtifactKind.AI_APP_PRESENCE)[0].data["status"] == "unsupported"


def test_legacy_json_storage_is_decoded() -> None:
    root = f"{HOME}/.local/share/opencode/storage"
    files = {
        f"{root}/session/proj/ses_1.json": json.dumps(
            {"id": "ses_1", "directory": "/Users/kim/work", "title": "Legacy", "time": {"created": T0}}
        ).encode(),
        f"{root}/message/ses_1/msg_1.json": json.dumps(
            {"id": "msg_1", "sessionID": "ses_1", "role": "user", "time": {"created": T0}}
        ).encode(),
        f"{root}/message/ses_1/msg_2.json": json.dumps(
            {"id": "msg_2", "sessionID": "ses_1", "role": "assistant", "modelID": "m", "time": {"created": T0 + 1000}}
        ).encode(),
        f"{root}/message/ses_1/msg_bad.json": b"{oops",
        f"{root}/part/msg_1/prt_1.json": json.dumps({"id": "prt_1", "type": "text", "text": "hello"}).encode(),
        f"{root}/part/msg_2/prt_2.json": json.dumps({"id": "prt_2", "type": "text", "text": "hi there"}).encode(),
        f"{root}/part/msg_2/prt_3.json": json.dumps(
            {"id": "prt_3", "type": "tool", "tool": "edit", "state": {"input": {"filePath": "/a/b.py", "newString": "x"}}}
        ).encode(),
    }
    records = _run(files)
    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(m.data["role"], m.data["text"], m.data["title"]) for m in messages] == [
        ("user", "hello", "Legacy"),
        ("assistant", "hi there", "Legacy"),
    ]
    assert messages[0].data["recovered_from"] == "json"
    assert messages[1].provenance.source_path.endswith("/storage/message/ses_1/msg_2.json")
    call = _kind(records, ArtifactKind.AI_TOOL_CALL)[0]
    assert (call.data["call_name"], call.data["file_path"], call.data["content"]) == ("edit", "/a/b.py", "x")
    assert [w.data["message"] for w in _kind(records, ArtifactKind.PARSE_WARNING)] == ["skipped 1 malformed record(s)"]


def test_config_presence_and_auth_never_exposes_values() -> None:
    config = '{\n  // model choice\n  "model": "anthropic/claude-x", "provider": {"openrouter": {},},\n}\n'
    records = _run(
        {
            f"{HOME}/.config/opencode/opencode.jsonc": config.encode(),
            f"{HOME}/.local/share/opencode/auth.json": json.dumps(
                {"openrouter": {"type": "api", "key": "sk-or-SECRETVALUE1234567890"}}
            ).encode(),
        }
    )
    presence = _kind(records, ArtifactKind.AI_APP_PRESENCE)[0]
    assert presence.data["status"] == "parsed"
    assert "anthropic/claude-x" in presence.data["detail"]
    assert "openrouter" in presence.data["detail"]
    credentials = _kind(records, ArtifactKind.AI_CREDENTIAL)
    assert [c.data["provider"] for c in credentials] == ["openrouter"]
    assert "SECRETVALUE" not in json.dumps([c.data for c in credentials])


def test_bad_config_and_auth_warn() -> None:
    records = _run(
        {
            f"{HOME}/.config/opencode/opencode.json": b"{broken",
            f"{HOME}/.local/share/opencode/auth.json": b"[1]",
        }
    )
    assert len(_kind(records, ArtifactKind.PARSE_WARNING)) == 2
    assert _kind(records, ArtifactKind.AI_APP_PRESENCE)[0].data["status"] == "present"


def test_windows_paths_are_normalized() -> None:
    rows = [
        (
            "INSERT INTO session VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("ses_1", "p", None, "s", "C:\\Users\\kim\\w", "T", "1", T0, T0, None, None),
        ),
        _msg("msg_1", 0, {"role": "assistant"}),
        _part("prt_1", "msg_1", 1, {"type": "text", "text": "hi"}),
        _part(
            "prt_2",
            "msg_1",
            2,
            {"type": "tool", "tool": "write", "state": {"input": {"filePath": "C:\\Users\\kim\\w\\a.md", "content": "x"}}},
        ),
    ]
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        raw = _build_db(Path(tmp) / "w.db", rows)
    records = _run({DB_PATH: raw}, OsFamily.WINDOWS)
    call = _kind(records, ArtifactKind.AI_TOOL_CALL)[0]
    assert call.data["file_path"] == "/Users/kim/w/a.md"
    assert call.data["raw_path"] == "C:\\Users\\kim\\w\\a.md"
    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE)[0].data["workspace"] == "/Users/kim/w"


@pytest.mark.realdata
def test_host_opencode_db_parses_when_present(tmp_path: Path) -> None:
    real = Path.home() / ".local/share/opencode/opencode.db"
    if not real.is_file():
        pytest.skip(f"store absent: {real}")
    small = tmp_path / "small.db"
    conn = sqlite3.connect(small.as_uri(), uri=True)
    conn.execute("ATTACH DATABASE ? AS real", (f"file:{real}?immutable=1",))
    conn.execute(
        "CREATE TABLE session AS SELECT * FROM real.session WHERE id IN "
        "(SELECT id FROM real.session ORDER BY time_updated DESC LIMIT 3)"
    )
    conn.execute("CREATE TABLE message AS SELECT * FROM real.message WHERE session_id IN (SELECT id FROM session)")
    conn.execute("CREATE TABLE part AS SELECT * FROM real.part WHERE session_id IN (SELECT id FROM session)")
    conn.commit()
    conn.execute("DETACH DATABASE real")
    conn.close()

    fs = MemoryFS({"/Users/examiner/.local/share/opencode/opencode.db": small.read_bytes()}, volume_os=OsFamily.MACOS)
    ctx = ParseContext(fs, "real", "Asia/Seoul", logging.getLogger("t"))
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))

    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    messages = [a.data["message"] for a in _kind(records, ArtifactKind.PARSE_WARNING)]
    assert all(m.startswith(("skipped", "schema_mismatch:")) for m in messages), messages
