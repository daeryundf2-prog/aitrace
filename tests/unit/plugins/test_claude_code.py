from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.ai.claude_code import PLUGIN
from aitrace.plugins.base import ParseContext

LOG = logging.getLogger("tests.claude_code")
HOME = "/Users/kim"
SESSION = f"{HOME}/.claude/projects/-Users-kim-work/s1.jsonl"


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


def _jsonl(*rows: object) -> bytes:
    return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()


def _user(text: object, ts: str = "2026-10-01T01:00:00Z") -> dict[str, object]:
    return {
        "type": "user",
        "sessionId": "sess-1",
        "cwd": "/Users/kim/work",
        "timestamp": ts,
        "message": {"role": "user", "content": text},
    }


def _assistant(blocks: list[object], ts: str = "2026-10-01T01:00:05Z") -> dict[str, object]:
    return {
        "type": "assistant",
        "sessionId": "sess-1",
        "cwd": "/Users/kim/work",
        "timestamp": ts,
        "message": {"role": "assistant", "model": "claude-opus-4", "content": blocks},
    }


def test_locate_yields_every_source() -> None:
    fs = MemoryFS(
        {
            SESSION: b"",
            f"{HOME}/.claude/projects/-Users-kim-work/s1/subagents/agent-a.jsonl": b"",
            f"{HOME}/.claude/history.jsonl": b"",
            f"{HOME}/.claude.json": b"{}",
            f"{HOME}/.claude/settings.json": b"{}",
            f"{HOME}/.claude/other.txt": b"",
        },
        volume_os=OsFamily.MACOS,
    )
    assert sorted(c.role for c in PLUGIN.locate(fs)) == ["config", "history", "session", "settings", "subagent"]


def test_session_yields_two_messages_and_one_tool_call_with_file_path() -> None:
    write = {
        "type": "tool_use",
        "name": "Write",
        "input": {"file_path": "/Users/kim/work/proposal.md", "content": "# Proposal"},
    }
    records = _run(
        {
            SESSION: _jsonl(
                _user("write a proposal"),
                _assistant([{"type": "text", "text": "Writing it."}, write]),
            )
        }
    )
    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [m.data["role"] for m in messages] == ["user", "assistant"]
    assert messages[0].data["text"] == "write a proposal"
    assert messages[0].data["session_id"] == "sess-1"
    assert messages[0].data["workspace"] == "/Users/kim/work"
    assert messages[1].data["model"] == "claude-opus-4"
    assert messages[0].user == "kim"
    assert messages[0].provenance.record_locator == "line:1"

    calls = _kind(records, ArtifactKind.AI_TOOL_CALL)
    assert len(calls) == 1
    assert calls[0].data["call_name"] == "Write"
    assert calls[0].data["file_path"] == "/Users/kim/work/proposal.md"
    assert calls[0].data["content"] == "# Proposal"
    assert calls[0].data["tool"] == "Claude Code"
    assert calls[0].data["input"] == write["input"]

    events = _events(records)
    assert [e.actor for e in events] == [Actor.HUMAN, Actor.AI, Actor.AI]
    assert all(e.category == EventCategory.AI_ACTIVITY for e in events)
    assert events[0].ts_utc == datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC)
    assert not _kind(records, ArtifactKind.PARSE_WARNING)
    presence = _kind(records, ArtifactKind.AI_APP_PRESENCE)
    assert presence[0].data["status"] == "parsed"
    assert presence[0].data["last_seen"] == "2026-10-01T01:00:05Z"


def test_edit_and_multiedit_store_new_string_as_content() -> None:
    edit = {"type": "tool_use", "name": "Edit", "input": {"file_path": "/a/b.py", "new_string": "x = 1"}}
    multi = {
        "type": "tool_use",
        "name": "MultiEdit",
        "input": {"file_path": "/a/c.py", "edits": [{"new_string": "a"}, {"new_string": "b"}]},
    }
    bash = {"type": "tool_use", "name": "Bash", "input": {"command": "ls -la"}}
    records = _run({SESSION: _jsonl(_assistant([edit, multi, bash]))})
    calls = _kind(records, ArtifactKind.AI_TOOL_CALL)
    assert [(c.data["call_name"], c.data.get("file_path"), c.data.get("content")) for c in calls] == [
        ("Edit", "/a/b.py", "x = 1"),
        ("MultiEdit", "/a/c.py", "a\nb"),
        ("Bash", None, None),
    ]
    assert calls[2].data["command"] == "ls -la"
    assert len({c.id for c in calls}) == 3


def test_tool_result_user_line_is_tool_role_and_list_content_is_joined() -> None:
    result = {"type": "tool_result", "tool_use_id": "t1", "content": "ok"}
    records = _run(
        {
            SESSION: _jsonl(
                _user([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]),
                _user([result]),
            )
        }
    )
    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(m.data["role"], m.data["text"]) for m in messages] == [("user", "a\nb"), ("tool", "ok")]
    assert [e.actor for e in _events(records)] == [Actor.HUMAN, Actor.SYSTEM]


def test_malformed_lines_counted_in_single_warning() -> None:
    raw = (
        json.dumps(_user("hello")).encode()
        + b"\n{not json\n[1, 2]\n"
        + json.dumps({"type": "assistant", "message": "bad"}).encode()
        + b"\n"
        + json.dumps({"type": "summary", "summary": "ignored"}).encode()
        + b"\n"
    )
    records = _run({SESSION: raw})
    assert len(_kind(records, ArtifactKind.AI_CHAT_MESSAGE)) == 1
    warnings = _kind(records, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 1
    assert warnings[0].data["message"] == "skipped 3 malformed record(s)"


def test_subagent_transcript_is_flagged() -> None:
    path = f"{HOME}/.claude/projects/-Users-kim-work/s1/subagents/agent-a.jsonl"
    records = _run({path: _jsonl(_user("sub task"))})
    message = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)[0]
    assert message.data["extra"] == {"subagent": True}


def test_history_yields_user_messages_with_display() -> None:
    history = _jsonl(
        {"display": "fix the bug", "timestamp": 1790816400000, "project": "/Users/kim/work"},
        {"display": "second"},
        {"nodisplay": 1},
    )
    records = _run({f"{HOME}/.claude/history.jsonl": history})
    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [m.data["text"] for m in messages] == ["fix the bug", "second"]
    assert all(m.data["role"] == "user" and "display" not in m.data for m in messages)
    assert messages[0].data["workspace"] == "/Users/kim/work"
    events = _events(records)
    assert events[0].ts_utc is not None
    assert events[1].ts_utc is None
    assert events[1].ts_basis == "unknown"
    assert len(_kind(records, ArtifactKind.PARSE_WARNING)) == 1


def test_config_and_settings_yield_presence_and_bad_json_warns() -> None:
    records = _run(
        {
            f"{HOME}/.claude.json": json.dumps({"projects": {"/a": {}, "/b": {}}, "x": 1}).encode(),
            f"{HOME}/.claude/settings.json": b"{broken",
        }
    )
    presence = {str(p.provenance.source_path): p for p in _kind(records, ArtifactKind.AI_APP_PRESENCE)}
    assert presence["/Users/kim/.claude.json"].data["status"] == "parsed"
    assert "2 project(s)" in str(presence["/Users/kim/.claude.json"].data["detail"])
    assert presence["/Users/kim/.claude/settings.json"].data["status"] == "present"
    assert len(_kind(records, ArtifactKind.PARSE_WARNING)) == 1


def test_windows_paths_are_normalized_with_raw_path_kept() -> None:
    files = {"/Users/kim/AppData/x": b"", "/Users/kim/.claude/projects/p/s.jsonl": _jsonl(
        {
            **_assistant(
                [
                    {
                        "type": "tool_use",
                        "name": "Write",
                        "input": {"file_path": "C:\\Users\\kim\\w\\a.md", "content": "hi"},
                    }
                ]
            ),
            "cwd": "C:\\Users\\kim\\w",
        }
    )}
    records = _run(files, OsFamily.WINDOWS)
    call = _kind(records, ArtifactKind.AI_TOOL_CALL)[0]
    assert call.data["file_path"] == "/Users/kim/w/a.md"
    assert call.data["raw_path"] == "C:\\Users\\kim\\w\\a.md"
    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE)[0].data["workspace"] == "/Users/kim/w"


@pytest.mark.realdata
def test_host_claude_sessions_parse_when_present() -> None:
    home = Path.home()
    pattern = ".claude/projects/*/*.jsonl"
    host_files = sorted(
        (p for p in home.glob(pattern) if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:5]
    if not host_files:
        pytest.skip(f"store absent: {pattern}")
    fs = MemoryFS(
        {f"/Users/examiner/{p.relative_to(home).as_posix()}": p.read_bytes() for p in host_files},
        volume_os=OsFamily.MACOS,
    )
    ctx = ParseContext(fs, "real", "Asia/Seoul", logging.getLogger("t"))
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))

    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    messages = [a.data["message"] for a in _kind(records, ArtifactKind.PARSE_WARNING)]
    assert all(m.startswith(("skipped", "schema_mismatch:")) for m in messages), messages
