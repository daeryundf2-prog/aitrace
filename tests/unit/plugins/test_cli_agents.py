from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.ai.cli_agents import PLUGIN
from aitrace.plugins.base import ParseContext

LOG = logging.getLogger("tests.cli_agents")
HOME = "/Users/kim"


def _run(files: dict[str, bytes], tz: str = "Asia/Seoul") -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=OsFamily.MACOS)
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz=tz, log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _warnings(records: list[Artifact | Event]) -> list[str]:
    return [str(r.data["message"]) for r in _kind(records, ArtifactKind.PARSE_WARNING)]


def _jsonl(*rows: object) -> bytes:
    return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()


def test_locate_yields_every_supported_format() -> None:
    fs = MemoryFS(
        {
            f"{HOME}/.codex/sessions/2026/10/01/rollout-a.jsonl": b"",
            f"{HOME}/.codex/history.jsonl": b"",
            f"{HOME}/.gemini/tmp/p1/logs.json": b"[]",
            f"{HOME}/.gemini/tmp/p1/chats/c1.json": b"{}",
            f"{HOME}/.copilot/session-state/s1.jsonl": b"",
            f"{HOME}/.continue/sessions/s1.json": b"{}",
            f"{HOME}/work/.aider.chat.history.md": b"",
            f"{HOME}/work/.aider.input.history": b"",
        },
        volume_os=OsFamily.MACOS,
    )
    roles = sorted(cand.role for cand in PLUGIN.locate(fs))
    assert roles == [
        "aider_input",
        "aider_md",
        "codex_history",
        "codex_rollout",
        "continue_session",
        "copilot_session",
        "gemini_chat",
        "gemini_logs",
    ]


def test_codex_rollout_yields_messages_and_tool_call() -> None:
    rollout = [
        {"type": "session_meta", "payload": {"id": "sess-1", "cwd": "/Users/kim/work"}},
        {
            "type": "response_item",
            "timestamp": "2026-10-01T01:00:05Z",
            "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "dump it"}]},
        },
        {
            "type": "response_item",
            "timestamp": "2026-10-01T01:00:09Z",
            "payload": {
                "type": "function_call",
                "name": "shell",
                "arguments": json.dumps({"command": "ls -la"}),
            },
        },
        {
            "type": "response_item",
            "timestamp": "2026-10-01T01:00:12Z",
            "payload": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Done."}]},
        },
    ]
    records = _run({f"{HOME}/.codex/sessions/2026/rollout-1.jsonl": _jsonl(*rollout)})

    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [m.data["role"] for m in messages] == ["user", "assistant"]
    assert all(m.data["tool"] == "Codex CLI" and m.data["session_id"] == "sess-1" for m in messages)
    assert messages[0].data["workspace"] == "/Users/kim/work"
    assert messages[0].user == "kim"

    (call,) = _kind(records, ArtifactKind.AI_TOOL_CALL)
    assert call.data["call_name"] == "shell"
    assert call.data["input"] == {"command": "ls -la"}
    assert call.data["command"] == "ls -la"

    events = [r for r in records if isinstance(r, Event)]
    assert events[0].actor is Actor.HUMAN
    assert events[0].ts_utc == datetime(2026, 10, 1, 1, 0, 5, tzinfo=UTC)
    assert events[0].ts_basis == "native_utc"
    assert events[0].category is EventCategory.AI_ACTIVITY
    assert _warnings(records) == []


def test_codex_rollout_counts_wrong_shape_as_parse_warning() -> None:
    rollout = [
        {
            "type": "response_item",
            "timestamp": "2026-10-01T01:00:05Z",
            "payload": {"type": "message", "role": "user", "content": 42},
        },
        {
            "type": "response_item",
            "timestamp": "2026-10-01T01:00:06Z",
            "payload": {"type": "message", "role": "user", "content": "still parsed"},
        },
    ]
    records = _run({f"{HOME}/.codex/sessions/rollout-2.jsonl": _jsonl(*rollout)})

    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [m.data["text"] for m in messages] == ["still parsed"]
    assert _warnings(records) == ["skipped 1 malformed record(s)"]


def test_codex_history_uses_unix_seconds() -> None:
    records = _run({f"{HOME}/.codex/history.jsonl": _jsonl({"session_id": "sess-9", "ts": 1790000000, "text": "hi"})})

    (message,) = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert message.data["session_id"] == "sess-9"
    assert message.data["recovered_from"] == "jsonl"
    (event,) = [r for r in records if isinstance(r, Event)]
    assert event.ts_utc == datetime.fromtimestamp(1790000000, UTC)


def test_gemini_logs_and_chats_are_parsed() -> None:
    logs = [
        {
            "sessionId": "g1",
            "messageId": 0,
            "type": "user",
            "message": "hi there",
            "timestamp": "2026-10-01T02:00:00.000Z",
        }
    ]
    chat = {
        "sessionId": "g1",
        "messages": [
            {"type": "user", "content": "q1", "timestamp": "2026-10-01T02:01:00.000Z"},
            {"type": "gemini", "content": "a1", "timestamp": "2026-10-01T02:01:02.000Z"},
        ],
    }
    records = _run(
        {
            f"{HOME}/.gemini/tmp/abc/logs.json": json.dumps(logs).encode(),
            f"{HOME}/.gemini/tmp/abc/chats/session-1.json": json.dumps(chat).encode(),
        }
    )

    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert sorted(m.data["text"] for m in messages) == ["a1", "hi there", "q1"]
    assert {m.data["role"] for m in messages} == {"user", "assistant"}
    assert all(m.data["tool"] == "Gemini CLI" for m in messages)
    assert _warnings(records) == []


def test_gemini_wrong_top_level_shape_yields_single_warning() -> None:
    records = _run({f"{HOME}/.gemini/tmp/abc/logs.json": json.dumps({"not": "a list"}).encode()})

    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE) == []
    assert _warnings(records) == ["unexpected JSON shape: expected a list of prompts"]


def test_gemini_invalid_json_yields_parse_warning() -> None:
    records = _run({f"{HOME}/.gemini/tmp/abc/chats/broken.json": b"{not json"})

    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE) == []
    (message,) = _warnings(records)
    assert message.startswith("invalid JSON:")


def test_aider_markdown_history_uses_assumed_local_time() -> None:
    text = (
        "# aider chat started at 2026-10-01 10:00:00\n"
        "\n"
        "#### fix the bug\n"
        "\n"
        "Sure, here is the fix.\n"
        "Applied edit to app.py\n"
        "\n"
        "#### thanks\n"
    )
    records = _run({f"{HOME}/work/.aider.chat.history.md": text.encode()})

    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [m.data["role"] for m in messages] == ["user", "assistant", "user"]
    assert messages[1].data["text"] == "Sure, here is the fix.\nApplied edit to app.py"
    assert messages[0].data["workspace"] == "/Users/kim/work"
    assert messages[0].data["recovered_from"] == "markdown"
    events = [r for r in records if isinstance(r, Event)]
    assert events[0].ts_utc == datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC)
    assert events[0].ts_basis == "assumed:Asia/Seoul"


def test_aider_input_history_groups_prompt_lines() -> None:
    text = (
        "# 2026-10-01 10:00:00.123456\n"
        "+fix the bug\n"
        "+in app.py\n"
        "\n"
        "# 2026-10-01 10:05:00\n"
        "+thanks\n"
    )
    records = _run({f"{HOME}/work/.aider.input.history": text.encode()})

    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [m.data["text"] for m in messages] == ["fix the bug\nin app.py", "thanks"]
    events = [r for r in records if isinstance(r, Event)]
    assert events[0].ts_utc == datetime(2026, 10, 1, 1, 0, 0, 123456, tzinfo=UTC)
    assert events[0].ts_basis == "assumed:Asia/Seoul"


def test_aider_input_history_counts_unprefixed_lines() -> None:
    text = "# 2026-10-01 10:00:00\n+ok\nstray text\n"
    records = _run({f"{HOME}/work/.aider.input.history": text.encode()})

    assert [m.data["text"] for m in _kind(records, ArtifactKind.AI_CHAT_MESSAGE)] == ["ok"]
    assert _warnings(records) == ["skipped 1 malformed record(s)"]


def test_copilot_session_lines_with_role_and_content() -> None:
    records = _run(
        {
            f"{HOME}/.copilot/session-state/abc-123.jsonl": _jsonl(
                {"role": "user", "content": "explain", "timestamp": "2026-10-01T03:00:00Z"},
                {"role": "assistant", "content": "sure"},
            )
        }
    )

    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [m.data["role"] for m in messages] == ["user", "assistant"]
    assert all(m.data["session_id"] == "abc-123" for m in messages)
    assert all(m.data["tool"] == "GitHub Copilot CLI" for m in messages)


def test_copilot_malformed_line_is_counted_and_others_kept() -> None:
    text = b'{"role": "user", "content": "ok"}\n{broken\n'
    records = _run({f"{HOME}/.copilot/session-state/s.jsonl": text})

    assert [m.data["text"] for m in _kind(records, ArtifactKind.AI_CHAT_MESSAGE)] == ["ok"]
    assert _warnings(records) == ["skipped 1 malformed record(s)"]


def test_continue_session_history_content_forms() -> None:
    session = {
        "history": [
            {"message": {"role": "user", "content": "hi"}},
            {"message": {"role": "assistant", "content": [{"type": "text", "text": "hello"}]}},
        ]
    }
    records = _run({f"{HOME}/.continue/sessions/s9.json": json.dumps(session).encode()})

    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [m.data["text"] for m in messages] == ["hi", "hello"]
    assert all(m.data["session_id"] == "s9" and m.data["tool"] == "Continue" for m in messages)
    events = [r for r in records if isinstance(r, Event)]
    assert all(e.ts_utc is None and e.ts_basis == "unknown" for e in events)


def test_continue_wrong_shape_yields_single_warning() -> None:
    records = _run({f"{HOME}/.continue/sessions/s1.json": json.dumps({"history": "nope"}).encode()})

    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE) == []
    assert _warnings(records) == ["unexpected JSON shape: expected an object with a history list"]


_REALDATA_MAX_FILES = 5


@pytest.mark.realdata
def test_host_codex_sessions_parse_into_chat_messages_when_present() -> None:
    home = Path.home()
    pattern = ".codex/sessions/**/*.jsonl"
    host_files = sorted(
        (path for path in home.glob(pattern) if path.is_file()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )[:_REALDATA_MAX_FILES]
    if not host_files:
        pytest.skip(f"store absent: {home / pattern}")
    fs = MemoryFS(
        {f"/Users/shinyoohag/{path.relative_to(home).as_posix()}": path.read_bytes() for path in host_files},
        volume_os=OsFamily.MACOS,
    )
    ctx = ParseContext(fs, "real", "Asia/Seoul", logging.getLogger("t"))
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))

    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    for message in _warnings(records):
        assert message.startswith(("skipped", "schema_mismatch:")), message
