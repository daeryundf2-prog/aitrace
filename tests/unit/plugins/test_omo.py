from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.ai.omo import PLUGIN
from aitrace.plugins.base import ParseContext

LOG = logging.getLogger("tests.omo")
HOME = "/Users/kim"
SESSION = f"{HOME}/.omo/agent/sessions/--Users-kim-work--/2026-10-01T01-00-00-000Z_abc.jsonl"
THREAD_DIR = f"{HOME}/.omo/desktop/userdata/omo-sessions/omo-1"
THREAD = f"{THREAD_DIR}/thread-t1-0.jsonl"


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


def _header(cwd: str = "/Users/kim/work") -> dict[str, object]:
    return {"type": "session", "version": 3, "id": "sess-1", "timestamp": "2026-10-01T01:00:00Z", "cwd": cwd}


def _msg(role: str, content: object, ts: str, **extra: object) -> dict[str, object]:
    return {
        "type": "message",
        "id": "m",
        "parentId": None,
        "timestamp": ts,
        "message": {"role": role, "content": content, **extra},
    }


def _transcript() -> bytes:
    write = {
        "type": "toolCall",
        "name": "write",
        "arguments": {"path": "/Users/kim/work/proposal.md", "content": "# Proposal"},
    }
    return _jsonl(
        _header(),
        {"type": "model_change", "provider": "anthropic", "modelId": "claude-x"},
        {"type": "custom_message", "customType": "note", "content": "ignored"},
        _msg("user", [{"type": "text", "text": "write a proposal"}], "2026-10-01T01:00:01Z"),
        _msg(
            "assistant",
            [{"type": "thinking", "thinking": "hmm"}, {"type": "text", "text": "Writing it."}, write],
            "2026-10-01T01:00:05Z",
            model="claude-y",
            provider="anthropic",
        ),
        _msg("toolResult", [{"type": "text", "text": "ok"}], "2026-10-01T01:00:06Z", toolName="write"),
    )


def test_locate_yields_every_source() -> None:
    fs = MemoryFS(
        {
            SESSION: b"",
            THREAD: b"",
            f"{THREAD_DIR}/thread-t1-0.jsonl.claude-sdk-oauth-binding.json": b"{}",
            f"{THREAD_DIR}/thread-t1-0-artifacts/a.png": b"x",
            f"{HOME}/.omo/memory/notes/a.md": b"# a",
            f"{HOME}/.omo/memory/b.md": b"# b",
            f"{HOME}/.omo/omo.jsonc": b"{}",
            f"{HOME}/.omo/agent/settings.json": b"{}",
            f"{HOME}/.omo/agent/auth.json": b'{"k": "secret"}',
        },
        volume_os=OsFamily.MACOS,
    )
    cands = list(PLUGIN.locate(fs))
    assert sorted(c.role for c in cands) == ["config", "config", "memory", "session", "thread"]
    assert next(c for c in cands if c.role == "memory").extra["count"] == 2


def test_session_yields_messages_tool_call_and_events() -> None:
    records = _run({SESSION: _transcript()})
    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(m.data["role"], m.data["text"]) for m in messages] == [
        ("user", "write a proposal"),
        ("assistant", "Writing it."),
        ("tool", "ok"),
    ]
    assert messages[0].data["session_id"] == "sess-1"
    assert messages[0].data["workspace"] == "/Users/kim/work"
    assert "model" not in messages[0].data
    assert messages[1].data["model"] == "claude-y"
    assert messages[0].user == "kim"
    assert messages[0].provenance.record_locator == "line:4"

    calls = _kind(records, ArtifactKind.AI_TOOL_CALL)
    assert len(calls) == 1
    assert calls[0].data["call_name"] == "write"
    assert calls[0].data["file_path"] == "/Users/kim/work/proposal.md"
    assert calls[0].data["content"] == "# Proposal"
    assert calls[0].data["tool"] == "omo"

    events = _events(records)
    assert [e.actor for e in events] == [Actor.HUMAN, Actor.AI, Actor.AI, Actor.SYSTEM]
    assert all(e.category == EventCategory.AI_ACTIVITY for e in events)
    assert events[0].ts_utc == datetime(2026, 10, 1, 1, 0, 1, tzinfo=UTC)
    assert not _kind(records, ArtifactKind.PARSE_WARNING)
    presence = _kind(records, ArtifactKind.AI_APP_PRESENCE)[0]
    assert presence.data["kind"] == "store"
    assert presence.data["last_seen"] == "2026-10-01T01:00:06Z"


def test_model_change_supplies_model_when_message_has_none() -> None:
    records = _run(
        {
            SESSION: _jsonl(
                _header(),
                {"type": "model_change", "provider": "p", "modelId": "m-1"},
                _msg("assistant", [{"type": "text", "text": "hi"}], "2026-10-01T01:00:05Z"),
            )
        }
    )
    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE)[0].data["model"] == "m-1"


def test_edit_apply_patch_and_bash_tool_calls() -> None:
    def call(name: str, **arguments: object) -> dict[str, object]:
        return {"type": "toolCall", "name": name, "arguments": arguments}

    blocks = [
        call(
            "edit", path="/a/b.py", edits=[{"oldText": "x", "newText": "a"}, {"oldText": "y", "newText": "b"}]
        ),
        call("apply_patch", path="/a/c.py", input="*** Begin Patch"),
        call("Bash", command="ls -la"),
        call("Write", file_path="/a/d.md", content="d"),
    ]
    records = _run({SESSION: _jsonl(_header(), _msg("assistant", blocks, "2026-10-01T01:00:05Z"))})
    calls = _kind(records, ArtifactKind.AI_TOOL_CALL)
    assert [(c.data["call_name"], c.data.get("file_path"), c.data.get("content")) for c in calls] == [
        ("edit", "/a/b.py", "a\nb"),
        ("apply_patch", "/a/c.py", "*** Begin Patch"),
        ("Bash", None, None),
        ("Write", "/a/d.md", "d"),
    ]
    assert calls[2].data["command"] == "ls -la"
    assert len({c.id for c in calls}) == 4
    assert not _kind(records, ArtifactKind.AI_CHAT_MESSAGE)


def test_malformed_lines_counted_in_single_warning() -> None:
    raw = (
        _jsonl(_header(), _msg("user", [{"type": "text", "text": "hello"}], "2026-10-01T01:00:01Z"))
        + b"{not json\n[1, 2]\n"
        + json.dumps({"type": "message", "message": "bad"}).encode()
        + b"\n"
    )
    records = _run({SESSION: raw})
    assert len(_kind(records, ArtifactKind.AI_CHAT_MESSAGE)) == 1
    warnings = _kind(records, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 1
    assert warnings[0].data["message"] == "skipped 3 malformed record(s)"


def test_desktop_thread_parses_and_counts_artifacts() -> None:
    records = _run({THREAD: _transcript(), f"{THREAD_DIR}/thread-t1-0-artifacts/a.png": b"x"})
    assert len(_kind(records, ArtifactKind.AI_CHAT_MESSAGE)) == 3
    detail = str(_kind(records, ArtifactKind.AI_APP_PRESENCE)[0].data["detail"])
    assert "1 artifact(s)" in detail


def test_memory_store_presence_has_count_and_newest_mtime() -> None:
    records = _run({f"{HOME}/.omo/memory/a.md": b"# a", f"{HOME}/.omo/memory/x/b.md": b"# b"})
    presence = _kind(records, ArtifactKind.AI_APP_PRESENCE)
    assert len(presence) == 1
    assert presence[0].data["kind"] == "store"
    assert "2 markdown note(s)" in str(presence[0].data["detail"])


def test_config_reports_model_and_provider_names_never_keys() -> None:
    jsonc = b"""{
      // comment with "quotes"
      "model": "claude-z", "apiKey": "sk-SECRET-123", /* block */
      "providers": {"openai": {"apiKey": "sk-ALSO-SECRET", "model": "gpt-9"}},
      "provider": "anthropic",
    }"""
    records = _run(
        {
            f"{HOME}/.omo/omo.jsonc": jsonc,
            f"{HOME}/.omo/agent/auth.json": b'{"anthropic": {"key": "sk-AUTH"}}',
            f"{HOME}/.omo/agent/settings.json": b"{broken",
        }
    )
    presence = {_p.provenance.source_path: _p for _p in _kind(records, ArtifactKind.AI_APP_PRESENCE)}
    cfg = presence["/Users/kim/.omo/omo.jsonc"]
    assert cfg.data["kind"] == "config"
    assert cfg.data["status"] == "parsed"
    detail = str(cfg.data["detail"])
    assert "claude-z" in detail and "gpt-9" in detail and "anthropic" in detail
    assert "SECRET" not in detail
    assert presence["/Users/kim/.omo/agent/settings.json"].data["status"] == "present"
    assert len(_kind(records, ArtifactKind.PARSE_WARNING)) == 1
    assert not any("sk-AUTH" in json.dumps(r.data) for r in records if isinstance(r, Artifact))


def test_windows_paths_are_normalized_with_raw_path_kept() -> None:
    write = {
        "type": "toolCall",
        "name": "write",
        "arguments": {"path": "C:\\Users\\kim\\w\\a.md", "content": "hi"},
    }
    files = {
        "/Users/kim/AppData/x": b"",
        "/Users/kim/.omo/agent/sessions/s/2026_a.jsonl": _jsonl(
            _header("C:\\Users\\kim\\w"),
            _msg("assistant", [{"type": "text", "text": "t"}, write], "2026-10-01T01:00:05Z"),
        ),
    }
    records = _run(files, OsFamily.WINDOWS)
    call = _kind(records, ArtifactKind.AI_TOOL_CALL)[0]
    assert call.data["file_path"] == "/Users/kim/w/a.md"
    assert call.data["raw_path"] == "C:\\Users\\kim\\w\\a.md"
    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE)[0].data["workspace"] == "/Users/kim/w"


def _smallest(home: Path, pattern: str, limit: int = 3) -> list[Path]:
    return sorted((p for p in home.glob(pattern) if p.is_file()), key=lambda p: p.stat().st_size)[:limit]


@pytest.mark.realdata
def test_host_omo_transcripts_parse_when_present() -> None:
    home = Path.home()
    session_pattern = ".omo/agent/sessions/*/*.jsonl"
    thread_pattern = ".omo/desktop/userdata/omo-sessions/*/thread-*.jsonl"
    host_files = _smallest(home, session_pattern) + _smallest(home, thread_pattern)
    if not host_files:
        pytest.skip(f"store absent: {home / '.omo'}")
    fs = MemoryFS(
        {f"/Users/examiner/{p.relative_to(home).as_posix()}": p.read_bytes() for p in host_files},
        volume_os=OsFamily.MACOS,
    )
    ctx = ParseContext(fs, "real", "Asia/Seoul", logging.getLogger("t"))
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))

    messages = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    print(
        f"omo realdata: files={len(host_files)} messages={len(messages)} tool_calls={len(_kind(records, ArtifactKind.AI_TOOL_CALL))}"
    )
    assert messages
    warnings = [a.data["message"] for a in _kind(records, ArtifactKind.PARSE_WARNING)]
    assert all(m.startswith(("skipped", "schema_mismatch:")) for m in warnings), warnings
