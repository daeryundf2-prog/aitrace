from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aitrace.core.kinds import ArtifactKind, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.ai.local_llm import PLUGIN, USER_PATTERNS
from aitrace.plugins.base import ParseContext

HOME = "/Users/kim"
GIN_OK = '[GIN] 2026/10/01 - 10:00:00 | 200 |     1.2ms |  127.0.0.1 | POST     "/api/generate"\n'


def _run(fs: MemoryFS, tz: str = "Asia/Seoul") -> list[Artifact | Event]:
    ctx = ParseContext(fs=fs, evidence_id=fs.evidence_id, tz=tz, log=logging.getLogger("test"))
    return [record for cand in PLUGIN.locate(fs) for record in PLUGIN.parse(ctx, cand)]


def _kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _warnings(records: list[Artifact | Event]) -> list[str]:
    return [a.data["message"] for a in _kind(records, ArtifactKind.PARSE_WARNING)]


def _events(records: list[Artifact | Event], ts_kind: str) -> list[Event]:
    return [r for r in records if isinstance(r, Event) and r.ts_kind == ts_kind]


def test_ollama_history_lines_become_prompts_without_timestamps() -> None:
    fs = MemoryFS({f"{HOME}/.ollama/history": b"first prompt\n\nsecond prompt\n"}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    chats = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(c.data["role"], c.data["text"]) for c in chats] == [
        ("user", "first prompt"),
        ("user", "second prompt"),
    ]
    events = _events(records, "message")
    assert len(events) == 2
    assert all(e.ts_utc is None and e.ts_basis == "unknown" for e in events)
    assert _warnings(records) == []


def test_non_utf8_history_yields_parse_warning_not_exception() -> None:
    fs = MemoryFS({f"{HOME}/.ollama/history": b"\xff\xfe\x00bad"}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE) == []
    assert len(_warnings(records)) == 1
    assert _warnings(records)[0].startswith("history is not UTF-8")


def test_ollama_server_log_request_lines_are_timed_in_assumed_timezone() -> None:
    log = (
        GIN_OK.encode()
        + b'[GIN] 2026/10/01 - 10:05:00 | 200 |  3ms | 127.0.0.1 | GET "/api/tags"\n'
        + b"time=2026-10-01 unrelated line\n"
    )
    fs = MemoryFS({f"{HOME}/.ollama/logs/server.log": log}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    requests = _events(records, "request")
    assert len(requests) == 2
    assert requests[0].ts_utc == datetime(2026, 10, 1, 1, 0, tzinfo=UTC)
    assert requests[0].ts_basis == "assumed:Asia/Seoul"
    assert "/api/generate" in requests[0].summary
    assert requests[1].subject == "/api/tags"
    assert _warnings(records) == []


def test_ollama_server_log_invalid_timestamp_is_parse_warning() -> None:
    log = b'[GIN] 2026/13/45 - 10:00:00 | 200 |  1ms | 127.0.0.1 | POST "/api/generate"\n'
    fs = MemoryFS({f"{HOME}/.ollama/logs/server.log": log}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    assert _events(records, "request") == []
    assert len(_warnings(records)) == 1
    assert "invalid timestamp" in _warnings(records)[0]


def test_linux_service_log_is_discovered_without_a_user() -> None:
    fs = MemoryFS({"/usr/share/ollama/.ollama/logs/server.log": GIN_OK.encode()}, volume_os=OsFamily.LINUX)

    records = _run(fs)

    presence = _kind(records, ArtifactKind.AI_APP_PRESENCE)
    assert len(presence) == 1
    assert presence[0].user is None
    assert presence[0].data["path"] == "/usr/share/ollama/.ollama/logs/server.log"
    assert len(_events(records, "request")) == 1


def test_ollama_manifest_yields_model_name_total_size_and_mtime() -> None:
    manifest = {"schemaVersion": 2, "layers": [{"size": 100}, {"size": 50}]}
    path = f"{HOME}/.ollama/models/manifests/registry.ollama.ai/library/llama3/latest"
    mtime = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
    fs = MemoryFS(
        {path: _json(manifest)},
        volume_os=OsFamily.MACOS,
        mtimes={path: mtime},
    )

    records = _run(fs)

    models = _kind(records, ArtifactKind.AI_MODEL)
    assert len(models) == 1
    assert models[0].data == {"tool": "Ollama", "model_name": "llama3:latest", "size": 150}
    assert [e.ts_utc for e in _events(records, "mtime")] == [mtime]
    assert _warnings(records) == []


def test_ollama_manifest_namespaced_model_keeps_namespace() -> None:
    path = f"{HOME}/.ollama/models/manifests/registry.ollama.ai/acme/coder/v2"
    fs = MemoryFS({path: _json({"layers": []})}, volume_os=OsFamily.MACOS)

    models = _kind(_run(fs), ArtifactKind.AI_MODEL)

    assert [m.data["model_name"] for m in models] == ["acme/coder:v2"]
    assert "size" not in models[0].data


def test_ollama_manifest_without_layers_is_schema_mismatch() -> None:
    path = f"{HOME}/.ollama/models/manifests/registry.ollama.ai/library/llama3/latest"
    fs = MemoryFS({path: _json({"schemaVersion": 2})}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    assert _kind(records, ArtifactKind.AI_MODEL) == []
    assert len(_warnings(records)) == 1
    assert _warnings(records)[0].startswith("schema_mismatch:")


def test_corrupt_manifest_yields_parse_warning() -> None:
    path = f"{HOME}/.ollama/models/manifests/registry.ollama.ai/library/llama3/latest"
    fs = MemoryFS({path: b"{not json"}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    assert _kind(records, ArtifactKind.AI_MODEL) == []
    assert len(_warnings(records)) == 1
    assert _warnings(records)[0].startswith("corrupt manifest JSON")


def test_lmstudio_conversation_reads_string_and_block_content() -> None:
    conversation = {
        "name": "Plan",
        "messages": [
            {"versions": [{"role": "user", "content": "hello there"}], "currentlySelected": 0},
            {
                "versions": [
                    {
                        "role": "assistant",
                        "content": [{"type": "text", "text": "hi"}, {"type": "image"}],
                    }
                ]
            },
        ],
    }
    fs = MemoryFS(
        {f"{HOME}/.lmstudio/conversations/chat1.conversation.json": _json(conversation)},
        volume_os=OsFamily.MACOS,
    )

    records = _run(fs)

    chats = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(c.data["role"], c.data["text"]) for c in chats] == [
        ("user", "hello there"),
        ("assistant", "hi"),
    ]
    assert {c.data["session_id"] for c in chats} == {"chat1.conversation.json"}
    assert all(c.data["title"] == "Plan" for c in chats)
    assert _warnings(records) == []


def test_lmstudio_cache_conversation_without_messages_is_schema_mismatch() -> None:
    fs = MemoryFS(
        {f"{HOME}/.cache/lm-studio/conversations/a/b.json": _json({"name": "x"})},
        volume_os=OsFamily.MACOS,
    )

    records = _run(fs)

    assert _kind(records, ArtifactKind.AI_CHAT_MESSAGE) == []
    assert len(_warnings(records)) == 1
    assert _warnings(records)[0].startswith("schema_mismatch:")


def test_jan_thread_lines_keep_roles_text_and_epoch_ms_timestamps() -> None:
    lines = [
        {"role": "user", "content": [{"type": "text", "text": {"value": "what is 2+2"}}], "created_at": 1790000000000},
        {"role": "assistant", "content": [{"type": "text", "text": {"value": "4"}}], "created_at": 1790000005000},
    ]
    body = "\n".join(_json_text(line) for line in lines).encode()
    fs = MemoryFS({f"{HOME}/jan/threads/thread-a/messages.jsonl": body}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    chats = _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(c.data["role"], c.data["text"], c.data["session_id"]) for c in chats] == [
        ("user", "what is 2+2", "thread-a"),
        ("assistant", "4", "thread-a"),
    ]
    assert [e.ts_utc for e in _events(records, "message")] == [
        datetime.fromtimestamp(1790000000, tz=UTC),
        datetime.fromtimestamp(1790000005, tz=UTC),
    ]
    assert _warnings(records) == []


def test_jan_bad_lines_warn_while_good_lines_survive() -> None:
    body = (
        b'{"role":"user","content":[{"text":{"value":"kept"}}],"created_at":1790000000000}\n'
        b'{"role": "user", \n'
        b'{"content":[]}\n'
    )
    fs = MemoryFS({f"{HOME}/Library/Application Support/Jan/data/threads/t1/messages.jsonl": body}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    assert [c.data["text"] for c in _kind(records, ArtifactKind.AI_CHAT_MESSAGE)] == ["kept"]
    warnings = _warnings(records)
    assert len(warnings) == 2
    assert warnings[0].startswith("corrupt JSON at line 2")
    assert warnings[1].startswith("schema_mismatch: line 3")


def test_gpt4all_model_file_yields_ai_model_with_size() -> None:
    path = f"{HOME}/Library/Application Support/nomic.ai/GPT4All/Llama-3.2-3B.gguf"
    fs = MemoryFS({path: b"x" * 2048}, volume_os=OsFamily.MACOS)

    models = _kind(_run(fs), ArtifactKind.AI_MODEL)

    assert [m.data for m in models] == [
        {"tool": "GPT4All", "model_name": "Llama-3.2-3B.gguf", "size": 2048},
    ]


_REALDATA_MAX_FILES = 5
_REALDATA_MAX_BYTES = 50 * 1024 * 1024


@pytest.mark.realdata
def test_host_local_llm_files_parse_without_schema_mismatch_when_present() -> None:
    home = Path.home()
    host_files = [
        path
        for _, _, pattern in USER_PATTERNS
        for path in home.glob(pattern)
        if path.is_file() and path.stat().st_size <= _REALDATA_MAX_BYTES
    ][:_REALDATA_MAX_FILES]
    if not host_files:
        pytest.skip(f"store absent: {home / '.ollama' / 'history'}")
    fs = MemoryFS(
        {str(path): path.read_bytes() for path in host_files},
        volume_os=OsFamily.MACOS,
    )

    records = _run(fs)

    assert [w for w in _warnings(records) if w.startswith("schema_mismatch:")] == []


def _json(value: object) -> bytes:
    return json.dumps(value).encode()


def _json_text(value: object) -> str:
    return json.dumps(value)
