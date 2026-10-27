from __future__ import annotations

import json
import logging
import struct
from datetime import UTC, datetime

from aitrace.core.kinds import Actor, ArtifactKind, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.ai.desktop_apps import PLUGIN
from aitrace.plugins.base import ParseContext
from aitrace.plugins.common.leveldb import _masked_crc

WIN_CHATGPT_DB = (
    "/Users/kim/AppData/Local/Packages/OpenAI.ChatGPT-Desktop_abc123/LocalCache/Roaming/ChatGPT/"
    "IndexedDB/https_chatgpt.com_0.indexeddb.leveldb"
)
WIN_CLAUDE = "/Users/kim/AppData/Roaming/Claude"
MAC_CHATGPT = "/Users/lee/Library/Application Support/com.openai.chat"
MAC_CLAUDE = "/Users/lee/Library/Application Support/Claude"


def _varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _leveldb_log(values: list[bytes]) -> bytes:
    batch = struct.pack("<QI", 1, len(values))
    for index, value in enumerate(values):
        key = f"k{index}".encode()
        batch += b"\x01" + _varint(len(key)) + key + _varint(len(value)) + value
    crc = _masked_crc(b"\x01" + batch)
    return struct.pack("<IHB", crc, len(batch), 1) + batch


def _run(fs: MemoryFS) -> list[Artifact | Event]:
    ctx = ParseContext(fs=fs, evidence_id=fs.evidence_id, tz="Asia/Seoul", log=logging.getLogger("test"))
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _artifacts(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def test_app_dirs_yield_presence_for_each_known_app() -> None:
    fs = MemoryFS(
        {
            "/Users/kim/AppData/Local/Packages/Microsoft.Copilot_8wekyb3d8bbwe/settings.dat": b"x",
            "/Users/kim/AppData/Local/Perplexity/app.cfg": b"x",
            f"{WIN_CLAUDE}/Preferences": b"{}",
        },
        volume_os=OsFamily.WINDOWS,
    )

    presence = _artifacts(_run(fs), ArtifactKind.AI_APP_PRESENCE)

    tools = {a.data["tool"] for a in presence if a.data["kind"] == "app"}
    assert tools == {"Microsoft Copilot", "Perplexity", "Claude Desktop"}
    assert all(a.data["status"] == "present" for a in presence)


def test_leveldb_json_message_and_fragment_are_recovered() -> None:
    message = json.dumps({"role": "assistant", "content": "planted assistant answer about quarterly plan"})
    fragment = '{"role": "user", "content": "truncated question about the merger'
    fs = MemoryFS(
        {f"{WIN_CHATGPT_DB}/000003.log": _leveldb_log([b"\x01\x02" + message.encode(), b"\x03" + fragment.encode()])},
        volume_os=OsFamily.WINDOWS,
    )

    chats = _artifacts(_run(fs), ArtifactKind.AI_CHAT_MESSAGE)

    structured = [c for c in chats if not c.data["fragment"]]
    fragments = [c for c in chats if c.data["fragment"]]
    assert [(c.data["role"], c.data["text"]) for c in structured] == [
        ("assistant", "planted assistant answer about quarterly plan")
    ]
    assert structured[0].data["recovered_from"] == "leveldb"
    assert structured[0].data["extra"]["confidence"] == "low"
    assert len(fragments) == 1
    assert fragments[0].data["role"] == "unknown"
    assert "truncated question about the merger" in fragments[0].data["text"]


def test_leveldb_noise_without_chat_keys_yields_nothing() -> None:
    noise = b"\x01" + b"just some unrelated cached string of sufficient length here"
    fs = MemoryFS({f"{WIN_CLAUDE}/Local Storage/leveldb/000003.log": _leveldb_log([noise])}, volume_os=OsFamily.WINDOWS)

    assert _artifacts(_run(fs), ArtifactKind.AI_CHAT_MESSAGE) == []


def test_mac_v1_conversation_yields_ordered_messages_with_roles() -> None:
    conversation = {
        "title": "Budget talk",
        "create_time": 1790000000.0,
        "mapping": {
            "root": {"message": None, "children": ["n2"]},
            "n3": {
                "message": {
                    "author": {"role": "assistant"},
                    "content": {"parts": ["Here is the budget."]},
                    "create_time": 1790000020.0,
                }
            },
            "n2": {
                "message": {
                    "author": {"role": "user"},
                    "content": {"parts": ["Draft a budget", "for next year"]},
                    "create_time": 1790000010.0,
                }
            },
        },
    }
    fs = MemoryFS(
        {f"{MAC_CHATGPT}/conversations-abc/c1.json": json.dumps(conversation).encode()},
        volume_os=OsFamily.MACOS,
    )

    records = _run(fs)

    chats = _artifacts(records, ArtifactKind.AI_CHAT_MESSAGE)
    assert [(c.data["role"], c.data["text"]) for c in chats] == [
        ("user", "Draft a budget\nfor next year"),
        ("assistant", "Here is the budget."),
    ]
    assert all(c.data["title"] == "Budget talk" and c.data["session_id"] == "c1" for c in chats)
    assert all(c.data["recovered_from"] == "json" and not c.data["fragment"] for c in chats)
    events = [r for r in records if isinstance(r, Event)]
    assert [e.actor for e in events] == [Actor.HUMAN, Actor.AI]
    assert events[0].ts_utc == datetime(2026, 9, 21, 14, 13, 30, tzinfo=UTC)


def test_malformed_v1_conversation_becomes_parse_warning() -> None:
    fs = MemoryFS({f"{MAC_CHATGPT}/conversations-abc/bad.json": b"{not json"}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    assert len(_artifacts(records, ArtifactKind.PARSE_WARNING)) == 1
    assert _artifacts(records, ArtifactKind.AI_CHAT_MESSAGE) == []


def test_v2_encrypted_store_is_presence_only() -> None:
    first = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
    second = datetime(2026, 9, 5, 2, 0, tzinfo=UTC)
    fs = MemoryFS(
        {
            f"{MAC_CHATGPT}/conversations-v2-abc/a.data": b"\x00\x01cipher",
            f"{MAC_CHATGPT}/conversations-v2-abc/b.data": b"\x02\x03cipher",
        },
        volume_os=OsFamily.MACOS,
        mtimes={
            f"{MAC_CHATGPT}/conversations-v2-abc/a.data": first,
            f"{MAC_CHATGPT}/conversations-v2-abc/b.data": second,
        },
    )

    records = _run(fs)

    assert _artifacts(records, ArtifactKind.AI_CHAT_MESSAGE) == []
    stores = [a for a in _artifacts(records, ArtifactKind.AI_APP_PRESENCE) if a.data["kind"] == "store"]
    assert len(stores) == 1
    assert stores[0].data["status"] == "encrypted_not_decoded"
    assert stores[0].data["extra"]["count"] == 2
    assert stores[0].data["extra"]["mtimes"] == ["2026-09-01T01:00:00Z", "2026-09-05T02:00:00Z"]
    assert stores[0].data["first_seen"] == "2026-09-01T01:00:00Z"
    assert stores[0].data["last_seen"] == "2026-09-05T02:00:00Z"


def test_claude_log_reports_first_and_last_timestamps() -> None:
    log = (
        "2026-10-01 10:00:00 [info] app starting\n"
        "continuation line without timestamp\n"
        "2026-10-02T12:30:00Z [info] app exiting\n"
    )
    fs = MemoryFS({"/Users/lee/Library/Logs/Claude/main.log": log.encode()}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    logs = [a for a in _artifacts(records, ArtifactKind.AI_APP_PRESENCE) if a.data["kind"] == "log"]
    assert len(logs) == 1
    assert logs[0].data["first_seen"] == "2026-10-01T01:00:00Z"
    assert logs[0].data["last_seen"] == "2026-10-02T12:30:00Z"
    assert logs[0].data["status"] == "parsed"


def test_claude_config_lists_mcp_servers_without_env_secrets() -> None:
    config = {
        "mcpServers": {
            "filesystem": {"command": "npx", "args": ["-y", "server-fs"], "env": {"TOKEN": "sk-secret-value"}},
            "git": {"command": "uvx", "args": ["mcp-git"]},
        }
    }
    fs = MemoryFS({f"{WIN_CLAUDE}/claude_desktop_config.json": json.dumps(config).encode()}, volume_os=OsFamily.WINDOWS)

    records = _run(fs)

    configs = [a for a in _artifacts(records, ArtifactKind.AI_APP_PRESENCE) if a.data["kind"] == "config"]
    assert len(configs) == 1
    servers = configs[0].data["extra"]["mcp_servers"]
    assert set(servers) == {"filesystem", "git"}
    assert servers["filesystem"] == {"command": "npx", "args": ["-y", "server-fs"]}
    assert "sk-secret-value" not in json.dumps(configs[0].data)
