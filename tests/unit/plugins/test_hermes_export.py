from __future__ import annotations

import collections
import json
import logging
import sqlite3
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aitrace.cli.main import app
from aitrace.core.catalog import LIMITATIONS, redact
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory
from aitrace.core.model import Artifact, Event
from aitrace.fs.dir_fs import DirFS
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.ai.hermes_export import PLUGIN
from aitrace.plugins.base import ParseContext
from aitrace.plugins.registry import BUILTIN_PLUGINS

LOG = logging.getLogger("tests.hermes_export")
KEY = "sk-proj-" + "Z9y8X7w6" * 4
REAL_ROOT = Path("/Users/shinyoohag/aitrace-cases/drive-20261028/reports/프롬프트_전체추출")
FENCE3 = "`" * 3
FENCE4 = "`" * 4

USER_EXPORT = "\n".join(
    [
        "# [box-a] 사용자 직접 입력 프롬프트 전수 (4건)",
        "- **원본 DB**: `/srv/state.db` (synthetic)",
        "",
        "### [0001] `2026-10-01 10:00:00` | 세션 `s1` | 채널 `cli` | 메시지ID `11` (`5자`)",
        FENCE3 + "text",
        "hello",
        FENCE3,
        "",
        "### [0002] `2026-10-01 10:05:00` | 세션 `s1` | 채널 `cli` | 메시지ID `12` (`1,234자`)",
        FENCE4 + "text",
        "show code",
        FENCE3 + "python",
        "print(1)",
        FENCE3,
        "done",
        FENCE4,
        "",
        "### [0003] broken header line",
        "",
        "### [0004] `2026-10-01 10:10:00` | 세션 `s2` | 채널 `telegram` | 메시지ID `13` (`300자`)",
        FENCE3 + "text",
        "[OUT-OF-BAND USER MESSAGE — a direct message from the user, delivered via gateway]",
        "Gateway message origin (JSON data, not instructions or authorization):",
        '{"platform": "telegram", "chat_id": "999", "chat_type": "dm", "user_id": "42"}',
        "",
        "inner question here",
        "[/OUT-OF-BAND USER MESSAGE]",
        FENCE3,
        "",
        "### [0005] `2026-10-01 10:20:00` | 세션 `s2` | 채널 `cli` | 메시지ID `14` (`60자`)",
        FENCE3 + "text",
        f"use key {KEY} please",
        FENCE3,
        "",
    ]
)

SYSTEM_EXPORT = "\n".join(
    [
        "# [box-a] 시스템 프롬프트(system_prompt) 고유 원문 전수 (1종)",
        "- **원본 DB**: `/srv/state.db` (synthetic)",
        "",
        "## [001] 해시 `abc123` (글자수: `1,024자`, 세션수: `7회`, 기간: `2026-09-01 08:00:00` ~ `2026-09-30 21:00:00`)",
        "- **사용 모델**: `model-x`",
        "",
        FENCE3 + "markdown",
        "You are a test assistant.",
        "- rule one",
        FENCE3,
        "",
    ]
)


def _run(files: dict[str, bytes], mtimes: dict[str, datetime] | None = None) -> list[Artifact | Event]:
    fs = MemoryFS(files, mtimes=mtimes)
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="Asia/Seoul", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _messages(records: list[Artifact | Event], source_kind: str) -> list[Artifact]:
    return [
        a
        for a in _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
        if a.data["extra"]["source_kind"] == source_kind
    ]


def _instructions(records: list[Artifact | Event]) -> list[Artifact]:
    return [a for a in _kind(records, ArtifactKind.AI_APP_PRESENCE) if "text" in a.data]


def _event_for(records: list[Artifact | Event], artifact: Artifact) -> Event:
    return next(r for r in records if isinstance(r, Event) and r.artifact_id == artifact.id)


def _db(script: str, rows: list[tuple[str, tuple[object, ...]]], *, wal_header: bool = False) -> bytes:
    conn = sqlite3.connect(":memory:")
    conn.executescript(script)
    for sql, values in rows:
        conn.execute(sql, values)
    conn.commit()
    data = bytes(conn.serialize())
    conn.close()
    return data[:18] + b"\x02\x02" + data[20:] if wal_header else data


def test_registered_after_hermes_with_limitation_entry() -> None:
    index = BUILTIN_PLUGINS.index("aitrace.plugins.ai.hermes")
    assert BUILTIN_PLUGINS[index + 1] == "aitrace.plugins.ai.hermes_export"
    assert PLUGIN.name == "hermes_export"
    entry = LIMITATIONS["hermes_export_tz"]
    assert isinstance(entry, dict) and entry["en"] and entry["ko"]


def test_user_prompt_export_entries_fences_oob_and_redaction() -> None:
    records = _run({"/case/x/04/box-a_user.md": USER_EXPORT.encode()})
    msgs = _messages(records, "export_user_prompt")
    assert [m.data["extra"]["message_id"] for m in msgs] == ["11", "12", "13", "14"]
    first, fenced, oob, secret = msgs
    assert first.data["role"] == "user" and first.data["text"] == "hello"
    assert first.data["session_id"] == "s1" and first.user is None
    assert first.data["extra"]["machine"] == "box-a"
    assert first.data["extra"]["channel"] == "cli"
    assert first.data["extra"]["origin_db"] == "/srv/state.db"
    assert first.data["extra"]["ts_assumed_tz"] == "Asia/Seoul"
    event = _event_for(records, first)
    assert event.ts_utc == datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC)
    assert event.ts_basis == "assumed:Asia/Seoul"
    assert event.actor == Actor.HUMAN and event.category == EventCategory.AI_ACTIVITY
    assert fenced.data["text"] == f"show code\n{FENCE3}python\nprint(1)\n{FENCE3}\ndone"
    assert fenced.data["extra"]["declared_chars"] == 1234
    assert oob.data["text"] == "inner question here"
    assert oob.data["extra"]["gateway"] == {"platform": "telegram", "chat_type": "dm"}
    assert oob.data["extra"]["raw_chars"] > len(oob.data["text"])
    assert "999" not in json.dumps(oob.data)
    assert KEY not in secret.data["text"] and redact(KEY) in secret.data["text"]
    warnings = _kind(records, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 1 and "malformed" in warnings[0].data["message"]


def test_unterminated_fence_reports_warning() -> None:
    text = USER_EXPORT.split("### [0003]")[0] + "### [0009] `2026-10-01 11:00:00` | 세션 `s` | 채널 `c` | "
    text += "메시지ID `1` (`1자`)\n" + FENCE3 + "text\nnever closed\n"
    records = _run({"/a/u.md": text.encode()})
    assert len(_messages(records, "export_user_prompt")) == 2
    assert any("unterminated" in w.data["message"] for w in _kind(records, ArtifactKind.PARSE_WARNING))


def test_system_prompt_export() -> None:
    records = _run({"/case/03/box-a_system.md": SYSTEM_EXPORT.encode()})
    assert not _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    (msg,) = _instructions(records)
    assert msg.data["kind"] == "instruction" and msg.data["extra"]["role"] == "system"
    assert msg.data["text"] == "You are a test assistant.\n- rule one"
    extra = msg.data["extra"]
    assert extra["model"] == "model-x" and extra["source_kind"] == "export_system_prompt"
    assert extra["hash"] == "abc123" and extra["sessions"] == 7 and extra["declared_chars"] == 1024
    assert extra["period_end"] == "2026-09-30T12:00:00Z"
    event = _event_for(records, msg)
    assert event.ts_utc == datetime(2026, 8, 31, 23, 0, 0, tzinfo=UTC)
    assert event.actor == Actor.SYSTEM


def test_export_tz_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AITRACE_EXPORT_TZ", "UTC")
    records = _run({"/case/03/s.md": SYSTEM_EXPORT.encode()})
    (msg,) = _instructions(records)
    assert _event_for(records, msg).ts_utc == datetime(2026, 9, 1, 8, 0, 0, tzinfo=UTC)
    assert msg.data["extra"]["ts_assumed_tz"] == "UTC"


def test_unrelated_markdown_and_skipped_dirs_yield_nothing() -> None:
    files = {
        "/law/a.md": b"# Civil code article 1\ntext",
        "/repo/.git/x/u.md": USER_EXPORT.encode(),
        "/repo/node_modules/pkg/AGENTS.md": b"agents",
        "/only/config.yaml": f"OPENAI_API_KEY: {KEY}".encode(),
    }
    assert _run(files) == []


def test_a2a_jsonl_by_directory_and_by_signature() -> None:
    line_user = json.dumps({"ts": 1790000000.5, "role": "user", "text": "delegate this", "task_id": "t1"})
    line_agent = json.dumps({"ts": 1790000010.0, "role": "agent", "text": "done it"})
    files = {
        "/x/a2a_conversations/conv_one.jsonl": f"{line_user}\nnot json\n{line_agent}\n".encode(),
        "/y/other/conv_two.jsonl": f"{line_user}\n".encode(),
        "/y/other/unrelated.jsonl": b'{"a": 1}\n',
    }
    records = _run(files)
    msgs = _messages(records, "a2a")
    assert len(msgs) == 3
    one = [m for m in msgs if m.data["session_id"] == "conv_one"]
    assert [m.data["role"] for m in one] == ["user", "assistant"]
    assert one[0].data["extra"]["channel"] == "a2a" and one[0].data["extra"]["task_id"] == "t1"
    assert one[1].data["extra"]["raw_role"] == "agent"
    assert _event_for(records, one[1]).actor == Actor.AI
    assert _event_for(records, one[0]).ts_utc == datetime.fromtimestamp(1790000000.5, UTC)
    assert any("1 malformed" in w.data["message"] for w in _kind(records, ArtifactKind.PARSE_WARNING))


KANBAN_SCHEMA = """
CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT, assignee TEXT, status TEXT NOT NULL,
    created_by TEXT, created_at INTEGER NOT NULL, completed_at INTEGER, result TEXT);
CREATE TABLE task_comments (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL, author TEXT NOT NULL,
    body TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL, profile TEXT,
    status TEXT NOT NULL, started_at INTEGER NOT NULL, ended_at INTEGER, outcome TEXT, summary TEXT);
"""


def test_kanban_tasks_results_comments_runs_from_wal_image() -> None:
    blob = _db(
        KANBAN_SCHEMA,
        [
            (
                "INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "t1",
                    "Title one",
                    "do the thing",
                    "worker",
                    "done",
                    "user",
                    1790000000,
                    1790000500,
                    "result text",
                ),
            ),
            (
                "INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?)",
                ("t2", "Title two", None, None, "todo", "user", 1790000100, None, None),
            ),
            (
                "INSERT INTO task_comments (task_id, author, body, created_at) VALUES (?,?,?,?)",
                ("t1", "user", "please hurry", 1790000200),
            ),
            (
                "INSERT INTO task_comments (task_id, author, body, created_at) VALUES (?,?,?,?)",
                ("t1", "default", "on it", 1790000300),
            ),
            (
                (
                    "INSERT INTO task_runs (task_id, profile, status, started_at, ended_at, outcome, summary) "
                    "VALUES (?,?,?,?,?,?,?)"
                ),
                ("t1", "coder", "done", 1790000250, 1790000400, "ok", "run summary"),
            ),
        ],
        wal_header=True,
    )
    records = _run({"/case/05/kanban.db": blob})
    msgs = _messages(records, "kanban")
    by = collections.defaultdict(list)
    for m in msgs:
        by[m.data["extra"]["kanban_record"]].append(m)
    assert len(by["task"]) == 2 and len(by["task_result"]) == 1 and len(by["run_summary"]) == 1
    task = by["task"][0]
    assert (
        task.data["role"] == "user"
        and task.data["text"] == "do the thing"
        and task.data["title"] == "Title one"
    )
    assert task.data["extra"]["assignee"] == "worker" and task.data["extra"]["created_by"] == "user"
    assert by["task"][1].data["text"] == "Title two"
    assert by["task_result"][0].data["role"] == "assistant"
    assert _event_for(records, by["task_result"][0]).ts_utc == datetime.fromtimestamp(1790000500, UTC)
    assert sorted(c.data["role"] for c in by["comment"]) == ["assistant", "user"]
    assert not _kind(records, ArtifactKind.PARSE_WARNING)


def test_corrupt_kanban_db_is_parse_warning() -> None:
    records = _run({"/case/kanban.db": b"this is not a sqlite database at all" * 20})
    assert len(_kind(records, ArtifactKind.PARSE_WARNING)) == 1
    (presence,) = _kind(records, ArtifactKind.AI_APP_PRESENCE)
    assert presence.data["status"] == "present"


def _jobs(*jobs: Mapping[str, object]) -> bytes:
    return json.dumps({"jobs": list(jobs), "updated_at": "x"}).encode()


def test_cron_jobs_versions_executions_deliveries_and_output_prompts() -> None:
    job_a = {
        "id": "ja",
        "name": "daily",
        "prompt": "summarise news",
        "schedule_display": "0 9 * * *",
        "enabled": True,
        "model": "m1",
        "script": None,
        "no_agent": False,
    }
    job_a_old = dict(job_a, prompt="summarise old news")
    job_b = {"id": "jb", "name": "script only", "prompt": "", "script": "x.py", "no_agent": True}
    mtime = datetime(2026, 10, 20, 0, 0, tzinfo=UTC)
    executions = _db(
        "CREATE TABLE executions (id TEXT PRIMARY KEY, job_id TEXT NOT NULL, source TEXT NOT NULL, "
        "status TEXT NOT NULL, claimed_at TEXT NOT NULL, started_at TEXT, finished_at TEXT);",
        [
            (
                "INSERT INTO executions VALUES (?,?,?,?,?,?,?)",
                (
                    "e1",
                    "ja",
                    "tick",
                    "completed",
                    "2026-10-01T00:00:00+09:00",
                    "2026-10-01T00:00:01+09:00",
                    None,
                ),
            ),
            (
                "INSERT INTO executions VALUES (?,?,?,?,?,?,?)",
                ("e2", "ja", "tick", "failed", "2026-10-02T00:00:00+09:00", None, None),
            ),
        ],
    )
    deliveries = _db(
        "CREATE TABLE deliveries (execution_id TEXT PRIMARY KEY, content TEXT NOT NULL, status TEXT NOT NULL);",
        [("INSERT INTO deliveries VALUES (?,?,?)", ("e1", "secret body", "delivered"))],
    )
    files = {
        "/c/cron/jobs.json": _jobs(job_a, job_b),
        "/c/cron/jobs.json.bak.20261015_164025": _jobs(job_a),
        "/c/cron/jobs.json.bak.noagent_20260922_000222": _jobs(job_a_old),
        "/c/cron/executions.db": executions,
        "/c/cron/deliveries.db": deliveries,
        "/c/cron/output/ja/prompt_20261001_090000.txt": b"rendered prompt",
    }
    records = _run(files, mtimes={"/c/cron/jobs.json": mtime})
    jobs = sorted(_messages(records, "cron_job"), key=lambda m: m.data["text"])
    assert [m.data["text"] for m in jobs] == ["summarise news", "summarise old news"]
    current, old = jobs
    assert current.data["extra"]["versions"] == ["jobs.json.bak.20261015_164025", "jobs.json"]
    assert current.data["extra"]["job_id"] == "ja" and current.data["extra"]["schedule"] == "0 9 * * *"
    assert current.data["model"] == "m1" and current.data["role"] == "user"
    assert _event_for(records, current).ts_utc == datetime(2026, 10, 15, 7, 40, 25, tzinfo=UTC)
    assert _event_for(records, old).ts_utc == datetime(2026, 9, 21, 15, 2, 22, tzinfo=UTC)
    assert old.data["extra"]["ts_kind"] == "file_name_version"
    exec_events = [r for r in records if isinstance(r, Event) and r.ts_kind == "cron_execution"]
    assert [e.summary for e in exec_events] == ["cron execution ja completed", "cron execution ja failed"]
    assert exec_events[0].category == EventCategory.OTHER
    assert exec_events[1].ts_utc == datetime(2026, 10, 1, 15, 0, tzinfo=UTC)
    stores = {a.data["extra"]["source_kind"]: a for a in _kind(records, ArtifactKind.AI_APP_PRESENCE)}
    assert stores["cron_executions"].data["extra"]["executions"] == 2
    assert stores["cron_deliveries"].data["extra"]["statuses"] == {"delivered": 1}
    assert "secret body" not in json.dumps([r.to_dict() for r in records])
    (prompt,) = _messages(records, "cron_output_prompt")
    assert prompt.data["text"] == "rendered prompt" and prompt.data["session_id"] == "cron:ja"
    assert _event_for(records, prompt).ts_utc == datetime(2026, 10, 1, 0, 0, tzinfo=UTC)


def test_instruction_files_dedupe_kinds_and_backup_version() -> None:
    soul = b"# Soul\nbe kind"
    mtime = datetime(2026, 10, 25, 3, 0, tzinfo=UTC)
    files = {
        "/a/hermes_dot/SOUL.md": soul,
        "/a/hermes_root/SOUL.md": soul,
        "/a/soul_repo/live/SOUL.node-1.md": soul,
        "/a/hermes_dot/SOUL.md.bak.20260919_1128": b"# Soul\nold",
        "/a/hermes_dot/RULES.yaml": b"rules: []",
        "/a/hermes_dot/memories/MEMORY.md": b"memory",
        "/a/ws/proj__AGENTS.md": b"agents",
        "/a/ws/proj__docker__SOUL.md": b"docker soul",
        "/a/skills/research/SKILL.md": b"skill body",
        "/a/soul_repo/STANDARD.md.tmpl": b"template",
        "/a/notes/SKILL.md": b"not under skills",
    }
    records = _run(files, mtimes={"/a/hermes_dot/SOUL.md": mtime})
    assert not _kind(records, ArtifactKind.AI_CHAT_MESSAGE)
    msgs = _instructions(records)
    kinds = collections.Counter(m.data["extra"]["source_kind"] for m in msgs)
    assert kinds == {
        "persona": 3,
        "rules": 1,
        "memory": 1,
        "workspace_instruction": 1,
        "skill": 1,
        "template": 1,
    }
    assert {m.data["kind"] for m in msgs if m.data["extra"]["source_kind"] == "persona"} == {"persona"}
    docker = next(m for m in msgs if m.data["text"] == "docker soul")
    assert docker.data["extra"]["workspace"] == "proj/docker"
    live = next(m for m in msgs if m.data["text"] == "# Soul\nbe kind")
    assert live.provenance.source_path == "/a/hermes_dot/SOUL.md"
    assert sorted(live.data["extra"]["duplicate_paths"]) == [
        "/a/hermes_root/SOUL.md",
        "/a/soul_repo/live/SOUL.node-1.md",
    ]
    assert live.data["extra"]["role"] == "system" and live.data["extra"]["ts_kind"] == "file_mtime"
    assert _event_for(records, live).ts_utc == mtime
    backup = next(m for m in msgs if m.data["text"] == "# Soul\nold")
    assert backup.data["extra"]["version_ts"] == "2026-09-19T02:28:00Z"
    assert _event_for(records, backup).ts_basis == "assumed:Asia/Seoul"


def test_instruction_text_truncated_at_limit() -> None:
    records = _run({"/a/AGENTS.md": b"x" * 400_010})
    (msg,) = _instructions(records)
    assert len(msg.data["text"]) == 400_000 and msg.data["extra"]["truncated"] is True


def test_evidence_folder_state_files_are_dated_presence() -> None:
    mtime = datetime(2026, 10, 20, 1, 2, 3, tzinfo=UTC)
    files = {
        "/e/hermes_dot/channel_directory.json": b"{}",
        "/e/hermes_dot/gateway_state.json": b"{}",
        "/e/hermes_dot/telegram_update_receipts_1.json": b"{}",
        "/e/hermes_dot/_a2a_pending.md": b"pending",
        "/e/soul_repo/machines/box.yaml": b"name: box",
        "/e/soul_repo/machines/box.yaml.bak_add_20261014_080728": b"name: box",
        "/e/soul_repo/build_soul.py": b"print()",
        "/e/notes/a2a_misc.md": b"not under a hermes dir",
    }
    records = _run(files, mtimes={"/e/hermes_dot/gateway_state.json": mtime})
    presence = _kind(records, ArtifactKind.AI_APP_PRESENCE)
    kinds = collections.Counter(a.data["extra"]["source_kind"] for a in presence)
    assert kinds == {"gateway_state": 3, "a2a_notes": 1, "soul_machine_config": 2, "soul_build_script": 1}
    gateway = next(a for a in presence if a.provenance.source_path.endswith("gateway_state.json"))
    assert gateway.data["last_seen"] == "2026-10-20T01:02:03Z"
    assert _event_for(records, gateway).ts_utc == mtime


def test_shell_history_reuses_history_tagging() -> None:
    files = {
        "/c/cli_history/.bash_history": f"#1790000000\nclaude -p hi\nexport OPENAI_API_KEY={KEY}\n".encode()
    }
    records = _run(files)
    cmds = _kind(records, ArtifactKind.SHELL_COMMAND)
    assert [c.data["shell"] for c in cmds] == ["bash", "bash"]
    assert cmds[0].data["rule_ids"] == ["AI-CLI"] and cmds[0].provenance.plugin == "hermes_export"
    assert KEY not in cmds[1].data["command"] and redact(KEY) in cmds[1].data["command"]
    event = _event_for(records, cmds[0])
    assert (
        event.ts_utc == datetime.fromtimestamp(1790000000, UTC) and event.category == EventCategory.EXECUTION
    )


def test_credentials_presence_only_never_values() -> None:
    auth = {"version": 1, "providers": {}, "credential_pool": {"gemini": [{"api_key": KEY}], "empty": []}}
    files = {
        "/h/hermes_dot/SOUL.md": b"soul",
        "/h/hermes_dot/auth.json": json.dumps(auth).encode(),
        "/h/hermes_dot/config.yaml": f"model: x\nOPENAI_API_KEY: {KEY}\n".encode(),
        "/h/hermes_dot/.env": f"OPENAI_API_KEY={KEY}\n".encode(),
    }
    records = _run(files)
    dumped = json.dumps([r.to_dict() for r in records], ensure_ascii=False)
    assert KEY not in dumped
    creds = _kind(records, ArtifactKind.AI_CREDENTIAL)
    assert {c.data["provider"] for c in creds} == {"gemini", "OpenAI"}
    configs = [a for a in _kind(records, ArtifactKind.AI_APP_PRESENCE) if a.data["kind"] == "config"]
    assert len(configs) == 3


@pytest.mark.realdata
def test_real_case_export_counts() -> None:
    if not REAL_ROOT.is_dir():
        pytest.skip(f"store absent: {REAL_ROOT}")
    started = time.monotonic()
    fs = DirFS(REAL_ROOT)
    ctx = ParseContext(fs, "real", "Asia/Seoul", LOG)
    counts: collections.Counter[str] = collections.Counter()
    warnings = 0
    for cand in PLUGIN.locate(fs):
        for record in PLUGIN.parse(ctx, cand):
            if not isinstance(record, Artifact):
                continue
            if record.kind == ArtifactKind.PARSE_WARNING:
                warnings += 1
            elif record.kind == ArtifactKind.AI_CHAT_MESSAGE or "text" in record.data:
                extra = record.data["extra"]
                suffix = f":{extra['kanban_record']}" if "kanban_record" in extra else ""
                counts[extra["source_kind"] + suffix] += 1
            else:
                counts[record.kind.value] += 1
    elapsed = time.monotonic() - started
    print(
        f"hermes_export real counts: {dict(sorted(counts.items()))} warnings={warnings} seconds={elapsed:.1f}"
    )
    assert counts["export_user_prompt"] >= 26000
    assert counts["export_system_prompt"] >= 300
    assert counts["a2a"] > 0
    assert counts["kanban:task"] > 0
    assert counts["cron_job"] > 0
    assert elapsed < 180


def _layout(root: Path) -> None:
    files = {
        "evidence/hermes_dot/SOUL.md": "# Persona\nbe precise",
        "evidence/hermes_dot/SOUL.md.bak.20260919_1128": "# Persona\nold",
        "evidence/hermes_dot/RULES.yaml": "rules: [one]",
        "evidence/hermes_dot/memories/MEMORY.md": "memory note",
        "evidence/hermes_dot/gateway_state.json": "{}",
        "evidence/hermes_root/SOUL.md": "# Persona\nbe precise",
        "evidence/soul_repo/live/SOUL.box.md": "# Persona\nbox",
        "evidence/soul_repo/STANDARD.md.tmpl": "template {{name}}",
        "evidence/workspace_instruction_md/proj__AGENTS.md": "agents rules",
        "reports/export/03_system/box_system.md": SYSTEM_EXPORT,
        "reports/export/04_user/box_user.md": USER_EXPORT,
        "reports/export/05_a2a/a2a_conversations/conv.jsonl": json.dumps(
            {"ts": 1790000000.0, "role": "user", "text": "delegate"}
        )
        + "\n",
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def test_cli_analyze_extracted_layout_fills_instructions_and_queries(tmp_path: Path) -> None:
    source = tmp_path / "src"
    _layout(source)
    case_dir = tmp_path / "case"
    result = CliRunner().invoke(
        app, ["analyze", str(source), "--case-dir", str(case_dir), "--formats", "json"]
    )
    assert result.exit_code == 0, result.output
    report = json.loads((case_dir / "report" / "report.json").read_text(encoding="utf-8"))
    sources = {Path(row["source"]).name for row in report["instructions"]}
    assert {"SOUL.md", "RULES.yaml", "MEMORY.md", "proj__AGENTS.md", "box_system.md"} <= sources
    assert all(row["text"] for row in report["instructions"])
    users = [q for q in report["ai_queries"] if q["role"] == "user"]
    assert len(users) >= 5
    assert any(q["text"] == "inner question here" and q["ts_utc"] for q in users)
    assert any(tool.get("tool") == "Hermes Agent" for tool in report["ai_tools"])
    assert report["timeline"]
