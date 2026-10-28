"""Synthetic large-case checks: the main report stays bounded while report.json and prompts.html stay complete."""

from __future__ import annotations

import importlib.util
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from aitrace.report.html import render_html_string
from aitrace.report.layout import Block, Document, Heading, Para, Table, build_document
from aitrace.report.model import (
    EXCERPT_CHARS,
    QUESTION_EXCERPT_CAP,
    QUESTION_EXCERPT_CHARS,
    TIMELINE_CHAT_DAY_THRESHOLD,
    TIMELINE_ROW_CAP,
    TOOL_CALL_ROW_CAP,
    ReportModel,
)
from aitrace.report.volume import render_prompts_volume

_SPEC = importlib.util.spec_from_file_location("report_sample", Path(__file__).with_name("sample.py"))
assert _SPEC is not None and _SPEC.loader is not None
sample = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sample)

N_USER = 5000
SESSIONS = 50
FLAG_EVERY = 500
N_INSTRUCTIONS = 30
N_CALLS = 300


def _clock(i: int) -> str:
    return f"{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}"


def _big_model(lang: str = "ko") -> ReportModel:
    base = sample.make_model(lang)
    queries: list[dict[str, Any]] = []
    meta: dict[str, dict[str, Any]] = {}
    timeline: list[dict[str, Any]] = []
    chat: list[tuple[str | None, str | None, str] | None] = []
    for i in range(N_USER):
        session = f"s{i % SESSIONS:03d}"
        machine = "node-a" if (i % SESSIONS) < SESSIONS // 2 else "node-b"
        text = f"synthetic prompt {i} " + "x" * 900
        flagged = i % FLAG_EVERY == 0
        if flagged:
            text += " bypass the password check"
        row = sample._query(lang, "Hermes", session, "user", _clock(i), text, f"/synthetic/{machine}.md")
        row["artifact_id"] = f"u{i}"
        row["ts_utc"] = f"2026-03-01T{_clock(i)}Z"
        queries.append(row)
        meta[f"u{i}"] = {"machine": machine, "channel": "cli", "flags": ["TASK-SECURITY"] if flagged else []}
        event = sample._event(lang, f"2026-03-01 {_clock(i)} (+09:00)", "chat", "ai_activity")
        event["artifact_id"] = f"u{i}"
        timeline.append(event)
        chat.append(("Hermes", session, "u"))
    for i in range(N_USER // 2):
        row = sample._query(lang, "Hermes", f"s{i % SESSIONS:03d}", "assistant", _clock(i), f"answer {i}")
        row["artifact_id"] = f"a{i}"
        row["ts_utc"] = f"2026-03-01T{_clock(i)}Z"
        queries.append(row)
    queries.sort(key=lambda r: r["ts_utc"])
    calls: list[dict[str, Any]] = []
    for i in range(N_CALLS):
        call = sample._query(lang, "Hermes", f"s{i % SESSIONS:03d}", "assistant", _clock(i), f"call {i}")
        name = "Write" if i % 3 == 0 else "Read"
        call.update(
            role="tool_call", role_label="tool", call_name=name, artifact_id=f"c{i}", text=f"{name} file {i}"
        )
        call["ts_utc"] = f"2026-03-01T{_clock(i)}Z"
        calls.append(call)
    instructions = []
    for i in range(N_INSTRUCTIONS):
        instructions.append(
            {
                "ts_utc": f"2026-03-01T00:00:{i:02d}Z",
                "ts_local": f"2026-03-01 00:00:{i:02d} (+09:00)",
                "tool": "Hermes",
                "session": None,
                "role": "instruction",
                "role_label": "instruction",
                "text": f"<script>rule {i}</script> " + "persona " * 400,
                "source": f"/synthetic/prompts/{i}.md",
                "artifact_id": f"p{i}",
            }
        )
        meta[f"p{i}"] = {"machine": "node-a", "kind": "instruction", "last_local": None}
    timeline.append(sample._event(lang, "2026-03-01 23:59:00 (+09:00)", "deleted", "file_deleted"))
    chat.append(None)
    return replace(
        base,
        ai_queries=queries,
        tool_calls=calls,
        instructions=instructions,
        timeline=timeline,
        timeline_relevant=(True,) * len(timeline),
        timeline_text=tuple(r["summary"] for r in timeline),
        timeline_chat=tuple(chat),
        query_meta=meta,
    )


def _section(doc: Document, level: int, title: str) -> list[Block]:
    start = next(
        i for i, b in enumerate(doc.blocks) if isinstance(b, Heading) and b.level == level and b.text == title
    )
    out: list[Block] = []
    for block in doc.blocks[start + 1 :]:
        if isinstance(block, Heading) and block.level <= level:
            break
        out.append(block)
    return out


def _rows(blocks: list[Block]) -> list[tuple[str, ...]]:
    return [row for b in blocks if isinstance(b, Table) for row in b.rows]


@pytest.fixture(scope="module")
def big() -> ReportModel:
    return _big_model()


def test_question_excerpts_are_capped_and_keep_flagged_questions(big: ReportModel) -> None:
    blocks = _section(build_document(big), 2, "사용자 직접 질의")
    rows = [row for b in blocks if isinstance(b, Table) and b.headers[-1] == "질의" for row in b.rows]
    assert len(rows) <= QUESTION_EXCERPT_CAP
    assert all(len(row[2]) <= QUESTION_EXCERPT_CHARS + 1 for row in rows)
    shown = "\n".join(row[2] for row in rows)
    for i in range(0, N_USER, FLAG_EVERY):
        assert f"synthetic prompt {i} " in shown
    note = next(b.text for b in blocks if isinstance(b, Para))
    assert f"{N_USER:,}" in note and "report/questions.html" in note and "questions.csv" in note


def test_counts_table_has_one_row_per_session(big: ReportModel) -> None:
    rows = _rows(_section(build_document(big), 2, "수량표"))
    assert len(rows) == SESSIONS
    assert sum(int(r[4]) for r in rows) == N_USER
    assert sum(int(r[6]) for r in rows) == N_CALLS
    assert {r[1] for r in rows} == {"node-a", "node-b"}


def test_instructions_one_row_each_with_short_excerpt(big: ReportModel) -> None:
    rows = _rows(_section(build_document(big), 2, "시스템 지시문·페르소나·규칙"))
    assert len(rows) == N_INSTRUCTIONS
    assert all(len(row[5]) <= EXCERPT_CHARS + 1 and len(row[4]) == 12 for row in rows)


def test_tool_call_rows_capped_to_risky_calls(big: ReportModel) -> None:
    rows = _rows(_section(build_document(big), 2, "AI 응답 및 도구 실행"))
    assert len(rows) == TOOL_CALL_ROW_CAP
    assert all("Write" in row[3] for row in rows)


def test_timeline_aggregates_chat_per_session_and_caps_rows(big: ReportModel) -> None:
    rows = _rows(_section(build_document(big), 1, "타임라인"))
    assert len(rows) <= TIMELINE_ROW_CAP + 1
    aggregated = [r for r in rows if "세션 s000" in r[3]]
    assert len(aggregated) == 1
    assert "사용자 입력 100건, AI 응답 0건, 도구 실행 0건" in aggregated[0][3]
    assert any("deleted" in r[3] for r in rows)
    assert TIMELINE_CHAT_DAY_THRESHOLD < N_USER


def test_small_day_keeps_individual_rows() -> None:
    days = sample.make_model("ko").timeline_days(100)
    assert not any(r.get("aggregated") for _, rows in days for r in rows)


def test_report_json_keeps_complete_data_and_main_html_stays_small(big: ReportModel) -> None:
    data = big.to_dict()
    assert len(data["ai_queries"]) == N_USER + N_USER // 2
    assert len(data["instructions"]) == N_INSTRUCTIONS
    assert set(data["ai_queries"][0]) == set(sample.make_model("ko").ai_queries[0])
    assert len(render_html_string(big)) < 5_000_000


def test_prompts_volume_has_every_message_escaped_with_toc(big: ReportModel, tmp_path: Path) -> None:
    text = render_prompts_volume(big, tmp_path / "prompts.html").read_text(encoding="utf-8")
    assert text.count('<div class="entry">') == N_USER + N_USER // 2 + N_INSTRUCTIONS + len(
        big.generated_files
    )
    assert "<script" not in text
    assert 'href="#generated"' in text and 'id="generated"' in text
    assert "&lt;script&gt;rule 0" in text
    assert 'href="#t1m1"' in text and 'id="t1m1"' in text and 'id="t1m1s1"' in text
    assert f"synthetic prompt {N_USER - 1} " in text


def test_days_emptied_by_the_row_cap_are_not_rendered() -> None:
    model = sample.make_model("ko")
    view = model.timeline_view(1)
    assert all(rows for _, rows in view.days)
    assert view.omitted == 3
    build_document(model, 1)
