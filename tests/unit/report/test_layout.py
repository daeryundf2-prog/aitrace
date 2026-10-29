from __future__ import annotations

import importlib.util
from pathlib import Path

from aitrace.report.layout import Block, Document, Heading, Para, Table, build_document, chapter_outline
from aitrace.report.model import GENERATED_ROW_CAP

_SPEC = importlib.util.spec_from_file_location("report_sample", Path(__file__).with_name("sample.py"))
assert _SPEC is not None and _SPEC.loader is not None
sample = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sample)


def _between(doc: Document, level: int, title: str) -> list[Block]:
    start = next(
        i for i, b in enumerate(doc.blocks) if isinstance(b, Heading) and b.level == level and b.text == title
    )
    out: list[Block] = []
    for block in doc.blocks[start + 1 :]:
        if isinstance(block, Heading) and block.level <= level:
            break
        out.append(block)
    return out


def _paragraphs(blocks: list[Block]) -> list[str]:
    return [b.text for b in blocks if isinstance(b, Para)]


def _plain_text(doc: Document) -> str:
    parts = [doc.title, doc.header_text, doc.notice]
    parts += [f"{k} {v}" for k, v in doc.cover]
    for block in doc.blocks:
        if isinstance(block, Heading):
            parts.append(f"{block.number} {block.text}")
        elif isinstance(block, Para):
            parts.append(block.text)
        elif isinstance(block, Table):
            parts += [block.caption, *block.headers]
            parts += [cell for row in block.rows for i, cell in enumerate(row) if i not in block.raw]
    return "\n".join(parts)


def test_chapter_order_ko() -> None:
    doc = build_document(sample.make_model("ko"))
    level1 = [f"{b.number} {b.text}" for b in doc.blocks if isinstance(b, Heading) and b.level == 1]
    assert level1 == sample.KO_CHAPTERS


def test_chapter_order_en() -> None:
    doc = build_document(sample.make_model("en"))
    level1 = [f"{b.number} {b.text}" for b in doc.blocks if isinstance(b, Heading) and b.level == 1]
    assert level1[0] == "Chapter 1 Overview"
    assert level1[-1] == "Annex 3 Signature"
    assert len(level1) == 12


def test_cover_fields_and_header() -> None:
    doc = build_document(sample.make_model("ko"))
    cover = dict(doc.cover)
    assert cover["사건번호"] == "T-1"
    assert cover["문서번호"] == "T-1-01"
    assert cover["감정·분석 대상"] == "win.E01"
    assert cover["의뢰처"] == "포렌식 연구소"
    assert cover["작성자"] == "홍길동"
    assert cover["작성일"] == "2026년 3월 2일"
    assert "대외비" in doc.notice
    assert doc.header_text == "문서번호 T-1-01 | 대외비"


def test_overview_sections() -> None:
    outline = chapter_outline(sample.make_model("ko"))
    assert outline[0]["no"] == "제1장" and outline[0]["title"] == "개요"
    assert [s["title"] for s in outline[0]["sections"]] == [
        "의뢰 및 분석 대상",
        "증거물 및 무결성 검증",
        "분석 도구 및 환경",
        "분석 방법",
    ]
    assert [c["landscape"] for c in outline] == [
        False,
        False,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        True,
        False,
        False,
    ]


def test_summary_and_opinion_statements_cite_their_basis() -> None:
    doc = build_document(sample.make_model("ko"))
    for title in ("분석결과 요약", "감정(분석) 의견"):
        lines = _paragraphs(_between(doc, 1, title))
        assert 5 <= len(lines) <= 10
        for i, line in enumerate(lines, start=1):
            assert line.startswith(f"{i}. ")
            assert "(근거: 제" in line
            assert not line.endswith("!") and "?" not in line


def test_prompts_chapter_counts_by_session_and_shows_all_questions_when_small() -> None:
    doc = build_document(sample.make_model("ko"))
    counts = [b for b in _between(doc, 2, "수량표") if isinstance(b, Table)]
    assert len(counts) == 1
    assert counts[0].headers[:4] == ("도구", "머신/프로필", "세션", "기간(현지)")
    assert {row[0] for row in counts[0].rows} == {"Claude Code", "Codex"}
    assert {row[2] for row in counts[0].rows} == {"s0", "s1", "s2"}
    user = _between(doc, 2, "사용자 직접 입력")
    assert "3건" in _paragraphs(user)[0] and "report/questions.html" in _paragraphs(user)[0]
    tables = [b for b in user if isinstance(b, Table)]
    assert tables[0].caption == "정제 기준 및 결과"
    assert dict(tables[0].rows)["사람이 직접 입력한 메시지"] == "3"
    excerpt = tables[-1]
    assert excerpt.headers == ("일시(현지)", "머신·채널", "입력 내용")
    assert sorted(row[2] for row in excerpt.rows) == sorted(
        ["이른 세션 질의", "경쟁사 제안서를 요약해줘", "다른 도구 질의"]
    )
    assert excerpt.raw == frozenset({2})


def test_system_and_assistant_sections_include_instructions_and_tool_calls() -> None:
    doc = build_document(sample.make_model("ko"))
    system = [
        row for b in _between(doc, 2, "시스템 지시문·페르소나·규칙") if isinstance(b, Table) for row in b.rows
    ]
    assert sorted(row[5] for row in system) == sorted(
        ["당신은 보조 개발자임", "Claude Code의 지시문 관련 설정으로 확인됨: CLAUDE.md"]
    )
    assert all(len(row[4]) == 12 for row in system)
    assistant = [
        row for b in _between(doc, 2, "AI 응답 및 도구 실행") if isinstance(b, Table) for row in b.rows
    ]
    assert sorted(row[2] for row in assistant) == ["AI 응답", "도구 호출"]


def test_timeline_grouped_by_day_with_undated_last() -> None:
    doc = build_document(sample.make_model("ko"))
    days = [b.text for b in _between(doc, 1, "타임라인") if isinstance(b, Heading)]
    assert days == ["2026-03-01 (2건)", "2026-03-02 (1건)", "일자 미상 (1건)"]
    first = next(b for b in _between(doc, 1, "타임라인") if isinstance(b, Table))
    assert first.headers == ("시각", "구분", "행위자", "내용", "출처")
    assert first.rows[0][0] == "18:00:00 (+09:00)"


def test_generated_files_chapter_lists_origin() -> None:
    doc = build_document(sample.make_model("ko"))
    blocks = _between(doc, 1, "생성물")
    assert any(isinstance(b, Heading) and b.text == "/Users/kim/proposal.md" for b in blocks)
    table = next(b for b in blocks if isinstance(b, Table))
    labels = [row[0] for row in table.rows]
    assert labels == ["판정", "신뢰도", "근거 신호", "생성 경위", "한계"]
    assert "도구 호출: Claude Code Write" in table.rows[3][1]


def test_transfer_channel_arrow_is_written_out_in_words() -> None:
    doc = build_document(sample.make_model("ko"))
    cells = [
        cell
        for b in _between(doc, 1, "반출·원격·전송 경로")
        if isinstance(b, Table)
        for row in b.rows
        for cell in row
    ]
    assert "scp, 대상 203.0.113.10" in cells
    english = build_document(sample.make_model("en"))
    cells = [
        cell
        for b in _between(english, 1, "Export, Remote Access and Transfer Paths")
        if isinstance(b, Table)
        for row in b.rows
        for cell in row
    ]
    assert "scp, destination 203.0.113.10" in cells


def test_machine_text_is_localized() -> None:
    text = _plain_text(build_document(sample.make_model("ko")))
    assert "encrypted_not_decoded" not in text
    assert "case_opened" not in text and "사건 개시" in text
    assert "→" not in text


def test_no_banned_expressions_in_ko_document() -> None:
    assert sample.find_banned(_plain_text(build_document(sample.make_model("ko")))) == []


def test_banned_scanner_detects_the_listed_patterns() -> None:
    for bad in (
        "핵심 결과",
        "전수 조사",
        "좋음!",
        "①",
        "\u2605",
        "\U0001f600",
        "매우 높음",
        "File created: /a",
        "Amcache: x recorded",
    ):
        assert sample.find_banned(bad), bad
    assert sample.find_banned("해시 검증 결과는 일치함") == []


def _generated_row(i: int) -> dict[str, object]:
    return {
        "attribution_id": f"at{i}",
        "subject": f"/c/cron/output/ja/out-{i:04d}.md",
        "verdict": "ai_generated",
        "verdict_label": "AI 생성",
        "confidence": 0.9,
        "confidence_display": "0.90 (강함)",
        "signals_summary": "",
        "origin": [f"origin {i}"],
        "limitations_display": ["공통 한계"],
        "output_kind": "cron_output",
        "tool": "Hermes Agent",
        "ts_utc": f"2026-10-01T00:{i // 60:02d}:{i % 60:02d}Z",
        "ts_local": f"2026-10-01 09:{i // 60:02d}:{i % 60:02d} (+09:00)",
        "basis": f"/c/cron/output/ja/out-{i:04d}.md (file)",
    }


def test_generated_chapter_caps_rows_to_most_recent_and_counts_every_job() -> None:
    model = sample.make_model("ko")
    total = GENERATED_ROW_CAP + 30
    model.generated_files = [_generated_row(i) for i in range(total)]
    job = {"job_id": "ja", "job_name": "daily", "mode": "agent", "first_local": "a", "last_local": "b"}
    counts = {"outputs": 3, "agent_outputs": 2, "script_outputs": 0, "silent": 1, "failed": 0, "other": 0}
    script = {"job_id": "jb", "job_name": "probe", "mode": "script", "first_local": "a", "last_local": "a"}
    script_counts = {
        "outputs": 4,
        "agent_outputs": 0,
        "script_outputs": 3,
        "silent": 1,
        "failed": 1,
        "other": 0,
    }
    model.generated_jobs = [job | counts, script | script_counts]
    blocks = _between(build_document(model), 1, "생성물")
    tables = [b for b in blocks if isinstance(b, Table)]
    jobs = next(tb for tb in tables if tb.headers[0] == "작업명 (ID)")
    assert [row[0] for row in jobs.rows] == ["daily (ja)", "probe (jb)", "합계"]
    assert jobs.rows[-1][2:8] == ("7", "2", "3", "2", "0", "1")
    listing = next(tb for tb in tables if tb.headers[0] == "시각(현지)")
    assert len(listing.rows) == GENERATED_ROW_CAP
    assert listing.rows[0][0] == _generated_row(30)["ts_local"]
    assert listing.rows[-1][0] == _generated_row(total - 1)["ts_local"]
    note = " ".join(_paragraphs(blocks))
    assert "report/prompts.html" in note and "report/csv/attributions.csv" in note
    assert "공통 한계" in note


def test_instruction_section_counts_skills_and_lists_persona_rows() -> None:
    model = sample.make_model("ko")
    base = dict(model.instructions[0])
    skills = [
        dict(base, artifact_id=f"sk{i}", source=f"/02_skills/skills/s{i}/SKILL.md", text=f"skill {i}")
        for i in range(3)
    ]
    persona = dict(base, artifact_id="soul", source="/01/hermes_dot/SOUL.md", text="persona text")
    model.instructions = [*skills, persona]
    model.query_meta.update({f"sk{i}": {"source_kind": "skill"} for i in range(3)})
    model.query_meta["soul"] = {"source_kind": "persona"}
    blocks = _between(build_document(model), 2, "시스템 지시문·페르소나·규칙")
    tables = [b for b in blocks if isinstance(b, Table)]
    counts = next(tb for tb in tables if "상위 디렉터리" in tb.headers)
    assert [(row[1], row[2], row[3]) for row in counts.rows] == [("스킬(SKILL.md)", "/02_skills/skills", "3")]
    listed = [row[5] for tb in tables if "상위 디렉터리" not in tb.headers for row in tb.rows]
    assert "persona text" in listed and not any(text.startswith("skill ") for text in listed)
    assert any("report/prompts.html" in p for p in _paragraphs(blocks))


def test_prompts_from_one_file_sit_under_a_file_heading_without_repeating_the_path() -> None:
    model = sample.make_model("ko")
    base = dict(model.instructions[0])
    model.instructions = [
        dict(base, artifact_id=f"sp{i}", source="/03/system_prompts.md", text=f"prompt {i}")
        for i in range(120)
    ]
    model.query_meta.update({f"sp{i}": {"source_kind": "export_system_prompt"} for i in range(120)})
    blocks = _between(build_document(model), 2, "시스템 지시문·페르소나·규칙")
    heads = [b.text for b in blocks if isinstance(b, Heading) and b.level == 3]
    assert any("/03/system_prompts.md (120건)" in h for h in heads)
    table = next(b for b in blocks if isinstance(b, Table) and len(b.rows) >= 120)
    assert len(table.headers) == 4
    assert not any("/03/system_prompts.md" in cell or "\u3003" in cell for row in table.rows for cell in row)


def test_opinion_does_not_say_records_exist_when_there_are_none() -> None:
    model = sample.make_model("ko")
    model.file_lifecycle = []
    model.exfil = []
    blocks = _chapter_blocks(build_document(model), "감정(분석) 의견")
    text = " ".join(b.text for b in blocks if isinstance(b, Para))
    assert "확인되지 않음" in text and "기록이 존재한다는 사실만으로" not in text


def _chapter_blocks(doc: Document, title: str) -> list[Block]:
    start = next(
        i for i, b in enumerate(doc.blocks) if isinstance(b, Heading) and b.level == 1 and b.text == title
    )
    out: list[Block] = []
    for block in doc.blocks[start + 1 :]:
        if isinstance(block, Heading) and block.level == 1:
            break
        out.append(block)
    return out
