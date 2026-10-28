from __future__ import annotations

import importlib.util
from pathlib import Path

from aitrace.report.layout import Block, Document, Heading, Para, Table, build_document, chapter_outline

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
    assert [c["landscape"] for c in outline] == [False, False, False, False, True, False, False, False, False, True, False, False]


def test_summary_and_opinion_statements_cite_their_basis() -> None:
    doc = build_document(sample.make_model("ko"))
    for title in ("분석결과 요약", "감정(분석) 의견"):
        lines = _paragraphs(_between(doc, 1, title))
        assert 5 <= len(lines) <= 10
        for i, line in enumerate(lines, start=1):
            assert line.startswith(f"{i}. ")
            assert "(근거: 제" in line
            assert not line.endswith("!") and "?" not in line


def test_prompts_grouped_by_tool_then_session_in_time_order() -> None:
    doc = build_document(sample.make_model("ko"))
    user = _between(doc, 2, "사용자 입력")
    tools = [b.text for b in user if isinstance(b, Heading) and b.level == 3]
    sessions = [b.text for b in user if isinstance(b, Heading) and b.level == 4]
    assert tools == ["Claude Code", "Codex"]
    assert sessions == ["세션 s0", "세션 s1", "세션 s2"]
    tables = [b for b in user if isinstance(b, Table)]
    assert [row[2] for t in tables for row in t.rows] == ["이른 세션 질의", "경쟁사 제안서를 요약해줘", "다른 도구 질의"]
    assert tables[0].headers == ("시각(현지)", "구분", "원문", "출처 경로")
    assert tables[0].raw == frozenset({2})


def test_system_and_assistant_sections_include_instructions_and_tool_calls() -> None:
    doc = build_document(sample.make_model("ko"))
    system = [row for b in _between(doc, 2, "시스템 지시문·페르소나·규칙") if isinstance(b, Table) for row in b.rows]
    assert [row[2] for row in system] == [
        "당신은 보조 개발자임",
        "Claude Code의 지시문 관련 설정으로 확인됨: CLAUDE.md",
    ]
    assistant = [row for b in _between(doc, 2, "AI 응답 및 도구 실행") if isinstance(b, Table) for row in b.rows]
    assert [row[1] for row in assistant] == ["AI 응답", "도구 호출"]


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
    cells = [cell for b in _between(doc, 1, "반출·원격·전송 경로") if isinstance(b, Table) for row in b.rows for cell in row]
    assert "scp, 대상 203.0.113.10" in cells
    english = build_document(sample.make_model("en"))
    cells = [cell for b in _between(english, 1, "Export, Remote Access and Transfer Paths") if isinstance(b, Table) for row in b.rows for cell in row]
    assert "scp, destination 203.0.113.10" in cells


def test_machine_text_is_localized() -> None:
    text = _plain_text(build_document(sample.make_model("ko")))
    assert "encrypted_not_decoded" not in text
    assert "case_opened" not in text and "사건 개시" in text
    assert "→" not in text


def test_no_banned_expressions_in_ko_document() -> None:
    assert sample.find_banned(_plain_text(build_document(sample.make_model("ko")))) == []


def test_banned_scanner_detects_the_listed_patterns() -> None:
    for bad in ("핵심 결과", "전수 조사", "좋음!", "①", "\u2605", "\U0001f600", "매우 높음", "File created: /a", "Amcache: x recorded"):
        assert sample.find_banned(bad), bad
    assert sample.find_banned("해시 검증 결과는 일치함") == []
