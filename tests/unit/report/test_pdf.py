from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pypdfium2 as pdfium

from aitrace.report.i18n import STRINGS
from aitrace.report.model import COLUMNS, SECTION_KEYS, ReportModel
from aitrace.report.pdf import render_pdf

CASE_NUMBER = "AI-2026-001"
APPENDIX_E_KO_HEADINGS = [STRINGS["ko"][f"section.{key}"] for key in SECTION_KEYS if key != "run"]


def _model(queries: list[dict[str, Any]] | None = None) -> ReportModel:
    return ReportModel(
        case={
            "id": "case-1",
            "name": "김철수 사건",
            "number": CASE_NUMBER,
            "examiner": "홍길동",
            "organisation": "포렌식 연구소",
            "timezone": "Asia/Seoul",
            "lang": "ko",
            "tool_version": "0.1.0",
            "notes": "비고 테스트",
            "handling_notice": "대외비 - 개인정보 포함 / Confidential - contains personal data",
        },
        evidence=[
            {
                "id": "ev-1",
                "path": "/images/win.E01",
                "kind": "e01",
                "size": 10,
                "acquisition_hashes": {"md5": "aa"},
                "media_sha256": "bb",
                "verification_label": "일치",
            }
        ],
        tools={"aitrace_version": "0.1.0", "python": "3.12", "dissect": {"dissect.target": "3.25.1"}},
        methodology={
            "paragraphs": ["증거물은 읽기 전용으로 열람하였다."],
            "standards_intro": "적용 기준",
            "standards": ["ISO/IEC 27037"],
            "tool_validation": "도구 검증",
        },
        summary=[{"id": "Q1", "question": "Q1", "bullets": ["AI 도구 사용 발견 1건"]}],
        ai_tools=[],
        ai_queries=queries or [],
        file_lifecycle=[],
        exfil=[],
        attribution=[],
        timeline=[],
        exports=[],
        coverage={
            "plugin_runs": [
                {
                    "name": "browser",
                    "version": "1",
                    "status": "ok",
                    "records": 3,
                    "warnings": 0,
                    "error": None,
                }
            ],
            "parse_warnings": [],
            "not_decoded": [],
            "findings": [],
        },
        limitations=["한계 테스트"],
        custody=[{"seq": 1, "actor": "examiner", "action": "open", "detail": "read-only"}],
        signature={"examiner": "홍길동"},
        run={},
    )


def _page_texts(path: Path) -> list[str]:
    doc = pdfium.PdfDocument(path)
    try:
        return [doc[i].get_textpage().get_text_range() for i in range(len(doc))]
    finally:
        doc.close()


def test_renders_korean_report_with_case_number_and_multiple_pages(tmp_path: Path) -> None:
    out = render_pdf(_model(), tmp_path / "report.pdf")

    pages = _page_texts(out)
    assert len(pages) >= 3
    text = "".join(pages)
    assert "증거" in text
    assert CASE_NUMBER in text


def test_no_non_final_page_is_nearly_blank(tmp_path: Path) -> None:
    out = render_pdf(_model(), tmp_path / "report.pdf")

    doc = pdfium.PdfDocument(out)
    try:
        for index in range(len(doc) - 1):
            histogram = doc[index].render(scale=1).to_pil().convert("L").histogram()
            white_ratio = sum(histogram[250:]) / sum(histogram)
            assert white_ratio <= 0.999, f"page {index + 1} is {white_ratio:.4%} white"
    finally:
        doc.close()


def test_every_appendix_e_korean_heading_is_extractable(tmp_path: Path) -> None:
    out = render_pdf(_model(), tmp_path / "report.pdf")

    text = "".join("".join(_page_texts(out)).split())
    for heading in APPENDIX_E_KO_HEADINGS:
        assert "".join(heading.split()) in text, heading


def test_table_cell_taller_than_a_page_renders_without_truncation(tmp_path: Path) -> None:
    unit = "한글 evidence text 증거 "
    long_text = (unit * 400)[:6000]
    assert len(long_text) == 6000
    model = _model()
    model.ai_queries.append({"tool": "Claude Code", "role_label": "사용자", "text": long_text})

    out = render_pdf(model, tmp_path / "tall.pdf")

    assert out.is_file()
    doc = pdfium.PdfDocument(out)
    try:
        assert len(doc) >= 3
    finally:
        doc.close()
    page_chrome = re.compile(rf"사건번호/Casenumber:{CASE_NUMBER}page\d+/\d+|aitracev[\d.]+-page\d+/\d+")
    text = page_chrome.sub("", "".join("".join(_page_texts(out)).split()))
    assert "".join(long_text.split()) in text


def test_single_5000_char_message_renders_without_exception(tmp_path: Path) -> None:
    long_text = "한글" * 2500
    queries = [{"tool": "Claude Code", "session_id": "s1", "role": "user", "text": long_text}]

    out = render_pdf(_model(queries), tmp_path / "long.pdf")

    assert len(_page_texts(out)) >= 3


SHA = "a" * 64


def _rich_model() -> ReportModel:
    model = _model()
    model.ai_tools.append(
        {
            "kind_label": "CLI",
            "tool": "Claude Code",
            "users": ["alice"],
            "first_seen_local": "2026-01-01 09:00:00",
            "last_seen_local": "2026-01-02 09:00:00",
            "evidence_count": 3,
        }
    )
    model.ai_queries.append(
        {
            "ts_local": "2026-01-01 09:00:00",
            "tool": "Claude Code",
            "role_label": "사용자",
            "text": "민감 파일 정리 방법",
            "source_name": "history.jsonl",
        }
    )
    model.timeline.append(
        {
            "ts_local": "2026-01-01 09:00:00",
            "category_label": "AI 활동",
            "actor_label": "사람",
            "user": "alice",
            "summary": "프롬프트 입력",
            "source_path": "/Users/alice/.claude/history.jsonl",
        }
    )
    model.exports.append({"export_path": "export/files/C/a.txt", "size": 5, "sha256": SHA})
    return model


def _headers(key: str) -> list[str]:
    return [STRINGS["ko"][label] for _, label, _ in COLUMNS[key]]


def test_table_headers_come_from_columns_labels_in_ko(tmp_path: Path) -> None:
    out = render_pdf(_rich_model(), tmp_path / "report.pdf")

    text = "".join("".join(_page_texts(out)).split())
    for key in ("ai_tools", "ai_queries", "timeline", "exports"):
        for header in _headers(key):
            assert "".join(header.split()) in text, (key, header)


def test_no_raw_json_or_internal_keys_in_text(tmp_path: Path) -> None:
    model = _rich_model()
    model.coverage = {
        "plugin_runs": [{"name": "p", "records": {"a": 1}}],
        "parse_warnings": [],
        "not_decoded": [],
    }
    out = render_pdf(model, tmp_path / "report.pdf")

    lines = [line.strip() for page in _page_texts(out) for line in page.splitlines() if line.strip()]
    assert not [line for line in lines if line.startswith(("{", "["))]
    text = "".join(lines)
    assert "artifact_id" not in text
    assert "kind_label" not in text


def test_timeline_and_exports_pages_are_landscape_others_portrait(tmp_path: Path) -> None:
    out = render_pdf(_rich_model(), tmp_path / "report.pdf")

    doc = pdfium.PdfDocument(out)
    try:
        landscape_text = []
        for index in range(len(doc)):
            width, height = doc[index].get_size()
            page_text = "".join(doc[index].get_textpage().get_text_range().split())
            if width > height:
                landscape_text.append(page_text)
        joined = "".join(landscape_text)
        assert "".join(STRINGS["ko"]["section.timeline"].split()) in joined
        assert "".join(STRINGS["ko"]["section.exports"].split()) in joined
    finally:
        doc.close()


def test_long_hash_is_present_unbroken_in_text(tmp_path: Path) -> None:
    out = render_pdf(_rich_model(), tmp_path / "report.pdf")

    text = "".join("".join(_page_texts(out)).split())
    assert SHA in text
