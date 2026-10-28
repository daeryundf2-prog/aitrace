from __future__ import annotations

import html as htmllib
import re
from pathlib import Path
from typing import Any

import pytest

from aitrace.report.html import HTML_SECTIONS, render_html
from aitrace.report.i18n import t
from aitrace.report.model import COLUMNS, ReportModel

XSS = "<script>alert('x')</script>"


def _section(html: str, key: str) -> str:
    start = html.index(f'<section id="sec-{key}"')
    return html[start : html.index("</section>", start)]


def _plain(fragment: str) -> str:
    return htmllib.unescape(re.sub(r"<[^>]+>", "", fragment)).strip()


def _finding(title: str) -> dict[str, Any]:
    return {
        "id": "f1",
        "severity": "high",
        "severity_label": "높음",
        "display_title": title,
        "display_steps": ["2026-03-01 18:00:00 생성", "2026-03-01 18:10:00 삭제"],
        "links_summary": "AI 연관 없음",
        "limitations_display": ["limit one"],
        "title": title,
        "narrative": "n" * 400,
        "confidence": 0.9,
        "band": "strong",
        "rule_id": None,
        "artifact_ids": ["a1"],
        "event_ids": [],
        "limitations": ["limit one"],
        "data": {"k": "값"},
    }


def _model(lang: str = "ko", **overrides: Any) -> ReportModel:
    values: dict[str, Any] = {
        "case": {
            "id": "case1",
            "name": "샘플 사건",
            "number": "T-1",
            "examiner": "QA",
            "organisation": "Lab",
            "timezone": "Asia/Seoul",
            "lang": lang,
            "tool_version": "0.1.0",
            "notes": "",
            "handling_notice": t("handling_notice", lang),
        },
        "evidence": [
            {
                "id": "ev1",
                "kind": "e01",
                "path": "/images/win.E01",
                "size": 10,
                "acquisition_hashes": {"md5": "aa"},
                "media_sha256": "bb",
                "verification_status": "match",
                "verification_label": t("verification.match", lang),
                "limitations": [],
            }
        ],
        "tools": {
            "aitrace_version": "0.1.0",
            "python": "3.12",
            "dissect": {"dissect.target": "3.0"},
            "os": "Darwin",
        },
        "methodology": {
            "paragraphs": [t("methodology.p1", lang)],
            "standards_intro": t("methodology.standards_intro", lang),
            "standards": ["ISO/IEC 27037"],
            "tool_validation": "validated",
        },
        "summary": [{"id": "Q1", "question": t("summary.q1", lang), "bullets": [t("summary.none", lang)]}],
        "ai_tools": [
            {
                "kind": "usage",
                "kind_label": "사용 흔적",
                "users": ["kim", "lee"],
                "first_seen_local": "2026-03-01 18:00:00 +09:00",
                "last_seen_local": "2026-03-02 18:00:00 +09:00",
                "evidence_count": 2,
                "tool": "Claude Code",
                "provider": None,
                "user": "kim",
                "status": None,
                "detail": None,
                "source_path": None,
                "artifact_id": None,
                "finding_id": "f1",
                "title": "Claude Code used",
                "severity": "medium",
                "narrative": "short",
                "data": {},
            }
        ],
        "ai_queries": [
            {
                "ts_utc": "2026-03-01T09:05:00Z",
                "ts_local": "2026-03-01 18:05:00 +09:00",
                "tool": "Claude Code",
                "session": "s1",
                "role": "user",
                "role_label": "사용자",
                "actor": "human",
                "text": "스크립트 작성해줘\nsecond line",
                "source": "/Users/kim/.claude/s1.jsonl",
                "source_name": "s1.jsonl",
                "artifact_id": "a1",
                "fragment": False,
            }
        ],
        "file_lifecycle": [_finding("deleted proposal.md")],
        "exfil": [
            {
                **_finding("gdrive upload"),
                "display_channel": "Google Drive → 203.0.113.10",
                "ts_local": "2026-03-01 18:20:00 +09:00",
                "actor_label": "사람",
                "user": "kim",
                "source_name": "proposal.md",
            }
        ],
        "attribution": [
            {
                "id": "at1",
                "subject": "/Users/kim/proposal.md",
                "verdict": "ai_assisted",
                "verdict_label": "AI 보조 작성",
                "confidence": 0.6,
                "confidence_display": "0.60 (중간)",
                "band": "moderate",
                "signals_summary": "AI 직후 생성 (지지)",
                "limitations_display": ["한계 하나", "한계 둘"],
                "signals": [{"type": "x"}],
                "rationale": "because",
                "subject_artifact_ids": [],
                "limitations": [],
            }
        ],
        "timeline": [
            {
                "ts_utc": "2026-03-01T09:00:00Z",
                "ts_local": "2026-03-01 18:00:00 +09:00",
                "category": "file_modified",
                "category_label": "파일 수정",
                "actor": "unknown",
                "actor_label": "알 수 없음",
                "user": "kim",
                "summary": "modified",
                "source_path": "/Users/kim/proposal.md",
                "artifact_id": "a1",
            }
        ],
        "exports": [
            {
                "export_path": "evidence/a.txt",
                "sha256": "cc",
                "size": 3,
                "source_volume": 0,
                "source_path": "/a.txt",
                "inode": 1,
                "artifact_ids": [],
                "deleted": True,
                "note": None,
            }
        ],
        "coverage": {
            "plugin_runs": [
                {
                    "evidence_id": "ev1",
                    "name": "p",
                    "version": "1",
                    "status": "ok",
                    "records": 1,
                    "warnings": 0,
                    "error": None,
                }
            ],
            "parse_warnings": [],
            "not_decoded": [],
            "findings": [],
        },
        "limitations": ["global limitation"],
        "custody": [],
        "signature": {"examiner": "QA", "organisation": "Lab", "signature": "", "date": ""},
        "run": {
            "created_utc": "2026-03-01T09:00:00Z",
            "custody": [
                {
                    "seq": 1,
                    "ts": "2026-03-01T09:00:00Z",
                    "actor": "QA",
                    "action": "open",
                    "detail": {"mode": "ro"},
                }
            ],
        },
    }
    values.update(overrides)
    return ReportModel(**values)


@pytest.mark.parametrize("lang", ["ko", "en"])
def test_renders_every_section_anchor_and_no_template_leftovers(tmp_path: Path, lang: str) -> None:
    out = render_html(_model(lang), tmp_path / "report" / "report.html")
    html = out.read_text(encoding="utf-8")
    for key in HTML_SECTIONS:
        assert f'id="sec-{key}"' in html
        assert f'href="#sec-{key}"' in html
        assert t(f"section.{key}", lang) in html
    assert "{{" not in html
    assert "{%" not in html
    assert f'<html lang="{lang}">' in html


def test_sections_follow_appendix_e_order(tmp_path: Path) -> None:
    html = render_html(_model(), tmp_path / "r.html").read_text(encoding="utf-8")
    positions = [html.index(f'<section id="sec-{key}"') for key in HTML_SECTIONS]
    assert positions == sorted(positions)


def test_self_contained_with_print_and_responsive_css(tmp_path: Path) -> None:
    html = render_html(_model(), tmp_path / "r.html").read_text(encoding="utf-8")
    assert '"Apple SD Gothic Neo", "Malgun Gothic", "Noto Sans KR", sans-serif' in html
    assert "@page { size: A4" in html
    assert "table-header-group" in html
    assert "overflow-x: auto" in html
    assert "position: sticky" in html
    assert "max-width: 60rem" in html
    assert not re.search(r"<(script|link|img|iframe)\b", html)
    assert "http://" not in html
    assert "https://" not in html
    assert "url(" not in html


def test_script_text_is_escaped(tmp_path: Path) -> None:
    model = _model(
        file_lifecycle=[_finding(XSS)],
        ai_queries=[{**_model().ai_queries[0], "text": XSS * 20}],
        timeline=[{**_model().timeline[0], "summary": XSS}],
    )
    html = render_html(model, tmp_path / "r.html").read_text(encoding="utf-8")
    assert "<script" not in html
    assert "&lt;script&gt;" in html


def test_long_text_goes_into_details_and_multiline_too(tmp_path: Path) -> None:
    long_query = {**_model().ai_queries[0], "text": "n" * 400}
    html = render_html(_model(ai_queries=[long_query]), tmp_path / "r.html").read_text(encoding="utf-8")
    assert "<details><summary>" in html
    assert "n" * 400 in html
    html = render_html(_model(), tmp_path / "r2.html").read_text(encoding="utf-8")
    assert "second line" in html


def test_empty_model_shows_none_lines_and_all_sections(tmp_path: Path) -> None:
    model = _model(
        ai_tools=[],
        ai_queries=[],
        file_lifecycle=[],
        exfil=[],
        attribution=[],
        timeline=[],
        exports=[],
        evidence=[],
        limitations=[],
        run={},
    )
    html = render_html(model, tmp_path / "r.html").read_text(encoding="utf-8")
    for key in HTML_SECTIONS:
        assert f'id="sec-{key}"' in html
    assert t("summary.none", "ko") in html


def test_table_headers_come_from_columns_labels_ko(tmp_path: Path) -> None:
    html = render_html(_model("ko"), tmp_path / "r.html").read_text(encoding="utf-8")
    for key, spec in COLUMNS.items():
        section = _section(html, key)
        headers = [_plain(h) for h in re.findall(r"<th>(.*?)</th>", section, flags=re.DOTALL)]
        assert headers == [t(label, "ko") for _, label, _ in spec], key
        widths = [float(w) for w in re.findall(r'<col style="width: ([0-9.]+)%">', section)]
        total = sum(weight for _, _, weight in spec)
        assert widths == [round(100 * weight / total, 1) for _, _, weight in spec], key


def test_no_cell_is_raw_json_or_internal_key(tmp_path: Path) -> None:
    html = render_html(_model("ko"), tmp_path / "r.html").read_text(encoding="utf-8")
    cells = [_plain(c) for c in re.findall(r"<td[^>]*>(.*?)</td>", html, flags=re.DOTALL)]
    assert cells
    assert all(not c.startswith(("{", "[")) for c in cells)
    assert "mode: ro" in html
    for internal in ("artifact_id", "finding_id", "'mode'", '"k"'):
        assert internal not in html


def test_ids_break_anywhere_and_korean_keeps_words(tmp_path: Path) -> None:
    html = render_html(_model("ko"), tmp_path / "r.html").read_text(encoding="utf-8")
    assert "word-break: keep-all" in html
    assert "overflow-wrap: anywhere" in html
    assert '<td class="id">' in html
    assert html.count('<div class="table-wrap">') == html.count("</table></div>")


def test_appendix_e_headings_in_order_ko_and_en(tmp_path: Path) -> None:
    for lang in ("ko", "en"):
        html = render_html(_model(lang), tmp_path / f"{lang}.html").read_text(encoding="utf-8")
        headings = [_plain(h) for h in re.findall(r"<h2><span class=\"num\">\d+</span>(.*?)</h2>", html)]
        assert headings == [t(f"section.{key}", lang) for key in HTML_SECTIONS]
