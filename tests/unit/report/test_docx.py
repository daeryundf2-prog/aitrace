from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, cast

from docx import Document
from docx.document import Document as DocumentObject
from docx.enum.section import WD_ORIENT
from docx.oxml.ns import qn
from docx.styles.style import ParagraphStyle

from aitrace.report.docx import render_docx

_SPEC = importlib.util.spec_from_file_location("report_sample", Path(__file__).with_name("sample.py"))
assert _SPEC is not None and _SPEC.loader is not None
sample = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sample)


def _fill(cell: Any) -> str | None:
    props = cell._tc.tcPr
    shading = props.find(qn("w:shd")) if props is not None else None
    return None if shading is None else shading.get(qn("w:fill"))


def _style(doc: DocumentObject, name: str) -> ParagraphStyle:
    return cast(ParagraphStyle, doc.styles[name])


def _open(tmp_path: Path, lang: str = "ko") -> DocumentObject:
    path = tmp_path / "report.docx"
    render_docx(sample.make_model(lang), path)
    return Document(str(path))


def test_control_characters_in_evidence_text_do_not_break_docx(tmp_path: Path) -> None:
    path = tmp_path / "report.docx"
    render_docx(sample.make_model("ko", prompt="\x1b[31m경쟁사\x00 제안서\x07 요약"), path)
    text = "\n".join(
        cell.text for table in Document(str(path)).tables for row in table.rows for cell in row.cells
    )
    assert "\ufffd[31m경쟁사\ufffd 제안서\ufffd 요약" in text


def test_chapter_headings_follow_the_required_order(tmp_path: Path) -> None:
    doc = _open(tmp_path)
    headings = [p.text for p in doc.paragraphs if p.style is not None and p.style.name == "Heading 1"]
    assert headings == sample.KO_CHAPTERS


def test_timeline_and_annex_one_sections_are_landscape(tmp_path: Path) -> None:
    doc = _open(tmp_path)
    orientations = [s.orientation for s in doc.sections]
    assert orientations == [
        WD_ORIENT.PORTRAIT,
        WD_ORIENT.LANDSCAPE,
        WD_ORIENT.PORTRAIT,
        WD_ORIENT.LANDSCAPE,
        WD_ORIENT.PORTRAIT,
    ]
    for section in doc.sections:
        assert section.left_margin is not None and abs(section.left_margin.mm - 25) < 0.1
        assert section.top_margin is not None and abs(section.top_margin.mm - 25) < 0.1


def test_page_header_and_footer(tmp_path: Path) -> None:
    doc = _open(tmp_path)
    first = doc.sections[0]
    assert first.header.paragraphs[0].text == "문서번호 T-1-01 | 대외비"
    footer = first.footer._element.xml
    assert "PAGE" in footer and "NUMPAGES" in footer
    assert all(not s.different_first_page_header_footer for s in doc.sections[1:])
    assert first.different_first_page_header_footer


def test_tables_are_plain_grids_with_gray_header_row(tmp_path: Path) -> None:
    doc = _open(tmp_path)
    assert doc.tables
    for table in doc.tables:
        assert table.style is not None and table.style.name == "Table Grid"
    body_tables = doc.tables[1:]
    for table in body_tables:
        assert {_fill(cell) for cell in table.rows[0].cells} == {"EFEFEF"}
        for row in table.rows[1:]:
            for cell in row.cells:
                assert _fill(cell) is None
                assert not any(run.bold for p in cell.paragraphs for run in p.runs)


def test_serif_body_and_black_headings(tmp_path: Path) -> None:
    doc = _open(tmp_path)
    normal = _style(doc, "Normal")
    assert normal.font.size is not None and normal.font.size.pt == 10.5
    fonts = normal.element.rPr.rFonts
    assert fonts.get(qn("w:eastAsia")) == "NanumMyeongjo"
    for level in (1, 2, 3, 4):
        style = _style(doc, f"Heading {level}")
        assert style.font.bold
        assert style.font.color.rgb is not None and str(style.font.color.rgb) == "000000"


def test_recovered_prompt_and_gray_header_text(tmp_path: Path) -> None:
    doc = _open(tmp_path)
    cells = [cell.text for table in doc.tables for row in table.rows for cell in row.cells]
    assert "경쟁사 제안서를 요약해줘" in cells
    run = doc.sections[0].header.paragraphs[0].runs[0]
    assert run.font.color.rgb is not None and str(run.font.color.rgb) == "808080"


def test_english_docx_headings(tmp_path: Path) -> None:
    doc = _open(tmp_path, "en")
    headings = [p.text for p in doc.paragraphs if p.style is not None and p.style.name == "Heading 1"]
    assert headings[0] == "Chapter 1 Overview" and headings[-1] == "Annex 3 Signature"
