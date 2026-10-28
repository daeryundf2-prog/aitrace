from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

from docx import Document as new_document
from docx.document import Document as DocumentObject
from docx.enum.section import WD_ORIENT, WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.opc.oxml import serialize_part_xml
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import qn
from docx.shared import Emu, Mm, Pt, RGBColor
from docx.styles.style import ParagraphStyle
from docx.table import _Row

from aitrace.report.i18n import t
from aitrace.report.layout import Document, Heading, Para, Table, build_document
from aitrace.report.model import TIMELINE_LIMIT_PDF_DOCX, ReportModel

SERIF = "NanumMyeongjo"
SANS = "NanumGothic"
FALLBACK_FONTS = ((SERIF, "Batang"), (SANS, "Malgun Gothic"))
BODY_PT = 10.5
TABLE_PT = 9
HEADER_PT = 8
HEADING_PT = {1: 16, 2: 12, 3: BODY_PT, 4: BODY_PT}
MARGIN_MM = 25
A4_MM = (210, 297)
HEAD_FILL = "EFEFEF"
GRAY = RGBColor(0x80, 0x80, 0x80)
BLACK = RGBColor(0, 0, 0)
# Characters XML 1.0 forbids (C0 controls except tab/LF/CR, lone surrogates, U+FFFE/U+FFFF); evidence text
# can carry them, so they are shown as U+FFFD instead of aborting the DOCX.
_XML_INVALID = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _xml(text: str) -> str:
    return _XML_INVALID.sub("\ufffd", text)


def _set_font(style: ParagraphStyle, name: str, size: float, *, bold: bool = False) -> None:
    fonts = style.element.get_or_add_rPr().get_or_add_rFonts()
    for attr in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
        fonts.attrib.pop(qn(attr), None)
    for slot in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
        fonts.set(qn(slot), name)
    style.font.size = Pt(size)
    style.font.bold = bold
    style.font.color.rgb = BLACK


def _declare_fallback_fonts(doc: DocumentObject) -> None:
    for rel in doc.part.rels.values():
        if not rel.reltype.endswith("/fontTable"):
            continue
        part = rel.target_part
        root = parse_xml(part.blob)
        for name, alternative in FALLBACK_FONTS:
            font = OxmlElement("w:font")
            font.set(qn("w:name"), name)
            alt = OxmlElement("w:altName")
            alt.set(qn("w:val"), alternative)
            font.append(alt)
            root.append(font)
        cast(Any, part)._blob = serialize_part_xml(root)


def _style(doc: DocumentObject, name: str) -> ParagraphStyle:
    return cast(ParagraphStyle, doc.styles[name])


def _apply_styles(doc: DocumentObject) -> None:
    _set_font(_style(doc, "Normal"), SERIF, BODY_PT)
    normal = _style(doc, "Normal").paragraph_format
    normal.space_after = Pt(6)
    normal.line_spacing = 1.5
    for level, size in HEADING_PT.items():
        style = _style(doc, f"Heading {level}")
        _set_font(style, SANS, size, bold=True)
        style.paragraph_format.space_before = Pt(18 if level > 1 else 0)
        style.paragraph_format.space_after = Pt(8)
        style.paragraph_format.keep_with_next = True


def _add_field(paragraph: Any, instruction: str) -> None:
    simple = OxmlElement("w:fldSimple")
    simple.set(qn("w:instr"), instruction)
    run = OxmlElement("w:r")
    text = OxmlElement("w:t")
    text.text = "1"
    run.append(text)
    simple.append(run)
    paragraph._p.append(simple)


def _page_setup(doc: DocumentObject, header_text: str) -> None:
    section = doc.sections[0]
    section.page_width, section.page_height = Mm(A4_MM[0]), Mm(A4_MM[1])
    section.left_margin = section.right_margin = Mm(MARGIN_MM)
    section.top_margin = section.bottom_margin = Mm(MARGIN_MM)
    section.different_first_page_header_footer = True
    head = section.header.paragraphs[0]
    head.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = head.add_run(header_text)
    run.font.size = Pt(HEADER_PT)
    run.font.color.rgb = GRAY
    foot = section.footer.paragraphs[0]
    foot.alignment = WD_ALIGN_PARAGRAPH.CENTER
    foot.add_run("- ")
    _add_field(foot, "PAGE")
    foot.add_run(" / ")
    _add_field(foot, "NUMPAGES")
    foot.add_run(" -")
    for run in foot.runs:
        run.font.size = Pt(TABLE_PT)


def _start_section(doc: DocumentObject, *, landscape: bool) -> None:
    section = doc.add_section(WD_SECTION.NEW_PAGE)
    section.different_first_page_header_footer = False
    wide, narrow = Mm(max(A4_MM)), Mm(min(A4_MM))
    section.orientation = WD_ORIENT.LANDSCAPE if landscape else WD_ORIENT.PORTRAIT
    section.page_width, section.page_height = (wide, narrow) if landscape else (narrow, wide)


def _usable_width(doc: DocumentObject) -> int:
    section = doc.sections[-1]
    return int((section.page_width or 0) - (section.left_margin or 0) - (section.right_margin or 0))


def _shade(cell: Any, fill: str) -> None:
    props = cell._tc.get_or_add_tcPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:val"), "clear")
    shading.set(qn("w:color"), "auto")
    shading.set(qn("w:fill"), fill)
    props.append(shading)


def _repeat_header(row: _Row) -> None:
    marker = OxmlElement("w:tblHeader")
    marker.set(qn("w:val"), "true")
    row._tr.get_or_add_trPr().append(marker)


def _fill(cell: Any, text: str, *, bold: bool = False) -> None:
    paragraph = cell.paragraphs[0]
    paragraph.paragraph_format.space_after = Pt(0)
    paragraph.paragraph_format.line_spacing = 1.15
    run = paragraph.add_run(_xml(text))
    run.font.size = Pt(TABLE_PT)
    run.bold = bold


def _table(doc: DocumentObject, block: Table) -> None:
    headers, rows, weights = block.headers, block.rows, block.weights
    if block.caption:
        note = doc.add_paragraph(_xml(block.caption))
        note.paragraph_format.space_after = Pt(2)
        note.paragraph_format.keep_with_next = True
        note.runs[0].font.size = Pt(TABLE_PT)
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.autofit = False
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    table._tbl.tblPr.append(layout)
    total = sum(weights)
    usable = _usable_width(doc)
    widths = [Emu(int(usable * w / total)) for w in weights]
    for col, width in zip(table.columns, widths, strict=True):
        col.width = width
    head = table.rows[0]
    _repeat_header(head)
    for cell, text, width in zip(head.cells, headers, widths, strict=True):
        cell.width = width
        _shade(cell, HEAD_FILL)
        _fill(cell, text, bold=True)
    for row in rows:
        for cell, text, width in zip(table.add_row().cells, row, widths, strict=True):
            cell.width = width
            _fill(cell, text)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def _cover(doc: DocumentObject, model_doc: Document) -> None:
    for _ in range(4):
        doc.add_paragraph()
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run(model_doc.title)
    run.font.name = SANS
    run._element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), SANS)
    run.font.size = Pt(22)
    run.bold = True
    for _ in range(2):
        doc.add_paragraph()
    table = doc.add_table(rows=0, cols=2)
    table.style = "Table Grid"
    table.autofit = False
    widths = [Emu(int(_usable_width(doc) * w / 7)) for w in (2, 5)]
    for label, value in model_doc.cover:
        cells = table.add_row().cells
        for cell, text, width in zip(cells, (label, value), widths, strict=True):
            cell.width = width
            _fill(cell, text)
    for _ in range(3):
        doc.add_paragraph()
    notice = doc.add_paragraph(model_doc.notice)
    notice.alignment = WD_ALIGN_PARAGRAPH.CENTER


def _toc(doc: DocumentObject, model_doc: Document, title: str) -> None:
    doc.add_page_break()
    head = doc.add_paragraph()
    run = head.add_run(title)
    run.font.name = SANS
    run._element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), SANS)
    run.font.size = Pt(HEADING_PT[1])
    run.bold = True
    for entry in model_doc.toc():
        line = doc.add_paragraph(_xml(f"{entry.number} {entry.text}"))
        line.paragraph_format.left_indent = Mm(0 if entry.level == 1 else 8)
        line.paragraph_format.space_after = Pt(3)
        line.paragraph_format.line_spacing = 1.15


def render_docx(model: ReportModel, out_path: Path | str) -> None:
    render_document_docx(
        build_document(model, TIMELINE_LIMIT_PDF_DOCX), out_path, author=str(model.case.get("examiner") or "")
    )


def render_document_docx(model_doc: Document, out_path: Path | str, *, author: str = "") -> None:
    doc = new_document()
    _apply_styles(doc)
    _declare_fallback_fonts(doc)
    doc.core_properties.title = model_doc.title
    doc.core_properties.author = author
    _page_setup(doc, model_doc.header_text)
    _cover(doc, model_doc)
    _toc(doc, model_doc, t("toc.title", model_doc.lang))
    landscape = False
    for block in model_doc.blocks:
        if isinstance(block, Heading):
            text = _xml(f"{block.number} {block.text}")
            if block.level == 1:
                if block.landscape != landscape:
                    _start_section(doc, landscape=block.landscape)
                    landscape = block.landscape
                    doc.add_heading(text, level=1)
                else:
                    heading = doc.add_heading(text, level=1)
                    heading.paragraph_format.page_break_before = True
            else:
                doc.add_heading(text, level=block.level)
        elif isinstance(block, Para):
            doc.add_paragraph(_xml(block.text))
        else:
            _table(doc, block)
    doc.save(str(out_path))
