from __future__ import annotations

from collections.abc import Sequence
from importlib import resources
from pathlib import Path
from typing import Any, cast

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

from aitrace.report.i18n import t
from aitrace.report.layout import Document, Heading, Para, Table, build_document
from aitrace.report.model import TIMELINE_LIMIT_PDF_DOCX, ReportModel

SERIF = "NanumMyeongjo"
SANS = "NanumGothic"
MARGIN_MM = 25
BODY_PT = 10.5
TABLE_PT = 9
HEADER_PT = 8
HEADING_PT = {1: 16, 2: 12, 3: BODY_PT, 4: BODY_PT}
BODY_LINE_MM = 6.4
TABLE_LINE_MM = 4.8
MIN_COL_MM = 14.0
ROW_FIT_RATIO = 0.8
HEAD_FILL = (239, 239, 239)
GRAY = (128, 128, 128)
LINE_MM = 0.18
KEEP_WITH_NEXT_MM = 35
CELL_PAD_MM = 1.3
COMPACT_PT = 7.5
COMPACT_LINE_MM = 3.3
COMPACT_PAD_MM = 0.5


class _ReportPDF(FPDF):
    def __init__(self, header_text: str, regular: Path, bold: Path, sans_bold: Path) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self._header_text = header_text
        self.set_margins(MARGIN_MM, MARGIN_MM, MARGIN_MM)
        self.set_auto_page_break(auto=True, margin=MARGIN_MM)
        self.alias_nb_pages()
        self.add_font(SERIF, "", str(regular))
        self.add_font(SERIF, "B", str(bold))
        self.add_font(SANS, "B", str(sans_bold))
        self.set_draw_color(0)
        self.set_text_color(0)
        self.set_line_width(LINE_MM)

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_y(12)
        self.set_font(SERIF, "", HEADER_PT)
        self.set_text_color(*GRAY)
        self.cell(0, 5, self._header_text, align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0)
        self.set_xy(self.l_margin, self.t_margin)

    def footer(self) -> None:
        if self.page_no() == 1:
            return
        self.set_y(-17)
        self.set_font(SERIF, "", TABLE_PT)
        self.cell(0, 5, f"- {self.page_no()} / {{nb}} -", align="C")


def _col_widths(weights: Sequence[int], total: float) -> list[float]:
    count = len(weights)
    if count * MIN_COL_MM >= total:
        return [total / count] * count
    fixed: set[int] = set()
    while True:
        free = total - MIN_COL_MM * len(fixed)
        pool = sum(weights[i] for i in range(count) if i not in fixed)
        widths = [MIN_COL_MM if i in fixed else free * weights[i] / pool for i in range(count)]
        low = {i for i in range(count) if i not in fixed and widths[i] < MIN_COL_MM}
        if not low:
            return widths
        fixed |= low


def _paragraph(pdf: _ReportPDF, text: str) -> None:
    pdf.set_font(SERIF, "", BODY_PT)
    pdf.multi_cell(0, BODY_LINE_MM, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1.5)


def _row_fits_page(pdf: _ReportPDF, row: Sequence[str], widths: Sequence[float], *, compact: bool = False) -> bool:
    size, line = (COMPACT_PT, COMPACT_LINE_MM) if compact else (TABLE_PT, TABLE_LINE_MM)
    pdf.set_font(SERIF, "", size)
    most = 0
    for cell, width in zip(row, widths, strict=True):
        lines = cast(
            list[str],
            pdf.multi_cell(width - 2 * pdf.c_margin, line, cell, dry_run=True, output="LINES"),
        )
        most = max(most, len(lines))
    usable = pdf.h - pdf.t_margin - pdf.b_margin
    return most * line <= usable * ROW_FIT_RATIO


def _grid(
    pdf: _ReportPDF,
    headers: Sequence[str] | None,
    rows: Sequence[Sequence[str]],
    widths: Sequence[float],
    *,
    compact: bool = False,
) -> None:
    size, line, pad = (COMPACT_PT, COMPACT_LINE_MM, COMPACT_PAD_MM) if compact else (TABLE_PT, TABLE_LINE_MM, CELL_PAD_MM)
    pdf.set_font(SERIF, "", size)
    with pdf.table(
        headings_style=FontFace(emphasis="BOLD", size_pt=size, color=(0, 0, 0), fill_color=HEAD_FILL),
        text_align="LEFT",
        col_widths=tuple(widths),
        line_height=line,
        borders_layout="ALL",
        v_align="TOP",
        padding=pad,
        first_row_as_headings=headers is not None,
    ) as table:
        if headers is not None:
            head = table.row()
            for header in headers:
                head.cell(header)
        for row in rows:
            cells = table.row()
            for cell in row:
                cells.cell(cell)
    pdf.ln(3)


def _table(pdf: _ReportPDF, block: Table) -> None:
    widths = _col_widths(block.weights, pdf.epw)
    if block.caption:
        pdf.set_font(SERIF, "", TABLE_PT)
        pdf.cell(0, 6, block.caption, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    fitting: list[Sequence[str]] = []
    for row in block.rows:
        if _row_fits_page(pdf, row, widths, compact=block.compact):
            fitting.append(row)
            continue
        if fitting:
            _grid(pdf, block.headers, fitting, widths, compact=block.compact)
            fitting = []
        _paragraph(pdf, "\n".join(f"{h}: {c}" for h, c in zip(block.headers, row, strict=True)))
    if fitting:
        _grid(pdf, block.headers, fitting, widths, compact=block.compact)


def _heading(pdf: _ReportPDF, block: Heading, *, fresh_page: bool = False) -> None:
    text = f"{block.number} {block.text}"
    if block.level == 1:
        if not fresh_page:
            pdf.add_page(orientation="L" if block.landscape else "P")
    elif pdf.get_y() > pdf.h - pdf.b_margin - KEEP_WITH_NEXT_MM:
        pdf.add_page(orientation="L" if pdf.w > pdf.h else "P")
    if block.toc and block.level <= 2:
        pdf.start_section(text, level=block.level - 1)
    size = HEADING_PT[block.level]
    if block.level >= 3:
        pdf.ln(2)
    pdf.set_font(SANS, "B", size)
    pdf.multi_cell(0, size * 0.62, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    if block.level == 1:
        pdf.line(pdf.l_margin, pdf.get_y() + 1, pdf.w - pdf.r_margin, pdf.get_y() + 1)
        pdf.ln(6)
    else:
        pdf.ln(1.5)


def _cover(pdf: _ReportPDF, doc: Document) -> None:
    pdf.add_page()
    pdf.ln(40)
    pdf.set_font(SANS, "B", 22)
    pdf.multi_cell(0, 13, doc.title, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(22)
    _grid(pdf, None, doc.cover, _col_widths((2, 5), pdf.epw))
    pdf.ln(24)
    pdf.set_font(SERIF, "", BODY_PT)
    pdf.multi_cell(0, BODY_LINE_MM, doc.notice, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _toc_renderer(title: str) -> Any:
    def render(pdf: _ReportPDF, outline: Sequence[Any]) -> None:
        pdf.set_x(pdf.l_margin)
        pdf.set_font(SANS, "B", HEADING_PT[1])
        pdf.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)
        page_w = 12
        for section in outline:
            indent = 0 if section.level == 0 else 8
            link = pdf.add_link(page=section.page_number)
            pdf.set_font(SERIF, "", BODY_PT)
            pdf.set_x(pdf.l_margin + indent)
            pdf.cell(pdf.epw - indent - page_w, 7, section.name, link=link)
            pdf.cell(page_w, 7, str(section.page_number), align="R", link=link, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    return render


def render_pdf(model: ReportModel, out_path: Path | str) -> Path:
    path = Path(out_path)
    doc = build_document(model, TIMELINE_LIMIT_PDF_DOCX)
    fonts = resources.files("aitrace.assets.fonts")
    with (
        resources.as_file(fonts.joinpath("NanumMyeongjo-Regular.ttf")) as regular,
        resources.as_file(fonts.joinpath("NanumMyeongjo-Bold.ttf")) as bold,
        resources.as_file(fonts.joinpath("NanumGothic-Bold.ttf")) as sans_bold,
    ):
        pdf = _ReportPDF(doc.header_text, regular, bold, sans_bold)
        pdf.set_title(doc.title)
        _cover(pdf, doc)
        pdf.add_page()
        pdf.insert_toc_placeholder(_toc_renderer(t("toc.title", doc.lang)), pages=1)
        first_chapter = True
        for block in doc.blocks:
            if isinstance(block, Heading):
                _heading(pdf, block, fresh_page=first_chapter and block.level == 1)
                first_chapter = first_chapter and block.level != 1
            elif isinstance(block, Para):
                _paragraph(pdf, block.text)
            else:
                _table(pdf, block)
        pdf.output(str(path))
    return path
