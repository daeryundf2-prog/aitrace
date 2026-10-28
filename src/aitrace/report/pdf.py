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
# Review-brief palette: navy for structure, one deep red kept for caution, cool greys for fills and rules.
NAVY = (22, 43, 77)
ACCENT = (140, 29, 38)
INK = (33, 37, 41)
MUTED = (104, 112, 122)
RULE = (196, 203, 212)
ZEBRA = (245, 247, 250)
TILE = (238, 242, 247)
COVER_BAND_MM = 120
TILE_GAP_MM = 4
TILE_H_MM = 27


class _ReportPDF(FPDF):
    def __init__(
        self,
        header_text: str,
        regular: Path,
        bold: Path,
        sans_bold: Path,
        *,
        theme: str = "plain",
        running: str = "",
    ) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self._header_text = header_text
        self.theme = theme
        self._running = running
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
        if self.theme == "brief":
            self.set_y(12)
            self.set_font(SANS, "B", HEADER_PT)
            self.set_text_color(*NAVY)
            self.cell(self.epw / 2, 5, self._running)
            self.set_font(SERIF, "", HEADER_PT)
            self.set_text_color(*MUTED)
            self.cell(self.epw / 2, 5, self._header_text, align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_draw_color(*NAVY)
            self.set_line_width(0.4)
            self.line(self.l_margin, 18, self.w - self.r_margin, 18)
            self.set_line_width(LINE_MM)
            self.set_draw_color(0)
            self.set_text_color(0)
            self.set_xy(self.l_margin, self.t_margin)
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
        if self.theme == "brief":
            self.set_font(SANS, "B", HEADER_PT)
            self.set_text_color(*ACCENT)
            self.cell(
                self.epw / 2, 5, t("brief.confidential", "ko" if self._running != "Review brief" else "en")
            )
            self.set_text_color(*NAVY)
            self.cell(self.epw / 2, 5, f"{self.page_no()} / {{nb}}", align="R")
            self.set_text_color(0)
            return
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


def _note(pdf: _ReportPDF, text: str) -> None:
    width = pdf.epw - 6
    pdf.set_font(SERIF, "", TABLE_PT + 0.5)
    lines = cast(list[str], pdf.multi_cell(width, TABLE_LINE_MM + 0.6, text, dry_run=True, output="LINES"))
    height = len(lines) * (TABLE_LINE_MM + 0.6) + 5
    if pdf.get_y() + height > pdf.h - pdf.b_margin:
        pdf.add_page()
    top = pdf.get_y() + 1
    pdf.set_fill_color(*TILE)
    pdf.rect(pdf.l_margin, top, pdf.epw, height, style="F")
    pdf.set_fill_color(*ACCENT)
    pdf.rect(pdf.l_margin, top, 1.2, height, style="F")
    pdf.set_xy(pdf.l_margin + 4.5, top + 2.5)
    pdf.set_text_color(*INK)
    pdf.multi_cell(width, TABLE_LINE_MM + 0.6, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0)
    pdf.set_y(top + height + 4)


def _figures(pdf: _ReportPDF, block: Table) -> None:
    count = len(block.headers)
    width = (pdf.epw - TILE_GAP_MM * (count - 1)) / count
    top = pdf.get_y() + 1
    for index, (label, value) in enumerate(zip(block.headers, block.rows[0], strict=True)):
        x = pdf.l_margin + index * (width + TILE_GAP_MM)
        pdf.set_fill_color(*TILE)
        pdf.rect(x, top, width, TILE_H_MM, style="F")
        pdf.set_fill_color(*NAVY)
        pdf.rect(x, top, width, 1.1, style="F")
        pdf.set_xy(x + 3, top + 5)
        pdf.set_font(SANS, "B", 20)
        pdf.set_text_color(*NAVY)
        pdf.cell(width - 6, 9, value)
        pdf.set_xy(x + 3, top + 17)
        pdf.set_font(SERIF, "", 8.5)
        pdf.set_text_color(*MUTED)
        pdf.multi_cell(width - 6, 3.8, label, align="L")
    pdf.set_text_color(0)
    pdf.set_y(top + TILE_H_MM + 7)


def _paragraph(pdf: _ReportPDF, text: str) -> None:
    pdf.set_font(SERIF, "", BODY_PT)
    pdf.multi_cell(0, BODY_LINE_MM, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1.5)


def _row_fits_page(
    pdf: _ReportPDF, row: Sequence[str], widths: Sequence[float], *, compact: bool = False
) -> bool:
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
    label_first: bool = False,
) -> None:
    size, line, pad = (
        (COMPACT_PT, COMPACT_LINE_MM, COMPACT_PAD_MM) if compact else (TABLE_PT, TABLE_LINE_MM, CELL_PAD_MM)
    )
    pdf.set_font(SERIF, "", size)
    brief = pdf.theme == "brief"
    if brief:
        pdf.set_draw_color(*RULE)
        pdf.set_text_color(*INK)
        head_style = FontFace(
            family=SANS, emphasis="BOLD", size_pt=size, color=(255, 255, 255), fill_color=NAVY
        )
    else:
        head_style = FontFace(emphasis="BOLD", size_pt=size, color=(0, 0, 0), fill_color=HEAD_FILL)
    label_style = FontFace(emphasis="BOLD", color=NAVY) if brief and label_first else None
    pdf.set_fill_color(255, 255, 255)
    with pdf.table(
        headings_style=head_style,
        text_align="LEFT",
        col_widths=tuple(widths),
        line_height=line,
        borders_layout="HORIZONTAL_LINES" if brief else "ALL",
        v_align="TOP",
        padding=pad + 0.6 if brief else pad,
        first_row_as_headings=headers is not None,
    ) as table:
        if headers is not None:
            head = table.row()
            for header in headers:
                head.cell(header)
        for number, row in enumerate(rows):
            cells = table.row()
            for index, cell in enumerate(row):
                cells.cell(
                    cell, style=_body_style(brief, number, label=label_style is not None and index == 0)
                )
    pdf.set_draw_color(0)
    pdf.set_text_color(0)
    pdf.ln(4 if brief else 3)


def _body_style(brief: bool, number: int, *, label: bool) -> FontFace | None:
    if not brief:
        return None
    fill = ZEBRA if number % 2 else (255, 255, 255)
    return (
        FontFace(emphasis="BOLD", color=NAVY, fill_color=fill)
        if label
        else FontFace(color=INK, fill_color=fill)
    )


def _table(pdf: _ReportPDF, block: Table) -> None:
    if block.figures and pdf.theme == "brief":
        _figures(pdf, block)
        return
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
            _grid(pdf, block.headers, fitting, widths, compact=block.compact, label_first=block.label_first)
            fitting = []
        _paragraph(pdf, "\n".join(f"{h}: {c}" for h, c in zip(block.headers, row, strict=True)))
    if fitting:
        _grid(pdf, block.headers, fitting, widths, compact=block.compact, label_first=block.label_first)


def _heading(pdf: _ReportPDF, block: Heading, *, fresh_page: bool = False) -> None:
    text = f"{block.number} {block.text}"
    if block.level == 1:
        if not fresh_page:
            pdf.add_page(orientation="L" if block.landscape else "P")
    elif pdf.get_y() > pdf.h - pdf.b_margin - KEEP_WITH_NEXT_MM:
        pdf.add_page(orientation="L" if pdf.w > pdf.h else "P")
    if block.toc and block.level <= 2:
        pdf.start_section(text, level=block.level - 1)
    if pdf.theme == "brief" and block.level <= 2:
        _brief_heading(pdf, block)
        return
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


def _brief_heading(pdf: _ReportPDF, block: Heading) -> None:
    if block.level == 1:
        pdf.set_font(SANS, "B", 9)
        pdf.set_text_color(*ACCENT)
        pdf.cell(0, 5, block.number, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)
        pdf.set_font(SANS, "B", 19)
        pdf.set_text_color(*NAVY)
        pdf.multi_cell(0, 10, block.text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_draw_color(*NAVY)
        pdf.set_line_width(0.6)
        pdf.line(pdf.l_margin, pdf.get_y() + 2, pdf.l_margin + 30, pdf.get_y() + 2)
        pdf.set_line_width(LINE_MM)
        pdf.set_draw_color(0)
        pdf.set_text_color(0)
        pdf.ln(9)
        return
    pdf.ln(2)
    top = pdf.get_y()
    pdf.set_fill_color(*NAVY)
    pdf.rect(pdf.l_margin, top + 1.2, 2.2, 4.6, style="F")
    pdf.set_x(pdf.l_margin + 5)
    pdf.set_font(SANS, "B", 12)
    pdf.set_text_color(*NAVY)
    pdf.multi_cell(0, 7, block.text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0)
    pdf.ln(2)


def _brief_cover(pdf: _ReportPDF, doc: Document) -> None:
    pdf.add_page()
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, pdf.w, COVER_BAND_MM, style="F")
    pdf.set_xy(pdf.l_margin, 46)
    pdf.set_font(SANS, "B", 10)
    pdf.set_text_color(178, 192, 214)
    pdf.cell(0, 6, t("brief.kicker", doc.lang), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)
    pdf.set_font(SANS, "B", 25)
    pdf.set_text_color(255, 255, 255)
    pdf.multi_cell(pdf.epw, 12, doc.title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_fill_color(*ACCENT)
    pdf.rect(pdf.l_margin, pdf.get_y() + 6, 26, 1.4, style="F")
    pdf.set_y(COVER_BAND_MM + 18)
    for label, value in doc.cover:
        top = pdf.get_y()
        pdf.set_font(SERIF, "", TABLE_PT)
        pdf.set_text_color(*MUTED)
        pdf.cell(42, 8, label)
        pdf.set_font(SERIF, "B", BODY_PT)
        pdf.set_text_color(*INK)
        pdf.multi_cell(pdf.epw - 42, 8, value or "-", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_draw_color(*RULE)
        pdf.line(pdf.l_margin, max(pdf.get_y(), top + 8), pdf.w - pdf.r_margin, max(pdf.get_y(), top + 8))
        pdf.set_y(max(pdf.get_y(), top + 8) + 1)
    pdf.set_draw_color(0)
    pdf.set_text_color(0)
    pdf.set_y(pdf.h - pdf.b_margin - 32)
    _note(pdf, doc.notice)


def _cover(pdf: _ReportPDF, doc: Document) -> None:
    if pdf.theme == "brief":
        _brief_cover(pdf, doc)
        return
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
        brief = pdf.theme == "brief"
        pdf.set_x(pdf.l_margin)
        pdf.set_font(SANS, "B", 19 if brief else HEADING_PT[1])
        if brief:
            pdf.set_text_color(*NAVY)
        pdf.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(6 if brief else 4)
        page_w = 12
        for section in outline:
            indent = 0 if section.level == 0 else 8
            link = pdf.add_link(page=section.page_number)
            if brief and section.level == 0:
                pdf.set_font(SANS, "B", BODY_PT)
                pdf.set_text_color(*NAVY)
                pdf.ln(1.5)
            else:
                pdf.set_font(SERIF, "", BODY_PT)
                pdf.set_text_color(*INK if brief else (0, 0, 0))
            pdf.set_x(pdf.l_margin + indent)
            pdf.cell(pdf.epw - indent - page_w, 7, section.name, link=link)
            pdf.cell(
                page_w, 7, str(section.page_number), align="R", link=link, new_x=XPos.LMARGIN, new_y=YPos.NEXT
            )
        pdf.set_text_color(0)

    return render


def render_pdf(model: ReportModel, out_path: Path | str) -> Path:
    return render_document_pdf(build_document(model, TIMELINE_LIMIT_PDF_DOCX), out_path)


def render_document_pdf(doc: Document, out_path: Path | str) -> Path:
    path = Path(out_path)
    fonts = resources.files("aitrace.assets.fonts")
    with (
        resources.as_file(fonts.joinpath("NanumMyeongjo-Regular.ttf")) as regular,
        resources.as_file(fonts.joinpath("NanumMyeongjo-Bold.ttf")) as bold,
        resources.as_file(fonts.joinpath("NanumGothic-Bold.ttf")) as sans_bold,
    ):
        pdf = _ReportPDF(
            doc.header_text,
            regular,
            bold,
            sans_bold,
            theme=doc.theme,
            running=t("brief.running", doc.lang) if doc.theme == "brief" else "",
        )
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
                if block.note and doc.theme == "brief":
                    _note(pdf, block.text)
                else:
                    _paragraph(pdf, block.text)
            else:
                _table(pdf, block)
        pdf.output(str(path))
    return path
