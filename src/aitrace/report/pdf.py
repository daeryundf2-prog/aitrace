from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from importlib import resources
from pathlib import Path
from typing import Any, cast

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

from aitrace.report.i18n import STRINGS, t
from aitrace.report.model import COLUMNS, SECTION_KEYS, TIMELINE_LIMIT_PDF_DOCX, ReportModel

FAMILY = "NanumGothic"
MONO_FAMILY = "Courier"
PDF_SECTIONS: tuple[str, ...] = tuple(key for key in SECTION_KEYS if key != "run")
LANDSCAPE_SECTIONS: frozenset[str] = frozenset({"timeline", "exports"})
TOC_TITLE = "목차 / Contents"
_KV_HEADERS: tuple[str, str] = ("항목 / Item", "값 / Value")
_BODY_SIZE = 9
_TABLE_SIZE = 8
_MONO_SIZE = 6.5
_CELL_LIMIT = 400
_LINE_HEIGHT = 5.5
_TABLE_LINE_HEIGHT = 4.2
_ROW_FIT_RATIO = 0.8
_MIN_COL_MM = 14.0
# Row fields rendered in a small monospace face; they may be broken anywhere.
_MONO_FIELDS: frozenset[str] = frozenset({"sha256", "export_path", "source_path", "source_name"})

# (row field, label key, width weight) for tables that are not part of model.COLUMNS.
_Spec = Sequence[tuple[str, str, int]]
_PLUGIN_RUN_SPEC: _Spec = (
    ("name", "coverage.plugin", 3),
    ("version", "col.version", 2),
    ("status", "col.status", 2),
    ("records", "col.records", 1),
    ("warnings", "col.warnings", 1),
    ("error", "col.error", 4),
)
_PARSE_WARNING_SPEC: _Spec = (
    ("plugin", "coverage.plugin", 3),
    ("message", "col.message", 5),
    ("error", "col.error", 3),
    ("source_path", "col.source_path", 4),
)
_NOT_DECODED_SPEC: _Spec = (
    ("tool", "col.tool", 3),
    ("status", "col.status", 2),
    ("detail", "col.detail", 5),
    ("source_path", "col.source_path", 4),
)
_COVERAGE_FINDING_SPEC: _Spec = (
    ("severity_label", "col.severity", 1),
    ("title", "col.display_title", 4),
    ("narrative", "col.text", 8),
)
_CUSTODY_SPEC: _Spec = (
    ("seq", "custody.seq", 1),
    ("actor", "custody.actor", 2),
    ("action", "custody.action", 3),
    ("detail", "custody.detail", 8),
)
_SIGNATURE_SPEC: _Spec = (
    ("examiner", "signature.examiner", 3),
    ("organisation", "label.organisation", 3),
    ("signature", "signature.signature", 3),
    ("date", "signature.date", 2),
)

_EXTRA_LABELS: dict[str, tuple[str, str]] = {
    "coverage.plugin": ("플러그인", "Plugin"),
    "col.version": ("버전", "Version"),
    "col.status": ("상태", "Status"),
    "col.records": ("레코드", "Records"),
    "col.warnings": ("경고", "Warnings"),
    "col.error": ("오류", "Error"),
    "col.message": ("메시지", "Message"),
    "col.detail": ("내용", "Detail"),
}


def _bilingual(key: str) -> str:
    return f"{STRINGS['ko'][key]} / {STRINGS['en'][key]}"


def _label(key: str, lang: str) -> str:
    if key in STRINGS.get(lang, STRINGS["en"]):
        return t(key, lang)
    ko, en = _EXTRA_LABELS[key]
    return ko if lang == "ko" else en


def _text(value: Any) -> str:
    """Flatten any value to plain reader text (never raw JSON)."""
    if value is None:
        return ""
    if isinstance(value, Mapping):
        return "\n".join(f"{k}: {_text(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return "\n".join(_text(item) for item in value)
    return str(value)


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    return isinstance(value, (Mapping, Sequence)) and not isinstance(value, str) and len(value) == 0


class _ReportPDF(FPDF):
    def __init__(self, case_number: str, app_version: str, regular: Path, bold: Path) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self._case_number = case_number
        self._app_version = app_version
        self.set_margins(15, 20, 15)
        self.set_auto_page_break(auto=True, margin=18)
        self.alias_nb_pages()
        self.add_font(FAMILY, "", str(regular))
        self.add_font(FAMILY, "B", str(bold))

    def header(self) -> None:
        self.set_font(FAMILY, "", 8)
        label = f"{_bilingual('label.case_number')}: {self._case_number}"
        self.cell(
            0, 6, f"{label}    page {self.page_no()}/{{nb}}", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font(FAMILY, "", 8)
        self.cell(0, 6, f"aitrace v{self._app_version} - page {self.page_no()}/{{nb}}", align="C")


def _paragraph(pdf: _ReportPDF, text: str, bold: bool = False) -> None:
    pdf.set_font(FAMILY, "B" if bold else "", _BODY_SIZE)
    pdf.multi_cell(0, _LINE_HEIGHT, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _col_widths(weights: Sequence[int], total: float) -> list[float]:
    """Widths proportional to weights, none narrower than _MIN_COL_MM (when it fits)."""
    count = len(weights)
    if count * _MIN_COL_MM >= total:
        return [total / count] * count
    fixed: set[int] = set()
    widths = [0.0] * count
    while True:
        free = total - _MIN_COL_MM * len(fixed)
        pool = sum(weights[i] for i in range(count) if i not in fixed)
        widths = [_MIN_COL_MM if i in fixed else free * weights[i] / pool for i in range(count)]
        low = {i for i in range(count) if i not in fixed and widths[i] < _MIN_COL_MM}
        if not low:
            return widths
        fixed |= low


def _cell_style(field: str | None, text: str) -> FontFace | None:
    if field in _MONO_FIELDS:
        if text.isascii():
            return FontFace(family=MONO_FAMILY, size_pt=_MONO_SIZE)
        return FontFace(family=FAMILY, size_pt=_MONO_SIZE)
    return None


def _table(
    pdf: _ReportPDF,
    headers: Sequence[str],
    rows: Iterable[Sequence[str]],
    weights: Sequence[int],
    fields: Sequence[str | None],
) -> None:
    pdf.set_font(FAMILY, "", _TABLE_SIZE)
    widths = _col_widths(weights, pdf.epw)
    with pdf.table(
        headings_style=FontFace(emphasis="BOLD", size_pt=_TABLE_SIZE),
        text_align="LEFT",
        col_widths=tuple(widths),
        line_height=_TABLE_LINE_HEIGHT,
    ) as table:
        head = table.row()
        for header in headers:
            head.cell(header)
        for row in rows:
            cells = table.row()
            for field, cell in zip(fields, row, strict=True):
                cells.cell(cell, style=_cell_style(field, cell))
    pdf.ln(2)


def _row_fits_page(pdf: _ReportPDF, row: Sequence[str], widths: Sequence[float]) -> bool:
    """Conservatively check that a table row fits on one page."""
    pdf.set_font(FAMILY, "", _TABLE_SIZE)
    most = 0
    for cell, width in zip(row, widths, strict=True):
        lines = cast(
            list[str],
            pdf.multi_cell(width - 2 * pdf.c_margin, _TABLE_LINE_HEIGHT, cell, dry_run=True, output="LINES"),
        )
        most = max(most, len(lines))
    usable = pdf.h - pdf.t_margin - pdf.b_margin
    return most * _TABLE_LINE_HEIGHT <= usable * _ROW_FIT_RATIO


def _label_value(headers: Sequence[str], row: Sequence[str]) -> str:
    return "\n".join(f"{h}: {c}" for h, c in zip(headers, row, strict=True))


def _records(
    pdf: _ReportPDF,
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    weights: Sequence[int],
    fields: Sequence[str | None],
) -> None:
    if any(len(cell) > _CELL_LIMIT for row in rows for cell in row):
        for row in rows:
            _paragraph(pdf, _label_value(headers, row))
        return
    widths = _col_widths(weights, pdf.epw)
    fitting: list[Sequence[str]] = []
    for row in rows:
        if _row_fits_page(pdf, row, widths):
            fitting.append(row)
            continue
        if fitting:
            _table(pdf, headers, fitting, weights, fields)
            fitting = []
        _paragraph(pdf, _label_value(headers, row))
    if fitting:
        _table(pdf, headers, fitting, weights, fields)


def _spec_table(pdf: _ReportPDF, spec: _Spec, rows: Sequence[Mapping[str, Any]], lang: str) -> None:
    if not rows:
        _paragraph(pdf, _label("summary.none", lang))
        return
    headers = [_label(label, lang) for _, label, _ in spec]
    weights = [weight for _, _, weight in spec]
    fields = [field for field, _, _ in spec]
    body = [[_text(row.get(field)) for field in fields] for row in rows]
    _records(pdf, headers, body, weights, fields)


def _pairs_table(
    pdf: _ReportPDF, pairs: Sequence[tuple[str, str]], mono_labels: frozenset[str] = frozenset()
) -> None:
    if not pairs:
        _paragraph(pdf, _bilingual("summary.none"))
        return
    rows = [(label, value) for label, value in pairs]
    mono = [("sha256" if label in mono_labels else None) for label, _ in pairs]
    pdf.set_font(FAMILY, "", _TABLE_SIZE)
    _kv_rows(pdf, rows, mono)


def _kv_rows(pdf: _ReportPDF, rows: Sequence[tuple[str, str]], mono: Sequence[str | None]) -> None:
    weights = (2, 5)
    widths = _col_widths(weights, pdf.epw)
    fitting: list[tuple[tuple[str, str], str | None]] = []

    def flush() -> None:
        if not fitting:
            return
        pdf.set_font(FAMILY, "", _TABLE_SIZE)
        with pdf.table(
            headings_style=FontFace(emphasis="BOLD", size_pt=_TABLE_SIZE),
            text_align="LEFT",
            col_widths=tuple(widths),
            line_height=_TABLE_LINE_HEIGHT,
        ) as table:
            head = table.row()
            for header in _KV_HEADERS:
                head.cell(header)
            for (label, value), field in fitting:
                cells = table.row()
                cells.cell(label)
                cells.cell(value, style=_cell_style(field, value))
        pdf.ln(2)
        fitting.clear()

    for row, field in zip(rows, mono, strict=True):
        if len(row[1]) <= _CELL_LIMIT and _row_fits_page(pdf, row, widths):
            fitting.append((row, field))
            continue
        flush()
        _paragraph(pdf, _label_value(_KV_HEADERS, row))
    flush()


def _columns_table(pdf: _ReportPDF, model: ReportModel, key: str, rows: Sequence[Mapping[str, Any]]) -> None:
    _spec_table(pdf, COLUMNS[key], rows, model.lang)


def _cover(pdf: _ReportPDF, model: ReportModel) -> None:
    pdf.add_page()
    pdf.ln(30)
    pdf.set_font(FAMILY, "B", 22)
    pdf.multi_cell(0, 12, _bilingual("report.title"), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(10)
    case = model.case
    fields = (
        ("label.case_name", "name"),
        ("label.case_number", "number"),
        ("label.examiner", "examiner"),
        ("label.organisation", "organisation"),
        ("label.timezone", "timezone"),
        ("label.tool_version", "tool_version"),
    )
    _kv_rows(pdf, [(_bilingual(label), _text(case[field])) for label, field in fields], [None] * len(fields))
    _paragraph(pdf, _text(case["handling_notice"]))


def _toc(pdf: _ReportPDF, links: Mapping[str, int]) -> None:
    pdf.add_page()
    pdf.set_font(FAMILY, "B", 16)
    pdf.cell(0, 10, TOC_TITLE, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font(FAMILY, "", 11)
    for number, key in enumerate(PDF_SECTIONS, start=1):
        entry = f"{number}. {_bilingual(f'section.{key}')}"
        pdf.cell(0, 8, entry, link=links[key], new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _subheading(pdf: _ReportPDF, text: str) -> None:
    pdf.set_font(FAMILY, "B", 10)
    pdf.cell(0, 7, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _render_body(pdf: _ReportPDF, model: ReportModel, key: str) -> None:
    lang = model.lang
    if key == "case":
        _pairs_table(pdf, model.case_pairs())
    elif key == "evidence":
        mono = frozenset(
            _label(k, lang) for k in ("label.acquisition_hashes", "label.media_sha256", "label.evidence_path")
        )
        if not model.evidence:
            _paragraph(pdf, _label("summary.none", lang))
        for pairs in model.evidence_pairs():
            _pairs_table(pdf, pairs, mono)
    elif key == "tools":
        _pairs_table(pdf, model.tools_pairs())
    elif key == "methodology":
        for paragraph in model.methodology.get("paragraphs", []):
            _paragraph(pdf, _text(paragraph))
        pdf.ln(1)
        _pairs_table(pdf, model.methodology_pairs())
    elif key == "summary":
        for item in model.summary:
            _paragraph(pdf, f"{item['id']}. {_text(item['question'])}", bold=True)
            for bullet in item.get("bullets", []):
                _paragraph(pdf, f"- {_text(bullet)}")
            pdf.ln(1)
    elif key == "timeline":
        _columns_table(pdf, model, key, model.timeline_render(TIMELINE_LIMIT_PDF_DOCX))
        note = model.timeline_note(TIMELINE_LIMIT_PDF_DOCX, lang)
        if note is not None:
            _paragraph(pdf, note)
    elif key in COLUMNS:
        _columns_table(pdf, model, key, getattr(model, key))
    elif key == "coverage":
        coverage = model.coverage
        for sub, spec in (
            ("plugin_runs", _PLUGIN_RUN_SPEC),
            ("parse_warnings", _PARSE_WARNING_SPEC),
            ("not_decoded", _NOT_DECODED_SPEC),
            ("findings", _COVERAGE_FINDING_SPEC),
        ):
            _subheading(pdf, _label(f"coverage.{sub}", lang))
            _spec_table(pdf, spec, coverage.get(sub) or [], lang)
    elif key == "limitations":
        if not model.limitations:
            _paragraph(pdf, _label("summary.none", lang))
        for item in model.limitations:
            _paragraph(pdf, f"- {_text(item)}")
    elif key == "custody":
        _spec_table(pdf, _CUSTODY_SPEC, model.custody, lang)
    elif key == "signature":
        _spec_table(pdf, _SIGNATURE_SPEC, [model.signature], lang)
    else:
        raise KeyError(key)


def _render_section(pdf: _ReportPDF, model: ReportModel, key: str, links: Mapping[str, int]) -> None:
    want = "L" if key in LANDSCAPE_SECTIONS else "P"
    if pdf.cur_orientation != want:
        pdf.add_page(orientation=want)
    pdf.set_font(FAMILY, "B", 13)
    pdf.set_link(links[key])
    pdf.cell(0, 9, _bilingual(f"section.{key}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)
    _render_body(pdf, model, key)
    pdf.ln(4)


def render_pdf(model: ReportModel, out_path: Path | str) -> Path:
    path = Path(out_path)
    fonts = resources.files("aitrace.assets.fonts")
    with (
        resources.as_file(fonts.joinpath("NanumGothic-Regular.ttf")) as regular,
        resources.as_file(fonts.joinpath("NanumGothic-Bold.ttf")) as bold,
    ):
        pdf = _ReportPDF(str(model.case["number"]), str(model.case["tool_version"]), regular, bold)
        _cover(pdf, model)
        links = {key: pdf.add_link() for key in PDF_SECTIONS}
        _toc(pdf, links)
        for key in PDF_SECTIONS:
            _render_section(pdf, model, key, links)
        pdf.output(str(path))
    return path
