"""Single-file, self-contained HTML report renderer (inline CSS, no external assets)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import partial
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from aitrace.report.i18n import DEFAULT_LANG, SUPPORTED_LANGS, t
from aitrace.report.model import COLUMNS, TIMELINE_LIMIT_HTML, ReportModel

TEMPLATE_NAME = "report.html.j2"
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

# Appendix E sections rendered in the document, in order; `run` is machine-only metadata.
HTML_SECTIONS: tuple[str, ...] = (
    "case",
    "evidence",
    "tools",
    "methodology",
    "summary",
    "ai_tools",
    "ai_queries",
    "file_lifecycle",
    "exfil",
    "attribution",
    "timeline",
    "exports",
    "coverage",
    "limitations",
    "custody",
    "signature",
)

LONG_TEXT_CHARS = 240

# Column keys holding paths, file names or hashes: monospace, small, breakable anywhere.
_ID_KEYS = frozenset({"source_path", "export_path", "sha256", "source_name"})
_TS_KEYS = frozenset({"ts_local", "ts", "first_seen_local", "last_seen_local"})
_BADGE_KEYS = {"severity_label": "severity", "verdict_label": "verdict"}
_PLAIN_KEYS = _ID_KEYS | _TS_KEYS

# Headers for the coverage / custody tables, which are not part of model.COLUMNS.
_EXTRA: dict[str, dict[str, str]] = {
    "ko": {
        "toc": "목차",
        "created": "생성 시각(UTC)",
        "plugin": "플러그인",
        "version": "버전",
        "status": "상태",
        "records": "레코드",
        "warnings": "경고",
        "error": "오류",
        "message": "메시지",
        "detail": "내용",
        "tool": "도구",
        "ts": "시각",
    },
    "en": {
        "toc": "Contents",
        "created": "Created (UTC)",
        "plugin": "Plugin",
        "version": "Version",
        "status": "Status",
        "records": "Records",
        "warnings": "Warnings",
        "error": "Error",
        "message": "Message",
        "detail": "Detail",
        "tool": "Tool",
        "ts": "Time",
    },
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Mapping):
        return ", ".join(f"{k}: {_text(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return ", ".join(_text(v) for v in value)
    return str(value)


def _items(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [s for s in (_text(v) for v in value) if s]
    text = _text(value)
    return [text] if text else []


def _cell(key: str, row: Mapping[str, Any]) -> dict[str, Any]:
    items = _items(row.get(key))
    badge = _BADGE_KEYS.get(key)
    cls = ""
    if key in _ID_KEYS:
        cls = "id"
    elif key in _TS_KEYS:
        cls = "ts"
    return {
        "items": items,
        "cls": cls,
        "plain": key in _PLAIN_KEYS,
        "badge": str(row.get(badge) or "") if badge and items else "",
    }


def _table(rows: Sequence[Mapping[str, Any]], columns: Sequence[tuple[str, str, int]]) -> dict[str, Any]:
    total = sum(w for _, _, w in columns) or 1
    return {
        "cols": [{"label": label, "pct": round(100 * w / total, 1)} for _, label, w in columns],
        "rows": [[_cell(key, row) for key, _, _ in columns] for row in rows],
    }


def _spec_table(key: str, rows: Sequence[Mapping[str, Any]], lang: str) -> dict[str, Any]:
    return _table(rows, [(field, t(label, lang), w) for field, label, w in COLUMNS[key]])


def _extra_table(
    rows: Sequence[Mapping[str, Any]],
    spec: Sequence[tuple[str, str, int]],
    lang: str,
    extra: Mapping[str, str],
) -> dict[str, Any]:
    columns = [(k, extra[label] if label in extra else t(label, lang), w) for k, label, w in spec]
    return _table(rows, columns)


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["scalar"] = _text
    return env


def _tables(
    model: ReportModel, lang: str, timeline: Sequence[Mapping[str, Any]], custody: Sequence[Any]
) -> dict[str, Any]:
    extra = _EXTRA[lang]
    cov = model.coverage
    tables: dict[str, Any] = {
        "ai_tools": _spec_table("ai_tools", model.ai_tools, lang),
        "ai_queries": _spec_table("ai_queries", model.ai_queries, lang),
        "file_lifecycle": _spec_table("file_lifecycle", model.file_lifecycle, lang),
        "exfil": _spec_table("exfil", model.exfil, lang),
        "attribution": _spec_table("attribution", model.attribution, lang),
        "timeline": _spec_table("timeline", timeline, lang),
        "exports": _spec_table("exports", model.exports, lang),
        "plugin_runs": _extra_table(
            cov.get("plugin_runs", []),
            [
                ("name", "plugin", 3),
                ("version", "version", 2),
                ("status", "status", 2),
                ("records", "records", 1),
                ("warnings", "warnings", 1),
                ("error", "error", 4),
            ],
            lang,
            extra,
        ),
        "parse_warnings": _extra_table(
            cov.get("parse_warnings", []),
            [
                ("plugin", "plugin", 2),
                ("message", "message", 4),
                ("error", "error", 3),
                ("source_path", "col.source_path", 4),
            ],
            lang,
            extra,
        ),
        "not_decoded": _extra_table(
            cov.get("not_decoded", []),
            [
                ("tool", "tool", 2),
                ("status", "status", 2),
                ("detail", "detail", 4),
                ("source_path", "col.source_path", 4),
            ],
            lang,
            extra,
        ),
        "coverage_findings": _extra_table(
            cov.get("findings", []),
            [
                ("severity_label", "col.severity", 1),
                ("title", "col.display_title", 3),
                ("narrative", "col.text", 5),
                ("limitations_display", "col.limitations", 4),
            ],
            lang,
            extra,
        ),
        "custody": _extra_table(
            [{**c, "seq": c.get("seq", i)} for i, c in enumerate(custody, start=1)],
            [
                ("seq", "custody.seq", 1),
                ("ts", "ts", 3),
                ("actor", "custody.actor", 2),
                ("action", "custody.action", 2),
                ("detail", "custody.detail", 5),
            ],
            lang,
            extra,
        ),
    }
    return tables


def render_html_string(model: ReportModel) -> str:
    lang = str(model.case.get("lang") or DEFAULT_LANG)
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    env = _environment()
    custody = model.run.get("custody") or model.custody
    timeline = model.timeline_render(TIMELINE_LIMIT_HTML)
    id_labels = {
        t(key, lang)
        for key in (
            "label.case_id",
            "label.evidence_id",
            "label.media_sha256",
            "label.acquisition_hashes",
            "label.evidence_path",
        )
    }
    return env.get_template(TEMPLATE_NAME).render(
        t=partial(t, lang=lang),
        x=_EXTRA[lang].__getitem__,
        long_chars=LONG_TEXT_CHARS,
        m=model,
        lang=lang,
        sections=HTML_SECTIONS,
        tables=_tables(model, lang, timeline, custody),
        id_labels=id_labels,
        case_pairs=model.case_pairs(),
        evidence_pairs=model.evidence_pairs(),
        evidence_limitations=[_items(ev.get("limitations")) for ev in model.evidence],
        tools_pairs=model.tools_pairs(),
        methodology_pairs=model.methodology_pairs(),
        timeline_note=model.timeline_note(TIMELINE_LIMIT_HTML, lang),
    )


def render_html(model: ReportModel, out_path: Path | str) -> Path:
    """Render `model` to one self-contained UTF-8 HTML file and return its path."""
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_string(model), encoding="utf-8")
    return path
