"""Single-file, self-contained HTML report renderer (inline CSS, no external assets)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from aitrace.report.i18n import DEFAULT_LANG, SUPPORTED_LANGS, t
from aitrace.report.layout import Document, Heading, Para, Table, build_document
from aitrace.report.model import TIMELINE_LIMIT_HTML, ReportModel

TEMPLATE_NAME = "report.html.j2"
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _table(block: Table) -> dict[str, Any]:
    total = sum(block.weights) or 1
    return {
        "kind": "table",
        "caption": block.caption,
        "headers": block.headers,
        "widths": [round(100 * w / total, 1) for w in block.weights],
        "rows": [
            [
                {"text": cell, "raw": i in block.raw, "label": block.label_first and i == 0}
                for i, cell in enumerate(row)
            ]
            for row in block.rows
        ],
    }


def _chapters(doc: Document) -> list[dict[str, Any]]:
    chapters: list[dict[str, Any]] = []
    for block in doc.blocks:
        if isinstance(block, Heading) and block.level == 1:
            chapters.append({"heading": block, "blocks": []})
        elif isinstance(block, Heading):
            chapters[-1]["blocks"].append(
                {
                    "kind": "heading",
                    "level": block.level + 1,
                    "number": block.number,
                    "text": block.text,
                    "anchor": block.anchor,
                }
            )
        elif isinstance(block, Para):
            chapters[-1]["blocks"].append({"kind": "para", "text": block.text})
        else:
            chapters[-1]["blocks"].append(_table(block))
    return chapters


def environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html_string(model: ReportModel) -> str:
    lang = str(model.case.get("lang") or DEFAULT_LANG)
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    doc = build_document(model, TIMELINE_LIMIT_HTML)
    return (
        environment()
        .get_template(TEMPLATE_NAME)
        .render(
            lang=lang,
            doc=doc,
            toc_title=t("toc.title", lang),
            toc=doc.toc(),
            chapters=_chapters(doc),
        )
    )


def render_html(model: ReportModel, out_path: Path | str) -> Path:
    """Render `model` to one self-contained UTF-8 HTML file and return its path."""
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_string(model), encoding="utf-8")
    return path
