"""Companion volume (prompts.html): every chat message and instruction text, grouped by tool, machine, session.

Plain HTML in the main report's style, no JavaScript. Written as a stream so a case with tens of
thousands of prompts never builds the whole page in memory.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from html import escape
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from aitrace.report.html import environment
from aitrace.report.i18n import DEFAULT_LANG, SUPPORTED_LANGS, t
from aitrace.report.layout import (
    QUESTION_LOOP_HEADERS,
    machine_label,
    question_clean_rows,
    question_loop_rows,
    question_month_table,
    question_topic_rows,
    tool_label,
)
from aitrace.report.model import QUESTIONS_CSV_PATH, ReportModel

_EXTRA_CSS = """
nav.toc p.l3 { padding-left: 16mm; }
nav.toc p.l2 { padding-left: 8mm; }
h3.machine { margin: 8mm 0 3mm; }
.entry { margin: 0 0 4mm; }
.entry .meta { margin: 0 0 1mm; text-align: left; font-family: var(--sans); font-size: 9pt; color: var(--muted); }
.entry pre { margin: 0; padding: 1.2mm 2mm; border: var(--rule); font-family: var(--serif); font-size: 9.5pt; line-height: 1.6; white-space: pre-wrap; overflow-wrap: anywhere; }
@media print { section.tool { break-before: page; } }
"""


class _Session:
    __slots__ = ("anchor", "label", "rows")

    def __init__(self, label: str) -> None:
        self.rows: list[Mapping[str, Any]] = []
        self.anchor = ""
        self.label = label


class _Machine:
    __slots__ = ("anchor", "instructions", "sessions")

    def __init__(self) -> None:
        self.instructions: list[Mapping[str, Any]] = []
        self.sessions: dict[str | None, _Session] = {}
        self.anchor = ""


def _tree(model: ReportModel) -> dict[str, dict[str, _Machine]]:
    lang = model.lang
    meta = model.query_meta
    tree: dict[str, dict[str, _Machine]] = {}
    for row in model.ai_queries:
        machine = tree.setdefault(tool_label(row.get("tool"), lang), {}).setdefault(
            machine_label(row, meta), _Machine()
        )
        session = row.get("session")
        label = t("sec.session", lang, session=session) if session else t("sec.no_session", lang)
        machine.sessions.setdefault(session, _Session(label)).rows.append(row)
    for row in model.instructions:
        tree.setdefault(tool_label(row.get("tool"), lang), {}).setdefault(
            machine_label(row, meta), _Machine()
        ).instructions.append(row)
    return tree


def _entry(row: Mapping[str, Any]) -> str:
    stamp = escape(str(row.get("ts_local") or "-"))
    role = escape(str(row.get("role_label") or ""))
    source = escape(str(row.get("source") or ""))
    text = escape(str(row.get("text") or ""))
    return f'<div class="entry"><p class="meta">{stamp} \u00b7 {role} \u00b7 {source}</p><pre>{text}</pre></div>\n'


def _toc(tree: dict[str, dict[str, _Machine]], lang: str, generated: bool = False) -> Iterator[str]:
    yield f'<nav class="toc" aria-label="{escape(t("vol.toc", lang))}">\n<h2>{escape(t("vol.toc", lang))}</h2>\n'
    for tool, machines in tree.items():
        yield f'<p class="l1"><a href="#{machines_anchor(tool, tree)}">{escape(tool)}</a></p>\n'
        for name, machine in machines.items():
            count = len(machine.instructions) + sum(len(s.rows) for s in machine.sessions.values())
            yield (
                f'<p class="l2"><a href="#{machine.anchor}">{escape(name)}</a> '
                f"({escape(t('vol.count', lang, n=count))})</p>\n"
            )
            for session in machine.sessions.values():
                yield (
                    f'<p class="l3"><a href="#{session.anchor}">{escape(session.label)}</a> '
                    f"({escape(t('vol.count', lang, n=len(session.rows)))})</p>\n"
                )
    if generated:
        yield f'<p class="l1"><a href="#{GENERATED_ANCHOR}">{escape(t("vol.generated", lang))}</a></p>\n'
    yield "</nav>\n"


def machines_anchor(tool: str, tree: dict[str, dict[str, _Machine]]) -> str:
    return f"t{list(tree).index(tool) + 1}"


def _assign_anchors(tree: dict[str, dict[str, _Machine]]) -> None:
    for ti, machines in enumerate(tree.values(), start=1):
        for mi, machine in enumerate(machines.values(), start=1):
            machine.anchor = f"t{ti}m{mi}"
            machine.sessions = dict(
                sorted(
                    machine.sessions.items(),
                    key=lambda kv: (kv[0] is None, str(kv[1].rows[0].get("ts_utc") or "~")),
                )
            )
            for si, session in enumerate(machine.sessions.values(), start=1):
                session.anchor = f"{machine.anchor}s{si}"


def _body(tree: dict[str, dict[str, _Machine]], lang: str) -> Iterator[str]:
    for ti, (tool, machines) in enumerate(tree.items(), start=1):
        yield f'<section class="tool">\n<h2 id="t{ti}">{escape(tool)}</h2>\n'
        for name, machine in machines.items():
            yield f'<h3 class="machine" id="{machine.anchor}">{escape(name)}</h3>\n'
            if machine.instructions:
                yield f"<h4>{escape(t('vol.instructions', lang))}</h4>\n"
                for row in machine.instructions:
                    yield _entry(row)
            for session in machine.sessions.values():
                yield f'<h4 id="{session.anchor}">{escape(session.label)}</h4>\n'
                for row in session.rows:
                    yield _entry(row)
        yield "</section>\n"


GENERATED_ANCHOR = "generated"


def _generated(model: ReportModel, lang: str) -> Iterator[str]:
    """Every item chapter 4 judged, in time order (items without a record time last)."""
    rows = sorted(
        model.generated_files,
        key=lambda r: (r.get("ts_utc") is None, str(r.get("ts_utc") or ""), str(r.get("subject"))),
    )
    yield f'<section class="tool">\n<h2 id="{GENERATED_ANCHOR}">{escape(t("vol.generated", lang))}</h2>\n'
    yield f"<p>{escape(t('vol.generated_intro', lang, n=len(rows)))}</p>\n"
    for row in rows:
        meta = " \u00b7 ".join(
            str(v)
            for v in (
                row.get("ts_local") or "-",
                row.get("verdict_label"),
                row.get("confidence_display"),
                row.get("basis") or row.get("subject"),
            )
            if v
        )
        lines = [
            str(row.get("subject") or ""),
            *(str(o) for o in row.get("origin") or ()),
            *(str(x) for x in row.get("limitations_display") or ()),
        ]
        yield (
            f'<div class="entry"><p class="meta">{escape(meta)}</p>'
            f"<pre>{escape(chr(10).join(lines))}</pre></div>\n"
        )
    yield "</section>\n"


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]], caption: str) -> str:
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{escape(c)}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><caption>{escape(caption)}</caption><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>\n"


def _question(q: Mapping[str, Any], lang: str) -> str:
    parts = [
        f"#{q.get('no')}",
        str(q.get("ts_local") or "-")[11:] or "-",
        str(q.get("machine") or ""),
        str(q.get("channel") or ""),
    ]
    if q.get("attachment"):
        parts.append(t("q.meta_attach", lang))
    if q.get("duplicates"):
        parts.append(t("q.meta_dup", lang, n=q["duplicates"]))
    meta = " \u00b7 ".join(p for p in parts if p)
    return f'<div class="entry"><p class="meta">{escape(meta)}</p><pre>{escape(str(q.get("text") or ""))}</pre></div>\n'


def render_questions_volume(model: ReportModel, out_path: Path | str) -> Path:
    lang = str(model.case.get("lang") or DEFAULT_LANG)
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    number = str(model.case.get("document_number") or "")
    title = t("q.title", lang)
    css = (
        environment()
        .get_template("report.css.j2")
        .render(doc=SimpleNamespace(header_text=f"{t('header.text', lang, doc=number)} - {title}"))
    )
    stats = model.question_stats
    days: dict[str, list[Mapping[str, Any]]] = {}
    for q in model.questions:
        days.setdefault(str(q.get("date") or ""), []).append(q)
    anchors = {day: f"d{i}" for i, day in enumerate(days, start=1)}
    with path.open("w", encoding="utf-8") as fh:
        fh.write(
            f'<!DOCTYPE html>\n<html lang="{lang}">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{escape(title)} - {escape(str(model.case.get('number') or ''))}</title>\n"
            f'<style>\n{css}{_EXTRA_CSS}</style>\n</head>\n<body>\n<div class="sheet">\n'
        )
        fh.write(
            f'<section class="cover">\n<h1>{escape(title)}</h1>\n'
            f"<p>{escape(t('q.intro', lang, csv=QUESTIONS_CSV_PATH))}</p>\n"
            f'<p class="notice">{escape(t("cover.notice", lang))}</p>\n</section>\n'
        )
        fh.write(f"<h2>{escape(t('q.clean_title', lang))}</h2>\n")
        fh.write(
            _table(
                (t("q.col_item", lang), t("q.col_count", lang)),
                question_clean_rows(stats, lang),
                t("q.clean_title", lang),
            )
        )
        loops = question_loop_rows(stats)
        if loops:
            fh.write(f"<h2>{escape(t('q.loop_title', lang))}</h2>\n")
            fh.write(_table([t(key, lang) for key in QUESTION_LOOP_HEADERS], loops, t("q.loop_title", lang)))
            fh.write(f"<p>{escape(t('q.loop_note', lang))}</p>\n")
        if not model.questions:
            fh.write(f"<p>{escape(t('q.none', lang))}</p>\n</div>\n</body>\n</html>\n")
            return path
        headers, rows = question_month_table(stats, lang)
        fh.write(f"<h2>{escape(t('q.period_title', lang))}</h2>\n")
        fh.write(_table(headers, rows, t("q.period_title", lang)))
        topics = question_topic_rows(model.questions, stats, lang)
        if topics:
            fh.write(f"<h2>{escape(t('q.topic_title', lang))}</h2>\n")
            fh.write(
                _table(
                    (t("q.col_topic", lang), t("q.col_count", lang), t("q.col_example", lang)),
                    topics,
                    t("q.topic_title", lang),
                )
            )
            fh.write(f"<p>{escape(t('q.topic_note', lang))}</p>\n")
        fh.write(f'<nav class="toc" aria-label="{escape(t("q.days_title", lang))}">\n')
        fh.write(f"<h2>{escape(t('q.days_title', lang))}</h2>\n")
        for day, items in days.items():
            label = t("q.day", lang, date=day or t("q.undated", lang), n=len(items))
            fh.write(f'<p class="l2"><a href="#{anchors[day]}">{escape(label)}</a></p>\n')
        fh.write("</nav>\n")
        fh.write(f"<h2>{escape(t('q.list_title', lang))}</h2>\n")
        for day, items in days.items():
            label = t("q.day", lang, date=day or t("q.undated", lang), n=len(items))
            fh.write(f'<h3 class="machine" id="{anchors[day]}">{escape(label)}</h3>\n')
            fh.writelines(_question(q, lang) for q in items)
        fh.write("</div>\n</body>\n</html>\n")
    return path


def render_prompts_volume(model: ReportModel, out_path: Path | str) -> Path:
    """Write the companion volume `prompts.html` and return its path."""
    lang = str(model.case.get("lang") or DEFAULT_LANG)
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    number = str(model.case.get("document_number") or "")
    title = t("vol.title", lang)
    css = (
        environment()
        .get_template("report.css.j2")
        .render(doc=SimpleNamespace(header_text=f"{t('header.text', lang, doc=number)} - {title}"))
    )
    tree = _tree(model)
    _assign_anchors(tree)
    messages = len(model.ai_queries)
    with path.open("w", encoding="utf-8") as fh:
        fh.write(
            f'<!DOCTYPE html>\n<html lang="{lang}">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{escape(title)} - {escape(str(model.case.get('number') or ''))}</title>\n"
            f'<style>\n{css}{_EXTRA_CSS}</style>\n</head>\n<body>\n<div class="sheet">\n'
        )
        fh.write(
            f'<section class="cover">\n<h1>{escape(title)}</h1>\n'
            f"<p>{escape(t('vol.intro', lang, m=messages, i=len(model.instructions)))}</p>\n"
            f'<p class="notice">{escape(t("cover.notice", lang))}</p>\n</section>\n'
        )
        if not tree and not model.generated_files:
            fh.write(f"<p>{escape(t('vol.none', lang))}</p>\n")
        else:
            fh.writelines(_toc(tree, lang, bool(model.generated_files)))
            fh.writelines(_body(tree, lang))
            if model.generated_files:
                fh.writelines(_generated(model, lang))
        fh.write("</div>\n</body>\n</html>\n")
    return path
