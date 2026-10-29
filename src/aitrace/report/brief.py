"""Plain-language review brief for audit and legal readers, built from the same model as the appraisal.

The appraisal (report.pdf) follows the examiner's order: method, evidence, findings. Reviewers who are not
forensic examiners need the reverse: the answer first, then who, when, what was asked, what came of it, and
whether the material can stand as evidence. Every number here is taken from the model the appraisal uses.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import date
from typing import Any

from aitrace.report.i18n import STRINGS, t
from aitrace.report.layout import Builder, Document, cover_rows
from aitrace.report.model import (
    AI_INPUTS_CSV_PATH,
    QUESTIONS_CSV_PATH,
    QUESTIONS_VOLUME_PATH,
    SENSITIVE_TASKS,
    ReportModel,
)
from aitrace.report.questions import FACT_KINDS, mask_sensitive

BRIEF_PDF_PATH = "report/brief.pdf"
BRIEF_DOCX_PATH = "report/brief.docx"
EXAMPLE_CHARS = 100
FLAGGED_CHARS = 200
FLAGGED_CAP = 15
FACT_CAP = 10
TOP_TOPICS = 3
WORK_HOURS = range(9, 18)
# Chapter numbers of the appraisal, in the order layout._build_document emits them.
APPRAISAL_CHAPTERS = {"overview": 1, "timeline": 3, "prompts": 4, "generated": 5, "limits": 8}
PASTED_CHARS = 400
# Openings of terminal sessions, file/url mentions and tool output that a person pasted rather than wrote.
_PASTED_START = re.compile(
    r"^(?:PS [A-Za-z]:|\(venv\)|[\w.-]+@[\w.-]+:|\$ |json:|---|\[You can examine|@url:|@file:|```)"
)
AI_KINDS = ("a2a", "subagent", "automated")
OTHER_KINDS = ("loop", "system_notice", "compaction", "empty")


def build_brief_document(model: ReportModel) -> Document:
    lang = model.lang
    b = Builder(lang)
    _conclusion(b, model)
    _when(b, model)
    _who(b, model)
    _what(b, model)
    _results(b, model)
    _evidence(b, model)
    _terms(b)
    _where(b)
    base = str(model.case.get("document_number") or f"{model.case.get('number') or ''}-01")
    number = t("brief.doc_number", lang, doc=base)
    cover = [(k, number if k == t("cover.document_number", lang) else v) for k, v in cover_rows(model, lang)]
    return Document(
        lang=lang,
        title=t("brief.title", lang),
        header_text=t("header.text", lang, doc=number),
        cover=cover,
        notice=t("brief.notice", lang),
        blocks=b.blocks,
    )


def _n(value: Any) -> str:
    return f"{int(value or 0):,}"


def _one_line(text: Any, limit: int) -> str:
    flat = " ".join(mask_sensitive(str(text or "")).split())
    return flat if len(flat) <= limit else flat[:limit].rstrip() + "…"


def _label(key: str, lang: str, fallback: str) -> str:
    return t(key, lang) if key in STRINGS.get(lang, STRINGS["en"]) else fallback


def _channel(channel: str, lang: str) -> str:
    return _label(f"q.ch.{channel or '-'}", lang, channel)


def _pasted(text: Any) -> bool:
    body = str(text or "").strip()
    return len(body) > PASTED_CHARS or "\\u" in body or bool(_PASTED_START.match(body))


def _appraisal(name: str, lang: str) -> str:
    return t("brief.appraisal_ref", lang, n=APPRAISAL_CHAPTERS[name], title=t(f"chapter.{name}", lang))


def _per_machine(questions: Sequence[Mapping[str, Any]]) -> list[tuple[str, int, str, str, str]]:
    """(machine, inputs, first date, last date, most used channel), busiest machine first."""
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for q in questions:
        groups.setdefault(str(q.get("machine") or "-"), []).append(q)
    rows = []
    for machine, items in groups.items():
        dates = sorted(str(q["date"]) for q in items if q.get("date"))
        channel = Counter(str(q.get("channel") or "") for q in items).most_common(1)[0][0]
        rows.append((machine, len(items), dates[0] if dates else "", dates[-1] if dates else "", channel))
    return sorted(rows, key=lambda r: (-r[1], r[0]))


def _flagged(questions: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Flagged inputs, the ones a person wrote as sentences before pasted logs, each group in time order."""
    hits = [q for q in questions if set(q.get("topics") or ()) & set(SENSITIVE_TASKS)]
    return sorted(hits, key=lambda q: (_pasted(q.get("text")), bool(q.get("denial")), int(q.get("no") or 0)))


def _topic_count(stats: Mapping[str, Any], topic: str) -> int:
    return int((stats.get("topics") or {}).get(topic) or 0)


def _conclusion(b: Builder, model: ReportModel) -> None:
    lang = b.lang
    stats = model.question_stats
    excluded = stats.get("excluded") or {}
    b.chapter(t("brief.ch.conclusion", lang))
    b.para(t("brief.conclusion_intro", lang))
    rows: list[tuple[str, str]] = []

    tools = [str(a.get("tool")) for a in model.ai_tools if a.get("tool")]
    if tools:
        firsts = sorted(
            str(a.get("first_seen_local") or "")[:10] for a in model.ai_tools if a.get("first_seen_local")
        )
        lasts = sorted(
            str(a.get("last_seen_local") or "")[:10] for a in model.ai_tools if a.get("last_seen_local")
        )
        used = t(
            "brief.a.used",
            lang,
            tools=", ".join(dict.fromkeys(tools)),
            first=firsts[0] if firsts else "-",
            last=lasts[-1] if lasts else "-",
        )
    else:
        used = t("brief.a.not_used", lang)
    rows.append((t("brief.q.used", lang), used))

    machines = _per_machine(model.questions)
    if machines:
        listed = ", ".join(t("brief.machine_count", lang, machine=m, n=_n(n)) for m, n, *_ in machines)
        rows.append((t("brief.q.devices", lang), t("brief.a.devices", lang, n=len(machines), list=listed)))
    else:
        rows.append((t("brief.q.devices", lang), t("brief.a.no_devices", lang)))

    rows.append(
        (
            t("brief.q.human", lang),
            t(
                "brief.a.human",
                lang,
                human=_n(stats.get("human")),
                raw=_n(stats.get("raw")),
                ai=_n(sum(int(excluded.get(k) or 0) for k in AI_KINDS)),
                other=_n(sum(int(excluded.get(k) or 0) for k in OTHER_KINDS)),
                dup=_n(stats.get("duplicates")),
            ),
        )
    )

    topics = [(k, v) for k, v in (stats.get("topics") or {}).items() if k not in SENSITIVE_TASKS][:TOP_TOPICS]
    if topics:
        top = ", ".join(t("brief.topic_count", lang, label=t(f"flag.{k}", lang), n=_n(v)) for k, v in topics)
        classified = sum(1 for q in model.questions if q.get("topics"))
        topic_answer = t("brief.a.topics", lang, top=top, rest=_n(len(model.questions) - classified))
    else:
        topic_answer = t("brief.a.no_topics", lang)
    rows.append((t("brief.q.topics", lang), topic_answer))

    security = _topic_count(stats, "TASK-SECURITY")
    exfil_q = _topic_count(stats, "TASK-EXFIL")
    if security or exfil_q:
        denials = sum(1 for q in _flagged(model.questions) if q.get("denial"))
        flagged = t("brief.a.flagged", lang, security=_n(security), exfil=_n(exfil_q), denial=_n(denials))
    else:
        flagged = t("brief.a.no_flagged", lang)
    rows.append((t("brief.q.flagged", lang), flagged))
    facts = stats.get("facts") or {}
    if any(facts.get(kind) for kind in FACT_KINDS):
        found = t("brief.a.facts", lang, **{kind: _n(facts.get(kind)) for kind in FACT_KINDS})
    else:
        found = t("brief.a.no_facts", lang)
    rows.append((t("brief.q.facts", lang), found))

    generated = len(model.generated_files)
    rows.append(
        (
            t("brief.q.generated", lang),
            t("brief.a.generated", lang, n=_n(generated)) if generated else t("brief.a.no_generated", lang),
        )
    )
    rows.append(
        (
            t("brief.q.exfil", lang),
            t("brief.a.exfil", lang, n=_n(len(model.exfil))) if model.exfil else t("brief.a.no_exfil", lang),
        )
    )
    rows.append((t("brief.q.integrity", lang), _integrity(model, lang)))
    b.table((t("brief.col.question", lang), t("brief.col.answer", lang)), rows, (3, 7), label_first=True)


def _integrity(model: ReportModel, lang: str) -> str:
    statuses = [str(ev.get("verification_status") or "") for ev in model.evidence]
    if not statuses:
        return t("brief.a.no_evidence", lang)
    if all(s == "match" for s in statuses):
        return t("brief.a.integrity_ok", lang, n=len(statuses))
    bad = sum(1 for s in statuses if s != "match")
    return t("brief.a.integrity_bad", lang, n=len(statuses), bad=bad)


def _who(b: Builder, model: ReportModel) -> None:
    lang = b.lang
    stats = model.question_stats
    excluded = stats.get("excluded") or {}
    b.chapter(t("brief.ch.who", lang))
    b.para(t("brief.who_intro", lang))
    b.section(t("brief.sec.split", lang))
    rows = [(t("brief.split.human", lang), t("brief.rule.human", lang), _n(stats.get("human")))]
    for kind in ("a2a", "subagent", "automated", "loop"):
        rows.append((t(f"brief.split.{kind}", lang), t(f"brief.rule.{kind}", lang), _n(excluded.get(kind))))
    notices = int(excluded.get("system_notice") or 0) + int(excluded.get("compaction") or 0)
    rows.append((t("brief.split.notice", lang), t("brief.rule.notice", lang), _n(notices)))
    if excluded.get("empty"):
        rows.append((t("brief.split.empty", lang), t("brief.rule.empty", lang), _n(excluded.get("empty"))))
    rows.append((t("brief.split.dup", lang), t("brief.rule.dup", lang), _n(stats.get("duplicates"))))
    rows.append((t("brief.split.total", lang), "", _n(stats.get("raw"))))
    b.table(
        (t("brief.col.kind", lang), t("brief.col.rule", lang), t("brief.col.count", lang)),
        rows,
        (3, 6, 2),
    )
    b.section(t("brief.sec.devices", lang))
    machines = _per_machine(model.questions)
    if machines:
        b.table(
            (
                t("brief.col.device", lang),
                t("brief.col.period", lang),
                t("brief.col.human_inputs", lang),
                t("brief.col.channel", lang),
            ),
            [
                (m, f"{first} ~ {last}" if first != last else first, _n(n), _channel(ch, lang))
                for m, n, first, last, ch in machines
            ],
            (3, 4, 2, 2),
        )
    else:
        b.para(t("brief.a.no_devices", lang))
    b.para(t("brief.note_mark", lang) + t("brief.who_caveat", lang))


def _when(b: Builder, model: ReportModel) -> None:
    lang = b.lang
    questions = model.questions
    b.chapter(t("brief.ch.when", lang))
    days = Counter(str(q["date"]) for q in questions if q.get("date"))
    if not days:
        b.para(t("brief.a.no_devices", lang))
        return
    busiest, busiest_n = max(days.items(), key=lambda kv: (kv[1], kv[0]))
    ordered = sorted(days)
    b.para(
        t(
            "brief.when_intro",
            lang,
            first=ordered[0],
            last=ordered[-1],
            days=len(days),
            avg=_n(round(sum(days.values()) / len(days))),
            busiest=busiest,
            busiest_n=_n(busiest_n),
        )
    )
    b.section(t("brief.sec.months", lang))
    rows = []
    for month, per_machine in sorted((model.question_stats.get("by_month") or {}).items()):
        top, top_n = max(per_machine.items(), key=lambda kv: (kv[1], kv[0])) if per_machine else ("-", 0)
        rows.append(
            (month, _n(sum(per_machine.values())), t("brief.machine_count", lang, machine=top, n=_n(top_n)))
        )
    b.table(
        (t("brief.col.month", lang), t("brief.col.human_inputs", lang), t("brief.col.top_device", lang)),
        rows,
        (2, 2, 5),
    )
    b.section(t("brief.sec.hours", lang))
    buckets = Counter(_hour_bucket(q) for q in questions)
    total = sum(buckets.values()) or 1
    b.table(
        (t("brief.col.hours", lang), t("brief.col.count", lang), t("brief.col.share", lang)),
        [
            (
                t(f"brief.hours.{name}", lang),
                _n(buckets.get(name)),
                f"{100 * buckets.get(name, 0) / total:.1f}%",
            )
            for name in ("work", "after", "weekend", "unknown")
            if name != "unknown" or buckets.get("unknown")
        ],
        (5, 2, 2),
    )
    b.para(t("brief.note_mark", lang) + t("brief.hours_note", lang))


def _hour_bucket(q: Mapping[str, Any]) -> str:
    local = str(q.get("ts_local") or "")
    try:
        day = date.fromisoformat(local[:10])
        hour = int(local[11:13])
    except ValueError:
        return "unknown"
    if day.weekday() >= 5:
        return "weekend"
    return "work" if hour in WORK_HOURS else "after"


def _example(q: Mapping[str, Any], lang: str, limit: int) -> str:
    return t(
        "brief.example",
        lang,
        no=q.get("no"),
        when=str(q.get("ts_local") or "")[:16],
        machine=q.get("machine") or "-",
        text=_one_line(q.get("text"), limit),
    )


def _what(b: Builder, model: ReportModel) -> None:
    lang = b.lang
    stats = model.question_stats
    b.chapter(t("brief.ch.what", lang))
    b.para(t("brief.what_intro", lang, volume=QUESTIONS_VOLUME_PATH))
    b.section(t("brief.sec.topics", lang))
    topics = list((stats.get("topics") or {}).items())
    if topics:
        rows = []
        used: set[Any] = set()
        for topic, count in topics:
            matches = [q for q in model.questions if topic in (q.get("topics") or ())]
            fresh = [q for q in matches if q.get("no") not in used]
            first = next(
                (q for q in fresh if not _pasted(q.get("text")) and not q.get("denial")),
                next(iter(fresh or matches), None),
            )
            if first is not None:
                used.add(first.get("no"))
            rows.append(
                (t(f"flag.{topic}", lang), _n(count), _example(first, lang, EXAMPLE_CHARS) if first else "-")
            )
        b.table(
            (t("brief.col.topic", lang), t("brief.col.count", lang), t("brief.col.example", lang)),
            rows,
            (2, 1, 7),
        )
    else:
        b.para(t("brief.a.no_topics", lang))
    _facts(b, model)
    b.section(t("brief.sec.flagged", lang))
    flagged = _flagged(model.questions)
    if not flagged:
        b.para(t("brief.a.no_flagged", lang))
        return
    unique: dict[str, list[Mapping[str, Any]]] = {}
    for q in flagged:
        unique.setdefault(" ".join(str(q.get("text") or "").split()), []).append(q)
    shown = list(unique.values())[:FLAGGED_CAP]
    b.para(t("brief.flagged_intro", lang, n=_n(len(flagged)), shown=len(shown), csv=QUESTIONS_CSV_PATH))
    rows = []
    for same in shown:
        q = same[0]
        where = t(
            "brief.no_when_device",
            lang,
            no=q.get("no"),
            when=str(q.get("ts_local") or "")[:16],
            machine=q.get("machine") or "-",
        )
        if len(same) > 1:
            where += "\n" + t("brief.repeat", lang, n=len(same))
        topics = ", ".join(t(f"flag.{k}", lang) for k in q.get("topics") or () if k in SENSITIVE_TASKS)
        if q.get("denial"):
            topics += "\n" + t("brief.denial", lang)
        rows.append((where, topics, _one_line(q.get("text"), FLAGGED_CHARS)))
    b.table(
        (t("brief.col.no_when_device", lang), t("brief.col.topic", lang), t("brief.col.input", lang)),
        rows,
        (3, 2, 7),
    )


def _where_cell(q: Mapping[str, Any], lang: str, repeats: int) -> str:
    where = t(
        "brief.no_when_device",
        lang,
        no=q.get("no"),
        when=str(q.get("ts_local") or "")[:16],
        machine=q.get("machine") or "-",
    )
    return where + ("\n" + t("brief.repeat", lang, n=repeats) if repeats > 1 else "")


def _facts(b: Builder, model: ReportModel) -> None:
    lang = b.lang
    b.section(t("brief.sec.facts", lang))
    if not any(q.get("facts") for q in model.questions):
        b.para(t("brief.a.no_facts", lang))
        return
    b.para(t("brief.facts_intro", lang, volume=QUESTIONS_VOLUME_PATH, csv=QUESTIONS_CSV_PATH))
    for kind in FACT_KINDS:
        hits = [q for q in model.questions if kind in (q.get("facts") or ())]
        if not hits:
            continue
        hits.sort(key=lambda q: (_pasted(q.get("text")), int(q.get("no") or 0)))
        unique: dict[str, list[Mapping[str, Any]]] = {}
        for q in hits:
            unique.setdefault(" ".join(str(q.get("text") or "").split()), []).append(q)
        shown = list(unique.values())[:FACT_CAP]
        b.sub(t(f"brief.fact.{kind}", lang))
        b.para(t("brief.fact_count", lang, n=_n(len(hits)), shown=len(shown)))
        b.table(
            (t("brief.col.no_when_device", lang), t("brief.col.input", lang)),
            [
                (_where_cell(same[0], lang, len(same)), _one_line(same[0].get("text"), FLAGGED_CHARS))
                for same in shown
            ],
            (3, 8),
        )


def _results(b: Builder, model: ReportModel) -> None:
    lang = b.lang
    b.chapter(t("brief.ch.results", lang))
    kinds = Counter(str(g.get("output_kind") or "-") for g in model.generated_files)
    rows = [
        (
            _label(f"brief.kind.{kind}", lang, kind),
            _n(n),
            _label(f"brief.kind_note.{kind}", lang, ""),
        )
        for kind, n in kinds.most_common()
    ]
    rows.append((t("brief.res.jobs", lang), _n(len(model.generated_jobs)), t("brief.res.jobs_note", lang)))
    rows.append((t("brief.res.files", lang), _n(len(model.file_lifecycle)), t("brief.res.files_note", lang)))
    rows.append((t("brief.res.exfil", lang), _n(len(model.exfil)), t("brief.res.exfil_note", lang)))
    b.table(
        (t("brief.col.kind", lang), t("brief.col.count", lang), t("brief.col.meaning", lang)), rows, (3, 1, 6)
    )
    b.para(t("brief.results_ref", lang, ref=_appraisal("generated", lang)))


def _evidence(b: Builder, model: ReportModel) -> None:
    lang = b.lang
    b.chapter(t("brief.ch.evidence", lang))
    b.para(t("brief.evidence_intro", lang))
    subjects = ", ".join(
        str(ev.get("path") or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] for ev in model.evidence
    )
    folders = any(ev.get("kind") == "dir" for ev in model.evidence)
    rows = [
        (t("brief.ev.integrity", lang), _integrity(model, lang), t("brief.ev.integrity_more", lang)),
        (
            t("brief.ev.identity", lang),
            t(
                "brief.ev.identity_dir" if folders else "brief.ev.identity_image",
                lang,
                subjects=subjects or "-",
            ),
            t("brief.ev.identity_more", lang),
        ),
        (
            t("brief.ev.method", lang),
            t("brief.ev.method_state", lang, version=model.tools.get("aitrace_version") or "-"),
            t("brief.ev.method_more", lang, ref=_appraisal("overview", lang)),
        ),
        (
            t("brief.ev.custody", lang),
            t("brief.ev.custody_state", lang, n=len(model.custody)),
            t("brief.ev.custody_more", lang),
        ),
        (t("brief.ev.actor", lang), t("brief.ev.actor_state", lang), t("brief.ev.actor_more", lang)),
        (
            t("brief.ev.dispute", lang),
            t("brief.ev.dispute_state", lang),
            t("brief.ev.dispute_more", lang, ref=_appraisal("limits", lang)),
        ),
    ]
    b.table(
        (t("brief.col.check", lang), t("brief.col.state", lang), t("brief.col.more", lang)),
        rows,
        (2, 4, 4),
        label_first=True,
    )
    b.para(t("brief.note_mark", lang) + t("brief.evidence_law", lang))


def _terms(b: Builder) -> None:
    lang = b.lang
    b.chapter(t("brief.ch.terms", lang))
    names = ("agent", "prompt", "session", "channel", "subagent", "a2a", "cron", "hash")
    b.table(
        (t("brief.col.term", lang), t("brief.col.meaning", lang)),
        [(t(f"brief.term.{n}", lang), t(f"brief.term.{n}.def", lang)) for n in names],
        (2, 7),
        label_first=True,
    )


def _where(b: Builder) -> None:
    lang = b.lang
    b.chapter(t("brief.ch.where", lang))
    rows = [
        (t("brief.where.human", lang), f"{QUESTIONS_VOLUME_PATH}, {QUESTIONS_CSV_PATH}"),
        (
            t("brief.where.ai", lang),
            t("brief.where.ai_at", lang, volume=QUESTIONS_VOLUME_PATH, csv=AI_INPUTS_CSV_PATH),
        ),
        (t("brief.where.chat", lang), t("brief.where.chat_at", lang, ref=_appraisal("prompts", lang))),
        (t("brief.where.generated", lang), _appraisal("generated", lang)),
        (
            t("brief.where.timeline", lang),
            t("brief.where.timeline_at", lang, ref=_appraisal("timeline", lang)),
        ),
        (t("brief.where.custody", lang), t("brief.where.custody_at", lang)),
    ]
    b.table((t("brief.col.want", lang), t("brief.col.look", lang)), rows, (4, 6), label_first=True)
