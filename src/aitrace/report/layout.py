"""Format-neutral report document: the chapter structure shared by the HTML, PDF and DOCX renderers."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from aitrace.core.time import fmt_local, fmt_utc, from_iso
from aitrace.report.i18n import t
from aitrace.report.model import (
    AI_QUERIES_CSV_PATH,
    COLUMNS,
    EXCERPT_CHARS,
    EXCERPT_DENSE_CHARS,
    EXCERPT_DENSE_ROWS,
    MACHINE_ROW_CAP,
    PROMPT_ROW_CAP,
    PROMPTS_VOLUME_PATH,
    REPORT_JSON_PATH,
    SESSION_ROW_CAP,
    SHA_PREFIX_CHARS,
    TIMELINE_CHAT_DAY_THRESHOLD,
    TIMELINE_COMPACT_ROWS,
    TIMELINE_CSV_PATH,
    TIMELINE_LIMIT_PDF_DOCX,
    TIMELINE_SOURCE_CHARS,
    TIMELINE_SUMMARY_CHARS,
    TOOL_CALL_ROW_CAP,
    ReportModel,
    text_sha256,
)

KO_LETTERS = "가나다라마바사아자차카타파하"
EN_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MAX_TOOL_NAMES = 8
CHANNEL_ARROW = " \u2192 "

WRITE_NAME = re.compile(r"write|edit|patch|create|delete|remove|unlink|rename|move|save|append|truncate|mkdir|\brm\b", re.IGNORECASE)
TRANSFER_COMMAND = re.compile(
    r"\b(scp|sftp|rsync|rclone|curl|wget|ssh|ftp|ncat|socat|nc|aws\s+s3|gsutil|git\s+push|rm|del)\b", re.IGNORECASE
)
LIMIT_SECTIONS: tuple[str, ...] = ("plugins", "warnings", "undecoded", "findings", "caveats")
LANDSCAPE_CHAPTERS: frozenset[str] = frozenset({"timeline", "exports"})


@dataclass(frozen=True, slots=True)
class Heading:
    level: int  # 1 chapter / annex, 2 "1.", 3 "가.", 4 "1)"
    number: str
    text: str
    anchor: str
    landscape: bool = False
    toc: bool = True


@dataclass(frozen=True, slots=True)
class Para:
    text: str


@dataclass(frozen=True, slots=True)
class Table:
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    weights: tuple[int, ...]
    raw: frozenset[int] = frozenset()  # columns holding recovered text, reproduced verbatim
    caption: str = ""
    label_first: bool = False  # key/value table whose first column labels the row
    compact: bool = False  # long table: renderers may use smaller type


Block = Heading | Para | Table


@dataclass(slots=True)
class Document:
    lang: str
    title: str
    header_text: str
    cover: list[tuple[str, str]]
    notice: str
    blocks: list[Block] = field(default_factory=list)

    def toc(self) -> list[Heading]:
        return [b for b in self.blocks if isinstance(b, Heading) and b.toc and b.level <= 2]


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Mapping):
        return "\n".join(f"{k}: {_text(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return "\n".join(_text(v) for v in value)
    return str(value)


def _lookup(key: str, lang: str, fallback: str) -> str:
    try:
        return t(key, lang)
    except KeyError:
        return fallback


def _detail(value: Any, lang: str) -> str:
    if isinstance(value, Mapping):
        return "\n".join(
            f"{_lookup(f'custody.key.{k}', lang, str(k))}: {_detail(v, lang)}" for k, v in value.items()
        )
    if isinstance(value, (list, tuple)):
        return "\n".join(_detail(v, lang) for v in value)
    return _text(value)


def _utc(value: Any) -> str:
    parsed = from_iso(value) if isinstance(value, str) else None
    return fmt_utc(parsed) if parsed is not None else _text(value)


def _basename(path: Any) -> str:
    return str(path or "").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


class _Builder:
    def __init__(self, lang: str) -> None:
        self.lang = lang
        self.blocks: list[Block] = []
        self._chapter = 0
        self._annex = 0
        self._sec = 0
        self._sub = 0
        self._subsub = 0
        self._anchors = 0

    def _anchor(self) -> str:
        self._anchors += 1
        return f"h{self._anchors}"

    def chapter(self, title: str, *, landscape: bool = False) -> None:
        self._chapter += 1
        self._sec = self._sub = self._subsub = 0
        label = t("chapter.label", self.lang, n=self._chapter)
        self.blocks.append(Heading(1, label, title, self._anchor(), landscape))

    def annex(self, title: str, *, landscape: bool = False) -> None:
        self._annex += 1
        self._sec = self._sub = self._subsub = 0
        label = t("annex.label", self.lang, n=self._annex)
        self.blocks.append(Heading(1, label, title, self._anchor(), landscape))

    def section(self, title: str, *, toc: bool = True) -> None:
        self._sec += 1
        self._sub = self._subsub = 0
        self.blocks.append(Heading(2, f"{self._sec}.", title, self._anchor(), toc=toc))

    def sub(self, title: str, *, toc: bool = False) -> None:
        letters = KO_LETTERS if self.lang == "ko" else EN_LETTERS
        letter = letters[self._sub % len(letters)]
        self._sub += 1
        self._subsub = 0
        self.blocks.append(Heading(3, f"{letter}.", title, self._anchor(), toc=toc))

    def subsub(self, title: str) -> None:
        self._subsub += 1
        self.blocks.append(Heading(4, f"{self._subsub})", title, self._anchor(), toc=False))

    def para(self, text: str) -> None:
        self.blocks.append(Para(text))

    def table(
        self,
        headers: Sequence[str],
        rows: Sequence[Sequence[str]],
        weights: Sequence[int],
        *,
        raw: Sequence[int] = (),
        caption: str = "",
        label_first: bool = False,
        compact: bool = False,
    ) -> None:
        self.blocks.append(
            Table(
                tuple(headers),
                tuple(tuple(c for c in row) for row in rows),
                tuple(weights),
                frozenset(raw),
                caption,
                label_first,
                compact,
            )
        )

    def kv(self, rows: Sequence[tuple[str, str]]) -> None:
        shown = [(k, v) for k, v in rows if v != ""]
        self.table((t("table.item", self.lang), t("table.value", self.lang)), shown, (2, 5), label_first=True)


def _numbered(items: Sequence[str]) -> list[str]:
    return [f"{i}. {item}" for i, item in enumerate(items, start=1)]


def _cite(lang: str, *refs: str) -> str:
    return f". ({t('ref.prefix', lang)}{', '.join(refs)})"


def _section_ref(lang: str, chapter: int, section: str) -> str:
    return t("ref.section", lang, n=chapter, s=section)


def _bytes(value: Any, lang: str) -> str:
    if isinstance(value, int):
        return f"{value:,} " + ("바이트" if lang == "ko" else "bytes")
    return _text(value)


def _cover_date(model: ReportModel, lang: str) -> str:
    created = model.run.get("created_utc")
    ts = from_iso(created) if isinstance(created, str) else None
    if ts is None:
        return ""
    day = fmt_local(ts, str(model.case.get("timezone") or "UTC")).split(" ", 1)[0]
    if lang != "ko":
        return day
    year, month, date = day.split("-")
    return f"{year}년 {int(month)}월 {int(date)}일"


def _cover(model: ReportModel, lang: str) -> list[tuple[str, str]]:
    case = model.case
    number = str(case.get("number") or "")
    subject = ", ".join(_basename(ev.get("path")) for ev in model.evidence if ev.get("path"))
    return [
        (t("cover.case_number", lang), number),
        (t("cover.document_number", lang), str(case.get("document_number") or f"{number}-01")),
        (t("cover.subject", lang), subject or "-"),
        (t("cover.client", lang), str(case.get("organisation") or t("cover.not_stated", lang))),
        (t("cover.author", lang), str(case.get("examiner") or "")),
        (t("cover.date", lang), _cover_date(model, lang)),
    ]


def _users(ev: Mapping[str, Any]) -> str:
    return ", ".join(str(u.get("name")) for u in ev.get("users") or [] if u.get("name"))


def _volumes(ev: Mapping[str, Any]) -> str:
    parts = []
    for vol in ev.get("volumes") or []:
        label = f" {vol['label']}" if vol.get("label") else ""
        parts.append(f"{vol.get('index')}: {vol.get('fs_type') or ''}{label}".strip())
    return "\n".join(parts)


def _os_names(ev: Mapping[str, Any]) -> str:
    return ", ".join(dict.fromkeys(str(v.get("os_family")) for v in ev.get("volumes") or [] if v.get("os_family")))


def _hash_rows(ev: Mapping[str, Any], lang: str) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    if ev.get("media_sha256"):
        rows.append((t("hash.media", lang), "SHA-256", str(ev["media_sha256"])))
    for algorithm, value in (ev.get("acquisition_hashes") or {}).items():
        rows.append((t("hash.acquisition", lang), str(algorithm).upper(), str(value)))
    for name, hashes in (ev.get("segment_hashes") or {}).items():
        for algorithm in ("md5", "sha1", "sha256"):
            if hashes.get(algorithm):
                rows.append((str(name), algorithm.upper().replace("SHA", "SHA-"), str(hashes[algorithm])))
    return rows


def _overview(b: _Builder, model: ReportModel) -> None:
    lang = b.lang
    case = model.case
    b.chapter(t("chapter.overview", lang))

    b.section(t("sec.subject", lang))
    rows = [
        (t("label.case_number", lang), str(case.get("number") or "")),
        (t("label.case_name", lang), str(case.get("name") or "")),
        (t("subject.client", lang), str(case.get("organisation") or t("cover.not_stated", lang))),
        (t("label.examiner", lang), str(case.get("examiner") or "")),
        (t("label.timezone", lang), str(case.get("timezone") or "")),
        (t("subject.target", lang), "\n".join(_basename(ev.get("path")) for ev in model.evidence)),
        (t("subject.os", lang), ", ".join(filter(None, (_os_names(ev) for ev in model.evidence)))),
        (t("subject.volumes", lang), "\n".join(filter(None, (_volumes(ev) for ev in model.evidence)))),
        (t("subject.users", lang), ", ".join(filter(None, (_users(ev) for ev in model.evidence)))),
        (t("label.notes", lang), str(case.get("notes") or "")),
    ]
    b.kv(rows)

    b.section(t("sec.evidence", lang))
    if not model.evidence:
        b.para(t("evidence.none", lang))
    for ev in model.evidence:
        b.sub(_basename(ev.get("path")) or str(ev.get("id") or ""))
        b.kv(
            [
                (t("label.evidence_id", lang), _text(ev.get("id"))),
                (t("label.evidence_path", lang), _text(ev.get("path"))),
                (t("label.evidence_kind", lang), _text(ev.get("kind"))),
                (t("label.size", lang), _bytes(ev.get("size"), lang)),
                (t("label.verification", lang), _text(ev.get("verification_label"))),
                (t("col.limitations", lang), _text(ev.get("limitations_display", ev.get("limitations")))),
            ]
        )
        hashes = _hash_rows(ev, lang)
        if hashes:
            b.table(
                (t("hash.target", lang), t("hash.algorithm", lang), t("hash.value", lang)),
                hashes,
                (4, 2, 9),
            )
        b.para(t("evidence.verdict", lang, label=_text(ev.get("verification_label"))))

    b.section(t("sec.environment", lang))
    tools = model.tools
    dissect = ", ".join(f"{name} {version}" for name, version in (tools.get("dissect") or {}).items())
    b.kv(
        [
            (t("label.aitrace_version", lang), _text(tools.get("aitrace_version"))),
            (t("label.python", lang), _text(tools.get("python"))),
            (t("env.dissect", lang), dissect),
            (t("label.os", lang), _text(tools.get("os"))),
        ]
    )
    if model.methodology.get("tool_validation"):
        b.para(_text(model.methodology["tool_validation"]))

    b.section(t("sec.method", lang))
    b.sub(t("sec.procedure", lang))
    for paragraph in model.methodology.get("paragraphs") or []:
        b.para(_text(paragraph))
    b.sub(t("sec.standards", lang))
    for i, standard in enumerate(model.methodology.get("standards") or [], start=1):
        b.para(f"{i}) {standard}")


@dataclass(frozen=True, slots=True)
class _Facts:
    evidence_n: int
    match: int
    mismatch: int
    unverified: int
    tool_names: list[str]
    system: int
    user: int
    assistant: int
    calls: int
    generated: dict[str, int]
    timeline_n: int
    first: str
    last: str
    ai_events: int
    changes: int
    deleted: int
    channels: list[str]
    undecoded: int
    warnings: int


def _facts(model: ReportModel) -> _Facts:
    status = [str(ev.get("verification_status") or "") for ev in model.evidence]
    roles = [str(q.get("role")) for q in model.ai_queries]
    stamps = [str(r["ts_local"]) for r in model.timeline if r.get("ts_local")]
    channels = dict.fromkeys(
        _channel(r["display_channel"], model.lang).split(",", 1)[0] for r in model.exfil if r.get("display_channel")
    )
    verdicts = [str(g["verdict"]) for g in model.generated_files]
    recycled = sum(
        1
        for row in model.file_lifecycle
        if any(step.get("event") in ("deleted", "recycled") for step in row.get("data", {}).get("lifecycle") or [])
    )
    return _Facts(
        evidence_n=len(model.evidence),
        match=status.count("match"),
        mismatch=status.count("mismatch"),
        unverified=len(status) - status.count("match") - status.count("mismatch"),
        tool_names=list(dict.fromkeys(str(r["tool"]) for r in model.ai_tools if r.get("tool"))),
        system=roles.count("system"),
        user=roles.count("user"),
        assistant=len(roles) - roles.count("system") - roles.count("user"),
        calls=len(model.tool_calls),
        generated={v: verdicts.count(v) for v in ("ai_generated", "ai_assisted", "undetermined")},
        timeline_n=len(model.timeline),
        first=stamps[0] if stamps else "",
        last=stamps[-1] if stamps else "",
        ai_events=sum(1 for r in model.timeline if r.get("actor") == "ai" or r.get("category") == "ai_activity"),
        changes=len(model.file_lifecycle),
        deleted=recycled,
        channels=list(channels),
        undecoded=len(model.coverage.get("not_decoded") or []),
        warnings=len(model.coverage.get("parse_warnings") or []),
    )


def _names(names: Sequence[str]) -> str:
    shown = ", ".join(names[:MAX_TOOL_NAMES])
    return shown + (f" 외 {len(names) - MAX_TOOL_NAMES}종" if len(names) > MAX_TOOL_NAMES else "")


def _statements(model: ReportModel) -> list[str]:
    lang = model.lang
    f = _facts(model)
    out: list[str] = []
    if f.evidence_n:
        out.append(
            t("stmt.evidence", lang, n=f.evidence_n, match=f.match, mismatch=f.mismatch, unverified=f.unverified)
            + _cite(lang, _section_ref(lang, 1, "2."))
        )
    else:
        out.append(t("stmt.evidence_none", lang) + _cite(lang, _section_ref(lang, 1, "2.")))
    tools_ref = t("ref.tools_table", lang)
    if f.tool_names:
        out.append(
            t("stmt.tools", lang, n=len(f.tool_names), names=_names(f.tool_names)) + _cite(lang, tools_ref)
        )
    else:
        out.append(t("stmt.tools_none", lang) + _cite(lang, tools_ref))
    total = len(model.ai_queries)
    if total or f.calls:
        out.append(
            t("stmt.messages", lang, total=total, s=f.system, u=f.user, a=f.assistant, c=f.calls)
            + _cite(lang, t("ref.range", lang, n=3, s1="1.", s2="4."))
        )
    else:
        out.append(t("stmt.messages_none", lang) + _cite(lang, t("ref.chapter", lang, n=3)))
    chapter4 = t("ref.chapter", lang, n=4)
    if model.generated_files:
        g = f.generated
        out.append(
            t(
                "stmt.generated",
                lang,
                n=len(model.generated_files),
                g=g["ai_generated"],
                a=g["ai_assisted"],
                u=g["undetermined"],
            )
            + _cite(lang, chapter4)
        )
    else:
        out.append(t("stmt.generated_none", lang) + _cite(lang, chapter4))
    chapter5 = t("ref.chapter", lang, n=5)
    if f.timeline_n:
        out.append(
            t("stmt.timeline", lang, n=f.timeline_n, first=f.first, last=f.last, ai=f.ai_events)
            + _cite(lang, chapter5)
        )
    else:
        out.append(t("stmt.timeline_none", lang) + _cite(lang, chapter5))
    chapter6 = t("ref.chapter", lang, n=6)
    if f.changes:
        out.append(t("stmt.changes", lang, n=f.changes, d=f.deleted) + _cite(lang, chapter6))
    else:
        out.append(t("stmt.changes_none", lang) + _cite(lang, chapter6))
    chapter7 = t("ref.chapter", lang, n=7)
    if model.exfil:
        out.append(
            t("stmt.transfer", lang, n=len(model.exfil), channels=_names(f.channels)) + _cite(lang, chapter7)
        )
    else:
        out.append(t("stmt.transfer_none", lang) + _cite(lang, chapter7))
    coverage_ref = t("ref.sections", lang, n=8, s1="2.", s2="3.")
    if f.undecoded or f.warnings:
        out.append(t("stmt.coverage", lang, u=f.undecoded, w=f.warnings) + _cite(lang, coverage_ref))
    else:
        out.append(t("stmt.coverage_none", lang) + _cite(lang, coverage_ref))
    return out


def _opinions(model: ReportModel) -> list[str]:
    lang = model.lang
    f = _facts(model)
    evidence_ref = _section_ref(lang, 1, "2.")
    verified = f.evidence_n > 0 and f.match == f.evidence_n
    out = [t("opin.evidence_ok" if verified else "opin.evidence_bad", lang) + _cite(lang, evidence_ref)]
    if f.tool_names:
        out.append(
            t("opin.tools", lang, names=_names(f.tool_names))
            + _cite(lang, t("ref.tools_table", lang), t("ref.range", lang, n=3, s1="1.", s2="4."))
        )
    else:
        out.append(t("opin.tools_none", lang) + _cite(lang, t("ref.tools_table", lang)))
    judged = f.generated["ai_generated"] + f.generated["ai_assisted"]
    if model.generated_files:
        out.append(t("opin.generated", lang, n=judged) + _cite(lang, t("ref.chapter", lang, n=4)))
    else:
        out.append(t("opin.generated_none", lang) + _cite(lang, t("ref.chapter", lang, n=4)))
    out.append(
        t("opin.transfer", lang, n=f.changes, m=len(model.exfil))
        + _cite(lang, t("ref.chapter", lang, n=6), t("ref.chapter", lang, n=7))
    )
    out.append(t("opin.limits", lang) + _cite(lang, t("ref.chapter", lang, n=8)))
    return out


def _tools_table(b: _Builder, model: ReportModel) -> None:
    lang = b.lang
    if not model.ai_tools:
        b.para(t("summary.none", lang))
        return
    spec = COLUMNS["ai_tools"]
    b.table(
        [t(label, lang) for _, label, _ in spec],
        [[_text(row.get(key)) for key, _, _ in spec] for row in model.ai_tools],
        [w for _, _, w in spec],
        caption=t("table.caption_tools", lang),
    )


def tool_label(tool: Any, lang: str) -> str:
    return str(tool) if tool else t("sec.unknown_tool", lang)


def _excerpt(value: Any, limit: int = EXCERPT_CHARS) -> str:
    text = _text(value)
    return text if len(text) <= limit else text[:limit].rstrip() + "\u2026"


def _excerpt_chars(rows: int) -> int:
    return EXCERPT_CHARS if rows <= EXCERPT_DENSE_ROWS else EXCERPT_DENSE_CHARS


def _tail(value: str, limit: int) -> str:
    return value if len(value) <= limit else "\u2026" + value[-(limit - 1) :]


def _stamp(row: Mapping[str, Any]) -> tuple[bool, str]:
    return (row.get("ts_utc") is None, str(row.get("ts_utc") or ""))


def machine_label(row: Mapping[str, Any], meta: Mapping[str, Mapping[str, Any]]) -> str:
    machine = (meta.get(str(row.get("artifact_id"))) or {}).get("machine")
    return str(machine) if machine else _basename(row.get("source")) or "-"


@dataclass(slots=True)
class _SessionCount:
    first: tuple[bool, str] = (True, "")
    last: tuple[bool, str] = (True, "")
    first_local: str = ""
    last_local: str = ""
    user: int = 0
    ai: int = 0
    calls: int = 0
    channels: dict[str, None] = field(default_factory=dict)

    def touch(self, row: Mapping[str, Any]) -> None:
        stamp = _stamp(row)
        local = _text(row.get("ts_local"))
        if stamp[0]:
            return
        if self.first[0] or stamp < self.first:
            self.first, self.first_local = stamp, local
        if self.last[0] or stamp > self.last:
            self.last, self.last_local = stamp, local


def _session_counts(model: ReportModel) -> dict[tuple[str, str, str | None], _SessionCount]:
    meta = model.query_meta
    lang = model.lang
    machine_of: dict[tuple[str, str | None], str] = {}
    for q in model.ai_queries:  # a session keeps the machine label of its labelled records
        label = (meta.get(str(q.get("artifact_id"))) or {}).get("machine")
        if label and q.get("session") is not None:
            machine_of.setdefault((tool_label(q.get("tool"), lang), q.get("session")), str(label))
    groups: dict[tuple[str, str, str | None], _SessionCount] = {}
    for q in model.ai_queries:
        role = q.get("role")
        if role == "system":
            continue
        tool = tool_label(q.get("tool"), lang)
        session = q.get("session")
        machine = machine_of.get((tool, session)) or machine_label(q, meta)
        group = groups.setdefault((tool, machine, session), _SessionCount())
        group.touch(q)
        if role == "user":
            group.user += 1
        else:
            group.ai += 1
        channel = (meta.get(str(q.get("artifact_id"))) or {}).get("channel")
        if channel:
            group.channels[str(channel)] = None
    for call in model.tool_calls:
        tool = tool_label(call.get("tool"), lang)
        session = call.get("session")
        machine = machine_of.get((tool, session)) or _basename(call.get("source")) or "-"
        group = groups.setdefault((tool, machine, session), _SessionCount())
        group.touch(call)
        group.calls += 1
    return groups


def _counts_section(b: _Builder, model: ReportModel) -> None:
    lang = b.lang
    b.section(t("sec.counts", lang))
    groups = _session_counts(model)
    if not groups:
        b.para(t("summary.none", lang))
        return
    b.para(t("counts.note", lang, n=len(groups), volume=PROMPTS_VOLUME_PATH))
    ordered = sorted(groups.items(), key=lambda item: (item[0][0], item[0][1], item[1].first, str(item[0][2])))
    if len(ordered) > SESSION_ROW_CAP:
        _machine_totals(b, ordered)
        busiest = sorted(ordered, key=lambda item: -(item[1].user + item[1].ai + item[1].calls))
        keep = {id(item) for item in busiest[:SESSION_ROW_CAP]}
        ordered = [item for item in ordered if id(item) in keep]
        b.para(t("counts.cap_note", lang, total=len(groups), shown=len(ordered), cap=SESSION_ROW_CAP))
    rows = []
    for (tool, machine, session), g in ordered:
        period = f"{g.first_local} ~ {g.last_local}" if g.first_local else "-"
        rows.append(
            (
                tool,
                machine,
                session or "-",
                period,
                str(g.user),
                str(g.ai),
                str(g.calls),
                ", ".join(g.channels) or "-",
            )
        )
    b.table(
        [
            t(key, lang)
            for key in (
                "counts.col_tool",
                "counts.col_machine",
                "counts.col_session",
                "counts.col_period",
                "counts.col_user",
                "counts.col_ai",
                "counts.col_calls",
                "counts.col_channel",
            )
        ],
        rows,
        (2, 3, 4, 5, 1, 1, 1, 2),
        caption=t("counts.cap_session", lang) if len(groups) > SESSION_ROW_CAP else "",
        compact=len(rows) > EXCERPT_DENSE_ROWS,
    )


def _machine_totals(b: _Builder, ordered: Sequence[tuple[tuple[str, str, str | None], _SessionCount]]) -> None:
    lang = b.lang
    totals: dict[tuple[str, str], _SessionCount] = {}
    sessions: dict[tuple[str, str], int] = {}
    for (tool, machine, _), g in ordered:
        total = totals.setdefault((tool, machine), _SessionCount())
        sessions[(tool, machine)] = sessions.get((tool, machine), 0) + 1
        _merge(total, g)
    busiest = sorted(totals.items(), key=lambda item: -(item[1].user + item[1].ai + item[1].calls))
    shown = sorted(busiest[:MACHINE_ROW_CAP])
    rest = busiest[MACHINE_ROW_CAP:]
    rows = [_total_row(tool, machine, sessions[(tool, machine)], g) for (tool, machine), g in shown]
    if rest:
        other = _SessionCount()
        for _, g in rest:
            _merge(other, g)
        label = t("counts.others", lang, n=len(rest))
        rows.append(_total_row("", label, sum(sessions[key] for key, _ in rest), other))
    b.table(
        [
            t(key, lang)
            for key in (
                "counts.col_tool",
                "counts.col_machine",
                "counts.col_sessions",
                "counts.col_period",
                "counts.col_user",
                "counts.col_ai",
                "counts.col_calls",
                "counts.col_channel",
            )
        ],
        rows,
        (2, 3, 2, 5, 1, 1, 1, 2),
        caption=t("counts.cap_machine", lang),
        compact=len(rows) > EXCERPT_DENSE_ROWS,
    )


def _merge(total: _SessionCount, g: _SessionCount) -> None:
    total.user += g.user
    total.ai += g.ai
    total.calls += g.calls
    total.channels.update(g.channels)
    if g.first_local and (not total.first_local or g.first < total.first):
        total.first, total.first_local = g.first, g.first_local
    if g.last_local and (not total.last_local or g.last > total.last):
        total.last, total.last_local = g.last, g.last_local


def _total_row(tool: str, machine: str, sessions: int, g: _SessionCount) -> tuple[str, ...]:
    return (
        tool,
        machine,
        f"{sessions:,}",
        f"{g.first_local} ~ {g.last_local}" if g.first_local else "-",
        f"{g.user:,}",
        f"{g.ai:,}",
        f"{g.calls:,}",
        ", ".join(g.channels) or "-",
    )


def _seen(first: str, last: str) -> str:
    return f"{first} ~ {last}" if first and last and first != last else first or last or "-"


def _instruction_section(b: _Builder, model: ReportModel) -> None:
    lang = b.lang
    b.section(t("sec.system", lang))
    meta = model.query_meta
    found = [*model.instructions, *(q for q in model.ai_queries if q.get("role") == "system")]
    if not found:
        b.para(t("summary.none", lang))
        return
    distinct: dict[tuple[str, str], dict[str, Any]] = {}
    for row in found:
        text = _text(row.get("text"))
        key = (_text(row.get("source")), text_sha256(text))
        extra = meta.get(str(row.get("artifact_id"))) or {}
        slot = distinct.get(key)
        if slot is None:
            slot = distinct[key] = {"row": row, "text": text, "first": (True, ""), "first_local": "", "last_local": ""}
        stamp = _stamp(row)
        if not stamp[0] and (slot["first"][0] or stamp < slot["first"]):
            slot["first"], slot["first_local"] = stamp, _text(row.get("ts_local"))
        later = _text(extra.get("last_local")) or _text(row.get("ts_local"))
        if later and later > slot["last_local"]:
            slot["last_local"] = later
    ordered = sorted(
        distinct.items(),
        key=lambda item: (_text(item[1]["row"].get("tool")), item[0][0], item[1]["first"]),
    )
    chars = _excerpt_chars(len(ordered))
    b.para(t("instr.note", lang, n=len(ordered), chars=chars, volume=PROMPTS_VOLUME_PATH))
    rows = []
    for (source, sha), slot in ordered:
        row = slot["row"]
        kind = _text(row.get("role_label"))
        extra_kind = (meta.get(str(row.get("artifact_id"))) or {}).get("kind")
        if extra_kind:
            kind = f"{kind} ({extra_kind})"
        rows.append(
            (
                f"{tool_label(row.get('tool'), lang)}\n{kind}",
                source,
                f"{len(slot['text'].encode('utf-8', 'replace')):,}",
                _seen(slot["first_local"], slot["last_local"]),
                sha[:SHA_PREFIX_CHARS],
                _excerpt(slot["text"], chars),
            )
        )
    b.table(
        (
            t("counts.col_tool", lang) + " / " + t("instr.col_kind", lang),
            t("instr.col_path", lang),
            t("instr.col_size", lang),
            t("instr.col_seen", lang),
            t("instr.col_sha", lang),
            t("instr.col_excerpt", lang, n=chars),
        ),
        rows,
        (3, 5, 2, 4, 3, 9),
        raw=(5,),
        compact=len(rows) > EXCERPT_DENSE_ROWS,
    )


def _where(row: Mapping[str, Any], model: ReportModel, machines: Mapping[tuple[str, str | None], str]) -> str:
    tool = tool_label(row.get("tool"), model.lang)
    session = row.get("session")
    if row.get("role") == "tool_call":
        machine = machines.get((tool, session)) or _basename(row.get("source")) or "-"
    else:
        machine = machine_label(row, model.query_meta)
    return f"{tool}\n{machine}\n{session or '-'}"


def _machines(model: ReportModel) -> dict[tuple[str, str | None], str]:
    out: dict[tuple[str, str | None], str] = {}
    for q in model.ai_queries:
        out.setdefault((tool_label(q.get("tool"), model.lang), q.get("session")), machine_label(q, model.query_meta))
    return out


def _user_excerpts(model: ReportModel, users: Sequence[Mapping[str, Any]]) -> tuple[list[tuple[Mapping[str, Any], str]], int]:
    """Rows to show plus the number of flagged prompts: everything when small, else flagged + session edges."""
    lang = model.lang
    meta = model.query_meta
    if len(users) <= PROMPT_ROW_CAP:
        return [(u, _flag_label(u, meta, lang, ())) for u in users], 0
    flagged = [u for u in users if (meta.get(str(u.get("artifact_id"))) or {}).get("flags")]
    edges: dict[tuple[str, str, str | None], list[Mapping[str, Any]]] = {}
    for u in users:
        key = (tool_label(u.get("tool"), lang), machine_label(u, meta), u.get("session"))
        pair = edges.setdefault(key, [u, u])
        pair[1] = u
    edge_label: dict[str, list[str]] = {}
    for first, last in edges.values():
        edge_label.setdefault(str(first.get("artifact_id")), []).append("flag.first")
        if last is not first:
            edge_label.setdefault(str(last.get("artifact_id")), []).append("flag.last")
    chosen: dict[str, Mapping[str, Any]] = {}
    for u in flagged:
        if len(chosen) < PROMPT_ROW_CAP:
            chosen[str(u.get("artifact_id"))] = u
    for first, last in edges.values():
        for u in (first, last):
            if len(chosen) < PROMPT_ROW_CAP:
                chosen.setdefault(str(u.get("artifact_id")), u)
    shown = sorted(chosen.values(), key=_stamp)
    return [(u, _flag_label(u, meta, lang, edge_label.get(str(u.get("artifact_id")), ()))) for u in shown], len(flagged)


def _flag_label(row: Mapping[str, Any], meta: Mapping[str, Mapping[str, Any]], lang: str, edges: Sequence[str]) -> str:
    keys = [f"flag.{f}" for f in (meta.get(str(row.get("artifact_id"))) or {}).get("flags") or ()] + list(edges)
    return ", ".join(t(k, lang) for k in keys) or t("flag.all", lang)


def _user_section(b: _Builder, model: ReportModel, users: Sequence[Mapping[str, Any]]) -> None:
    lang = b.lang
    b.section(t("sec.user_excerpt", lang))
    if not users:
        b.para(t("summary.none", lang))
        return
    selected, flagged = _user_excerpts(model, users)
    chars = _excerpt_chars(len(selected))
    if len(users) <= PROMPT_ROW_CAP:
        b.para(t("user.note_all", lang, n=len(users)))
    else:
        b.para(
            t(
                "user.note_cap",
                lang,
                total=len(users),
                shown=len(selected),
                flagged=flagged,
                cap=PROMPT_ROW_CAP,
                chars=chars,
                volume=PROMPTS_VOLUME_PATH,
                csv=AI_QUERIES_CSV_PATH,
            )
        )
    machines = _machines(model)
    b.table(
        (
            t("prompts.col_time", lang),
            t("user.col_where", lang),
            t("user.col_flag", lang),
            t("prompts.col_text", lang),
            t("prompts.col_source", lang),
        ),
        [
            (
                _text(u.get("ts_local")) or "-",
                _where(u, model, machines),
                flag,
                _excerpt(u.get("text"), chars),
                _text(u.get("source")),
            )
            for u, flag in selected
        ],
        (3, 4, 2, 9, 4),
        raw=(3,),
        compact=len(selected) > EXCERPT_DENSE_ROWS,
    )


def _risky_call(row: Mapping[str, Any]) -> bool:
    name = _text(row.get("call_name"))
    return bool(WRITE_NAME.search(name) or TRANSFER_COMMAND.search(f"{name} {_text(row.get('text'))}"))


def _assistant_section(b: _Builder, model: ReportModel) -> None:
    lang = b.lang
    b.section(t("sec.assistant", lang))
    answers = [q for q in model.ai_queries if q.get("role") not in ("system", "user")]
    calls = model.tool_calls
    if not answers and not calls:
        b.para(t("summary.none", lang))
        return
    machines = _machines(model)
    if len(answers) + len(calls) <= TOOL_CALL_ROW_CAP:
        b.para(t("ai.note_all", lang, a=len(answers), c=len(calls)))
        rows = sorted([*answers, *calls], key=_stamp)
    else:
        risky = [c for c in calls if _risky_call(c)]
        rows = risky[:TOOL_CALL_ROW_CAP]
        b.para(
            t(
                "ai.note_cap",
                lang,
                a=len(answers),
                c=len(calls),
                m=len(risky),
                shown=len(rows),
                cap=TOOL_CALL_ROW_CAP,
                volume=PROMPTS_VOLUME_PATH,
                json=REPORT_JSON_PATH,
            )
        )
    if not rows:
        return
    chars = _excerpt_chars(len(rows))
    b.table(
        (
            t("prompts.col_time", lang),
            t("user.col_where", lang),
            t("prompts.col_kind", lang),
            t("prompts.col_text", lang),
            t("prompts.col_source", lang),
        ),
        [
            (
                _text(r.get("ts_local")) or "-",
                _where(r, model, machines),
                _text(r.get("role_label")),
                _excerpt(r.get("text"), chars),
                _text(r.get("source")),
            )
            for r in rows
        ],
        (3, 4, 2, 9, 4),
        raw=(3,),
        compact=len(rows) > EXCERPT_DENSE_ROWS,
    )


def _prompts(b: _Builder, model: ReportModel) -> None:
    lang = b.lang
    b.chapter(t("chapter.prompts", lang))
    b.para(t("prompts.intro", lang))
    _tools_table(b, model)
    users = [q for q in model.ai_queries if q.get("role") == "user"]
    _counts_section(b, model)
    _instruction_section(b, model)
    _user_section(b, model, users)
    _assistant_section(b, model)


def _generated(b: _Builder, model: ReportModel) -> None:
    lang = b.lang
    b.chapter(t("chapter.generated", lang))
    if not model.generated_files:
        b.para(t("stmt.generated_none", lang))
        return
    b.para(t("generated.intro", lang, n=len(model.generated_files)))
    for row in model.generated_files:
        b.sub(_text(row.get("subject")))
        b.kv(
            [
                (t("generated.verdict", lang), _text(row.get("verdict_label"))),
                (t("generated.confidence", lang), _text(row.get("confidence_display"))),
                (t("generated.signals", lang), _text(row.get("signals_summary"))),
                (t("generated.origin", lang), _text(row.get("origin")) or t("generated.no_origin", lang)),
                (t("generated.limits", lang), _text(row.get("limitations_display"))),
            ]
        )


def _timeline_cell(row: Mapping[str, Any], key: str, compact: bool) -> str:
    value = _text(row.get(key))
    if not compact or row.get("collapsed"):
        return value
    if key == "summary":
        return value if len(value) <= TIMELINE_SUMMARY_CHARS else value[:TIMELINE_SUMMARY_CHARS].rstrip() + "\u2026"
    if key == "source_path":
        return _tail(value, TIMELINE_SOURCE_CHARS)
    return value


def _timeline(b: _Builder, model: ReportModel, limit: int) -> None:
    lang = b.lang
    b.chapter(t("chapter.timeline", lang), landscape=True)
    view = model.timeline_view(limit)
    days = view.days
    if not days:
        b.para(t("stmt.timeline_none", lang))
        return
    spec = COLUMNS["timeline"]
    headers = [t(label, lang) for _, label, _ in spec]
    compact = sum(len(rows) for _, rows in days) > TIMELINE_COMPACT_ROWS
    quiet: list[tuple[str | None, list[dict[str, Any]]]] = []

    def flush_quiet() -> None:
        if quiet:
            b.table(
                [t("timeline.col_day", lang), t("timeline.col_content", lang)],
                [[day or t("sec.no_day", lang), _text(rows[0].get("summary"))] for day, rows in quiet],
                [3, 11],
            )
            quiet.clear()

    for day, rows in days:
        if all(r.get("collapsed") for r in rows):
            quiet.append((day, rows))
            continue
        flush_quiet()
        total = sum(int(r.get("count", 1)) for r in rows)
        b.section(t("sec.day", lang, day=day or t("sec.no_day", lang), n=total), toc=False)
        b.table(
            headers,
            [[_timeline_cell(r, key, compact) for key, _, _ in spec] for r in rows],
            [w for _, _, w in spec],
            compact=compact,
        )
    flush_quiet()
    note = model.timeline_note_for(view.omitted, limit, lang)
    if note:
        b.para(note)
    if view.aggregated:
        b.para(
            t(
                "timeline.aggregated_note",
                lang,
                n=TIMELINE_CHAT_DAY_THRESHOLD,
                csv=TIMELINE_CSV_PATH,
                volume=PROMPTS_VOLUME_PATH,
            )
        )


def _channel(value: Any, lang: str) -> str:
    name, arrow, destination = _text(value).partition(CHANNEL_ARROW)
    return t("channel.with_destination", lang, name=name, dest=destination) if arrow else _text(value)


def _spec_table(b: _Builder, spec_key: str, rows: Sequence[Mapping[str, Any]]) -> None:
    lang = b.lang
    if not rows:
        b.para(t("summary.none", lang))
        return
    spec = COLUMNS[spec_key]
    b.table(
        [t(label, lang) for _, label, _ in spec],
        [
            [(_channel(r.get(key), lang) if key == "display_channel" else _text(r.get(key))) or "-" for key, _, _ in spec]
            for r in rows
        ],
        [w for _, _, w in spec],
    )


def _status(value: Any, lang: str) -> str:
    text = _text(value)
    return _lookup(f"status.{text}", lang, text)


def _plain_table(
    b: _Builder, columns: Sequence[tuple[str, str, int]], rows: Sequence[Mapping[str, Any]], *, status: str = ""
) -> None:
    lang = b.lang
    if not rows:
        b.para(t("summary.none", lang))
        return
    b.table(
        [t(label, lang) for _, label, _ in columns],
        [[_status(r.get(key), lang) if key == status else _text(r.get(key)) for key, _, _ in columns] for r in rows],
        [w for _, _, w in columns],
    )


def _limits(b: _Builder, model: ReportModel) -> None:
    lang = b.lang
    cov = model.coverage
    b.chapter(t("chapter.limits", lang))
    b.section(t("sec.plugins", lang))
    _plain_table(
        b,
        (
            ("name", "plugin.col_name", 3),
            ("version", "plugin.col_version", 2),
            ("status", "plugin.col_status", 2),
            ("records", "plugin.col_records", 2),
            ("warnings", "plugin.col_warnings", 2),
            ("error", "plugin.col_error", 4),
        ),
        cov.get("plugin_runs") or [],
        status="status",
    )
    b.section(t("sec.warnings", lang))
    _plain_table(
        b,
        (
            ("plugin", "plugin.col_name", 2),
            ("message", "plugin.col_message", 4),
            ("error", "plugin.col_error", 3),
            ("source_path", "plugin.col_source", 4),
        ),
        cov.get("parse_warnings") or [],
    )
    b.section(t("sec.undecoded", lang))
    _plain_table(
        b,
        (
            ("tool", "plugin.col_tool", 2),
            ("status", "plugin.col_status", 3),
            ("detail", "plugin.col_detail", 4),
            ("source_path", "plugin.col_source", 4),
        ),
        cov.get("not_decoded") or [],
        status="status",
    )
    b.section(t("sec.findings", lang))
    findings = [
        {
            "title": f.get("title"),
            "narrative": f.get("narrative"),
            "limits": f.get("limitations_display"),
        }
        for f in cov.get("findings") or []
    ]
    _plain_table(
        b,
        (("title", "limits.col_title", 3), ("narrative", "limits.col_narrative", 5), ("limits", "limits.col_limits", 4)),
        findings,
    )
    b.section(t("sec.caveats", lang))
    if not model.limitations:
        b.para(t("summary.none", lang))
    for i, item in enumerate(model.limitations, start=1):
        b.para(f"{i}) {item}")


def _annexes(b: _Builder, model: ReportModel) -> None:
    lang = b.lang
    b.annex(t("annex.exports", lang), landscape=True)
    b.para(t("annex.exports_note", lang, n=len(model.exports)))
    if model.exports:
        spec = COLUMNS["exports"]
        b.table(
            [t(label, lang) for _, label, _ in spec],
            [[_text(r.get(key)) for key, _, _ in spec] for r in model.exports],
            [w for _, _, w in spec],
        )
    else:
        b.para(t("summary.none", lang))

    b.annex(t("annex.custody", lang))
    entries = model.run.get("custody") or model.custody
    if entries:
        rows = []
        for i, e in enumerate(entries, start=1):
            name = _text(e.get("action"))
            rows.append(
                (
                    str(e.get("seq", i)),
                    _utc(e.get("ts_utc") or e.get("ts")),
                    _text(e.get("actor")),
                    _lookup(f"custody.action.{name}", lang, name),
                    _detail(e.get("detail"), lang),
                )
            )
        b.table(
            (
                t("table.no", lang),
                t("custody.col_time", lang),
                t("custody.actor", lang),
                t("custody.action", lang),
                t("custody.detail", lang),
            ),
            rows,
            (1, 4, 2, 2, 8),
        )
    else:
        b.para(t("summary.none", lang))

    b.annex(t("annex.signature", lang))
    sig = model.signature
    b.table(
        (t("sign.author", lang), t("sign.organisation", lang), t("sign.signature", lang), t("sign.date", lang)),
        [(_text(sig.get("examiner")), _text(sig.get("organisation")), "\n\n", "\n\n")],
        (3, 3, 3, 2),
    )


def build_document(model: ReportModel, timeline_limit: int = TIMELINE_LIMIT_PDF_DOCX) -> Document:
    cached = model.doc_cache.get(timeline_limit)
    if cached is None:
        cached = model.doc_cache[timeline_limit] = _build_document(model, timeline_limit)
    return cached


def _build_document(model: ReportModel, timeline_limit: int) -> Document:
    lang = model.lang
    b = _Builder(lang)
    _overview(b, model)
    b.chapter(t("chapter.summary", lang))
    for line in _numbered(_statements(model)):
        b.para(line)
    _prompts(b, model)
    _generated(b, model)
    _timeline(b, model, timeline_limit)
    b.chapter(t("chapter.changes", lang))
    _spec_table(b, "file_lifecycle", model.lifecycle_rows())
    if model.lifecycle_hidden:
        b.para(t("changes.omitted", lang, n=len(model.lifecycle_hidden), csv="report/csv/file_lifecycle.csv"))
    b.chapter(t("chapter.transfer", lang))
    _spec_table(b, "exfil", model.exfil)
    _limits(b, model)
    b.chapter(t("chapter.opinion", lang))
    for line in _numbered(_opinions(model)):
        b.para(line)
    _annexes(b, model)
    number = str(model.case.get("document_number") or f"{model.case.get('number') or ''}-01")
    return Document(
        lang=lang,
        title=t("cover.title", lang),
        header_text=t("header.text", lang, doc=number),
        cover=_cover(model, lang),
        notice=t("cover.notice", lang),
        blocks=b.blocks,
    )


def chapter_outline(model: ReportModel) -> list[dict[str, Any]]:
    """Ordered chapter / section list as rendered; stored in report.json as `chapters`."""
    chapters: list[dict[str, Any]] = []
    for block in build_document(model).blocks:
        if not isinstance(block, Heading) or block.level > 2:
            continue
        if block.level == 1:
            chapters.append(
                {"no": block.number, "title": block.text, "landscape": block.landscape, "sections": []}
            )
        else:
            chapters[-1]["sections"].append({"no": block.number, "title": block.text})
    return chapters
