from __future__ import annotations

import json
import platform
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from importlib import metadata
from pathlib import PurePath
from typing import Any

from aitrace.core import catalog
from aitrace.core.kinds import (
    Actor,
    ArtifactKind,
    EventCategory,
    FindingCategory,
    Verdict,
)
from aitrace.core.model import Artifact, Attribution, Case, Evidence, Finding, format_utc
from aitrace.core.time import fmt_local, fmt_utc, from_iso
from aitrace.db.store import CaseStore
from aitrace.report.i18n import DEFAULT_LANG, LIMITATION_ALIASES, STANDARDS, STRINGS, t

SECTION_KEYS: tuple[str, ...] = (
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
    "run",
)

TIMELINE_COLUMNS: tuple[str, ...] = (
    "ts_utc",
    "ts_local",
    "category",
    "actor",
    "user",
    "summary",
    "source_path",
    "artifact_id",
)

# Reader-facing columns per section: (row field key, i18n label key, width weight).
# Hash / ID columns (artifact_id, session ids, finding ids) stay in JSON/CSV only.
COLUMNS: dict[str, list[tuple[str, str, int]]] = {
    "ai_tools": [
        ("kind_label", "col.kind", 2),
        ("tool", "col.tool", 3),
        ("users", "col.users", 2),
        ("first_seen_local", "col.first_seen_local", 3),
        ("last_seen_local", "col.last_seen_local", 3),
        ("evidence_count", "col.evidence_count", 1),
    ],
    "ai_queries": [
        ("ts_local", "col.ts_local", 3),
        ("tool", "col.tool", 2),
        ("role_label", "col.role", 2),
        ("text", "col.text", 8),
        ("source_name", "col.source_name", 3),
    ],
    "file_lifecycle": [
        ("severity_label", "col.severity", 1),
        ("display_title", "col.display_title", 4),
        ("display_steps", "col.display_steps", 5),
        ("links_summary", "col.links_summary", 3),
    ],
    "exfil": [
        ("severity_label", "col.severity", 1),
        ("display_channel", "col.display_channel", 4),
        ("ts_local", "col.ts_local", 3),
        ("actor_label", "col.actor", 1),
        ("user", "col.user", 2),
        ("source_name", "col.source_name", 3),
    ],
    "attribution": [
        ("subject", "col.subject", 4),
        ("verdict_label", "col.verdict", 2),
        ("confidence_display", "col.confidence_display", 2),
        ("signals_summary", "col.signals_summary", 4),
        ("limitations_display", "col.limitations", 4),
    ],
    "timeline": [
        ("ts_local", "col.ts_local", 3),
        ("category_label", "col.category", 2),
        ("actor_label", "col.actor", 1),
        ("user", "col.user", 2),
        ("summary", "col.summary", 5),
        ("source_path", "col.source_path", 4),
    ],
    "exports": [
        ("export_path", "col.export_path", 5),
        ("size", "label.size", 1),
        ("sha256", "col.sha256", 4),
    ],
}

TIMELINE_LIMIT_PDF_DOCX = 5000
TIMELINE_LIMIT_HTML = 20000
TIMELINE_CSV_PATH = "report/csv/timeline.csv"
TOP_FINDINGS = 3
SIGNAL_SUMMARY_LIMIT = 4

_PRIORITY_CATEGORIES = frozenset(
    {EventCategory.AI_ACTIVITY, EventCategory.UPLOAD, EventCategory.TRANSFER, EventCategory.REMOTE_ACCESS}
)
_LINKED_FINDING_CATEGORIES = (
    FindingCategory.AI_TOOL_USAGE,
    FindingCategory.AI_QUERY,
    FindingCategory.FILE_LIFECYCLE,
    FindingCategory.EXFIL_CHANNEL,
)
_ROLE_ACTOR = {"user": Actor.HUMAN, "assistant": Actor.AI, "system": Actor.SYSTEM, "tool": Actor.SYSTEM}
_NOT_DECODED_STATUSES = frozenset({"encrypted_not_decoded", "unsupported"})
_NOT_INSTALLED = "not installed"


def _plain(value: Any) -> Any:
    if isinstance(value, datetime):
        return format_utc(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, PurePath):
        return value.as_posix()
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(v) for v in value]
    return value


@dataclass(slots=True)
class ReportModel:
    case: dict[str, Any]
    evidence: list[dict[str, Any]]
    tools: dict[str, Any]
    methodology: dict[str, Any]
    summary: list[dict[str, Any]]
    ai_tools: list[dict[str, Any]]
    ai_queries: list[dict[str, Any]]
    file_lifecycle: list[dict[str, Any]]
    exfil: list[dict[str, Any]]
    attribution: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    exports: list[dict[str, Any]]
    coverage: dict[str, Any]
    limitations: list[str]
    custody: list[dict[str, Any]]
    signature: dict[str, Any]
    run: dict[str, Any]
    priority_rows: frozenset[int] = field(default_factory=frozenset, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {key: _plain(getattr(self, key)) for key in SECTION_KEYS}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def timeline_render(self, limit: int) -> list[dict[str, Any]]:
        """AI-linked, lifecycle and exfil events first, then the rest, each group in timeline order."""
        first = [row for i, row in enumerate(self.timeline) if i in self.priority_rows]
        rest = [row for i, row in enumerate(self.timeline) if i not in self.priority_rows]
        return (first + rest)[:limit]

    @property
    def lang(self) -> str:
        return str(self.case.get("lang") or DEFAULT_LANG)

    def case_pairs(self) -> list[tuple[str, str]]:
        spec = (
            ("id", "label.case_id"),
            ("name", "label.case_name"),
            ("number", "label.case_number"),
            ("examiner", "label.examiner"),
            ("organisation", "label.organisation"),
            ("timezone", "label.timezone"),
            ("tool_version", "label.tool_version"),
            ("notes", "label.notes"),
        )
        return _pairs(self.case, spec, self.lang)

    def evidence_pairs(self) -> list[list[tuple[str, str]]]:
        spec = (
            ("id", "label.evidence_id"),
            ("path", "label.evidence_path"),
            ("kind", "label.evidence_kind"),
            ("size", "label.size"),
            ("acquisition_hashes", "label.acquisition_hashes"),
            ("media_sha256", "label.media_sha256"),
            ("verification_label", "label.verification"),
        )
        return [_pairs(row, spec, self.lang) for row in self.evidence]

    def tools_pairs(self) -> list[tuple[str, str]]:
        spec = (
            ("aitrace_version", "label.aitrace_version"),
            ("python", "label.python"),
            ("dissect", "label.dissect"),
            ("os", "label.os"),
        )
        return _pairs(self.tools, spec, self.lang)

    def methodology_pairs(self) -> list[tuple[str, str]]:
        spec = (("standards", "label.standards"), ("tool_validation", "label.tool_validation"))
        return _pairs(self.methodology, spec, self.lang)

    def timeline_note(self, limit: int, lang: str) -> str | None:
        omitted = len(self.timeline) - limit
        if omitted <= 0:
            return None
        return t("timeline.note", lang, limit=limit, omitted=omitted, csv=TIMELINE_CSV_PATH)


def _label(key: str, lang: str, fallback: str) -> str:
    table = STRINGS.get(lang, STRINGS["en"])
    return table.get(key, fallback)


def _enum_label(prefix: str, value: object, lang: str) -> str:
    text = "" if value is None else str(value)
    return _label(f"{prefix}.{text}", lang, text)


def _pair_value(value: Any) -> str:
    if isinstance(value, Mapping):
        return ", ".join(f"{k}: {v}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def _pairs(source: Mapping[str, Any], spec: Sequence[tuple[str, str]], lang: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for key, label_key in spec:
        value = source.get(key)
        if value is None or value == "" or value == [] or value == {}:
            continue
        pairs.append((t(label_key, lang), _pair_value(value)))
    return pairs


def _local(iso: Any, tz: str) -> str | None:
    ts = from_iso(iso) if isinstance(iso, str) else None
    return fmt_local(ts, tz) if ts is not None else None


def _basename(path: Any) -> str | None:
    if not path:
        return None
    return str(path).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or None


def _dedupe(items: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _norm(text: str) -> str:
    return text.strip().rstrip(".").casefold()


def _build_limit_index() -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    entries: list[dict[str, str]] = []
    for value in catalog.LIMITATIONS.values():
        entries.extend(value if isinstance(value, list) else [value])
    entries.extend(LIMITATION_ALIASES.values())
    for entry in entries:
        index[_norm(entry["en"])] = entry
        index[_norm(entry["ko"])] = entry
    return index


_LIMIT_INDEX = _build_limit_index()


def _localize_limit(text: str, lang: str) -> str:
    entry = _LIMIT_INDEX.get(_norm(text))
    if entry is None:
        return text
    if lang == "en" and _norm(text) == _norm(entry["en"]):
        return text
    return entry.get(lang, entry["en"])


def _localize_limits(items: Sequence[str], lang: str) -> list[str]:
    return _dedupe([_localize_limit(i, lang) for i in items])


def _channel_key(rule_id: str | None, channel: str) -> str:
    if rule_id:
        if rule_id.startswith("TR-"):
            return rule_id
        if rule_id.startswith("EXFIL-REMOTE-"):
            return rule_id.removeprefix("EXFIL-REMOTE-").lower()
        if rule_id == "EXFIL-USB":
            return "usb"
    head = channel.split(" to ")[0].strip()
    return head if head.startswith("TR-") else head.lower()


def _channel_name(rule_id: str | None, channel: str, lang: str) -> str:
    return _label(f"channel.{_channel_key(rule_id, channel)}", lang, channel)


def _display_channel(rule_id: str | None, channel: str, destination: str | None, lang: str) -> str:
    name = _channel_name(rule_id, channel, lang)
    if destination and destination not in name:
        return f"{name} \u2192 {destination}"
    return name


_LIFECYCLE_PREFIX = "File lifecycle: "
_EXFIL_PREFIX = "Exfiltration channel: "
_OBSERVED_RE = re.compile(r"AI tools observed: (\d+)")


def _finding_title(f: Finding, lang: str) -> str:
    title = f.title
    if f.category is FindingCategory.FILE_LIFECYCLE and title.startswith(_LIFECYCLE_PREFIX):
        return t("title.file_lifecycle", lang, path=title[len(_LIFECYCLE_PREFIX) :])
    if f.category is FindingCategory.EXFIL_CHANNEL and title.startswith(_EXFIL_PREFIX):
        channel = _channel_name(f.rule_id, title[len(_EXFIL_PREFIX) :], lang)
        return t("title.exfil", lang, channel=channel)
    match = _OBSERVED_RE.fullmatch(title)
    if f.category is FindingCategory.AI_TOOL_USAGE and match:
        return t("title.ai_tools_observed", lang, n=match.group(1))
    return title


def _dissect_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for dist in metadata.distributions():
        name = dist.metadata["Name"]
        if name and name.lower().startswith("dissect"):
            versions[name.lower()] = dist.version
    return dict(sorted(versions.items()))


def _tools_section(case: Case) -> dict[str, Any]:
    return {
        "aitrace_version": case.tool_version,
        "python": platform.python_version(),
        "dissect": _dissect_versions(),
        "os": f"{platform.system()} {platform.release()}".strip(),
    }


def _methodology_section(case: Case, dissect: Mapping[str, str], lang: str) -> dict[str, Any]:
    return {
        "paragraphs": [t(f"methodology.p{i}", lang) for i in range(1, 5)],
        "standards_intro": t("methodology.standards_intro", lang),
        "standards": list(STANDARDS),
        "tool_validation": t(
            "methodology.tool_validation",
            lang,
            aitrace=case.tool_version,
            dissect=dissect.get("dissect.target", _NOT_INSTALLED),
        ),
    }


def _case_section(case: Case, lang: str) -> dict[str, Any]:
    return {
        "id": case.id,
        "name": case.name,
        "number": case.number,
        "examiner": case.examiner,
        "organisation": case.organisation,
        "timezone": case.timezone,
        "lang": lang,
        "tool_version": case.tool_version,
        "notes": case.notes,
        "handling_notice": t("handling_notice", lang),
    }


def _evidence_section(evidences: Sequence[Evidence], lang: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for ev in sorted(evidences, key=lambda e: e.id):
        row = ev.to_dict()
        row["verification_label"] = _label(f"verification.{ev.verification_status}", lang, ev.verification_status)
        rows.append(row)
    return rows


def _finding_row(finding: Finding, lang: str) -> dict[str, Any]:
    return {
        "id": finding.id,
        "severity": finding.severity.value,
        "severity_label": _enum_label("severity", finding.severity.value, lang),
        "band_label": _enum_label("band", finding.band.value, lang),
        "limitations_display": _localize_limits(finding.limitations, lang),
        "title": finding.title,
        "narrative": finding.narrative,
        "confidence": finding.confidence,
        "band": finding.band.value,
        "rule_id": finding.rule_id,
        "artifact_ids": list(finding.artifact_ids),
        "event_ids": list(finding.event_ids),
        "limitations": list(finding.limitations),
        "data": _plain(finding.data),
    }


def _signals_summary(item: Attribution, lang: str) -> str:
    ranked = sorted(item.signals, key=lambda s: -s.weight)
    parts = [
        f"{_enum_label('signal', s.type.value, lang)} ({_enum_label('direction', s.direction, lang)})"
        for s in ranked
    ]
    return "; ".join(_dedupe(parts)[:SIGNAL_SUMMARY_LIMIT])


def _lifecycle_row(finding: Finding, tz: str, lang: str) -> dict[str, Any]:
    row = _finding_row(finding, lang)
    path = str(finding.data.get("path") or "")
    steps = sorted(finding.data.get("lifecycle") or [], key=lambda s: str(s.get("ts") or ""))
    display_steps = []
    for step in steps:
        name = str(step.get("event") or "")
        stage = _label(f"step.{name}", lang, _enum_label("category", name, lang))
        stamp = _local(step.get("ts"), tz) or str(step.get("ts") or "")
        display_steps.append(f"{stamp} {stage}")
    links = [
        f"{_enum_label('link', link.get('kind'), lang)} ({float(link.get('confidence') or 0):.2f})"
        for link in finding.data.get("links") or []
    ]
    row["display_title"] = _finding_title(finding, lang) if not path else t("title.file_lifecycle", lang, path=path)
    row["display_steps"] = display_steps
    row["links_summary"] = ", ".join(_dedupe(links)) or t("link.none", lang)
    return row


def _exfil_row(finding: Finding, tz: str, lang: str) -> dict[str, Any]:
    row = _finding_row(finding, lang)
    data = finding.data
    channel = str(data.get("channel") or "")
    sources = data.get("source_paths") or []
    row["display_channel"] = _display_channel(finding.rule_id, channel, data.get("destination"), lang)
    row["actor_label"] = _enum_label("actor", data.get("actor"), lang)
    row["user"] = data.get("user")
    row["ts_local"] = _local(data.get("time"), tz)
    row["source_name"] = _basename(sources[0]) if sources else None
    return row


def _attribution_row(item: Attribution, lang: str) -> dict[str, Any]:
    band_label = _enum_label("band", item.band.value, lang)
    return {
        "id": item.id,
        "subject": item.subject,
        "verdict": item.verdict.value,
        "verdict_label": _enum_label("verdict", item.verdict.value, lang),
        "confidence": item.confidence,
        "confidence_display": f"{item.confidence:.2f} ({band_label})",
        "band": item.band.value,
        "band_label": band_label,
        "signals_summary": _signals_summary(item, lang),
        "limitations_display": _localize_limits(item.limitations, lang),
        "signals": [s.to_dict() for s in item.signals],
        "rationale": item.rationale,
        "subject_artifact_ids": list(item.subject_artifact_ids),
        "limitations": list(item.limitations),
    }


def _inventory_row(entry: Mapping[str, Any], tz: str, lang: str) -> dict[str, Any]:
    kind = str(entry.get("kind") or "")
    tool = entry.get("tool")
    provider = None
    if kind == "credential":
        provider = entry.get("provider") or tool
        tool = tool or provider
    users = list(entry.get("users") or [])
    return {
        "tool": tool,
        "kind": kind,
        "kind_label": _enum_label("kind", kind, lang),
        "first_seen_local": _local(entry.get("first_seen"), tz),
        "last_seen_local": _local(entry.get("last_seen"), tz),
        "provider": provider,
        "users": users,
        "first_seen": entry.get("first_seen"),
        "last_seen": entry.get("last_seen"),
        "evidence_count": entry.get("evidence_count", 0),
        "artifact_ids": list(entry.get("artifact_ids") or []),
        # keys the HTML/DOCX/CSV renderers read; they render None as blank
        "user": ", ".join(str(u) for u in users) or None,
        "status": None,
        "detail": None,
        "source_path": None,
        "title": None,
        "narrative": None,
    }


def _ai_tools_section(usage: Sequence[Finding], tz: str, lang: str) -> list[dict[str, Any]]:
    rows = [_inventory_row(entry, tz, lang) for f in usage for entry in f.data.get("inventory") or []]
    rows.sort(key=lambda r: (r["kind"], r["tool"] or ""))
    return _plain(rows)


def _query_actor(role: str, event_actor: Actor | None) -> str:
    if event_actor is not None:
        return event_actor.value
    return _ROLE_ACTOR.get(role, Actor.UNKNOWN).value


def _ai_queries_section(
    messages: Sequence[Artifact], first_event: Mapping[str, Any], tz: str, lang: str
) -> list[dict[str, Any]]:
    keyed: list[tuple[tuple[bool, str], dict[str, Any]]] = []
    for a in messages:
        event = first_event.get(a.id)
        ts: datetime | None = event.ts_utc if event is not None else None
        role = str(a.data.get("role", "unknown"))
        actor = _query_actor(role, event.actor if event is not None else None)
        row = {
            "ts_utc": fmt_utc(ts) if ts is not None else None,
            "ts_local": fmt_local(ts, tz) if ts is not None else None,
            "tool": a.data.get("tool"),
            "session": a.data.get("session_id"),
            "role": role,
            "role_label": _enum_label("role", role, lang),
            "actor": actor,
            "actor_label": _enum_label("actor", actor, lang),
            "text": a.data.get("text", ""),
            "source": a.provenance.source_path,
            "source_name": _basename(a.provenance.source_path),
            "artifact_id": a.id,
            "fragment": bool(a.data.get("fragment", False)),
        }
        keyed.append(((ts is None, ts.isoformat() if ts is not None else ""), row))
    keyed.sort(key=lambda pair: pair[0])
    return [row for _, row in keyed]


def _top_bullets(findings: Sequence[Finding], lang: str) -> list[str]:
    return [
        t("summary.top", lang, severity=t(f"severity.{f.severity.value}", lang), title=_finding_title(f, lang))
        for f in findings[:TOP_FINDINGS]
    ]


def _summary_section(
    by_category: Mapping[FindingCategory, Sequence[Finding]],
    attributions: Sequence[Attribution],
    chat_count: int,
    lang: str,
) -> list[dict[str, Any]]:
    none = [t("summary.none", lang)]
    usage = by_category[FindingCategory.AI_TOOL_USAGE]
    queries = by_category[FindingCategory.AI_QUERY]
    lifecycle = by_category[FindingCategory.FILE_LIFECYCLE]
    exfil = by_category[FindingCategory.EXFIL_CHANNEL]

    q1 = [t("summary.q1.count", lang, n=len(usage)), *_top_bullets(usage, lang)] if usage else none
    q2 = (
        [t("summary.q2.count", lang, n=len(queries), m=chat_count), *_top_bullets(queries, lang)]
        if queries or chat_count
        else none
    )
    q3 = [t("summary.q3.count", lang, n=len(lifecycle)), *_top_bullets(lifecycle, lang)] if lifecycle else none
    q4 = [t("summary.q4.count", lang, n=len(exfil)), *_top_bullets(exfil, lang)] if exfil else none
    if attributions:
        q5 = [t("summary.q5.count", lang, n=len(attributions))]
        for verdict in Verdict:
            n = sum(1 for a in attributions if a.verdict is verdict)
            if n:
                q5.append(t("summary.q5.verdict", lang, verdict=t(f"verdict.{verdict.value}", lang), n=n))
    else:
        q5 = none
    return [
        {"id": f"Q{i}", "question": t(f"summary.q{i}", lang), "bullets": _dedupe(bullets)}
        for i, bullets in enumerate((q1, q2, q3, q4, q5), start=1)
    ]


def _coverage_section(
    store: CaseStore,
    warnings: Sequence[Artifact],
    presence: Sequence[Artifact],
    by_category: Mapping[FindingCategory, Sequence[Finding]],
    lang: str,
) -> dict[str, Any]:
    runs = [
        {
            "evidence_id": r.evidence_id,
            "name": r.name,
            "version": r.version,
            "status": r.status,
            "records": r.records,
            "warnings": r.warnings,
            "error": r.error,
        }
        for r in store.plugin_runs()
    ]
    parse_warnings = sorted(
        (
            {
                "plugin": a.data.get("plugin"),
                "message": a.data.get("message"),
                "error": a.data.get("error"),
                "source_path": a.provenance.source_path,
                "artifact_id": a.id,
            }
            for a in warnings
        ),
        key=lambda w: (w["plugin"] or "", w["source_path"], w["message"] or "", w["artifact_id"]),
    )
    not_decoded = [
        {
            "tool": a.data.get("tool"),
            "status": a.data.get("status"),
            "detail": a.data.get("detail"),
            "source_path": a.provenance.source_path,
            "artifact_id": a.id,
        }
        for a in presence
        if a.data.get("status") in _NOT_DECODED_STATUSES
    ]
    related = [*by_category[FindingCategory.INTEGRITY], *by_category[FindingCategory.COVERAGE]]
    return {
        "plugin_runs": runs,
        "parse_warnings": parse_warnings,
        "not_decoded": not_decoded,
        "findings": [_finding_row(f, lang) for f in related],
    }


def _limitations_section(
    findings: Sequence[Finding],
    attributions: Sequence[Attribution],
    evidences: Sequence[Evidence],
    lang: str,
) -> list[str]:
    specific: set[str] = set()
    for f in findings:
        specific.update(f.limitations)
    for a in attributions:
        specific.update(a.limitations)
    for ev in evidences:
        specific.update(ev.limitations)
    result = sorted(specific)
    global_items = catalog.LIMITATIONS["GLOBAL"]
    assert isinstance(global_items, list)
    for item in global_items:
        text = item.get(lang, item["en"])
        if text not in specific:
            result.append(text)
    return _localize_limits(result, lang)


def _custody_rows(entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "seq": e.get("seq", i),
            "actor": e.get("actor", ""),
            "action": e.get("action", ""),
            "detail": _plain(e.get("detail", "")),
        }
        for i, e in enumerate(entries, start=1)
    ]


def build_report_model(
    store: CaseStore,
    case: Case,
    evidences: Sequence[Evidence],
    custody_entries: Sequence[Mapping[str, Any]],
    run_info: Mapping[str, Any],
    tz: str,
    lang: str,
) -> ReportModel:
    source_paths: dict[str, str] = {}
    buckets: dict[ArtifactKind, list[Artifact]] = {
        ArtifactKind.AI_CHAT_MESSAGE: [],
        ArtifactKind.AI_APP_PRESENCE: [],
        ArtifactKind.PARSE_WARNING: [],
    }
    for artifact in store.artifacts():
        source_paths[artifact.id] = artifact.provenance.source_path
        bucket = buckets.get(artifact.kind)
        if bucket is not None:
            bucket.append(artifact)

    events = list(store.events())
    first_event: dict[str, Any] = {}
    for event in events:
        first_event.setdefault(event.artifact_id, event)

    by_category = {cat: store.findings(cat) for cat in FindingCategory}
    all_findings = [f for cat in FindingCategory for f in by_category[cat]]
    attributions = store.attributions()

    linked_events: set[str] = set()
    linked_artifacts: set[str] = set()
    for cat in _LINKED_FINDING_CATEGORIES:
        for f in by_category[cat]:
            linked_events.update(f.event_ids)
            linked_artifacts.update(f.artifact_ids)
    for a in attributions:
        linked_artifacts.update(a.subject_artifact_ids)

    timeline: list[dict[str, Any]] = []
    priority: set[int] = set()
    for i, e in enumerate(events):
        timeline.append(
            {
                "ts_utc": fmt_utc(e.ts_utc) if e.ts_utc is not None else None,
                "ts_local": fmt_local(e.ts_utc, tz) if e.ts_utc is not None else None,
                "category": e.category.value,
                "actor": e.actor.value,
                "user": e.user,
                "summary": e.summary,
                "source_path": source_paths.get(e.artifact_id),
                "artifact_id": e.artifact_id,
                "category_label": _enum_label("category", e.category.value, lang),
                "actor_label": _enum_label("actor", e.actor.value, lang),
            }
        )
        if (
            e.actor is Actor.AI
            or e.category in _PRIORITY_CATEGORIES
            or e.id in linked_events
            or e.artifact_id in linked_artifacts
        ):
            priority.add(i)

    tools = _tools_section(case)
    runs = store.plugin_runs()
    run: dict[str, Any] = _plain(dict(run_info))
    run["created_utc"] = format_utc(case.created_utc)
    run["custody"] = [_plain(dict(e)) for e in custody_entries]
    run["plugin_timings"] = [
        {
            "evidence_id": r.evidence_id,
            "name": r.name,
            "started_utc": format_utc(r.started_utc),
            "finished_utc": format_utc(r.finished_utc),
            "seconds": (r.finished_utc - r.started_utc).total_seconds(),
        }
        for r in runs
    ]

    return ReportModel(
        case=_case_section(case, lang),
        evidence=_evidence_section(evidences, lang),
        tools=tools,
        methodology=_methodology_section(case, tools["dissect"], lang),
        summary=_summary_section(by_category, attributions, len(buckets[ArtifactKind.AI_CHAT_MESSAGE]), lang),
        ai_tools=_ai_tools_section(by_category[FindingCategory.AI_TOOL_USAGE], tz, lang),
        ai_queries=_ai_queries_section(buckets[ArtifactKind.AI_CHAT_MESSAGE], first_event, tz, lang),
        file_lifecycle=[_lifecycle_row(f, tz, lang) for f in by_category[FindingCategory.FILE_LIFECYCLE]],
        exfil=[_exfil_row(f, tz, lang) for f in by_category[FindingCategory.EXFIL_CHANNEL]],
        attribution=[_attribution_row(a, lang) for a in attributions],
        timeline=timeline,
        exports=store.exports(),
        coverage=_coverage_section(
            store,
            buckets[ArtifactKind.PARSE_WARNING],
            buckets[ArtifactKind.AI_APP_PRESENCE],
            by_category,
            lang,
        ),
        limitations=_limitations_section(all_findings, attributions, evidences, lang),
        custody=_custody_rows(custody_entries),
        signature={
            "examiner": case.examiner,
            "organisation": case.organisation,
            "signature": "",
            "date": "",
        },
        run=run,
        priority_rows=frozenset(priority),
    )
