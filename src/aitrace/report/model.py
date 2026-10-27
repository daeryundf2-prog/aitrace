from __future__ import annotations

import json
import platform
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
from aitrace.core.time import fmt_local, fmt_utc
from aitrace.db.store import CaseStore
from aitrace.report.i18n import STANDARDS, STRINGS, t

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

TIMELINE_LIMIT_PDF_DOCX = 5000
TIMELINE_LIMIT_HTML = 20000
TIMELINE_CSV_PATH = "report/csv/timeline.csv"
TOP_FINDINGS = 3

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
_TOOL_ROW_ORDER = {"usage": 0, "presence": 1, "model": 2, "credential": 3}
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

    def timeline_note(self, limit: int, lang: str) -> str | None:
        omitted = len(self.timeline) - limit
        if omitted <= 0:
            return None
        return t("timeline.note", lang, limit=limit, omitted=omitted, csv=TIMELINE_CSV_PATH)


def _label(key: str, lang: str, fallback: str) -> str:
    table = STRINGS.get(lang, STRINGS["en"])
    return table.get(key, fallback)


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


def _finding_row(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "severity": finding.severity.value,
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


def _attribution_row(item: Attribution) -> dict[str, Any]:
    return {
        "id": item.id,
        "subject": item.subject,
        "verdict": item.verdict.value,
        "confidence": item.confidence,
        "band": item.band.value,
        "signals": [s.to_dict() for s in item.signals],
        "rationale": item.rationale,
        "subject_artifact_ids": list(item.subject_artifact_ids),
        "limitations": list(item.limitations),
    }


def _tool_row(kind: str, **values: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "kind": kind,
        "tool": None,
        "provider": None,
        "user": None,
        "status": None,
        "detail": None,
        "source_path": None,
        "artifact_id": None,
        "finding_id": None,
        "title": None,
        "severity": None,
        "narrative": None,
        "data": {},
    }
    row.update(values)
    return row


def _ai_tools_section(
    usage: Sequence[Finding],
    presence: Sequence[Artifact],
    models: Sequence[Artifact],
    credentials: Sequence[Artifact],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for f in usage:
        rows.append(
            _tool_row(
                "usage",
                tool=f.data.get("tool"),
                user=f.data.get("user"),
                finding_id=f.id,
                title=f.title,
                severity=f.severity.value,
                narrative=f.narrative,
                data=_plain(f.data),
            )
        )
    for a in presence:
        rows.append(
            _tool_row(
                "presence",
                tool=a.data.get("tool"),
                user=a.user,
                status=a.data.get("status"),
                detail=a.data.get("detail"),
                source_path=a.provenance.source_path,
                artifact_id=a.id,
            )
        )
    for a in models:
        rows.append(
            _tool_row(
                "model",
                tool=a.data.get("tool"),
                user=a.user,
                detail=a.data.get("model_name"),
                source_path=a.provenance.source_path,
                artifact_id=a.id,
            )
        )
    for a in credentials:
        rows.append(
            _tool_row(
                "credential",
                tool=a.data.get("tool"),
                provider=a.data.get("provider"),
                user=a.user,
                detail=a.data.get("redacted"),
                source_path=a.provenance.source_path,
                artifact_id=a.id,
            )
        )
    rows.sort(
        key=lambda r: (
            _TOOL_ROW_ORDER[r["kind"]],
            r["tool"] or "",
            r["provider"] or "",
            r["artifact_id"] or "",
            r["finding_id"] or "",
        )
    )
    return rows


def _query_actor(role: str, event_actor: Actor | None) -> str:
    if event_actor is not None:
        return event_actor.value
    return _ROLE_ACTOR.get(role, Actor.UNKNOWN).value


def _ai_queries_section(
    messages: Sequence[Artifact], first_event: Mapping[str, Any], tz: str
) -> list[dict[str, Any]]:
    keyed: list[tuple[tuple[bool, str], dict[str, Any]]] = []
    for a in messages:
        event = first_event.get(a.id)
        ts: datetime | None = event.ts_utc if event is not None else None
        role = str(a.data.get("role", "unknown"))
        row = {
            "ts_utc": fmt_utc(ts) if ts is not None else None,
            "ts_local": fmt_local(ts, tz) if ts is not None else None,
            "tool": a.data.get("tool"),
            "session": a.data.get("session_id"),
            "role": role,
            "actor": _query_actor(role, event.actor if event is not None else None),
            "text": a.data.get("text", ""),
            "source": a.provenance.source_path,
            "artifact_id": a.id,
            "fragment": bool(a.data.get("fragment", False)),
        }
        keyed.append(((ts is None, ts.isoformat() if ts is not None else ""), row))
    keyed.sort(key=lambda pair: pair[0])
    return [row for _, row in keyed]


def _top_bullets(findings: Sequence[Finding], lang: str) -> list[str]:
    return [
        t("summary.top", lang, severity=t(f"severity.{f.severity.value}", lang), title=f.title)
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
        {"id": f"Q{i}", "question": t(f"summary.q{i}", lang), "bullets": bullets}
        for i, bullets in enumerate((q1, q2, q3, q4, q5), start=1)
    ]


def _coverage_section(
    store: CaseStore,
    warnings: Sequence[Artifact],
    presence: Sequence[Artifact],
    by_category: Mapping[FindingCategory, Sequence[Finding]],
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
        "findings": [_finding_row(f) for f in related],
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
    return result


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
        ArtifactKind.AI_CREDENTIAL: [],
        ArtifactKind.AI_APP_PRESENCE: [],
        ArtifactKind.AI_MODEL: [],
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
        ai_tools=_ai_tools_section(
            by_category[FindingCategory.AI_TOOL_USAGE],
            buckets[ArtifactKind.AI_APP_PRESENCE],
            buckets[ArtifactKind.AI_MODEL],
            buckets[ArtifactKind.AI_CREDENTIAL],
        ),
        ai_queries=_ai_queries_section(buckets[ArtifactKind.AI_CHAT_MESSAGE], first_event, tz),
        file_lifecycle=[_finding_row(f) for f in by_category[FindingCategory.FILE_LIFECYCLE]],
        exfil=[_finding_row(f) for f in by_category[FindingCategory.EXFIL_CHANNEL]],
        attribution=[_attribution_row(a) for a in attributions],
        timeline=timeline,
        exports=store.exports(),
        coverage=_coverage_section(
            store,
            buckets[ArtifactKind.PARSE_WARNING],
            buckets[ArtifactKind.AI_APP_PRESENCE],
            by_category,
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
