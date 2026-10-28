from __future__ import annotations

import csv
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from aitrace.report.model import TIMELINE_COLUMNS, ReportModel

QUESTION_CSV_TEXT_LIMIT = (
    32_000  # Excel holds at most 32,767 characters per cell; the full text is in questions.html
)
QUESTION_CSV_CUT_NOTE = " …(이하 생략, 전문은 report/questions.html)"
QUESTION_COLUMNS: tuple[str, ...] = (
    "no",
    "ts_local",
    "machine",
    "channel",
    "session",
    "topics",
    "attachment",
    "duplicates",
    "text",
    "source",
)
AI_INPUT_COLUMNS: tuple[str, ...] = ("ts_local", "machine", "channel", "sender", "session", "text", "source")
AI_QUERY_COLUMNS: tuple[str, ...] = (
    "ts_utc",
    "ts_local",
    "tool",
    "session",
    "role",
    "actor",
    "text",
    "source",
    "artifact_id",
    "fragment",
)
ATTRIBUTION_COLUMNS: tuple[str, ...] = (
    "id",
    "subject",
    "verdict",
    "confidence",
    "band",
    "rationale",
    "subject_artifact_ids",
    "limitations",
)
FINDING_COLUMNS: tuple[str, ...] = (
    "id",
    "severity",
    "title",
    "narrative",
    "confidence",
    "band",
    "rule_id",
    "artifact_ids",
    "event_ids",
    "limitations",
)
FINDINGS_COLUMNS: tuple[str, ...] = ("section", *FINDING_COLUMNS)


def _cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ";".join(_cell(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _write_csv(path: Path, columns: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> Path:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([_cell(row.get(column)) for column in columns])
    return path


def _findings_rows(model: ReportModel) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [{**row, "section": "coverage"} for row in model.coverage["findings"]]
    rows.extend(
        {
            "section": "ai_tools",
            "id": row.get("finding_id") or row.get("tool"),
            "severity": row.get("severity") or "info",
            "title": row.get("title") or f"{row.get('tool')} ({row.get('kind_label') or row.get('kind')})",
            "narrative": row.get("narrative")
            or f"{row.get('first_seen_local') or '-'} ~ {row.get('last_seen_local') or '-'} / {row.get('evidence_count') or 0}",
        }
        for row in model.ai_tools
    )
    return sorted(rows, key=lambda r: (r["section"], str(r.get("id") or "")))


def write_json(model: ReportModel, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(model.to_json() + "\n", encoding="utf-8")
    return path


def _excel_question(q: Mapping[str, Any]) -> Mapping[str, Any]:
    text = str(q.get("text") or "")
    if len(text) <= QUESTION_CSV_TEXT_LIMIT:
        return q
    return {**q, "text": text[:QUESTION_CSV_TEXT_LIMIT] + QUESTION_CSV_CUT_NOTE}


def write_csvs(model: ReportModel, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    tables: list[tuple[str, Sequence[str], Sequence[Mapping[str, Any]]]] = [
        ("timeline.csv", TIMELINE_COLUMNS, model.timeline),
        ("ai_queries.csv", AI_QUERY_COLUMNS, [_excel_question(q) for q in model.ai_queries]),
        ("questions.csv", QUESTION_COLUMNS, [_excel_question(q) for q in model.questions]),
        (
            "ai_sent_inputs.csv",
            AI_INPUT_COLUMNS,
            [_excel_question(a) for a in model.question_stats.get("ai_inputs") or ()],
        ),
        ("findings.csv", FINDINGS_COLUMNS, _findings_rows(model)),
        ("attributions.csv", ATTRIBUTION_COLUMNS, model.attribution),
        ("file_lifecycle.csv", FINDING_COLUMNS, model.file_lifecycle),
        ("exfil.csv", FINDING_COLUMNS, model.exfil),
    ]
    return [_write_csv(out_dir / name, columns, rows) for name, columns, rows in tables]
