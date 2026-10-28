from __future__ import annotations

import codecs
import csv
import io
import json
from pathlib import Path
from typing import Any

from aitrace.report.model import TIMELINE_COLUMNS, ReportModel
from aitrace.report.tabular import (
    AI_QUERY_COLUMNS,
    ATTRIBUTION_COLUMNS,
    FINDINGS_COLUMNS,
    QUESTION_CSV_CUT_NOTE,
    QUESTION_CSV_TEXT_LIMIT,
    _excel_question,
    write_csvs,
    write_json,
)

CSV_NAMES = (
    "timeline.csv",
    "ai_queries.csv",
    "questions.csv",
    "findings.csv",
    "attributions.csv",
    "file_lifecycle.csv",
    "exfil.csv",
)


def _finding(fid: str, severity: str = "high") -> dict[str, Any]:
    return {
        "id": fid,
        "severity": severity,
        "title": f"title {fid}",
        "narrative": "narrative, with comma",
        "confidence": 0.9,
        "band": "strong",
        "rule_id": "rule.x",
        "artifact_ids": ["a2", "a1"],
        "event_ids": [],
        "limitations": ["lim one"],
        "data": {},
    }


def _model() -> ReportModel:
    return ReportModel(
        case={},
        evidence=[],
        tools={},
        methodology={},
        summary=[],
        ai_tools=[
            {
                "kind": "usage",
                "tool": "Claude Code",
                "user": "kim",
                "finding_id": "f-usage",
                "title": "usage",
                "severity": "medium",
                "narrative": "used",
                "data": {},
            },
            {"kind": "presence", "tool": "Cursor", "artifact_id": "p1", "data": {}},
        ],
        ai_queries=[
            {
                "ts_utc": "2026-03-01T09:00:00Z",
                "ts_local": "2026-03-01T18:00:00+09:00",
                "tool": "Claude Code",
                "session": "s1",
                "role": "user",
                "actor": "human",
                "text": "한글 텍스트, with comma\nsecond line",
                "source": "/Users/kim/.claude/s1.jsonl",
                "artifact_id": "m1",
                "fragment": False,
            }
        ],
        file_lifecycle=[_finding("f-life")],
        exfil=[_finding("f-exfil", "low")],
        attribution=[
            {
                "id": "att1",
                "subject": "/Users/kim/out.png",
                "verdict": "ai_generated",
                "confidence": 0.8,
                "band": "moderate",
                "signals": [],
                "rationale": "metadata",
                "subject_artifact_ids": ["s2", "s1"],
                "limitations": ["lim"],
            }
        ],
        timeline=[
            {
                "ts_utc": "2026-03-01T09:00:00Z",
                "ts_local": "2026-03-01T18:00:00+09:00",
                "category": "ai_activity",
                "actor": "human",
                "user": "kim",
                "summary": "prompt: a, b",
                "source_path": "/Users/kim/.claude/s1.jsonl",
                "artifact_id": "m1",
            }
        ],
        exports=[],
        coverage={
            "plugin_runs": [],
            "parse_warnings": [],
            "not_decoded": [],
            "findings": [{**_finding("f-cov", "info"), "section": "coverage"}],
        },
        limitations=[],
        custody=[],
        signature={},
        run={},
    )


def _read_csv(path: Path) -> list[list[str]]:
    return list(csv.reader(io.StringIO(path.read_bytes().decode("utf-8-sig"))))


def test_write_csvs_emits_all_tables_with_bom_and_headers(tmp_path: Path) -> None:
    paths = write_csvs(_model(), tmp_path)

    assert [p.name for p in paths] == list(CSV_NAMES)
    for path in paths:
        assert path.read_bytes().startswith(codecs.BOM_UTF8)
    assert _read_csv(tmp_path / "timeline.csv")[0] == list(TIMELINE_COLUMNS)
    assert _read_csv(tmp_path / "ai_queries.csv")[0] == list(AI_QUERY_COLUMNS)
    assert _read_csv(tmp_path / "findings.csv")[0] == list(FINDINGS_COLUMNS)
    assert _read_csv(tmp_path / "attributions.csv")[0] == list(ATTRIBUTION_COLUMNS)


def test_write_csvs_keeps_values_and_quotes_commas(tmp_path: Path) -> None:
    write_csvs(_model(), tmp_path)

    query = _read_csv(tmp_path / "ai_queries.csv")[1]
    assert query[AI_QUERY_COLUMNS.index("text")] == "한글 텍스트, with comma\nsecond line"
    findings = _read_csv(tmp_path / "findings.csv")
    sections = [row[0] for row in findings[1:]]
    assert sections == ["ai_tools", "coverage"]
    assert findings[2][FINDINGS_COLUMNS.index("narrative")] == "narrative, with comma"


def test_attribution_subject_artifacts_are_sorted_and_joined(tmp_path: Path) -> None:
    write_csvs(_model(), tmp_path)

    row = _read_csv(tmp_path / "attributions.csv")[1]
    assert row[ATTRIBUTION_COLUMNS.index("subject_artifact_ids")] == "s2;s1"


def test_write_csvs_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    write_csvs(_model(), first)
    write_csvs(_model(), second)

    for name in CSV_NAMES:
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_write_json_round_trips_model_dict(tmp_path: Path) -> None:
    model = _model()

    path = write_json(model, tmp_path / "report.json")

    assert json.loads(path.read_text(encoding="utf-8")) == model.to_dict()


def test_question_text_is_cut_to_fit_one_excel_cell() -> None:
    long_q = {"no": 1, "text": "가" * (QUESTION_CSV_TEXT_LIMIT + 5)}
    cut = _excel_question(long_q)
    assert cut["text"] == "가" * QUESTION_CSV_TEXT_LIMIT + QUESTION_CSV_CUT_NOTE
    assert len(cut["text"]) <= 32_767
    assert long_q["text"] == "가" * (QUESTION_CSV_TEXT_LIMIT + 5)
    short_q = {"no": 2, "text": "짧은 질문"}
    assert _excel_question(short_q) is short_q
