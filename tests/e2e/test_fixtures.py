from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from aitrace.acquisition.custody import CustodyLog
from aitrace.report.i18n import STRINGS

REPO = Path(__file__).resolve().parents[2]
AITRACE = REPO / ".venv" / "bin" / "aitrace"
IMAGES = REPO / "tests" / "fixtures" / "images"
EXPECTED = REPO / "tests" / "fixtures" / "expected"
OS_NAMES: tuple[str, ...] = ("windows", "macos", "linux")
FORMATS = "html,pdf,docx,json,csv"
RUN_TIMEOUT_S = 900
NOT_EXPORTED_NOTE = "source not found or not a regular file"
CHAPTER_KEYS: tuple[str, ...] = (
    "chapter.overview",
    "chapter.summary",
    "chapter.prompts",
    "chapter.generated",
    "chapter.timeline",
    "chapter.changes",
    "chapter.transfer",
    "chapter.limits",
    "chapter.opinion",
    "annex.exports",
    "annex.custody",
    "annex.signature",
)


@dataclass(frozen=True, slots=True)
class Analysis:
    os_name: str
    case_dir: Path
    report: dict[str, Any]
    image_sha256_before: str
    image_sha256_after: str
    image_mtime_ns_before: int
    image_mtime_ns_after: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_analyze(image: Path, case_dir: Path, case_number: str, extra: tuple[str, ...] = ()) -> None:
    cmd = [
        sys.executable,
        "-m",
        "aitrace.cli.main",
        "analyze",
        str(image),
        "--case-dir",
        str(case_dir),
        "--case-number",
        case_number,
        "--examiner",
        "QA",
        "--formats",
        FORMATS,
        *extra,
    ]
    proc = subprocess.run(
        cmd, cwd=REPO, capture_output=True, text=True, timeout=RUN_TIMEOUT_S, check=False
    )
    assert proc.returncode == 0, f"aitrace exited {proc.returncode}; stderr tail:\n{proc.stderr[-2000:]}"


def _load_report(case_dir: Path) -> dict[str, Any]:
    loaded = json.loads((case_dir / "report" / "report.json").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _expected(os_name: str) -> dict[str, Any]:
    loaded = json.loads((EXPECTED / f"{os_name}.json").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _lower_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False).lower()


def _walk_values(node: object, key: str) -> Iterator[object]:
    if isinstance(node, Mapping):
        for k, v in node.items():
            if k == key:
                yield v
            yield from _walk_values(v, key)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_values(item, key)


def fact_failures(report: Mapping[str, Any], expected: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []

    users = sorted({u["name"] for ev in report["evidence"] for u in ev["users"]})
    missing_users = [u for u in expected.get("users", []) if u not in users]
    if missing_users:
        failures.append(f"users missing {missing_users}; report evidence users: {users}")

    tool_names = {row["tool"] for row in report["ai_tools"]}
    missing_tools = [t for t in expected.get("tools", []) if t not in tool_names]
    if missing_tools:
        failures.append(f"tools missing {missing_tools}; ai_tools rows: {sorted(map(str, tool_names))}")

    queries = [str(q["text"]) for q in report["ai_queries"]]
    for prompt in expected.get("prompts_contain", []):
        if not any(prompt in text for text in queries):
            failures.append(f"prompt not found in any ai_queries text: {prompt!r}")

    for path in expected.get("deleted_files", []):
        rows = [r for r in report["file_lifecycle"] if path in json.dumps(r, ensure_ascii=False)]
        if not any("deleted" in _lower_json(r["data"]) for r in rows):
            failures.append(f"no deleted file_lifecycle row for {path!r}; matched rows: {len(rows)}")

    exfil_text = _lower_json(report["exfil"])
    for channel in expected.get("exfil", []):
        if channel.lower() not in exfil_text:
            failures.append(f"exfil channel not found: {channel!r}")

    for subject, verdict in expected.get("attributions", {}).items():
        matches = [a for a in report["attribution"] if a["subject"] == subject]
        if not matches:
            failures.append(f"no attribution row for subject {subject!r}")
        elif matches[0]["verdict"] != verdict:
            failures.append(
                f"attribution verdict for {subject!r}: expected {verdict!r}, actual {matches[0]['verdict']!r}"
            )

    trailer_sources = [
        report["attribution"],
        report["file_lifecycle"],
        report["exfil"],
        report["coverage"]["findings"],
    ]
    trailers = [str(v).lower() for source in trailer_sources for v in _walk_values(source, "ai_trailer")]
    trailers += [
        str(signal.get("note", "")).lower()
        for row in report["attribution"]
        for signal in row["signals"]
        if signal.get("type") == "vcs_ai_trailer"
    ]
    for tool in expected.get("vcs_ai_trailers", []):
        if not any(tool.lower() in trailer for trailer in trailers):
            failures.append(f"vcs ai_trailer not found for {tool!r}; trailers seen: {trailers}")

    coverage_text = json.dumps(report["coverage"], ensure_ascii=False)
    for needle in expected.get("coverage_contains", []):
        if needle not in coverage_text:
            failures.append(f"coverage does not contain {needle!r}")

    credential_text = _lower_json([r for r in report["ai_tools"] if r["kind"] == "credential"])
    for provider in expected.get("credentials_providers", []):
        if provider.lower() not in credential_text:
            failures.append(f"credential provider not found in ai_tools rows: {provider!r}")

    report_text = json.dumps(report, ensure_ascii=False)
    for needle in expected.get("download_origins", []):
        if needle not in report_text:
            failures.append(f"download origin not found in report.json: {needle!r}")
    for needle in expected.get("cache_images", []):
        if needle not in report_text:
            failures.append(f"cache image not found in report.json: {needle!r}")
    for needle in expected.get("download_origins", []):
        if not needle.endswith(".png"):
            continue
        rows = [a for a in report["attribution"] if needle in str(a["subject"])]
        if not rows:
            failures.append(f"no attribution row for {needle!r}")
            continue
        row = rows[0]
        if row["verdict"] == "human":
            failures.append(f"attribution verdict for {needle!r} is human")
        if not any(s.get("type") == "ai_download_origin" for s in row["signals"]):
            failures.append(f"{needle!r} lacks an ai_download_origin signal")

    return failures


def _without_run(report: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in report.items() if k != "run"}


@pytest.fixture(scope="module", params=OS_NAMES)
def analysis(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> Analysis:
    os_name: str = request.param
    image = IMAGES / f"{os_name}.E01"
    if not image.is_file():
        pytest.skip(f"E01 fixture missing: {image}")
    case_dir = tmp_path_factory.mktemp(f"{os_name}-a", numbered=True)
    sha_before = _sha256(image)
    mtime_before = image.stat().st_mtime_ns
    _run_analyze(image, case_dir, f"T-{os_name}")
    return Analysis(
        os_name=os_name,
        case_dir=case_dir,
        report=_load_report(case_dir),
        image_sha256_before=sha_before,
        image_sha256_after=_sha256(image),
        image_mtime_ns_before=mtime_before,
        image_mtime_ns_after=image.stat().st_mtime_ns,
    )


def test_expected_facts(analysis: Analysis) -> None:
    failures = fact_failures(analysis.report, _expected(analysis.os_name))
    assert not failures, f"{analysis.os_name}: {len(failures)} fact(s) failed:\n" + "\n".join(
        f"- {f}" for f in failures
    )


def test_run_twice_is_deterministic(analysis: Analysis, tmp_path_factory: pytest.TempPathFactory) -> None:
    second = tmp_path_factory.mktemp(f"{analysis.os_name}-b", numbered=True)
    _run_analyze(IMAGES / f"{analysis.os_name}.E01", second, f"T-{analysis.os_name}")
    first = _without_run(analysis.report)
    again = _without_run(_load_report(second))
    differing = sorted(k for k in first.keys() | again.keys() if first.get(k) != again.get(k))
    assert not differing, f"{analysis.os_name}: report.json differs between runs in sections {differing}"


def test_export_manifest_matches_disk(analysis: Analysis) -> None:
    manifest = json.loads((analysis.case_dir / "export" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest, f"{analysis.os_name}: export manifest is empty"
    mismatches: list[str] = []
    for entry in manifest:
        if entry.get("note") == NOT_EXPORTED_NOTE:
            continue
        path = analysis.case_dir / entry["export_path"]
        if str(entry.get("note", "")).startswith("not copied: file holds credentials"):
            if path.exists():
                mismatches.append(f"credential file copied: {entry['export_path']}")
            continue
        if not path.is_file():
            mismatches.append(f"missing file: {entry['export_path']}")
        elif _sha256(path) != entry["sha256"] or path.stat().st_size != entry["size"]:
            mismatches.append(f"hash or size mismatch: {entry['export_path']}")
    assert not mismatches, f"{analysis.os_name}: manifest mismatches:\n" + "\n".join(mismatches)


def test_evidence_untouched(analysis: Analysis) -> None:
    assert analysis.image_sha256_before == analysis.image_sha256_after, f"{analysis.os_name}: E01 sha256 changed"
    assert analysis.image_mtime_ns_before == analysis.image_mtime_ns_after, (
        f"{analysis.os_name}: E01 mtime changed"
    )


def test_custody_chain_verifies(analysis: Analysis) -> None:
    assert CustodyLog(analysis.case_dir / "custody.jsonl").verify_chain(), (
        f"{analysis.os_name}: custody chain does not verify"
    )


def test_timeline_csv_rows_have_source_and_local_time(analysis: Analysis) -> None:
    path = analysis.case_dir / "report" / "csv" / "timeline.csv"
    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        fields = reader.fieldnames or []
        rows = list(reader)
    assert "ts_local" in fields, f"{analysis.os_name}: timeline.csv columns {fields}"
    assert rows, f"{analysis.os_name}: timeline.csv has no rows"
    blank = [line for line, row in enumerate(rows, start=2) if not (row.get("source_path") or "").strip()]
    assert not blank, f"{analysis.os_name}: timeline.csv rows with empty source_path (lines): {blank}"


def test_ai_tools_rows_carry_first_and_last_seen(analysis: Analysis) -> None:
    rows = analysis.report["ai_tools"]
    assert rows, f"{analysis.os_name}: ai_tools is empty"
    missing = [i for i, row in enumerate(rows) if not {"first_seen", "last_seen"} <= row.keys()]
    assert not missing, f"{analysis.os_name}: ai_tools rows missing first_seen/last_seen at indexes {missing}"


def test_linux_lang_en_uses_english_headings(tmp_path_factory: pytest.TempPathFactory) -> None:
    image = IMAGES / "linux.E01"
    if not image.is_file():
        pytest.skip(f"E01 fixture missing: {image}")
    case_dir = tmp_path_factory.mktemp("linux-en", numbered=True)
    _run_analyze(image, case_dir, "T-linux", extra=("--lang", "en"))
    report = _load_report(case_dir)
    assert report["case"]["lang"] == "en", f"case.lang is {report['case']['lang']!r}"
    html = (case_dir / "report" / "report.html").read_text(encoding="utf-8")
    headings = [STRINGS["en"][key].replace("'", "&#39;") for key in CHAPTER_KEYS]
    missing = [h for h in headings if h not in html]
    assert not missing, f"English chapter headings missing from report.html: {missing}"
    assert [c["title"] for c in report["chapters"]] == [STRINGS["en"][key] for key in CHAPTER_KEYS]
