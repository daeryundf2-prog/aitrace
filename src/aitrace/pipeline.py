from __future__ import annotations

import hashlib
import importlib
import logging
import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aitrace import __version__
from aitrace.acquisition import verify
from aitrace.acquisition.custody import CustodyLog
from aitrace.analyzers.base import Analyzer
from aitrace.core.ids import make_id
from aitrace.core.kinds import FindingCategory, Severity, band_for
from aitrace.core.model import Attribution, Case, Evidence, Finding
from aitrace.db.store import CaseStore
from aitrace.export.exporter import ExportEntry, export_artifacts
from aitrace.export.manifest import write_manifest
from aitrace.fs.base import EvidenceFS
from aitrace.fs.open import UnsupportedEvidence, ewf_segments, open_evidence
from aitrace.plugins.registry import load_plugins
from aitrace.plugins.runner import run_plugins
from aitrace.report.docx import render_docx
from aitrace.report.html import render_html
from aitrace.report.model import ReportModel, build_report_model
from aitrace.report.pdf import render_pdf
from aitrace.report.tabular import write_csvs, write_json
from aitrace.report.volume import render_prompts_volume, render_questions_volume

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INTEGRITY = 3
EXIT_REFUSED = 4
EXIT_EVIDENCE = 5
EXIT_CUSTODY = 6

FORMATS: tuple[str, ...] = ("html", "pdf", "docx", "json", "csv")
LANGS: tuple[str, ...] = ("ko", "en")
ANALYZER_MODULES: tuple[str, ...] = (
    "aitrace.analyzers.ai_sessions",
    "aitrace.analyzers.file_correlation",
    "aitrace.analyzers.exfil_channels",
    "aitrace.analyzers.attribution",
)
CASE_DB = "case.sqlite"
CUSTODY_FILE = "custody.jsonl"
LOG_FILE = "logs/aitrace.log"
REPORT_DIR = "report"
EXPORT_DIR = "export"
# `--force` deletes exactly these aitrace outputs and never any other file in the case dir.
CASE_OUTPUTS: tuple[str, ...] = (
    CASE_DB,
    f"{CASE_DB}-wal",
    f"{CASE_DB}-shm",
    CUSTODY_FILE,
    "logs",
    REPORT_DIR,
    EXPORT_DIR,
)
ACTOR = "aitrace"
DIR_EVIDENCE_LIMITATION = (
    "Directory evidence has no image segments; files were read in place and no acquisition hash exists"
)
INTEGRITY_RULE_ID = "INTEGRITY-REVERIFY"
INTEGRITY_LIMITATION = "Only segment files are re-hashed; the media stream is hashed once at intake"

LOGGER_NAME = "aitrace"
log = logging.getLogger(f"{LOGGER_NAME}.pipeline")


class PipelineError(Exception):
    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True, kw_only=True)
class AnalyzeOptions:
    images: tuple[Path, ...]
    case_dir: Path
    case_name: str = ""
    case_number: str = ""
    examiner: str = ""
    org: str = ""
    tz: str = "Asia/Seoul"
    lang: str = "ko"
    formats: tuple[str, ...] = FORMATS
    export: bool = True
    media_hash: bool = True
    force: bool = False


@dataclass(frozen=True, slots=True)
class RenderedReport:
    case_relative_path: str
    sha256: str


@dataclass(slots=True)
class PipelineResult:
    exit_code: int
    case_dir: Path
    counts: dict[str, int] = field(default_factory=dict)
    reports: list[RenderedReport] = field(default_factory=list)
    verification: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class _Opened:
    evidence: Evidence
    fs: EvidenceFS
    intake: dict[str, Any]


def parse_formats(value: str) -> tuple[str, ...]:
    wanted = [part.strip().lower() for part in value.split(",") if part.strip()]
    unknown = sorted(set(wanted) - set(FORMATS))
    if unknown:
        raise ValueError(f"unknown format(s): {', '.join(unknown)}; choose from {','.join(FORMATS)}")
    if not wanted:
        raise ValueError("at least one format is required")
    return tuple(fmt for fmt in FORMATS if fmt in wanted)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence_dir(image: Path) -> Path:
    resolved = image.resolve()
    return resolved if resolved.is_dir() else resolved.parent


def check_case_dir(images: Sequence[Path], case_dir: Path, force: bool) -> None:
    target = case_dir.resolve()
    for image in images:
        evidence_dir = _evidence_dir(image)
        if target.is_relative_to(evidence_dir):
            raise PipelineError(
                f"case dir {case_dir} is inside evidence directory {evidence_dir}; refusing to write there",
                EXIT_REFUSED,
            )
    if target.exists() and not target.is_dir():
        raise PipelineError(f"case dir {case_dir} exists and is not a directory", EXIT_REFUSED)
    if target.is_dir() and any(target.iterdir()) and not force:
        raise PipelineError(f"case dir {case_dir} is not empty; use --force to overwrite", EXIT_REFUSED)


def _clear_previous_outputs(case_dir: Path) -> None:
    for name in CASE_OUTPUTS:
        path = case_dir / name
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif path.exists() or path.is_symlink():
            path.unlink()


def _attach_log_file(case_dir: Path) -> logging.Handler:
    log_path = case_dir / LOG_FILE
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger(LOGGER_NAME)
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    return handler


def _detach_log_file(handler: logging.Handler) -> None:
    logging.getLogger(LOGGER_NAME).removeHandler(handler)
    handler.close()


def _segment_paths(image: Path) -> list[Path]:
    if image.suffix.lower() == ".e01":
        return [Path(p) for p in ewf_segments(image.resolve())]
    return [image.resolve()]


def intake_image(image: Path, *, media_hash: bool) -> dict[str, Any]:
    if not image.exists():
        raise PipelineError(f"evidence not found: {image}", EXIT_EVIDENCE)
    if image.is_dir():
        if not media_hash:
            return {
                "kind": "dir",
                "segments": [],
                "media_sha256": None,
                "acquisition_hashes": {},
                "limitations": [DIR_EVIDENCE_LIMITATION],
            }
        try:
            return verify.intake_dir(image.resolve())
        except OSError as exc:
            raise PipelineError(f"evidence unreadable: {image}: {exc}", EXIT_EVIDENCE) from exc
    try:
        return verify.intake(_segment_paths(image), skip_media=not media_hash)
    except (OSError, ValueError) as exc:
        raise PipelineError(f"evidence unreadable: {image}: {exc}", EXIT_EVIDENCE) from exc


def _open(image: Path, intake: dict[str, Any]) -> EvidenceFS:
    segments = intake["segments"]
    evidence_id = make_id("evidence", image.name, segments[0]["sha256"]) if segments else None
    try:
        return open_evidence(image, evidence_id)
    except (UnsupportedEvidence, OSError) as exc:
        raise PipelineError(f"evidence unreadable or unsupported: {image}: {exc}", EXIT_EVIDENCE) from exc


def _evidence_record(image: Path, fs: EvidenceFS, intake: dict[str, Any], status: str) -> Evidence:
    segments = intake["segments"]
    return Evidence(
        id=fs.evidence_id,
        kind=intake["kind"],
        path=str(image.resolve()),
        segments=tuple(seg["path"] for seg in segments),
        size=sum(seg["size"] for seg in segments) if segments else None,
        acquisition_hashes=dict(intake["acquisition_hashes"]),
        segment_hashes={seg["name"]: {k: seg[k] for k in ("md5", "sha1", "sha256")} for seg in segments},
        media_sha256=intake["media_sha256"],
        verification_status=status,
        volumes=tuple(fs.volumes()),
        users=tuple(fs.users()),
        limitations=tuple(intake["limitations"]),
    )


def load_analyzers() -> list[Analyzer]:
    analyzers: list[Analyzer] = []
    for dotted in ANALYZER_MODULES:
        analyzer: Analyzer = importlib.import_module(dotted).ANALYZER
        analyzers.append(analyzer)
    return analyzers


def _integrity_finding(
    evidence: Evidence, intake: dict[str, Any], current: dict[str, dict[str, str]]
) -> Finding:
    segments = {
        seg["name"]: {
            "intake_sha256": seg["sha256"],
            "reverify_sha256": current.get(seg["path"], {}).get("sha256"),
        }
        for seg in intake["segments"]
    }
    return Finding(
        id=make_id("finding", FindingCategory.INTEGRITY.value, evidence.id),
        category=FindingCategory.INTEGRITY,
        severity=Severity.HIGH,
        title=f"Evidence hash mismatch after analysis: {Path(evidence.path).name}",
        narrative=(
            "Re-hashing the evidence after analysis did not reproduce the intake hashes. "
            "The evidence may have changed during analysis; results must not be relied on until "
            "integrity is re-established."
        ),
        artifact_ids=(),
        event_ids=(),
        confidence=1.0,
        band=band_for(1.0),
        rule_id=INTEGRITY_RULE_ID,
        limitations=(INTEGRITY_LIMITATION,),
        data={"evidence_id": evidence.id, "segments": segments},
    )


def _count_results(items: Sequence[Finding | Attribution]) -> dict[str, int]:
    findings = sum(1 for item in items if isinstance(item, Finding))
    return {"findings": findings, "attributions": len(items) - findings}


def render_reports(
    model: ReportModel, case_dir: Path, formats: Sequence[str], custody: CustodyLog
) -> list[RenderedReport]:
    report_dir = case_dir / REPORT_DIR
    report_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    renderers: dict[str, Callable[[], None]] = {
        "html": lambda: written.extend(
            [
                render_html(model, report_dir / "report.html"),
                render_prompts_volume(model, report_dir / "prompts.html"),
                render_questions_volume(model, report_dir / "questions.html"),
            ]
        ),
        "pdf": lambda: written.append(render_pdf(model, report_dir / "report.pdf")),
        "docx": lambda: _render_docx(model, report_dir / "report.docx", written),
        "json": lambda: written.append(write_json(model, report_dir / "report.json")),
        "csv": lambda: written.extend(write_csvs(model, report_dir / "csv")),
    }
    for fmt in formats:
        renderers[fmt]()
        log.info("rendered %s", fmt)
    reports: list[RenderedReport] = []
    for path in written:
        rel = path.resolve().relative_to(case_dir.resolve()).as_posix()
        rendered = RenderedReport(case_relative_path=rel, sha256=_sha256_file(path))
        custody.append(ACTOR, "report_rendered", {"path": rel, "sha256": rendered.sha256})
        reports.append(rendered)
    return reports


def _render_docx(model: ReportModel, path: Path, written: list[Path]) -> None:
    render_docx(model, path)
    written.append(path)


def section_counts(model: ReportModel) -> dict[str, int]:
    return {
        "ai_tools": len(model.ai_tools),
        "ai_queries": len(model.ai_queries),
        "file_lifecycle": len(model.file_lifecycle),
        "exfil": len(model.exfil),
        "attribution": len(model.attribution),
        "timeline": len(model.timeline),
        "exports": len(model.exports),
        "coverage_findings": len(model.coverage["findings"]),
        "parse_warnings": len(model.coverage["parse_warnings"]),
    }


def _utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def analyze(opts: AnalyzeOptions) -> PipelineResult:
    check_case_dir(opts.images, opts.case_dir, opts.force)
    case_dir = opts.case_dir.resolve()
    case_dir.mkdir(parents=True, exist_ok=True)
    if opts.force:
        _clear_previous_outputs(case_dir)
    handler = _attach_log_file(case_dir)
    try:
        return _analyze(opts, case_dir)
    except PipelineError as exc:
        log.error("%s (exit %d)", exc, exc.exit_code)
        raise
    finally:
        _detach_log_file(handler)


def _analyze(opts: AnalyzeOptions, case_dir: Path) -> PipelineResult:
    started = datetime.now(UTC)
    durations: dict[str, float] = {}
    custody = CustodyLog(case_dir / CUSTODY_FILE)
    case = Case(
        id=make_id("case", opts.case_number),
        name=opts.case_name,
        number=opts.case_number,
        examiner=opts.examiner,
        organisation=opts.org,
        created_utc=started,
        timezone=opts.tz,
        lang=opts.lang,
        tool_version=__version__,
    )
    custody.append(
        ACTOR,
        "case_opened",
        {
            "case_id": case.id,
            "case_name": case.name,
            "case_number": case.number,
            "examiner": case.examiner,
            "organisation": case.organisation,
            "timezone": case.timezone,
            "lang": case.lang,
            "aitrace_version": __version__,
            "images": [image.name for image in opts.images],
        },
    )
    log.info("case %s opened in %s", case.number, case_dir)

    opened: list[_Opened] = []
    mark = datetime.now(UTC)
    for image in opts.images:
        intake = intake_image(image, media_hash=opts.media_hash)
        custody.append(
            ACTOR,
            "evidence_intake",
            {
                "image": image.name,
                "kind": intake["kind"],
                "segments": [
                    {k: seg[k] for k in ("name", "size", "md5", "sha1", "sha256")}
                    for seg in intake["segments"]
                ],
                "media_sha256": intake["media_sha256"],
                "acquisition_hashes": intake["acquisition_hashes"],
                **({"tree": intake["tree"]} if "tree" in intake else {}),
            },
        )
        fs = _open(image, intake)
        evidence = _evidence_record(image, fs, intake, "unverified")
        custody.append(
            ACTOR,
            "evidence_opened",
            {
                "image": image.name,
                "evidence_id": evidence.id,
                "volumes": len(evidence.volumes),
                "users": sorted(user.name for user in evidence.users),
            },
        )
        opened.append(_Opened(evidence=evidence, fs=fs, intake=intake))
    durations["intake"] = (datetime.now(UTC) - mark).total_seconds()

    store = CaseStore(case_dir / CASE_DB)
    try:
        return _analyze_store(opts, case_dir, case, store, custody, opened, started, durations)
    finally:
        store.close()


def _analyze_store(
    opts: AnalyzeOptions,
    case_dir: Path,
    case: Case,
    store: CaseStore,
    custody: CustodyLog,
    opened: list[_Opened],
    started: datetime,
    durations: dict[str, float],
) -> PipelineResult:
    store.init_case(case)
    for item in opened:
        store.put_evidence(item.evidence)

    mark = datetime.now(UTC)
    plugins = load_plugins()
    for item in opened:
        results = run_plugins(item.fs, store, item.evidence.id, plugins, log, opts.tz)
        custody.append(
            ACTOR,
            "plugins_run",
            {
                "evidence_id": item.evidence.id,
                "plugins": [f"{r.name}@{r.version}" for r in results],
                "records": sum(r.records for r in results),
                "warnings": sum(r.warnings for r in results),
                "errors": sorted(r.name for r in results if r.status == "error"),
            },
        )
    durations["plugins"] = (datetime.now(UTC) - mark).total_seconds()

    mark = datetime.now(UTC)
    for analyzer in load_analyzers():
        produced = list(analyzer.run(store, opts.tz))
        store.add_results(produced)
        custody.append(
            ACTOR,
            "analyzer_run",
            {"analyzer": analyzer.name, "version": analyzer.version, **_count_results(produced)},
        )
    durations["analyzers"] = (datetime.now(UTC) - mark).total_seconds()

    mark = datetime.now(UTC)
    if opts.export:
        _export(case_dir, store, custody, opened)
    durations["export"] = (datetime.now(UTC) - mark).total_seconds()
    store.finalize()

    mark = datetime.now(UTC)
    verification: dict[str, str] = {}
    for index, item in enumerate(opened):
        status, current = verify.reverify(item.intake)
        if status == "match" and not item.intake["segments"] and "tree" not in item.intake:
            final = "unverified"
        else:
            final = status
        verification[item.evidence.id] = final
        evidence = _evidence_record(Path(item.evidence.path), item.fs, item.intake, final)
        opened[index] = _Opened(evidence=evidence, fs=item.fs, intake=item.intake)
        store.put_evidence(evidence)
        custody.append(
            ACTOR,
            "evidence_reverified",
            {
                "evidence_id": evidence.id,
                "status": final,
                "segments": {
                    Path(path).name: digests.get("sha256") for path, digests in sorted(current.items())
                },
            },
        )
        if status == "mismatch":
            finding = _integrity_finding(evidence, item.intake, current)
            store.add_results([finding])
            log.error("integrity mismatch for evidence %s", evidence.id)
    durations["reverify"] = (datetime.now(UTC) - mark).total_seconds()

    mismatch = any(status == "mismatch" for status in verification.values())
    exit_code = EXIT_INTEGRITY if mismatch else EXIT_OK
    custody.append(
        ACTOR,
        "analysis_finished",
        {
            "exit_code": exit_code,
            "verification": dict(sorted(verification.items())),
            "formats": list(opts.formats),
        },
    )

    finished = datetime.now(UTC)
    durations["total"] = (finished - started).total_seconds()
    model = build_report_model(
        store,
        case,
        [item.evidence for item in opened],
        custody.entries(),
        {
            "started_utc": _utc(started),
            "finished_utc": _utc(finished),
            "durations": durations,
            "case_dir": str(case_dir),
        },
        opts.tz,
        opts.lang,
    )
    reports = render_reports(model, case_dir, opts.formats, custody)
    log.info("analysis finished with exit code %d", exit_code)
    return PipelineResult(
        exit_code=exit_code,
        case_dir=case_dir,
        counts=section_counts(model),
        reports=reports,
        verification=verification,
    )


def _export(case_dir: Path, store: CaseStore, custody: CustodyLog, opened: list[_Opened]) -> None:
    if len(opened) != 1:
        # The exporter resolves artifact sources without an evidence filter, so exporting from
        # several evidence trees at once would read paths from the wrong evidence.
        reason = "export supports one evidence item per case; skipped for multi-evidence cases"
        log.warning(reason)
        custody.append(ACTOR, "export_skipped", {"reason": reason, "evidence_count": len(opened)})
        return
    entries: list[ExportEntry] = export_artifacts(opened[0].fs, store, case_dir)
    manifests = write_manifest(entries, case_dir / EXPORT_DIR)
    custody.append(
        ACTOR,
        "export_written",
        {
            "files": sum(1 for entry in entries if entry.sha256),
            "skipped": sum(1 for entry in entries if not entry.sha256),
            "manifests": {
                path.resolve().relative_to(case_dir).as_posix(): _sha256_file(path) for path in manifests
            },
        },
    )


def report(case_dir: Path, lang: str | None, formats: Sequence[str]) -> PipelineResult:
    case_dir = case_dir.resolve()
    custody = CustodyLog(case_dir / CUSTODY_FILE)
    db_path = case_dir / CASE_DB
    if not custody.path.is_file() or not db_path.is_file():
        raise PipelineError(
            f"{case_dir} is not an aitrace case dir (missing {CUSTODY_FILE} or {CASE_DB})", EXIT_USAGE
        )
    if not custody.verify_chain():
        raise PipelineError(f"custody chain in {custody.path} is broken; refusing to render", EXIT_CUSTODY)
    handler = _attach_log_file(case_dir)
    store = CaseStore(db_path)
    try:
        case = store.case()
        if case is None:
            raise PipelineError(f"{db_path} holds no case record", EXIT_USAGE)
        render_lang = lang or case.lang
        started = datetime.now(UTC)
        custody.append(ACTOR, "report_requested", {"lang": render_lang, "formats": list(formats)})
        evidences = store.evidences()
        model = build_report_model(
            store,
            case,
            evidences,
            custody.entries(),
            {
                "started_utc": _utc(started),
                "finished_utc": _utc(datetime.now(UTC)),
                "durations": {},
                "case_dir": str(case_dir),
            },
            case.timezone,
            render_lang,
        )
        reports = render_reports(model, case_dir, formats, custody)
        return PipelineResult(
            exit_code=EXIT_OK,
            case_dir=case_dir,
            counts=section_counts(model),
            reports=reports,
            verification={ev.id: ev.verification_status for ev in evidences},
        )
    finally:
        store.close()
        _detach_log_file(handler)


def verify_image(image: Path, *, media_hash: bool = True) -> dict[str, Any]:
    if image.is_dir():
        raise PipelineError(f"{image} is a directory; verify hashes image files only", EXIT_EVIDENCE)
    return intake_image(image, media_hash=media_hash)
