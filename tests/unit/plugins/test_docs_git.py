from __future__ import annotations

import io
import logging
import subprocess
import zipfile
from pathlib import Path

from docx import Document
from pypdf import PdfWriter

from aitrace.core.kinds import ArtifactKind, OsFamily, SignalType
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.provenance.docs_git import PLUGIN

LOG = logging.getLogger("tests.docs_git")
APP_PART = "docProps/app.xml"
APP_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
    "<Application>{application}</Application><TotalTime>{total}</TotalTime>"
    "</Properties>"
)
GIT_IDENTITY = ("-c", "user.name=Kim", "-c", "user.email=kim@example.com", "-c", "commit.gpgsign=false")


def _run(files: dict[str, bytes]) -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=OsFamily.MACOS)
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="UTC", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _of_kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _docx(*, author: str, revision: int, application: str, total_time: int) -> bytes:
    doc = Document()
    doc.core_properties.author = author
    doc.core_properties.revision = revision
    buf = io.BytesIO()
    doc.save(buf)
    app_xml = APP_TEMPLATE.format(application=application, total=total_time).encode("utf-8")
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as src, zipfile.ZipFile(out, "w") as dst:
        for name in src.namelist():
            if name != APP_PART:
                dst.writestr(name, src.read(name))
        dst.writestr(APP_PART, app_xml)
    return out.getvalue()


def _pdf(producer: str) -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.metadata = {"/Producer": producer, "/Creator": "Writer"}
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _make_repo(root: Path) -> None:
    root.mkdir()
    _git(root, "init", "-q")
    (root / "a.txt").write_text("one\n")
    _git(root, "add", "a.txt")
    _git(root, *GIT_IDENTITY, "commit", "-q", "-m", "feat: first")
    (root / "b.txt").write_text("two\n")
    _git(root, "add", "b.txt")
    _git(
        root,
        *GIT_IDENTITY,
        "commit",
        "-q",
        "-m",
        "feat: generated",
        "-m",
        "Co-Authored-By: Claude <noreply@anthropic.com>",
    )
    (root / "CLAUDE.md").write_text("# rules\n")


def _tree(root: Path, prefix: str) -> dict[str, bytes]:
    return {f"{prefix}/{p.relative_to(root).as_posix()}": p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_docx_metadata_carries_python_docx_and_human_process_hints() -> None:
    payload = _docx(author="Kim", revision=6, application="python-docx", total_time=45)
    records = _run({"/Users/kim/Documents/report.docx": payload})
    [doc] = _of_kind(records, ArtifactKind.DOC_METADATA)
    assert doc.data["path"] == "/Users/kim/Documents/report.docx"
    assert doc.data["application"] == "python-docx"
    assert doc.data["creator"] == "Kim"
    assert doc.data["total_time"] == 45
    assert doc.data["revision"] == 6
    hint_types = {(h["type"], h["value"]) for h in doc.data["hints"]}
    assert (SignalType.METADATA_HINT.value, "python-docx") in hint_types
    assert any(h["type"] == SignalType.HUMAN_PROCESS.value for h in doc.data["hints"])


def test_pdf_producer_hint_is_emitted() -> None:
    records = _run({"/Users/kim/Desktop/invoice.pdf": _pdf("ReportLab PDF Library - www.reportlab.com")})
    [doc] = _of_kind(records, ArtifactKind.DOC_METADATA)
    assert doc.data["path"] == "/Users/kim/Desktop/invoice.pdf"
    assert doc.data["producer"].startswith("ReportLab")
    assert {"type": SignalType.METADATA_HINT.value, "value": "ReportLab"} in doc.data["hints"]


def test_corrupt_docx_yields_parse_warning() -> None:
    records = _run({"/Users/kim/Documents/broken.docx": b"this is not a zip archive"})
    assert _of_kind(records, ArtifactKind.DOC_METADATA) == []
    [warning] = _of_kind(records, ArtifactKind.PARSE_WARNING)
    assert warning.data["plugin"] == "docs_git"
    assert warning.data["message"]


def test_git_history_flags_claude_trailer_commit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _make_repo(repo)
    records = _run(_tree(repo, "/Users/kim/repo"))

    commits = {r.data["message"]: r for r in _of_kind(records, ArtifactKind.VCS_COMMIT)}
    assert set(commits) == {"feat: first", "feat: generated"}
    flagged = commits["feat: generated"]
    assert flagged.data["repo_path"] == "/Users/kim/repo"
    assert flagged.data["ai_trailer"] == "Claude"
    assert "Co-Authored-By: Claude <noreply@anthropic.com>" in flagged.data["trailers"]
    assert "ai_trailer" not in commits["feat: first"].data

    presence = _of_kind(records, ArtifactKind.AI_APP_PRESENCE)
    assert [(p.data["tool"], p.data["kind"]) for p in presence] == [("Claude Code", "repo_ai_config")]
