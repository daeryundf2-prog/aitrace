from __future__ import annotations

import io
import re
import tempfile
import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from dulwich.errors import (
    FileFormatException,
    MissingCommitError,
    NotCommitError,
    NotGitRepository,
    ObjectFormatException,
    ObjectMissing,
    PackedRefsException,
    RefFormatError,
)
from dulwich.objects import Commit
from dulwich.repo import Repo
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from aitrace.core.catalog import VCS_AI_TRAILER_PATTERNS
from aitrace.core.kinds import ArtifactKind, OsFamily, SignalType
from aitrace.core.model import Artifact, Event, format_utc
from aitrace.core.paths import basename, normalize
from aitrace.core.time import from_unix
from aitrace.fs.base import EntryRef, EvidenceFS
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

DOC_SUFFIXES = (".docx", ".pptx", ".xlsx", ".pdf")
DOC_MAX_DEPTH = 6
REPO_MAX_DEPTH = 6
WALK_MAX_DEPTH = max(DOC_MAX_DEPTH, REPO_MAX_DEPTH + 2)

APP_XML = "docProps/app.xml"
CORE_XML = "docProps/core.xml"
APP_HINTS = ("python-docx",)
PRODUCER_HINTS = ("ReportLab", "Skia/PDF", "wkhtmltopdf", "Chromium")
HUMAN_MIN_TOTAL_TIME_MINUTES = 30
HUMAN_MIN_REVISION = 5

AI_CONFIG_PATHS: tuple[tuple[str, str], ...] = (
    ("Cursor", ".cursor"),
    ("Claude Code", ".claude"),
    ("Claude Code", "CLAUDE.md"),
    ("AGENTS.md", "AGENTS.md"),
    ("GitHub Copilot", ".github/copilot-instructions.md"),
)
AIDER_PREFIX = ".aider"

_TRAILER_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s+\S")
_DOC_ERRORS = (zipfile.BadZipFile, zlib.error, NotImplementedError, OSError, ValueError, ET.ParseError, PdfReadError)
_GIT_ERRORS = (
    OSError,
    ValueError,
    zlib.error,
    FileFormatException,
    MissingCommitError,
    NotCommitError,
    NotGitRepository,
    ObjectFormatException,
    ObjectMissing,
    PackedRefsException,
    RefFormatError,
)


def _xml_fields(payload: bytes) -> dict[str, str]:
    root = ET.fromstring(payload)
    fields: dict[str, str] = {}
    for element in root.iter():
        if element.text and element.text.strip():
            fields.setdefault(element.tag.rsplit("}", 1)[-1], element.text.strip())
    return fields


def _int(value: str | None) -> int | None:
    return None if value is None else int(value)


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else format_utc(value)


def _hints(application: str | None, producer: str | None, total_time: int | None, revision: int | None) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    if application is not None and application.casefold() in APP_HINTS:
        hints.append({"type": SignalType.METADATA_HINT.value, "value": application})
    if producer is not None:
        for needle in PRODUCER_HINTS:
            if needle.casefold() in producer.casefold():
                hints.append({"type": SignalType.METADATA_HINT.value, "value": needle})
    if total_time is not None and revision is not None and total_time >= HUMAN_MIN_TOTAL_TIME_MINUTES and revision >= HUMAN_MIN_REVISION:
        hints.append({"type": SignalType.HUMAN_PROCESS.value, "value": f"total_time={total_time};revision={revision}"})
    return hints


def _doc_fields(
    *,
    application: str | None,
    producer: str | None,
    creator: str | None,
    total_time: int | None,
    revision: int | None,
    extra: dict[str, str | None],
) -> dict[str, Any]:
    present = {
        "application": application,
        "producer": producer,
        "creator": creator,
        "total_time": total_time,
        "revision": revision,
    }
    data: dict[str, Any] = {key: value for key, value in present.items() if value is not None}
    extra_present = {key: value for key, value in extra.items() if value is not None}
    if extra_present:
        data["extra"] = extra_present
    data["hints"] = _hints(application, producer, total_time, revision)
    return data


def _office_metadata(payload: bytes) -> dict[str, Any]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = set(archive.namelist())
        app = _xml_fields(archive.read(APP_XML)) if APP_XML in names else {}
        core = _xml_fields(archive.read(CORE_XML)) if CORE_XML in names else {}
    return _doc_fields(
        application=app.get("Application"),
        producer=None,
        creator=core.get("creator"),
        total_time=_int(app.get("TotalTime")),
        revision=_int(core.get("revision")),
        extra={
            "app_version": app.get("AppVersion"),
            "template": app.get("Template"),
            "last_modified_by": core.get("lastModifiedBy"),
            "created": core.get("created"),
            "modified": core.get("modified"),
        },
    )


def _pdf_metadata(payload: bytes) -> dict[str, Any]:
    info = PdfReader(io.BytesIO(payload)).metadata
    if info is None:
        return _doc_fields(application=None, producer=None, creator=None, total_time=None, revision=None, extra={})
    return _doc_fields(
        application=None,
        producer=_text(info.get("/Producer")),
        creator=_text(info.get("/Creator")),
        total_time=None,
        revision=None,
        extra={"creation_date": _text(info.get("/CreationDate")), "mod_date": _text(info.get("/ModDate"))},
    )


def _trailers(message: str) -> list[str]:
    paragraphs = message.strip().split("\n\n")
    if len(paragraphs) < 2:
        return []
    return [line.strip() for line in paragraphs[-1].splitlines() if _TRAILER_LINE.match(line)]


def _ai_trailer(message: str) -> str | None:
    for pattern, tool in VCS_AI_TRAILER_PATTERNS:
        if pattern.search(message):
            return tool
    return None


def _commit_data(commit: Commit) -> dict[str, Any]:
    message = commit.message.decode("utf-8", errors="replace")
    data: dict[str, Any] = {
        "sha": commit.id.decode("ascii"),
        "author": commit.author.decode("utf-8", errors="replace"),
        "committer": commit.committer.decode("utf-8", errors="replace"),
        "message": message.strip().split("\n", 1)[0],
        "trailers": _trailers(message),
        "extra": {
            "author_time": _iso(from_unix(commit.author_time)),
            "commit_time": _iso(from_unix(commit.commit_time)),
        },
    }
    tool = _ai_trailer(message)
    if tool is not None:
        data["ai_trailer"] = tool
    return data


def _read_commits(fs: EvidenceFS, git_dir: EntryRef) -> list[dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="aitrace-git-") as tmp:
        prefix = git_dir.path + "/"
        for ref in fs.walk(git_dir):
            target = Path(tmp) / ".git" / ref.path[len(prefix) :]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(fs.read_bytes(ref))
        with Repo(tmp) as repo:
            include = sorted({repo.get_peeled(name) for name in repo.get_refs()})
            if not include:
                return []
            return [_commit_data(entry.commit) for entry in repo.get_walker(include=include)]


def _relative_segments(path: str, home: str) -> list[str]:
    return path[len(home.rstrip("/")) + 1 :].split("/")


class Plugin(PluginBase):
    name = "docs_git"
    version = "1.0"
    description = "Office/PDF document metadata, git commit history, and repo-level AI config presence"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for user in fs.users():
            for ref in fs.walk(EntryRef(user.volume, user.home), max_depth=WALK_MAX_DEPTH):
                segments = _relative_segments(ref.path, user.home)
                name = segments[-1]
                if name.casefold().endswith(DOC_SUFFIXES):
                    if len(segments) <= DOC_MAX_DEPTH:
                        yield Candidate(ref=ref, role="doc", user=user)
                elif name == "HEAD" and len(segments) - 2 in range(REPO_MAX_DEPTH + 1) and segments[-2] == ".git":
                    root = EntryRef(user.volume, ref.path[: -len("/.git/HEAD")])
                    yield Candidate(ref=root, role="repo", user=user)
                    yield Candidate(ref=root, role="repo_ai_config", user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        if cand.role == "doc":
            yield from self._parse_document(ctx, cand)
        elif cand.role == "repo":
            yield from self._parse_repo(ctx, cand)
        elif cand.role == "repo_ai_config":
            yield from self._parse_ai_config(ctx, cand)

    def _parse_document(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact]:
        path = _normalize(cand)
        payload = ctx.fs.read_bytes(cand.ref)
        try:
            if cand.ref.path.casefold().endswith(".pdf"):
                metadata = _pdf_metadata(payload)
            else:
                metadata = _office_metadata(payload)
        except _DOC_ERRORS as exc:
            yield self.warning(ctx, cand, f"unreadable document metadata: {exc}")
            return
        yield self.artifact(ctx, cand, ArtifactKind.DOC_METADATA, {"path": path, **metadata})

    def _parse_repo(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact]:
        repo_path = _normalize(cand)
        git_dir = EntryRef(cand.ref.volume, cand.ref.path + "/.git")
        try:
            commits = _read_commits(ctx.fs, git_dir)
        except _GIT_ERRORS as exc:
            yield self.warning(ctx, cand, f"git history unreadable: {exc}")
            return
        for commit in commits:
            data = {"repo_path": repo_path, **commit}
            yield self.artifact(ctx, cand, ArtifactKind.VCS_COMMIT, data, locator=f"commit:{commit['sha']}")

    def _parse_ai_config(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact]:
        root = cand.ref.path.rstrip("/")
        for tool, relative in AI_CONFIG_PATHS:
            entry = EntryRef(cand.ref.volume, f"{root}/{relative}")
            if ctx.fs.exists(entry):
                yield self._ai_presence(ctx, cand, tool, entry, relative)
        for child in ctx.fs.listdir(cand.ref):
            name = basename(child.path)
            if name.startswith(AIDER_PREFIX):
                yield self._ai_presence(ctx, cand, "Aider", child, name)

    def _ai_presence(self, ctx: ParseContext, cand: Candidate, tool: str, entry: EntryRef, relative: str) -> Artifact:
        data = {"tool": tool, "kind": "repo_ai_config", "status": "present", "detail": relative}
        return self.artifact(ctx, cand, ArtifactKind.AI_APP_PRESENCE, data, locator=f"repo_ai_config:{relative}", ref=entry)


def _normalize(cand: Candidate) -> str:
    os_family = cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN
    return normalize(cand.ref.path, os_family)


PLUGIN = Plugin()
