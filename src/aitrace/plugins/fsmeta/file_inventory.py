from __future__ import annotations

import dataclasses
import hashlib
import io
import zipfile
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Any
from xml.etree import ElementTree

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event, format_utc
from aitrace.core.paths import normalize
from aitrace.fs.base import EntryRef, EvidenceFS
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

MAX_DEPTH = 8
MAX_FILES_PER_USER = 200_000
MAX_CONTENT_BYTES = 2 * 1024 * 1024
SAMPLE_CHARS = 64 * 1024
TEXT_EXTENSIONS = frozenset({".md", ".txt", ".py", ".js", ".ts", ".html", ".css", ".json", ".csv"})
DOCX_EXTENSION = ".docx"
PRUNE_NAMES = frozenset({"node_modules", ".git", ".venv", "site-packages"})
EXCLUDED_SUBPATHS = ("/Library/Caches/", "/AppData/Local/Temp/")
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_DOCX_ERRORS = (zipfile.BadZipFile, KeyError, ElementTree.ParseError)


def _excluded(path: str) -> bool:
    return any(marker in path for marker in EXCLUDED_SUBPATHS)


def _content_eligible(path: str, size: int | None) -> bool:
    if size is None or size > MAX_CONTENT_BYTES:
        return False
    suffix = PurePosixPath(path).suffix.lower()
    return suffix in TEXT_EXTENSIONS or suffix == DOCX_EXTENSION


def _decode_text(raw: bytes, path: str) -> str:
    if PurePosixPath(path).suffix.lower() == DOCX_EXTENSION:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            root = ElementTree.fromstring(archive.read("word/document.xml"))
        return "".join(node.text or "" for node in root.iter(f"{{{W_NS}}}t"))
    return raw.decode("utf-8", errors="replace")


class FileInventoryPlugin(PluginBase):
    name = "file_inventory"
    version = "1.0"
    description = "Per-user file inventory (depth 8) with timestamps, content hashes and text samples"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for user in fs.users():
            yield Candidate(ref=EntryRef(user.volume, user.home), role="home", user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        walked = ctx.fs.walk(cand.ref, max_depth=MAX_DEPTH, skip_names=PRUNE_NAMES)
        kept = (ref for ref in walked if not _excluded(ref.path))
        for count, ref in enumerate(kept, start=1):
            if count > MAX_FILES_PER_USER:
                yield self.warning(ctx, cand, f"file cap of {MAX_FILES_PER_USER} reached; remaining files skipped")
                return
            yield from self._emit_file(ctx, cand, ref)

    def _emit_file(self, ctx: ParseContext, cand: Candidate, ref: EntryRef) -> Iterator[Artifact | Event]:
        file_cand = Candidate(ref=ref, role=cand.role, user=cand.user)
        try:
            st = ctx.fs.stat(ref)
        except OSError as exc:
            yield self.warning(ctx, file_cand, f"stat failed: {exc}")
            return
        os_family = cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN
        home = cand.user.home if cand.user is not None else None
        path = normalize(ref.path, os_family, home)
        data: dict[str, Any] = {
            "path": path,
            "size": st.size,
            "is_dir": False,
            "in_use": True,
            "source": "stat",
        }
        for key, value in (("btime", st.btime), ("mtime", st.mtime), ("atime", st.atime), ("ctime", st.ctime)):
            if value is not None:
                data[key] = format_utc(value)
        if _content_eligible(ref.path, st.size):
            try:
                raw = ctx.fs.read_bytes(ref)
            except OSError as exc:
                yield self.warning(ctx, file_cand, f"unreadable content: {exc}")
            else:
                data["content_sha256"] = hashlib.sha256(raw).hexdigest()
                try:
                    data["text_sample"] = _decode_text(raw, ref.path)[:SAMPLE_CHARS]
                except _DOCX_ERRORS as exc:
                    yield self.warning(ctx, file_cand, f"docx text extraction failed: {exc}")
        artifact = self.artifact(ctx, file_cand, ArtifactKind.FILE_RECORD, data)
        artifact = dataclasses.replace(
            artifact, provenance=dataclasses.replace(artifact.provenance, inode=st.inode, size=st.size)
        )
        yield artifact
        if st.btime is not None:
            yield self.event(
                artifact,
                st.btime,
                "btime",
                EventCategory.FILE_CREATED,
                Actor.SYSTEM,
                f"file created: {path}",
                subject=path,
            )
        if st.mtime is not None:
            yield self.event(
                artifact,
                st.mtime,
                "mtime",
                EventCategory.FILE_MODIFIED,
                Actor.SYSTEM,
                f"file modified: {path}",
                subject=path,
            )


PLUGIN = FileInventoryPlugin()
