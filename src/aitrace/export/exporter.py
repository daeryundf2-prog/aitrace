from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aitrace.core.catalog import EXPORT_KINDS
from aitrace.core.hashing import sha256_bytes
from aitrace.core.kinds import ArtifactKind
from aitrace.core.model import Artifact
from aitrace.core.paths import basename
from aitrace.db.store import CaseStore
from aitrace.fs.base import EntryRef, EvidenceFS

MAX_EXPORT_BYTES = 512 * 1024 * 1024
MAX_NAME = 200
LONG_BASENAME = 80
EXPORT_ROOT = "export/files"
LONG_DIR = "_long"
_UNSAFE = str.maketrans({ch: "_" for ch in ':*?"<>|'})


@dataclass(frozen=True, slots=True)
class ExportEntry:
    export_path: str
    sha256: str
    size: int
    source_volume: int
    source_path: str
    inode: int | None
    artifact_ids: tuple[str, ...]
    deleted: bool
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "export_path": self.export_path,
            "sha256": self.sha256,
            "size": self.size,
            "source_volume": self.source_volume,
            "source_path": self.source_path,
            "inode": self.inode,
            "artifact_ids": list(self.artifact_ids),
            "deleted": self.deleted,
            "note": self.note,
        }


@dataclass(slots=True)
class _Source:
    volume: int
    path: str
    artifact_ids: set[str] = field(default_factory=set)
    deleted: bool = False
    credential: bool = False


def _sanitize(name: str) -> str:
    return name.translate(_UNSAFE)[:MAX_NAME]


def _export_path(volume: int, source_path: str) -> str:
    parts = [_sanitize(part) for part in source_path.split("/") if part]
    rel = "/".join([EXPORT_ROOT, str(volume), *parts])
    if len(rel) <= MAX_NAME:
        return rel
    digest = hashlib.sha256(source_path.encode("utf-8")).hexdigest()[:16]
    return f"{EXPORT_ROOT}/{LONG_DIR}/{digest}__{_sanitize(basename(source_path))[:LONG_BASENAME]}"


def _sources(store: CaseStore, kinds: frozenset[ArtifactKind]) -> list[_Source]:
    sources: dict[tuple[int, str], _Source] = {}

    def claim(artifact: Artifact) -> None:
        key = (artifact.provenance.volume, artifact.provenance.source_path)
        source = sources.setdefault(key, _Source(volume=key[0], path=key[1]))
        source.artifact_ids.add(artifact.id)
        source.deleted = source.deleted or artifact.provenance.deleted
        source.credential = source.credential or artifact.kind is ArtifactKind.AI_CREDENTIAL

    for artifact in store.artifacts(kinds=kinds):
        claim(artifact)
    for attribution in store.attributions():
        for artifact_id in attribution.subject_artifact_ids:
            subject = store.artifact(artifact_id)
            if subject is None:
                raise KeyError(f"attribution {attribution.id} references unknown artifact {artifact_id}")
            claim(subject)
    return [sources[key] for key in sorted(sources)]


def _skipped(source: _Source, ids: tuple[str, ...], size: int, note: str, inode: int | None) -> ExportEntry:
    return ExportEntry(
        export_path=_export_path(source.volume, source.path),
        sha256="",
        size=size,
        source_volume=source.volume,
        source_path=source.path,
        inode=inode,
        artifact_ids=ids,
        deleted=source.deleted,
        note=note,
    )


def _export_one(fs: EvidenceFS, case_dir: Path, source: _Source) -> ExportEntry:
    ref = EntryRef(source.volume, source.path)
    ids = tuple(sorted(source.artifact_ids))
    if not fs.exists(ref) or fs.is_dir(ref):
        return _skipped(source, ids, 0, "source not found or not a regular file", None)
    stat = fs.stat(ref)
    size = stat.size or 0
    if size > MAX_EXPORT_BYTES:
        note = f"skipped: {size} bytes exceeds {MAX_EXPORT_BYTES} byte limit"
        return _skipped(source, ids, size, note, stat.inode)
    data = fs.read_bytes(ref)
    if source.credential:
        note = f"not copied: file holds credentials; source sha256 {sha256_bytes(data)}"
        return _skipped(source, ids, len(data), note, stat.inode)
    export_path = _export_path(source.volume, source.path)
    dest = case_dir / export_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return ExportEntry(
        export_path=export_path,
        sha256=sha256_bytes(data),
        size=len(data),
        source_volume=source.volume,
        source_path=source.path,
        inode=stat.inode,
        artifact_ids=ids,
        deleted=source.deleted,
        note="",
    )


def export_artifacts(
    fs: EvidenceFS,
    store: CaseStore,
    case_dir: Path,
    kinds: frozenset[ArtifactKind] = EXPORT_KINDS,
) -> list[ExportEntry]:
    entries = sorted(
        (_export_one(fs, case_dir, source) for source in _sources(store, kinds)),
        key=lambda entry: entry.export_path,
    )
    store.add_exports(entry.to_dict() for entry in entries)
    return entries
