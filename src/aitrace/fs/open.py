from __future__ import annotations

import os
import string
from collections.abc import Iterator
from pathlib import Path

from aitrace.fs.base import EvidenceFS
from aitrace.fs.dir_fs import DirFS

EWF_SUFFIXES = frozenset({".e01"})
EWF2_SUFFIXES = frozenset({".ex01", ".lx01"})
RAW_SUFFIXES = frozenset({".raw", ".dd", ".img", ".dmg", ".cdr"})


class UnsupportedEvidence(Exception):
    pass


def _ewf_extensions() -> Iterator[str]:
    for number in range(1, 100):
        yield f"E{number:02d}"
    for first in string.ascii_uppercase[4:]:
        for second in string.ascii_uppercase:
            for third in string.ascii_uppercase:
                yield first + second + third


def ewf_segments(first: Path) -> tuple[str, ...]:
    """`X.E01, X.E02, ... X.E99, X.EAA ...` until the first gap; extension case follows the first segment."""
    lower = first.suffix[1:].islower()
    segments: list[str] = []
    for ext in _ewf_extensions():
        candidate = first.with_suffix("." + (ext.lower() if lower else ext))
        if not candidate.is_file():
            break
        segments.append(str(candidate))
    return tuple(segments)


def open_evidence(path: str | os.PathLike[str], evidence_id: str | None = None) -> EvidenceFS:
    source = Path(path)
    suffix = source.suffix.lower()
    if suffix in EWF2_SUFFIXES:
        raise UnsupportedEvidence("EWF2 not supported")
    if not source.exists():
        raise FileNotFoundError(str(source))
    if source.is_dir():
        return DirFS(source, evidence_id)
    if suffix in EWF_SUFFIXES:
        kind, segments = "e01", ewf_segments(source.resolve())
    elif suffix in RAW_SUFFIXES:
        kind, segments = "raw", (str(source.resolve()),)
    else:
        raise UnsupportedEvidence(f"unsupported evidence type: {source.name}")

    from aitrace.fs.dissect_fs import DissectFS

    fs = DissectFS(str(source.resolve()), evidence_id, kind=kind, segments=segments)
    if not fs.volumes():
        raise UnsupportedEvidence(f"no readable filesystem in {source.name}")
    return fs
