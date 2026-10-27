from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from dissect.evidence.ewf import EWF

from aitrace.core.hashing import hash_file, hash_stream

LIMITATION_NO_STORED_HASH = (
    "E01 stored acquisition hash not readable by this tool; segment and media hashes recorded instead"
)
_EWF_SUFFIX_RE = re.compile(r"\.(e|ex|l|lx|s)\d{2}", re.IGNORECASE)
_DIGEST_KEYS = ("md5", "sha1", "sha256")


def _is_ewf(path: Path) -> bool:
    return _EWF_SUFFIX_RE.fullmatch(path.suffix) is not None


def intake(paths: Sequence[str | Path], *, skip_media: bool = False) -> dict[str, Any]:
    files = [Path(p) for p in paths]
    if not files:
        raise ValueError("intake needs at least one evidence file")
    is_e01 = _is_ewf(files[0])
    segments = []
    for path in files:
        digests = hash_file(path)
        segments.append({"path": str(path), "name": path.name, "size": path.stat().st_size, **digests})

    media_sha256: str | None = None
    if not skip_media:
        if is_e01:
            with EWF(files).open() as stream:
                media_sha256 = hash_stream(stream)["sha256"]
        else:
            media_sha256 = segments[0]["sha256"] if len(segments) == 1 else hash_file(files[0])["sha256"]

    return {
        "kind": "e01" if is_e01 else "raw",
        "segments": segments,
        "media_sha256": media_sha256,
        "acquisition_hashes": {},
        "limitations": [LIMITATION_NO_STORED_HASH] if is_e01 else [],
    }


def reverify(evidence: Mapping[str, Any]) -> tuple[Literal["match", "mismatch"], dict[str, dict[str, str]]]:
    status: Literal["match", "mismatch"] = "match"
    current: dict[str, dict[str, str]] = {}
    for segment in evidence["segments"]:
        digests = hash_file(segment["path"])
        current[segment["path"]] = digests
        if any(digests[key] != segment[key] for key in _DIGEST_KEYS):
            status = "mismatch"
    return status, current
