from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from dissect.evidence.ewf import EWF

from aitrace.core.hashing import hash_file, hash_stream

LIMITATION_NO_STORED_HASH = (
    "E01 stored acquisition hash not readable by this tool; segment and media hashes recorded instead"
)
LIMITATION_DIR_TREE = (
    "Directory evidence has no image segments; every file was SHA-256 hashed at intake and after analysis, "
    "and the recorded media hash is the SHA-256 of the sorted per-file manifest (path, size, sha256)"
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


def tree_digests(root: Path) -> dict[str, tuple[int, str]]:
    digests: dict[str, tuple[int, str]] = {}
    for current, dirs, files in os.walk(root):
        dirs.sort()
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                continue
            digests[path.relative_to(root).as_posix()] = (path.stat().st_size, hash_file(path)["sha256"])
    return dict(sorted(digests.items()))


def tree_manifest_sha256(digests: Mapping[str, tuple[int, str]]) -> str:
    lines = "".join(f"{sha}  {size}  {rel}\n" for rel, (size, sha) in digests.items())
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def intake_dir(root: Path) -> dict[str, Any]:
    digests = tree_digests(root)
    return {
        "kind": "dir",
        "segments": [],
        "media_sha256": tree_manifest_sha256(digests),
        "acquisition_hashes": {},
        "limitations": [LIMITATION_DIR_TREE],
        "tree": {
            "root": str(root),
            "files": len(digests),
            "bytes": sum(size for size, _ in digests.values()),
        },
        "tree_digests": digests,
    }


def reverify(evidence: Mapping[str, Any]) -> tuple[Literal["match", "mismatch"], dict[str, dict[str, str]]]:
    status: Literal["match", "mismatch"] = "match"
    current: dict[str, dict[str, str]] = {}
    tree = evidence.get("tree")
    if tree is not None:
        digests = tree_digests(Path(tree["root"]))
        manifest = tree_manifest_sha256(digests)
        current[tree["root"]] = {"sha256": manifest}
        return ("match" if manifest == evidence["media_sha256"] else "mismatch"), current
    for segment in evidence["segments"]:
        digests = hash_file(segment["path"])
        current[segment["path"]] = digests
        if any(digests[key] != segment[key] for key in _DIGEST_KEYS):
            status = "mismatch"
    return status, current
