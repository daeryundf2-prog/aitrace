from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO

CHUNK = 8 * 1024 * 1024


def hash_stream(fileobj: BinaryIO) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    while chunk := fileobj.read(CHUNK):
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def hash_file(path: str | Path) -> dict[str, str]:
    with Path(path).open("rb") as fh:
        return hash_stream(fh)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
