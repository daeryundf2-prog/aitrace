from __future__ import annotations

import hashlib
from io import BytesIO
from pathlib import Path

import pytest

from aitrace.core import hashing
from aitrace.core.hashing import hash_file, hash_stream, sha256_bytes

PAYLOAD = bytes(range(256)) * 37


def _expected(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def test_sha256_bytes_matches_known_vector() -> None:
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hash_stream_returns_all_three_digests() -> None:
    assert hash_stream(BytesIO(PAYLOAD)) == _expected(PAYLOAD)


@pytest.mark.parametrize("chunk", [1, 7, 64, len(PAYLOAD) + 1])
def test_hash_stream_is_independent_of_chunk_size(monkeypatch: pytest.MonkeyPatch, chunk: int) -> None:
    monkeypatch.setattr(hashing, "CHUNK", chunk)
    assert hash_stream(BytesIO(PAYLOAD)) == _expected(PAYLOAD)


def test_hash_file_hashes_file_contents(tmp_path: Path) -> None:
    target = tmp_path / "evidence.bin"
    target.write_bytes(PAYLOAD)
    assert hash_file(target) == _expected(PAYLOAD)


def test_hash_file_of_empty_file_matches_empty_digests(tmp_path: Path) -> None:
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")
    assert hash_file(str(target)) == _expected(b"")
