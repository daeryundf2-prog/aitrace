from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from aitrace.acquisition.verify import LIMITATION_NO_STORED_HASH, intake, reverify
from aitrace.core.hashing import sha256_bytes

RAW = bytes(range(256)) * 512
requires_ewfacquire = pytest.mark.skipif(shutil.which("ewfacquire") is None, reason="ewfacquire not installed")


@pytest.fixture
def raw_image(tmp_path: Path) -> Path:
    path = tmp_path / "x.raw"
    path.write_bytes(RAW)
    return path


@pytest.fixture
def e01_image(tmp_path: Path, raw_image: Path) -> Path:
    if shutil.which("ewfacquire") is None:
        pytest.skip("ewfacquire not installed")
    subprocess.run(
        [
            "ewfacquire",
            "-u",
            "-t",
            str(tmp_path / "x"),
            "-f",
            "encase6",
            "-c",
            "deflate:fast",
            "-C",
            "c",
            "-D",
            "d",
            "-E",
            "e",
            "-e",
            "ex",
            "-N",
            "n",
            "-d",
            "sha256",
            "-q",
            str(raw_image),
        ],
        check=True,
        capture_output=True,
    )
    return tmp_path / "x.E01"


def test_raw_intake_records_segment_and_media_hashes(raw_image: Path) -> None:
    evidence = intake([raw_image])
    assert evidence["kind"] == "raw"
    assert evidence["media_sha256"] == sha256_bytes(RAW)
    assert evidence["acquisition_hashes"] == {}
    assert evidence["limitations"] == []
    (segment,) = evidence["segments"]
    assert segment["size"] == len(RAW)
    assert segment["sha256"] == sha256_bytes(RAW)


def test_intake_skip_media_omits_media_hash(raw_image: Path) -> None:
    assert intake([raw_image], skip_media=True)["media_sha256"] is None


def test_reverify_matches_unchanged_segments(raw_image: Path) -> None:
    evidence = intake([raw_image])
    status, hashes = reverify(evidence)
    assert status == "match"
    assert hashes[str(raw_image)]["sha256"] == sha256_bytes(RAW)


def test_reverify_reports_mismatch_after_copied_segment_byte_changes(tmp_path: Path, raw_image: Path) -> None:
    copied = tmp_path / "copy.raw"
    shutil.copyfile(raw_image, copied)
    evidence = intake([copied])
    data = bytearray(copied.read_bytes())
    data[1000] ^= 0xFF
    copied.write_bytes(bytes(data))
    status, _ = reverify(evidence)
    assert status == "mismatch"


@requires_ewfacquire
def test_e01_intake_records_limitation_and_decoded_media_hash(e01_image: Path) -> None:
    evidence = intake([e01_image])
    assert evidence["kind"] == "e01"
    assert evidence["acquisition_hashes"] == {}
    assert evidence["limitations"] == [LIMITATION_NO_STORED_HASH]
    assert evidence["media_sha256"] == sha256_bytes(RAW)


@requires_ewfacquire
def test_e01_reverify_detects_modified_segment(tmp_path: Path, e01_image: Path) -> None:
    copied = tmp_path / "copy.E01"
    shutil.copyfile(e01_image, copied)
    evidence = intake([copied])
    assert reverify(evidence)[0] == "match"
    data = bytearray(copied.read_bytes())
    data[len(data) // 2] ^= 0xFF
    copied.write_bytes(bytes(data))
    assert reverify(evidence)[0] == "mismatch"
