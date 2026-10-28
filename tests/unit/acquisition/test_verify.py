from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from aitrace.acquisition.verify import LIMITATION_NO_STORED_HASH, intake, intake_dir, reverify
from aitrace.core.hashing import sha256_bytes

RAW = bytes(range(256)) * 512
requires_ewfacquire = pytest.mark.skipif(
    shutil.which("ewfacquire") is None, reason="ewfacquire not installed"
)


def _tree(root: Path) -> Path:
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "one.md").write_text("one", encoding="utf-8")
    (root / "two.db").write_bytes(b"\x00\x01")
    return root


def test_dir_intake_hashes_every_file_and_reverifies_as_match(tmp_path: Path) -> None:
    root = _tree(tmp_path / "ev")
    record = intake_dir(root)
    assert record["kind"] == "dir"
    assert record["tree"] == {"root": str(root), "files": 2, "bytes": 5}
    manifest = f"{sha256_bytes(b'one')}  3  a/b/one.md\n{sha256_bytes(b'\x00\x01')}  2  two.db\n"
    assert record["media_sha256"] == sha256_bytes(manifest.encode("utf-8"))
    assert reverify(record)[0] == "match"


def test_dir_reverify_detects_changed_and_added_files(tmp_path: Path) -> None:
    root = _tree(tmp_path / "ev")
    record = intake_dir(root)
    (root / "two.db-wal").write_bytes(b"")
    assert reverify(record)[0] == "mismatch"
    (root / "two.db-wal").unlink()
    (root / "a" / "b" / "one.md").write_text("ONE", encoding="utf-8")
    assert reverify(record)[0] == "mismatch"


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
