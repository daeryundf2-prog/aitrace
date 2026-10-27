from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from aitrace.fs.dir_fs import DirFS
from aitrace.fs.dissect_fs import DissectFS
from aitrace.fs.open import UnsupportedEvidence, ewf_segments, open_evidence


def test_directory_opens_as_dirfs(tmp_path: Path) -> None:
    (tmp_path / "home/alice").mkdir(parents=True)
    fs = open_evidence(tmp_path, evidence_id="ev")
    assert isinstance(fs, DirFS)
    assert fs.evidence_id == "ev"
    assert [u.name for u in fs.users()] == ["alice"]


def test_missing_e01_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        open_evidence(tmp_path / "nope.E01")


@pytest.mark.parametrize("name", ["disk.Ex01", "disk.ex01", "disk.Lx01"])
def test_ewf2_is_unsupported(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(b"EVF2")
    with pytest.raises(UnsupportedEvidence, match="EWF2 not supported"):
        open_evidence(tmp_path / name)
    with pytest.raises(UnsupportedEvidence):
        open_evidence(tmp_path / "absent.Ex01")


def test_unknown_suffix_is_unsupported(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_bytes(b"x")
    with pytest.raises(UnsupportedEvidence):
        open_evidence(tmp_path / "notes.txt")


def test_raw_without_filesystem_is_unsupported(tmp_path: Path) -> None:
    (tmp_path / "zero.raw").write_bytes(bytes(1 << 20))
    with pytest.raises(UnsupportedEvidence, match="no readable filesystem"):
        open_evidence(tmp_path / "zero.raw")


def test_ewf_segment_discovery(tmp_path: Path) -> None:
    for ext in ("E01", "E02", "E03", "E05"):
        (tmp_path / f"case.{ext}").write_bytes(b"")
    assert ewf_segments(tmp_path / "case.E01") == tuple(str(tmp_path / f"case.{e}") for e in ("E01", "E02", "E03"))
    (tmp_path / "low.e01").write_bytes(b"")
    (tmp_path / "low.e02").write_bytes(b"")
    assert ewf_segments(tmp_path / "low.e01") == (str(tmp_path / "low.e01"), str(tmp_path / "low.e02"))


def test_ewf_segments_roll_over_to_letters(tmp_path: Path) -> None:
    for number in range(1, 100):
        (tmp_path / f"big.E{number:02d}").write_bytes(b"")
    (tmp_path / "big.EAA").write_bytes(b"")
    segments = ewf_segments(tmp_path / "big.E01")
    assert len(segments) == 100 and segments[-1].endswith("big.EAA")


def test_raw_image_opens_as_dissectfs(tmp_path: Path) -> None:
    mke2fs = shutil.which("mke2fs")
    if mke2fs is None:
        pytest.skip("mke2fs not installed")
    stage = tmp_path / "stage"
    (stage / "home/alice").mkdir(parents=True)
    (stage / "home/alice/.bash_history").write_bytes(b"ls\n")
    image = tmp_path / "disk.img"
    subprocess.run([mke2fs, "-q", "-t", "ext4", "-d", str(stage), str(image), "16M"], check=True)
    fs = open_evidence(image)
    assert isinstance(fs, DissectFS)
    assert fs.kind == "raw" and fs.segments == (str(image.resolve()),)
    assert [(u.name, u.os_family.value) for u in fs.users()] == [("alice", "linux")]
