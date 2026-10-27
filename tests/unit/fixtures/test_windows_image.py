from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
from dissect.target import Target
from dissect.target.filesystem import Filesystem

REPO = Path(__file__).resolve().parents[3]
IMAGE = REPO / "tests" / "fixtures" / "images" / "windows.E01"
EXPECTED = REPO / "tests" / "fixtures" / "expected" / "windows.json"
BUILDER = REPO / "tools" / "fixtures" / "build_windows.py"
NTFS_SYSTEM_ROOTS = {"System Volume Information", "$Extend", "$Secure", "$UpCase", "$MFT", "$MFTMirr",
                     "$LogFile", "$Volume", "$AttrDef", "$Bitmap", "$Boot", "$BadClus", "$Quota",
                     "$Reparse", "$ObjId", "$RmMetadata", "$Txf", "$TxfLog", "$Repair", "$TxfLog.blf"}


def _load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_windows", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


builder = _load_builder()


@pytest.fixture(scope="module")
def ntfs() -> Filesystem:
    target = Target.open(IMAGE)
    return next(iter(target.filesystems))


def _image_files(fs: Filesystem) -> list[str]:
    found: list[str] = []
    stack = [p for p in fs.path("/").iterdir() if p.name not in NTFS_SYSTEM_ROOTS]
    while stack:
        path = stack.pop()
        if path.is_dir():
            stack.extend(path.iterdir())
        else:
            found.append(str(path))
    return sorted(found)


def test_image_exists_and_is_small() -> None:
    assert IMAGE.is_file()
    assert IMAGE.stat().st_size < 5 * 1024 * 1024


def test_volume_is_ntfs_windows() -> None:
    target = Target.open(IMAGE)
    assert target.os == "windows"
    assert type(next(iter(target.filesystems))).__name__ == "NtfsFilesystem"


@pytest.mark.parametrize("rel", builder.planted_files())
def test_planted_path_exists(ntfs: Filesystem, rel: str) -> None:
    assert ntfs.path(rel).is_file()


def test_planted_listing_matches_builder(ntfs: Filesystem) -> None:
    assert _image_files(ntfs) == builder.planted_files()
    assert builder.planted_files() == builder.planted_files()


def test_proposal_mtime(ntfs: Filesystem) -> None:
    mtime = datetime.fromtimestamp(ntfs.path("/Users/kim/work/proposal.md").stat().st_mtime, UTC)
    assert mtime == datetime(2026, 10, 1, 1, 0, 21, tzinfo=UTC)


def test_planted_content(ntfs: Filesystem) -> None:
    assert ntfs.path("/Users/kim/work/proposal.md").read_bytes().decode("utf-8") == builder.PROPOSAL
    assert ntfs.path("/Users/kim/work/edited.md").read_bytes().decode("utf-8") == builder.MINUTES_EDITED
    png = ntfs.path(f"/Users/kim/Downloads/{builder.PNG_NAME}").read_bytes()
    assert b"caBX" in png and b"c2pa" in png and b'"claim_generator":"ChatGPT"' in png
    assert b"trainedAlgorithmicMedia" in png


def test_secret_plan_deleted_from_listing(ntfs: Filesystem) -> None:
    names = [p.name for p in ntfs.path("/Users/kim/Documents").iterdir()]
    assert "secret_plan.txt" not in names
    assert not ntfs.path("/Users/kim/Documents/secret_plan.txt").exists()
    assert all(not f.endswith("secret_plan.txt") for f in _image_files(ntfs))


def test_expected_json_matches_scenario() -> None:
    assert json.loads(EXPECTED.read_text(encoding="utf-8")) == builder.EXPECTED_JSON


def test_missing_docker_exits_2(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "docker" else "/usr/bin/" + name)
    assert builder.main() == 2
    assert "docker" in capsys.readouterr().err
