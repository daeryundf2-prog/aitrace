from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

from dissect.target import Target

REPO_ROOT = Path(__file__).resolve().parents[3]
IMAGE_PATH = REPO_ROOT / "tests" / "fixtures" / "images" / "linux.E01"
EXPECTED_PATH = REPO_ROOT / "tests" / "fixtures" / "expected" / "linux.json"
BUILDER_PATH = REPO_ROOT / "tools" / "fixtures" / "build_linux.py"
MAX_IMAGE_BYTES = 5 * 1024 * 1024


def _load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_linux", BUILDER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _present_paths(image: Path, candidates: tuple[str, ...]) -> list[str]:
    target = Target.open(image)
    return sorted(path for path in candidates if target.fs.exists(path))


def test_planted_paths_exist_in_image() -> None:
    builder = _load_builder()
    present = _present_paths(IMAGE_PATH, builder.PLANTED_PATHS)
    assert present == sorted(builder.PLANTED_PATHS)


def test_rebuild_yields_same_planted_file_listing(tmp_path: Path) -> None:
    builder = _load_builder()
    rebuilt = builder.build_image(tmp_path)
    assert _present_paths(rebuilt, builder.PLANTED_PATHS) == _present_paths(
        IMAGE_PATH, builder.PLANTED_PATHS
    )


def test_image_is_under_size_budget() -> None:
    assert IMAGE_PATH.stat().st_size < MAX_IMAGE_BYTES


def test_expected_json_matches_builder_expectations() -> None:
    builder = _load_builder()
    assert json.loads(EXPECTED_PATH.read_text(encoding="utf-8")) == builder.EXPECTED
