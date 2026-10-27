from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest
from dissect.target import Target
from dissect.target.filesystem import Filesystem

REPO = Path(__file__).resolve().parents[3]
IMAGE = REPO / "tests" / "fixtures" / "images" / "macos.E01"
EXPECTED = REPO / "tests" / "fixtures" / "expected" / "macos.json"
BUILDER = REPO / "tools" / "fixtures" / "build_macos.py"

CONV = "/Users/lee/Library/Application Support/com.openai.chat/conversations-11111111-2222/conv1.json"
ROLLOUT = "/Users/lee/.codex/sessions/2026/10/02/rollout-2026-10-02T03-00-00-abc.jsonl"
ZSH_HISTORY = "/Users/lee/.zsh_history"

PLANTED = (
    CONV,
    "/Users/lee/Library/Application Support/com.openai.chat/conversations-v2-11111111-2222/abc.data",
    "/Users/lee/Library/Application Support/Cursor/User/globalStorage/state.vscdb",
    "/Users/lee/Library/Safari/History.db",
    "/Users/lee/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
    ROLLOUT,
    ZSH_HISTORY,
    "/Users/lee/proj/parser.py",
    "/Users/lee/proj/.git/HEAD",
    "/System/Library/CoreServices/SystemVersion.plist",
)


def _load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_macos", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def target() -> Target:
    assert IMAGE.is_file(), f"missing fixture image: {IMAGE}"
    return Target.open(IMAGE)


def _volume(target: Target) -> Filesystem:
    for fs in target.filesystems:
        if fs.exists("Users/lee"):
            return fs
    raise AssertionError("no filesystem holds Users/lee")


def _read(target: Target, path: str) -> str:
    return _volume(target).path(path).read_text(encoding="utf-8")


def test_expected_json_matches_builder_contract() -> None:
    assert json.loads(EXPECTED.read_text(encoding="utf-8")) == _load_builder().EXPECTED


def test_builder_refuses_non_darwin(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    builder = _load_builder()
    monkeypatch.setattr(sys, "platform", "linux")
    assert builder.main() == 2
    assert "requires macOS" in capsys.readouterr().err


@pytest.mark.parametrize("planted", PLANTED)
def test_planted_path_exists(target: Target, planted: str) -> None:
    assert _volume(target).path(planted).exists()


def test_planted_prompt_text_is_recoverable(target: Target) -> None:
    conv = json.loads(_read(target, CONV))
    assert conv["messages"][0]["text"] == "엑셀 데이터를 csv로 바꾸는 파이썬 코드 짜줘"
    assert "IP만 추출하는" in _read(target, ROLLOUT)
    assert "rsync -av ~/proj lee@198.51.100.7:/backup" in _read(target, ZSH_HISTORY)
