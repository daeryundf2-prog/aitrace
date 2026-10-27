from __future__ import annotations

import logging
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from aitrace.plugins import registry
from aitrace.plugins.registry import BUILTIN_PLUGINS, load_plugins


class _FakePlugin:
    name = "fake"
    version = "1.0"
    description = "fake"

    def locate(self, fs: Any) -> Any:
        return iter(())

    def parse(self, ctx: Any, cand: Any) -> Any:
        return iter(())


class _EntryPoint:
    def __init__(self, name: str, target: object) -> None:
        self.name = name
        self._target = target

    def load(self) -> object:
        return self._target


def test_builtin_plugin_paths_are_unique_and_namespaced() -> None:
    assert len(BUILTIN_PLUGINS) == len(set(BUILTIN_PLUGINS))
    assert all(path.startswith("aitrace.plugins.") for path in BUILTIN_PLUGINS)


def test_module_plugin_is_loaded_from_plugin_attribute(monkeypatch: pytest.MonkeyPatch) -> None:
    module = SimpleNamespace(PLUGIN=_FakePlugin())
    monkeypatch.setitem(sys.modules, "fake_plugin_mod", module)

    plugins = load_plugins(["fake_plugin_mod"])

    assert [p.name for p in plugins] == ["fake"]


def test_missing_module_is_reported_not_fatal(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR, logger=registry.__name__):
        plugins = load_plugins(["aitrace_no_such_plugin_module"])

    assert plugins == []
    assert "aitrace_no_such_plugin_module" in caplog.text


def test_default_load_combines_builtins_and_entry_points(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "BUILTIN_PLUGINS", ["aitrace_no_such_builtin"])
    entry = _EntryPoint("ext", _FakePlugin())
    seen: dict[str, str] = {}

    def fake_entry_points(*, group: str) -> list[_EntryPoint]:
        seen["group"] = group
        return [entry]

    monkeypatch.setattr(registry, "entry_points", fake_entry_points)

    plugins = load_plugins()

    assert seen["group"] == "aitrace.plugins"
    assert [p.name for p in plugins] == ["fake"]
