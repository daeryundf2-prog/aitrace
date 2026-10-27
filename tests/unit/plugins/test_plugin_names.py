from __future__ import annotations

import importlib

import pytest

from aitrace.plugins.registry import BUILTIN_PLUGINS


@pytest.mark.parametrize("module", BUILTIN_PLUGINS)
def test_plugin_name_is_last_module_segment(module: str) -> None:
    plugin = importlib.import_module(module).PLUGIN
    assert plugin.name == module.rsplit(".", 1)[1]


def test_plugin_names_are_unique() -> None:
    names = [importlib.import_module(m).PLUGIN.name for m in BUILTIN_PLUGINS]
    assert len(names) == len(set(names))
