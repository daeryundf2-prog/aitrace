from __future__ import annotations

import importlib
import logging
from collections.abc import Sequence
from importlib.metadata import EntryPoint, entry_points

from aitrace.plugins.base import ArtifactPlugin

ENTRY_POINT_GROUP = "aitrace.plugins"

BUILTIN_PLUGINS: list[str] = [
    "aitrace.plugins.ai.claude_code",
    "aitrace.plugins.ai.cli_agents",
    "aitrace.plugins.ai.desktop_apps",
    "aitrace.plugins.ai.ide_assistants",
    "aitrace.plugins.ai.local_llm",
    "aitrace.plugins.ai.sdk_keys",
    "aitrace.plugins.ai.omo",
    "aitrace.plugins.ai.opencode",
    "aitrace.plugins.ai.hermes",
    "aitrace.plugins.ai.hermes_export",
    "aitrace.plugins.browser.history_downloads",
    "aitrace.plugins.browser.cache_images",
    "aitrace.plugins.shell.history",
    "aitrace.plugins.windows.mft",
    "aitrace.plugins.windows.usn",
    "aitrace.plugins.windows.recycle_lnk_jumplist",
    "aitrace.plugins.windows.execution",
    "aitrace.plugins.windows.evtx_rdp_usb",
    "aitrace.plugins.macos.activity",
    "aitrace.plugins.unix.remote_auth",
    "aitrace.plugins.remote.remote_tools",
    "aitrace.plugins.remote.cloud_sync",
    "aitrace.plugins.provenance.images",
    "aitrace.plugins.provenance.docs_git",
    "aitrace.plugins.fsmeta.file_inventory",
    "aitrace.plugins.fsmeta.download_origin",
    "aitrace.plugins.fsmeta.doc_clues",
]

log = logging.getLogger(__name__)


def _load_module(dotted: str) -> ArtifactPlugin | None:
    try:
        module = importlib.import_module(dotted)
        plugin: ArtifactPlugin = module.PLUGIN
    except Exception:
        log.exception("plugin module %s failed to load", dotted)
        return None
    return plugin


def _load_entry_point(ep: EntryPoint) -> ArtifactPlugin | None:
    try:
        plugin: ArtifactPlugin = ep.load()
    except Exception:
        log.exception("entry point plugin %s failed to load", ep.name)
        return None
    return plugin


def load_plugins(names: Sequence[str] | None = None) -> list[ArtifactPlugin]:
    """Load the named plugin modules, or with no names the builtin list plus entry points.

    A module that fails to import is logged and skipped; it never aborts the load.
    """
    plugins: list[ArtifactPlugin] = []
    if names is None:
        candidates: list[ArtifactPlugin | None] = [_load_module(d) for d in BUILTIN_PLUGINS]
        candidates += [_load_entry_point(ep) for ep in entry_points(group=ENTRY_POINT_GROUP)]
    else:
        candidates = [_load_module(d) for d in names]
    plugins.extend(p for p in candidates if p is not None)
    return plugins
