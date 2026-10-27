from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from aitrace.core.kinds import ArtifactKind
from aitrace.core.model import Artifact, Event
from aitrace.db.store import CaseStore
from aitrace.fs.base import EntryRef
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins import runner
from aitrace.plugins.base import Candidate, ParseContext, PluginBase
from aitrace.plugins.runner import run_plugins

EVIDENCE = "ev-1"
TZ = "UTC"
LOG = logging.getLogger("test.runner")


class GoodPlugin(PluginBase):
    name = "good"
    version = "1.0"
    description = "parses every file under the root"

    def locate(self, fs: Any) -> Iterator[Candidate]:
        for ref in fs.walk(EntryRef(0, "/")):
            yield Candidate(ref=ref, role="file")

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        yield self.artifact(ctx, cand, ArtifactKind.FILE_RECORD, {"path": cand.ref.path, "is_dir": False})


class RaisingPlugin(GoodPlugin):
    name = "boom"
    description = "locates one file and fails to parse it"

    def locate(self, fs: Any) -> Iterator[Candidate]:
        yield Candidate(ref=EntryRef(0, "/b.txt"), role="file")

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        raise ValueError("bad header")


class BrokenLocatePlugin(GoodPlugin):
    name = "broken"
    description = "fails while enumerating candidates"

    def locate(self, fs: Any) -> Iterator[Candidate]:
        raise OSError("disk gone")


@pytest.fixture
def fs() -> MemoryFS:
    return MemoryFS({"/a.txt": b"a", "/b.txt": b"bb"}, evidence_id=EVIDENCE)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[CaseStore]:
    case_store = CaseStore(tmp_path / "case.sqlite")
    yield case_store
    case_store.close()


def test_plugin_records_are_stored(fs: MemoryFS, store: CaseStore) -> None:
    results = run_plugins(fs, store, EVIDENCE, [GoodPlugin()], LOG, TZ)

    assert [(r.name, r.status, r.records, r.warnings) for r in results] == [("good", "ok", 2, 0)]
    stored = list(store.artifacts(kind=ArtifactKind.FILE_RECORD))
    assert sorted(a.provenance.source_path for a in stored) == ["/a.txt", "/b.txt"]
    assert [r.name for r in store.plugin_runs()] == ["good"]


def test_raising_plugin_yields_one_warning_and_others_still_stored(fs: MemoryFS, store: CaseStore) -> None:
    results = run_plugins(fs, store, EVIDENCE, [RaisingPlugin(), GoodPlugin()], LOG, TZ)

    by_name = {r.name: r for r in results}
    assert (by_name["boom"].status, by_name["boom"].records, by_name["boom"].warnings) == ("ok", 0, 1)
    assert (by_name["good"].status, by_name["good"].records) == ("ok", 2)

    warnings = list(store.artifacts(kind=ArtifactKind.PARSE_WARNING))
    assert len(warnings) == 1
    warning = warnings[0]
    assert warning.data["plugin"] == "boom"
    assert "bad header" in warning.data["error"]
    assert warning.provenance.source_path == "/b.txt"
    assert len(warning.data["extra"]["traceback"]) <= 5
    assert len(list(store.artifacts(kind=ArtifactKind.FILE_RECORD))) == 2


def test_locate_failure_marks_plugin_as_error(fs: MemoryFS, store: CaseStore) -> None:
    results = run_plugins(fs, store, EVIDENCE, [BrokenLocatePlugin(), GoodPlugin()], LOG, TZ)

    by_name = {r.name: r for r in results}
    assert by_name["broken"].status == "error"
    assert "disk gone" in (by_name["broken"].error or "")
    assert by_name["good"].status == "ok"
    assert len(list(store.artifacts(kind=ArtifactKind.FILE_RECORD))) == 2


def test_plugin_without_candidates_reports_no_candidates(store: CaseStore) -> None:
    empty = MemoryFS({}, evidence_id=EVIDENCE)

    results = run_plugins(empty, store, EVIDENCE, [GoodPlugin()], LOG, TZ)

    assert [r.status for r in results] == ["no_candidates"]


def test_records_flush_in_batches_of_batch_size(
    fs: MemoryFS, store: CaseStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "BATCH_SIZE", 1)
    batch_sizes: list[int] = []
    original_add = store.add

    def recording_add(records: Any) -> int:
        batch = list(records)
        batch_sizes.append(len(batch))
        return original_add(batch)

    monkeypatch.setattr(store, "add", recording_add)

    run_plugins(fs, store, EVIDENCE, [GoodPlugin()], LOG, TZ)

    assert batch_sizes == [1, 1]
