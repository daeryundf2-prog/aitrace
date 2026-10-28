from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aitrace.core.hashing import sha256_bytes
from aitrace.core.ids import make_id
from aitrace.core.kinds import ArtifactKind
from aitrace.core.model import Artifact, Case, Provenance
from aitrace.db.store import EXPORT_COLUMNS, CaseStore
from aitrace.export import exporter
from aitrace.export.exporter import ExportEntry, export_artifacts
from aitrace.export.manifest import write_manifest
from aitrace.fs.base import EntryRef
from aitrace.fs.memory_fs import MemoryFS

T0 = datetime(2026, 3, 1, 9, 0, 0, tzinfo=UTC)


def _case() -> Case:
    return Case(
        id=make_id("case", "T-40"),
        name="Export test",
        number="T-40",
        examiner="QA",
        organisation="Lab",
        created_utc=T0,
        timezone="Asia/Seoul",
        lang="en",
        tool_version="0.1.0",
    )


def _artifact(path: str, key: str, kind: ArtifactKind = ArtifactKind.SHELL_COMMAND) -> Artifact:
    return Artifact(
        id=make_id("artifact", kind.value, key),
        kind=kind,
        provenance=Provenance(
            evidence_id="mem", volume=0, source_path=path, plugin="p", plugin_version="1.0"
        ),
        data={},
        user="kim",
    )


@pytest.fixture
def case_store(tmp_path: Path) -> CaseStore:
    store = CaseStore(tmp_path / "case.db")
    store.init_case(_case())
    return store


def test_credential_bearing_file_is_hashed_but_not_copied(case_store: CaseStore, tmp_path: Path) -> None:
    path = "/Users/kim/.hermes/auth.json"
    data = b'{"api_key": "sk-not-a-real-key-0000000000000000"}'
    fs = MemoryFS({path: data})
    case_store.add(
        [
            _artifact(path, "cfg", ArtifactKind.AI_APP_PRESENCE),
            _artifact(path, "key", ArtifactKind.AI_CREDENTIAL),
        ]
    )
    case_store.finalize()
    case_dir = tmp_path / "case"

    entries = export_artifacts(fs, case_store, case_dir)

    assert len(entries) == 1
    assert entries[0].sha256 == ""
    assert entries[0].note == f"not copied: file holds credentials; source sha256 {sha256_bytes(data)}"
    assert not (case_dir / entries[0].export_path).exists()


def test_exported_file_hash_equals_source_hash(case_store: CaseStore, tmp_path: Path) -> None:
    path = "/Users/kim/notes.txt"
    data = b"echo hello\n"
    fs = MemoryFS({path: data})
    first = _artifact(path, "a")
    second = _artifact(path, "b", ArtifactKind.BROWSER_DOWNLOAD)
    case_store.add([first, second])
    case_store.finalize()
    case_dir = tmp_path / "case"

    entries = export_artifacts(fs, case_store, case_dir)

    assert len(entries) == 1
    entry = entries[0]
    source_sha = hashlib.sha256(fs.read_bytes(EntryRef(0, path))).hexdigest()
    assert entry.sha256 == source_sha == sha256_bytes(data)
    assert entry.size == len(data)
    assert entry.export_path == "export/files/0/Users/kim/notes.txt"
    assert (case_dir / entry.export_path).read_bytes() == data
    assert entry.artifact_ids == tuple(sorted([first.id, second.id]))
    stored = case_store.exports()
    assert len(stored) == 1
    assert stored[0]["sha256"] == source_sha
    assert stored[0]["source_path"] == path


def test_colon_and_shell_unsafe_chars_are_sanitized(case_store: CaseStore, tmp_path: Path) -> None:
    path = '/Users/kim/a:b*?"<>|.txt'
    fs = MemoryFS({path: b"x"})
    case_store.add([_artifact(path, "colon")])
    case_store.finalize()

    entry = export_artifacts(fs, case_store, tmp_path / "case")[0]

    assert entry.export_path == "export/files/0/Users/kim/a_b______.txt"
    assert entry.source_path == path
    assert (tmp_path / "case" / entry.export_path).read_bytes() == b"x"


def test_300_char_name_uses_hashed_long_path(case_store: CaseStore, tmp_path: Path) -> None:
    name = "a:" + "n" * 298
    assert len(name) == 300
    path = f"/Users/kim/{name}"
    fs = MemoryFS({path: b"long"})
    case_store.add([_artifact(path, "long")])
    case_store.finalize()

    entry = export_artifacts(fs, case_store, tmp_path / "case")[0]

    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
    assert entry.export_path == f"export/files/_long/{digest}__a_" + "n" * 78
    assert ":" not in entry.export_path
    assert entry.source_path == path
    assert (tmp_path / "case" / entry.export_path).read_bytes() == b"long"


def test_oversize_source_is_skipped_with_note(
    case_store: CaseStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(exporter, "MAX_EXPORT_BYTES", 4)
    path = "/Users/kim/big.bin"
    fs = MemoryFS({path: b"0123456789"})
    case_store.add([_artifact(path, "big")])
    case_store.finalize()
    case_dir = tmp_path / "case"

    entry = export_artifacts(fs, case_store, case_dir)[0]

    assert entry.note.startswith("skipped: 10 bytes")
    assert entry.sha256 == ""
    assert not (case_dir / entry.export_path).exists()
    assert case_store.exports()[0]["note"] == entry.note


def test_manifest_writes_csv_and_json(tmp_path: Path) -> None:
    entry = ExportEntry(
        export_path="export/files/0/a.txt",
        sha256="ab" * 32,
        size=1,
        source_volume=0,
        source_path="/a.txt",
        inode=3,
        artifact_ids=("x", "y"),
        deleted=True,
        note="",
    )

    write_manifest([entry], tmp_path)

    rows = list(csv.DictReader(io.StringIO((tmp_path / "manifest.csv").read_text(encoding="utf-8-sig"))))
    assert rows[0]["source_path"] == "/a.txt"
    assert rows[0]["artifact_ids"] == "x;y"
    assert rows[0]["deleted"] == "true"
    data = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert data[0]["source_path"] == "/a.txt"
    assert set(data[0]) == set(EXPORT_COLUMNS)
