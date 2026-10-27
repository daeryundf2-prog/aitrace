from __future__ import annotations

import hashlib
import io
import logging
import zipfile
from datetime import UTC, datetime
from typing import Any

from aitrace.core.kinds import ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.base import EntryRef
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.fsmeta.file_inventory import PLUGIN, W_NS

LOG = logging.getLogger("tests.file_inventory")
T0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


class _UnreadableFS(MemoryFS):
    def __init__(self, files: dict[str, bytes], unreadable: str, **kwargs: Any) -> None:
        super().__init__(files, **kwargs)
        self._unreadable = unreadable

    def read_bytes(self, ref: EntryRef, max_bytes: int | None = None) -> bytes:
        if ref.path == self._unreadable:
            raise OSError("simulated I/O error")
        return super().read_bytes(ref, max_bytes)


def _run(fs: MemoryFS) -> list[Artifact | Event]:
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="UTC", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _artifacts(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _docx(text: str) -> bytes:
    body = f'<w:document xmlns:w="{W_NS}"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("word/document.xml", body)
    return buf.getvalue()


def test_happy_path_two_files_emit_records_and_events() -> None:
    fs = MemoryFS(
        {"/Users/alice/notes.md": b"hello", "/Users/alice/photo.jpg": b"\x89PNG\x00\x01"},
        volume_os=OsFamily.MACOS,
        mtimes={"/Users/alice/notes.md": T0, "/Users/alice/photo.jpg": T0},
    )
    records = _run(fs)

    file_records = _artifacts(records, ArtifactKind.FILE_RECORD)
    assert len(file_records) == 2
    events = [r for r in records if isinstance(r, Event)]
    assert 2 <= len(events) <= 4
    assert {e.category for e in events} == {EventCategory.FILE_MODIFIED}

    notes = next(a for a in file_records if a.data["path"] == "/Users/alice/notes.md")
    assert notes.data["content_sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert notes.data["text_sample"] == "hello"
    assert notes.data["mtime"] == "2026-10-01T09:00:00Z"
    assert notes.provenance.size == 5

    photo = next(a for a in file_records if a.data["path"] == "/Users/alice/photo.jpg")
    assert "content_sha256" not in photo.data
    assert "text_sample" not in photo.data


def test_unreadable_file_warns_and_walk_continues() -> None:
    fs = _UnreadableFS(
        {"/Users/alice/a.txt": b"first", "/Users/alice/b.txt": b"second"},
        unreadable="/Users/alice/a.txt",
        volume_os=OsFamily.MACOS,
    )
    records = _run(fs)

    warnings = _artifacts(records, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 1
    assert warnings[0].provenance.source_path == "/Users/alice/a.txt"
    assert "simulated I/O error" in warnings[0].data["message"]

    file_records = _artifacts(records, ArtifactKind.FILE_RECORD)
    assert len(file_records) == 2
    paths = {a.data["path"]: a.data for a in file_records}
    assert "content_sha256" not in paths["/Users/alice/a.txt"]
    assert paths["/Users/alice/b.txt"]["content_sha256"] == hashlib.sha256(b"second").hexdigest()


def test_docx_text_comes_from_word_document_xml() -> None:
    fs = MemoryFS({"/Users/alice/Documents/memo.docx": _docx("Quarterly memo")}, volume_os=OsFamily.MACOS)
    records = _run(fs)

    (record,) = _artifacts(records, ArtifactKind.FILE_RECORD)
    assert record.data["text_sample"] == "Quarterly memo"
    assert record.data["content_sha256"] == hashlib.sha256(_docx("Quarterly memo")).hexdigest()


def test_pruned_and_cache_paths_are_not_inventoried() -> None:
    fs = MemoryFS(
        {
            "/Users/alice/keep.txt": b"keep",
            "/Users/alice/project/node_modules/pkg/index.js": b"x",
            "/Users/alice/.git/config": b"x",
            "/Users/alice/Library/Caches/cache.txt": b"x",
        },
        volume_os=OsFamily.MACOS,
    )
    records = _run(fs)

    (record,) = _artifacts(records, ArtifactKind.FILE_RECORD)
    assert record.data["path"] == "/Users/alice/keep.txt"
