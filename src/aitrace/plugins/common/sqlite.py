from __future__ import annotations

import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from aitrace.fs.base import EntryRef, EvidenceFS

_SIDECAR_SUFFIXES = ("-wal", "-journal")
_DB_NAME = "evidence.db"


@contextmanager
def open_sqlite(fs: EvidenceFS, ref: EntryRef) -> Iterator[sqlite3.Connection]:
    with tempfile.TemporaryDirectory(prefix="aitrace-sqlite-") as tmp:
        tmp_dir = Path(tmp)
        (tmp_dir / _DB_NAME).write_bytes(fs.read_bytes(ref))
        for suffix in _SIDECAR_SUFFIXES:
            sidecar = EntryRef(ref.volume, ref.path + suffix)
            if fs.exists(sidecar) and not fs.is_dir(sidecar):
                (tmp_dir / (_DB_NAME + suffix)).write_bytes(fs.read_bytes(sidecar))
        conn = sqlite3.connect((tmp_dir / _DB_NAME).as_uri() + "?mode=ro", uri=True)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            yield conn
        finally:
            conn.close()


def has_table(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
    return row is not None


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    if not has_table(conn, table):
        return set()
    quoted = table.replace('"', '""')
    return {row[1] for row in conn.execute(f'PRAGMA table_info("{quoted}")')}
