from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from aitrace.fs.base import EntryRef
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.common.sqlite import has_table, open_sqlite, table_columns

DB_PATH = "/Users/kim/Library/Application Support/app/store.db"


def _uncheckpointed_wal_database(tmp_path: Path) -> tuple[bytes, bytes]:
    db_file = tmp_path / "store.db"
    writer = sqlite3.connect(db_file)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, role TEXT, body TEXT)")
        writer.execute("INSERT INTO messages (role, body) VALUES ('user', '고객 DB를 덤프해서')")
        writer.commit()
        wal_bytes = Path(f"{db_file}-wal").read_bytes()
        db_bytes = db_file.read_bytes()
    finally:
        writer.close()
    assert wal_bytes, "precondition: rows must be held in the -wal file"
    return db_bytes, wal_bytes


def test_open_sqlite_reads_rows_held_in_wal_sidecar(tmp_path: Path) -> None:
    db_bytes, wal_bytes = _uncheckpointed_wal_database(tmp_path)
    fs = MemoryFS({DB_PATH: db_bytes, DB_PATH + "-wal": wal_bytes})

    with open_sqlite(fs, EntryRef(0, DB_PATH)) as conn:
        assert has_table(conn, "messages")
        assert table_columns(conn, "messages") == {"id", "role", "body"}
        rows = conn.execute("SELECT role, body FROM messages").fetchall()

    assert [(row["role"], row["body"]) for row in rows] == [("user", "고객 DB를 덤프해서")]


def test_open_sqlite_without_wal_sidecar_misses_uncheckpointed_rows(tmp_path: Path) -> None:
    db_bytes, _ = _uncheckpointed_wal_database(tmp_path)
    fs = MemoryFS({DB_PATH: db_bytes})

    with open_sqlite(fs, EntryRef(0, DB_PATH)) as conn:
        assert not has_table(conn, "messages")


def test_table_helpers_report_absent_table(tmp_path: Path) -> None:
    db_bytes, wal_bytes = _uncheckpointed_wal_database(tmp_path)
    fs = MemoryFS({DB_PATH: db_bytes, DB_PATH + "-wal": wal_bytes})

    with open_sqlite(fs, EntryRef(0, DB_PATH)) as conn:
        assert not has_table(conn, "no_such_table")
        assert table_columns(conn, "no_such_table") == set()


def test_open_sqlite_rejects_non_sqlite_bytes() -> None:
    fs = MemoryFS({DB_PATH: b"this is not a sqlite database" * 64})

    with pytest.raises(sqlite3.DatabaseError) as excinfo, open_sqlite(fs, EntryRef(0, DB_PATH)):
        pass

    assert excinfo.type is sqlite3.DatabaseError
