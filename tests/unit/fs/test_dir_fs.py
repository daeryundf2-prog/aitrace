from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aitrace.core.kinds import OsFamily
from aitrace.fs.base import EntryRef, user_glob
from aitrace.fs.dir_fs import DirFS

MTIME = datetime(2026, 10, 1, 1, 0, 21, tzinfo=UTC)

FILES = {
    "home/alice/.claude/projects/p1/a.jsonl": b'{"a":1}\n',
    "home/alice/.claude/projects/p1/sub/b.JSONL": b"{}\n",
    "home/alice/node_modules/pkg/index.js": b"x",
    "home/alice/.bash_history": b"ls\n",
    "Users/kim/AppData/Local/x.txt": b"x",
    "Users/Public/desktop.ini": b"",
    "etc/os-release": b"ID=test\n",
}


def _tree(root: Path) -> DirFS:
    for rel, data in FILES.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    ts = MTIME.timestamp()
    os.utime(root / "home/alice/.bash_history", (ts, ts))
    return DirFS(root, evidence_id="ev-dir")


def _paths(refs: Iterable[EntryRef]) -> list[str]:
    return [r.path for r in refs]


def test_volume_and_os_detection(tmp_path: Path) -> None:
    fs = _tree(tmp_path)
    [vol] = fs.volumes()
    assert (vol.index, vol.fs_type, vol.os_family) == (0, "dir", OsFamily.LINUX)
    assert fs.raw_ntfs(0) is None


def test_users_discovered(tmp_path: Path) -> None:
    users = {(u.name, u.home, u.os_family) for u in _tree(tmp_path).users()}
    assert users == {("alice", "/home/alice", OsFamily.LINUX), ("kim", "/Users/kim", OsFamily.WINDOWS)}


def test_glob_case_insensitive_and_double_star(tmp_path: Path) -> None:
    fs = _tree(tmp_path)
    assert _paths(fs.glob(0, "/HOME/*/.claude/projects/**/*.jsonl")) == [
        "/home/alice/.claude/projects/p1/a.jsonl",
        "/home/alice/.claude/projects/p1/sub/b.JSONL",
    ]
    assert _paths(fs.glob(0, "/home/*")) == ["/home/alice"]
    everything = _paths(fs.glob(0, "/**"))
    assert everything == sorted(everything)
    assert "/etc/os-release" in everything


def test_user_glob(tmp_path: Path) -> None:
    fs = _tree(tmp_path)
    alice = next(u for u in fs.users() if u.name == "alice")
    assert _paths(user_glob(fs, alice, ".bash_history")) == ["/home/alice/.bash_history"]


def test_listdir_exists_is_dir(tmp_path: Path) -> None:
    fs = _tree(tmp_path)
    assert _paths(fs.listdir(EntryRef(0, "/home/alice"))) == [
        "/home/alice/.bash_history",
        "/home/alice/.claude",
        "/home/alice/node_modules",
    ]
    assert fs.exists(EntryRef(0, "/etc/os-release"))
    assert not fs.exists(EntryRef(0, "/etc/missing"))
    assert fs.is_dir(EntryRef(0, "/etc")) and not fs.is_dir(EntryRef(0, "/etc/os-release"))
    with pytest.raises(NotADirectoryError):
        fs.listdir(EntryRef(0, "/etc/os-release"))
    with pytest.raises(FileNotFoundError):
        fs.exists(EntryRef(1, "/etc"))


def test_walk_depth_and_skip(tmp_path: Path) -> None:
    fs = _tree(tmp_path)
    root = EntryRef(0, "/home/alice")
    assert _paths(fs.walk(root, max_depth=1)) == ["/home/alice/.bash_history"]
    walked = _paths(fs.walk(root, skip_names=frozenset({"node_modules"})))
    assert walked == [
        "/home/alice/.bash_history",
        "/home/alice/.claude/projects/p1/a.jsonl",
        "/home/alice/.claude/projects/p1/sub/b.JSONL",
    ]


def test_open_read_only_and_read_bytes(tmp_path: Path) -> None:
    fs = _tree(tmp_path)
    ref = EntryRef(0, "/etc/os-release")
    with fs.open(ref) as fh:
        assert fh.mode == "rb"
        fh.seek(3)
        assert fh.read() == b"test\n"
    assert fs.read_bytes(ref, max_bytes=2) == b"ID"
    with pytest.raises(IsADirectoryError):
        fs.open(EntryRef(0, "/etc"))


def test_dotdot_cannot_escape_root(tmp_path: Path) -> None:
    (tmp_path / "outside.txt").write_bytes(b"host")
    root = tmp_path / "ev"
    root.mkdir()
    fs = _tree(root)
    assert not fs.exists(EntryRef(0, "/../outside.txt"))


def test_symlink_outside_root_is_not_followed(tmp_path: Path) -> None:
    host = tmp_path / "host"
    host.mkdir()
    (host / "secret.txt").write_bytes(b"host")
    root = tmp_path / "ev"
    root.mkdir()
    fs = _tree(root)
    (root / "home/alice/link").symlink_to(host, target_is_directory=True)
    (root / "home/alice/flink").symlink_to(host / "secret.txt")
    assert fs.exists(EntryRef(0, "/home/alice/link"))
    assert not fs.is_dir(EntryRef(0, "/home/alice/link"))
    with pytest.raises(PermissionError):
        fs.read_bytes(EntryRef(0, "/home/alice/flink"))
    assert "/home/alice/link/secret.txt" not in _paths(fs.glob(0, "/**"))


def test_stat_and_provenance(tmp_path: Path) -> None:
    fs = _tree(tmp_path)
    ref = EntryRef(0, "/home/alice/.bash_history")
    st = fs.stat(ref)
    assert st.size == 3 and not st.is_dir
    assert st.inode == os.stat(tmp_path / "home/alice/.bash_history").st_ino
    assert st.mtime == MTIME
    assert fs.stat(EntryRef(0, "/home")).is_dir
    prov = fs.provenance(ref, "test.plugin", "1.0", record_locator="line:1", with_hash=True)
    assert prov.evidence_id == "ev-dir" and prov.volume == 0
    assert prov.source_path == "/home/alice/.bash_history"
    assert prov.inode == st.inode and prov.size == 3
    assert prov.sha256 == hashlib.sha256(b"ls\n").hexdigest()
    assert prov.mft_seq is None and prov.byte_offset is None
    with pytest.raises(FileNotFoundError):
        fs.stat(EntryRef(0, "/nope"))
