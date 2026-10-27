from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aitrace.core.kinds import OsFamily
from aitrace.fs.base import EntryRef
from aitrace.fs.dissect_fs import DissectFS

MTIME = datetime(2026, 10, 1, 1, 0, 21, tzinfo=UTC)
IMAGES_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "images"

FILES = {
    "home/alice/.claude/projects/p1/a.jsonl": b'{"a":1}\n',
    "home/alice/.claude/projects/p1/sub/b.JSONL": b"{}\n",
    "home/alice/.bash_history": b"ls\nscp x host:/tmp\n",
    "etc/os-release": b"ID=test\n",
}


def build_ext4(tmp_path: Path) -> Path:
    mke2fs = shutil.which("mke2fs")
    if mke2fs is None:
        pytest.skip("mke2fs not installed")
    stage = tmp_path / "stage"
    for rel, data in FILES.items():
        target = stage / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    ts = MTIME.timestamp()
    os.utime(stage / "home/alice/.bash_history", (ts, ts))
    image = tmp_path / "linux.raw"
    subprocess.run([mke2fs, "-q", "-t", "ext4", "-d", str(stage), str(image), "16M"], check=True)
    return image


def _paths(refs: Iterable[EntryRef]) -> list[str]:
    return [r.path for r in refs]


@pytest.fixture
def ext4(tmp_path: Path) -> DissectFS:
    return DissectFS(str(build_ext4(tmp_path)), evidence_id="ev-ext4")


def test_volumes(ext4: DissectFS) -> None:
    [vol] = ext4.volumes()
    assert vol.index == 0
    assert vol.fs_type == "ExtFilesystem"
    assert vol.size == 16 * 1024 * 1024
    assert vol.os_family is OsFamily.LINUX
    assert ext4.raw_ntfs(0) is None


def test_users_home_alice_is_linux(ext4: DissectFS) -> None:
    users = ext4.users()
    assert [(u.name, u.home, u.volume, u.os_family, u.sid) for u in users] == [
        ("alice", "/home/alice", 0, OsFamily.LINUX, None)
    ]


def test_glob_case_insensitive_on_ext4(ext4: DissectFS) -> None:
    assert _paths(ext4.glob(0, "/HOME/*/.CLAUDE/projects/**/*.jsonl")) == [
        "/home/alice/.claude/projects/p1/a.jsonl",
        "/home/alice/.claude/projects/p1/sub/b.JSONL",
    ]
    assert _paths(ext4.glob(0, "/home/*")) == ["/home/alice"]


def test_listdir_walk_read(ext4: DissectFS) -> None:
    assert "/home" in _paths(ext4.listdir(EntryRef(0, "/")))
    assert _paths(ext4.walk(EntryRef(0, "/home/alice"), skip_names=frozenset({".claude"}))) == [
        "/home/alice/.bash_history"
    ]
    ref = EntryRef(0, "/home/alice/.bash_history")
    assert ext4.exists(ref) and not ext4.is_dir(ref)
    assert not ext4.exists(EntryRef(0, "/home/bob"))
    assert ext4.read_bytes(ref) == FILES["home/alice/.bash_history"]
    assert ext4.read_bytes(ref, max_bytes=2) == b"ls"
    with ext4.open(ref) as fh:
        fh.seek(3)
        assert fh.read(3) == b"scp"
    with pytest.raises(FileNotFoundError):
        ext4.listdir(EntryRef(5, "/"))


def test_stat_and_provenance(ext4: DissectFS) -> None:
    ref = EntryRef(0, "/home/alice/.bash_history")
    st = ext4.stat(ref)
    assert st.size == len(FILES["home/alice/.bash_history"]) and not st.is_dir
    assert st.mtime == MTIME and st.mtime.tzinfo is UTC
    assert st.inode is not None and st.inode > 0
    assert ext4.stat(EntryRef(0, "/home")).is_dir
    prov = ext4.provenance(ref, "test.plugin", "1.0", record_locator="line:2", with_hash=True)
    assert prov.evidence_id == "ev-ext4"
    assert prov.source_path == "/home/alice/.bash_history"
    assert prov.inode == st.inode
    assert prov.mft_seq is None and prov.byte_offset is None
    assert prov.sha256 == hashlib.sha256(FILES["home/alice/.bash_history"]).hexdigest()
    with pytest.raises(FileNotFoundError):
        ext4.stat(EntryRef(0, "/nope"))


def test_e01_fixture_images_open_when_present() -> None:
    for image in sorted(IMAGES_DIR.glob("*.E01")):
        fs = DissectFS(str(image), kind="e01")
        assert fs.volumes(), f"no volumes in {image.name}"
        assert fs.users(), f"no users in {image.name}"
