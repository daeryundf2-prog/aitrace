from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime

import pytest

from aitrace.core.ids import make_id
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.fs.base import EntryRef, user_glob
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

MTIME = datetime(2026, 10, 1, 1, 0, 21, tzinfo=UTC)


def _fs() -> MemoryFS:
    return MemoryFS(
        {
            "/Users/kim/.claude/projects/p1/a.jsonl": b'{"a":1}\n',
            "/Users/kim/.claude/projects/p1/sub/b.JSONL": b"{}\n",
            "/Users/kim/AppData/Local/x.txt": b"x",
            "/Users/kim/work/proposal.md": b"# P\n",
            "/Users/Public/desktop.ini": b"",
            "/Users/.hidden/f": b"",
            "/Users/lee/Library/Prefs/p.plist": b"",
            "/home/y/.bash_history": b"ls\n",
            "/root/.bashrc": b"",
            "/etc/hostname": b"lnx\n",
        },
        volume_os=OsFamily.LINUX,
        mtimes={"/Users/kim/work/proposal.md": MTIME},
    )


def _paths(refs: object) -> list[str]:
    return [r.path for r in refs]  # type: ignore[attr-defined]


def test_glob_double_star_any_depth() -> None:
    fs = _fs()
    assert _paths(fs.glob(0, "/Users/*/.claude/projects/**/*.jsonl")) == [
        "/Users/kim/.claude/projects/p1/a.jsonl",
        "/Users/kim/.claude/projects/p1/sub/b.JSONL",
    ]
    assert _paths(fs.glob(0, "/**/hostname")) == ["/etc/hostname"]


def test_glob_case_insensitive_and_single_segment_star() -> None:
    fs = _fs()
    assert _paths(fs.glob(0, "/users/KIM/WORK/*.MD")) == ["/Users/kim/work/proposal.md"]
    assert _paths(fs.glob(0, "/Users/*/proposal.md")) == []


def test_glob_includes_directories_and_is_sorted() -> None:
    assert _paths(_fs().glob(0, "/home/*")) == ["/home/y"]
    found = _paths(_fs().glob(0, "/**"))
    assert found == sorted(found)


def test_listdir_sorted_children() -> None:
    fs = _fs()
    assert _paths(fs.listdir(EntryRef(0, "/Users"))) == [
        "/Users/.hidden",
        "/Users/Public",
        "/Users/kim",
        "/Users/lee",
    ]
    assert _paths(fs.listdir(EntryRef(0, "/"))) == ["/Users", "/etc", "/home", "/root"]
    with pytest.raises(NotADirectoryError):
        fs.listdir(EntryRef(0, "/etc/hostname"))


def test_exists_is_dir_and_read() -> None:
    fs = _fs()
    assert fs.exists(EntryRef(0, "/Users/kim/work"))
    assert fs.is_dir(EntryRef(0, "/Users/kim/work"))
    assert not fs.is_dir(EntryRef(0, "/Users/kim/work/proposal.md"))
    assert not fs.exists(EntryRef(0, "/nope"))
    assert fs.read_bytes(EntryRef(0, "/etc/hostname"), max_bytes=3) == b"lnx"
    with fs.open(EntryRef(0, "/etc/hostname")) as handle:
        handle.seek(1)
        assert handle.read() == b"nx\n"
    with pytest.raises(FileNotFoundError):
        fs.read_bytes(EntryRef(0, "/Users"))


def test_stat() -> None:
    fs = _fs()
    st = fs.stat(EntryRef(0, "/Users/kim/work/proposal.md"))
    assert (st.size, st.is_dir, st.mtime) == (4, False, MTIME)
    assert st.inode is not None and st.inode == fs.stat(EntryRef(0, "/Users/kim/work/proposal.md")).inode
    dir_stat = fs.stat(EntryRef(0, "/Users/kim"))
    assert dir_stat.is_dir and dir_stat.size is None
    assert dir_stat.inode != st.inode
    with pytest.raises(FileNotFoundError):
        fs.stat(EntryRef(0, "/missing"))


def test_users_discovery() -> None:
    users = {u.name: u for u in _fs().users()}
    assert set(users) == {"kim", "lee", "y", "root"}
    assert users["kim"].home == "/Users/kim" and users["kim"].os_family is OsFamily.WINDOWS
    assert users["lee"].os_family is OsFamily.MACOS
    assert users["y"].home == "/home/y" and users["y"].os_family is OsFamily.LINUX
    assert users["root"].home == "/root"
    assert all(u.volume == 0 for u in users.values())


def test_users_skip_private_var_root() -> None:
    fs = MemoryFS({"/private/var/root/.zsh_history": b"", "/Users/x/f": b""}, volume_os=OsFamily.MACOS)
    assert [(u.name, u.os_family) for u in fs.users()] == [("x", OsFamily.MACOS)]


def test_user_glob() -> None:
    fs = _fs()
    kim = next(u for u in fs.users() if u.name == "kim")
    assert _paths(user_glob(fs, kim, "work/*.md")) == ["/Users/kim/work/proposal.md"]


def test_walk_files_only_with_depth_and_skip() -> None:
    fs = _fs()
    root = EntryRef(0, "/Users/kim")
    assert _paths(fs.walk(root)) == [
        "/Users/kim/.claude/projects/p1/a.jsonl",
        "/Users/kim/.claude/projects/p1/sub/b.JSONL",
        "/Users/kim/AppData/Local/x.txt",
        "/Users/kim/work/proposal.md",
    ]
    assert _paths(fs.walk(root, max_depth=2)) == ["/Users/kim/work/proposal.md"]
    assert _paths(fs.walk(root, skip_names=frozenset({".claude", "AppData"}))) == ["/Users/kim/work/proposal.md"]


def test_volumes_and_provenance() -> None:
    fs = _fs()
    (volume,) = fs.volumes()
    assert volume.index == 0 and volume.os_family is OsFamily.LINUX
    ref = EntryRef(0, "/etc/hostname")
    prov = fs.provenance(ref, "p", "1.0", record_locator="line:1", with_hash=True)
    assert prov.source_path == "/etc/hostname"
    assert prov.sha256 == hashlib.sha256(b"lnx\n").hexdigest()
    assert prov.record_locator == "line:1" and prov.inode is None
    assert fs.provenance(ref, "p", "1.0").sha256 is None
    assert fs.raw_ntfs(0) is None


class _Plugin(PluginBase):
    name = "sample"
    version = "2.0"


def test_plugin_base_ids_follow_appendix_a4() -> None:
    fs = _fs()
    plugin = _Plugin()
    kim = next(u for u in fs.users() if u.name == "kim")
    ctx = ParseContext(fs=fs, evidence_id="mem", tz="UTC", log=logging.getLogger("test"))
    cand = Candidate(ref=EntryRef(0, "/Users/kim/work/proposal.md"), role="doc", user=kim)
    art = plugin.artifact(ctx, cand, ArtifactKind.FILE_RECORD, {"path": cand.ref.path}, locator="row:1")
    assert art.id == make_id("mem", "sample", 0, "/Users/kim/work/proposal.md", "row:1", ArtifactKind.FILE_RECORD)
    assert art.user == "kim" and art.provenance.plugin_version == "2.0"
    deleted = plugin.artifact(ctx, cand, ArtifactKind.FILE_RECORD, {}, deleted=True)
    assert deleted.provenance.deleted
    ev = plugin.event(art, MTIME, "mtime", EventCategory.FILE_MODIFIED, Actor.UNKNOWN, "modified", index=3)
    assert ev.id == make_id(art.id, "mtime", EventCategory.FILE_MODIFIED, 3)
    assert ev.user == "kim" and ev.data == {}
    warn = plugin.warning(ctx, cand, "bad line")
    assert warn.kind is ArtifactKind.PARSE_WARNING
    assert warn.data == {"plugin": "sample", "message": "bad line"}
    assert warn.id != plugin.warning(ctx, cand, "other").id
