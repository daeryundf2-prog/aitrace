from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from pathlib import Path

import pytest

from aitrace.core.kinds import OsFamily
from aitrace.fs.base import EntryRef
from aitrace.fs.dir_fs import DirFS
from aitrace.fs.dissect_fs import DissectFS
from aitrace.fs.memory_fs import MemoryFS

IMAGES_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "images"
WHERE_FROMS = "com.apple.metadata:kMDItemWhereFroms"
PLIST = b"bplist00\xa1\x01_\x10\x15https://claude.ai/x/1\x08\n\x00\x00\x00\x00\x00\x00\x01\x01"


def _set_host_xattr(path: Path, name: str, value: bytes) -> None:
    if hasattr(os, "setxattr"):
        os.setxattr(path, name, value)
        return
    if sys.platform != "darwin":
        pytest.skip("no xattr support on this host")
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.setxattr.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    if libc.setxattr(os.fsencode(path), name.encode(), value, len(value), 0, 0) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(path))


def test_memory_fs_streams_and_xattrs() -> None:
    fs = MemoryFS(
        {"/Users/kim/a.txt": b"a", "/Users/kim/b.txt": b"b"},
        volume_os=OsFamily.MACOS,
        streams={"Users/kim/a.txt": {"Zone.Identifier": b"[ZoneTransfer]\r\nZoneId=3\r\n", "Alt": b"x"}},
        xattrs={"/Users/kim/a.txt": {WHERE_FROMS: PLIST}},
    )
    a, b = EntryRef(0, "/Users/kim/a.txt"), EntryRef(0, "/Users/kim/b.txt")
    assert fs.streams(a) == ["Alt", "Zone.Identifier"]
    assert fs.read_stream(a, "Zone.Identifier").startswith(b"[ZoneTransfer]")
    assert fs.xattrs(a) == {WHERE_FROMS: PLIST}
    assert fs.streams(b) == [] and fs.xattrs(b) == {}
    with pytest.raises(FileNotFoundError):
        fs.read_stream(b, "Zone.Identifier")


def test_memory_fs_default_has_no_streams_or_xattrs() -> None:
    fs = MemoryFS({"/x": b""})
    assert fs.streams(EntryRef(0, "/x")) == [] and fs.xattrs(EntryRef(0, "/x")) == {}


def test_dir_fs_reads_real_host_xattr(tmp_path: Path) -> None:
    target = tmp_path / "Users" / "kim" / "Downloads" / "f.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"payload")
    plain = target.with_name("plain.bin")
    plain.write_bytes(b"")
    name = WHERE_FROMS if sys.platform == "darwin" else "user.aitrace_test"
    _set_host_xattr(target, name, PLIST)
    fs = DirFS(tmp_path)
    ref = EntryRef(0, "/Users/kim/Downloads/f.bin")
    assert fs.xattrs(ref)[name] == PLIST
    assert name not in fs.xattrs(EntryRef(0, "/Users/kim/Downloads/plain.bin"))
    if os.name != "nt":
        assert fs.streams(ref) == []
    with pytest.raises(FileNotFoundError):
        fs.xattrs(EntryRef(0, "/Users/kim/missing.bin"))


def _image(name: str) -> DissectFS:
    path = IMAGES_DIR / name
    if not path.is_file():
        pytest.skip(f"fixture image absent: {path}")
    return DissectFS(str(path))


def _first_user_file(fs: DissectFS) -> EntryRef:
    user = fs.users()[0]
    return next(fs.walk(EntryRef(user.volume, user.home), max_depth=6))


def test_dissect_ntfs_user_file_has_no_streams_but_metafile_does() -> None:
    fs = _image("windows.E01")
    ref = _first_user_file(fs)
    assert fs.streams(ref) == []
    assert fs.xattrs(ref) == {}
    secure = EntryRef(ref.volume, "/$Secure")
    assert "$SDS" in fs.streams(secure)
    assert len(fs.read_stream(secure, "$SDS")) > 0


def test_dissect_apfs_has_xattrs_and_no_streams() -> None:
    fs = _image("macos.E01")
    ref = _first_user_file(fs)
    assert fs.streams(ref) == []
    attrs = fs.xattrs(ref)
    assert all(isinstance(k, str) and isinstance(v, bytes) for k, v in attrs.items())
    assert WHERE_FROMS not in attrs
    with pytest.raises(FileNotFoundError):
        fs.read_stream(ref, "Zone.Identifier")
