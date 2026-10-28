from __future__ import annotations

import ctypes
import ctypes.util
import errno
import functools
import hashlib
import os
import posixpath
import stat as stat_mod
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterator
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from aitrace.core.ids import make_id
from aitrace.core.kinds import OsFamily
from aitrace.core.model import Provenance, UserProfile, VolumeInfo
from aitrace.core.time import from_unix
from aitrace.fs.base import EntryRef, EntryStat, discover_users

_HASH_CHUNK = 1 << 20
_XATTR_NOFOLLOW = 0x0001  # darwin <sys/xattr.h>
_XATTR_UNSUPPORTED = frozenset({errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)})


@functools.cache
def _darwin_libc() -> ctypes.CDLL:
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
    libc.listxattr.restype = ctypes.c_ssize_t
    libc.getxattr.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    libc.getxattr.restype = ctypes.c_ssize_t
    return libc


def _xattr_error(host: str) -> OSError:
    code = ctypes.get_errno()
    return OSError(code, os.strerror(code), host)


def _darwin_xattrs(host: str) -> dict[str, bytes]:
    """Extended attributes of `host` itself (symlinks are not followed); {} when the volume has none."""
    libc = _darwin_libc()
    path = os.fsencode(host)
    size = libc.listxattr(path, None, 0, _XATTR_NOFOLLOW)
    if size < 0:
        if ctypes.get_errno() in _XATTR_UNSUPPORTED:
            return {}
        raise _xattr_error(host)
    if size == 0:
        return {}
    names = ctypes.create_string_buffer(size)
    size = libc.listxattr(path, names, size, _XATTR_NOFOLLOW)
    if size < 0:
        raise _xattr_error(host)
    result: dict[str, bytes] = {}
    for raw_name in names.raw[:size].split(b"\0"):
        if not raw_name:
            continue
        length = libc.getxattr(path, raw_name, None, 0, 0, _XATTR_NOFOLLOW)
        if length < 0:
            raise _xattr_error(host)
        value = ctypes.create_string_buffer(max(length, 1))
        length = libc.getxattr(path, raw_name, value, length, 0, _XATTR_NOFOLLOW)
        if length < 0:
            raise _xattr_error(host)
        result[os.fsdecode(raw_name)] = value.raw[:length]
    return result


def host_xattrs(host: str) -> dict[str, bytes]:
    """Host extended attributes via os.listxattr (Linux) or libc (macOS); {} where unsupported."""
    if hasattr(os, "listxattr"):
        try:
            names = os.listxattr(host, follow_symlinks=False)
        except OSError as exc:
            if exc.errno in _XATTR_UNSUPPORTED:
                return {}
            raise
        return {name: os.getxattr(host, name, follow_symlinks=False) for name in names}
    if sys.platform == "darwin":
        return _darwin_xattrs(host)
    return {}


class StatLike(Protocol):
    @property
    def st_mode(self) -> int: ...
    @property
    def st_ino(self) -> int: ...
    @property
    def st_size(self) -> int: ...
    @property
    def st_mtime(self) -> float: ...
    @property
    def st_atime(self) -> float: ...
    @property
    def st_ctime(self) -> float: ...


def clean_path(path: str) -> str:
    return "/" + posixpath.normpath("/" + path.replace("\\", "/").lstrip("/")).lstrip("/")


def _join(parent: str, name: str) -> str:
    return parent.rstrip("/") + "/" + name


def _segments(pattern: str) -> list[str]:
    return [s for s in pattern.replace("\\", "/").split("/") if s]


def entry_stat(st: StatLike) -> EntryStat:
    is_dir = stat_mod.S_ISDIR(st.st_mode)
    birth = getattr(st, "st_birthtime", None)
    return EntryStat(
        size=None if is_dir else st.st_size,
        is_dir=is_dir,
        inode=st.st_ino or None,
        mtime=from_unix(st.st_mtime),
        atime=from_unix(st.st_atime),
        ctime=from_unix(st.st_ctime),
        btime=from_unix(birth),
    )


class TreeFS(ABC):
    evidence_id: str

    @abstractmethod
    def _volume_indexes(self) -> list[int]: ...

    @abstractmethod
    def _exists(self, volume: int, path: str) -> bool: ...

    @abstractmethod
    def _is_dir(self, volume: int, path: str) -> bool: ...

    @abstractmethod
    def _is_symlink(self, volume: int, path: str) -> bool: ...

    @abstractmethod
    def _names(self, volume: int, path: str) -> list[str]: ...

    @abstractmethod
    def _lstat(self, volume: int, path: str) -> StatLike: ...

    @abstractmethod
    def _open(self, volume: int, path: str) -> BinaryIO: ...

    def _mft_seq(self, volume: int, path: str) -> int | None:
        return None

    def _streams(self, volume: int, path: str) -> list[str]:
        return []

    def _read_stream(self, volume: int, path: str, name: str) -> bytes:
        raise FileNotFoundError(f"{path}:{name}")

    def _xattrs(self, volume: int, path: str) -> dict[str, bytes]:
        return {}

    @abstractmethod
    def volumes(self) -> list[VolumeInfo]: ...

    @abstractmethod
    def raw_ntfs(self, volume: int) -> Any | None: ...

    def _check_volume(self, volume: int) -> None:
        if volume not in self._volume_indexes():
            raise FileNotFoundError(f"{type(self).__name__} has no volume {volume}")

    def _path(self, ref: EntryRef) -> str:
        self._check_volume(ref.volume)
        return clean_path(ref.path)

    def detect_os(self, volume: int) -> OsFamily:
        def has(path: str) -> bool:
            return self._find_ci(volume, path) is not None

        has_windows = has("/Windows")
        if has("/Windows/System32"):
            return OsFamily.WINDOWS
        if has("/System/Library/CoreServices/SystemVersion.plist") or (
            has("/Users") and has("/Library") and not has_windows
        ):
            return OsFamily.MACOS
        if has("/etc/os-release") or has("/home"):
            return OsFamily.LINUX
        return OsFamily.UNKNOWN

    def _find_ci(self, volume: int, path: str) -> str | None:
        if self._exists(volume, path):
            return path
        current = "/"
        for segment in _segments(path):
            if not self._is_dir(volume, current):
                return None
            wanted = segment.casefold()
            match = next((n for n in self._names(volume, current) if n.casefold() == wanted), None)
            if match is None:
                return None
            current = _join(current, match)
        return current

    def users(self) -> list[UserProfile]:
        users: list[UserProfile] = []
        for info in self.volumes():
            users.extend(discover_users(self, info.index, info.os_family))
        return users

    def exists(self, ref: EntryRef) -> bool:
        return self._exists(ref.volume, self._path(ref))

    def is_dir(self, ref: EntryRef) -> bool:
        return self._is_dir(ref.volume, self._path(ref))

    def listdir(self, ref: EntryRef) -> list[EntryRef]:
        path = self._path(ref)
        if not self._is_dir(ref.volume, path):
            raise NotADirectoryError(path)
        return [EntryRef(ref.volume, p) for p in sorted(_join(path, n) for n in self._names(ref.volume, path))]

    def open(self, ref: EntryRef) -> BinaryIO:
        path = self._path(ref)
        if self._is_dir(ref.volume, path):
            raise IsADirectoryError(path)
        return self._open(ref.volume, path)

    def read_bytes(self, ref: EntryRef, max_bytes: int | None = None) -> bytes:
        with self.open(ref) as fh:
            return fh.read() if max_bytes is None else fh.read(max_bytes)

    def stat(self, ref: EntryRef) -> EntryStat:
        path = self._path(ref)
        if not self._exists(ref.volume, path):
            raise FileNotFoundError(path)
        return entry_stat(self._lstat(ref.volume, path))

    def streams(self, ref: EntryRef) -> list[str]:
        return sorted(self._streams(ref.volume, self._path(ref)))

    def read_stream(self, ref: EntryRef, name: str) -> bytes:
        return self._read_stream(ref.volume, self._path(ref), name)

    def xattrs(self, ref: EntryRef) -> dict[str, bytes]:
        return self._xattrs(ref.volume, self._path(ref))

    def _children(self, volume: int, path: str) -> list[str]:
        if self._is_symlink(volume, path) or not self._is_dir(volume, path):
            return []
        return [_join(path, n) for n in self._names(volume, path)]

    def _match(self, volume: int, current: str, pattern: list[str]) -> Iterator[str]:
        if not pattern:
            yield current
            return
        head, rest = pattern[0], pattern[1:]
        if head == "**":
            yield from self._match(volume, current, rest)
            for child in self._children(volume, current):
                yield from self._match(volume, child, pattern)
            return
        wanted = head.casefold()
        for child in self._children(volume, current):
            if fnmatchcase(posixpath.basename(child).casefold(), wanted):
                yield from self._match(volume, child, rest)

    def glob(self, volume: int, pattern: str) -> Iterator[EntryRef]:
        self._check_volume(volume)
        found = set(self._match(volume, "/", _segments(pattern)))
        found.discard("/")
        for path in sorted(found):
            yield EntryRef(volume, path)

    def walk(
        self, ref: EntryRef, max_depth: int | None = None, skip_names: frozenset[str] = frozenset()
    ) -> Iterator[EntryRef]:
        root = self._path(ref)
        files: list[str] = []
        stack: list[tuple[str, int]] = [(root, 0)]
        while stack:
            current, depth = stack.pop()
            if max_depth is not None and depth >= max_depth:
                continue
            for child in self._children(ref.volume, current):
                if posixpath.basename(child) in skip_names:
                    continue
                if self._is_dir(ref.volume, child):
                    if not self._is_symlink(ref.volume, child):
                        stack.append((child, depth + 1))
                else:
                    files.append(child)
        for path in sorted(files):
            yield EntryRef(ref.volume, path)

    def provenance(
        self,
        ref: EntryRef,
        plugin: str,
        plugin_version: str,
        *,
        record_locator: str | None = None,
        with_hash: bool = False,
    ) -> Provenance:
        """`byte_offset` is always None: physical offsets are not resolved (documented limitation)."""
        path = self._path(ref)
        st = self.stat(ref)
        sha256: str | None = None
        if with_hash:
            digest = hashlib.sha256()
            with self.open(ref) as fh:
                while chunk := fh.read(_HASH_CHUNK):
                    digest.update(chunk)
            sha256 = digest.hexdigest()
        return Provenance(
            evidence_id=self.evidence_id,
            volume=ref.volume,
            source_path=path,
            plugin=plugin,
            plugin_version=plugin_version,
            inode=st.inode,
            mft_seq=self._mft_seq(ref.volume, path),
            byte_offset=None,
            size=st.size,
            sha256=sha256,
            record_locator=record_locator,
        )


class DirFS(TreeFS):
    """Symlinks whose real target lies outside the root are never followed: they exist (as links) but
    are not directories and cannot be opened, so the examiner's own host files never leak in.
    """

    def __init__(self, root: str | os.PathLike[str], evidence_id: str | None = None) -> None:
        resolved = Path(root).resolve()
        if not resolved.is_dir():
            raise NotADirectoryError(str(root))
        self.root = resolved
        self.evidence_id = evidence_id or make_id("evidence", "dir", str(resolved))
        self.kind = "dir"
        self.path = str(resolved)
        self.segments: tuple[str, ...] = ()
        self._os: OsFamily | None = None

    def _host(self, path: str) -> Path:
        return self.root / path.lstrip("/") if path != "/" else self.root

    def _contained(self, host: Path) -> bool:
        return host.resolve().is_relative_to(self.root)

    def _volume_indexes(self) -> list[int]:
        return [0]

    def _exists(self, volume: int, path: str) -> bool:
        host = self._host(path)
        return os.path.lexists(host)

    def _is_dir(self, volume: int, path: str) -> bool:
        host = self._host(path)
        return host.is_dir() and self._contained(host)

    def _is_symlink(self, volume: int, path: str) -> bool:
        return self._host(path).is_symlink()

    def _names(self, volume: int, path: str) -> list[str]:
        return os.listdir(self._host(path))

    def _lstat(self, volume: int, path: str) -> os.stat_result:
        return os.lstat(self._host(path))

    def _open(self, volume: int, path: str) -> BinaryIO:
        host = self._host(path)
        if not self._contained(host):
            raise PermissionError(f"symlink escapes evidence root: {path}")
        return open(host, "rb")

    def volumes(self) -> list[VolumeInfo]:
        if self._os is None:
            self._os = self.detect_os(0)
        return [VolumeInfo(index=0, fs_type="dir", label=self.root.name or None, size=None, os_family=self._os)]

    def raw_ntfs(self, volume: int) -> Any | None:
        self._check_volume(volume)
        return None

    _WINDOWS_STREAMS = ("Zone.Identifier",)

    def _streams(self, volume: int, path: str) -> list[str]:
        """Windows hosts only, and only the known download-origin stream (no portable ADS listing API)."""
        host = self._host(path)
        if os.name != "nt" or host.is_symlink() or not host.is_file():
            return []
        found: list[str] = []
        for name in self._WINDOWS_STREAMS:
            try:
                with open(f"{host}:{name}", "rb"):
                    found.append(name)
            except FileNotFoundError:
                continue
        return found

    def _read_stream(self, volume: int, path: str, name: str) -> bytes:
        host = self._host(path)
        if os.name != "nt" or not self._contained(host):
            raise FileNotFoundError(f"{path}:{name}")
        with open(f"{host}:{name}", "rb") as fh:
            return fh.read()

    def _xattrs(self, volume: int, path: str) -> dict[str, bytes]:
        return host_xattrs(str(self._host(path)))
