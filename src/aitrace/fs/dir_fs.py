from __future__ import annotations

import hashlib
import os
import posixpath
import stat as stat_mod
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
