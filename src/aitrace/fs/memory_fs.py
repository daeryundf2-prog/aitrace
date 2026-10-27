from __future__ import annotations

import hashlib
import io
import posixpath
from collections.abc import Iterator
from datetime import datetime
from fnmatch import fnmatchcase
from typing import Any, BinaryIO

from aitrace.core.kinds import OsFamily
from aitrace.core.model import Provenance, UserProfile, VolumeInfo
from aitrace.fs.base import EntryRef, EntryStat, discover_users


def _clean(path: str) -> str:
    return "/" + posixpath.normpath("/" + path.replace("\\", "/").lstrip("/")).lstrip("/")


def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s]


def _glob_match(pattern: list[str], parts: list[str]) -> bool:
    if not pattern:
        return not parts
    head = pattern[0]
    if head == "**":
        return any(_glob_match(pattern[1:], parts[i:]) for i in range(len(parts) + 1))
    if not parts:
        return False
    return fnmatchcase(parts[0].casefold(), head.casefold()) and _glob_match(pattern[1:], parts[1:])


class MemoryFS:
    def __init__(
        self,
        files: dict[str, bytes],
        volume_os: OsFamily = OsFamily.UNKNOWN,
        mtimes: dict[str, datetime] | None = None,
        evidence_id: str = "mem",
    ) -> None:
        self.evidence_id = evidence_id
        self._volume_os = volume_os
        self._files: dict[str, bytes] = {_clean(p): data for p, data in files.items()}
        self._mtimes: dict[str, datetime] = {_clean(p): ts for p, ts in (mtimes or {}).items()}
        dirs: set[str] = {"/"}
        for path in self._files:
            parent = posixpath.dirname(path)
            while parent not in dirs:
                dirs.add(parent)
                parent = posixpath.dirname(parent)
        self._dirs = dirs
        self._inodes = {path: index for index, path in enumerate(sorted(dirs | set(self._files)), start=1)}

    def _check_volume(self, volume: int) -> None:
        if volume != 0:
            raise FileNotFoundError(f"MemoryFS has only volume 0, not {volume}")

    def _path(self, ref: EntryRef) -> str:
        self._check_volume(ref.volume)
        return _clean(ref.path)

    def volumes(self) -> list[VolumeInfo]:
        size = sum(len(data) for data in self._files.values())
        return [VolumeInfo(index=0, fs_type="memory", label=None, size=size, os_family=self._volume_os)]

    def users(self) -> list[UserProfile]:
        return discover_users(self, 0, self._volume_os)

    def exists(self, ref: EntryRef) -> bool:
        path = self._path(ref)
        return path in self._files or path in self._dirs

    def is_dir(self, ref: EntryRef) -> bool:
        return self._path(ref) in self._dirs

    def listdir(self, ref: EntryRef) -> list[EntryRef]:
        path = self._path(ref)
        if path not in self._dirs:
            raise NotADirectoryError(path)
        children = {
            p for p in self._inodes if p != path and posixpath.dirname(p) == path
        }
        return [EntryRef(0, p) for p in sorted(children)]

    def open(self, ref: EntryRef) -> BinaryIO:
        return io.BytesIO(self.read_bytes(ref))

    def read_bytes(self, ref: EntryRef, max_bytes: int | None = None) -> bytes:
        path = self._path(ref)
        if path not in self._files:
            raise FileNotFoundError(path)
        data = self._files[path]
        return data if max_bytes is None else data[:max_bytes]

    def stat(self, ref: EntryRef) -> EntryStat:
        path = self._path(ref)
        if path in self._files:
            return EntryStat(
                size=len(self._files[path]),
                is_dir=False,
                inode=self._inodes[path],
                mtime=self._mtimes.get(path),
                atime=None,
                ctime=None,
                btime=None,
            )
        if path in self._dirs:
            return EntryStat(
                size=None,
                is_dir=True,
                inode=self._inodes[path],
                mtime=self._mtimes.get(path),
                atime=None,
                ctime=None,
                btime=None,
            )
        raise FileNotFoundError(path)

    def glob(self, volume: int, pattern: str) -> Iterator[EntryRef]:
        self._check_volume(volume)
        pattern_parts = _segments(pattern.replace("\\", "/"))
        for path in sorted(self._inodes):
            if path != "/" and _glob_match(pattern_parts, _segments(path)):
                yield EntryRef(0, path)

    def walk(
        self, ref: EntryRef, max_depth: int | None = None, skip_names: frozenset[str] = frozenset()
    ) -> Iterator[EntryRef]:
        """Files below `ref`; depth 1 = direct children; any path segment in `skip_names` prunes it."""
        root = self._path(ref)
        prefix = root.rstrip("/") + "/"
        for path in sorted(self._files):
            if not path.startswith(prefix):
                continue
            rel = _segments(path[len(prefix) :])
            if max_depth is not None and len(rel) > max_depth:
                continue
            if any(segment in skip_names for segment in rel):
                continue
            yield EntryRef(0, path)

    def provenance(
        self,
        ref: EntryRef,
        plugin: str,
        plugin_version: str,
        *,
        record_locator: str | None = None,
        with_hash: bool = False,
    ) -> Provenance:
        path = self._path(ref)
        sha256 = hashlib.sha256(self.read_bytes(ref)).hexdigest() if with_hash else None
        return Provenance(
            evidence_id=self.evidence_id,
            volume=0,
            source_path=path,
            plugin=plugin,
            plugin_version=plugin_version,
            sha256=sha256,
            record_locator=record_locator,
        )

    def raw_ntfs(self, volume: int) -> Any | None:
        self._check_volume(volume)
        return None
