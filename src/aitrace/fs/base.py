from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any, BinaryIO, Protocol

from aitrace.core.kinds import OsFamily
from aitrace.core.model import Provenance, UserProfile, VolumeInfo


@dataclass(frozen=True, slots=True)
class EntryRef:
    volume: int
    path: str  # POSIX absolute within volume, e.g. "/Users/kim/.claude"


@dataclass(frozen=True, slots=True)
class EntryStat:
    size: int | None
    is_dir: bool
    inode: int | None
    mtime: datetime | None
    atime: datetime | None
    ctime: datetime | None
    btime: datetime | None


class EvidenceFS(Protocol):
    evidence_id: str

    def volumes(self) -> list[VolumeInfo]: ...

    def users(self) -> list[UserProfile]: ...

    def exists(self, ref: EntryRef) -> bool: ...

    def is_dir(self, ref: EntryRef) -> bool: ...

    def listdir(self, ref: EntryRef) -> list[EntryRef]: ...  # sorted by path

    def open(self, ref: EntryRef) -> BinaryIO: ...  # read-only, seekable

    def read_bytes(self, ref: EntryRef, max_bytes: int | None = None) -> bytes: ...

    def stat(self, ref: EntryRef) -> EntryStat: ...

    def glob(self, volume: int, pattern: str) -> Iterator[EntryRef]: ...  # "*" one segment, "**" any depth; case-insensitive; sorted

    def walk(
        self, ref: EntryRef, max_depth: int | None = None, skip_names: frozenset[str] = frozenset()
    ) -> Iterator[EntryRef]: ...  # files only, sorted

    def provenance(
        self,
        ref: EntryRef,
        plugin: str,
        plugin_version: str,
        *,
        record_locator: str | None = None,
        with_hash: bool = False,
    ) -> Provenance: ...

    def raw_ntfs(self, volume: int) -> Any | None: ...  # dissect.ntfs.NTFS or None


def user_glob(fs: EvidenceFS, user: UserProfile, rel_pattern: str) -> Iterator[EntryRef]:
    pattern = user.home.rstrip("/") + "/" + rel_pattern.lstrip("/")
    return fs.glob(user.volume, pattern)


SKIPPED_USER_DIRS = frozenset({"Public", "Default", "Default User", "All Users", "Shared", "Guest"})


def _user_os(fs: EvidenceFS, volume: int, home: str, volume_os: OsFamily) -> OsFamily:
    if fs.is_dir(EntryRef(volume, home + "/AppData")):
        return OsFamily.WINDOWS
    if fs.is_dir(EntryRef(volume, home + "/Library")):
        return OsFamily.MACOS
    return volume_os


def discover_users(fs: EvidenceFS, volume: int, os_family: OsFamily) -> list[UserProfile]:
    """Children of /Users and /home, plus /root; /private/var/root is never reported."""
    users: list[UserProfile] = []
    users_root = EntryRef(volume, "/Users")
    if fs.is_dir(users_root):
        for child in fs.listdir(users_root):
            name = child.path.rsplit("/", 1)[-1]
            if name in SKIPPED_USER_DIRS or name.startswith(".") or not fs.is_dir(child):
                continue
            users.append(
                UserProfile(
                    name=name,
                    home=child.path,
                    volume=volume,
                    os_family=_user_os(fs, volume, child.path, os_family),
                )
            )
    home_root = EntryRef(volume, "/home")
    if fs.is_dir(home_root):
        for child in fs.listdir(home_root):
            name = child.path.rsplit("/", 1)[-1]
            if name.startswith(".") or not fs.is_dir(child):
                continue
            users.append(UserProfile(name=name, home=child.path, volume=volume, os_family=os_family))
    if fs.is_dir(EntryRef(volume, "/root")):
        users.append(UserProfile(name="root", home="/root", volume=volume, os_family=os_family))
    return users
