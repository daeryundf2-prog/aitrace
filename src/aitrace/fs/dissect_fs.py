from __future__ import annotations

import dataclasses
import logging
import posixpath
from typing import Any, BinaryIO, cast

from dissect.apfs.exception import Error as ApfsError
from dissect.ntfs.exceptions import Error as NtfsError
from dissect.regf import RegistryHive
from dissect.regf.exceptions import Error as RegfError
from dissect.regf.regf import KeyNode
from dissect.target import Target
from dissect.target.exceptions import Error as TargetError
from dissect.target.filesystem import Filesystem
from dissect.target.filesystems.apfs import ApfsFilesystem, ApfsVolumeFilesystem
from dissect.target.filesystems.ntfs import NtfsFilesystem, NtfsFilesystemEntry
from dissect.target.helpers.fsutil import TargetPath

from aitrace.core.ids import make_id
from aitrace.core.kinds import OsFamily
from aitrace.core.model import UserProfile, VolumeInfo
from aitrace.fs.base import EntryRef
from aitrace.fs.dir_fs import StatLike, TreeFS

log = logging.getLogger(__name__)

_SOFTWARE_HIVE = "/Windows/System32/config/SOFTWARE"
_PROFILE_LIST = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList"


def _volume_size(fs: Filesystem) -> int | None:
    size = getattr(fs.volume, "size", None)
    return size if isinstance(size, int) else None


def _volume_label(fs: Filesystem) -> str | None:
    if isinstance(fs, NtfsFilesystem):
        return fs.ntfs.volume_name
    if isinstance(fs, ApfsVolumeFilesystem):
        return getattr(fs.apfs, "name", None)
    name = getattr(fs.volume, "name", None)
    return name if isinstance(name, str) else None


def _collect_filesystems(target: Target) -> dict[int, Filesystem]:
    """APFS containers are replaced by their volume filesystems (the container root only lists volume
    names); filesystems of size 0 are skipped. Indexes follow `enumerate(target.filesystems)`."""
    found: list[Filesystem] = list(target.filesystems)
    for fs in list(found):
        if isinstance(fs, ApfsFilesystem):
            found.extend(sub for sub in fs.iter_subfs() if not any(sub is seen for seen in found))
    selected: dict[int, Filesystem] = {}
    for index, fs in enumerate(found):
        if isinstance(fs, ApfsFilesystem) or _volume_size(fs) == 0:
            continue
        selected[index] = fs
    return selected


class DissectFS(TreeFS):
    def __init__(
        self,
        path: str,
        evidence_id: str | None = None,
        *,
        kind: str = "raw",
        segments: tuple[str, ...] = (),
    ) -> None:
        self.path = path
        self.kind = kind
        self.segments = segments
        self.evidence_id = evidence_id or make_id("evidence", kind, path)
        self.target = Target.open(path)
        self._fs = _collect_filesystems(self.target)
        self._volumes: list[VolumeInfo] | None = None

    def _filesystem(self, volume: int) -> Filesystem:
        try:
            return self._fs[volume]
        except KeyError:
            raise FileNotFoundError(f"DissectFS has no volume {volume}") from None

    def _tp(self, volume: int, path: str) -> TargetPath:
        return self._filesystem(volume).path(path)

    def _volume_indexes(self) -> list[int]:
        return list(self._fs)

    def _exists(self, volume: int, path: str) -> bool:
        tp = self._tp(volume, path)
        return tp.exists() or tp.is_symlink()

    def _is_dir(self, volume: int, path: str) -> bool:
        return self._tp(volume, path).is_dir()

    def _is_symlink(self, volume: int, path: str) -> bool:
        return self._tp(volume, path).is_symlink()

    def _names(self, volume: int, path: str) -> list[str]:
        return [child.name for child in self._tp(volume, path).iterdir()]

    def _lstat(self, volume: int, path: str) -> StatLike:
        return self._tp(volume, path).lstat()

    def _open(self, volume: int, path: str) -> BinaryIO:
        return cast(BinaryIO, self._tp(volume, path).open("rb"))

    def _mft_seq(self, volume: int, path: str) -> int | None:
        if not isinstance(self._filesystem(volume), NtfsFilesystem):
            return None
        try:
            record = self._tp(volume, path).get().entry
            return int(record.header.SequenceNumber)
        except (AttributeError, OSError):
            return None

    def _streams(self, volume: int, path: str) -> list[str]:
        """Named $DATA attributes of the MFT record (NTFS only)."""
        if not isinstance(self._filesystem(volume), NtfsFilesystem):
            return []
        try:
            record = self._tp(volume, path).get().entry
            return sorted({attr.name for attr in record.attributes.DATA if attr.name})
        except (NtfsError, TargetError) as exc:
            raise OSError(f"cannot list streams of {path}: {exc!r}") from exc

    def _read_stream(self, volume: int, path: str, name: str) -> bytes:
        if not isinstance(self._filesystem(volume), NtfsFilesystem):
            raise FileNotFoundError(f"{path}:{name}")
        try:
            entry = cast(NtfsFilesystemEntry, self._tp(volume, path).get())
            with entry.open(name) as fh:
                return fh.read()
        except (NtfsError, TargetError) as exc:
            if isinstance(exc, FileNotFoundError):
                raise
            raise OSError(f"cannot read stream {path}:{name}: {exc!r}") from exc

    def _xattrs(self, volume: int, path: str) -> dict[str, bytes]:
        """APFS inode xattrs (symlinks not followed); {} for other filesystems."""
        if not isinstance(self._filesystem(volume), ApfsVolumeFilesystem):
            return {}
        try:
            inode = self._tp(volume, path).get().entry
            return {name: xattr.open().read() for name, xattr in inode.xattr.items()}
        except (ApfsError, TargetError) as exc:
            raise OSError(f"cannot read xattrs of {path}: {exc!r}") from exc

    def volumes(self) -> list[VolumeInfo]:
        if self._volumes is None:
            self._volumes = [
                VolumeInfo(
                    index=index,
                    fs_type=type(fs).__name__,
                    label=_volume_label(fs),
                    size=_volume_size(fs),
                    os_family=self.detect_os(index),
                )
                for index, fs in self._fs.items()
            ]
        return self._volumes

    def raw_ntfs(self, volume: int) -> Any | None:
        fs = self._filesystem(volume)
        return fs.ntfs if isinstance(fs, NtfsFilesystem) else None

    def users(self) -> list[UserProfile]:
        users = super().users()
        sid_maps: dict[int, dict[str, str]] = {}
        resolved: list[UserProfile] = []
        for user in users:
            if user.os_family is OsFamily.WINDOWS and self._find_ci(user.volume, user.home + "/NTUSER.DAT"):
                if user.volume not in sid_maps:
                    sid_maps[user.volume] = self._profile_sids(user.volume)
                sid = sid_maps[user.volume].get(user.name.casefold())
                user = dataclasses.replace(user, sid=sid)
            resolved.append(user)
        return resolved

    def _profile_sids(self, volume: int) -> dict[str, str]:
        hive_path = self._find_ci(volume, _SOFTWARE_HIVE)
        if hive_path is None:
            return {}
        sids: dict[str, str] = {}
        try:
            with self.open(EntryRef(volume, hive_path)) as fh:
                profile_list = RegistryHive(fh).open(_PROFILE_LIST)
                if not isinstance(profile_list, KeyNode):
                    return {}
                for key in profile_list.subkeys():
                    try:
                        image_path = key.value("ProfileImagePath").value
                    except RegfError:
                        continue
                    if isinstance(image_path, str):
                        folder = posixpath.basename(image_path.replace("\\", "/").rstrip("/"))
                        sids[folder.casefold()] = key.name
        except (RegfError, OSError, EOFError, ValueError) as exc:
            log.warning("SID lookup failed on volume %d (%s): %r", volume, hive_path, exc)
            return {}
        return sids
