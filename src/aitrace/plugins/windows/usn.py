from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, BinaryIO

from dissect.ntfs.exceptions import Error as NtfsError

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_filetime
from aitrace.fs.base import EntryRef
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

USN_PATH = "/$Extend/$UsnJrnl:$J"
USN_PAGE_SIZE = 4096
_MIN_RECORD = 60
_MAX_RECORD = 0x10000
_HEADER = struct.Struct("<IHH")  # RecordLength, MajorVersion, MinorVersion
# FileReferenceNumber, ParentFileReferenceNumber, Usn, TimeStamp, Reason, SourceInfo, SecurityId, FileAttributes,
# FileNameLength, FileNameOffset (follows the 8-byte common header)
_BODY = struct.Struct("<QQqQIIIIHH")

USN_REASONS: tuple[tuple[int, str], ...] = (
    (0x00000001, "DATA_OVERWRITE"),
    (0x00000002, "DATA_EXTEND"),
    (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"),
    (0x00000020, "NAMED_DATA_EXTEND"),
    (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"),
    (0x00000200, "FILE_DELETE"),
    (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"),
    (0x00001000, "RENAME_OLD_NAME"),
    (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"),
    (0x00008000, "BASIC_INFO_CHANGE"),
    (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"),
    (0x00040000, "ENCRYPTION_CHANGE"),
    (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"),
    (0x00200000, "STREAM_CHANGE"),
    (0x00400000, "TRANSACTED_CHANGE"),
    (0x00800000, "INTEGRITY_CHANGE"),
    (0x80000000, "CLOSE"),
)
_DATA_REASONS = frozenset(
    {"DATA_OVERWRITE", "DATA_EXTEND", "DATA_TRUNCATION", "NAMED_DATA_OVERWRITE", "NAMED_DATA_EXTEND", "NAMED_DATA_TRUNCATION"}
)


@dataclass(frozen=True, slots=True)
class UsnRecord:
    offset: int
    usn: int
    filename: str
    file_ref: int
    parent_ref: int
    reason_flags: int
    reasons: tuple[str, ...]
    timestamp_filetime: int
    file_attributes: int


def decode_reasons(flags: int) -> tuple[str, ...]:
    names = [name for bit, name in USN_REASONS if flags & bit]
    unknown = flags & ~sum(bit for bit, _ in USN_REASONS)
    if unknown:
        names.append(f"UNKNOWN_0x{unknown:08x}")
    return tuple(names)


def category_for(reasons: tuple[str, ...]) -> EventCategory:
    if "FILE_CREATE" in reasons:
        return EventCategory.FILE_CREATED
    if "FILE_DELETE" in reasons:
        return EventCategory.FILE_DELETED
    if "RENAME_NEW_NAME" in reasons:
        return EventCategory.FILE_RENAMED
    if _DATA_REASONS.intersection(reasons):
        return EventCategory.FILE_MODIFIED
    return EventCategory.OTHER


def _ref_str(ref: int) -> str:
    # low 48 bits: MFT entry number, high 16 bits: sequence number
    return f"{ref & 0xFFFFFFFFFFFF}-{ref >> 48}"


def parse_usn_stream(fileobj: BinaryIO, errors: list[str] | None = None) -> Iterator[UsnRecord]:
    """Yield USN_RECORD_V2 records from a ``$UsnJrnl:$J`` stream, skipping sparse zero pages.

    Malformed records are skipped (resynchronising at the next page); a description of each is
    appended to ``errors`` when given. Non-V2 records are skipped silently.
    """
    offset = 0
    while True:
        fileobj.seek(offset)
        head = fileobj.read(_HEADER.size)
        if len(head) < _HEADER.size:
            return
        length, major, _minor = _HEADER.unpack(head)
        if length == 0:
            offset += USN_PAGE_SIZE - (offset % USN_PAGE_SIZE)
            continue
        if length < _MIN_RECORD or length > _MAX_RECORD or length % 8 or major not in (2, 3, 4):
            if errors is not None:
                errors.append(f"invalid USN record header at offset {offset} (length={length}, version={major})")
            offset += USN_PAGE_SIZE - (offset % USN_PAGE_SIZE)
            continue
        if major == 2:
            body = fileobj.read(length - _HEADER.size)
            if len(body) < length - _HEADER.size:
                if errors is not None:
                    errors.append(f"truncated USN record at offset {offset}")
                return
            (file_ref, parent_ref, usn, ts, reason, _src, _sec, attrs, name_len, name_off) = _BODY.unpack_from(body)
            start = name_off - _HEADER.size
            raw_name = body[start : start + name_len]
            if start < _BODY.size or len(raw_name) != name_len or name_len % 2:
                if errors is not None:
                    errors.append(f"invalid USN filename bounds at offset {offset}")
            else:
                yield UsnRecord(
                    offset=offset,
                    usn=usn,
                    filename=raw_name.decode("utf-16-le", errors="replace"),
                    file_ref=file_ref,
                    parent_ref=parent_ref,
                    reason_flags=reason,
                    reasons=decode_reasons(reason),
                    timestamp_filetime=ts,
                    file_attributes=attrs,
                )
        offset += length


class Plugin(PluginBase):
    name = "usn"
    version = "1.0"
    description = "NTFS USN change journal ($Extend/$UsnJrnl:$J): file create, delete, rename, modify records"

    def locate(self, fs: Any) -> Iterator[Candidate]:
        for volume in fs.volumes():
            ref = EntryRef(volume.index, USN_PATH)
            if fs.exists(ref) or _raw_usn_stream(fs, volume.index) is not None:
                yield Candidate(ref=ref, role="usn")

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        stream = ctx.fs.open(cand.ref) if ctx.fs.exists(cand.ref) else _raw_usn_stream(ctx.fs, cand.ref.volume)
        if stream is None:
            yield self.warning(ctx, cand, "USN journal stream is not readable")
            return
        errors: list[str] = []
        mft = _MftDirs(getattr(ctx.fs.raw_ntfs(cand.ref.volume), "mft", None))
        try:
            for rec in parse_usn_stream(stream, errors):
                yield from self._record(ctx, cand, rec, mft)
        finally:
            stream.close()
        for message in errors:
            yield self.warning(ctx, cand, message)

    def _record(self, ctx: ParseContext, cand: Candidate, rec: UsnRecord, mft: _MftDirs) -> Iterator[Artifact | Event]:
        ts = from_filetime(rec.timestamp_filetime)
        parent_segment = rec.parent_ref & 0xFFFFFFFFFFFF
        parent_dir = mft.directory(parent_segment)
        if parent_dir is None:
            path = f"/$UNRESOLVED/{parent_segment}/{rec.filename}"
        else:
            path = normalize(f"{parent_dir}/{rec.filename}", OsFamily.WINDOWS)
        data: dict[str, Any] = {
            "source": "usn",
            "path": path,
            "reasons": list(rec.reasons),
            "extra": {
                "usn": rec.usn,
                "filename": rec.filename,
                "path_resolved": parent_dir is not None,
                "file_ref": _ref_str(rec.file_ref),
                "parent_ref": _ref_str(rec.parent_ref),
                "file_attributes": rec.file_attributes,
                "timestamp_filetime": rec.timestamp_filetime,
            },
        }
        artifact = self.artifact(ctx, cand, ArtifactKind.FILE_JOURNAL, data, locator=f"usn:{rec.usn}")
        yield artifact
        category = category_for(rec.reasons)
        yield self.event(
            artifact,
            ts,
            "usn_timestamp",
            category,
            Actor.UNKNOWN,
            f"USN {','.join(rec.reasons) or 'NONE'}: {rec.filename}",
            ts_basis="native_utc" if ts is not None else "unknown",
            subject=rec.filename,
            data={"usn": rec.usn},
        )


class _MftDirs:
    """Cached MFT segment number -> directory path lookup (``mft.get(segment).full_path()``)."""

    def __init__(self, mft: Any | None) -> None:
        self._mft = mft
        self._cache: dict[int, str | None] = {}

    def directory(self, segment: int) -> str | None:
        if self._mft is None:
            return None
        if segment not in self._cache:
            try:
                self._cache[segment] = self._mft.get(segment).full_path(ignore_dos=True)
            except (NtfsError, ValueError, OSError, EOFError):
                self._cache[segment] = None
        return self._cache[segment]


def _raw_usn_stream(fs: Any, volume: int) -> BinaryIO | None:
    ntfs = fs.raw_ntfs(volume)
    jrnl = getattr(ntfs, "usnjrnl", None) if ntfs is not None else None
    return getattr(jrnl, "fh", None) if jrnl is not None else None


PLUGIN = Plugin()
