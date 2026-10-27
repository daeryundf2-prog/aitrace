from __future__ import annotations

import dataclasses
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any, BinaryIO

from dissect.ntfs.attr import FileName, StandardInformation
from dissect.ntfs.exceptions import BrokenMftError
from dissect.ntfs.exceptions import Error as NtfsError
from dissect.ntfs.mft import MftRecord
from dissect.ntfs.util import segment_reference

from aitrace.core.catalog import INTERESTING_NAME_PATTERNS, LIMITATIONS
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event, format_utc
from aitrace.core.paths import normalize
from aitrace.fs.base import EntryRef, EvidenceFS
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

RECORD_SIZE = 1024
ROOT_ENTRY = 5
MIN_SYSTEM_RECORDS = 16  # entries 0-15 are reserved NTFS metadata files; any real $MFT has them
ORPHAN_PREFIX = "/$OrphanFiles"
TS_DELETED = "last_modified_before_delete"

_FLAG_IN_USE = 0x0001
_NAMESPACE_RANK = {1: 0, 3: 0, 0: 1, 2: 2}  # Win32 / Win32+DOS, then POSIX, then DOS-only
_UNDER_PREFIXES = ("/users/", "/programdata/")
_RECORD_ERRORS = (NtfsError, EOFError, ValueError, struct.error)
_TIME_ERRORS = (OverflowError, ValueError, OSError)


@dataclass(frozen=True, slots=True)
class MftRow:
    entry: int
    seq: int
    path: str
    name: str
    parent_entry: int
    resolved: bool
    in_use: bool
    is_dir: bool
    size: int
    si_btime: datetime | None
    si_mtime: datetime | None
    si_atime: datetime | None
    si_ctime: datetime | None
    fn_btime: datetime | None
    fn_mtime: datetime | None
    fn_atime: datetime | None
    fn_ctime: datetime | None
    namespace: int
    offset: int


@dataclass(frozen=True, slots=True)
class MftScan:
    rows: list[MftRow]
    warnings: list[str]
    records_seen: int


def _ts(value: Any) -> datetime | None:
    try:
        ts = value()
    except _TIME_ERRORS:
        return None
    return ts if isinstance(ts, datetime) and ts.tzinfo is not None else None


def _iso(ts: datetime | None) -> str | None:
    return format_utc(ts) if ts is not None else None


def _preferred_name(names: list[FileName]) -> FileName | None:
    if not names:
        return None
    return min(names, key=lambda fn: _NAMESPACE_RANK.get(fn.flags, 3))


def _first_si(record: MftRecord) -> StandardInformation | None:
    items = record.attributes.STANDARD_INFORMATION
    return items[0] if items else None


def _data_size(record: MftRecord, fn: FileName) -> int:
    try:
        return int(record.size())
    except NtfsError:
        return int(fn.file_size)


@dataclass(slots=True)
class _Rec:
    entry: int
    seq: int
    in_use: bool
    is_dir: bool
    fn: FileName
    si: StandardInformation | None
    size: int
    offset: int


def _read_record(fh: BinaryIO, index: int) -> _Rec | None:
    """Return the usable record at `index`, or None for unused slots, extension records and no-name records."""
    offset = index * RECORD_SIZE
    fh.seek(offset)
    signature = fh.read(4)
    if signature != b"FILE":
        if signature.strip(b"\x00") == b"":
            return None
        raise BrokenMftError(f"record {index} has invalid signature {signature!r}")
    record = MftRecord.from_fh(fh, offset)
    header = record.header
    if header is None:
        raise BrokenMftError(f"record {index} has no header")
    if header.BaseFileRecordSegment.SegmentNumberLowPart != 0:
        return None
    fn = _preferred_name(list(record.attributes.FILE_NAME))
    if fn is None or index == ROOT_ENTRY:
        return None
    return _Rec(
        entry=index,
        seq=int(header.SequenceNumber),
        in_use=bool(header.Flags & _FLAG_IN_USE),
        is_dir=bool(record.is_dir()),
        fn=fn,
        si=_first_si(record),
        size=0 if record.is_dir() else _data_size(record, fn),
        offset=offset,
    )


def _build_path(rec: _Rec, recs: dict[int, _Rec]) -> tuple[str, bool]:
    parts = [rec.fn.file_name]
    seen = {rec.entry}
    parent = segment_reference(rec.fn.attr.ParentDirectory)
    while parent != ROOT_ENTRY:
        node = recs.get(parent)
        if node is None or parent in seen:
            return ORPHAN_PREFIX + "/" + "/".join(reversed(parts)), False
        seen.add(parent)
        parts.append(node.fn.file_name)
        parent = segment_reference(node.fn.attr.ParentDirectory)
    return "/" + "/".join(reversed(parts)), True


def _wanted(path: str, name: str, in_use: bool) -> bool:
    if not in_use or path.lower().startswith(_UNDER_PREFIXES):
        return True
    return any(p.search(name) for p in INTERESTING_NAME_PATTERNS)


def parse_mft_stream(fileobj: BinaryIO, volume: int, *, apply_filter: bool = True) -> MftScan:
    """Parse a raw $MFT stream into FILE_RECORD rows; failures become warnings, never exceptions.

    `volume` is only used in warning text. With `apply_filter` (the plugin default) rows are limited to
    /Users, /ProgramData, deleted records and interesting names; pass False to get every named record.
    """
    fileobj.seek(0, 2)
    total = fileobj.tell()
    count, trailing = divmod(total, RECORD_SIZE)
    warnings: list[str] = []
    if count < MIN_SYSTEM_RECORDS or trailing:
        warnings.append(
            f"volume {volume}: $MFT stream truncated ({total} bytes, {count} complete records"
            f"{f', {trailing} trailing bytes' if trailing else ''}); results are incomplete"
        )
    recs: dict[int, _Rec] = {}
    bad = 0
    for index in range(count):
        try:
            rec = _read_record(fileobj, index)
        except _RECORD_ERRORS:
            bad += 1
            continue
        if rec is not None:
            recs[index] = rec
    if bad:
        warnings.append(f"volume {volume}: skipped {bad} unparsable MFT record(s)")

    rows: list[MftRow] = []
    for rec in recs.values():
        path, resolved = _build_path(rec, recs)
        name = rec.fn.file_name
        if apply_filter and not _wanted(path, name, rec.in_use):
            continue
        si = rec.si
        rows.append(
            MftRow(
                entry=rec.entry,
                seq=rec.seq,
                path=normalize(path, OsFamily.WINDOWS),
                name=name,
                parent_entry=segment_reference(rec.fn.attr.ParentDirectory),
                resolved=resolved,
                in_use=rec.in_use,
                is_dir=rec.is_dir,
                size=rec.size,
                si_btime=_ts(lambda si=si: si.creation_time) if si else None,
                si_mtime=_ts(lambda si=si: si.last_modification_time) if si else None,
                si_atime=_ts(lambda si=si: si.last_access_time) if si else None,
                si_ctime=_ts(lambda si=si: si.last_change_time) if si else None,
                fn_btime=_ts(lambda fn=rec.fn: fn.creation_time),
                fn_mtime=_ts(lambda fn=rec.fn: fn.last_modification_time),
                fn_atime=_ts(lambda fn=rec.fn: fn.last_access_time),
                fn_ctime=_ts(lambda fn=rec.fn: fn.last_change_time),
                namespace=int(rec.fn.flags),
                offset=rec.offset,
            )
        )
    return MftScan(rows=rows, warnings=warnings, records_seen=count)


class Plugin(PluginBase):
    name = "mft"
    version = "1.0"
    description = "NTFS $MFT file records, including deleted (not in use) records"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for vol in fs.volumes():
            if fs.raw_ntfs(vol.index) is not None:
                yield Candidate(ref=EntryRef(vol.index, "/$MFT"), role="mft")

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        ntfs = ctx.fs.raw_ntfs(cand.ref.volume)
        if ntfs is None:
            yield self.warning(ctx, cand, "raw NTFS access unavailable for this volume")
            return
        try:
            stream = ntfs.mft.get(0).open()
            scan = parse_mft_stream(stream, cand.ref.volume)
        except (*_RECORD_ERRORS, OSError, AttributeError) as exc:
            yield self.warning(ctx, cand, f"cannot read $MFT: {type(exc).__name__}: {exc}")
            return
        for message in scan.warnings:
            yield self.warning(ctx, cand, message)
        for row in scan.rows:
            yield from self._emit(ctx, cand, row)

    def _emit(self, ctx: ParseContext, cand: Candidate, row: MftRow) -> Iterator[Artifact | Event]:
        data: dict[str, Any] = {
            "path": row.path,
            "size": row.size,
            "is_dir": row.is_dir,
            "in_use": row.in_use,
            "btime": _iso(row.si_btime),
            "mtime": _iso(row.si_mtime),
            "atime": _iso(row.si_atime),
            "ctime": _iso(row.si_ctime),
            "source": "mft",
            "extra": {
                "mft_entry": row.entry,
                "mft_seq": row.seq,
                "parent_entry": row.parent_entry,
                "path_resolved": row.resolved,
                "name_namespace": row.namespace,
                "fn_btime": _iso(row.fn_btime),
                "fn_mtime": _iso(row.fn_mtime),
                "fn_atime": _iso(row.fn_atime),
                "fn_ctime": _iso(row.fn_ctime),
            },
        }
        art = self.artifact(
            ctx, cand, ArtifactKind.FILE_RECORD, data, locator=f"mft:{row.entry}", deleted=not row.in_use
        )
        art = dataclasses.replace(
            art,
            provenance=dataclasses.replace(
                art.provenance, inode=row.entry, mft_seq=row.seq, byte_offset=row.offset
            ),
        )
        yield art
        base = {"path": row.path, "mft_entry": row.entry, "in_use": row.in_use}
        if row.si_btime is not None:
            yield self.event(
                art,
                row.si_btime,
                "si_created",
                EventCategory.FILE_CREATED,
                Actor.UNKNOWN,
                f"File created: {row.path}",
                subject=row.path,
                data=dict(base),
            )
        if row.si_mtime is not None:
            yield self.event(
                art,
                row.si_mtime,
                "si_modified",
                EventCategory.FILE_MODIFIED,
                Actor.UNKNOWN,
                f"File modified: {row.path}",
                subject=row.path,
                data=dict(base),
            )
            if not row.in_use:
                limitation = LIMITATIONS["DELETED_TIME"]
                note = limitation["en"] if isinstance(limitation, dict) else str(limitation)
                yield self.event(
                    art,
                    row.si_mtime,
                    TS_DELETED,
                    EventCategory.FILE_DELETED,
                    Actor.UNKNOWN,
                    f"File deleted (time unknown; last modified shown): {row.path}",
                    subject=row.path,
                    data={**base, "deleted": True, "limitation": note},
                )


PLUGIN = Plugin()
