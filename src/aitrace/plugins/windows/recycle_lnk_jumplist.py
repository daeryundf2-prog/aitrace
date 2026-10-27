from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import datetime
from io import BufferedReader, BytesIO
from typing import Any, cast

from dissect.cstruct.exceptions import Error as CstructError
from dissect.ole import OLE
from dissect.ole import Error as OleError
from dissect.shellitem.lnk import Lnk

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_filetime, from_iso, from_unix
from aitrace.fs.base import EntryRef, EvidenceFS, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

ROLE_RECYCLE = "recycle_i"
ROLE_LNK = "lnk"
ROLE_AUTO_JUMPLIST = "automatic_destinations"
ROLE_CUSTOM_JUMPLIST = "custom_destinations"

_USER_GLOBS: tuple[tuple[str, str], ...] = (
    (ROLE_LNK, "AppData/Roaming/Microsoft/Windows/Recent/*.lnk"),
    (ROLE_LNK, "Desktop/*.lnk"),
    (ROLE_AUTO_JUMPLIST, "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms"),
    (ROLE_CUSTOM_JUMPLIST, "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*.customDestinations-ms"),
)

_I_V1_MIN = 24 + 2
_I_V2_MIN = 28
_I_V1_PATH_BYTES = 520
_LNK_MAGIC = bytes.fromhex("4c000000" "0114020000000000c000000000000046")
_AUTO_SKIP_STREAMS = frozenset({"DestList"})

_PARSE_ERRORS = (
    OleError,
    CstructError,
    NotImplementedError,
    struct.error,
    EOFError,
    ValueError,
    KeyError,
    IndexError,
    OverflowError,
    AttributeError,
    TypeError,
)


def _iso(ts: datetime | None) -> str | None:
    return ts.isoformat().replace("+00:00", "Z") if ts is not None else None


def _text(raw: object) -> str:
    if isinstance(raw, bytes):
        return raw.decode("cp1252", errors="replace").rstrip("\x00")
    return str(raw).rstrip("\x00")


def _utf16(raw: bytes) -> str:
    text = raw.decode("utf-16-le", errors="replace")
    return text.split("\x00", 1)[0]


class RecycleError(ValueError):
    pass


def parse_recycle_i(data: bytes) -> tuple[int, int, int, str]:
    if len(data) < _I_V1_MIN:
        raise RecycleError(f"$I file too short: {len(data)} bytes")
    version, size, filetime = struct.unpack_from("<QQQ", data, 0)
    if version == 1:
        path = _utf16(data[24 : 24 + _I_V1_PATH_BYTES])
    elif version == 2:
        if len(data) < _I_V2_MIN:
            raise RecycleError(f"$I v2 file too short: {len(data)} bytes")
        (name_chars,) = struct.unpack_from("<I", data, 24)
        end = 28 + name_chars * 2
        if name_chars == 0 or end > len(data):
            raise RecycleError(f"$I v2 name length {name_chars} exceeds file size {len(data)}")
        path = _utf16(data[28:end])
    else:
        raise RecycleError(f"unsupported $I version {version}")
    return version, size, filetime, path


def _split_custom_jumplist(data: bytes) -> list[bytes]:
    offsets: list[int] = []
    start = data.find(_LNK_MAGIC)
    while start != -1:
        offsets.append(start)
        start = data.find(_LNK_MAGIC, start + 1)
    bounds = [*offsets[1:], len(data)][: len(offsets)]
    return [data[begin:end] for begin, end in zip(offsets, bounds, strict=True)]


def _lnk_target(lnk: Lnk) -> str | None:
    info = lnk.linkinfo.link_info
    if info is not None:
        suffix = _text(info.common_path_suffix) if info.common_path_suffix else ""
        if info.local_base_path:
            return _text(info.local_base_path) + suffix
        network = info.common_network_relative_link
        if network is not None and network.net_name:
            return _text(network.net_name) + ("\\" + suffix if suffix else "")
    strings = lnk.stringdata.string_data or {}
    relative = strings.get("relative_path")
    if relative is not None and relative.string:
        return _text(relative.string)
    return None


def _lnk_details(lnk: Lnk, os_family: OsFamily) -> dict[str, Any]:
    header = lnk.link_header
    if header is None:
        raise ValueError("LNK header missing")
    target = _lnk_target(lnk)
    extra: dict[str, Any] = {
        "target_created": _iso(from_filetime(header.creation_time)),
        "target_accessed": _iso(from_filetime(header.access_time)),
        "target_modified": _iso(from_filetime(header.write_time)),
        "target_size": header.filesize,
    }
    info = lnk.linkinfo.link_info
    if info is not None and info.volumeid is not None:
        extra["volume_serial"] = f"{info.volumeid.drive_serial_number:08X}"
        extra["drive_type"] = info.volumeid.drive_type
    tracker = lnk.extradata.extradata.get("TRACKER_PROPS")
    if tracker is not None:
        extra["machine_id"] = _text(tracker.machine_id)
    strings = lnk.stringdata.string_data or {}
    for key in ("working_dir", "command_line_arguments", "name_string"):
        value = strings.get(key)
        if value is not None and value.string:
            extra[key] = _text(value.string)
    data: dict[str, Any] = {"target_path": normalize(target, os_family) if target else "", "extra": extra}
    if target and normalize(target, os_family) != target:
        data["raw_path"] = target
    return data


class Plugin(PluginBase):
    name = "recycle_lnk_jumplist"
    version = "1.0"
    description = "Recycle Bin $I records, LNK shortcuts and JumpLists"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for volume in fs.volumes():
            for ref in fs.glob(volume.index, "/$Recycle.Bin/*/$I*"):
                sid = ref.path.split("/")[2]
                yield Candidate(ref=ref, role=ROLE_RECYCLE, extra={"sid": sid})
        for user in fs.users():
            if user.os_family != OsFamily.WINDOWS:
                continue
            for role, pattern in _USER_GLOBS:
                for ref in user_glob(fs, user, pattern):
                    yield Candidate(ref=ref, role=role, user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        if cand.role == ROLE_RECYCLE:
            yield from self._parse_recycle(ctx, cand)
        elif cand.role == ROLE_LNK:
            yield from self._parse_lnk_file(ctx, cand)
        elif cand.role == ROLE_AUTO_JUMPLIST:
            yield from self._parse_auto_jumplist(ctx, cand)
        elif cand.role == ROLE_CUSTOM_JUMPLIST:
            yield from self._parse_custom_jumplist(ctx, cand)
        else:
            yield self.warning(ctx, cand, f"unknown candidate role {cand.role!r}")

    def _read(self, ctx: ParseContext, cand: Candidate) -> bytes | Artifact:
        try:
            return ctx.fs.read_bytes(cand.ref)
        except OSError as exc:
            return self.warning(ctx, cand, f"cannot read file: {exc}")

    def _parse_recycle(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        raw = self._read(ctx, cand)
        if isinstance(raw, Artifact):
            yield raw
            return
        try:
            version, size, filetime, original = parse_recycle_i(raw)
        except RecycleError as exc:
            yield self.warning(ctx, cand, str(exc))
            return
        deleted = from_filetime(filetime)
        directory, _, name = cand.ref.path.rpartition("/")
        pair = EntryRef(cand.ref.volume, f"{directory}/$R{name[2:]}")
        data: dict[str, Any] = {
            "original_path": normalize(original, OsFamily.WINDOWS),
            "deleted_utc": _iso(deleted),
            "size": size,
            "extra": {
                "version": version,
                "sid": cand.extra.get("sid"),
                "r_file_present": ctx.fs.exists(pair),
                "r_file": pair.path,
            },
        }
        if data["original_path"] != original:
            data["raw_path"] = original
        artifact = self.artifact(ctx, cand, ArtifactKind.RECYCLED_FILE, data, locator="recycle")
        warnings: tuple[str, ...] = ()
        if deleted is None:
            warnings = (f"deletion FILETIME {filetime} outside the valid range",)
            artifact = Artifact(
                id=artifact.id, kind=artifact.kind, provenance=artifact.provenance, data=data, user=artifact.user,
                warnings=warnings,
            )
        yield artifact
        if deleted is not None:
            yield self.event(
                artifact,
                deleted,
                "deleted",
                EventCategory.FILE_DELETED,
                Actor.UNKNOWN,
                f"Recycled {data['original_path']}",
                subject=data["original_path"],
            )

    def _shortcut(
        self,
        ctx: ParseContext,
        cand: Candidate,
        lnk_bytes: bytes,
        *,
        source: str,
        locator: str,
        with_event: bool,
        stream_time: datetime | None = None,
    ) -> Iterator[Artifact | Event]:
        try:
            lnk = Lnk(cast(BufferedReader, cast(object, BytesIO(lnk_bytes))))
            if lnk.link_header is None:
                yield self.warning(ctx, cand, f"{locator}: not a valid LNK header")
                return
            data = _lnk_details(lnk, OsFamily.WINDOWS)
        except _PARSE_ERRORS as exc:
            yield self.warning(ctx, cand, f"{locator}: LNK parse failed: {exc}")
            return
        if not data["target_path"]:
            yield self.warning(ctx, cand, f"{locator}: LNK has no resolvable target path")
            return
        data["source"] = source
        artifact = self.artifact(ctx, cand, ArtifactKind.SHORTCUT, data, locator=locator)
        yield artifact
        if with_event:
            extra = data["extra"]
            fallback = from_iso(extra["target_accessed"]) or from_iso(extra["target_modified"])
            ts = stream_time or fallback
            yield self.event(
                artifact,
                ts,
                "accessed",
                EventCategory.FILE_ACCESSED,
                Actor.HUMAN,
                f"JumpList entry for {data['target_path']}",
                ts_basis="native_utc" if ts is not None else "unknown",
                subject=data["target_path"],
            )

    def _parse_lnk_file(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        raw = self._read(ctx, cand)
        if isinstance(raw, Artifact):
            yield raw
            return
        yield from self._shortcut(ctx, cand, raw, source="lnk", locator="lnk", with_event=False)

    def _parse_auto_jumplist(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        raw = self._read(ctx, cand)
        if isinstance(raw, Artifact):
            yield raw
            return
        try:
            ole = OLE(BytesIO(raw))
            entries = sorted(ole.root.listdir().items())
        except _PARSE_ERRORS as exc:
            yield self.warning(ctx, cand, f"OLE parse failed: {exc}")
            return
        for name, entry in entries:
            if name in _AUTO_SKIP_STREAMS or not entry.is_stream:
                continue
            try:
                stream = entry.open().read()
            except _PARSE_ERRORS as exc:
                yield self.warning(ctx, cand, f"stream {name}: read failed: {exc}")
                continue
            yield from self._shortcut(
                ctx, cand, stream, source="jumplist", locator=f"stream:{name}", with_event=True,
                stream_time=_valid_time(entry.mtime),
            )

    def _parse_custom_jumplist(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        raw = self._read(ctx, cand)
        if isinstance(raw, Artifact):
            yield raw
            return
        segments = _split_custom_jumplist(raw)
        if not segments:
            yield self.warning(ctx, cand, "no LNK records found in customDestinations file")
            return
        for index, segment in enumerate(segments):
            yield from self._shortcut(
                ctx, cand, segment, source="jumplist", locator=f"lnk:{index}", with_event=True
            )


def _valid_time(ts: datetime | None) -> datetime | None:
    if ts is None:
        return None
    return from_unix(ts.timestamp())


PLUGIN = Plugin()
