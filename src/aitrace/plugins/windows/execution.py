from __future__ import annotations

import math
import re
import struct
from collections.abc import Iterable, Iterator
from datetime import datetime
from typing import Any, cast

from dissect.cstruct.exceptions import Error as CstructError
from dissect.database.ese.ese import ESE
from dissect.database.exception import Error as DatabaseError
from dissect.regf import regf
from dissect.regf.exceptions import Error as RegfError
from dissect.regf.exceptions import RegistryKeyNotFoundError
from dissect.target.plugins.os.windows.prefetch import Prefetch

from aitrace.core.catalog import match_ai_program
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import basename, normalize
from aitrace.core.time import from_filetime, from_unix
from aitrace.fs.base import EvidenceFS
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

ROLE_PREFETCH = "prefetch"
ROLE_AMCACHE = "amcache"
ROLE_SRUM = "srum"

PREFETCH_GLOB = "/Windows/Prefetch/*.pf"
AMCACHE_PATH = "/Windows/AppCompat/Programs/Amcache.hve"
SRUM_PATH = "/Windows/System32/sru/SRUDB.dat"
AMCACHE_KEY = "Root\\InventoryApplicationFile"

SRUM_APP_TABLE = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
SRUM_NETWORK_TABLE = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
SRUM_ID_MAP_TABLE = "SruDbIdMapTable"
_SRUM_TEXT_ID_TYPES = frozenset({0, 1, 2})

_OLE_UNIX_DAYS = 25569.0
_DEVICE_PREFIX_RE = re.compile(r"^[\\/]device[\\/]harddiskvolume\d+", re.IGNORECASE)

_PARSE_ERRORS = (
    CstructError,
    DatabaseError,
    RegfError,
    NotImplementedError,
    struct.error,
    EOFError,
    ValueError,
    KeyError,
    IndexError,
    OverflowError,
    AttributeError,
    TypeError,
    OSError,
)


def _iso(ts: datetime | None) -> str | None:
    return ts.isoformat().replace("+00:00", "Z") if ts is not None else None


def srum_time(value: object) -> datetime | None:
    """SRUM `TimeStamp` -> UTC.

    SRUM stores an OLE Automation date (days since 1899-12-30, a double). A float is that
    value; an int is the raw IEEE-754 bit pattern of the double as ESE hands it back; a
    datetime passes through unchanged.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, int):
        (days,) = struct.unpack("<d", struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))
    elif isinstance(value, float):
        days = value
    else:
        return None
    if math.isnan(days):
        return None
    return from_unix((days - _OLE_UNIX_DAYS) * 86400)


def _app_identity(app_id: object, id_map: dict[int, str]) -> tuple[str, str | None, str] | None:
    if not isinstance(app_id, int):
        return None
    raw = id_map.get(app_id)
    if not raw:
        return None
    if "\\" in raw or "/" in raw:
        path = normalize(_DEVICE_PREFIX_RE.sub("", raw), OsFamily.WINDOWS)
        return basename(path), path, raw
    return raw, None, raw


def srum_app_rows(rows: Iterable[dict[str, Any]], id_map: dict[int, str]) -> list[dict[str, Any]]:
    """Application Resource Usage rows -> `{program, path, raw_app, ts, row_id}`; unresolved AppIds are dropped."""
    out: list[dict[str, Any]] = []
    for row in rows:
        identity = _app_identity(row.get("AppId"), id_map)
        if identity is None:
            continue
        program, path, raw = identity
        out.append(
            {"program": program, "path": path, "raw_app": raw, "ts": srum_time(row.get("TimeStamp")),
             "row_id": row.get("AutoIncId")}
        )
    return out


def srum_network_rows(rows: Iterable[dict[str, Any]], id_map: dict[int, str]) -> list[dict[str, Any]]:
    """Network Data Usage rows -> `{program, path, raw_app, ts, row_id, bytes_sent, bytes_received}`."""
    out: list[dict[str, Any]] = []
    for row in rows:
        identity = _app_identity(row.get("AppId"), id_map)
        if identity is None:
            continue
        program, path, raw = identity
        out.append(
            {
                "program": program,
                "path": path,
                "raw_app": raw,
                "ts": srum_time(row.get("TimeStamp")),
                "row_id": row.get("AutoIncId"),
                "bytes_sent": int(cast(Any, row.get("BytesSent")) or 0),
                "bytes_received": int(cast(Any, row.get("BytesRecvd")) or 0),
            }
        )
    return out


def _with_ai_tool(data: dict[str, Any], program: str) -> dict[str, Any]:
    tool = match_ai_program(program)
    if tool is not None:
        data["ai_tool"] = tool
    return data


class Plugin(PluginBase):
    name = "windows.execution"
    version = "1.0"
    description = "Prefetch, Amcache and SRUM program-execution evidence"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for volume in fs.volumes():
            for ref in fs.glob(volume.index, PREFETCH_GLOB):
                yield Candidate(ref=ref, role=ROLE_PREFETCH)
            for ref in fs.glob(volume.index, AMCACHE_PATH):
                yield Candidate(ref=ref, role=ROLE_AMCACHE)
            for ref in fs.glob(volume.index, SRUM_PATH):
                yield Candidate(ref=ref, role=ROLE_SRUM)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        if cand.role == ROLE_PREFETCH:
            yield from self._parse_prefetch(ctx, cand)
        elif cand.role == ROLE_AMCACHE:
            yield from self._parse_amcache(ctx, cand)
        elif cand.role == ROLE_SRUM:
            yield from self._parse_srum(ctx, cand)
        else:
            yield self.warning(ctx, cand, f"unknown candidate role {cand.role!r}")

    def _parse_prefetch(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            with ctx.fs.open(cand.ref) as fh:
                pf = Prefetch(fh)
                exe = pf.header.name.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
                if not exe:
                    raise ValueError("empty executable name")
                info = cast(Any, pf.fn)
                run_count = int(info.run_count)
                raw_times = [info.last_run_time, *getattr(info, "last_run_remains", [])]
                referenced = list(pf.metrics or [])
                version = int(pf.version)
                pf_hash = int(pf.header.hash)
        except _PARSE_ERRORS as exc:
            yield self.warning(ctx, cand, f"prefetch parse failed: {exc}")
            return
        times = [t for t in (from_filetime(int(raw)) for raw in raw_times if raw) if t is not None]
        files = [normalize(name, OsFamily.WINDOWS) for name in referenced if name]
        exe_path = next((f for f in files if basename(f).casefold() == exe.casefold()), None)
        data: dict[str, Any] = {
            "program": exe,
            "path": exe_path,
            "source": "prefetch",
            "run_count": run_count,
            "extra": {
                "version": version,
                "prefetch_hash": f"{pf_hash:08X}",
                "run_times": [_iso(t) for t in times],
                "referenced_files": files,
            },
        }
        artifact = self.artifact(ctx, cand, ArtifactKind.EXECUTION, _with_ai_tool(data, exe), locator="prefetch")
        yield artifact
        for index, ts in enumerate(times):
            yield self.event(
                artifact,
                ts,
                "last_run" if index == 0 else "previous_run",
                EventCategory.EXECUTION,
                Actor.UNKNOWN,
                f"Prefetch: {exe} executed",
                subject=exe_path or exe,
                index=index,
            )

    def _parse_amcache(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            with ctx.fs.open(cand.ref) as fh:
                hive = regf.RegistryHive(fh)
                try:
                    key = hive.open(AMCACHE_KEY)
                except RegistryKeyNotFoundError:
                    yield self.warning(ctx, cand, f"{AMCACHE_KEY} not found in Amcache hive")
                    return
                root = cast(Any, key)
                entries = [(sub.name, sub.timestamp, {v.name: v.value for v in sub.values()}) for sub in root.subkeys()]
        except _PARSE_ERRORS as exc:
            yield self.warning(ctx, cand, f"amcache parse failed: {exc}")
            return
        for sub_name, key_ts, values in entries:
            raw_path = values.get("LowerCaseLongPath")
            name = values.get("Name")
            program = str(name) if name else (basename(str(raw_path)) if raw_path else "")
            if not program:
                yield self.warning(ctx, cand, f"amcache entry {sub_name!r} has neither Name nor LowerCaseLongPath")
                continue
            path = normalize(str(raw_path), OsFamily.WINDOWS) if raw_path else None
            data: dict[str, Any] = {
                "program": program,
                "path": path,
                "source": "amcache",
                "extra": {
                    "product_name": values.get("ProductName"),
                    "link_date": values.get("LinkDate"),
                    "file_id": values.get("FileId"),
                    "publisher": values.get("Publisher"),
                    "key_last_write": _iso(key_ts),
                },
            }
            if path is not None and path != raw_path:
                data["raw_path"] = raw_path
            artifact = self.artifact(
                ctx, cand, ArtifactKind.EXECUTION, _with_ai_tool(data, program), locator=f"key:{sub_name}"
            )
            yield artifact
            yield self.event(
                artifact,
                key_ts,
                "amcache_key_write",
                EventCategory.EXECUTION,
                Actor.UNKNOWN,
                f"Amcache: {program} recorded",
                subject=path or program,
            )

    def _parse_srum(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            with ctx.fs.open(cand.ref) as fh:
                db = ESE(fh)
                id_map = _srum_id_map(db)
                app_rows = _table_rows(db, SRUM_APP_TABLE, ("AutoIncId", "TimeStamp", "AppId"))
                net_rows = _table_rows(db, SRUM_NETWORK_TABLE, ("AutoIncId", "TimeStamp", "AppId", "BytesSent", "BytesRecvd"))
        except _PARSE_ERRORS as exc:
            yield self.warning(ctx, cand, f"SRUM parse failed: {exc}")
            return
        if app_rows is None:
            ctx.log.debug("%s: %s: application usage table %s absent", self.name, cand.ref.path, SRUM_APP_TABLE)
        else:
            for row in srum_app_rows(app_rows, id_map):
                data: dict[str, Any] = {"program": row["program"], "path": row["path"], "source": "srum"}
                if row["path"] is not None and row["raw_app"] != row["path"]:
                    data["raw_path"] = row["raw_app"]
                artifact = self.artifact(
                    ctx, cand, ArtifactKind.EXECUTION, _with_ai_tool(data, row["program"]),
                    locator=f"row:{SRUM_APP_TABLE}.AutoIncId={row['row_id']}",
                )
                yield artifact
                yield self.event(
                    artifact, row["ts"], "srum_interval", EventCategory.EXECUTION, Actor.UNKNOWN,
                    f"SRUM: {row['program']} resource usage", ts_basis="native_utc" if row["ts"] else "unknown",
                    subject=row["path"] or row["program"],
                )
        if net_rows is None:
            ctx.log.debug("%s: %s: network usage table %s absent", self.name, cand.ref.path, SRUM_NETWORK_TABLE)
            return
        for row in srum_network_rows(net_rows, id_map):
            data = {"program": row["program"], "bytes_sent": row["bytes_sent"], "bytes_received": row["bytes_received"]}
            artifact = self.artifact(
                ctx, cand, ArtifactKind.NETWORK_USAGE, _with_ai_tool(data, row["program"]),
                locator=f"row:{SRUM_NETWORK_TABLE}.AutoIncId={row['row_id']}",
            )
            yield artifact
            yield self.event(
                artifact, row["ts"], "srum_interval", EventCategory.OTHER, Actor.UNKNOWN,
                f"SRUM: {row['program']} sent {row['bytes_sent']} / received {row['bytes_received']} bytes",
                ts_basis="native_utc" if row["ts"] else "unknown", subject=row["path"] or row["program"],
            )


def _srum_id_map(db: ESE) -> dict[int, str]:
    id_map: dict[int, str] = {}
    for record in db.table(SRUM_ID_MAP_TABLE).records():
        blob = cast(Any, record.get("IdBlob"))
        index = cast(Any, record.get("IdIndex"))
        if index is None or not blob or record.get("IdType") not in _SRUM_TEXT_ID_TYPES:
            continue
        id_map[int(index)] = bytes(blob).decode("utf-16-le", errors="replace").rstrip("\x00")
    return id_map


def _table_rows(db: ESE, guid: str, columns: tuple[str, ...]) -> list[dict[str, Any]] | None:
    try:
        table = db.table(guid)
    except KeyError:
        return None
    return [{column: record.get(column) for column in columns} for record in table.records()]


PLUGIN = Plugin()
