"""macOS activity sources: quarantine downloads, knowledgeC app usage, TCC grants and FSEvents journals.

AI relevance comes from `catalog.AI_PROGRAMS` (bundle ids and CLI names) and `catalog.match_ai_domain`
(download URLs). knowledgeC and TCC rows for programs outside the AI catalog are not emitted.
Malformed stores and FSEvents pages produce PARSE_WARNING artifacts instead of raising.
"""

from __future__ import annotations

import gzip
import plistlib
import sqlite3
import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from xml.parsers.expat import ExpatError

from aitrace.core.catalog import match_ai_domain, match_ai_program
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event, format_utc
from aitrace.core.paths import basename, normalize
from aitrace.core.time import from_cocoa, from_unix
from aitrace.fs.base import EvidenceFS, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase
from aitrace.plugins.common.sqlite import open_sqlite

_ROLE_QUARANTINE = "quarantine"
_ROLE_KNOWLEDGEC = "knowledgec"
_ROLE_TCC = "tcc"
_ROLE_FSEVENTS = "fsevents"

_SYSTEM_SOURCES: tuple[tuple[str, str], ...] = (
    ("/private/var/db/CoreDuet/Knowledge/knowledgeC.db", _ROLE_KNOWLEDGEC),
    ("/Library/Application Support/com.apple.TCC/TCC.db", _ROLE_TCC),
    ("/.fseventsd/*", _ROLE_FSEVENTS),
)
_USER_SOURCES: tuple[tuple[str, str], ...] = (
    ("Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2", _ROLE_QUARANTINE),
    ("Library/Application Support/Knowledge/knowledgeC.db", _ROLE_KNOWLEDGEC),
    ("Library/Application Support/com.apple.TCC/TCC.db", _ROLE_TCC),
)

_SQLITE_MAGIC = b"SQLite format 3\x00"
_KNOWLEDGE_SQL = """
SELECT rowid AS pk, ZSTREAMNAME AS stream, ZVALUESTRING AS bundle, ZSTARTDATE AS start, ZENDDATE AS end
FROM ZOBJECT
WHERE ZSTREAMNAME IN ('/app/usage', '/app/inFocus') AND ZVALUESTRING IS NOT NULL
ORDER BY ZSTARTDATE, rowid
"""
_TCC_SQL = "SELECT rowid AS pk, service, client, auth_value, last_modified FROM access ORDER BY rowid"

_FSEVENTS_VERSIONS: dict[bytes, int] = {b"1SLD": 1, b"2SLD": 2, b"3SLD": 3}
_FLAG_NAMES: tuple[tuple[int, str], ...] = (
    (0x100, "Created"),
    (0x200, "Removed"),
    (0x800, "Renamed"),
    (0x1000, "Modified"),
)
_FLAG_CATEGORY: dict[str, EventCategory] = {
    "Created": EventCategory.FILE_CREATED,
    "Removed": EventCategory.FILE_DELETED,
    "Renamed": EventCategory.FILE_RENAMED,
    "Modified": EventCategory.FILE_MODIFIED,
}


@dataclass(frozen=True, slots=True)
class _FsRecord:
    path: str
    event_id: int
    flags: int
    node_id: int | None
    extra: int | None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _iso(dt: Any) -> str | None:
    return format_utc(dt) if dt is not None else None


def _ts_basis(ts: Any) -> str:
    return "native_utc" if ts is not None else "unknown"


def _ai_service(*urls: str | None) -> str | None:
    for url in urls:
        if url:
            service = match_ai_domain(url)
            if service is not None:
                return service
    return None


def _quarantine_rows(ctx: ParseContext, cand: Candidate) -> list[dict[str, Any]]:
    raw = ctx.fs.read_bytes(cand.ref)
    if raw.startswith(_SQLITE_MAGIC):
        with open_sqlite(ctx.fs, cand.ref) as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM LSQuarantineEvent ORDER BY rowid")]
    obj = plistlib.loads(raw)
    items = obj.get("LSQuarantineEvents", []) if isinstance(obj, dict) else obj
    if not isinstance(items, list):
        raise TypeError("no LSQuarantineEvents array")
    return [item for item in items if isinstance(item, dict)]


def _decode_records(raw: bytes, version: int) -> tuple[list[_FsRecord], str | None]:
    records: list[_FsRecord] = []
    tail = 12 + (8 if version >= 2 else 0) + (4 if version >= 3 else 0)
    offset = 4
    while offset < len(raw):
        end = raw.find(b"\x00", offset)
        if end == -1:
            return records, f"unterminated FSEvents path at byte {offset}"
        if end == offset:
            break
        path = raw[offset:end].decode("utf-8", errors="replace")
        start = end + 1
        if start + tail > len(raw):
            return records, f"truncated FSEvents record at byte {offset}"
        event_id, flags = struct.unpack_from("<QI", raw, start)
        pos = start + 12
        node_id: int | None = None
        extra: int | None = None
        if version >= 2:
            (node_id,) = struct.unpack_from("<Q", raw, pos)
            pos += 8
        if version >= 3:
            (extra,) = struct.unpack_from("<I", raw, pos)
            pos += 4
        records.append(_FsRecord(path=path, event_id=event_id, flags=flags, node_id=node_id, extra=extra))
        offset = pos
    return records, None


class Plugin(PluginBase):
    name = "macos.activity"
    version = "1.0"
    description = "macOS quarantine downloads, knowledgeC app usage, TCC grants and FSEvents journals"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for volume in fs.volumes():
            for pattern, role in _SYSTEM_SOURCES:
                for ref in fs.glob(volume.index, pattern):
                    if not fs.is_dir(ref):
                        yield Candidate(ref=ref, role=role)
        for user in fs.users():
            for pattern, role in _USER_SOURCES:
                for ref in user_glob(fs, user, pattern):
                    if not fs.is_dir(ref):
                        yield Candidate(ref=ref, role=role, user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        if cand.role == _ROLE_QUARANTINE:
            yield from self._quarantine(ctx, cand)
        elif cand.role == _ROLE_KNOWLEDGEC:
            yield from self._knowledgec(ctx, cand)
        elif cand.role == _ROLE_TCC:
            yield from self._tcc(ctx, cand)
        elif cand.role == _ROLE_FSEVENTS:
            yield from self._fsevents(ctx, cand)
        else:
            raise ValueError(f"unknown activity role {cand.role!r}")

    def _quarantine(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            rows = _quarantine_rows(ctx, cand)
        except (ValueError, TypeError, OverflowError, ExpatError, sqlite3.Error) as exc:
            yield self.warning(ctx, cand, f"unreadable quarantine store: {exc}")
            return
        for index, row in enumerate(rows):
            url = _text(row.get("LSQuarantineDataURLString"))
            origin = _text(row.get("LSQuarantineOriginURLString"))
            agent = _text(row.get("LSQuarantineAgentName")) or _text(row.get("LSQuarantineAgentBundleIdentifier"))
            service = _ai_service(url, origin)
            ts = from_cocoa(_number(row.get("LSQuarantineTimeStamp")))
            artifact = self.artifact(
                ctx,
                cand,
                ArtifactKind.DOWNLOAD_ORIGIN,
                {"url": url or "", "origin_url": origin or "", "agent": agent or "", "ai_service": service},
                locator=f"quarantine:{index}",
            )
            yield artifact
            yield self.event(
                artifact,
                ts,
                "quarantine_timestamp",
                EventCategory.DOWNLOAD,
                Actor.HUMAN,
                f"Downloaded {url or 'unknown URL'} via {agent or 'unknown agent'}",
                ts_basis=_ts_basis(ts),
                subject=url,
                data={"ai_service": service},
            )

    def _knowledgec(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            with open_sqlite(ctx.fs, cand.ref) as conn:
                rows = [dict(row) for row in conn.execute(_KNOWLEDGE_SQL)]
        except sqlite3.Error as exc:
            yield self.warning(ctx, cand, f"unreadable knowledgeC store: {exc}")
            return
        for row in rows:
            bundle = _text(row["bundle"])
            tool = match_ai_program(bundle) if bundle is not None else None
            if bundle is None or tool is None:
                continue
            start = from_cocoa(_number(row["start"]))
            end = from_cocoa(_number(row["end"]))
            artifact = self.artifact(
                ctx,
                cand,
                ArtifactKind.EXECUTION,
                {
                    "program": bundle,
                    "source": "knowledgec",
                    "ai_tool": tool,
                    "extra": {"stream": row["stream"], "start": _iso(start), "end": _iso(end)},
                },
                locator=f"row:ZOBJECT.rowid={row['pk']}",
            )
            yield artifact
            yield self.event(
                artifact,
                start,
                "knowledgec_start",
                EventCategory.EXECUTION,
                Actor.HUMAN,
                f"{tool} in use ({bundle})",
                ts_basis=_ts_basis(start),
                subject=bundle,
                data={"ai_tool": tool},
            )

    def _tcc(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            with open_sqlite(ctx.fs, cand.ref) as conn:
                rows = [dict(row) for row in conn.execute(_TCC_SQL)]
        except sqlite3.Error as exc:
            yield self.warning(ctx, cand, f"unreadable TCC store: {exc}")
            return
        for row in rows:
            client = _text(row["client"])
            tool = match_ai_program(client) if client is not None else None
            if client is None or tool is None:
                continue
            service = _text(row["service"]) or ""
            ts = from_unix(_number(row["last_modified"]))
            artifact = self.artifact(
                ctx,
                cand,
                ArtifactKind.PERMISSION_GRANT,
                {"service": service, "client": client, "auth_value": row["auth_value"], "ai_tool": tool},
                locator=f"row:access.rowid={row['pk']}",
            )
            yield artifact
            yield self.event(
                artifact,
                ts,
                "tcc_last_modified",
                EventCategory.AUTH,
                Actor.HUMAN,
                f"{tool} granted {service} (auth_value {row['auth_value']})",
                ts_basis=_ts_basis(ts),
                subject=client,
                data={"ai_tool": tool},
            )

    def _fsevents(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            raw = gzip.decompress(ctx.fs.read_bytes(cand.ref))
        except (OSError, EOFError, zlib.error) as exc:
            yield self.warning(ctx, cand, f"FSEvents page is not gzip data: {exc}")
            return
        version = _FSEVENTS_VERSIONS.get(raw[:4])
        if version is None:
            yield self.warning(ctx, cand, f"bad FSEvents magic {raw[:4]!r}")
            return
        records, problem = _decode_records(raw, version)
        if problem is not None:
            yield self.warning(ctx, cand, problem)
        page_mtime = ctx.fs.stat(cand.ref).mtime
        for index, rec in enumerate(records):
            yield from self._journal(ctx, cand, rec, index, version, page_mtime)

    def _journal(
        self,
        ctx: ParseContext,
        cand: Candidate,
        rec: _FsRecord,
        index: int,
        version: int,
        page_mtime: Any,
    ) -> Iterator[Artifact | Event]:
        path = normalize(rec.path, OsFamily.MACOS)
        reasons = [name for bit, name in _FLAG_NAMES if rec.flags & bit]
        page_iso = _iso(page_mtime)
        data: dict[str, Any] = {
            "source": "fsevents",
            "path": path,
            "reasons": reasons,
            "page_mtime": page_iso,
            "extra": {
                "event_id": rec.event_id,
                "flags": f"0x{rec.flags:x}",
                "node_id": rec.node_id,
                "record_extra": rec.extra,
                "page_version": version,
            },
        }
        if path != rec.path:
            data["raw_path"] = rec.path
        artifact = self.artifact(
            ctx,
            cand,
            ArtifactKind.FILE_JOURNAL,
            data,
            locator=f"fsevents:{basename(cand.ref.path)}:{index}",
        )
        category = next((_FLAG_CATEGORY[r] for r in reasons), EventCategory.OTHER)
        yield artifact
        yield self.event(
            artifact,
            None,
            "page_mtime_bound",
            category,
            Actor.UNKNOWN,
            f"{' + '.join(reasons) or f'flags 0x{rec.flags:x}'} {path}",
            ts_basis="fsevents_page_mtime_bound",
            subject=path,
            data={"page_mtime": page_iso},
        )


PLUGIN = Plugin()
