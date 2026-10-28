"""Download origins that survive deleted browser history.

Windows: NTFS alternate data stream `Zone.Identifier` (ini `[ZoneTransfer]` with ZoneId, ReferrerUrl, HostUrl).
macOS: xattrs `com.apple.metadata:kMDItemWhereFroms` (plist array of URLs: download URL, then referrer) and
`com.apple.quarantine` (`flags;hextime;agent;uuid`). Malformed values produce PARSE_WARNING artifacts.
"""

from __future__ import annotations

import plistlib
from collections.abc import Iterator
from datetime import datetime
from typing import Any
from xml.parsers.expat import ExpatError

from aitrace.core.catalog import match_ai_domain
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_unix
from aitrace.fs.base import EntryRef, EntryStat, EvidenceFS
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

MAX_DEPTH = 6
MAX_FILES_PER_USER = 200_000
PRUNE_NAMES = frozenset({"node_modules", ".git", ".venv"})
EXCLUDED_SUBPATHS = ("/Library/Caches/", "/AppData/Local/Temp/")
ZONE_STREAM = "Zone.Identifier"
WHERE_FROMS = "com.apple.metadata:kMDItemWhereFroms"
QUARANTINE = "com.apple.quarantine"
_ZONE_KEYS = {"zoneid": "ZoneId", "referrerurl": "ReferrerUrl", "hosturl": "HostUrl"}


def _excluded(path: str) -> bool:
    return any(marker in path for marker in EXCLUDED_SUBPATHS)


def _decode(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def parse_zone_identifier(raw: bytes) -> dict[str, str]:
    """`[ZoneTransfer]` keys (canonical case); ValueError when the section or every known key is missing."""
    section: str | None = None
    found: dict[str, str] = {}
    for line in _decode(raw).replace("\x00", "").splitlines():
        text = line.strip()
        if not text or text.startswith((";", "#")):
            continue
        if text.startswith("[") and text.endswith("]"):
            section = text[1:-1].strip().casefold()
            continue
        key, sep, value = text.partition("=")
        canonical = _ZONE_KEYS.get(key.strip().casefold())
        if sep and section == "zonetransfer" and canonical is not None:
            found[canonical] = value.strip()
    if not found:
        raise ValueError("no [ZoneTransfer] ZoneId/ReferrerUrl/HostUrl entries")
    return found


def parse_where_froms(raw: bytes) -> list[str]:
    """URL list from a binary or XML plist; ValueError on corrupt data, TypeError on a non-list value."""
    try:
        value = plistlib.loads(raw)
    except (ValueError, ExpatError) as exc:
        raise ValueError(f"corrupt plist: {exc!r}") from exc
    if not isinstance(value, list):
        raise TypeError(f"expected a plist array, got {type(value).__name__}")
    return [item for item in value if isinstance(item, str)]


def parse_quarantine(raw: bytes) -> tuple[str, datetime | None, str, str]:
    """(flags, time, agent, uuid); ValueError when the time field is not hexadecimal."""
    fields = raw.decode("utf-8", errors="replace").rstrip("\x00").split(";")
    if len(fields) < 2:
        raise ValueError("expected 'flags;hextime;agent;uuid'")
    flags, hextime = fields[0], fields[1]
    agent = fields[2] if len(fields) > 2 else ""
    uuid = fields[3] if len(fields) > 3 else ""
    try:
        seconds = int(hextime, 16)
    except ValueError:
        raise ValueError(f"quarantine time is not hexadecimal: {hextime[:16]!r}") from None
    return flags, from_unix(seconds), agent, uuid


def _ai_service(*urls: str) -> str | None:
    return next((s for u in urls if u and (s := match_ai_domain(u))), None)


class Plugin(PluginBase):
    name = "download_origin"
    version = "1.0"
    description = "Download origin URLs from NTFS Zone.Identifier streams and macOS WhereFroms/quarantine xattrs"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for user in fs.users():
            yield Candidate(ref=EntryRef(user.volume, user.home), role="home", user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        walked = ctx.fs.walk(cand.ref, max_depth=MAX_DEPTH, skip_names=PRUNE_NAMES)
        kept = (ref for ref in walked if not _excluded(ref.path))
        for count, ref in enumerate(kept, start=1):
            if count > MAX_FILES_PER_USER:
                yield self.warning(ctx, cand, f"file cap of {MAX_FILES_PER_USER} reached; remaining files skipped")
                return
            yield from self._file(ctx, Candidate(ref=ref, role="file", user=cand.user))

    def _file(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            streams = ctx.fs.streams(cand.ref)
            xattrs = ctx.fs.xattrs(cand.ref)
        except OSError as exc:
            yield self.warning(ctx, cand, f"stream/xattr listing failed: {exc}")
            return
        if ZONE_STREAM in streams:
            yield from self._zone(ctx, cand)
        if WHERE_FROMS in xattrs or QUARANTINE in xattrs:
            yield from self._macos(ctx, cand, xattrs)

    def _target(self, cand: Candidate) -> str:
        os_family = cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN
        home = cand.user.home if cand.user is not None else None
        return normalize(cand.ref.path, os_family, home)

    def _zone(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            zone = parse_zone_identifier(ctx.fs.read_stream(cand.ref, ZONE_STREAM))
        except OSError as exc:
            yield self.warning(ctx, cand, f"unreadable {ZONE_STREAM} stream: {exc}")
            return
        except ValueError as exc:
            yield self.warning(ctx, cand, f"malformed {ZONE_STREAM} stream: {exc}")
            return
        url = zone.get("HostUrl", "")
        origin = zone.get("ReferrerUrl", "")
        extra: dict[str, Any] = {"source": "zone_identifier"}
        if "ZoneId" in zone:
            zone_id = zone["ZoneId"]
            extra["zone_id"] = int(zone_id) if zone_id.isdigit() else zone_id
        yield from self._emit(ctx, cand, f"ads:{ZONE_STREAM}", url, origin, "", extra, None)

    def _macos(self, ctx: ParseContext, cand: Candidate, xattrs: dict[str, bytes]) -> Iterator[Artifact | Event]:
        urls: list[str] = []
        extra: dict[str, Any] = {}
        agent = ""
        quarantined: datetime | None = None
        if WHERE_FROMS in xattrs:
            try:
                urls = parse_where_froms(xattrs[WHERE_FROMS])
            except (ValueError, TypeError) as exc:
                yield self.warning(ctx, cand, f"malformed {WHERE_FROMS} xattr: {exc}")
            else:
                extra["source"] = "kMDItemWhereFroms"
        if QUARANTINE in xattrs:
            try:
                flags, quarantined, agent, uuid = parse_quarantine(xattrs[QUARANTINE])
            except ValueError as exc:
                yield self.warning(ctx, cand, f"malformed {QUARANTINE} xattr: {exc}")
            else:
                extra.setdefault("source", "quarantine")
                extra["quarantine_flags"] = flags
                if uuid:
                    extra["quarantine_uuid"] = uuid
        if "source" not in extra:
            return
        url = urls[0] if urls else ""
        origin = urls[1] if len(urls) > 1 else ""
        yield from self._emit(ctx, cand, "xattr", url, origin, agent, extra, quarantined)

    def _emit(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        url: str,
        origin: str,
        agent: str,
        extra: dict[str, Any],
        quarantined: datetime | None,
    ) -> Iterator[Artifact | Event]:
        target = self._target(cand)
        data: dict[str, Any] = {"url": url, "origin_url": origin, "agent": agent, "target_path": target}
        service = _ai_service(url, origin)
        if service is not None:
            data["ai_service"] = service
        data["extra"] = extra
        artifact = self.artifact(ctx, cand, ArtifactKind.DOWNLOAD_ORIGIN, data, locator=locator)
        yield artifact
        ts, ts_kind = quarantined, "quarantine_time"
        if ts is None:
            ts, ts_kind = self._file_time(ctx, cand)
        yield self.event(
            artifact,
            ts,
            ts_kind,
            EventCategory.DOWNLOAD,
            Actor.HUMAN,
            f"Downloaded {url or 'unknown URL'} to {target}",
            ts_basis="unknown" if ts is None else "native_utc",
            subject=target,
            data={"ai_service": service, "source": extra["source"]},
        )

    @staticmethod
    def _file_time(ctx: ParseContext, cand: Candidate) -> tuple[datetime | None, str]:
        try:
            st: EntryStat = ctx.fs.stat(cand.ref)
        except OSError:
            return None, "unknown"
        if st.btime is not None:
            return st.btime, "btime"
        if st.mtime is not None:
            return st.mtime, "mtime"
        return None, "unknown"


PLUGIN = Plugin()
