"""Remote-access tools: AnyDesk file transfers, TeamViewer connection logs and saved RDP files.

Formats follow dissect.target's remoteaccess plugins: AnyDesk ``file_transfer_trace.txt`` is UTF-16 LE
tab-separated rows with timestamps in UTC; TeamViewer ``Connections_incoming.txt`` is tab-separated with
7 fields; RDP files are ``key:type:value`` lines.
"""

from __future__ import annotations

import codecs
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Final

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory
from aitrace.core.model import Artifact, Event, UserProfile, format_utc
from aitrace.fs.base import EntryRef, EvidenceFS, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

ROLE_ANYDESK: Final = "anydesk_file_transfer"
ROLE_TV_INCOMING: Final = "teamviewer_incoming"
ROLE_TV_CONNECTIONS: Final = "teamviewer_connections"
ROLE_RDP: Final = "rdp_file"

_SERVICE_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (ROLE_ANYDESK, "/ProgramData/AnyDesk/file_transfer_trace.txt"),
    (ROLE_TV_INCOMING, "/Program Files*/TeamViewer/Connections_incoming.txt"),
)
_USER_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (ROLE_ANYDESK, "AppData/Roaming/AnyDesk/file_transfer_trace.txt"),
    (ROLE_ANYDESK, "Library/Application Support/AnyDesk/file_transfer_trace.txt"),
    (ROLE_ANYDESK, ".anydesk/file_transfer_trace.txt"),
    (ROLE_TV_CONNECTIONS, "AppData/Roaming/TeamViewer/Connections.txt"),
    (ROLE_RDP, "*.rdp"),
    (ROLE_RDP, "*/*.rdp"),
    (ROLE_RDP, "*/*/*.rdp"),
)

_ANYDESK_TIME: Final = "%Y-%m-%d, %H:%M"
_TEAMVIEWER_TIME: Final = "%d-%m-%Y %H:%M:%S"
_QUOTED_NAME: Final = re.compile(r"'([^']*)'")
_TRANSFER_DIRECTIONS: Final = frozenset({"upload", "download"})
_TRANSFER_CATEGORY: Final[dict[str, EventCategory]] = {
    "upload": EventCategory.UPLOAD,
    "download": EventCategory.DOWNLOAD,
}


def _targets(fs: EvidenceFS) -> Iterator[tuple[EntryRef, str, UserProfile | None]]:
    for volume in fs.volumes():
        for role, pattern in _SERVICE_PATTERNS:
            for ref in fs.glob(volume.index, pattern):
                yield ref, role, None
    for user in fs.users():
        for role, pattern in _USER_PATTERNS:
            for ref in user_glob(fs, user, pattern):
                yield ref, role, user


def _decode(raw: bytes) -> str:
    if raw.startswith(codecs.BOM_UTF16_LE):
        return raw.decode("utf-16")
    if b"\x00" in raw[:64]:
        return raw[: len(raw) - len(raw) % 2].decode("utf-16-le")
    return raw.decode("utf-8-sig")


def _lines(text: str) -> Iterator[tuple[int, str]]:
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        yield number, raw


class Plugin(PluginBase):
    name = "remote_tools"
    version = "1.0"
    description = "AnyDesk file transfers, TeamViewer incoming connections and saved RDP connection files"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        seen: set[tuple[int, str]] = set()
        for ref, role, user in _targets(fs):
            key = (ref.volume, ref.path)
            if key in seen:
                continue
            seen.add(key)
            yield Candidate(ref=ref, role=role, user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            text = _decode(ctx.fs.read_bytes(cand.ref))
        except UnicodeDecodeError as exc:
            yield self.warning(ctx, cand, f"undecodable text: {exc}")
            return
        if cand.role == ROLE_ANYDESK:
            yield from self._anydesk_transfers(ctx, cand, text)
        elif cand.role == ROLE_TV_INCOMING:
            yield from self._teamviewer_sessions(ctx, cand, text, direction="inbound")
        elif cand.role == ROLE_TV_CONNECTIONS:
            yield from self._teamviewer_sessions(ctx, cand, text, direction="unknown")
        elif cand.role == ROLE_RDP:
            yield from self._rdp(ctx, cand, text)
        else:
            raise ValueError(f"unknown remote_tools role: {cand.role}")

    def _anydesk_transfers(self, ctx: ParseContext, cand: Candidate, text: str) -> Iterator[Artifact | Event]:
        # Row: Clipboard<TAB><TAB>2025-01-01, 13:37<TAB>start <TAB>download<TAB>'malware.exe' (~0 B out of ...)
        for number, line in _lines(text):
            fields = line.split("\t")
            name_match = _QUOTED_NAME.search(line)
            if len(fields) < 6 or name_match is None:
                yield self.warning(ctx, cand, f"line {number}: unrecognised AnyDesk transfer row")
                continue
            try:
                when = datetime.strptime(fields[2].strip(), _ANYDESK_TIME).replace(tzinfo=UTC)
            except ValueError:
                yield self.warning(ctx, cand, f"line {number}: unparseable AnyDesk transfer timestamp")
                continue
            direction = fields[4].strip().lower()
            if direction not in _TRANSFER_DIRECTIONS:
                direction = "unknown"
            file_name = name_match.group(1)
            artifact = self.artifact(
                ctx,
                cand,
                ArtifactKind.FILE_TRANSFER,
                {
                    "channel": "anydesk",
                    "direction": direction,
                    "local_paths": [],
                    "tool": "AnyDesk",
                    "extra": {"file_name": file_name, "action": fields[3].strip()},
                },
                locator=f"line:{number}",
            )
            yield artifact
            yield self.event(
                artifact,
                when,
                "transfer",
                _TRANSFER_CATEGORY.get(direction, EventCategory.TRANSFER),
                Actor.UNKNOWN,
                f"AnyDesk {direction}: {file_name}",
                subject=file_name,
            )

    def _teamviewer_sessions(
        self, ctx: ParseContext, cand: Candidate, text: str, *, direction: str
    ) -> Iterator[Artifact | Event]:
        for number, line in _lines(text):
            fields = [field.strip() for field in line.split("\t")]
            if len(fields) < 7:
                yield self.warning(ctx, cand, f"line {number}: TeamViewer connection row has {len(fields)} fields")
                continue
            try:
                start = datetime.strptime(fields[2], _TEAMVIEWER_TIME).replace(tzinfo=UTC)
                end = datetime.strptime(fields[3], _TEAMVIEWER_TIME).replace(tzinfo=UTC)
            except ValueError:
                yield self.warning(ctx, cand, f"line {number}: unparseable TeamViewer connection timestamp")
                continue
            remote_id, name, account, connection_type, connection_id = (
                fields[0],
                fields[1],
                fields[4],
                fields[5],
                fields[6],
            )
            artifact = self.artifact(
                ctx,
                cand,
                ArtifactKind.REMOTE_SESSION,
                {
                    "protocol": "teamviewer",
                    "direction": direction,
                    "remote_host": remote_id,
                    "account": account or None,
                    "extra": {
                        "name": name,
                        "connection_type": connection_type,
                        "connection_id": connection_id,
                        "end_utc": format_utc(end),
                    },
                },
                locator=f"line:{number}",
            )
            yield artifact
            yield self.event(
                artifact,
                start,
                "session_start",
                EventCategory.REMOTE_ACCESS,
                Actor.UNKNOWN,
                f"TeamViewer {direction} session with {remote_id}",
                subject=remote_id,
            )
            yield self.event(
                artifact,
                end,
                "session_end",
                EventCategory.REMOTE_ACCESS,
                Actor.UNKNOWN,
                f"TeamViewer {direction} session with {remote_id} ended",
                subject=remote_id,
                index=1,
            )

    def _rdp(self, ctx: ParseContext, cand: Candidate, text: str) -> Iterator[Artifact | Event]:
        host: str | None = None
        host_line = 0
        username: str | None = None
        for number, line in _lines(text):
            parts = line.split(":", 2)
            if len(parts) != 3:
                continue
            key = parts[0].strip().lower()
            value = parts[2].strip()
            if key == "full address" and host is None:
                host, host_line = value, number
            elif key == "username" and username is None:
                username = value
        if not host:
            return
        yield self.artifact(
            ctx,
            cand,
            ArtifactKind.REMOTE_SESSION,
            {
                "protocol": "rdp",
                "direction": "outbound",
                "remote_host": host,
                "account": username or None,
                "extra": {"source": "saved_connection_file"},
            },
            locator=f"line:{host_line}",
        )


PLUGIN = Plugin()
