from __future__ import annotations

import gzip
import re
import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory
from aitrace.core.model import Artifact, Event
from aitrace.core.time import from_local_naive, from_unix
from aitrace.fs.base import EvidenceFS, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

ROLE_AUTH: Final = "auth_log"
ROLE_WTMP: Final = "wtmp"
ROLE_KNOWN_HOSTS: Final = "known_hosts"
ROLE_SSH_CONFIG: Final = "ssh_config"
ROLE_RCLONE: Final = "rclone_conf"
ROLE_JOURNAL: Final = "journald"

_SYSTEM_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (ROLE_AUTH, "/var/log/auth.log*"),
    (ROLE_AUTH, "/var/log/secure*"),
    (ROLE_WTMP, "/var/log/wtmp"),
    (ROLE_JOURNAL, "/var/log/journal/**/*.journal"),
)
_USER_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (ROLE_KNOWN_HOSTS, ".ssh/known_hosts"),
    (ROLE_SSH_CONFIG, ".ssh/config"),
    (ROLE_RCLONE, ".config/rclone/rclone.conf"),
)

_SYSLOG: Final = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[^:\s\[]+)(?:\[\d+\])?:\s(?P<msg>.*)$"
)
_ACCEPTED: Final = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_MONTHS: Final[dict[str, int]] = {
    name: number
    for number, name in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)
}
_KH_BRACKETED: Final = re.compile(r"^\[(?P<host>[^\]]+)\]:\d+$")
_SSH_WILDCARDS: Final = ("*", "?", "!")

# glibc utmp record on Linux: type, pid, line[32], id[4], user[32], host[256], exit (2 shorts),
# session, tv_sec, tv_usec, addr_v6[16], unused[20]; 384 bytes in total.
_UTMP: Final = struct.Struct("<i i 32s 4s 32s 256s h h i i i 16s 20s")


@dataclass(slots=True)
class _SshBlock:
    line: int
    patterns: tuple[str, ...]
    hostname: str | None = None


def _cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _basis(ts: datetime | None, basis: str) -> str:
    return basis if ts is not None else "unknown"


def _known_host_name(token: str) -> tuple[str, bool]:
    if token.startswith("|1|"):
        return "<hashed>", True
    first = token.split(",")[0]
    bracketed = _KH_BRACKETED.match(first)
    return (bracketed["host"] if bracketed else first), False


class Plugin(PluginBase):
    name = "remote_auth"
    version = "1.0"
    description = "SSH and remote logins from auth logs and wtmp, SSH client hosts, rclone remotes; journald detected"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for volume in fs.volumes():
            for role, pattern in _SYSTEM_PATTERNS:
                for ref in fs.glob(volume.index, pattern):
                    if not fs.is_dir(ref):
                        yield Candidate(ref=ref, role=role)
        for user in fs.users():
            for role, pattern in _USER_PATTERNS:
                for ref in user_glob(fs, user, pattern):
                    yield Candidate(ref=ref, role=role, user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        match cand.role:
            case "auth_log":
                yield from self._auth_log(ctx, cand)
            case "wtmp":
                yield from self._wtmp(ctx, cand)
            case "known_hosts":
                yield from self._known_hosts(ctx, cand)
            case "ssh_config":
                yield from self._ssh_config(ctx, cand)
            case "rclone_conf":
                yield from self._rclone(ctx, cand)
            case "journald":
                yield self.warning(ctx, cand, "journald not parsed: dissect journal reader requires a Target")
            case _:
                raise ValueError(f"unknown remote_auth role: {cand.role}")

    def _auth_log(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        raw = ctx.fs.read_bytes(cand.ref)
        if cand.ref.path.endswith(".gz"):
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError, zlib.error) as exc:
                yield self.warning(ctx, cand, f"undecodable gzip: {exc}")
                return
        mtime = ctx.fs.stat(cand.ref).mtime
        year = mtime.year if mtime is not None else None
        malformed = 0
        for number, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
            match = _SYSLOG.match(line)
            if match is None:
                if line.strip():
                    malformed += 1
                continue
            accepted = _ACCEPTED.match(match["msg"])
            if accepted is None or not match["proc"].startswith("sshd"):
                continue
            ts: datetime | None = None
            if year is not None:
                hour, minute, second = (int(part) for part in match["time"].split(":"))
                try:
                    naive = datetime(year, _MONTHS[match["mon"]], int(match["day"]), hour, minute, second)
                except (KeyError, ValueError):
                    malformed += 1
                    continue
                ts = from_local_naive(naive, ctx.tz)
            user, ip = accepted["user"], accepted["ip"]
            artifact = self.artifact(
                ctx,
                cand,
                ArtifactKind.REMOTE_SESSION,
                {
                    "protocol": "ssh",
                    "direction": "inbound",
                    "remote_host": ip,
                    "account": user,
                    "extra": {
                        "method": accepted["method"],
                        "port": int(accepted["port"]),
                        "server_host": match["host"],
                    },
                },
                locator=f"line:{number}",
            )
            yield artifact
            yield self.event(
                artifact,
                ts,
                "session_start",
                EventCategory.REMOTE_ACCESS,
                Actor.UNKNOWN,
                f"SSH login as {user} from {ip}",
                ts_basis=_basis(ts, f"assumed:{ctx.tz}"),
                subject=ip,
            )
        if malformed:
            yield self.warning(ctx, cand, f"skipped {malformed} malformed record(s)")

    def _wtmp(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        raw = ctx.fs.read_bytes(cand.ref)
        size = _UTMP.size
        trailing = 1 if len(raw) % size else 0
        for index in range(len(raw) // size):
            (_type, pid, line_raw, _id, user_raw, host_raw, _term, _exit, _session, tv_sec, _usec, _addr, _unused) = (
                _UTMP.unpack_from(raw, index * size)
            )
            host = _cstr(host_raw)
            if not host:
                continue
            user = _cstr(user_raw) or None
            ts = from_unix(tv_sec)
            artifact = self.artifact(
                ctx,
                cand,
                ArtifactKind.REMOTE_SESSION,
                {
                    "protocol": "other",
                    "direction": "inbound",
                    "remote_host": host,
                    "account": user,
                    "extra": {"line": _cstr(line_raw), "pid": pid},
                },
                locator=f"record:{index}",
            )
            yield artifact
            yield self.event(
                artifact,
                ts,
                "login",
                EventCategory.REMOTE_ACCESS,
                Actor.UNKNOWN,
                f"wtmp login from {host}",
                ts_basis=_basis(ts, "native_utc"),
                subject=host,
            )
        if trailing:
            yield self.warning(ctx, cand, f"skipped {trailing} malformed record(s)")

    def _known_hosts(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        mtime = ctx.fs.stat(cand.ref).mtime
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        malformed = 0
        for number, line in enumerate(text.splitlines(), start=1):
            fields = line.split()
            if not fields or fields[0].startswith("#"):
                continue
            if fields[0].startswith("@"):
                fields = fields[1:]
            if len(fields) < 3:
                malformed += 1
                continue
            host, hashed = _known_host_name(fields[0])
            artifact = self.artifact(
                ctx,
                cand,
                ArtifactKind.REMOTE_SESSION,
                {
                    "protocol": "ssh",
                    "direction": "outbound",
                    "remote_host": host,
                    "account": None,
                    "extra": {"source": "known_hosts", "hashed": hashed},
                },
                locator=f"line:{number}",
            )
            yield artifact
            yield self.event(
                artifact,
                mtime,
                "file_mtime",
                EventCategory.REMOTE_ACCESS,
                Actor.UNKNOWN,
                f"known SSH host {host}",
                ts_basis=_basis(mtime, "native_utc"),
                subject=host,
            )
        if malformed:
            yield self.warning(ctx, cand, f"skipped {malformed} malformed record(s)")

    def _ssh_config(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        mtime = ctx.fs.stat(cand.ref).mtime
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        blocks: list[_SshBlock] = []
        for number, line in enumerate(text.splitlines(), start=1):
            fields = line.split()
            if len(fields) < 2 or fields[0].startswith("#"):
                continue
            keyword = fields[0].lower()
            if keyword == "host":
                blocks.append(_SshBlock(line=number, patterns=tuple(fields[1:])))
            elif keyword == "hostname" and blocks:
                blocks[-1].hostname = fields[1]
        for block in blocks:
            concrete = [p for p in block.patterns if not any(w in p for w in _SSH_WILDCARDS)]
            if not concrete:
                continue
            host = block.hostname or concrete[0]
            artifact = self.artifact(
                ctx,
                cand,
                ArtifactKind.REMOTE_SESSION,
                {
                    "protocol": "ssh",
                    "direction": "outbound",
                    "remote_host": host,
                    "account": None,
                    "extra": {"source": "ssh_config", "alias": concrete[0]},
                },
                locator=f"line:{block.line}",
            )
            yield artifact
            yield self.event(
                artifact,
                mtime,
                "file_mtime",
                EventCategory.REMOTE_ACCESS,
                Actor.UNKNOWN,
                f"SSH config host {host}",
                ts_basis=_basis(mtime, "native_utc"),
                subject=host,
            )

    def _rclone(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        mtime = ctx.fs.stat(cand.ref).mtime
        text = ctx.fs.read_bytes(cand.ref).decode("utf-8", errors="replace")
        section: str | None = None
        malformed = 0
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1].strip()
                continue
            key, sep, value = stripped.partition("=")
            if not sep or section is None:
                malformed += 1
                continue
            # Only `type` is read; token, password and key values are never loaded into output.
            if key.strip().lower() != "type":
                continue
            service = value.strip()
            artifact = self.artifact(
                ctx,
                cand,
                ArtifactKind.CLOUD_SYNC,
                {"service": service, "extra": {"remote_name": section}},
                locator=f"line:{number}",
            )
            yield artifact
            yield self.event(
                artifact,
                mtime,
                "file_mtime",
                EventCategory.CONFIG,
                Actor.UNKNOWN,
                f"rclone remote '{section}' ({service})",
                ts_basis=_basis(mtime, "native_utc"),
                subject=section,
            )
        if malformed:
            yield self.warning(ctx, cand, f"skipped {malformed} malformed record(s)")


PLUGIN = Plugin()
