from __future__ import annotations

import gzip
import json
import logging
import struct
from datetime import UTC, datetime

from aitrace.core.kinds import ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.unix.remote_auth import PLUGIN

LOG = logging.getLogger("tests.remote_auth")
HOME = "/home/park"
AUTH_LOG = "/var/log/auth.log"
MTIME = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
ACCEPTED = "Oct  1 10:00:00 host sshd[1]: Accepted publickey for park from 198.51.100.7 port 5000 ssh2"
UTMP = struct.Struct("<ii32s4s32s256shhiii16s20s")


def _run(files: dict[str, bytes], mtimes: dict[str, datetime] | None = None) -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=OsFamily.LINUX, mtimes=mtimes)
    ctx = ParseContext(fs=fs, evidence_id=fs.evidence_id, tz="UTC", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _events(records: list[Artifact | Event]) -> list[Event]:
    return [r for r in records if isinstance(r, Event)]


def _warnings(records: list[Artifact | Event]) -> list[str]:
    return [str(r.data["message"]) for r in _kind(records, ArtifactKind.PARSE_WARNING)]


def _utmp(host: str, user: str, tv_sec: int) -> bytes:
    return UTMP.pack(7, 1234, b"pts/0", b"", user.encode(), host.encode(), 0, 0, 0, tv_sec, 0, bytes(16), bytes(20))


def test_accepted_publickey_becomes_inbound_ssh_session() -> None:
    records = _run({AUTH_LOG: (ACCEPTED + "\n").encode()}, {AUTH_LOG: MTIME})

    sessions = _kind(records, ArtifactKind.REMOTE_SESSION)
    assert [s.data["remote_host"] for s in sessions] == ["198.51.100.7"]
    assert sessions[0].data["protocol"] == "ssh"
    assert sessions[0].data["direction"] == "inbound"
    assert sessions[0].data["account"] == "park"
    (event,) = _events(records)
    assert event.category == EventCategory.REMOTE_ACCESS
    assert event.ts_utc == datetime(2026, 10, 1, 10, 0, tzinfo=UTC)
    assert event.ts_basis == "assumed:UTC"


def test_unparsable_lines_are_ignored_and_counted() -> None:
    text = (
        "garbage line\n"
        f"{ACCEPTED}\n"
        "Oct 99 10:00:00 host sshd[2]: Accepted password for x from 10.0.0.1 port 1 ssh2\n"
        "Oct  1 10:00:01 host cron[3]: job ran"
    )
    records = _run({AUTH_LOG: (text + "\n").encode()}, {AUTH_LOG: MTIME})

    assert [s.data["remote_host"] for s in _kind(records, ArtifactKind.REMOTE_SESSION)] == ["198.51.100.7"]
    assert _warnings(records) == ["skipped 2 malformed record(s)"]


def test_gzip_rotated_auth_log_is_read() -> None:
    rotated = "/var/log/auth.log.2.gz"
    records = _run({rotated: gzip.compress((ACCEPTED + "\n").encode())}, {rotated: MTIME})

    assert [s.data["remote_host"] for s in _kind(records, ArtifactKind.REMOTE_SESSION)] == ["198.51.100.7"]


def test_wtmp_record_with_host_becomes_remote_session() -> None:
    assert UTMP.size == 384
    raw = _utmp("198.51.100.9", "park", 1700000000) + _utmp("", "reboot", 1700000100)

    records = _run({"/var/log/wtmp": raw})

    sessions = _kind(records, ArtifactKind.REMOTE_SESSION)
    assert [s.data["remote_host"] for s in sessions] == ["198.51.100.9"]
    assert sessions[0].data["account"] == "park"
    (event,) = _events(records)
    assert event.ts_utc == datetime.fromtimestamp(1700000000, tz=UTC)


def test_known_hosts_and_ssh_config_are_outbound_targets() -> None:
    known_hosts = f"{HOME}/.ssh/known_hosts"
    ssh_config = f"{HOME}/.ssh/config"
    files = {
        known_hosts: b"example.com ssh-ed25519 AAAAC3\n|1|abc=|def= ssh-rsa AAAAB3\n",
        ssh_config: b"Host work\n  HostName bastion.example.net\nHost *\n  User park\n",
    }
    records = _run(files, {known_hosts: MTIME, ssh_config: MTIME})

    sessions = _kind(records, ArtifactKind.REMOTE_SESSION)
    assert {s.data["remote_host"] for s in sessions} == {"example.com", "<hashed>", "bastion.example.net"}
    assert {s.data["direction"] for s in sessions} == {"outbound"}
    file_events = [e for e in _events(records) if e.ts_kind == "file_mtime"]
    assert len(file_events) == 3
    assert all(e.ts_utc == MTIME for e in file_events)


def test_rclone_remote_type_is_kept_and_secrets_dropped() -> None:
    conf = (
        b"[gdrive]\n"
        b"type = drive\n"
        b'token = {"access_token":"SECRET-TOKEN-VALUE"}\n'
        b"\n"
        b"[backup]\n"
        b"type = s3\n"
        b"secret_access_key = SECRET-KEY-VALUE\n"
    )
    records = _run({f"{HOME}/.config/rclone/rclone.conf": conf}, {f"{HOME}/.config/rclone/rclone.conf": MTIME})

    syncs = _kind(records, ArtifactKind.CLOUD_SYNC)
    assert [s.data["service"] for s in syncs] == ["drive", "s3"]
    assert [s.data["account"] for s in syncs] == ["gdrive", "backup"]
    assert {s.data["extra"]["tool"] for s in syncs} == {"rclone"}
    assert "SECRET" not in json.dumps([s.data for s in syncs])


def test_journald_files_are_reported_not_parsed() -> None:
    records = _run({"/var/log/journal/abc123/system.journal": b"\x00" * 8})

    assert len(_warnings(records)) == 1
    assert _warnings(records)[0].startswith("journald not parsed")
