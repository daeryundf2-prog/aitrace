from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.shell.history import PLUGIN, unmetafy

LOG = logging.getLogger("tests.history")
HOME = "/Users/kim"
FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "fixtures/files/third_party/dissect/plugins/os/windows/powershell/ConsoleHost_history.txt"
)
PS_PATH = f"{HOME}/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"


def _run(files: dict[str, bytes], os_family: OsFamily = OsFamily.MACOS) -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=os_family)
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="Asia/Seoul", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _events(records: list[Artifact | Event]) -> list[Event]:
    return [r for r in records if isinstance(r, Event)]


def test_locate_yields_every_history_location_including_root() -> None:
    fs = MemoryFS(
        {
            f"{HOME}/.bash_history": b"",
            f"{HOME}/.zsh_history": b"",
            f"{HOME}/.zhistory": b"",
            f"{HOME}/.local/share/fish/fish_history": b"",
            PS_PATH: b"",
            "/root/.bash_history": b"",
        },
        volume_os=OsFamily.LINUX,
    )
    found = sorted((cand.role, cand.ref.path) for cand in PLUGIN.locate(fs))
    assert found == sorted(
        [
            ("bash", f"{HOME}/.bash_history"),
            ("zsh", f"{HOME}/.zsh_history"),
            ("zsh", f"{HOME}/.zhistory"),
            ("fish", f"{HOME}/.local/share/fish/fish_history"),
            ("powershell", PS_PATH),
            ("bash", "/root/.bash_history"),
        ]
    )


def test_bash_epoch_line_sets_timestamp_of_next_command_only() -> None:
    data = b"#1700000000\nls -la\npwd\n"
    records = _run({f"{HOME}/.bash_history": data})
    commands = _kind(records, ArtifactKind.SHELL_COMMAND)
    assert [c.data["command"] for c in commands] == ["ls -la", "pwd"]
    assert all(c.data["shell"] == "bash" for c in commands)
    events = _events(records)
    assert events[0].ts_utc == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
    assert events[0].ts_basis == "native_utc"
    assert events[0].category == EventCategory.EXECUTION
    assert events[0].actor == Actor.HUMAN
    assert events[1].ts_utc is None
    assert events[1].ts_basis == "unknown"


def test_zsh_extended_format_multiline_and_plain_lines() -> None:
    data = b": 1700000000:3;echo one\\\ntwo\n: 1700000100:0;pwd\nplain\n"
    records = _run({f"{HOME}/.zsh_history": data})
    commands = _kind(records, ArtifactKind.SHELL_COMMAND)
    assert [c.data["command"] for c in commands] == ["echo one\ntwo", "pwd", "plain"]
    assert commands[0].provenance.record_locator == "line:1"
    assert commands[1].provenance.record_locator == "line:3"
    stamps = [e.ts_utc for e in _events(records)]
    assert stamps[0] == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)
    assert stamps[1] == datetime(2023, 11, 14, 22, 15, 0, tzinfo=UTC)
    assert stamps[2] is None


def test_zsh_metafied_bytes_are_decoded() -> None:
    assert unmetafy(b"a\x83\x89b") == b"a\xa9b"
    data = b": 1700000000:0;echo \xc3\x83\x89\n"
    records = _run({f"{HOME}/.zhistory": data})
    assert _kind(records, ArtifactKind.SHELL_COMMAND)[0].data["command"] == "echo \u00e9"


def test_fish_history_cmd_when_and_escapes() -> None:
    data = (
        b"- cmd: echo hi\n  when: 1700000000\n"
        b"- cmd: printf a\\\\nb\\nc\n  when: 1700000050\n  paths:\n    - /tmp/x\n"
    )
    records = _run({f"{HOME}/.local/share/fish/fish_history": data})
    commands = _kind(records, ArtifactKind.SHELL_COMMAND)
    assert [c.data["command"] for c in commands] == ["echo hi", "printf a\\nb\nc"]
    assert all(c.data["shell"] == "fish" for c in commands)
    assert _events(records)[1].ts_utc == datetime(2023, 11, 14, 22, 14, 10, tzinfo=UTC)


def test_powershell_dissect_fixture_has_no_timestamps() -> None:
    records = _run({PS_PATH: FIXTURE.read_bytes()}, OsFamily.WINDOWS)
    commands = _kind(records, ArtifactKind.SHELL_COMMAND)
    assert [c.data["command"] for c in commands] == [
        'Write-Host "Hello World!"',
        'Get-Service | Where-Object {$_.Status -eq "Running"}',
        'Get-ComputerInfo -Property "*version"',
        "exit",
    ]
    assert all(c.data["shell"] == "powershell" for c in commands)
    assert all(e.ts_utc is None for e in _events(records))
    assert not _kind(records, ArtifactKind.PARSE_WARNING)


def test_scp_emits_file_transfer_with_destination_host_and_local_path() -> None:
    data = b"#1700000000\nscp a.txt u@203.0.113.10:/tmp\n"
    records = _run({f"{HOME}/.bash_history": data})
    command = _kind(records, ArtifactKind.SHELL_COMMAND)[0]
    assert command.data["rule_ids"] == ["TR-SCP"]
    assert "transfer" in command.data["tags"]
    transfers = _kind(records, ArtifactKind.FILE_TRANSFER)
    assert len(transfers) == 1
    assert transfers[0].data["channel"] == "TR-SCP"
    assert transfers[0].data["destination"] == "203.0.113.10"
    assert transfers[0].data["direction"] == "upload"
    assert transfers[0].data["local_paths"] == ["/a.txt"]
    assert transfers[0].data["command"] == "scp a.txt u@203.0.113.10:/tmp"
    transfer_events = [e for e in _events(records) if e.category == EventCategory.TRANSFER]
    assert len(transfer_events) == 1
    assert transfer_events[0].ts_utc == datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)


def test_windows_transfer_and_cloud_cli_tags() -> None:
    lines = (
        "claude\n"
        r"scp C:\Users\kim\work\proposal.md kim@203.0.113.10:/tmp/" "\n"
        r"rclone copy C:\Users\kim\work gdrive:backup"
    )
    records = _run({PS_PATH: lines.encode()}, OsFamily.WINDOWS)
    commands = _kind(records, ArtifactKind.SHELL_COMMAND)
    assert commands[0].data["tags"] == ["ai_cli"]
    assert commands[0].data["rule_ids"] == ["AI-CLI"]
    assert commands[2].data["tags"] == ["transfer", "cloud_cli"]
    transfers = {t.data["channel"]: t for t in _kind(records, ArtifactKind.FILE_TRANSFER)}
    assert transfers["TR-SCP"].data["destination"] == "203.0.113.10"
    assert transfers["TR-SCP"].data["local_paths"] == ["/Users/kim/work/proposal.md"]
    assert transfers["TR-RCLONE"].data["local_paths"] == ["/Users/kim/work"]


def test_remote_and_archive_tags_without_transfer() -> None:
    data = b"ssh admin@10.0.0.5\ntar czf out.tgz docs\n"
    records = _run({"/root/.bash_history": data}, OsFamily.LINUX)
    commands = _kind(records, ArtifactKind.SHELL_COMMAND)
    assert commands[0].data["tags"] == ["remote"]
    assert "archive" in commands[1].data["tags"]
    assert not _kind(records, ArtifactKind.FILE_TRANSFER)
    assert commands[0].user == "root"


def test_curl_upload_destination_is_url() -> None:
    data = b"curl -T secret.zip https://files.example.org/up\n"
    records = _run({f"{HOME}/.bash_history": data})
    transfer = _kind(records, ArtifactKind.FILE_TRANSFER)[0]
    assert transfer.data["channel"] == "TR-CURL-UP"
    assert transfer.data["destination"] == "https://files.example.org/up"
    assert "/secret.zip" in transfer.data["local_paths"]


def test_binary_garbage_yields_warning_and_no_commands() -> None:
    garbage = bytes(range(256)) * 8 + b"\x00\x00\x00"
    records = _run({f"{HOME}/.bash_history": garbage})
    assert len(_kind(records, ArtifactKind.PARSE_WARNING)) == 1
    assert not _kind(records, ArtifactKind.SHELL_COMMAND)
    assert not _events(records)


def test_empty_history_yields_nothing() -> None:
    assert _run({f"{HOME}/.bash_history": b""}) == []
