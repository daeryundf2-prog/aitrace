from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime

from aitrace.core.catalog import match_command
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_unix
from aitrace.fs.base import EvidenceFS, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

_ROLE_GLOBS: tuple[tuple[str, str], ...] = (
    ("bash", ".bash_history"),
    ("zsh", ".zsh_history"),
    ("zsh", ".zhistory"),
    ("fish", ".local/share/fish/fish_history"),
    ("powershell", "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"),
)

_BASH_TS = re.compile(r"^#(\d{9,11})$")
_ZSH_EXTENDED = re.compile(r"^: (\d+):\d+;(.*)$")
_FISH_CMD = "- cmd: "
_FISH_WHEN = re.compile(r"^\s+when:\s*(\d+)\s*$")
_REMOTE_SPEC = re.compile(r"^(\S+@)?[\w.-]+:")
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_SCHEME = re.compile(r"^\w+://")
_HOST_RULES = frozenset({"TR-SCP", "TR-RSYNC", "TR-SFTP"})
_BINARY_RATIO = 0.1


@dataclass(frozen=True, slots=True)
class _Command:
    line: int
    text: str
    epoch: int | None


def unmetafy(data: bytes) -> bytes:
    """Undo zsh history metafication: 0x83 marks that the next byte is XOR 0x20."""
    if b"\x83" not in data:
        return data
    out = bytearray()
    skip = False
    for byte in data:
        if skip:
            out.append(byte ^ 0x20)
            skip = False
        elif byte == 0x83:
            skip = True
        else:
            out.append(byte)
    return bytes(out)


def _looks_binary(data: bytes, text: str) -> bool:
    if b"\x00" in data:
        return True
    return bool(text) and text.count("\ufffd") / len(text) > _BINARY_RATIO


def _parse_bash(lines: list[str]) -> Iterator[_Command]:
    pending: int | None = None
    for number, line in enumerate(lines, start=1):
        match = _BASH_TS.match(line)
        if match is not None:
            pending = int(match.group(1))
        elif line.strip():
            yield _Command(number, line.strip(), pending)
            pending = None


def _parse_zsh(lines: list[str]) -> Iterator[_Command]:
    index = 0
    while index < len(lines):
        start = index + 1
        line = lines[index]
        index += 1
        extended = _ZSH_EXTENDED.match(line)
        epoch = int(extended.group(1)) if extended is not None else None
        text = extended.group(2) if extended is not None else line
        while text.endswith("\\") and index < len(lines):
            text = text[:-1] + "\n" + lines[index]
            index += 1
        if text.strip():
            yield _Command(start, text.strip(), epoch)


def _fish_unescape(value: str) -> str:
    out: list[str] = []
    chars = iter(value)
    for char in chars:
        if char != "\\":
            out.append(char)
            continue
        nxt = next(chars, "")
        out.append("\n" if nxt == "n" else nxt if nxt == "\\" else "\\" + nxt)
    return "".join(out)


def _parse_fish(lines: list[str]) -> Iterator[_Command]:
    current: _Command | None = None
    for number, line in enumerate(lines, start=1):
        if line.startswith(_FISH_CMD):
            if current is not None:
                yield current
            current = _Command(number, _fish_unescape(line[len(_FISH_CMD) :]).strip(), None)
            continue
        when = _FISH_WHEN.match(line)
        if when is not None and current is not None and current.epoch is None:
            current = _Command(current.line, current.text, int(when.group(1)))
    if current is not None:
        yield current


def _parse_powershell(lines: list[str]) -> Iterator[_Command]:
    for number, line in enumerate(lines, start=1):
        if line.strip():
            yield _Command(number, line.strip(), None)


_PARSERS = {"bash": _parse_bash, "zsh": _parse_zsh, "fish": _parse_fish, "powershell": _parse_powershell}


def _tokens(command: str, shell: str) -> list[str]:
    if shell != "powershell":
        try:
            return shlex.split(command)
        except ValueError:
            pass
    return [tok.strip("'\"") for tok in command.split()]


def _local_paths(command: str, rule_id: str, shell: str, os_family: OsFamily, home: str | None) -> list[str]:
    tokens = _tokens(command, shell)[1:]
    found: list[str] = []
    for token in tokens:
        value = token[1:] if token.startswith("@") and len(token) > 1 else token
        if not value or value.startswith("-") or _SCHEME.match(value):
            continue
        if _REMOTE_SPEC.match(value) and not _DRIVE.match(value):
            continue
        pathlike = "/" in value or "\\" in value or value.startswith("~") or "." in value.strip(".")
        if not pathlike and rule_id not in _HOST_RULES:
            continue
        if rule_id in _HOST_RULES and value in {"scp", "rsync", "sftp"}:
            continue
        path = normalize(value, os_family, home)
        if path not in found:
            found.append(path)
    return found


class Plugin(PluginBase):
    name = "history"
    version = "1.0"
    description = "Shell command history (bash, zsh, fish, PowerShell) with transfer/remote/AI-CLI tagging"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        seen: set[tuple[int, str]] = set()
        for user in fs.users():
            for role, pattern in _ROLE_GLOBS:
                for ref in user_glob(fs, user, pattern):
                    key = (ref.volume, ref.path)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield Candidate(ref=ref, role=role, user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        raw = ctx.fs.read_bytes(cand.ref)
        data = unmetafy(raw) if cand.role == "zsh" else raw
        text = data.decode("utf-8", errors="replace")
        if _looks_binary(raw, text):
            yield self.warning(ctx, cand, "history file is not text (binary content); skipped")
            return
        lines = text.replace("\r\n", "\n").split("\n")
        os_family = cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN
        home = cand.user.home if cand.user is not None else None
        for command in _PARSERS[cand.role](lines):
            yield from self._emit(ctx, cand, command, os_family, home)

    def _emit(
        self, ctx: ParseContext, cand: Candidate, command: _Command, os_family: OsFamily, home: str | None
    ) -> Iterator[Artifact | Event]:
        matches = match_command(command.text)
        rule_ids = [rule.rule_id for rule, _ in matches]
        tags: list[str] = []
        for rule, _ in matches:
            for tag in rule.tags:
                if tag not in tags:
                    tags.append(tag)
        ts: datetime | None = from_unix(command.epoch) if command.epoch is not None else None
        basis = "native_utc" if ts is not None else "unknown"
        shell = cand.role
        locator = f"line:{command.line}"
        artifact = self.artifact(
            ctx,
            cand,
            ArtifactKind.SHELL_COMMAND,
            {"shell": shell, "command": command.text, "tags": tags, "rule_ids": rule_ids},
            locator=locator,
        )
        yield artifact
        yield self.event(
            artifact,
            ts,
            "command_executed",
            EventCategory.EXECUTION,
            Actor.HUMAN,
            f"{shell}: {command.text[:120]}",
            ts_basis=basis,
            subject=command.text,
        )
        for rule, destination in matches:
            if "transfer" not in rule.tags:
                continue
            transfer = self.artifact(
                ctx,
                cand,
                ArtifactKind.FILE_TRANSFER,
                {
                    "channel": rule.rule_id,
                    "direction": "upload",
                    "local_paths": _local_paths(command.text, rule.rule_id, shell, os_family, home),
                    "destination": destination,
                    "command": command.text,
                },
                locator=f"{locator}:{rule.rule_id}",
            )
            yield transfer
            yield self.event(
                transfer,
                ts,
                "transfer_command",
                EventCategory.TRANSFER,
                Actor.HUMAN,
                f"{rule.rule_id} -> {destination or 'unknown destination'}",
                ts_basis=basis,
                subject=destination,
            )


PLUGIN = Plugin()
