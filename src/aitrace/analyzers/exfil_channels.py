from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from aitrace.core import catalog
from aitrace.core.ids import make_id
from aitrace.core.kinds import (
    Actor,
    ArtifactKind,
    EventCategory,
    FindingCategory,
    OsFamily,
    Severity,
    SignalType,
    band_for,
)
from aitrace.core.model import Artifact, Attribution, Finding
from aitrace.core.paths import basename, normalize
from aitrace.core.time import fmt_utc

if TYPE_CHECKING:
    from aitrace.db.store import CaseStore

AI_WINDOW = timedelta(minutes=60)
TRANSFER_TAG = "transfer"
USB_LIMITATION = "USB insertion does not prove file copy"
CHANNEL_KINDS = (
    ArtifactKind.FILE_TRANSFER,
    ArtifactKind.SHELL_COMMAND,
    ArtifactKind.REMOTE_SESSION,
    ArtifactKind.USB_DEVICE,
    ArtifactKind.CLOUD_SYNC,
    ArtifactKind.NETWORK_USAGE,
    ArtifactKind.AI_TOOL_CALL,
)
_DISPLAY_NAMES = {
    "anydesk": "AnyDesk",
    "teamviewer": "TeamViewer",
    "rdp": "RDP",
    "ssh": "SSH",
    "other": "remote session",
    "browser_file_dialog_last_dir": "browser file dialog",
    "agent": "AI agent",
}


def _en(key: SignalType | str) -> str:
    entry = catalog.LIMITATIONS[key]
    if isinstance(entry, dict):
        return entry["en"]
    raise TypeError(f"limitation {key} has no single entry")


def _key(path: str) -> str:
    return normalize(path, OsFamily.UNKNOWN).casefold()


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _command_paths(command: str) -> list[str]:
    paths: list[str] = []
    for token in command.split():
        token = token.strip("'\"")
        if token in {".", ".."} or token.startswith("-") or "://" in token or "@" in token or ":" in token:
            continue
        if "/" in token or "." in token:
            paths.append(token)
    return paths


class _Index:
    def __init__(self, store: CaseStore) -> None:
        self.ts: dict[str, datetime] = {}
        self.event_ids: dict[str, str] = {}
        self.actors: dict[str, Actor] = {}
        self.ai_times: dict[str | None, list[datetime]] = {}
        for event in store.events():
            self.event_ids.setdefault(event.artifact_id, event.id)
            self.actors.setdefault(event.artifact_id, event.actor)
            if event.ts_utc is None:
                continue
            self.ts.setdefault(event.artifact_id, event.ts_utc)
            if event.actor is Actor.AI and event.category is EventCategory.AI_ACTIVITY:
                self.ai_times.setdefault(event.user, []).append(event.ts_utc)
        for times in self.ai_times.values():
            times.sort()

        self.ai_file_keys: set[str] = set()
        chat_parts: list[str] = []
        for art in store.artifacts(kinds=(ArtifactKind.AI_TOOL_CALL, ArtifactKind.AI_CHAT_MESSAGE)):
            if art.kind is ArtifactKind.AI_TOOL_CALL:
                path = _str(art.data.get("file_path"))
                if path:
                    self.ai_file_keys.add(_key(path))
            else:
                text = _str(art.data.get("text"))
                if text:
                    chat_parts.append(text)
        self.chat = "\n".join(chat_parts).casefold()

    def ai_window(self, user: str | None, ts: datetime | None) -> bool:
        times = self.ai_times.get(user, [])
        if ts is None or not times:
            return False
        idx = bisect_right(times, ts) - 1
        return idx >= 0 and ts - times[idx] <= AI_WINDOW

    def link_reasons(self, paths: list[str]) -> list[str]:
        reasons: list[str] = []
        for path in paths:
            norm = normalize(path, OsFamily.UNKNOWN)
            name = basename(norm)
            if _key(path) in self.ai_file_keys:
                reasons.append(f"AI tool call targeted {norm}")
            elif name and name.casefold() in self.chat:
                reasons.append(f"named in AI chat: {name}")
        return reasons

    def finding(
        self,
        art: Artifact,
        *,
        rule_id: str,
        channel: str,
        destination: str | None,
        sources: list[str],
        actor: Actor,
        limitations: tuple[str, ...] = (),
    ) -> Finding:
        ts = self.ts.get(art.id)
        reasons = self.link_reasons(sources)
        extra = limitations
        if reasons:
            severity, basis = Severity.HIGH, "path_linked"
        elif self.ai_window(art.user, ts):
            severity, basis = Severity.HIGH, "within_60m_after_ai"
            extra = (*extra, _en(SignalType.TIME_PROXIMITY))
        else:
            severity, basis = Severity.MEDIUM, "no_ai_link"
        confidence = 0.8 if severity is Severity.HIGH else 0.5
        source_text = ", ".join(sources) if sources else "none recorded"
        time_text = fmt_utc(ts) if ts is not None else "unknown"
        narrative = (
            f"Channel: {channel}. Source: {source_text}. Destination: {destination or 'unknown'}. "
            f"Time: {time_text}. Actor: {actor.value}. Basis: {basis}."
        )
        if reasons:
            narrative += " Links: " + "; ".join(reasons) + "."
        event_id = self.event_ids.get(art.id)
        return Finding(
            id=make_id("exfil_channel", art.id, rule_id, channel),
            category=FindingCategory.EXFIL_CHANNEL,
            severity=severity,
            title=f"Exfiltration channel: {channel}",
            narrative=narrative,
            artifact_ids=(art.id,),
            event_ids=(event_id,) if event_id else (),
            confidence=confidence,
            band=band_for(confidence),
            rule_id=rule_id,
            limitations=extra,
            data={
                "channel": channel,
                "destination": destination,
                "source_paths": list(sources),
                "actor": actor.value,
                "basis": basis,
                "time": fmt_utc(ts) if ts is not None else None,
                "user": art.user,
            },
        )

    def shell_findings(self, art: Artifact, command: str, actor: Actor) -> Iterator[Finding]:
        sources = _command_paths(command)
        for rule, destination in catalog.match_command(command):
            if TRANSFER_TAG not in rule.tags:
                continue
            channel = f"{rule.rule_id} to {destination}" if destination else rule.rule_id
            yield self.finding(
                art,
                rule_id=rule.rule_id,
                channel=channel,
                destination=destination,
                sources=sources,
                actor=actor,
            )

    def findings_for(self, art: Artifact) -> Iterator[Finding]:
        data = art.data
        actor = self.actors.get(art.id, Actor.UNKNOWN)
        kind = art.kind
        if kind is ArtifactKind.FILE_TRANSFER:
            channel_key = _str(data.get("channel")) or "unknown"
            destination = _str(data.get("destination"))
            if channel_key == "agent":
                actor = Actor.AI
            display = _DISPLAY_NAMES.get(channel_key, channel_key)
            limitations = (_en("BROWSER_LAST_DIR"),) if channel_key == "browser_file_dialog_last_dir" else ()
            yield self.finding(
                art,
                rule_id=f"EXFIL-{channel_key.upper()}",
                channel=f"{display} to {destination}" if destination else display,
                destination=destination,
                sources=_str_list(data.get("local_paths")),
                actor=actor,
                limitations=limitations,
            )
        elif kind is ArtifactKind.SHELL_COMMAND:
            command = _str(data.get("command"))
            if command:
                yield from self.shell_findings(art, command, actor)
        elif kind is ArtifactKind.AI_TOOL_CALL:
            raw_input = data.get("input")
            command = _str(data.get("command")) or (
                _str(raw_input.get("command")) if isinstance(raw_input, dict) else None
            )
            if command:
                yield from self.shell_findings(art, command, Actor.AI)
        elif kind is ArtifactKind.REMOTE_SESSION:
            protocol = (_str(data.get("protocol")) or "other").lower()
            host = _str(data.get("remote_host"))
            display = _DISPLAY_NAMES.get(protocol, protocol)
            yield self.finding(
                art,
                rule_id=f"EXFIL-REMOTE-{protocol.upper()}",
                channel=f"{display} to {host}" if host else display,
                destination=host,
                sources=[],
                actor=actor,
            )
        elif kind is ArtifactKind.USB_DEVICE:
            name = " ".join(p for p in (_str(data.get("vendor")), _str(data.get("product"))) if p)
            yield self.finding(
                art,
                rule_id="EXFIL-USB",
                channel=f"USB {name}".rstrip(),
                destination=None,
                sources=[],
                actor=actor,
                limitations=(USB_LIMITATION,),
            )
        elif kind is ArtifactKind.CLOUD_SYNC:
            service = _str(data.get("service")) or "unknown service"
            item = _str(data.get("item_path"))
            yield self.finding(
                art,
                rule_id="EXFIL-CLOUD-SYNC",
                channel=f"cloud sync: {service}",
                destination=service,
                sources=[item] if item else [],
                actor=actor,
            )
        elif kind is ArtifactKind.NETWORK_USAGE:
            program = _str(data.get("program")) or ""
            ai_name = catalog.match_ai_program(program) or _str(data.get("ai_tool"))
            sent = data.get("bytes_sent")
            if ai_name and isinstance(sent, int) and sent > 0:
                yield self.finding(
                    art,
                    rule_id="EXFIL-NETWORK",
                    channel=f"network upload: {ai_name}",
                    destination=None,
                    sources=[],
                    actor=actor,
                )


class ExfilChannelsAnalyzer:
    name = "exfil_channels"
    version = "1.0"

    def run(self, store: CaseStore, tz: str) -> Iterator[Finding | Attribution]:
        index = _Index(store)
        for art in store.artifacts(kinds=CHANNEL_KINDS):
            yield from index.findings_for(art)


ANALYZER = ExfilChannelsAnalyzer()
