from __future__ import annotations

import io
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any, BinaryIO

from dissect.eventlog.evtx import Evtx
from dissect.eventlog.exceptions import MalformedElfChnkException

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory
from aitrace.core.model import Artifact, Event
from aitrace.core.time import from_iso, from_local_naive
from aitrace.fs.base import EvidenceFS
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

EVTX_DIR = "/Windows/System32/winevt/Logs/"
SETUPAPI_LOG = "/Windows/INF/setupapi.dev.log"
SECURITY = "Security"
LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational"
RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational"
RDP_CLIENT = "Microsoft-Windows-TerminalServices-RDPClient%4Operational"
POWERSHELL = "Microsoft-Windows-PowerShell%4Operational"
PARTITION = "Microsoft-Windows-Partition%4Diagnostic"
DRIVER_FW = "Microsoft-Windows-DriverFrameworks-UserMode%4Operational"
CHANNELS: tuple[str, ...] = (SECURITY, LSM, RCM, RDP_CLIENT, POWERSHELL, PARTITION, DRIVER_FW)
EVTX_HEADER_SIZE = 4096
EVTX_CHUNK_SIZE = 65536

_RDP_LOGON_TYPES = {"3": "network", "10": "rdp"}
_LSM_EVENTS = {21: "logon", 24: "disconnect", 25: "reconnect"}
_RDP_CLIENT_EVENTS = {1024: "dns_resolution", 1102: "connection_attempt"}
_USB_EVENTS = frozenset({(PARTITION, 1006), (DRIVER_FW, 2003)})

_SECTION_START = re.compile(r"^>>>\s+Section start\s+(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_DEVICE_INSTALL = re.compile(r"^>>>\s+\[Device Install.*?-\s*(USB(?:STOR)?\\[^\]\s]+)\]")
_VENDOR = re.compile(r"(?:VID_|VEN_)([^&\\]+)")
_PRODUCT = re.compile(r"(?:PID_|PROD_)([^&\\]+)")


@dataclass(frozen=True, slots=True)
class SetupapiDevice:
    instance_id: str
    bus: str
    vendor: str | None
    product: str | None
    serial: str | None
    section_start: str | None


@dataclass(frozen=True, slots=True)
class _Mapped:
    kind: ArtifactKind
    category: EventCategory
    actor: Actor
    summary: str
    fields: dict[str, Any]


def iter_evtx(fileobj: BinaryIO) -> Iterator[dict[str, Any]]:
    for record in Evtx(fileobj):
        yield dict(record.items())


def parse_setupapi(text: str) -> Iterator[SetupapiDevice]:
    section_start: str | None = None
    for line in text.splitlines():
        start = _SECTION_START.match(line)
        if start is not None:
            section_start = start.group(1)
            continue
        install = _DEVICE_INSTALL.match(line)
        if install is None:
            continue
        instance_id = install.group(1)
        parts = instance_id.split("\\")
        ident = parts[1] if len(parts) > 1 else ""
        vendor = _VENDOR.search(ident)
        product = _PRODUCT.search(ident)
        serial = parts[-1] if len(parts) > 2 else None
        yield SetupapiDevice(
            instance_id=instance_id,
            bus=parts[0],
            vendor=vendor.group(1) if vendor else None,
            product=product.group(1) if product else None,
            serial=serial,
            section_start=section_start,
        )


def _text(rec: dict[str, Any], key: str) -> str:
    value = rec.get(key)
    return "" if value is None else str(value)


def _event_id(rec: dict[str, Any]) -> int | None:
    try:
        return int(rec["EventID"])
    except (KeyError, TypeError, ValueError):
        return None


def _record_time(rec: dict[str, Any]) -> datetime | None:
    return from_iso(_text(rec, "TimeCreated_SystemTime"))


def _brief(rec: dict[str, Any]) -> dict[str, str]:
    return {key: str(value)[:200] for key, value in list(rec.items())[:40]}


def _classify_security(event_id: int, rec: dict[str, Any]) -> _Mapped | None:
    if event_id in (4624, 4625):
        logon_type = _text(rec, "LogonType")
        protocol = _RDP_LOGON_TYPES.get(logon_type)
        if protocol is None:
            return None
        outcome = "success" if event_id == 4624 else "failure"
        user = _text(rec, "TargetUserName")
        return _Mapped(
            ArtifactKind.REMOTE_SESSION,
            EventCategory.REMOTE_ACCESS,
            Actor.UNKNOWN,
            f"{outcome} {protocol} logon for {user}",
            {
                "protocol": protocol,
                "outcome": outcome,
                "logon_type": logon_type,
                "user": user,
                "source_ip": _text(rec, "IpAddress"),
            },
        )
    if event_id in (4778, 4779):
        state = "reconnect" if event_id == 4778 else "disconnect"
        user = _text(rec, "AccountName")
        return _Mapped(
            ArtifactKind.REMOTE_SESSION,
            EventCategory.REMOTE_ACCESS,
            Actor.UNKNOWN,
            f"session {state} for {user}",
            {"protocol": "rdp", "state": state, "user": user, "source_ip": _text(rec, "ClientAddress")},
        )
    return None


def _classify(channel: str, event_id: int, rec: dict[str, Any]) -> _Mapped | None:
    if channel == SECURITY:
        return _classify_security(event_id, rec)
    if channel == LSM and event_id in _LSM_EVENTS:
        state = _LSM_EVENTS[event_id]
        user = _text(rec, "User")
        return _Mapped(
            ArtifactKind.REMOTE_SESSION,
            EventCategory.REMOTE_ACCESS,
            Actor.UNKNOWN,
            f"terminal services {state} for {user}",
            {"protocol": "rdp", "state": state, "user": user, "source_ip": _text(rec, "Address")},
        )
    if channel == RCM and event_id == 1149:
        user = _text(rec, "Param1")
        return _Mapped(
            ArtifactKind.REMOTE_SESSION,
            EventCategory.REMOTE_ACCESS,
            Actor.UNKNOWN,
            f"RDP authentication for {user}",
            {"protocol": "rdp", "state": "authenticated", "user": user, "source_ip": _text(rec, "Param3")},
        )
    if channel == RDP_CLIENT and event_id in _RDP_CLIENT_EVENTS:
        state = _RDP_CLIENT_EVENTS[event_id]
        target = _text(rec, "Param1")
        return _Mapped(
            ArtifactKind.REMOTE_SESSION,
            EventCategory.REMOTE_ACCESS,
            Actor.UNKNOWN,
            f"RDP client {state} to {target}",
            {"protocol": "rdp", "state": state, "direction": "outbound", "target": target},
        )
    if channel == POWERSHELL and event_id == 4104:
        script = _text(rec, "ScriptBlockText")
        return _Mapped(
            ArtifactKind.SHELL_COMMAND,
            EventCategory.EXECUTION,
            Actor.UNKNOWN,
            f"PowerShell script block: {script[:160]}",
            {"script": script},
        )
    if (channel, event_id) in _USB_EVENTS:
        device = _text(rec, "DeviceId") or _text(rec, "DeviceInstanceId") or _text(rec, "DeviceName")
        return _Mapped(
            ArtifactKind.USB_DEVICE,
            EventCategory.DEVICE,
            Actor.SYSTEM,
            f"device event {event_id}: {device}",
            {"event_id": event_id, "device": device},
        )
    return None


class WindowsEvtxRdpUsbPlugin(PluginBase):
    name = "windows.evtx_rdp_usb"
    version = "1.0"
    description = "Windows event logs (RDP, PowerShell, USB) and setupapi device-install blocks"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for volume in fs.volumes():
            for channel in CHANNELS:
                for ref in fs.glob(volume.index, EVTX_DIR + channel + ".evtx"):
                    if not fs.is_dir(ref):
                        yield Candidate(ref=ref, role="evtx", extra={"channel": channel})
            for ref in fs.glob(volume.index, SETUPAPI_LOG):
                if not fs.is_dir(ref):
                    yield Candidate(ref=ref, role="setupapi")

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        if cand.role == "evtx":
            yield from self._parse_evtx(ctx, cand)
        elif cand.role == "setupapi":
            yield from self._parse_setupapi(ctx, cand)
        else:
            yield self.warning(ctx, cand, f"unknown candidate role {cand.role!r}")

    def _parse_evtx(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        channel = cand.extra["channel"]
        try:
            with ctx.fs.open(cand.ref) as fh:
                size = fh.seek(0, io.SEEK_END)
                fh.seek(0)
                rows = list(iter_evtx(fh))
        except (OSError, EOFError, ValueError, MalformedElfChnkException) as exc:
            yield self.warning(ctx, cand, f"{channel}: evtx parse failed: {type(exc).__name__}: {exc}")
            return
        if (size - EVTX_HEADER_SIZE) % EVTX_CHUNK_SIZE:
            yield self.warning(ctx, cand, f"{channel}: evtx truncated: size {size} is not header plus whole chunks")
        for rec in rows:
            event_id = _event_id(rec)
            if event_id is None:
                continue
            mapped = _classify(channel, event_id, rec)
            if mapped is None:
                continue
            record_id = _text(rec, "EventRecordID")
            data = {
                "channel": channel,
                "event_id": event_id,
                "record_id": record_id,
                **mapped.fields,
                "raw": _brief(rec),
            }
            artifact = self.artifact(ctx, cand, mapped.kind, data, locator=f"evtx:{channel}:{record_id}")
            yield artifact
            ts = _record_time(rec)
            yield self.event(
                artifact,
                ts,
                "event_time",
                mapped.category,
                mapped.actor,
                mapped.summary,
                ts_basis="native_utc" if ts is not None else "unknown",
                data=data,
            )

    def _parse_setupapi(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            text = ctx.fs.read_bytes(cand.ref).decode("utf-8-sig", errors="replace")
        except OSError as exc:
            yield self.warning(ctx, cand, f"setupapi read failed: {exc}")
            return
        for index, device in enumerate(parse_setupapi(text)):
            data = {
                "source": "setupapi",
                "bus": device.bus,
                "vendor": device.vendor,
                "product": device.product,
                "serial": device.serial,
                "instance_id": device.instance_id,
            }
            artifact = self.artifact(
                ctx, cand, ArtifactKind.USB_DEVICE, data, locator=f"setupapi:{index}:{device.instance_id}"
            )
            yield artifact
            ts = None
            if device.section_start is not None:
                naive = datetime.fromisoformat(device.section_start.replace("/", "-"))
                ts = from_local_naive(naive, ctx.tz)
            yield self.event(
                artifact,
                ts,
                "install_time",
                EventCategory.DEVICE,
                Actor.SYSTEM,
                f"USB device install: {device.instance_id}",
                ts_basis=f"assumed:{ctx.tz}" if ts is not None else "unknown",
                data=data,
            )


PLUGIN = WindowsEvtxRdpUsbPlugin()
