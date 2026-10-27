from __future__ import annotations

import dataclasses
import types
import typing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Self

from aitrace.core.kinds import (
    Actor,
    ArtifactKind,
    ConfidenceBand,
    EventCategory,
    FindingCategory,
    OsFamily,
    Severity,
    SignalType,
    Verdict,
)

__all__ = [
    "Artifact",
    "Attribution",
    "Case",
    "Event",
    "Evidence",
    "Finding",
    "Provenance",
    "Signal",
    "UserProfile",
    "VolumeInfo",
    "format_utc",
    "parse_utc",
]


def format_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError(f"naive datetime not allowed: {dt!r}")
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_utc(text: str) -> datetime:
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError(f"datetime string without timezone: {text!r}")
    return dt.astimezone(UTC)


def _encode(value: Any) -> Any:
    if isinstance(value, datetime):
        return format_utc(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, _Record):
        return value.to_dict()
    if isinstance(value, (tuple, list)):
        return [_encode(v) for v in value]
    if isinstance(value, dict):
        return {k: _encode(v) for k, v in value.items()}
    return value


def _decode(tp: Any, value: Any) -> Any:
    origin = typing.get_origin(tp)
    if origin is types.UnionType or origin is typing.Union:
        if value is None:
            return None
        members = [a for a in typing.get_args(tp) if a is not type(None)]
        if len(members) != 1:
            raise TypeError(f"unsupported union type {tp!r}")
        return _decode(members[0], value)
    if origin is tuple:
        item_type = typing.get_args(tp)[0]
        return tuple(_decode(item_type, v) for v in value)
    if origin is dict or tp is dict:
        return dict(value)
    if tp is datetime:
        return parse_utc(value)
    if isinstance(tp, type) and issubclass(tp, Enum):
        return tp(value)
    if isinstance(tp, type) and issubclass(tp, _Record):
        return tp.from_dict(value)
    return value


class _Record:
    __slots__ = ()

    def _check_datetimes(self) -> None:
        for f in dataclasses.fields(typing.cast(Any, self)):
            value = getattr(self, f.name)
            if isinstance(value, datetime) and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError(f"{type(self).__name__}.{f.name} must be timezone-aware UTC")

    def __post_init__(self) -> None:
        self._check_datetimes()

    def to_dict(self) -> dict[str, Any]:
        return {f.name: _encode(getattr(self, f.name)) for f in dataclasses.fields(typing.cast(Any, self))}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        hints = typing.get_type_hints(cls)
        kwargs = {
            f.name: _decode(hints[f.name], data[f.name])
            for f in dataclasses.fields(typing.cast(Any, cls))
            if f.name in data
        }
        return cls(**kwargs)


@dataclass(frozen=True, slots=True, kw_only=True)
class UserProfile(_Record):
    name: str
    home: str
    volume: int
    os_family: OsFamily
    sid: str | None = None
    uid: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class VolumeInfo(_Record):
    index: int
    fs_type: str
    label: str | None
    size: int | None
    os_family: OsFamily


@dataclass(frozen=True, slots=True, kw_only=True)
class Evidence(_Record):
    id: str
    kind: str  # "e01" | "raw" | "dir"
    path: str
    segments: tuple[str, ...]
    size: int | None
    acquisition_hashes: dict[str, str]
    segment_hashes: dict[str, dict[str, str]]
    media_sha256: str | None
    verification_status: str  # "match" | "mismatch" | "unverified"
    volumes: tuple[VolumeInfo, ...] = ()
    users: tuple[UserProfile, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class Case(_Record):
    id: str
    name: str
    number: str
    examiner: str
    organisation: str
    created_utc: datetime
    timezone: str
    lang: str
    tool_version: str
    notes: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Provenance(_Record):
    evidence_id: str
    volume: int
    source_path: str
    plugin: str
    plugin_version: str
    inode: int | None = None
    mft_seq: int | None = None
    byte_offset: int | None = None
    size: int | None = None
    sha256: str | None = None
    deleted: bool = False
    record_locator: str | None = None  # e.g. "line:12", "row:urls.id=5", "usn:12345"


@dataclass(frozen=True, slots=True, kw_only=True)
class Artifact(_Record):
    id: str
    kind: ArtifactKind
    provenance: Provenance
    data: dict[str, Any]
    user: str | None = None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class Event(_Record):
    id: str
    artifact_id: str
    ts_utc: datetime | None
    ts_kind: str
    ts_basis: str  # "native_utc" | "converted:<tz>" | "assumed:<tz>" | "unknown" | other documented
    category: EventCategory
    actor: Actor
    user: str | None
    summary: str
    subject: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True, kw_only=True)
class Signal(_Record):
    type: SignalType
    direction: str
    weight: float
    artifact_ids: tuple[str, ...]
    note: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Attribution(_Record):
    id: str
    subject: str
    subject_artifact_ids: tuple[str, ...]
    verdict: Verdict
    confidence: float
    band: ConfidenceBand
    signals: tuple[Signal, ...]
    rationale: str
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        self._check_datetimes()
        if not self.limitations:
            raise ValueError("Attribution.limitations must not be empty")


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding(_Record):
    id: str
    category: FindingCategory
    severity: Severity
    title: str
    narrative: str
    artifact_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    confidence: float
    band: ConfidenceBand
    rule_id: str | None
    limitations: tuple[str, ...]
    data: dict[str, Any] = field(default_factory=dict)
