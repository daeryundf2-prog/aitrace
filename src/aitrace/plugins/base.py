from __future__ import annotations

import dataclasses
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from aitrace.core.ids import make_id
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory
from aitrace.core.model import Artifact, Event, UserProfile
from aitrace.fs.base import EntryRef, EvidenceFS


@dataclass(frozen=True, slots=True)
class Candidate:
    ref: EntryRef
    role: str
    user: UserProfile | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParseContext:
    fs: EvidenceFS
    evidence_id: str
    tz: str
    log: logging.Logger


class ArtifactPlugin(Protocol):
    name: str
    version: str
    description: str

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]: ...

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]: ...


class PluginBase:
    name = ""
    version = "1.0"
    description = ""

    def artifact(
        self,
        ctx: ParseContext,
        cand: Candidate,
        kind: ArtifactKind,
        data: dict[str, Any],
        *,
        locator: str | None = None,
        ref: EntryRef | None = None,
        deleted: bool = False,
        user: str | None = None,
    ) -> Artifact:
        target = ref if ref is not None else cand.ref
        provenance = ctx.fs.provenance(target, self.name, self.version, record_locator=locator)
        if deleted:
            provenance = dataclasses.replace(provenance, deleted=True)
        owner = user if user is not None else (cand.user.name if cand.user is not None else None)
        artifact_id = make_id(ctx.evidence_id, self.name, target.volume, provenance.source_path, locator, kind)
        return Artifact(id=artifact_id, kind=kind, provenance=provenance, data=data, user=owner)

    def event(
        self,
        artifact: Artifact,
        ts: datetime | None,
        ts_kind: str,
        category: EventCategory,
        actor: Actor,
        summary: str,
        *,
        ts_basis: str = "native_utc",
        subject: str | None = None,
        data: dict[str, Any] | None = None,
        index: int = 0,
    ) -> Event:
        return Event(
            id=make_id(artifact.id, ts_kind, category, index),
            artifact_id=artifact.id,
            ts_utc=ts,
            ts_kind=ts_kind,
            ts_basis=ts_basis,
            category=category,
            actor=actor,
            user=artifact.user,
            summary=summary,
            subject=subject,
            data=data if data is not None else {},
        )

    def warning(self, ctx: ParseContext, cand: Candidate, message: str) -> Artifact:
        ctx.log.warning("%s: %s: %s", self.name, cand.ref.path, message)
        return self.artifact(
            ctx,
            cand,
            ArtifactKind.PARSE_WARNING,
            {"plugin": self.name, "message": message},
            locator="warning:" + make_id(message)[:16],
        )


@dataclass(frozen=True, slots=True)
class PluginRunResult:
    evidence_id: str
    name: str
    version: str
    status: str  # "ok" | "error" | "no_candidates"
    records: int
    warnings: int
    error: str | None
    started_utc: datetime
    finished_utc: datetime
