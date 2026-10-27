from __future__ import annotations

import logging
import traceback
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

from aitrace.core.ids import make_id
from aitrace.core.kinds import ArtifactKind
from aitrace.core.model import Artifact, Event
from aitrace.db.store import BATCH_SIZE, CaseStore
from aitrace.fs.base import EvidenceFS
from aitrace.plugins.base import ArtifactPlugin, Candidate, ParseContext, PluginRunResult

TRACEBACK_LINES = 5


@dataclass(slots=True)
class _Tally:
    records: int = 0
    warnings: int = 0
    candidates: int = 0
    error: str | None = None


def _parse_warning(ctx: ParseContext, plugin: ArtifactPlugin, cand: Candidate, exc: Exception) -> Artifact:
    tb_lines = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)).splitlines()
    return Artifact(
        id=make_id(ctx.evidence_id, plugin.name, cand.ref.volume, cand.ref.path, "parse_error"),
        kind=ArtifactKind.PARSE_WARNING,
        provenance=ctx.fs.provenance(cand.ref, plugin.name, plugin.version, record_locator="parse_error"),
        data={
            "plugin": plugin.name,
            "message": f"parse failed: {type(exc).__name__}",
            "error": repr(exc),
            "extra": {"traceback": tb_lines[-TRACEBACK_LINES:]},
        },
        user=cand.user.name if cand.user is not None else None,
    )


def _parse_guarded(
    plugin: ArtifactPlugin, ctx: ParseContext, cand: Candidate, tally: _Tally
) -> Iterator[Artifact | Event]:
    try:
        for record in plugin.parse(ctx, cand):
            if isinstance(record, Artifact) and record.kind is ArtifactKind.PARSE_WARNING:
                tally.warnings += 1
            else:
                tally.records += 1
            yield record
    except Exception as exc:
        ctx.log.exception("%s: %s: parse failed", plugin.name, cand.ref.path)
        tally.warnings += 1
        yield _parse_warning(ctx, plugin, cand, exc)


def _stream(
    plugin: ArtifactPlugin, fs: EvidenceFS, ctx: ParseContext, tally: _Tally
) -> Iterator[Artifact | Event]:
    try:
        for cand in plugin.locate(fs):
            tally.candidates += 1
            yield from _parse_guarded(plugin, ctx, cand, tally)
    except Exception as exc:
        ctx.log.exception("%s: locate failed", plugin.name)
        tally.error = repr(exc)


def _run_one(
    fs: EvidenceFS,
    store: CaseStore,
    evidence_id: str,
    plugin: ArtifactPlugin,
    log: logging.Logger,
    tz: str,
) -> PluginRunResult:
    started = datetime.now(UTC)
    ctx = ParseContext(fs=fs, evidence_id=evidence_id, tz=tz, log=log)
    tally = _Tally()
    buffer: list[Artifact | Event] = []
    for record in _stream(plugin, fs, ctx, tally):
        buffer.append(record)
        if len(buffer) >= BATCH_SIZE:
            store.add(buffer)
            buffer.clear()
    if buffer:
        store.add(buffer)
    finished = datetime.now(UTC)
    if tally.error is not None:
        status = "error"
    elif tally.candidates == 0:
        status = "no_candidates"
    else:
        status = "ok"
    result = PluginRunResult(
        evidence_id=evidence_id,
        name=plugin.name,
        version=plugin.version,
        status=status,
        records=tally.records,
        warnings=tally.warnings,
        error=tally.error,
        started_utc=started,
        finished_utc=finished,
    )
    store.record_plugin_run(result)
    return result


def run_plugins(
    fs: EvidenceFS,
    store: CaseStore,
    evidence_id: str,
    plugins: list[ArtifactPlugin],
    log: logging.Logger,
    tz: str,
) -> list[PluginRunResult]:
    """Run each plugin over the evidence; one plugin's failure never stops the others."""
    return [_run_one(fs, store, evidence_id, plugin, log, tz) for plugin in plugins]
