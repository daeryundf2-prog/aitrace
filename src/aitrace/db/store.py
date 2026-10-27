from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from aitrace.core.kinds import ArtifactKind, EventCategory, FindingCategory
from aitrace.core.model import Artifact, Attribution, Case, Event, Evidence, Finding
from aitrace.plugins.base import PluginRunResult

BATCH_SIZE = 5000

EXPORT_COLUMNS: tuple[str, ...] = (
    "export_path",
    "sha256",
    "size",
    "source_volume",
    "source_path",
    "inode",
    "artifact_ids",
    "deleted",
    "note",
)

_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_artifact_kind ON artifact(kind)",
    "CREATE INDEX IF NOT EXISTS idx_event_ts ON event(ts_utc)",
    "CREATE INDEX IF NOT EXISTS idx_event_category ON event(category)",
    "CREATE INDEX IF NOT EXISTS idx_artifact_source_path ON artifact(source_path)",
)

_SEVERITY_RANK = "CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"

_INSERT_ARTIFACT = (
    "INSERT OR IGNORE INTO artifact (id, kind, evidence_id, volume, source_path, deleted, user, json) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
)
_INSERT_EVENT = (
    "INSERT OR IGNORE INTO event (id, artifact_id, ts_utc, category, actor, user, json) "
    "VALUES (?, ?, ?, ?, ?, ?, ?)"
)


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _sortable_ts(dt: datetime) -> str:
    """Fixed-width UTC text so lexical order in SQLite equals chronological order."""
    if dt.tzinfo is None:
        raise ValueError(f"naive datetime not allowed: {dt!r}")
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _artifact_row(artifact: Artifact) -> tuple[Any, ...]:
    prov = artifact.provenance
    if not prov.source_path:
        raise ValueError(f"artifact {artifact.id}: provenance.source_path is empty")
    if not prov.plugin_version:
        raise ValueError(f"artifact {artifact.id}: provenance.plugin_version is empty")
    return (
        artifact.id,
        artifact.kind.value,
        prov.evidence_id,
        prov.volume,
        prov.source_path,
        int(prov.deleted),
        artifact.user,
        _dumps(artifact.to_dict()),
    )


def _event_row(event: Event) -> tuple[Any, ...]:
    return (
        event.id,
        event.artifact_id,
        _sortable_ts(event.ts_utc) if event.ts_utc is not None else None,
        event.category.value,
        event.actor.value,
        event.user,
        _dumps(event.to_dict()),
    )


class CaseStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        schema = resources.files("aitrace.db").joinpath("schema.sql").read_text(encoding="utf-8")
        with self._conn:
            self._conn.executescript(schema)

    def init_case(self, case: Case) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO case_info (id, json) VALUES (?, ?)", (case.id, _dumps(case.to_dict()))
            )

    def put_evidence(self, ev: Evidence) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO evidence (id, json) VALUES (?, ?)", (ev.id, _dumps(ev.to_dict()))
            )

    def add(self, records: Iterable[Artifact | Event]) -> int:
        """Insert artifacts/events (duplicates ignored); returns the number of newly inserted rows."""
        inserted = 0
        artifacts: list[tuple[Any, ...]] = []
        events: list[tuple[Any, ...]] = []
        for record in records:
            if isinstance(record, Artifact):
                artifacts.append(_artifact_row(record))
            elif isinstance(record, Event):
                events.append(_event_row(record))
            else:
                raise TypeError(f"CaseStore.add accepts Artifact or Event, got {type(record).__name__}")
            if len(artifacts) + len(events) >= BATCH_SIZE:
                inserted += self._flush(artifacts, events)
                artifacts, events = [], []
        if artifacts or events:
            inserted += self._flush(artifacts, events)
        return inserted

    def _flush(self, artifacts: list[tuple[Any, ...]], events: list[tuple[Any, ...]]) -> int:
        before = self._conn.total_changes
        with self._conn:
            if artifacts:
                self._conn.executemany(_INSERT_ARTIFACT, artifacts)
            if events:
                self._conn.executemany(_INSERT_EVENT, events)
        return self._conn.total_changes - before

    def add_results(self, items: Iterable[Finding | Attribution]) -> None:
        with self._conn:
            for item in items:
                if isinstance(item, Finding):
                    self._conn.execute(
                        "INSERT OR REPLACE INTO finding (id, category, severity, json) VALUES (?, ?, ?, ?)",
                        (item.id, item.category.value, item.severity.value, _dumps(item.to_dict())),
                    )
                elif isinstance(item, Attribution):
                    self._conn.execute(
                        "INSERT OR REPLACE INTO attribution (id, subject, verdict, json) VALUES (?, ?, ?, ?)",
                        (item.id, item.subject, item.verdict.value, _dumps(item.to_dict())),
                    )
                else:
                    raise TypeError(
                        f"CaseStore.add_results accepts Finding or Attribution, got {type(item).__name__}"
                    )

    def record_plugin_run(self, result: PluginRunResult) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO plugin_run (evidence_id, name, version, status, records, warnings, "
                "error, started, finished) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    result.evidence_id,
                    result.name,
                    result.version,
                    result.status,
                    result.records,
                    result.warnings,
                    result.error,
                    _sortable_ts(result.started_utc),
                    _sortable_ts(result.finished_utc),
                ),
            )

    def add_exports(self, entries: Iterable[dict[str, Any]]) -> None:
        rows: list[tuple[Any, ...]] = []
        for entry in entries:
            if set(entry) != set(EXPORT_COLUMNS):
                raise ValueError(f"export entry keys must be exactly {EXPORT_COLUMNS}, got {sorted(entry)}")
            row = dict(entry)
            row["artifact_ids"] = _dumps(list(entry["artifact_ids"]))
            row["deleted"] = int(bool(entry["deleted"]))
            rows.append(tuple(row[c] for c in EXPORT_COLUMNS))
        placeholders = ", ".join("?" for _ in EXPORT_COLUMNS)
        with self._conn:
            self._conn.executemany(
                f"INSERT OR REPLACE INTO export ({', '.join(EXPORT_COLUMNS)}) VALUES ({placeholders})", rows
            )

    def exports(self) -> list[dict[str, Any]]:
        cursor = self._conn.execute(f"SELECT {', '.join(EXPORT_COLUMNS)} FROM export ORDER BY export_path")
        result: list[dict[str, Any]] = []
        for values in cursor.fetchall():
            entry = dict(zip(EXPORT_COLUMNS, values, strict=True))
            entry["artifact_ids"] = json.loads(entry["artifact_ids"])
            entry["deleted"] = bool(entry["deleted"])
            result.append(entry)
        return result

    def finalize(self) -> None:
        with self._conn:
            for statement in _INDEXES:
                self._conn.execute(statement)

    def case(self) -> Case | None:
        row = self._conn.execute("SELECT json FROM case_info ORDER BY id LIMIT 1").fetchone()
        return Case.from_dict(json.loads(row[0])) if row else None

    def evidences(self) -> list[Evidence]:
        rows = self._conn.execute("SELECT json FROM evidence ORDER BY id").fetchall()
        return [Evidence.from_dict(json.loads(r[0])) for r in rows]

    def artifacts(
        self, kind: ArtifactKind | None = None, kinds: Iterable[ArtifactKind] | None = None
    ) -> Iterator[Artifact]:
        wanted: list[str] = []
        if kind is not None:
            wanted.append(ArtifactKind(kind).value)
        if kinds is not None:
            wanted.extend(ArtifactKind(k).value for k in kinds)
        if kind is None and kinds is None:
            cursor = self._conn.execute("SELECT json FROM artifact ORDER BY id")
        else:
            marks = ", ".join("?" for _ in wanted)
            cursor = self._conn.execute(
                f"SELECT json FROM artifact WHERE kind IN ({marks}) ORDER BY id", tuple(wanted)
            )
        for (blob,) in cursor:
            yield Artifact.from_dict(json.loads(blob))

    def artifact(self, id: str) -> Artifact | None:
        row = self._conn.execute("SELECT json FROM artifact WHERE id = ?", (id,)).fetchone()
        return Artifact.from_dict(json.loads(row[0])) if row else None

    def events(
        self,
        category: EventCategory | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> Iterator[Event]:
        """Ordered by ts_utc (NULLs last) then id; `start` and `end` are inclusive bounds."""
        clauses: list[str] = []
        params: list[Any] = []
        if category is not None:
            clauses.append("category = ?")
            params.append(EventCategory(category).value)
        if start is not None:
            clauses.append("ts_utc >= ?")
            params.append(_sortable_ts(start))
        if end is not None:
            clauses.append("ts_utc <= ?")
            params.append(_sortable_ts(end))
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        cursor = self._conn.execute(
            f"SELECT json FROM event {where}ORDER BY ts_utc IS NULL, ts_utc, id", tuple(params)
        )
        for (blob,) in cursor:
            yield Event.from_dict(json.loads(blob))

    def findings(self, category: FindingCategory | None = None) -> list[Finding]:
        order = f"ORDER BY category, {_SEVERITY_RANK} DESC, id"
        if category is None:
            rows = self._conn.execute(f"SELECT json FROM finding {order}").fetchall()
        else:
            rows = self._conn.execute(
                f"SELECT json FROM finding WHERE category = ? {order}", (FindingCategory(category).value,)
            ).fetchall()
        return [Finding.from_dict(json.loads(r[0])) for r in rows]

    def attributions(self) -> list[Attribution]:
        rows = self._conn.execute("SELECT json FROM attribution ORDER BY subject, id").fetchall()
        return [Attribution.from_dict(json.loads(r[0])) for r in rows]

    def plugin_runs(self) -> list[PluginRunResult]:
        rows = self._conn.execute(
            "SELECT evidence_id, name, version, status, records, warnings, error, started, finished "
            "FROM plugin_run ORDER BY evidence_id, name"
        ).fetchall()
        return [
            PluginRunResult(
                evidence_id=r[0],
                name=r[1],
                version=r[2],
                status=r[3],
                records=r[4],
                warnings=r[5],
                error=r[6],
                started_utc=datetime.fromisoformat(r[7]),
                finished_utc=datetime.fromisoformat(r[8]),
            )
            for r in rows
        ]

    def counts(self) -> dict[str, int]:
        """One key per ArtifactKind value (0 when absent) plus "events", "findings", "attributions"."""
        result = {kind.value: 0 for kind in ArtifactKind}
        for kind, n in self._conn.execute("SELECT kind, COUNT(*) FROM artifact GROUP BY kind"):
            result[kind] = n
        for table, key in (("event", "events"), ("finding", "findings"), ("attribution", "attributions")):
            result[key] = self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return result

    def close(self) -> None:
        self._conn.close()
