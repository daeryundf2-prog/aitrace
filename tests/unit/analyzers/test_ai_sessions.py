from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aitrace.analyzers.ai_sessions import ANALYZER
from aitrace.core.ids import make_id
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, FindingCategory, Severity
from aitrace.core.model import Artifact, Event, Finding, Provenance
from aitrace.db.store import CaseStore

T0 = datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[CaseStore]:
    case_store = CaseStore(tmp_path / "case.sqlite")
    yield case_store
    case_store.close()


def _art(aid: str, kind: ArtifactKind, data: dict[str, Any], user: str | None = "kim") -> Artifact:
    return Artifact(
        id=aid,
        kind=kind,
        provenance=Provenance(evidence_id="ev", volume=0, source_path="/src", plugin="p", plugin_version="1.0"),
        data=data,
        user=user,
    )


def _event(aid: str, ts: datetime) -> Event:
    return Event(
        id=make_id("e", aid),
        artifact_id=aid,
        ts_utc=ts,
        ts_kind="k",
        ts_basis="native_utc",
        category=EventCategory.AI_ACTIVITY,
        actor=Actor.HUMAN,
        user="kim",
        summary="s",
    )


def _prompt(aid: str, ts: datetime, text: str, session_id: str | None) -> list[Artifact | Event]:
    data: dict[str, Any] = {
        "tool": "Claude Code",
        "session_id": session_id,
        "role": "user",
        "text": text,
        "fragment": False,
    }
    return [_art(aid, ArtifactKind.AI_CHAT_MESSAGE, data), _event(aid, ts)]


def _findings(store: CaseStore, category: FindingCategory) -> list[Finding]:
    return [
        item
        for item in ANALYZER.run(store, "UTC")
        if isinstance(item, Finding) and item.category is category
    ]


def test_three_prompts_in_one_session_yield_one_query_finding(store: CaseStore) -> None:
    store.add(
        [
            *_prompt("p1", T0, "파이썬 함수 작성해줘 with a bug fix", "s1"),
            *_prompt("p2", T0 + timedelta(minutes=1), "write an email summary", "s1"),
            *_prompt("p3", T0 + timedelta(minutes=2), "what is a regex", "s1"),
        ]
    )

    queries = _findings(store, FindingCategory.AI_QUERY)
    usage = _findings(store, FindingCategory.AI_TOOL_USAGE)

    assert len(queries) == 1
    assert queries[0].title == "파이썬 함수 작성해줘 with a bug fix"
    assert queries[0].data["prompt_count"] == 3
    assert queries[0].data["tasks"] == ["TASK-CODE", "TASK-SEARCH", "TASK-WRITE"]
    assert len(usage) == 1
    row = usage[0].data["inventory"][0]
    assert usage[0].data["providers"] == ["Claude Code"]
    assert row["tool"] == "Claude Code"
    assert row["kind"] == "cli"
    assert row["users"] == ["kim"]
    assert row["evidence_count"] == 3
    assert row["first_seen"] == "2026-10-01T01:00:00Z"
    assert row["last_seen"] == "2026-10-01T01:02:00Z"


def test_store_without_ai_artifacts_yields_no_findings(store: CaseStore) -> None:
    store.add([_art("sh1", ArtifactKind.SHELL_COMMAND, {"shell": "bash", "command": "ls", "tags": [], "rule_ids": []})])

    assert list(ANALYZER.run(store, "UTC")) == []


def test_credential_rows_use_provider_as_tool(store: CaseStore) -> None:
    store.add([_art("c1", ArtifactKind.AI_CREDENTIAL, {"provider": "OpenAI", "redacted": "sk-...abcd"})])

    usage = _findings(store, FindingCategory.AI_TOOL_USAGE)

    assert usage[0].data["providers"] == ["OpenAI"]
    assert usage[0].data["inventory"][0]["tool"] == "OpenAI"
    assert usage[0].data["inventory"][0]["kind"] == "credential"
    assert _findings(store, FindingCategory.AI_QUERY) == []


def test_prompts_without_session_id_split_after_thirty_minutes(store: CaseStore) -> None:
    store.add(
        [
            *_prompt("p1", T0, "code review please", None),
            *_prompt("p2", T0 + timedelta(minutes=45), "translate this", None),
        ]
    )

    queries = _findings(store, FindingCategory.AI_QUERY)

    assert len(queries) == 2
    assert [q.data["prompt_count"] for q in queries] == [1, 1]


def _good_records() -> list[Artifact | Event]:
    return _prompt("p1", T0, "write an email summary", "s1")


def _bad_records() -> list[Artifact | Event]:
    base: dict[str, Any] = {"tool": "Claude Code", "session_id": "s1"}
    return [
        _art("bad-missing", ArtifactKind.AI_CHAT_MESSAGE, {**base, "text": "no role key"}),
        _art("bad-type", ArtifactKind.AI_CHAT_MESSAGE, {**base, "role": "user", "text": 123}),
    ]



def test_malformed_artifacts_are_skipped_and_reported(store: CaseStore) -> None:
    store.add(_good_records())
    baseline = list(ANALYZER.run(store, "UTC"))
    assert not [f for f in baseline if isinstance(f, Finding) and f.category is FindingCategory.COVERAGE]

    store.add(_bad_records())
    result = list(ANALYZER.run(store, "UTC"))  # must not raise

    coverage = [f for f in result if isinstance(f, Finding) and f.category is FindingCategory.COVERAGE]
    assert [item for item in result if item not in coverage] == baseline
    assert len(coverage) == 1
    assert coverage[0].severity is Severity.LOW
    assert coverage[0].title == "ai_sessions: skipped 2 malformed artifacts"
    assert coverage[0].data["artifact_ids"] == ["bad-missing", "bad-type"]
