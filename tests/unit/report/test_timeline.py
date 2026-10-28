from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import Any

import pytest

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory
from aitrace.core.model import Artifact, Event, Provenance
from aitrace.report.html import render_html_string
from aitrace.report.timeline import Focus, display_summary, focus_paths, is_relevant

from . import sample
from .test_html import _visible_text

TS = datetime(2026, 3, 1, 9, 0, tzinfo=UTC)
ATTRIBUTED = "C:/Users/kim/proposal.md"


def _artifact(kind: ArtifactKind, **data: Any) -> Artifact:
    prov = Provenance(evidence_id="e", volume=0, source_path="/src", plugin="p", plugin_version="1")
    return Artifact(id=f"a-{kind.value}", kind=kind, provenance=prov, data=data)


def _event(
    category: EventCategory,
    summary: str = "raw",
    *,
    actor: Actor = Actor.SYSTEM,
    subject: str | None = None,
    artifact: Artifact | None = None,
    data: dict[str, Any] | None = None,
) -> Event:
    return Event(
        id="ev",
        artifact_id=artifact.id if artifact else "a-none",
        ts_utc=TS,
        ts_kind="k",
        ts_basis="native_utc",
        category=category,
        actor=actor,
        user=None,
        summary=summary,
        subject=subject,
        data=data or {},
    )


FOCUS = Focus(
    paths=focus_paths([ATTRIBUTED], [_artifact(ArtifactKind.AI_TOOL_CALL, file_path="/tmp/out.py")])
)
INVENTORY = _artifact(ArtifactKind.FILE_RECORD, path="C:/Windows/x.dll")
VISIT = _artifact(ArtifactKind.BROWSER_VISIT, browser="Chrome", url="https://example.com")
AI_VISIT = _artifact(
    ArtifactKind.BROWSER_VISIT, browser="Chrome", url="https://claude.ai", ai_service="Claude"
)
SHELL_PLAIN = _artifact(ArtifactKind.SHELL_COMMAND, tags=[])
SHELL_TRANSFER = _artifact(ArtifactKind.SHELL_COMMAND, tags=["transfer"])
AMCACHE = _artifact(ArtifactKind.EXECUTION, source="amcache", program="calc.exe")
AMCACHE_AI = _artifact(ArtifactKind.EXECUTION, source="amcache", program="claude.exe", ai_tool="Claude Code")


@pytest.mark.parametrize(
    ("event", "artifact", "expected"),
    [
        (_event(EventCategory.AI_ACTIVITY), None, True),
        (_event(EventCategory.OTHER, actor=Actor.AI), None, True),
        (_event(EventCategory.FILE_DELETED, subject="C:/tmp/z"), INVENTORY, True),
        (_event(EventCategory.TRANSFER), SHELL_TRANSFER, True),
        (_event(EventCategory.REMOTE_ACCESS), None, True),
        (_event(EventCategory.DEVICE), None, True),
        (_event(EventCategory.FILE_CREATED, subject="C:/Windows/x.dll"), INVENTORY, False),
        (_event(EventCategory.FILE_CREATED, subject="c:\\Users\\kim\\Proposal.md"), INVENTORY, True),
        (_event(EventCategory.FILE_MODIFIED, subject="/tmp/out.py"), INVENTORY, True),
        (_event(EventCategory.BROWSING, subject="https://example.com"), VISIT, False),
        (_event(EventCategory.BROWSING, subject="https://claude.ai"), AI_VISIT, True),
        (_event(EventCategory.BROWSING, subject="u"), _artifact(ArtifactKind.MEDIA_PROVENANCE), True),
        (_event(EventCategory.DOWNLOAD, data={"ai_service": "Claude"}), None, True),
        (_event(EventCategory.EXECUTION), SHELL_PLAIN, False),
        (_event(EventCategory.EXECUTION), SHELL_TRANSFER, True),
        (_event(EventCategory.EXECUTION), AMCACHE, False),
        (_event(EventCategory.EXECUTION), AMCACHE_AI, True),
        (_event(EventCategory.OTHER), None, False),
    ],
)
def test_relevance_filter(event: Event, artifact: Artifact | None, expected: bool) -> None:
    assert is_relevant(event, artifact, FOCUS) is expected


@pytest.mark.parametrize(
    ("event", "artifact", "expected"),
    [
        (_event(EventCategory.FILE_CREATED, "File created: /a", subject="/a"), INVENTORY, "파일 생성: /a"),
        (_event(EventCategory.FILE_MODIFIED, "File modified: /a", subject="/a"), INVENTORY, "파일 수정: /a"),
        (_event(EventCategory.FILE_DELETED, "File deleted: /a", subject="/a"), INVENTORY, "파일 삭제: /a"),
        (_event(EventCategory.EXECUTION, "Amcache: calc.exe recorded"), AMCACHE, "Amcache 기록: calc.exe"),
        (
            _event(EventCategory.EXECUTION, "SRUM: a resource usage"),
            _artifact(ArtifactKind.EXECUTION, source="srum", program="a.exe"),
            "SRUM 자원 사용: a.exe",
        ),
        (
            _event(EventCategory.EXECUTION, "Prefetch: a executed"),
            _artifact(ArtifactKind.EXECUTION, source="prefetch", program="a.exe"),
            "Prefetch 실행: a.exe",
        ),
        (_event(EventCategory.BROWSING, "Chrome visit: u"), VISIT, "Chrome 방문: https://example.com"),
        (
            _event(EventCategory.DOWNLOAD, "Chrome download: u -> t"),
            _artifact(ArtifactKind.BROWSER_DOWNLOAD, browser="Chrome", url="https://u", target_path="C:/t"),
            "Chrome 다운로드: https://u -> C:/t",
        ),
        (
            _event(EventCategory.BROWSING, "AI image viewed (cache): u", subject="https://img"),
            _artifact(ArtifactKind.MEDIA_PROVENANCE),
            "브라우저 캐시의 AI 이미지: https://img",
        ),
        (
            _event(EventCategory.AI_ACTIVITY, "Claude Code tool call: Write", actor=Actor.AI),
            _artifact(ArtifactKind.AI_TOOL_CALL, tool="Claude Code", call_name="Write", file_path="/a.py"),
            "Claude Code 도구 실행: Write /a.py",
        ),
    ],
)
def test_ko_summaries_come_from_templates(event: Event, artifact: Artifact, expected: str) -> None:
    assert display_summary(event, artifact, "ko") == expected
    assert display_summary(event, artifact, "en") == event.summary


def test_days_collapse_to_one_row_and_html_has_no_english_prefix() -> None:
    base = sample.make_model("ko")
    n = len(base.timeline)
    model = dataclasses.replace(
        base,
        timeline_relevant=tuple(i == 0 for i in range(n)),
        timeline_text=tuple("파일 수정: /a" for _ in range(n)),
    )
    days = dict(model.timeline_days(100))
    collapsed = [r for rows in days.values() for r in rows if r.get("collapsed")]
    assert len(collapsed) == len(days)
    assert sum(r["count"] for r in collapsed) == n - 1
    assert "기타 시스템 기록" in collapsed[0]["summary"]
    assert "report/csv/timeline.csv" in collapsed[0]["summary"]
    assert model.timeline == base.timeline
    assert sample.find_banned(_visible_text(render_html_string(model))) == []
