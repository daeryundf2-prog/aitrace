from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aitrace.analyzers.attribution import ANALYZER, decide
from aitrace.core import catalog
from aitrace.core.ids import make_id
from aitrace.core.kinds import (
    Actor,
    ArtifactKind,
    ConfidenceBand,
    EventCategory,
    FindingCategory,
    Severity,
    SignalType,
    Verdict,
)
from aitrace.core.model import Artifact, Attribution, Event, Finding, Provenance, Signal
from aitrace.db.store import CaseStore

T0 = datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC)
P = "# 제안서 요약\n\n본 문서는 경쟁사 제안서의 핵심 조건을 정리한 것이다. 가격 조건, 납기, 보증 범위를 비교하였다.\n"
Q = "# 회의록\n\n1. 일정 확정\n2. 예산 검토\n3. 담당자 배정\n"
LONG_TEXT = "the quick brown fox jumps over the lazy dog while the cat sleeps quietly on the warm sofa today"


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _art(aid: str, kind: ArtifactKind, data: dict[str, Any]) -> Artifact:
    return Artifact(
        id=aid,
        kind=kind,
        provenance=Provenance(evidence_id="ev", volume=0, source_path="/src", plugin="p", plugin_version="1.0"),
        data=data,
        user="kim",
    )


def _event(aid: str, ts: datetime, actor: Actor = Actor.AI) -> Event:
    return Event(
        id=make_id("e", aid),
        artifact_id=aid,
        ts_utc=ts,
        ts_kind="k",
        ts_basis="native_utc",
        category=EventCategory.AI_ACTIVITY,
        actor=actor,
        user="kim",
        summary="s",
    )


def _tool_call(aid: str, path: str, content: str | None, ts: datetime) -> list[Artifact | Event]:
    data: dict[str, Any] = {
        "tool": "Claude Code",
        "session_id": "s",
        "call_name": "Write",
        "input": {},
        "file_path": path,
    }
    if content is not None:
        data["content"] = content
    return [_art(aid, ArtifactKind.AI_TOOL_CALL, data), _event(aid, ts)]


def _file(aid: str, path: str, *, content: str | None = None, mtime: datetime | None = None, **extra: Any) -> Artifact:
    data: dict[str, Any] = {"path": path, "size": 1, "is_dir": False, "in_use": True, "source": "stat"}
    if content is not None:
        data["content_sha256"] = _sha(content)
    if mtime is not None:
        data["mtime"] = _iso(mtime)
    data.update(extra)
    return _art(aid, ArtifactKind.FILE_RECORD, data)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[CaseStore]:
    s = CaseStore(tmp_path / "case.sqlite")
    yield s
    s.close()


def _run(store: CaseStore) -> tuple[dict[str, Attribution], list[Finding]]:
    results = list(ANALYZER.run(store, "UTC"))
    attrs = {r.subject: r for r in results if isinstance(r, Attribution)}
    findings = [r for r in results if isinstance(r, Finding)]
    return attrs, findings


def test_exact_agent_write_is_ai_generated_strong(store: CaseStore) -> None:
    store.add(
        [
            *_tool_call("tc1", "C:\\Users\\kim\\work\\proposal.md", P, T0 + timedelta(seconds=20)),
            _file("f1", "/Users/kim/work/proposal.md", content=P, mtime=T0 + timedelta(seconds=21)),
        ]
    )
    attrs, findings = _run(store)
    att = attrs["/Users/kim/work/proposal.md"]
    assert att.verdict is Verdict.AI_GENERATED
    assert att.confidence == pytest.approx(0.90)
    assert att.band is ConfidenceBand.STRONG
    assert [s.type for s in att.signals] == [SignalType.AGENT_TOOL_WRITE]
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.ATTRIBUTION
    assert findings[0].confidence == att.confidence


def test_crlf_copy_of_agent_write_is_still_exact(store: CaseStore) -> None:
    crlf = P.replace("\n", "\r\n")
    store.add(
        [
            *_tool_call("tc1", "/home/alice/a.md", P, T0),
            _file("f1", "/home/alice/a.md", content=crlf, mtime=T0 + timedelta(hours=1), text_sample=crlf),
        ]
    )
    attrs, _ = _run(store)
    att = attrs["/home/alice/a.md"]
    assert att.verdict is Verdict.AI_GENERATED
    assert att.confidence == pytest.approx(0.90)


def test_agent_write_with_later_human_edit_is_ai_assisted(store: CaseStore) -> None:
    edited = Q + "\n사람이 추가한 결론: 예산 10% 삭감.\n"
    store.add(
        [
            *_tool_call("tc2", "C:\\Users\\kim\\work\\edited.md", Q, T0 + timedelta(minutes=2)),
            _file("f2", "/Users/kim/work/edited.md", content=edited, mtime=T0 + timedelta(hours=2)),
        ]
    )
    att = _run(store)[0]["/Users/kim/work/edited.md"]
    assert att.verdict is Verdict.AI_ASSISTED
    assert att.confidence == pytest.approx(0.54)
    assert att.band is ConfidenceBand.MODERATE
    assert {s.type for s in att.signals} == {SignalType.AGENT_TOOL_WRITE, SignalType.HUMAN_EDIT_AFTER}


def test_edit_within_grace_window_is_not_human_edit(store: CaseStore) -> None:
    store.add(
        [
            *_tool_call("tc3", "/w/a.md", Q, T0),
            _file("f3", "/w/a.md", content=Q + "x", mtime=T0 + timedelta(seconds=60)),
        ]
    )
    att = _run(store)[0]["/w/a.md"]
    assert att.verdict is Verdict.AI_GENERATED
    assert att.confidence == pytest.approx(0.54)


def test_file_without_any_signal_is_not_attributed(store: CaseStore) -> None:
    store.add([_file("f4", "/Users/kim/work/notes.txt", content="개인 메모", mtime=T0 - timedelta(days=1))])
    attrs, findings = _run(store)
    assert attrs == {}
    assert findings == []


def test_time_proximity_only_is_undetermined_weak(store: CaseStore) -> None:
    store.add(
        [
            _art("m1", ArtifactKind.AI_CHAT_MESSAGE, {"tool": "ChatGPT", "role": "assistant", "text": "hi"}),
            _event("m1", T0),
            _file("f5", "/Users/kim/out.txt", mtime=T0 + timedelta(seconds=30)),
        ]
    )
    att = _run(store)[0]["/Users/kim/out.txt"]
    assert att.verdict is Verdict.UNDETERMINED
    assert att.band is ConfidenceBand.WEAK
    assert att.confidence == pytest.approx(0.40)
    assert [s.type for s in att.signals] == [SignalType.TIME_PROXIMITY]


def test_time_proximity_does_not_inflate_other_signals(store: CaseStore) -> None:
    store.add(
        [
            *_tool_call("tc6", "/w/p.md", P, T0),
            _file("f6", "/w/p.md", content=P, mtime=T0 + timedelta(seconds=1)),
        ]
    )
    att = _run(store)[0]["/w/p.md"]
    assert att.confidence == pytest.approx(0.90)


def test_media_download_and_filename_signals_combine_to_strong(store: CaseStore) -> None:
    path = "/Users/kim/Downloads/DALL·E 2026-10-01 00.35.00 - a red logo.png"
    store.add(
        [
            _art(
                "mp1",
                ArtifactKind.MEDIA_PROVENANCE,
                {
                    "path": path,
                    "signals": [
                        {"type": "c2pa", "value": "ChatGPT"},
                        {"type": "ai_filename_pattern", "value": "DALL-E"},
                        {"type": "bogus", "value": "ignored"},
                    ],
                },
            ),
            _art(
                "bd1",
                ArtifactKind.BROWSER_DOWNLOAD,
                {
                    "browser": "chrome",
                    "url": "https://files.oaiusercontent.com/x",
                    "target_path": "C:\\Users\\kim\\Downloads\\DALL·E 2026-10-01 00.35.00 - a red logo.png",
                    "ai_service": "ChatGPT",
                },
            ),
        ]
    )
    att = _run(store)[0][path]
    assert att.verdict is Verdict.AI_GENERATED
    assert att.confidence == pytest.approx(0.95)
    assert att.band is ConfidenceBand.STRONG
    assert {s.type for s in att.signals} == {
        SignalType.C2PA,
        SignalType.AI_FILENAME_PATTERN,
        SignalType.AI_DOWNLOAD_ORIGIN,
    }


def test_vcs_ai_trailer_subject_is_repo_and_sha(store: CaseStore) -> None:
    store.add(
        [
            _art(
                "v1",
                ArtifactKind.VCS_COMMIT,
                {
                    "repo_path": "/Users/park/repo",
                    "sha": "abc123",
                    "author": "a",
                    "committer": "a",
                    "message": "m",
                    "trailers": [],
                    "ai_trailer": "Claude Code",
                },
            ),
            _art(
                "v2",
                ArtifactKind.VCS_COMMIT,
                {"repo_path": "/Users/park/repo", "sha": "def456", "author": "a", "committer": "a", "message": "m",
                 "trailers": []},
            ),
        ]
    )
    attrs, _ = _run(store)
    assert list(attrs) == ["/Users/park/repo@abc123"]
    assert attrs["/Users/park/repo@abc123"].verdict is Verdict.AI_GENERATED
    assert attrs["/Users/park/repo@abc123"].confidence == pytest.approx(0.85)


def test_content_match_scales_with_jaccard(store: CaseStore) -> None:
    store.add(
        [
            _art("m2", ArtifactKind.AI_CHAT_MESSAGE, {"tool": "ChatGPT", "role": "assistant", "text": LONG_TEXT}),
            _file("f7", "/Users/kim/essay.txt", text_sample=LONG_TEXT, mtime=T0 - timedelta(days=3)),
            _file("f8", "/Users/kim/other.txt", text_sample="completely unrelated words " * 6,
                  mtime=T0 - timedelta(days=3)),
        ]
    )
    attrs, _ = _run(store)
    assert list(attrs) == ["/Users/kim/essay.txt"]
    att = attrs["/Users/kim/essay.txt"]
    assert att.verdict is Verdict.AI_GENERATED
    assert att.confidence == pytest.approx(0.80)
    assert att.signals[0].type is SignalType.CONTENT_MATCH


def test_metadata_hint_alone_is_undetermined_weak(store: CaseStore) -> None:
    store.add(
        [_art("d1", ArtifactKind.DOC_METADATA, {"path": "/d/a.docx", "hints": [{"type": "x", "value": "Copilot"}]})]
    )
    att = _run(store)[0]["/d/a.docx"]
    assert att.verdict is Verdict.UNDETERMINED
    assert att.band is ConfidenceBand.WEAK


def test_every_attribution_has_catalog_limitations(store: CaseStore) -> None:
    store.add(
        [
            *_tool_call("tc7", "/w/a.md", P, T0),
            _file("f9", "/w/a.md", content=P, mtime=T0),
        ]
    )
    att = _run(store)[0]["/w/a.md"]
    entry = catalog.LIMITATIONS[SignalType.AGENT_TOOL_WRITE]
    assert isinstance(entry, dict)
    assert entry["en"] in att.limitations
    assert att.limitations[-1] == "absence of AI traces does not prove human authorship"


def test_decide_human_authored_requires_human_signal() -> None:
    human = Signal(type=SignalType.HUMAN_PROCESS, direction="human", weight=0.5, artifact_ids=(), note="n")
    assert decide([human]) == (Verdict.HUMAN_AUTHORED, 0.5)
    assert decide([]) == (Verdict.UNDETERMINED, 0.0)


def test_decide_weak_ai_and_human_signal_is_undetermined() -> None:
    human = Signal(type=SignalType.HUMAN_PROCESS, direction="human", weight=0.5, artifact_ids=(), note="n")
    ai = Signal(type=SignalType.METADATA_HINT, direction="ai", weight=0.3, artifact_ids=(), note="n")
    assert decide([human, ai]) == (Verdict.UNDETERMINED, 0.5)


def test_decide_extra_ai_signals_add_bonus_capped() -> None:
    sigs = [
        Signal(type=t, direction="ai", weight=w, artifact_ids=(), note="n")
        for t, w in (
            (SignalType.C2PA, 0.9),
            (SignalType.AI_FILENAME_PATTERN, 0.6),
            (SignalType.AI_DOWNLOAD_ORIGIN, 0.75),
        )
    ]
    verdict, conf = decide(sigs)
    assert verdict is Verdict.AI_GENERATED
    assert conf == pytest.approx(0.95)


def _good_records() -> list[Artifact | Event]:
    return _tool_call("w1", "/Users/kim/work/proposal.md", P, T0)


def _bad_records() -> list[Artifact | Event]:
    wrong_type: dict[str, Any] = {"tool": "Claude Code", "call_name": "Write", "input": {}, "file_path": 123}
    return [
        _art("bad-missing", ArtifactKind.VCS_COMMIT, {"sha": "abc", "ai_trailer": "Claude"}),
        _art("bad-type", ArtifactKind.AI_TOOL_CALL, wrong_type),
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
    assert coverage[0].title == "attribution: skipped 2 malformed artifacts"
    assert coverage[0].data["artifact_ids"] == ["bad-missing", "bad-type"]
