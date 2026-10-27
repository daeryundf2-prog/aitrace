from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

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
from aitrace.core.model import (
    Artifact,
    Attribution,
    Case,
    Event,
    Evidence,
    Finding,
    Provenance,
    Signal,
)
from aitrace.db.store import CaseStore
from aitrace.plugins.base import PluginRunResult
from aitrace.report.i18n import STRINGS, t
from aitrace.report.model import (
    SECTION_KEYS,
    TIMELINE_COLUMNS,
    TIMELINE_LIMIT_HTML,
    TIMELINE_LIMIT_PDF_DOCX,
    ReportModel,
    build_report_model,
)

T0 = datetime(2026, 3, 1, 9, 0, 0, tzinfo=UTC)
APPENDIX_E_ORDER = [
    "case",
    "evidence",
    "tools",
    "methodology",
    "summary",
    "ai_tools",
    "ai_queries",
    "file_lifecycle",
    "exfil",
    "attribution",
    "timeline",
    "exports",
    "coverage",
    "limitations",
    "custody",
    "signature",
    "run",
]


def _case() -> Case:
    return Case(
        id=make_id("case", "T-1"),
        name="Test case",
        number="T-1",
        examiner="QA",
        organisation="Lab",
        created_utc=T0,
        timezone="Asia/Seoul",
        lang="en",
        tool_version="0.1.0",
    )


def _evidence() -> Evidence:
    return Evidence(
        id=make_id("evidence", "win.E01", "abc"),
        kind="e01",
        path="/images/win.E01",
        segments=("/images/win.E01",),
        size=10,
        acquisition_hashes={"md5": "aa"},
        segment_hashes={},
        media_sha256="bb",
        verification_status="match",
    )


def _prov(path: str, plugin: str = "p") -> Provenance:
    return Provenance(evidence_id="ev", volume=0, source_path=path, plugin=plugin, plugin_version="1.0")


def _artifact(kind: ArtifactKind, key: str, data: dict[str, object], path: str, user: str | None = None) -> Artifact:
    return Artifact(
        id=make_id("artifact", kind.value, key),
        kind=kind,
        provenance=_prov(path),
        data=data,
        user=user,
    )


def _event(artifact: Artifact, ts: datetime | None, category: EventCategory, actor: Actor, index: int = 0) -> Event:
    return Event(
        id=make_id(artifact.id, "k", category.value, index),
        artifact_id=artifact.id,
        ts_utc=ts,
        ts_kind="created",
        ts_basis="native_utc",
        category=category,
        actor=actor,
        user="kim",
        summary=f"{category.value}:{artifact.id[:6]}",
    )


@pytest.fixture
def empty_store(tmp_path: Path) -> CaseStore:
    store = CaseStore(tmp_path / "empty.db")
    store.init_case(_case())
    return store


@pytest.fixture
def full_store(tmp_path: Path) -> CaseStore:
    store = CaseStore(tmp_path / "full.db")
    store.init_case(_case())
    store.put_evidence(_evidence())

    prompt = _artifact(
        ArtifactKind.AI_CHAT_MESSAGE,
        "m1",
        {"tool": "Claude Code", "session_id": "s1", "role": "user", "text": "write a script\nsecond line"},
        "/Users/kim/.claude/s1.jsonl",
        "kim",
    )
    reply = _artifact(
        ArtifactKind.AI_CHAT_MESSAGE,
        "m2",
        {"tool": "Claude Code", "session_id": "s1", "role": "assistant", "text": "here it is"},
        "/Users/kim/.claude/s1.jsonl",
        "kim",
    )
    orphan = _artifact(
        ArtifactKind.AI_CHAT_MESSAGE,
        "m3",
        {"tool": "Claude Code", "session_id": "s2", "role": "system", "text": "no event"},
        "/Users/kim/.claude/s2.jsonl",
    )
    credential = _artifact(
        ArtifactKind.AI_CREDENTIAL,
        "c1",
        {"tool": "Claude Code", "provider": "Anthropic", "redacted": "sk-ant-****"},
        "/Users/kim/.zshrc",
        "kim",
    )
    encrypted = _artifact(
        ArtifactKind.AI_APP_PRESENCE,
        "a1",
        {"tool": "ChatGPT Desktop", "kind": "store", "status": "encrypted_not_decoded", "detail": "conversations"},
        "/Users/kim/Library/chatgpt",
        "kim",
    )
    warning = _artifact(
        ArtifactKind.PARSE_WARNING,
        "w1",
        {"plugin": "browser", "message": "bad row", "error": "ValueError"},
        "/Users/kim/History",
    )
    doc = _artifact(
        ArtifactKind.FILE_RECORD,
        "f1",
        {"path": "/Users/kim/proposal.md", "size": 3, "is_dir": False, "in_use": True, "source": "stat"},
        "/Users/kim/proposal.md",
    )
    store.add([prompt, reply, orphan, credential, encrypted, warning, doc])

    e_prompt = _event(prompt, T0 + timedelta(minutes=5), EventCategory.AI_ACTIVITY, Actor.HUMAN)
    e_reply = _event(reply, T0 + timedelta(minutes=6), EventCategory.AI_ACTIVITY, Actor.AI)
    e_file = _event(doc, T0, EventCategory.FILE_MODIFIED, Actor.UNKNOWN)
    e_plain_late = _event(doc, T0 + timedelta(hours=1), EventCategory.FILE_ACCESSED, Actor.HUMAN, index=1)
    e_null = _event(doc, None, EventCategory.OTHER, Actor.UNKNOWN, index=2)
    store.add([e_prompt, e_reply, e_file, e_plain_late, e_null])

    store.add_results(
        [
            Finding(
                id="f-usage",
                category=FindingCategory.AI_TOOL_USAGE,
                severity=Severity.MEDIUM,
                title="Claude Code used",
                narrative="n",
                artifact_ids=(prompt.id,),
                event_ids=(e_prompt.id,),
                confidence=0.9,
                band=ConfidenceBand.STRONG,
                rule_id=None,
                limitations=("usage limitation",),
                data={"tool": "Claude Code", "user": "kim", "count": 2},
            ),
            Finding(
                id="f-life",
                category=FindingCategory.FILE_LIFECYCLE,
                severity=Severity.HIGH,
                title="proposal.md modified",
                narrative="n",
                artifact_ids=(doc.id,),
                event_ids=(e_file.id,),
                confidence=0.7,
                band=ConfidenceBand.MODERATE,
                rule_id="LC-1",
                limitations=("lifecycle limitation",),
                data={"path": "/Users/kim/proposal.md", "deleted": False},
            ),
            Attribution(
                id="at1",
                subject="/Users/kim/proposal.md",
                subject_artifact_ids=(doc.id,),
                verdict=Verdict.AI_GENERATED,
                confidence=0.9,
                band=ConfidenceBand.STRONG,
                signals=(
                    Signal(
                        type=SignalType.AGENT_TOOL_WRITE,
                        direction="ai",
                        weight=0.9,
                        artifact_ids=(prompt.id,),
                        note="exact",
                    ),
                ),
                rationale="r",
                limitations=("attribution limitation",),
            ),
        ]
    )
    store.record_plugin_run(
        PluginRunResult(
            evidence_id="ev",
            name="browser",
            version="1.0",
            status="ok",
            records=3,
            warnings=1,
            error=None,
            started_utc=T0,
            finished_utc=T0 + timedelta(seconds=2),
        )
    )
    store.add_exports(
        [
            {
                "export_path": "export/files/0/a.md",
                "sha256": "cc",
                "size": 3,
                "source_volume": 0,
                "source_path": "/a.md",
                "inode": None,
                "artifact_ids": ["x"],
                "deleted": False,
                "note": "",
            }
        ]
    )
    store.finalize()
    return store


def _build(store: CaseStore, run_info: dict[str, object] | None = None, lang: str = "en") -> ReportModel:
    custody = [{"seq": 1, "actor": "QA", "action": "intake", "detail": "hashed", "ts": "2026-03-01T09:00:00Z"}]
    return build_report_model(
        store, _case(), [_evidence()], custody, run_info or {"case_dir": "/tmp/a"}, "Asia/Seoul", lang
    )


def test_section_keys_order_matches_appendix_e(full_store: CaseStore) -> None:
    model = _build(full_store)
    assert list(SECTION_KEYS) == APPENDIX_E_ORDER
    assert list(model.to_dict()) == APPENDIX_E_ORDER
    assert list(json.loads(model.to_json())) == APPENDIX_E_ORDER


def test_empty_store_gives_empty_lists_and_no_findings_summary(empty_store: CaseStore) -> None:
    model = build_report_model(empty_store, _case(), [], [], {}, "Asia/Seoul", "en")
    for key in ("ai_tools", "ai_queries", "file_lifecycle", "exfil", "attribution", "timeline", "exports"):
        assert getattr(model, key) == []
    assert [q["id"] for q in model.summary] == ["Q1", "Q2", "Q3", "Q4", "Q5"]
    assert all(q["bullets"] == [t("summary.none", "en")] for q in model.summary)
    assert model.coverage["plugin_runs"] == []
    assert model.coverage["parse_warnings"] == []
    assert model.limitations
    model_ko = build_report_model(empty_store, _case(), [], [], {}, "Asia/Seoul", "ko")
    assert model_ko.summary[0]["bullets"] == [t("summary.none", "ko")]


def test_cover_tools_and_methodology(full_store: CaseStore) -> None:
    model = _build(full_store)
    assert model.case["handling_notice"] == "대외비 - 개인정보 포함 / Confidential - contains personal data"
    assert "created_utc" not in model.case
    assert model.run["created_utc"] == "2026-03-01T09:00:00Z"
    assert model.tools["aitrace_version"] == "0.1.0"
    assert {"python", "dissect", "os"} <= set(model.tools)
    standards = " ".join(model.methodology["standards"])
    for needle in ("ISO/IEC 27037", "ISO/IEC 27042", "NIST SP 800-86", "ACPO"):
        assert needle in standards
    validation = model.methodology["tool_validation"]
    assert "validated against the synthetic fixtures documented in docs/validation.md" in validation
    assert "0.1.0" in validation
    assert model.evidence[0]["verification_status"] == "match"
    assert model.evidence[0]["acquisition_hashes"] == {"md5": "aa"}


def test_ai_queries_full_text_and_ordering(full_store: CaseStore) -> None:
    rows = _build(full_store).ai_queries
    assert [r["role"] for r in rows] == ["user", "assistant", "system"]
    assert rows[0]["text"] == "write a script\nsecond line"
    assert rows[0]["actor"] == "human"
    assert rows[1]["actor"] == "ai"
    assert rows[2]["ts_utc"] is None
    assert rows[2]["actor"] == "system"
    assert rows[0]["ts_local"] == "2026-03-01 18:05:00 (+09:00)"
    assert rows[0]["source"] == "/Users/kim/.claude/s1.jsonl"
    assert rows[0]["session"] == "s1"


def test_ai_tools_rows_include_credentials_with_provider(full_store: CaseStore) -> None:
    rows = _build(full_store).ai_tools
    by_kind = {r["kind"]: r for r in rows}
    assert set(by_kind) == {"usage", "presence", "credential"}
    assert by_kind["credential"]["provider"] == "Anthropic"
    assert by_kind["credential"]["detail"] == "sk-ant-****"
    assert by_kind["usage"]["tool"] == "Claude Code"


def test_timeline_order_columns_and_render(full_store: CaseStore) -> None:
    model = _build(full_store)
    assert len(model.timeline) == 5
    assert all(tuple(row) == TIMELINE_COLUMNS for row in model.timeline)
    stamps = [r["ts_utc"] for r in model.timeline]
    assert stamps[-1] is None
    assert stamps[:-1] == sorted(s for s in stamps if s is not None)
    assert model.timeline[0]["source_path"] == "/Users/kim/proposal.md"

    rendered = model.timeline_render(TIMELINE_LIMIT_PDF_DOCX)
    assert len(rendered) == 5
    assert [r["category"] for r in rendered[:3]] == ["file_modified", "ai_activity", "ai_activity"]
    assert {r["category"] for r in rendered[3:]} == {"file_accessed", "other"}
    assert len(model.timeline_render(2)) == 2
    assert model.timeline_note(TIMELINE_LIMIT_HTML, "en") is None
    note = model.timeline_note(2, "en")
    assert note is not None
    assert "report/csv/timeline.csv" in note


def test_summary_findings_attribution_and_limitations(full_store: CaseStore) -> None:
    model = _build(full_store)
    q1 = model.summary[0]["bullets"]
    assert any("Claude Code used" in b for b in q1)
    assert any("proposal.md modified" in b for b in model.summary[2]["bullets"])
    assert model.summary[3]["bullets"] == [t("summary.none", "en")]
    assert any("AI-generated" in b for b in model.summary[4]["bullets"])
    assert model.file_lifecycle[0]["data"]["deleted"] is False
    assert model.attribution[0]["verdict"] == "ai_generated"
    for text in ("usage limitation", "lifecycle limitation", "attribution limitation"):
        assert text in model.limitations
    assert "absence of AI traces does not prove human authorship" in model.limitations


def test_coverage_has_no_top_level_timestamps_and_timings_live_in_run(full_store: CaseStore) -> None:
    model = _build(full_store)
    run_row = model.coverage["plugin_runs"][0]
    assert not {"started_utc", "finished_utc", "started", "finished"} & set(run_row)
    assert run_row["name"] == "browser"
    assert model.coverage["parse_warnings"][0]["message"] == "bad row"
    assert model.coverage["not_decoded"][0]["status"] == "encrypted_not_decoded"
    timing = model.run["plugin_timings"][0]
    assert timing["seconds"] == 2.0
    assert timing["started_utc"] == "2026-03-01T09:00:00Z"


def test_custody_split_between_top_level_and_run(full_store: CaseStore) -> None:
    model = _build(full_store)
    assert model.custody == [{"seq": 1, "actor": "QA", "action": "intake", "detail": "hashed"}]
    assert model.run["custody"][0]["ts"] == "2026-03-01T09:00:00Z"
    assert model.exports[0]["export_path"] == "export/files/0/a.md"


def test_to_json_is_deterministic_except_run(full_store: CaseStore) -> None:
    first = _build(full_store, {"case_dir": "/tmp/a", "started_utc": T0})
    second = _build(full_store, {"case_dir": "/tmp/b", "started_utc": T0 + timedelta(hours=1)})
    assert first.to_json() != second.to_json()
    d1, d2 = first.to_dict(), second.to_dict()
    d1.pop("run")
    d2.pop("run")
    assert d1 == d2
    assert json.dumps(d1, ensure_ascii=False) == json.dumps(d2, ensure_ascii=False)
    assert first.to_json() == _build(full_store, {"case_dir": "/tmp/a", "started_utc": T0}).to_json()


def test_i18n_tables_cover_the_same_keys() -> None:
    assert set(STRINGS["ko"]) == set(STRINGS["en"])
    for key in (f"section.{k}" for k in APPENDIX_E_ORDER if k != "run"):
        assert t(key, "ko") and t(key, "en")
    assert t("section.timeline", "ko") == "통합 타임라인"
    assert t("section.timeline", "xx") == "Super-timeline"
    with pytest.raises(KeyError):
        t("no.such.key", "en")
