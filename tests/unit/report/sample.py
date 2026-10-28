from __future__ import annotations

import re
from functools import partial
from typing import Any

from aitrace.report.i18n import t
from aitrace.report.model import ReportModel

KO_CHAPTERS = [
    "제1장 개요",
    "제2장 분석결과 요약",
    "제3장 프롬프트(질의·응답)",
    "제4장 생성물",
    "제5장 타임라인",
    "제6장 파일 생성·변경·삭제 내역",
    "제7장 반출·원격·전송 경로",
    "제8장 분석의 한계 및 미해석 항목",
    "제9장 감정(분석) 의견",
    "별첨1 추출 자료 목록(해시)",
    "별첨2 증거물 관리 이력",
    "별첨3 서명",
]

BANNED_WORDS = ("핵심", "전수", "종합적으로", "결론적으로 살펴보면", "놀랍게도", "매우", "반드시 확인", "한눈에", "!")
ENGLISH_PREFIXES = (
    "File created: ",
    "File modified: ",
    "File deleted",
    "Amcache: ",
    "SRUM: ",
    "Prefetch: ",
    "Chrome visit:",
    "Chrome download:",
    "AI image viewed (cache)",
    "Claude Code tool call:",
)
_EMOJI = re.compile("[\U0001f000-\U0001faff\u2600-\u27bf\u2190-\u21ff\u2b00-\u2bff\u2460-\u24ff\u2605\u2713\u2714]")


def find_banned(text: str) -> list[str]:
    found = [word for word in BANNED_WORDS if word in text]
    found += [prefix for prefix in ENGLISH_PREFIXES if prefix in text]
    found += sorted(set(_EMOJI.findall(text)))
    return found


def _query(
    lang: str, tool: str, session: str, role: str, clock: str, text: str, source: str | None = None
) -> dict[str, Any]:
    day, time = "2026-03-01", clock
    return {
        "ts_utc": f"{day} {time} UTC",
        "ts_local": f"{day} {time} (+09:00)",
        "tool": tool,
        "session": session,
        "role": role,
        "role_label": t(f"role.{role}", lang),
        "actor": "human" if role == "user" else "ai",
        "text": text,
        "source": source or f"/Users/kim/.{tool}/{session}.jsonl",
        "source_name": f"{session}.jsonl",
        "artifact_id": f"{tool}-{session}-{clock}",
        "fragment": False,
    }


def _event(lang: str, local: str | None, summary: str, category: str = "file_modified") -> dict[str, Any]:
    return {
        "ts_utc": None,
        "ts_local": local,
        "category": category,
        "category_label": t(f"category.{category}", lang),
        "actor": "unknown",
        "actor_label": t("actor.unknown", lang),
        "user": "kim",
        "summary": summary,
        "source_path": "/Users/kim/proposal.md",
        "artifact_id": "a1",
    }


def make_model(lang: str = "ko", prompt: str = "경쟁사 제안서를 요약해줘") -> ReportModel:
    q = partial(_query, lang)
    queries = [
        q("Claude Code", "s1", "system", "09:00:00", "당신은 보조 개발자임"),
        q("Claude Code", "s1", "user", "09:05:00", prompt),
        q("Claude Code", "s1", "assistant", "09:06:00", "작성하겠음"),
        q("Codex", "s2", "user", "08:00:00", "다른 도구 질의"),
        q("Claude Code", "s0", "user", "07:00:00", "이른 세션 질의"),
    ]
    tool_call = q("Claude Code", "s1", "assistant", "09:07:00", "호출 도구 Write, 대상 경로 /Users/kim/proposal.md")
    tool_call.update(role="tool_call", role_label=t("prompts.tool_call", lang), call_name="Write")
    instruction = {
        "ts_utc": None,
        "ts_local": None,
        "tool": "Claude Code",
        "session": None,
        "role": "instruction",
        "role_label": t("prompts.instruction", lang),
        "text": "Claude Code의 지시문 관련 설정으로 확인됨: CLAUDE.md",
        "source": "/Users/kim/repo/CLAUDE.md",
        "artifact_id": "p1",
    }
    return ReportModel(
        case={
            "id": "case1",
            "name": "샘플 사건",
            "number": "T-1",
            "examiner": "홍길동",
            "organisation": "포렌식 연구소",
            "timezone": "Asia/Seoul",
            "lang": lang,
            "tool_version": "0.1.0",
            "notes": "",
            "handling_notice": t("handling_notice", lang),
            "document_number": "T-1-01",
        },
        evidence=[
            {
                "id": "ev1",
                "kind": "e01",
                "path": "/images/win.E01",
                "size": 1234,
                "acquisition_hashes": {},
                "segment_hashes": {"win.E01": {"md5": "aa", "sha1": "bb", "sha256": "cc"}},
                "media_sha256": "dd",
                "verification_status": "match",
                "verification_label": t("verification.match", lang),
                "limitations": [],
                "limitations_display": [],
                "volumes": [{"index": 0, "fs_type": "NtfsFilesystem", "label": "WIN", "os_family": "windows"}],
                "users": [{"name": "kim"}],
            }
        ],
        tools={"aitrace_version": "0.1.0", "python": "3.12", "dissect": {"dissect.target": "3.25"}, "os": "Darwin"},
        methodology={
            "paragraphs": [t("methodology.p1", lang)],
            "standards_intro": t("methodology.standards_intro", lang),
            "standards": ["ISO/IEC 27037"],
            "tool_validation": "도구 검증 문장임",
        },
        summary=[],
        ai_tools=[
            {
                "kind": "cli",
                "kind_label": t("kind.cli", lang),
                "tool": "Claude Code",
                "users": ["kim"],
                "first_seen_local": "2026-03-01 16:00:00 (+09:00)",
                "last_seen_local": "2026-03-01 18:07:00 (+09:00)",
                "evidence_count": 3,
            }
        ],
        ai_queries=queries,
        file_lifecycle=[
            {
                "display_path": "/Users/kim/proposal.md",
                "display_steps": ["2026-03-01 18:00:00 (+09:00) 생성", "2026-03-01 19:00:00 (+09:00) 삭제"],
                "links_summary": t("link.none", lang),
                "data": {"lifecycle": [{"event": "created"}, {"event": "deleted"}]},
            }
        ],
        exfil=[
            {
                "display_channel": "scp \u2192 203.0.113.10",
                "ts_local": "2026-03-01 18:20:00 (+09:00)",
                "actor_label": t("actor.human", lang),
                "user": "kim",
                "source_name": "proposal.md",
            }
        ],
        attribution=[],
        timeline=[
            _event(lang, "2026-03-01 18:00:00 (+09:00)", "수정됨"),
            _event(lang, "2026-03-01 19:00:00 (+09:00)", "삭제됨", "file_deleted"),
            _event(lang, "2026-03-02 09:00:00 (+09:00)", "접근됨", "file_accessed"),
            _event(lang, None, "시각 없음", "other"),
        ],
        exports=[{"export_path": "export/files/0/a.md", "size": 3, "sha256": "ee"}],
        coverage={
            "plugin_runs": [
                {"name": "browser", "version": "1.0", "status": "ok", "records": 3, "warnings": 0, "error": None}
            ],
            "parse_warnings": [],
            "not_decoded": [
                {"tool": "ChatGPT Desktop", "status": "encrypted_not_decoded", "detail": "conversations", "source_path": "/x"}
            ],
            "findings": [],
        },
        limitations=["전역 한계 문구임"],
        custody=[{"seq": 1, "actor": "QA", "action": "case_opened", "detail": {"case_number": "T-1"}}],
        signature={"examiner": "홍길동", "organisation": "포렌식 연구소", "signature": "", "date": ""},
        run={
            "created_utc": "2026-03-02T00:00:00Z",
            "custody": [
                {
                    "seq": 1,
                    "actor": "QA",
                    "action": "case_opened",
                    "detail": {"case_number": "T-1"},
                    "ts_utc": "2026-03-01T09:00:00Z",
                }
            ],
        },
        tool_calls=[tool_call],
        instructions=[instruction],
        generated_files=[
            {
                "attribution_id": "at1",
                "subject": "/Users/kim/proposal.md",
                "verdict": "ai_generated",
                "verdict_label": t("verdict.ai_generated", lang),
                "confidence": 0.9,
                "confidence_display": "0.90 (강함)",
                "signals_summary": "에이전트 파일 기록 (AI)",
                "origin": ["도구 호출: Claude Code Write, 세션 s1, 2026-03-01 18:07:00 (+09:00)"],
                "limitations_display": ["한계 하나"],
            }
        ],
    )
