"""Human-typed questions: separates what a person typed from agent, gateway and system text stored as role 'user'.

Agent stores record more than the person's own words under the user role: messaging-gateway framing,
context-compaction handoffs, runtime notices, agent-to-agent (A2A) traffic and scheduled job prompts.
The report shows the person's questions on their own, so each user row is classified, cleaned and,
when the same text was recorded twice at the same moment, counted once.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from aitrace.core import catalog

HUMAN = "human"
EXCLUDED_KINDS: tuple[str, ...] = ("compaction", "system_notice", "a2a", "automated", "loop", "empty")
# A scheduled job or batch script sends the same long instruction once per fresh session; a person who resends
# a message does so inside one session. Text this long, opening identically in this many different sessions,
# and alone in its session this often, is counted as an automated loop rather than a typed question.
LOOP_MIN_CHARS = 100
LOOP_PREFIX_CHARS = 50
LOOP_MIN_SESSIONS = 5
LOOP_MIN_SOLO_SHARE = 0.8

_GATEWAY = re.compile(
    r"(?:Gateway message origin \(JSON data[^)]*\):\s*)?(\{[^{}]*\})?\s*"
    r"Do not guess a reply destination when these fields are insufficient\.\s*",
    re.DOTALL,
)
_OOB_MARKERS = re.compile(r"\s*\[/?OUT-OF-BAND USER MESSAGE[^\]]*\]\s*")
_COMPACTION = re.compile(
    r"\[(?:CONTEXT COMPACTION|Your active task list was preserved|System note:|ASYNC DELEGATION"
    r"|Continuing toward your standing goal)"
)
_AGENT_REPORT = re.compile(
    r"^\s*\[(?:ASYNC DELEGATION|IMPORTANT:|System note:|Continuing toward your standing goal"
    r"|Your active task list was preserved)"
)
_FRAMEWORK_NOTICE = re.compile(
    r"^\s*(?:You've reached the maximum number of tool-calling iterations"
    r"|Your previous final response was rejected by the output contract validator"
    r"|You just executed tool calls but returned an empty response)"
)
_GATEWAY_GENERATED = re.compile(r"\[INTERNAL NOTIFICATION [^\]]*not written by a human user")
_SKILL_INVOKED = re.compile(
    r'^\s*\[IMPORTANT: The user has invoked the "(?P<skill>[^"]+)" skill[^\]]*\]', re.DOTALL
)
_DOCUMENT = re.compile(r"\[The user sent a document: '(?P<name>[^']*)'[^\]]*\]\s*")
_IMAGE_NOTES = re.compile(
    r"\[(?:If you need a closer look, use vision_analyze[^\]]*|The user sent an image[^\]]*)\]\s*"
)
_CORRECTION = re.compile(r"\[Additional user correction\]\s*")
_AGENT_PREFIX = re.compile(r"^\s*\[(?:STILL IN PROGRESS|PRIOR CONTEXT)[^\]]*\]\s*")
_REPLY_QUOTE = re.compile(r'\[Replying to: ".*?"\]\s*', re.DOTALL)
_SYSTEM_NOTICE = re.compile(r"\s*\[System:[^\]]*\]\s*")
_EXPORT_NAME = re.compile(r"^(?P<machine>.+?)_(?:사용자입력|사용자_입력|시스템프롬프트)_")
_A2A = re.compile(r"^\s*\[A2A (?:inbound|outbound)")
_ATTACHMENT = re.compile(r"^\s*\[The user (?:attached|sent) [^\]]*\]\s*")
_AUTOMATED_NAMES = re.compile(r"^(?:jobs\.json.*|kanban\.db|executions\.db|deliveries\.db|cron\.db)$")
_AUTOMATED_DIRS = ("/cron/", "/a2a_conversations/")


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def machine_of(source: str, tool: str | None = None) -> str:
    name = _basename(source)
    match = _EXPORT_NAME.match(name)
    if match:
        return match.group("machine").replace("_", " ")
    return tool or name


def normalise(text: str, source: str = "") -> tuple[str, str, str | None, bool]:
    """Return (kind, cleaned text, gateway platform or None, attachment noted) for one user-role row."""
    norm_source = source.replace("\\", "/")
    if _AUTOMATED_NAMES.match(_basename(norm_source)) or any(d in norm_source for d in _AUTOMATED_DIRS):
        return ("a2a" if "/a2a_conversations/" in norm_source else "automated"), text.strip(), None, False
    body = _OOB_MARKERS.sub("\n", text)
    platform: str | None = None
    for gateway in list(_GATEWAY.finditer(body)):
        try:
            origin = json.loads(gateway.group(1)) if gateway.group(1) else {}
        except json.JSONDecodeError:
            origin = {}
        if platform is None and isinstance(origin, dict) and origin.get("platform"):
            platform = str(origin["platform"])
    body = _GATEWAY.sub("\n", body).strip()
    skill = _SKILL_INVOKED.match(body)
    if skill is not None:
        return HUMAN, f"(스킬 실행 요청: {skill.group('skill')})", platform, False
    if _AGENT_REPORT.match(body) or _GATEWAY_GENERATED.search(body) or _FRAMEWORK_NOTICE.match(body):
        return "system_notice", body, platform, False
    attachment = False
    documents = [m.group("name") for m in _DOCUMENT.finditer(body)]
    if documents or _IMAGE_NOTES.search(body):
        attachment = True
        body = _IMAGE_NOTES.sub("", _DOCUMENT.sub("", body))
        body = "\n".join([*(f"(문서 첨부: {name})" for name in documents), body.strip()]).strip()
    body = _CORRECTION.sub("", body)
    while (prefix := _AGENT_PREFIX.match(body)) is not None:
        body = body[prefix.end() :]
    body = _REPLY_QUOTE.sub("", body).strip()
    compaction = _COMPACTION.search(body)
    if compaction is not None:
        if not body[: compaction.start()].strip():
            return "compaction", body, platform, False
        body = body[: compaction.start()].strip()
    if _A2A.match(body):
        return "a2a", body, platform, False
    if _SYSTEM_NOTICE.search(body) is not None:
        body = _SYSTEM_NOTICE.sub("\n", body).strip()
        if not body:
            return "system_notice", "", platform, False
    attached = _ATTACHMENT.match(body)
    if attached is not None:
        attachment = True
        body = body[attached.end() :].strip()
    if not body and not attachment:
        return "empty", "", platform, False
    return HUMAN, body or "(이미지 첨부)", platform, attachment


def _topics(text: str) -> list[str]:
    flat = " ".join(text.split())
    return [rule for rule, pattern in catalog.TASK_RULES if pattern.search(flat)]


def build_questions(
    ai_queries: Sequence[Mapping[str, Any]], meta: Mapping[str, Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = 0
    excluded: Counter[str] = Counter()
    kept: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in ai_queries:
        if row.get("role") != "user":
            continue
        raw += 1
        source = str(row.get("source") or "")
        kind, text, platform, attachment = normalise(str(row.get("text") or ""), source)
        if kind != HUMAN:
            excluded[kind] += 1
            continue
        info = meta.get(str(row.get("artifact_id"))) or {}
        machine = str(info.get("machine") or machine_of(source, row.get("tool")) or "-")
        channel = platform or (str(info["channel"]) if info.get("channel") else "")
        key = (machine, str(row.get("session") or ""), str(row.get("ts_utc") or ""), text)
        found = kept.get(key)
        if found is not None:
            found["duplicates"] += 1
            continue
        local = str(row.get("ts_local") or "")
        kept[key] = {
            "ts_utc": row.get("ts_utc"),
            "ts_local": row.get("ts_local"),
            "date": local[:10] if local else "",
            "machine": machine,
            "channel": channel,
            "session": row.get("session"),
            "text": text,
            "attachment": attachment,
            "topics": _topics(text),
            "source": source,
            "artifact_id": row.get("artifact_id"),
            "duplicates": 0,
        }
    duplicates = sum(q["duplicates"] for q in kept.values())
    questions, loops = _split_loops(list(kept.values()))
    excluded["loop"] = sum(int(loop["count"]) for loop in loops)
    questions.sort(key=lambda q: (q["ts_utc"] is None, str(q["ts_utc"] or ""), q["machine"]))
    for number, question in enumerate(questions, start=1):
        question["no"] = number
    stats = {
        "raw": raw,
        "excluded": {kind: excluded.get(kind, 0) for kind in EXCLUDED_KINDS},
        "duplicates": duplicates,
        "loops": loops,
        "human": len(questions),
        "attachments": sum(1 for q in questions if q["attachment"]),
        "by_month": _by_month(questions),
        "topics": dict(Counter(topic for q in questions for topic in q["topics"]).most_common()),
    }
    return questions, stats


def _split_loops(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    per_session = Counter((q["machine"], q["session"]) for q in rows)
    groups: dict[str, list[dict[str, Any]]] = {}
    for q in rows:
        if len(q["text"]) >= LOOP_MIN_CHARS:
            groups.setdefault(q["text"][:LOOP_PREFIX_CHARS], []).append(q)
    looped: set[int] = set()
    loops: list[dict[str, Any]] = []
    for prefix, members in groups.items():
        sessions = {(q["machine"], q["session"]) for q in members}
        solo = sum(1 for q in members if per_session[(q["machine"], q["session"])] == 1) / len(members)
        if len(sessions) < LOOP_MIN_SESSIONS or solo < LOOP_MIN_SOLO_SHARE:
            continue
        looped.update(id(q) for q in members)
        dates = sorted(str(q["date"]) for q in members if q["date"])
        clock, at_clock = Counter(str(q["ts_local"] or "")[11:16] for q in members).most_common(1)[0]
        loops.append(
            {
                "prefix": prefix,
                "count": len(members),
                "sessions": len(sessions),
                "machines": sorted({str(q["machine"]) for q in members}),
                "first": dates[0] if dates else "",
                "last": dates[-1] if dates else "",
                "common_time": clock,
                "at_common_time": at_clock,
            }
        )
    loops.sort(key=lambda loop: (-int(loop["count"]), str(loop["prefix"])))
    return [q for q in rows if id(q) not in looped], loops


def _by_month(questions: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    table: dict[str, Counter[str]] = {}
    for q in questions:
        month = str(q["date"])[:7] or "-"
        table.setdefault(month, Counter())[str(q["machine"])] += 1
    return {month: dict(sorted(counts.items())) for month, counts in sorted(table.items())}
