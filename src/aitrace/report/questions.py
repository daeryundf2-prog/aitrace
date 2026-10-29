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
EXCLUDED_KINDS: tuple[str, ...] = (
    "compaction",
    "system_notice",
    "a2a",
    "subagent",
    "automated",
    "loop",
    "empty",
)
# Input channels recorded by the agent: these carry text another program or agent wrote, never a person.
AGENT_CHANNELS: dict[str, str] = {
    "a2a": "a2a",
    "subagent": "subagent",
    "kanban": "automated",
    "oneshot": "automated",
    "api_server": "automated",
    "cron": "automated",
}
_A2A_HEADER = re.compile(r"^\s*\[A2A (?:inbound|outbound)[^\]]*\]\s*")
_A2A_PEER = re.compile(r"remote agent peer named '([^']+)'")
_A2A_ARROW = re.compile(r"\[([^\]\n]{1,40}?)\s*(?:→|->)\s*([^\]\n]{1,40})\]")
LENGTH_BUCKETS: tuple[tuple[str, int], ...] = (("le5", 5), ("le20", 20), ("le1000", 1000), ("gt1000", 10**12))
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
_KANBAN_NOTICE = re.compile(r"^\s*\[kanban\]", re.IGNORECASE)
# A sensitive keyword followed closely by a negation or a prevention word: "외부 유출에 해당하지 않아",
# "유출 방지를 위해", "scp로 전송 안 해도 되게". Such inputs deny or prevent the act rather than ask for it.
_DENIAL = re.compile(
    r"(?:유출|반출|우회|전송|scp|외부로)[^.\n]{0,30}?(?:없|아니|않|방지|금지|안 ?[해되]|막|피하|피할|차단)"
    r"|(?:방지|막기|차단|금지)[^.\n]{0,8}?(?:유출|반출|우회)",
    re.IGNORECASE,
)
# Facts a reviewer must see first, decided by the text alone. Order is the reading order in the brief.
FACT_KINDS: tuple[str, ...] = ("document", "deletion", "personal", "credential")
_DOCUMENT_NOTE = re.compile(r"\(문서 첨부: ")
_DELETION = re.compile(
    r"삭제했|삭제해\s*줘|지웠|지운\s*거|휴지통|비웠|포맷했|영구\s*삭제|기록을?\s*지워|로그를?\s*지워|\bwipe\b|\bshred\b",
    re.IGNORECASE,
)
_PHONE = re.compile(r"(?<!\d)(01[016789])[-. ]?\d{3,4}[-. ]?\d{4}(?!\d)")
_RRN = re.compile(r"(?<![\d_])\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-[1-4]\d{6}(?!\d)")
_EMAIL = re.compile(
    r"(?<!ssh )(?<!-l )(?<![\w.+-])([\w.+-])[\w.+-]*@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})"
)
_REMOTE_COMMAND = re.compile(r"\b(?:ssh|scp|sftp|rsync)\b")


def _mail(match: re.Match[str]) -> bool:
    """An address on a line that starts a remote shell command is a login, not an e-mail address."""
    line_start = match.string.rfind("\n", 0, match.start()) + 1
    return _REMOTE_COMMAND.search(match.string, line_start, match.start()) is None


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
        return match.group("machine")
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
    if (
        _AGENT_REPORT.match(body)
        or _GATEWAY_GENERATED.search(body)
        or _FRAMEWORK_NOTICE.match(body)
        or _KANBAN_NOTICE.match(body)
    ):
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


def facts_of(text: str) -> list[str]:
    found = {
        "document": _DOCUMENT_NOTE.search(text) is not None,
        "deletion": _DELETION.search(text) is not None,
        "personal": bool(
            _PHONE.search(text) or _RRN.search(text) or any(_mail(m) for m in _EMAIL.finditer(text))
        ),
        "credential": any(p.search(text) for _, p in catalog.SECRET_PATTERNS),
    }
    return [kind for kind in FACT_KINDS if found[kind]]


def mask_sensitive(text: str) -> str:
    """Phone numbers, resident numbers, e-mail addresses and API keys masked for a document that is handed on."""
    for _, pattern in catalog.SECRET_PATTERNS:
        text = pattern.sub(lambda m: catalog.redact(m.group(0)), text)
    text = _RRN.sub("******-*******", text)
    text = _PHONE.sub(lambda m: f"{m.group(1)}-****-****", text)
    return _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}" if _mail(m) else m.group(0), text)


def denies_sensitive(text: str) -> bool:
    return _DENIAL.search(" ".join(text.split())) is not None


def _topics(text: str) -> list[str]:
    flat = " ".join(text.split())
    return [rule for rule, pattern in catalog.TASK_RULES if pattern.search(flat)]


def build_questions(
    ai_queries: Sequence[Mapping[str, Any]], meta: Mapping[str, Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw = 0
    excluded: Counter[str] = Counter()
    kept: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    ai_inputs: list[dict[str, Any]] = []
    for row in ai_queries:
        if row.get("role") != "user":
            continue
        raw += 1
        source = str(row.get("source") or "")
        info = meta.get(str(row.get("artifact_id"))) or {}
        recorded_channel = str(info.get("channel") or "")
        if recorded_channel in AGENT_CHANNELS:
            excluded[AGENT_CHANNELS[recorded_channel]] += 1
            ai_inputs.append(_ai_input(row, info, source, recorded_channel))
            continue
        kind, text, platform, attachment = normalise(str(row.get("text") or ""), source)
        if kind != HUMAN:
            excluded[kind] += 1
            if kind in ("a2a", "automated"):
                route = recorded_channel or (
                    "a2a" if kind == "a2a" else "kanban" if "kanban" in source else "cron"
                )
                ai_inputs.append(_ai_input(row, info, source, route))
            continue
        machine = str(info.get("machine") or machine_of(source, row.get("tool")) or "-")
        channel = platform or recorded_channel
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
            "denial": denies_sensitive(text),
            "facts": facts_of(text),
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
        "by_length": _by_length(questions),
        "facts": {kind: sum(1 for q in questions if kind in q["facts"]) for kind in FACT_KINDS},
        "ai_inputs": sorted(
            ai_inputs, key=lambda a: (a["ts_utc"] is None, str(a["ts_utc"] or ""), a["machine"])
        ),
        "ai_by_channel": dict(Counter(a["channel"] for a in ai_inputs).most_common()),
        "by_channel": dict(Counter(str(q["channel"]) or "-" for q in questions).most_common()),
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


def _ai_input(row: Mapping[str, Any], info: Mapping[str, Any], source: str, channel: str) -> dict[str, Any]:
    text = str(row.get("text") or "")
    peer = _A2A_PEER.search(text)
    arrow = _A2A_ARROW.search(text[:300])
    sender = peer.group(1) if peer else arrow.group(1).strip() if arrow else ""
    local = str(row.get("ts_local") or "")
    return {
        "ts_utc": row.get("ts_utc"),
        "ts_local": row.get("ts_local"),
        "date": local[:10] if local else "",
        "machine": str(info.get("machine") or machine_of(source, row.get("tool")) or "-"),
        "channel": channel,
        "sender": sender,
        "session": row.get("session"),
        "text": _A2A_HEADER.sub("", text).strip(),
        "source": source,
    }


def _by_length(questions: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys((name for name, _ in LENGTH_BUCKETS), 0)
    for q in questions:
        size = len(str(q["text"]))
        counts[next(name for name, limit in LENGTH_BUCKETS if size <= limit)] += 1
    return counts


def _by_month(questions: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    table: dict[str, Counter[str]] = {}
    for q in questions:
        month = str(q["date"])[:7] or "-"
        table.setdefault(month, Counter())[str(q["machine"])] += 1
    return {month: dict(sorted(counts.items())) for month, counts in sorted(table.items())}
