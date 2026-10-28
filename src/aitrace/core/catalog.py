from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from aitrace.core.kinds import ArtifactKind, SignalType

AI_DOMAINS: dict[str, str] = {
    "chatgpt.com": "ChatGPT",
    "chat.openai.com": "ChatGPT",
    "openai.com": "ChatGPT",
    "oaiusercontent.com": "ChatGPT",
    "claude.ai": "Claude",
    "anthropic.com": "Claude",
    "gemini.google.com": "Gemini",
    "bard.google.com": "Gemini",
    "aistudio.google.com": "Gemini",
    "copilot.microsoft.com": "Microsoft Copilot",
    "copilot.cloud.microsoft": "Microsoft Copilot",
    "m365.cloud.microsoft": "Microsoft Copilot",
    "perplexity.ai": "Perplexity",
    "poe.com": "Poe",
    "chat.deepseek.com": "DeepSeek",
    "deepseek.com": "DeepSeek",
    "grok.com": "Grok",
    "x.ai": "Grok",
    "midjourney.com": "Midjourney",
    "huggingface.co": "Hugging Face",
    "character.ai": "Character.AI",
    "you.com": "You.com",
    "mistral.ai": "Mistral",
    "chat.mistral.ai": "Mistral",
    "wrtn.ai": "Wrtn",
    "clova-x.naver.com": "CLOVA X",
    "github.com/copilot": "GitHub Copilot",
    "cursor.com": "Cursor",
    "suno.com": "Suno",
    "runwayml.com": "Runway",
    "ideogram.ai": "Ideogram",
    "leonardo.ai": "Leonardo",
    "firefly.adobe.com": "Adobe Firefly",
}


def _host_matches(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def match_ai_domain(url: str) -> str | None:
    """Service name for a URL or bare host; longest catalog entry wins."""
    text = url.strip()
    parts = urlsplit(text if "://" in text else "http://" + text)
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    path = parts.path.lower()
    for entry in sorted(AI_DOMAINS, key=len, reverse=True):
        if "/" in entry:
            entry_host, entry_path = entry.split("/", 1)
            prefix = "/" + entry_path
            if _host_matches(host, entry_host) and (path == prefix or path.startswith(prefix + "/")):
                return AI_DOMAINS[entry]
        elif _host_matches(host, entry):
            return AI_DOMAINS[entry]
    return None


AI_PROGRAMS: dict[str, str] = {
    "chatgpt.exe": "ChatGPT Desktop",
    "com.openai.chat": "ChatGPT Desktop",
    "openai.chatgpt-desktop": "ChatGPT Desktop",
    "claude.exe": "Claude Desktop",
    "com.anthropic.claudefordesktop": "Claude Desktop",
    "copilot.exe": "Microsoft Copilot",
    "microsoft.copilot": "Microsoft Copilot",
    "cursor.exe": "Cursor",
    "com.todesktop.230313mzl4w4u92": "Cursor",
    "windsurf.exe": "Windsurf",
    "ollama.exe": "Ollama",
    "ollama app.exe": "Ollama",
    "com.electron.ollama": "Ollama",
    "lm studio.exe": "LM Studio",
    "ai.elementlabs.lmstudio": "LM Studio",
    "jan.exe": "Jan",
    "gpt4all.exe": "GPT4All",
    "perplexity.exe": "Perplexity",
    "ai.perplexity.mac": "Perplexity",
    "claude": "Claude Code",
    "codex": "Codex CLI",
    "gemini": "Gemini CLI",
    "aider": "Aider",
    "copilot": "GitHub Copilot CLI",
    "opencode": "OpenCode",
    "opencode.exe": "OpenCode",
    "hermes": "Hermes Agent",
    "hermes.exe": "Hermes Agent",
    "omo.exe": "omo",
    "omo.app": "omo",
    "com.code-yeongyu.omo": "omo",
}

CANONICAL_TOOL_NAMES: tuple[str, ...] = (
    "Claude Code",
    "Codex CLI",
    "Gemini CLI",
    "Aider",
    "GitHub Copilot CLI",
    "Continue",
    "ChatGPT Desktop",
    "Claude Desktop",
    "Microsoft Copilot",
    "Perplexity",
    "Cursor",
    "VS Code Copilot Chat",
    "Windsurf",
    "Ollama",
    "LM Studio",
    "Jan",
    "GPT4All",
    "omo",
    "OpenCode",
    "Hermes Agent",
)


def match_ai_program(name: str) -> str | None:
    """Exact lookup of the lowercase basename (exe name or bundle id)."""
    base = name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].strip().lower()
    return AI_PROGRAMS.get(base)


AI_FILENAME_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^DALL[·.]?E \d{4}-\d{2}-\d{2}"), "DALL-E"),
    (re.compile(r"^ChatGPT Image "), "ChatGPT"),
    (re.compile(r"^Gemini_Generated_Image_"), "Gemini"),
    (re.compile(r"^Firefly[ _]"), "Adobe Firefly"),
    (re.compile(r"^(\d{5}-\d+|ComfyUI_\d+_)"), "StableDiffusion/ComfyUI"),
    # Midjourney rule: the uuid-suffixed PNG only counts when "midjourney" appears in the name.
    (re.compile(r"^(?=.*(?i:midjourney)).*_[0-9a-f]{8}-[0-9a-f]{4}-.*\.png$"), "Midjourney"),
    (re.compile(r"^Copilot_\d{8}_\d{6}"), "Microsoft Copilot"),
]


@dataclass(frozen=True, slots=True)
class CommandRule:
    rule_id: str
    tags: tuple[str, ...]
    regex: str
    dest_group: int | None


URL_RE = r"https?://[^\s'\"]+"
HOST_AT_RE = r"@([\w.-]+):"

_TRANSFER = ("transfer",)
_CLOUD_CLI = ("transfer", "cloud_cli")

COMMAND_RULES: list[CommandRule] = [
    CommandRule("TR-SCP", _TRANSFER, r"\bscp\b.*\s(\S+@)?([\w.-]+):", 2),
    CommandRule("TR-RSYNC", _TRANSFER, r"\brsync\b.*\s(\S+@)?([\w.-]+):", 2),
    CommandRule("TR-RCLONE", _CLOUD_CLI, r"\brclone\s+(copy|sync|move)\b.*\s(?![A-Za-z]:[\\/])(\S+:\S*)", 2),
    CommandRule("TR-CURL-UP", _TRANSFER, r"\bcurl\b.*(\s-F\s|\s-T\s|--upload-file|--data-binary\s@)", None),
    CommandRule("TR-WGET-POST", _TRANSFER, r"\bwget\b.*--post-file", None),
    CommandRule("TR-NC", _TRANSFER, r"\b(nc|ncat|netcat)\b.*\s\d+\s*<", None),
    CommandRule("TR-SFTP", _TRANSFER, r"\bsftp\b", None),
    CommandRule("TR-AWS-S3", _CLOUD_CLI, r"\baws\s+s3\s+(cp|sync|mv)\b.*\s(s3://\S+)", 2),
    CommandRule("TR-GSUTIL", _TRANSFER, r"\bgsutil\s+(cp|rsync)\b.*\s(gs://\S+)", 2),
    CommandRule("TR-AZCOPY", _TRANSFER, r"\bazcopy\b", None),
    CommandRule("TR-GIT-PUSH", _TRANSFER, r"\bgit\s+push\b", None),
    CommandRule("TR-PS-COPY", _TRANSFER, r"(Copy-Item|Move-Item).*\\\\[\w.-]+\\", None),
    CommandRule("TR-PS-WEB", _TRANSFER, r"Invoke-(WebRequest|RestMethod).*-(InFile|Body)", None),
    CommandRule("RM-SSH", ("remote",), r"\bssh\s+(\S+@)?[\w.-]+", None),
    CommandRule("RM-RDP", ("remote",), r"\bmstsc\b", None),
    CommandRule(
        "AI-CLI",
        ("ai_cli",),
        r"^(sudo\s+)?(claude|codex|gemini|aider|ollama|llm|sgpt|copilot|cursor-agent|opencode|hermes|omo|senpi)\b",
        None,
    ),
    CommandRule(
        "AI-PIP",
        ("ai_cli",),
        r"\b(pip3?|uv)\s+(install|add)\b.*\b(openai|anthropic|google-generativeai|langchain|ollama|transformers)\b",
        None,
    ),
    CommandRule("AR-ZIP", ("archive",), r"\b(zip|7z|tar|rar)\b", None),
]


def _fallback_destination(cmd: str) -> str | None:
    url = re.search(URL_RE, cmd)
    if url:
        return url.group(0)
    host = re.search(HOST_AT_RE, cmd)
    if host:
        return host.group(1)
    return None


def match_command(cmd: str) -> list[tuple[CommandRule, str | None]]:
    """Every matching rule in catalog order, with the destination (host or URL) when one is found."""
    results: list[tuple[CommandRule, str | None]] = []
    for rule in COMMAND_RULES:
        match = re.search(rule.regex, cmd)
        if match is None:
            continue
        destination = match.group(rule.dest_group) if rule.dest_group is not None else None
        if not destination:
            destination = _fallback_destination(cmd)
        results.append((rule, destination))
    return results


SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI", re.compile(r"sk-(proj-)?[A-Za-z0-9_-]{20,}")),
    ("Anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("Google", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("HuggingFace", re.compile(r"hf_[A-Za-z0-9]{30,}")),
    ("Groq", re.compile(r"gsk_[A-Za-z0-9]{40,}")),
    ("xAI", re.compile(r"xai-[A-Za-z0-9]{40,}")),
    ("Perplexity", re.compile(r"pplx-[A-Za-z0-9]{40,}")),
    ("DeepSeek", re.compile(r"DEEPSEEK_API_KEY\s*=\s*\S+")),
    ("generic", re.compile(r"(OPENAI|ANTHROPIC|GEMINI|GOOGLE|MISTRAL|COHERE|AZURE_OPENAI)_API_KEY\s*[=:]\s*['\"]?(\S+)")),
]


def redact(secret: str) -> str:
    """First 6 characters + an ellipsis + a short SHA-256 tag, so equal secrets still correlate."""
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]
    return f"{secret[:6]}…sha256:{digest}"


# Git trailer keys are case-insensitive, so the trailer patterns compile with IGNORECASE.
VCS_AI_TRAILER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"Co-Authored-By:\s*Claude", re.IGNORECASE), "Claude"),
    (re.compile(r"noreply@anthropic\.com", re.IGNORECASE), "Claude"),
    (re.compile(r"Co-authored-by:\s*Copilot", re.IGNORECASE), "GitHub Copilot"),
    (re.compile(r"Co-authored-by:.*cursoragent", re.IGNORECASE), "Cursor"),
    (re.compile(r"\(aider\)", re.IGNORECASE), "Aider"),
    (re.compile(r"Generated with \[?Claude Code", re.IGNORECASE), "Claude Code"),
    (re.compile(r"Co-authored-by:\s*(Codex|OpenAI)", re.IGNORECASE), "Codex"),
    (re.compile(r"Co-authored-by:.*gemini", re.IGNORECASE), "Gemini"),
]

TASK_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "TASK-CODE",
        re.compile(r"코드|함수|버그|에러|script|function|code|debug|python|javascript|sql|regex", re.IGNORECASE),
    ),
    (
        "TASK-WRITE",
        re.compile(r"작성|보고서|이메일|메일|문서|요약|자기소개|write|draft|essay|email|summar", re.IGNORECASE),
    ),
    ("TASK-TRANSLATE", re.compile(r"번역|translate|영어로|한국어로", re.IGNORECASE)),
    ("TASK-IMAGE", re.compile(r"이미지|그림|사진|image|picture|logo|draw|dall|midjourney", re.IGNORECASE)),
    ("TASK-DATA", re.compile(r"엑셀|csv|데이터|분석|표|excel|dataset|analy", re.IGNORECASE)),
    (
        "TASK-SECURITY",
        re.compile(
            r"해킹|우회|비밀번호|크랙|exploit|bypass|phish|malware|keylog|password|ransom", re.IGNORECASE
        ),
    ),
    (
        "TASK-EXFIL",
        re.compile(r"유출|빼내|몰래|외부로|exfil|leak|upload.*(drive|dropbox|server)|scp|rclone", re.IGNORECASE),
    ),
    ("TASK-SEARCH", re.compile(r"검색|찾아|알려줘|what is|who is|search", re.IGNORECASE)),
]

# File names on NTFS/APFS are case-insensitive, so the MFT filter matches case-insensitively.
INTERESTING_NAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\.(docx|xlsx|pptx|pdf|txt|md|csv|zip|7z|rar|png|jpe?g|py|js|json|jsonl|env|sqlite|db|log)$",
        re.IGNORECASE,
    ),
    re.compile(r"chatgpt|claude|copilot|cursor|ollama|gemini|openai|anthropic", re.IGNORECASE),
]

LIMITATIONS: dict[SignalType | str, dict[str, str] | list[dict[str, str]]] = {
    SignalType.C2PA: {
        "ko": "C2PA 메타데이터는 제거되거나 추가될 수 있으며, 본 도구는 서명을 검증하지 않는다.",
        "en": "C2PA metadata can be stripped or added; signature not validated by this tool",
    },
    SignalType.IPTC_DIGITAL_SOURCE: {
        "ko": "IPTC 디지털 소스 유형 값은 편집 도구로 임의 수정할 수 있다.",
        "en": "IPTC digital source type values can be edited freely with metadata tools",
    },
    SignalType.SD_PARAMETERS: {
        "ko": "생성 파라미터 텍스트는 다른 이미지에 복사되거나 제거될 수 있다.",
        "en": "generation parameter text can be copied into other images or removed",
    },
    SignalType.AI_FILENAME_PATTERN: {
        "ko": "파일명은 사용자가 임의로 변경할 수 있으므로 단독 근거가 될 수 없다.",
        "en": "file names can be changed by anyone and are not proof on their own",
    },
    SignalType.VCS_AI_TRAILER: {
        "ko": "커밋 트레일러는 커밋 단위 정보이며 개별 줄의 작성 주체를 증명하지 않는다.",
        "en": "commit trailers describe a whole commit and do not prove who wrote each line",
    },
    SignalType.AGENT_TOOL_WRITE: {
        "ko": "에이전트가 해당 내용을 기록했음을 증명하며, 이후 타인의 수정은 내용/수정시각 비교로만 탐지된다.",
        "en": "proves the agent wrote this content; later edits by others are detected only via content/mtime",
    },
    SignalType.CONTENT_MATCH: {
        "ko": "내용 유사도는 AI 응답을 사람이 옮겨 적은 경우와 구분하지 못한다.",
        "en": "content similarity cannot distinguish AI output from a human copying that output",
    },
    SignalType.AI_DOWNLOAD_ORIGIN: {
        "ko": "AI 서비스에서 내려받았다는 사실이 해당 파일이 AI로 생성되었음을 증명하지는 않는다.",
        "en": "downloading from an AI service does not prove the file was generated by AI",
    },
    SignalType.TIME_PROXIMITY: {
        "ko": "시간적 근접성만으로는 인과관계를 증명할 수 없다.",
        "en": "temporal proximity alone does not prove causation",
    },
    SignalType.METADATA_HINT: {
        "ko": "문서 메타데이터 힌트는 약한 정황이며 쉽게 변경될 수 있다.",
        "en": "document metadata hints are weak indicators and easily altered",
    },
    SignalType.HUMAN_EDIT_AFTER: {
        "ko": "생성 이후 수정은 수정 주체를 특정하지 않는다(다른 도구나 사람일 수 있음).",
        "en": "an edit after generation does not identify who made the edit",
    },
    SignalType.HUMAN_PROCESS: {
        "ko": "사람의 작업 흔적은 AI 사용 가능성을 배제하지 않는다.",
        "en": "traces of a human workflow do not exclude AI assistance",
    },
    "FSEVENTS": {
        "ko": "FSEvents 레코드에는 개별 이벤트 시각이 기록되지 않는다.",
        "en": "FSEvents records carry no per-event timestamp",
    },
    "DELETED_TIME": {
        "ko": "MFT에는 삭제 시각이 기록되지 않으므로 마지막 $SI 수정 시각을 표시한다.",
        "en": "MFT deletion time is not recorded; last $SI modification is shown",
    },
    "BROWSER_LAST_DIR": {
        "ko": "파일 대화상자의 마지막 디렉터리는 업로드를 증명하지 않는다.",
        "en": "the last file-dialog directory does not prove an upload",
    },
    "USB_NO_COPY_PROOF": {
        "ko": "USB 연결 기록은 파일 복사를 증명하지 않는다.",
        "en": "USB insertion does not prove a file copy",
    },
    "hermes_export_tz": {
        "ko": "Hermes 추출본의 시각은 시간대 표기가 없는 서버 현지 시각이므로 Asia/Seoul(+09:00)로 가정하여 변환하였다.",
        "en": "Hermes export times are server wall-clock times without a zone; they were read as Asia/Seoul (+09:00)",
    },
    "GLOBAL": [
        {
            "ko": "시스템 시계 오차로 시각이 실제와 다를 수 있다.",
            "en": "system clock skew may make recorded times differ from real time",
        },
        {
            "ko": "시간대 정보가 없는 시각은 지정된 시간대를 가정하여 변환하였다.",
            "en": "times without zone information were converted assuming the configured timezone",
        },
        {
            "ko": "암호화된 저장소는 해독하지 않았으며 존재 여부만 보고한다.",
            "en": "encrypted stores were not decrypted; only their presence is reported",
        },
        {
            "ko": "흔적이 발견되지 않았다는 사실이 해당 행위가 없었음을 증명하지 않는다.",
            "en": "absence of a trace does not prove absence of the activity",
        },
        {
            "ko": "AI 흔적이 없다는 사실이 사람이 작성했음을 증명하지 않는다.",
            "en": "absence of AI traces does not prove human authorship",
        },
    ],
}

EXPORT_KINDS: frozenset[ArtifactKind] = frozenset(
    {
        ArtifactKind.AI_CHAT_MESSAGE,
        ArtifactKind.AI_TOOL_CALL,
        ArtifactKind.AI_APP_PRESENCE,
        ArtifactKind.AI_CREDENTIAL,
        ArtifactKind.AI_MODEL,
        ArtifactKind.BROWSER_VISIT,
        ArtifactKind.BROWSER_DOWNLOAD,
        ArtifactKind.SHELL_COMMAND,
        ArtifactKind.FILE_TRANSFER,
        ArtifactKind.REMOTE_SESSION,
        ArtifactKind.MEDIA_PROVENANCE,
        ArtifactKind.DOC_METADATA,
        ArtifactKind.DOWNLOAD_ORIGIN,
        ArtifactKind.RECYCLED_FILE,
        ArtifactKind.SHORTCUT,
    }
)
