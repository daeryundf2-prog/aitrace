from __future__ import annotations

from enum import StrEnum


class OsFamily(StrEnum):
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    UNKNOWN = "unknown"


class ArtifactKind(StrEnum):
    AI_CHAT_MESSAGE = "ai_chat_message"
    AI_TOOL_CALL = "ai_tool_call"
    AI_APP_PRESENCE = "ai_app_presence"
    AI_CREDENTIAL = "ai_credential"
    AI_MODEL = "ai_model"
    BROWSER_VISIT = "browser_visit"
    BROWSER_DOWNLOAD = "browser_download"
    SHELL_COMMAND = "shell_command"
    FILE_RECORD = "file_record"
    FILE_JOURNAL = "file_journal"
    RECYCLED_FILE = "recycled_file"
    SHORTCUT = "shortcut"
    EXECUTION = "execution"
    NETWORK_USAGE = "network_usage"
    REMOTE_SESSION = "remote_session"
    FILE_TRANSFER = "file_transfer"
    USB_DEVICE = "usb_device"
    CLOUD_SYNC = "cloud_sync"
    DOWNLOAD_ORIGIN = "download_origin"
    PERMISSION_GRANT = "permission_grant"
    MEDIA_PROVENANCE = "media_provenance"
    DOC_METADATA = "doc_metadata"
    VCS_COMMIT = "vcs_commit"
    PARSE_WARNING = "parse_warning"


class EventCategory(StrEnum):
    AI_ACTIVITY = "ai_activity"
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    FILE_RENAMED = "file_renamed"
    FILE_ACCESSED = "file_accessed"
    EXECUTION = "execution"
    BROWSING = "browsing"
    DOWNLOAD = "download"
    UPLOAD = "upload"
    REMOTE_ACCESS = "remote_access"
    TRANSFER = "transfer"
    DEVICE = "device"
    AUTH = "auth"
    CONFIG = "config"
    OTHER = "other"


class Actor(StrEnum):
    HUMAN = "human"
    AI = "ai"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class FindingCategory(StrEnum):
    AI_TOOL_USAGE = "ai_tool_usage"
    AI_QUERY = "ai_query"
    FILE_LIFECYCLE = "file_lifecycle"
    EXFIL_CHANNEL = "exfil_channel"
    ATTRIBUTION = "attribution"
    INTEGRITY = "integrity"
    COVERAGE = "coverage"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Verdict(StrEnum):
    AI_GENERATED = "ai_generated"
    AI_ASSISTED = "ai_assisted"
    HUMAN_AUTHORED = "human_authored"
    UNDETERMINED = "undetermined"


class ConfidenceBand(StrEnum):
    UNDETERMINED = "undetermined"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"


def band_for(conf: float) -> ConfidenceBand:
    """<0.2 undetermined, <0.5 weak, <0.75 moderate, else strong."""
    if conf < 0.2:
        return ConfidenceBand.UNDETERMINED
    if conf < 0.5:
        return ConfidenceBand.WEAK
    if conf < 0.75:
        return ConfidenceBand.MODERATE
    return ConfidenceBand.STRONG


class SignalType(StrEnum):
    C2PA = "c2pa"
    IPTC_DIGITAL_SOURCE = "iptc_digital_source"
    SD_PARAMETERS = "sd_parameters"
    AI_FILENAME_PATTERN = "ai_filename_pattern"
    VCS_AI_TRAILER = "vcs_ai_trailer"
    AGENT_TOOL_WRITE = "agent_tool_write"
    CONTENT_MATCH = "content_match"
    AI_DOWNLOAD_ORIGIN = "ai_download_origin"
    TIME_PROXIMITY = "time_proximity"
    METADATA_HINT = "metadata_hint"
    HUMAN_EDIT_AFTER = "human_edit_after"
    HUMAN_PROCESS = "human_process"


SIGNAL_CAPS: dict[SignalType, float] = {
    SignalType.C2PA: 0.90,
    SignalType.IPTC_DIGITAL_SOURCE: 0.85,
    SignalType.SD_PARAMETERS: 0.90,
    SignalType.AGENT_TOOL_WRITE: 0.90,
    SignalType.VCS_AI_TRAILER: 0.85,
    SignalType.CONTENT_MATCH: 0.80,
    SignalType.AI_DOWNLOAD_ORIGIN: 0.75,
    SignalType.AI_FILENAME_PATTERN: 0.60,
    SignalType.TIME_PROXIMITY: 0.40,
    SignalType.METADATA_HINT: 0.30,
    SignalType.HUMAN_EDIT_AFTER: 0.70,
    SignalType.HUMAN_PROCESS: 0.50,
}

_HUMAN_SIGNALS = frozenset({SignalType.HUMAN_EDIT_AFTER, SignalType.HUMAN_PROCESS})

SIGNAL_DIRECTION: dict[SignalType, str] = {
    signal: ("human" if signal in _HUMAN_SIGNALS else "ai") for signal in SignalType
}
