"""Display-only helpers for the report timeline: relevance filter and localized event summaries.

Nothing here changes stored events; report.json "timeline" and the CSV exports stay complete.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory
from aitrace.core.model import Artifact, Event
from aitrace.report.i18n import t

# Categories that are always shown: AI activity, deletions and every exfil / remote / transfer / USB route.
ALWAYS_CATEGORIES = frozenset(
    {
        EventCategory.AI_ACTIVITY,
        EventCategory.FILE_DELETED,
        EventCategory.UPLOAD,
        EventCategory.TRANSFER,
        EventCategory.REMOTE_ACCESS,
        EventCategory.DEVICE,
    }
)
FILE_CATEGORIES = frozenset(
    {
        EventCategory.FILE_CREATED,
        EventCategory.FILE_MODIFIED,
        EventCategory.FILE_RENAMED,
        EventCategory.FILE_ACCESSED,
    }
)
WEB_CATEGORIES = frozenset({EventCategory.BROWSING, EventCategory.DOWNLOAD})
SHELL_TAGS = frozenset({"transfer", "remote", "ai_cli", "cloud_cli"})

_FILE_TEMPLATES = {
    EventCategory.FILE_CREATED: "tl.file_created",
    EventCategory.FILE_MODIFIED: "tl.file_modified",
    EventCategory.FILE_DELETED: "tl.file_deleted",
    EventCategory.FILE_RENAMED: "tl.file_renamed",
    EventCategory.FILE_ACCESSED: "tl.file_accessed",
}


def norm_path(path: object) -> str:
    return str(path or "").replace("\\", "/").strip().casefold()


@dataclass(frozen=True, slots=True)
class Focus:
    """What makes a plain file event relevant: attributed paths, AI tool-call paths and finding links."""

    paths: frozenset[str] = frozenset()
    linked_events: frozenset[str] = frozenset()
    linked_artifacts: frozenset[str] = frozenset()


def focus_paths(subjects: Iterable[object], calls: Iterable[Artifact]) -> frozenset[str]:
    paths = {norm_path(s) for s in subjects}
    for call in calls:
        paths.add(norm_path(call.data.get("file_path")))
        paths.add(norm_path(call.data.get("raw_path")))
    paths.discard("")
    return frozenset(paths)


def is_relevant(event: Event, artifact: Artifact | None, focus: Focus) -> bool:
    category = event.category
    if event.actor is Actor.AI or category in ALWAYS_CATEGORIES:
        return True
    if event.id in focus.linked_events or event.artifact_id in focus.linked_artifacts:
        return True
    data: Mapping[str, Any] = artifact.data if artifact is not None else {}
    if artifact is not None and artifact.kind is ArtifactKind.SHELL_COMMAND:
        return bool(SHELL_TAGS.intersection(data.get("tags") or ()))
    if category in WEB_CATEGORIES:
        has_service = bool(event.data.get("ai_service") or data.get("ai_service"))
        return has_service or (artifact is not None and artifact.kind is ArtifactKind.MEDIA_PROVENANCE)
    if category in FILE_CATEGORIES:
        return bool(focus.paths.intersection(norm_path(p) for p in (event.subject, data.get("path"))))
    return bool(data.get("ai_tool"))


def display_summary(event: Event, artifact: Artifact | None, lang: str) -> str:
    """Localized summary chosen by artifact kind / event category; unknown shapes keep the raw text."""
    if lang != "ko" or artifact is None:
        return event.summary
    data = artifact.data
    kind = artifact.kind
    if kind is ArtifactKind.AI_TOOL_CALL:
        path = data.get("file_path") or data.get("raw_path")
        name = str(data.get("call_name") or "")
        tool = str(data.get("tool") or "")
        if path:
            return t("tl.tool_call", lang, tool=tool, name=name, path=path)
        return t("tl.tool_call_nopath", lang, tool=tool, name=name)
    if kind is ArtifactKind.BROWSER_VISIT:
        return t("tl.browser_visit", lang, browser=data.get("browser") or "", url=data.get("url") or "")
    if kind is ArtifactKind.BROWSER_DOWNLOAD:
        return t(
            "tl.browser_download",
            lang,
            browser=data.get("browser") or "",
            url=data.get("url") or "",
            target=data.get("target_path") or t("tl.unknown_target", lang),
        )
    if kind is ArtifactKind.DOWNLOAD_ORIGIN:
        return t(
            "tl.download_origin",
            lang,
            url=data.get("url") or t("tl.unknown_target", lang),
            path=data.get("target_path") or t("tl.unknown_target", lang),
        )
    if kind is ArtifactKind.MEDIA_PROVENANCE and event.category is EventCategory.BROWSING and event.subject:
        return t("tl.cache_image", lang, url=event.subject)
    if kind is ArtifactKind.EXECUTION:
        key = {"prefetch": "tl.prefetch", "amcache": "tl.amcache", "srum": "tl.srum"}.get(str(data.get("source")))
        if key and data.get("program"):
            return t(key, lang, program=data["program"])
    if kind is ArtifactKind.NETWORK_USAGE and data.get("program"):
        return t(
            "tl.srum_network",
            lang,
            program=data["program"],
            sent=data.get("bytes_sent", 0),
            received=data.get("bytes_received", 0),
        )
    if kind is ArtifactKind.FILE_JOURNAL and event.subject:
        reasons = ", ".join(str(r) for r in data.get("reasons") or ()) or "-"
        return t("tl.usn", lang, reasons=reasons, name=event.subject)
    key = _FILE_TEMPLATES.get(event.category)
    if key and event.subject:
        if event.category is EventCategory.FILE_DELETED and event.data.get("limitation"):
            key = "tl.file_deleted_untimed"
        return t(key, lang, path=event.subject)
    return event.summary


def collapsed_row(count: int, lang: str, csv_path: str) -> dict[str, Any]:
    """The single per-day row that stands in for every event the filter dropped."""
    return {
        "time_only": "",
        "category_label": "",
        "actor_label": "",
        "summary": t("timeline.collapsed", lang, n=count, csv=csv_path),
        "source_path": "",
        "collapsed": True,
        "count": count,
    }


def split_days(
    rows: Collection[Mapping[str, Any]], relevant: Collection[bool]
) -> dict[str | None, tuple[list[dict[str, Any]], int]]:
    """Group rows by local date: (relevant rows in order, number of dropped rows)."""
    days: dict[str | None, tuple[list[dict[str, Any]], int]] = {}
    for row, keep in zip(rows, relevant, strict=True):
        local = row.get("ts_local")
        day = str(local).split(" ", 1)[0] if local else None
        shown, dropped = days.get(day, ([], 0))
        if keep:
            item = dict(row)
            item["time_only"] = str(local).split(" ", 1)[1] if local and " " in str(local) else ""
            shown.append(item)
        else:
            dropped += 1
        days[day] = (shown, dropped)
    return days
