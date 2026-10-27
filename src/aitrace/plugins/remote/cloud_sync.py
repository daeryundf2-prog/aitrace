"""Cloud sync clients: OneDrive, Google Drive (DriveFS), Dropbox and iCloud Drive.

DriveFS keeps its metadata in ``metadata_sqlite_db`` with an ``items`` table (id, local_title, modified_date in
Unix milliseconds, trashed). Dropbox ``info.json`` maps the ``personal`` and ``business`` accounts to their sync
folders. OneDrive settings, OneDrive diagnostics logs, Dropbox instance folders and the iCloud Drive folder are
recorded by presence only.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Final

from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_unix_ms
from aitrace.fs.base import EvidenceFS, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase
from aitrace.plugins.common.sqlite import has_table, open_sqlite

ROLE_ONEDRIVE_SETTINGS: Final = "onedrive_settings"
ROLE_ONEDRIVE_LOG: Final = "onedrive_log"
ROLE_DRIVEFS: Final = "drivefs_metadata"
ROLE_DROPBOX_INFO: Final = "dropbox_info"
ROLE_DROPBOX_INSTANCE: Final = "dropbox_instance"
ROLE_ICLOUD: Final = "icloud_drive"

_USER_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (ROLE_ONEDRIVE_SETTINGS, "AppData/Local/Microsoft/OneDrive/settings/*/*.ini"),
    (ROLE_ONEDRIVE_SETTINGS, "Library/Application Support/OneDrive/settings/*/*.ini"),
    (ROLE_ONEDRIVE_LOG, "AppData/Local/Microsoft/OneDrive/logs/**/SyncDiagnostics.log"),
    (ROLE_ONEDRIVE_LOG, "Library/Containers/com.microsoft.OneDrive-mac/**/SyncDiagnostics.log"),
    (ROLE_DRIVEFS, "AppData/Local/Google/DriveFS/*/metadata_sqlite_db"),
    (ROLE_DRIVEFS, "Library/Application Support/Google/DriveFS/*/metadata_sqlite_db"),
    (ROLE_DROPBOX_INFO, "AppData/Local/Dropbox/info.json"),
    (ROLE_DROPBOX_INFO, "Library/Application Support/Dropbox/info.json"),
    (ROLE_DROPBOX_INSTANCE, ".dropbox/instance*"),
    (ROLE_ICLOUD, "Library/Mobile Documents"),
)

_PRESENCE_SERVICE: Final[dict[str, str]] = {
    ROLE_ONEDRIVE_SETTINGS: "OneDrive",
    ROLE_ONEDRIVE_LOG: "OneDrive",
    ROLE_DROPBOX_INSTANCE: "Dropbox",
    ROLE_ICLOUD: "iCloud Drive",
}
_DROPBOX_ACCOUNTS: Final[tuple[str, ...]] = ("personal", "business")


def _candidates(fs: EvidenceFS) -> Iterator[Candidate]:
    for user in fs.users():
        for role, pattern in _USER_PATTERNS:
            for ref in user_glob(fs, user, pattern):
                yield Candidate(ref=ref, role=role, user=user)


def _os_family(ctx: ParseContext, volume: int) -> OsFamily:
    return next(info.os_family for info in ctx.fs.volumes() if info.index == volume)


class Plugin(PluginBase):
    name = "cloud_sync"
    version = "1.0"
    description = "Cloud sync clients: OneDrive, Google Drive DriveFS items, Dropbox accounts and iCloud Drive"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        seen: set[tuple[int, str]] = set()
        for cand in _candidates(fs):
            key = (cand.ref.volume, cand.ref.path)
            if key in seen:
                continue
            seen.add(key)
            yield cand

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        if cand.role == ROLE_DRIVEFS:
            yield from self._drivefs_items(ctx, cand)
        elif cand.role == ROLE_DROPBOX_INFO:
            yield from self._dropbox_accounts(ctx, cand)
        else:
            yield self.artifact(
                ctx,
                cand,
                ArtifactKind.CLOUD_SYNC,
                {"service": _PRESENCE_SERVICE[cand.role], "account": None, "item_path": None},
            )

    def _drivefs_items(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        account = PurePosixPath(cand.ref.path).parent.name
        try:
            with open_sqlite(ctx.fs, cand.ref) as conn:
                if not has_table(conn, "items"):
                    yield self.warning(ctx, cand, "DriveFS metadata has no items table")
                    return
                rows = conn.execute(
                    "SELECT id, local_title, modified_date, trashed FROM items ORDER BY id"
                ).fetchall()
        except sqlite3.Error as exc:
            yield self.warning(ctx, cand, f"unreadable DriveFS database: {exc}")
            return
        for row in rows:
            title = row["local_title"]
            trashed = bool(row["trashed"])
            artifact = self.artifact(
                ctx,
                cand,
                ArtifactKind.CLOUD_SYNC,
                {
                    "service": "Google Drive",
                    "account": account,
                    "item_path": None,
                    "extra": {"title": title, "item_id": str(row["id"]), "trashed": trashed},
                },
                locator=f"item:{row['id']}",
            )
            yield artifact
            modified = from_unix_ms(row["modified_date"])
            if modified is None:
                continue
            state = "trashed" if trashed else "item"
            yield self.event(
                artifact,
                modified,
                "modified",
                EventCategory.FILE_MODIFIED,
                Actor.UNKNOWN,
                f"Google Drive {state}: {title or row['id']}",
                subject=title,
            )

    def _dropbox_accounts(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            info = json.loads(ctx.fs.read_bytes(cand.ref).decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            yield self.warning(ctx, cand, f"unreadable Dropbox info.json: {exc}")
            return
        if not isinstance(info, dict):
            yield self.warning(ctx, cand, "Dropbox info.json is not an object")
            return
        os_family = _os_family(ctx, cand.ref.volume)
        for account in _DROPBOX_ACCOUNTS:
            entry = info.get(account)
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                continue
            yield self.artifact(
                ctx,
                cand,
                ArtifactKind.CLOUD_SYNC,
                {
                    "service": "Dropbox",
                    "account": account,
                    "item_path": normalize(entry["path"], os_family),
                },
                locator=f"account:{account}",
            )


PLUGIN = Plugin()
