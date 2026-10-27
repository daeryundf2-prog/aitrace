from __future__ import annotations

import dataclasses
import json
import sqlite3
from collections.abc import Iterator
from datetime import datetime
from typing import Any
from urllib.parse import unquote, urlsplit

from aitrace.core.catalog import LIMITATIONS, match_ai_domain
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.core.time import from_cocoa, from_unix_us, from_webkit
from aitrace.fs.base import EntryRef, EvidenceFS, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase
from aitrace.plugins.common.sqlite import has_table, open_sqlite, table_columns

_CHROMIUM: dict[str, dict[OsFamily, tuple[str, ...]]] = {
    "Chrome": {
        OsFamily.WINDOWS: ("AppData/Local/Google/Chrome/User Data",),
        OsFamily.MACOS: ("Library/Application Support/Google/Chrome",),
        OsFamily.LINUX: (".config/google-chrome",),
    },
    "Edge": {
        OsFamily.WINDOWS: ("AppData/Local/Microsoft/Edge/User Data",),
        OsFamily.MACOS: ("Library/Application Support/Microsoft Edge",),
        OsFamily.LINUX: (".config/microsoft-edge",),
    },
    "Brave": {
        OsFamily.WINDOWS: ("AppData/Local/BraveSoftware/Brave-Browser/User Data",),
        OsFamily.MACOS: ("Library/Application Support/BraveSoftware/Brave-Browser",),
        OsFamily.LINUX: (".config/BraveSoftware/Brave-Browser",),
    },
    "Arc": {
        OsFamily.WINDOWS: ("AppData/Local/Arc/User Data",),
        OsFamily.MACOS: ("Library/Application Support/Arc/User Data",),
    },
    "Opera": {
        OsFamily.WINDOWS: ("AppData/Local/Opera Software/Opera Stable", "AppData/Roaming/Opera Software/Opera Stable"),
        OsFamily.MACOS: ("Library/Application Support/com.operasoftware.Opera",),
        OsFamily.LINUX: (".config/opera",),
    },
    "Vivaldi": {
        OsFamily.WINDOWS: ("AppData/Local/Vivaldi/User Data",),
        OsFamily.MACOS: ("Library/Application Support/Vivaldi",),
        OsFamily.LINUX: (".config/vivaldi",),
    },
    "Chromium": {
        OsFamily.WINDOWS: ("AppData/Local/Chromium/User Data",),
        OsFamily.MACOS: ("Library/Application Support/Chromium",),
        OsFamily.LINUX: (".config/chromium",),
    },
}
_FIREFOX: dict[OsFamily, str] = {
    OsFamily.WINDOWS: "AppData/Roaming/Mozilla/Firefox/Profiles",
    OsFamily.MACOS: "Library/Application Support/Firefox/Profiles",
    OsFamily.LINUX: ".mozilla/firefox",
}
_FF_DEST_ANNO = "downloads/destinationFileURI"
_FF_META_ANNO = "downloads/metaData"


def _files(fs: EvidenceFS, user: Any, pattern: str) -> Iterator[EntryRef]:
    return (ref for ref in user_glob(fs, user, pattern) if not fs.is_dir(ref))


def _pick(cols: set[str], wanted: tuple[str, ...], prefix: str = "") -> str:
    return ", ".join(f"{prefix}{c} AS {c}" if c in cols else f"NULL AS {c}" for c in wanted)


def _text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    text = str(value)
    return text if text else None


def _number(value: object) -> float | None:
    return None if isinstance(value, bool) or not isinstance(value, (int, float)) else value


def _file_uri_path(uri: str) -> str:
    path = unquote(urlsplit(uri).path)
    if len(path) > 2 and path[0] == "/" and path[2] == ":":
        path = path[1:]
    return path


class Plugin(PluginBase):
    name = "history_downloads"
    version = "1.0"
    description = "Chromium-family, Firefox and Safari history and downloads, plus the Chromium last file-dialog directory"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for user in fs.users():
            for browser, roots in _CHROMIUM.items():
                for root in roots.get(user.os_family, ()):
                    for ref in _files(fs, user, f"{root}/*/History"):
                        yield Candidate(ref, "chromium_history", user, {"browser": browser})
                    for ref in _files(fs, user, f"{root}/*/Preferences"):
                        yield Candidate(ref, "chromium_prefs", user, {"browser": browser})
                    if browser == "Opera":
                        for ref in _files(fs, user, f"{root}/History"):
                            yield Candidate(ref, "chromium_history", user, {"browser": browser})
                        for ref in _files(fs, user, f"{root}/Preferences"):
                            yield Candidate(ref, "chromium_prefs", user, {"browser": browser})
            firefox_root = _FIREFOX.get(user.os_family)
            if firefox_root is not None:
                for ref in _files(fs, user, f"{firefox_root}/*/places.sqlite"):
                    yield Candidate(ref, "firefox_places", user, {"browser": "Firefox"})
            if user.os_family is OsFamily.MACOS:
                for ref in _files(fs, user, "Library/Safari/History.db"):
                    yield Candidate(ref, "safari_history", user, {"browser": "Safari"})

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        if cand.role == "chromium_prefs":
            yield from self._prefs(ctx, cand)
            return
        try:
            with open_sqlite(ctx.fs, cand.ref) as conn:
                if cand.role == "chromium_history":
                    yield from self._chromium(ctx, cand, conn)
                elif cand.role == "firefox_places":
                    yield from self._firefox(ctx, cand, conn)
                else:
                    yield from self._safari(ctx, cand, conn)
        except (sqlite3.Error, OSError) as exc:
            yield self.warning(ctx, cand, f"{cand.role}: cannot read database: {exc}")

    def _visit(
        self, ctx: ParseContext, cand: Candidate, locator: str, url: str, title: str | None, ts: datetime | None
    ) -> Iterator[Artifact | Event]:
        browser = str(cand.extra["browser"])
        data: dict[str, Any] = {"browser": browser, "url": url, "title": title or ""}
        service = match_ai_domain(url)
        if service is not None:
            data["ai_service"] = service
        art = self.artifact(ctx, cand, ArtifactKind.BROWSER_VISIT, data, locator=locator)
        yield art
        yield self.event(
            art,
            ts,
            "visit_time",
            EventCategory.BROWSING,
            Actor.HUMAN,
            f"{browser} visit: {url}",
            ts_basis="native_utc" if ts is not None else "unknown",
            subject=url,
            data={"ai_service": service} if service is not None else {},
        )

    def _download(
        self,
        ctx: ParseContext,
        cand: Candidate,
        locator: str,
        *,
        url: str,
        target_raw: str,
        ts: datetime | None,
        ts_kind: str,
        received_bytes: float | None,
        referrer: str | None,
        tab_url: str | None,
        also_urls: tuple[str, ...] = (),
    ) -> Iterator[Artifact | Event]:
        browser = str(cand.extra["browser"])
        os_family = cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN
        home = cand.user.home if cand.user is not None else None
        target = normalize(target_raw, os_family, home) if target_raw else ""
        data: dict[str, Any] = {"browser": browser, "url": url, "target_path": target}
        if target_raw and target_raw != target:
            data["raw_path"] = target_raw
        if tab_url:
            data["tab_url"] = tab_url
        if referrer:
            data["referrer"] = referrer
        if received_bytes is not None:
            data["received_bytes"] = int(received_bytes)
        service = next(
            (s for u in (url, *also_urls, referrer or "", tab_url or "") if u and (s := match_ai_domain(u))), None
        )
        if service is not None:
            data["ai_service"] = service
        art = self.artifact(ctx, cand, ArtifactKind.BROWSER_DOWNLOAD, data, locator=locator)
        yield art
        yield self.event(
            art,
            ts,
            ts_kind,
            EventCategory.DOWNLOAD,
            Actor.HUMAN,
            f"{browser} download: {url} -> {target or '(unknown)'}",
            ts_basis="native_utc" if ts is not None else "unknown",
            subject=target or None,
            data={"ai_service": service} if service is not None else {},
        )

    def _chromium(self, ctx: ParseContext, cand: Candidate, conn: sqlite3.Connection) -> Iterator[Artifact | Event]:
        url_cols = table_columns(conn, "urls")
        visit_cols = table_columns(conn, "visits")
        if {"id", "url"} <= url_cols and {"id", "url", "visit_time"} <= visit_cols:
            sel = _pick(url_cols, ("title",), "u.")
            rows = conn.execute(
                f"SELECT v.id AS vid, v.visit_time AS visit_time, u.url AS url, {sel} "
                "FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.id"
            ).fetchall()
            for row in rows:
                url = _text(row["url"])
                if url is None:
                    continue
                yield from self._visit(
                    ctx, cand, f"row:visits.id={row['vid']}", url, _text(row["title"]), from_webkit(row["visit_time"])
                )
        else:
            yield self.warning(ctx, cand, "History has no usable urls/visits tables; visits skipped")

        dl_cols = table_columns(conn, "downloads")
        if "id" not in dl_cols:
            return
        wanted = (
            "target_path", "current_path", "start_time", "received_bytes", "referrer", "tab_url", "tab_referrer_url"
        )
        chains: dict[int, list[str]] = {}
        chain_cols = table_columns(conn, "downloads_url_chains")
        if {"id", "chain_index", "url"} <= chain_cols:
            for crow in conn.execute("SELECT id, url FROM downloads_url_chains ORDER BY id, chain_index"):
                if (curl := _text(crow["url"])) is not None:
                    chains.setdefault(crow["id"], []).append(curl)
        for row in conn.execute(f"SELECT id, {_pick(dl_cols, wanted)} FROM downloads ORDER BY id"):
            chain = chains.get(row["id"], [])
            referrer = _text(row["referrer"]) or _text(row["tab_referrer_url"])
            yield from self._download(
                ctx,
                cand,
                f"row:downloads.id={row['id']}",
                url=chain[-1] if chain else "",
                target_raw=_text(row["target_path"]) or _text(row["current_path"]) or "",
                ts=from_webkit(row["start_time"]) if isinstance(row["start_time"], int) else None,
                ts_kind="download_start",
                received_bytes=_number(row["received_bytes"]),
                referrer=referrer,
                tab_url=_text(row["tab_url"]),
                also_urls=tuple(chain),
            )

    def _prefs(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        try:
            prefs = json.loads(ctx.fs.read_bytes(cand.ref).decode("utf-8"))
        except (ValueError, OSError) as exc:  # UnicodeDecodeError and JSONDecodeError are ValueErrors
            yield self.warning(ctx, cand, f"Preferences unreadable: {exc}")
            return
        selectfile = prefs.get("selectfile") if isinstance(prefs, dict) else None
        last_dir = selectfile.get("last_directory") if isinstance(selectfile, dict) else None
        if not isinstance(last_dir, str) or not last_dir:
            return
        os_family = cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN
        home = cand.user.home if cand.user is not None else None
        directory = normalize(last_dir, os_family, home)
        limitation = LIMITATIONS["BROWSER_LAST_DIR"]
        if not isinstance(limitation, dict):
            raise TypeError("LIMITATIONS['BROWSER_LAST_DIR'] must be a ko/en pair")
        art = self.artifact(
            ctx,
            cand,
            ArtifactKind.FILE_TRANSFER,
            {
                "channel": "browser_file_dialog_last_dir",
                "direction": "unknown",
                "local_paths": [directory],
                "tool": str(cand.extra["browser"]),
            },
            locator="key:selectfile.last_directory",
        )
        art = dataclasses.replace(art, warnings=(f"{limitation['ko']} / {limitation['en']}",))
        yield art
        mtime = ctx.fs.stat(cand.ref).mtime
        yield self.event(
            art,
            mtime,
            "file_mtime",
            EventCategory.OTHER,
            Actor.UNKNOWN,
            f"{cand.extra['browser']} last file-dialog directory: {directory}",
            ts_basis="native_utc" if mtime is not None else "unknown",
            subject=directory,
        )

    def _firefox(self, ctx: ParseContext, cand: Candidate, conn: sqlite3.Connection) -> Iterator[Artifact | Event]:
        place_cols = table_columns(conn, "moz_places")
        hv_cols = table_columns(conn, "moz_historyvisits")
        if {"id", "url"} <= place_cols and {"id", "place_id", "visit_date"} <= hv_cols:
            sel = _pick(place_cols, ("title",), "p.")
            for row in conn.execute(
                f"SELECT v.id AS vid, v.visit_date AS visit_date, p.url AS url, {sel} "
                "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id ORDER BY v.id"
            ):
                url = _text(row["url"])
                if url is None:
                    continue
                yield from self._visit(
                    ctx,
                    cand,
                    f"row:moz_historyvisits.id={row['vid']}",
                    url,
                    _text(row["title"]),
                    from_unix_us(row["visit_date"]),
                )
        else:
            yield self.warning(ctx, cand, "places.sqlite has no usable moz_places/moz_historyvisits; visits skipped")

        if not (has_table(conn, "moz_annos") and has_table(conn, "moz_anno_attributes")):
            return
        annos = conn.execute(
            "SELECT a.id AS aid, a.place_id AS place_id, n.name AS name, a.content AS content, "
            "a.dateAdded AS added, p.url AS url "
            "FROM moz_annos a JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id "
            "LEFT JOIN moz_places p ON p.id = a.place_id WHERE n.name IN (?, ?) ORDER BY a.id",
            (_FF_DEST_ANNO, _FF_META_ANNO),
        ).fetchall()
        sizes: dict[int, float] = {}
        for row in annos:
            if row["name"] != _FF_META_ANNO:
                continue
            try:
                meta = json.loads(_text(row["content"]) or "")
            except ValueError as exc:
                yield self.warning(ctx, cand, f"moz_annos.id={row['aid']} metaData is not JSON: {exc}")
                continue
            size = _number(meta.get("fileSize")) if isinstance(meta, dict) else None
            if size is not None:
                sizes[row["place_id"]] = size
        for row in annos:
            if row["name"] != _FF_DEST_ANNO:
                continue
            dest = _text(row["content"])
            if dest is None:
                continue
            yield from self._download(
                ctx,
                cand,
                f"row:moz_annos.id={row['aid']}",
                url=_text(row["url"]) or "",
                target_raw=_file_uri_path(dest),
                ts=from_unix_us(row["added"]) if isinstance(row["added"], int) else None,
                ts_kind="download_added",
                received_bytes=sizes.get(row["place_id"]),
                referrer=None,
                tab_url=None,
            )

    def _safari(self, ctx: ParseContext, cand: Candidate, conn: sqlite3.Connection) -> Iterator[Artifact | Event]:
        item_cols = table_columns(conn, "history_items")
        visit_cols = table_columns(conn, "history_visits")
        if not ({"id", "url"} <= item_cols and {"id", "history_item", "visit_time"} <= visit_cols):
            yield self.warning(ctx, cand, "History.db has no usable history_items/history_visits; visits skipped")
            return
        sel = _pick(visit_cols, ("title",), "v.")
        for row in conn.execute(
            f"SELECT v.id AS vid, v.visit_time AS visit_time, i.url AS url, {sel} "
            "FROM history_visits v JOIN history_items i ON i.id = v.history_item ORDER BY v.id"
        ):
            url = _text(row["url"])
            if url is None:
                continue
            ts = from_cocoa(row["visit_time"]) if isinstance(row["visit_time"], (int, float)) else None
            yield from self._visit(ctx, cand, f"row:history_visits.id={row['vid']}", url, _text(row["title"]), ts)


PLUGIN = Plugin()
