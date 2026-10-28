from __future__ import annotations

import posixpath
import re
import sqlite3
import struct
from collections.abc import Iterator
from typing import Any

from aitrace.core.catalog import match_ai_domain, redact
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily, SignalType
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import basename, normalize
from aitrace.fs.base import EntryRef, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase
from aitrace.plugins.common.sqlite import has_table, open_sqlite

try:
    from aitrace.plugins.provenance import images as _images
except ImportError:
    _images = None

TOOL = "Browser cache"
MAX_ENTRY_BYTES = 64 * 1024 * 1024

_SIMPLE_HEADER_MAGIC = 0xFCFB6D1BA7725C30
_SIMPLE_EOF_MAGIC = 0xF4FA6F45970D41D8
_SIMPLE_HEADER = struct.Struct("<QIIII")
_SIMPLE_EOF = struct.Struct("<QIIII")
_EOF_HAS_KEY_SHA256 = 2
_SHA256_LEN = 32
_BLOCKFILE_INDEX_MAGIC = b"\xc3\xca\x03\xc1"

_SIMPLE_NAME = re.compile(r"^[0-9a-f]{16}_0$")
_BLOCK_NAME = re.compile(r"^(?:f_[0-9a-f]{6}|data_[0-3])$", re.IGNORECASE)
_FIREFOX_NAME = re.compile(r"^[0-9A-Fa-f]{40}$")
_FIREFOX_KEY = re.compile(rb":(https?://[^\x00]+)")
_CONTENT_TYPE = re.compile(rb"content-type:[ \t]*([^\r\n\x00;]+)", re.IGNORECASE)
_URL_IN_BLOCK = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,512}")
_SECRET_PARAM = re.compile(
    r"([?&](?:sig|signature|token|access_token|key|x-amz-signature|x-amz-security-token|x-goog-signature)=)"
    r"([^&#\s]+)",
    re.IGNORECASE,
)

_IMAGE_TYPES: tuple[tuple[str, str, bytes], ...] = (
    ("png", "image/png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", "image/jpeg", b"\xff\xd8\xff"),
    ("gif", "image/gif", b"GIF87a"),
    ("gif", "image/gif", b"GIF89a"),
)

_CHROMIUM_CACHE_ROOTS: dict[str, tuple[str, ...]] = {
    "Chrome": (
        "Library/Caches/Google/Chrome",
        "Library/Application Support/Google/Chrome",
        ".cache/google-chrome",
        ".config/google-chrome",
        "AppData/Local/Google/Chrome/User Data",
    ),
    "Edge": (
        "Library/Caches/Microsoft Edge",
        "Library/Application Support/Microsoft Edge",
        ".cache/microsoft-edge",
        ".config/microsoft-edge",
        "AppData/Local/Microsoft/Edge/User Data",
    ),
    "Brave": (
        "Library/Caches/BraveSoftware/Brave-Browser",
        "Library/Application Support/BraveSoftware/Brave-Browser",
        ".cache/BraveSoftware/Brave-Browser",
        ".config/BraveSoftware/Brave-Browser",
        "AppData/Local/BraveSoftware/Brave-Browser/User Data",
    ),
    "Arc": (
        "Library/Caches/Arc/User Data",
        "Library/Application Support/Arc/User Data",
        "AppData/Local/Arc/User Data",
    ),
    "Opera": (
        "Library/Caches/com.operasoftware.Opera",
        "Library/Application Support/com.operasoftware.Opera",
        ".cache/opera",
        ".config/opera",
        "AppData/Local/Opera Software/Opera Stable",
        "AppData/Roaming/Opera Software/Opera Stable",
    ),
}
_FIREFOX_PROFILE_GLOBS: tuple[str, ...] = (
    "Library/Caches/Firefox/Profiles/*",
    ".cache/mozilla/firefox/*",
    "AppData/Local/Mozilla/Firefox/Profiles/*",
)
_SAFARI_DB = "Library/Caches/com.apple.Safari/Cache.db"


class _CacheError(ValueError):
    pass


def _image_type(body: bytes) -> tuple[str, str] | None:
    for kind, mime, magic in _IMAGE_TYPES:
        if body.startswith(magic):
            return kind, mime
    if body[:4] == b"RIFF" and body[8:12] == b"WEBP":
        return "webp", "image/webp"
    return None


def _redact_url(url: str) -> str:
    return _SECRET_PARAM.sub(lambda m: m.group(1) + redact(m.group(2)), url)


def _header_content_type(headers: bytes) -> str | None:
    match = _CONTENT_TYPE.search(headers)
    return match.group(1).decode("latin-1").strip().lower() if match else None


def _marker_signals(body: bytes) -> list[tuple[SignalType, str]]:
    if b"caBX" in body or (b"jumb" in body and b"c2pa" in body):
        return [(SignalType.C2PA, "present")]
    return []


def _image_signals(kind: str, body: bytes, url: str) -> list[tuple[SignalType, str]]:
    filename = basename(url.split("?", 1)[0].split("#", 1)[0]) or ""
    if _images is not None:
        try:
            return list(_images._signals(kind, body, filename))
        except (OSError, ValueError, SyntaxError, struct.error):
            pass
    return _marker_signals(body)


def _simple_entry(data: bytes) -> tuple[str, int, int, bytes]:
    if len(data) < _SIMPLE_HEADER.size:
        raise _CacheError("truncated simple cache header")
    magic, _version, key_length, _key_hash, _pad = _SIMPLE_HEADER.unpack_from(data, 0)
    if magic != _SIMPLE_HEADER_MAGIC:
        raise _CacheError("bad simple cache header magic")
    key_end = _SIMPLE_HEADER.size + key_length
    if key_end > len(data):
        raise _CacheError("key length exceeds file size")
    key = data[_SIMPLE_HEADER.size : key_end].decode("utf-8", errors="replace")

    eof0_at = len(data) - _SIMPLE_EOF.size
    if eof0_at < key_end:
        raise _CacheError("no stream 0 EOF record")
    magic0, flags0, _crc0, size0, _pad0 = _SIMPLE_EOF.unpack_from(data, eof0_at)
    if magic0 != _SIMPLE_EOF_MAGIC:
        raise _CacheError("bad stream 0 EOF magic")
    sha_len = _SHA256_LEN if flags0 & _EOF_HAS_KEY_SHA256 else 0
    headers_end = eof0_at - sha_len
    headers_start = headers_end - size0
    eof1_at = headers_start - _SIMPLE_EOF.size
    if eof1_at < key_end:
        raise _CacheError("stream 0 size exceeds file size")
    magic1, _flags1, _crc1, size1, _pad1 = _SIMPLE_EOF.unpack_from(data, eof1_at)
    if magic1 != _SIMPLE_EOF_MAGIC:
        raise _CacheError("bad stream 1 EOF magic")
    body_start = eof1_at - size1
    if body_start < key_end:
        raise _CacheError("stream 1 size exceeds file size")
    return key, body_start, size1, data[headers_start:headers_end]


def _last_url(key: str) -> str | None:
    tokens = [t for t in key.split() if "://" in t]
    return tokens[-1] if tokens else None


class Plugin(PluginBase):
    name = "cache_images"
    version = "1.0"
    description = "AI-site images recovered from Chromium, Firefox and Safari browser caches"

    def locate(self, fs: Any) -> Iterator[Candidate]:
        for user in fs.users():
            yield from self._chromium(fs, user)
            for profile in _FIREFOX_PROFILE_GLOBS:
                for ref in user_glob(fs, user, f"{profile}/cache2/entries/*"):
                    if _FIREFOX_NAME.match(posixpath.basename(ref.path)) and not fs.is_dir(ref):
                        yield Candidate(ref, "firefox", user, {"browser": "Firefox"})
            for ref in user_glob(fs, user, _SAFARI_DB):
                yield Candidate(ref, "safari", user, {"browser": "Safari"})

    @staticmethod
    def _chromium(fs: Any, user: Any) -> Iterator[Candidate]:
        seen: set[str] = set()
        for browser, roots in _CHROMIUM_CACHE_ROOTS.items():
            for root in roots:
                for cache_dir in (
                    f"{root}/*/Cache/Cache_Data",
                    f"{root}/Cache/Cache_Data",
                    f"{root}/*/Cache",
                    f"{root}/Cache",
                ):
                    for ref in user_glob(fs, user, f"{cache_dir}/*"):
                        name = posixpath.basename(ref.path)
                        if ref.path in seen or fs.is_dir(ref):
                            continue
                        if _SIMPLE_NAME.match(name):
                            role = "simple"
                        elif name == "index" and fs.read_bytes(ref, 4) == _BLOCKFILE_INDEX_MAGIC:
                            role = "blockfile"
                        else:
                            continue
                        seen.add(ref.path)
                        yield Candidate(ref, role, user, {"browser": browser})

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        match cand.role:
            case "simple":
                yield from self._simple(ctx, cand)
            case "firefox":
                yield from self._firefox(ctx, cand)
            case "safari":
                yield from self._safari(ctx, cand)
            case "blockfile":
                yield from self._blockfile(ctx, cand)
            case _:
                raise ValueError(f"unknown browser cache candidate role {cand.role!r}")

    def _emit(
        self,
        ctx: ParseContext,
        cand: Candidate,
        url: str,
        body: bytes,
        body_offset: int,
        content_type: str | None,
        locator: str,
    ) -> Iterator[Artifact | Event]:
        image = _image_type(body)
        if image is None or match_ai_domain(url) is None:
            return
        kind, mime = image
        shown_url = _redact_url(url)
        signals: list[tuple[SignalType, str]] = [(SignalType.AI_DOWNLOAD_ORIGIN, f"browser cache: {shown_url}")]
        for signal in _image_signals(kind, body, url):
            if signal not in signals:
                signals.append(signal)
        os_family = cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN
        data: dict[str, Any] = {
            "path": normalize(cand.ref.path, os_family),
            "signals": [{"type": s.value, "value": v} for s, v in signals],
            "extra": {
                "recovered_from": "browser_cache",
                "url": shown_url,
                "browser": str(cand.extra["browser"]),
                "body_offset": body_offset,
                "body_size": len(body),
                "content_type": content_type or mime,
            },
        }
        artifact = self.artifact(ctx, cand, ArtifactKind.MEDIA_PROVENANCE, data, locator=locator)
        yield artifact
        mtime = ctx.fs.stat(cand.ref).mtime
        yield self.event(
            artifact,
            mtime,
            "file_mtime",
            EventCategory.BROWSING,
            Actor.HUMAN,
            f"AI image viewed (cache): {shown_url}",
            ts_basis="native_utc" if mtime is not None else "unknown",
            subject=shown_url,
        )

    def _simple(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        data = ctx.fs.read_bytes(cand.ref, MAX_ENTRY_BYTES)
        try:
            key, offset, size, headers = _simple_entry(data)
        except _CacheError as exc:
            yield self.warning(ctx, cand, f"corrupt simple cache entry: {exc}")
            return
        url = _last_url(key)
        if url is None:
            yield self.warning(ctx, cand, "simple cache key holds no URL")
            return
        yield from self._emit(
            ctx, cand, url, data[offset : offset + size], offset, _header_content_type(headers), "body"
        )

    def _firefox(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        data = ctx.fs.read_bytes(cand.ref, MAX_ENTRY_BYTES)
        if len(data) < 8:
            yield self.warning(ctx, cand, "corrupt firefox cache2 entry: too small")
            return
        (meta_offset,) = struct.unpack(">I", data[-4:])
        if not 0 < meta_offset < len(data) - 4:
            yield self.warning(ctx, cand, "corrupt firefox cache2 entry: metadata offset out of range")
            return
        meta = data[meta_offset:-4]
        key = _FIREFOX_KEY.search(meta)
        if key is None:
            yield self.warning(ctx, cand, "corrupt firefox cache2 entry: no URL key in metadata")
            return
        url = key.group(1).decode("utf-8", errors="replace")
        yield from self._emit(ctx, cand, url, data[:meta_offset], 0, _header_content_type(meta), "body")

    def _safari(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        directory = posixpath.dirname(cand.ref.path)
        try:
            with open_sqlite(ctx.fs, cand.ref) as conn:
                if not (has_table(conn, "cfurl_cache_response") and has_table(conn, "cfurl_cache_receiver_data")):
                    yield self.warning(ctx, cand, "Safari Cache.db lacks cfurl_cache tables")
                    return
                rows = conn.execute(
                    "SELECT r.entry_ID AS entry_id, r.request_key AS url, d.isDataOnFS AS on_fs, "
                    "d.receiver_data AS payload FROM cfurl_cache_response r "
                    "JOIN cfurl_cache_receiver_data d ON d.entry_ID = r.entry_ID ORDER BY r.entry_ID"
                ).fetchall()
        except (sqlite3.Error, OSError) as exc:
            yield self.warning(ctx, cand, f"cannot read Safari Cache.db: {exc}")
            return
        for row in rows:
            url = row["url"]
            if not isinstance(url, str) or match_ai_domain(url) is None:
                continue
            payload = row["payload"]
            if row["on_fs"]:
                name = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload)
                body_ref = EntryRef(cand.ref.volume, posixpath.join(directory, "fsCachedData", posixpath.basename(name)))
                try:
                    payload = ctx.fs.read_bytes(body_ref, MAX_ENTRY_BYTES)
                except OSError:
                    yield self.warning(ctx, cand, f"entry {row['entry_id']}: fsCachedData file missing")
                    continue
            if not isinstance(payload, bytes):
                continue
            yield from self._emit(ctx, cand, url, payload, 0, None, f"row:{row['entry_id']}")

    def _blockfile(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        directory = EntryRef(cand.ref.volume, posixpath.dirname(cand.ref.path))
        carved: dict[str, int] = {}
        ai_urls: set[str] = set()
        for ref in ctx.fs.listdir(directory):
            name = posixpath.basename(ref.path)
            if not _BLOCK_NAME.match(name) or ctx.fs.is_dir(ref):
                continue
            blob = ctx.fs.read_bytes(ref, MAX_ENTRY_BYTES)
            if name.lower().startswith("f_"):
                image = _image_type(blob)
                if image is not None:
                    carved[image[0]] = carved.get(image[0], 0) + 1
                continue
            for _kind, _mime, magic in _IMAGE_TYPES:
                carved[_kind] = carved.get(_kind, 0) + blob.count(magic)
            carved["webp"] = carved.get("webp", 0) + blob.count(b"WEBP")
            for match in _URL_IN_BLOCK.finditer(blob):
                url = match.group(0).decode("ascii", errors="replace")
                if match_ai_domain(url) is not None:
                    ai_urls.add(_redact_url(url))
        carved = {k: v for k, v in carved.items() if v}
        if not carved and not ai_urls:
            return
        detail = (
            f"blockfile cache {directory.path}: image magics {dict(sorted(carved.items()))}; "
            f"{len(ai_urls)} AI-host URL(s); per-entry body recovery not supported (best effort)"
        )
        data: dict[str, Any] = {
            "tool": TOOL,
            "kind": "store",
            "status": "present",
            "detail": detail,
            "extra": {"cache_type": "blockfile", "browser": str(cand.extra["browser"]), "ai_urls": sorted(ai_urls)[:50]},
        }
        yield self.artifact(ctx, cand, ArtifactKind.AI_APP_PRESENCE, data, locator="blockfile")


PLUGIN = Plugin()
