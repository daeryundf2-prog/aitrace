from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Any
from xml.etree import ElementTree

from aitrace.core.catalog import SECRET_PATTERNS, redact
from aitrace.core.kinds import Actor, ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.core.paths import normalize
from aitrace.fs.base import EntryRef
from aitrace.plugins.base import Candidate, ParseContext, PluginBase
from aitrace.plugins.fsmeta.file_inventory import (
    EXCLUDED_SUBPATHS,
    MAX_CONTENT_BYTES,
    MAX_DEPTH,
    MAX_FILES_PER_USER,
    PRUNE_NAMES,
    W_NS,
)

A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
TEXT_EXTENSIONS = frozenset({".md", ".txt", ".rtf", ".html", ".csv", ".json", ".py", ".js", ".ts"})
DOCX_EXTENSION = ".docx"
PPTX_EXTENSION = ".pptx"
MAX_EXCERPTS = 3
EXCERPT_CHARS = 160
MAX_HINTS = 50
EVENT_SUMMARY = "AI usage clue in document"
_ARCHIVE_ERRORS = (zipfile.BadZipFile, KeyError, ElementTree.ParseError)
_SLIDE_NAME = re.compile(r"ppt/slides/slide(\d+)\.xml")

_FLAGS = re.IGNORECASE | re.MULTILINE
CLUE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "CLUE-SELFREF",
        re.compile(
            r"as an ai language model|as a large language model|저는 ai|ai 언어 모델로서|i'm sorry, but i can't",
            _FLAGS,
        ),
    ),
    ("CLUE-CHATUI", re.compile(r"regenerate response|chatgpt said|copy code|^[ \t]*you said:", _FLAGS)),
    (
        "CLUE-BRAND",
        re.compile(r"\b(?:chatgpt|gpt-4|gpt-5|claude|gemini|copilot|perplexity|midjourney|dall[·-]e)", _FLAGS),
    ),
    ("CLUE-PROMPT", re.compile(r"^[ \t]*prompt:|프롬프트:|다음과 같이 작성해줘|\bact as a\b", _FLAGS)),
    (
        "CLUE-ARTIFACT",
        re.compile(r"【\d+†|turn0search\d*|oaicite|contentReference\[oaicite", _FLAGS),
    ),
)
_SECRET_RES = tuple(re.compile(regex) for _, regex in SECRET_PATTERNS)


def _excluded(path: str) -> bool:
    return any(marker in path for marker in EXCLUDED_SUBPATHS)


def _eligible(path: str, size: int | None) -> bool:
    if size is None or size > MAX_CONTENT_BYTES:
        return False
    suffix = PurePosixPath(path).suffix.lower()
    return suffix in TEXT_EXTENSIONS or suffix in (DOCX_EXTENSION, PPTX_EXTENSION)


def _paragraph_text(root: ElementTree.Element, ns: str) -> str:
    lines = ["".join(t.text or "" for t in para.iter(f"{{{ns}}}t")) for para in root.iter(f"{{{ns}}}p")]
    return "\n".join(lines)


def _decode_text(raw: bytes, path: str) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == DOCX_EXTENSION:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            return _paragraph_text(ElementTree.fromstring(archive.read("word/document.xml")), W_NS)
    if suffix == PPTX_EXTENSION:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            slides = sorted(
                (int(m.group(1)), name) for name in archive.namelist() if (m := _SLIDE_NAME.fullmatch(name))
            )
            if not slides:
                raise KeyError("ppt/slides/slide*.xml")
            return "\n".join(_paragraph_text(ElementTree.fromstring(archive.read(name)), A_NS) for _, name in slides)
    return raw.decode("utf-8", errors="replace")


def _scrub(text: str) -> str:
    for pattern in _SECRET_RES:
        text = pattern.sub(lambda m: redact(m.group(0)), text)
    return text


def _excerpt(text: str, start: int, end: int) -> str:
    pad = max(0, (EXCERPT_CHARS - (end - start)) // 2)
    window = _scrub(text[max(0, start - pad) : end + pad])
    return " ".join(window.split())[:EXCERPT_CHARS]


def find_clues(text: str) -> tuple[list[dict[str, str]], list[str], set[str]]:
    hints: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    spans: list[tuple[int, int]] = []
    rules: set[str] = set()
    for rule_id, pattern in CLUE_RULES:
        for match in pattern.finditer(text):
            rules.add(rule_id)
            shown = " ".join(match.group(0).split())
            key = (rule_id, shown.lower())
            if key not in seen and len(hints) < MAX_HINTS:
                seen.add(key)
                hints.append({"type": "metadata_hint", "value": f"clue:{rule_id}:{shown}"})
            spans.append(match.span())
    spans.sort()
    excerpts: list[str] = []
    last_end = -1
    for start, end in spans:
        if len(excerpts) == MAX_EXCERPTS:
            break
        if start < last_end:
            continue
        excerpts.append(_excerpt(text, start, end))
        last_end = end
    return hints, excerpts, rules


class DocCluesPlugin(PluginBase):
    name = "doc_clues"
    version = "1.0"
    description = "Textual clues of AI use in user documents (clues only, never proof)"

    def locate(self, fs: Any) -> Iterator[Candidate]:
        for user in fs.users():
            yield Candidate(ref=EntryRef(user.volume, user.home), role="home", user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        walked = ctx.fs.walk(cand.ref, max_depth=MAX_DEPTH, skip_names=PRUNE_NAMES)
        kept = (ref for ref in walked if not _excluded(ref.path))
        for count, ref in enumerate(kept, start=1):
            if count > MAX_FILES_PER_USER:
                yield self.warning(ctx, cand, f"file cap of {MAX_FILES_PER_USER} reached; remaining files skipped")
                return
            yield from self._scan(ctx, cand, ref)

    def _scan(self, ctx: ParseContext, cand: Candidate, ref: EntryRef) -> Iterator[Artifact | Event]:
        if PurePosixPath(ref.path).suffix.lower() not in TEXT_EXTENSIONS | {DOCX_EXTENSION, PPTX_EXTENSION}:
            return
        file_cand = Candidate(ref=ref, role=cand.role, user=cand.user)
        try:
            st = ctx.fs.stat(ref)
        except OSError as exc:
            yield self.warning(ctx, file_cand, f"stat failed: {exc}")
            return
        if not _eligible(ref.path, st.size):
            return
        try:
            raw = ctx.fs.read_bytes(ref)
        except OSError as exc:
            yield self.warning(ctx, file_cand, f"unreadable content: {exc}")
            return
        try:
            text = _decode_text(raw, ref.path)
        except _ARCHIVE_ERRORS as exc:
            yield self.warning(ctx, file_cand, f"office text extraction failed: {exc}")
            return
        hints, excerpts, rules = find_clues(text)
        if not rules:
            return
        os_family = cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN
        home = cand.user.home if cand.user is not None else None
        path = normalize(ref.path, os_family, home)
        extra: dict[str, Any] = {"clue": True, "excerpts": excerpts}
        if rules == {"CLUE-BRAND"}:
            extra["weak"] = True
        data: dict[str, Any] = {"path": path, "hints": hints, "extra": extra}
        artifact = self.artifact(ctx, file_cand, ArtifactKind.DOC_METADATA, data, locator="clues")
        yield artifact
        yield self.event(
            artifact,
            st.mtime,
            "file_mtime",
            EventCategory.OTHER,
            Actor.UNKNOWN,
            EVENT_SUMMARY,
            ts_basis="native_utc" if st.mtime is not None else "unknown",
            subject=path,
        )


PLUGIN = DocCluesPlugin()
