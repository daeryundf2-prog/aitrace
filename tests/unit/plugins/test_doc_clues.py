from __future__ import annotations

import io
import logging
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from docx import Document

from aitrace.core.kinds import ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.fsmeta.doc_clues import PLUGIN

LOG = logging.getLogger("tests.doc_clues")
HOME = "/Users/kim"
T0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


def _run(files: dict[str, bytes], mtimes: dict[str, datetime] | None = None) -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=OsFamily.MACOS, mtimes=mtimes or {})
    ctx = ParseContext(fs=fs, evidence_id="ev-1", tz="UTC", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _kind(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _events(records: list[Artifact | Event]) -> list[Event]:
    return [r for r in records if isinstance(r, Event)]


def _hint_values(artifact: Artifact) -> list[str]:
    return [h["value"] for h in artifact.data["hints"]]


def _docx(paragraphs: list[str]) -> bytes:
    document = Document()
    for text in paragraphs:
        document.add_paragraph(text)
    buf = io.BytesIO()
    document.save(buf)
    return buf.getvalue()


def _pptx(slide_texts: list[str]) -> bytes:
    ns = "http://schemas.openxmlformats.org/drawingml/2006/main"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for number, text in enumerate(slide_texts, start=1):
            archive.writestr(
                f"ppt/slides/slide{number}.xml",
                f'<p:sld xmlns:p="p" xmlns:a="{ns}"><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:sld>',
            )
    return buf.getvalue()


def test_locate_yields_one_candidate_per_home() -> None:
    fs = MemoryFS({f"{HOME}/a.txt": b"x"}, volume_os=OsFamily.MACOS)
    assert [c.role for c in PLUGIN.locate(fs)] == ["home"]


def test_text_file_with_selfref_and_brand_emits_one_artifact_and_one_event() -> None:
    path = f"{HOME}/essay.md"
    body = "Intro.\nAs an AI language model, I think so. ChatGPT wrote it.\nAs an AI language model again.\n"
    records = _run({path: body.encode(), f"{HOME}/clean.txt": b"nothing here"}, {path: T0})

    docs = _kind(records, ArtifactKind.DOC_METADATA)
    assert len(docs) == 1
    doc = docs[0]
    assert doc.data["path"] == path
    assert _hint_values(doc) == ["clue:CLUE-SELFREF:As an AI language model", "clue:CLUE-BRAND:ChatGPT"]
    assert all(h["type"] == "metadata_hint" for h in doc.data["hints"])
    extra = doc.data["extra"]
    assert extra["clue"] is True
    assert "weak" not in extra
    assert 1 <= len(extra["excerpts"]) <= 3
    assert all(len(e) <= 160 for e in extra["excerpts"])
    assert doc.user == "kim"

    events = _events(records)
    assert len(events) == 1
    assert events[0].category == EventCategory.OTHER
    assert events[0].summary == "AI usage clue in document"
    assert events[0].ts_kind == "file_mtime"
    assert events[0].ts_utc == T0
    assert not _kind(records, ArtifactKind.PARSE_WARNING)


@pytest.mark.parametrize(
    ("text", "rule", "matched"),
    [
        ("저는 AI 입니다", "CLUE-SELFREF", "저는 AI"),
        ("I'm sorry, but I can't do that", "CLUE-SELFREF", "I'm sorry, but I can't"),
        ("Regenerate response", "CLUE-CHATUI", "Regenerate response"),
        ("line\nYou said: hi", "CLUE-CHATUI", "You said:"),
        ("Prompt: write a poem", "CLUE-PROMPT", "Prompt:"),
        ("프롬프트: 시 써줘", "CLUE-PROMPT", "프롬프트:"),
        ("please Act as a lawyer", "CLUE-PROMPT", "Act as a"),
        ("source 【12†link】", "CLUE-ARTIFACT", "【12†"),
        ("see turn0search1 here", "CLUE-ARTIFACT", "turn0search1"),
        ("x contentReference[oaicite:0]", "CLUE-ARTIFACT", "contentReference[oaicite"),
        ("x oaicite:0", "CLUE-ARTIFACT", "oaicite"),
        ("made with DALL·E", "CLUE-BRAND", "DALL·E"),
        ("made with dall-e", "CLUE-BRAND", "dall-e"),
    ],
)
def test_each_rule_matches_case_insensitively(text: str, rule: str, matched: str) -> None:
    records = _run({f"{HOME}/doc.txt": text.encode()})
    docs = _kind(records, ArtifactKind.DOC_METADATA)
    assert len(docs) == 1
    assert f"clue:{rule}:{matched}" in _hint_values(docs[0])


def test_line_anchored_rules_do_not_match_mid_line() -> None:
    records = _run({f"{HOME}/doc.txt": b"he said you said: x and the prompt: y"})
    assert not _kind(records, ArtifactKind.DOC_METADATA)


def test_brand_only_match_is_weak() -> None:
    records = _run({f"{HOME}/doc.txt": b"We compared Gemini and Claude."})
    doc = _kind(records, ArtifactKind.DOC_METADATA)[0]
    assert doc.data["extra"]["weak"] is True
    assert len(_events(records)) == 1


def test_brand_plus_other_rule_is_not_weak() -> None:
    records = _run({f"{HOME}/doc.txt": b"Claude here.\nPrompt: do it"})
    assert "weak" not in _kind(records, ArtifactKind.DOC_METADATA)[0].data["extra"]


def test_excerpts_are_capped_at_three_and_160_chars() -> None:
    long_pad = "x" * 400
    body = "\n".join(f"{long_pad} chatgpt {long_pad} claude {long_pad} gemini {long_pad} copilot" for _ in range(2))
    doc = _kind(_run({f"{HOME}/doc.md": body.encode()}), ArtifactKind.DOC_METADATA)[0]
    assert len(doc.data["extra"]["excerpts"]) == 3
    assert all(len(e) <= 160 for e in doc.data["extra"]["excerpts"])


def test_secrets_in_excerpts_are_redacted() -> None:
    secret = "sk-" + "A1b2C3d4E5" * 3
    doc = _kind(_run({f"{HOME}/doc.txt": f"ChatGPT key {secret} end".encode()}), ArtifactKind.DOC_METADATA)[0]
    assert secret not in "".join(doc.data["extra"]["excerpts"])


def test_docx_text_is_scanned() -> None:
    records = _run({f"{HOME}/report.docx": _docx(["Intro", "As a large language model, I cannot."])})
    doc = _kind(records, ArtifactKind.DOC_METADATA)[0]
    assert "clue:CLUE-SELFREF:As a large language model" in _hint_values(doc)
    assert not _kind(records, ArtifactKind.PARSE_WARNING)


def test_docx_paragraph_start_anchors_apply() -> None:
    records = _run({f"{HOME}/report.docx": _docx(["Hello", "Prompt: summarize"])})
    assert "clue:CLUE-PROMPT:Prompt:" in _hint_values(_kind(records, ArtifactKind.DOC_METADATA)[0])


def test_pptx_slide_text_is_scanned() -> None:
    records = _run({f"{HOME}/deck.pptx": _pptx(["Title", "Generated by Midjourney"])})
    doc = _kind(records, ArtifactKind.DOC_METADATA)[0]
    assert _hint_values(doc) == ["clue:CLUE-BRAND:Midjourney"]
    assert doc.data["extra"]["weak"] is True


def test_corrupt_docx_yields_warning_and_scan_continues() -> None:
    records = _run({f"{HOME}/bad.docx": b"not a zip at all", f"{HOME}/ok.txt": b"chatgpt said hi"})
    warnings = _kind(records, ArtifactKind.PARSE_WARNING)
    assert len(warnings) == 1
    assert warnings[0].data["plugin"] == "doc_clues"
    assert warnings[0].provenance.source_path == f"{HOME}/bad.docx"
    docs = _kind(records, ArtifactKind.DOC_METADATA)
    assert [d.data["path"] for d in docs] == [f"{HOME}/ok.txt"]


def test_docx_without_document_xml_and_corrupt_pptx_warn() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("other.xml", "<a/>")
    records = _run({f"{HOME}/empty.docx": buf.getvalue(), f"{HOME}/bad.pptx": b"junk"})
    assert len(_kind(records, ArtifactKind.PARSE_WARNING)) == 2
    assert not _kind(records, ArtifactKind.DOC_METADATA)


def test_skip_rules_extension_size_and_pruned_dirs() -> None:
    big = b"chatgpt " + b"a" * (2 * 1024 * 1024)
    records = _run(
        {
            f"{HOME}/image.png": b"chatgpt",
            f"{HOME}/big.txt": big,
            f"{HOME}/proj/node_modules/x.js": b"chatgpt",
            f"{HOME}/Library/Caches/c.txt": b"chatgpt",
            f"{HOME}/keep.json": b'{"a": "chatgpt"}',
        }
    )
    assert [d.data["path"] for d in _kind(records, ArtifactKind.DOC_METADATA)] == [f"{HOME}/keep.json"]


@pytest.mark.realdata
def test_host_documents_scan_without_errors_when_present() -> None:
    home = Path.home()
    host_files = sorted(
        (
            p
            for pattern in ("Documents/*.md", "Documents/*.txt", "Desktop/*.md", "Desktop/*.txt")
            for p in home.glob(pattern)
            if p.is_file() and p.stat().st_size <= 2 * 1024 * 1024
        ),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:20]
    if not host_files:
        pytest.skip("store absent: ~/Documents or ~/Desktop *.md/*.txt")
    fs = MemoryFS(
        {f"/Users/examiner/{p.relative_to(home).as_posix()}": p.read_bytes() for p in host_files},
        volume_os=OsFamily.MACOS,
    )
    ctx = ParseContext(fs, "real", "UTC", logging.getLogger("t"))
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    assert not _kind(records, ArtifactKind.PARSE_WARNING)
    docs = _kind(records, ArtifactKind.DOC_METADATA)
    assert len(_events(records)) == len(docs)
    assert all(d.data["extra"]["clue"] is True for d in docs)
