from __future__ import annotations

import importlib.util
from pathlib import Path

import pypdfium2 as pdfium

from aitrace.report.layout import Document, Heading, Para
from aitrace.report.pdf import render_document_pdf, render_pdf

_SPEC = importlib.util.spec_from_file_location("report_sample", Path(__file__).with_name("sample.py"))
assert _SPEC is not None and _SPEC.loader is not None
sample = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sample)


BODY_START = 2


def _render(
    tmp_path: Path, lang: str = "ko", prompt: str = "경쟁사 제안서를 요약해줘"
) -> tuple[Path, list[str], list[tuple[float, float]]]:
    path = render_pdf(sample.make_model(lang, prompt=prompt), tmp_path / "report.pdf")
    pdf = pdfium.PdfDocument(str(path))
    texts = [page.get_textpage().get_text_range() for page in pdf]
    sizes = [page.get_size() for page in pdf]
    return path, texts, sizes


def _page_with(texts: list[str], needle: str) -> int:
    return next(i for i, text in enumerate(texts) if i >= BODY_START and needle in text)


def test_cover_toc_and_chapters_are_present(tmp_path: Path) -> None:
    _, texts, _ = _render(tmp_path)
    cover = texts[0]
    for label in ("사건번호", "문서번호", "감정·분석 대상", "의뢰처", "작성자", "작성일", "대외비"):
        assert label in cover
    assert "목차" in texts[1]
    for chapter in sample.KO_CHAPTERS:
        assert chapter.replace(" ", "") in "".join(texts[1].split()), chapter
        assert any(chapter.replace(" ", "") in "".join(text.split()) for text in texts[2:]), chapter


def test_first_chapter_follows_the_contents_page_without_a_blank_page(tmp_path: Path) -> None:
    _, texts, _ = _render(tmp_path)
    assert "제1장" in texts[2]


def test_header_and_footer_on_body_pages_only(tmp_path: Path) -> None:
    _, texts, _ = _render(tmp_path)
    assert "| 대외비" not in texts[0] and "- 1 /" not in texts[0]
    assert "문서번호 T-1-01 | 대외비" in texts[2]
    assert f"- 3 / {len(texts)} -" in texts[2]


def test_timeline_and_annex_one_are_landscape_and_the_rest_portrait(tmp_path: Path) -> None:
    _, texts, sizes = _render(tmp_path)
    landscape = {i for i, (w, h) in enumerate(sizes) if w > h}
    assert _page_with(texts, "제5장 타임라인") in landscape
    assert _page_with(texts, "별첨1 추출 자료 목록") in landscape
    for chapter in ("제4장 생성물", "제6장", "제9장 감정", "별첨3"):
        index = max(i for i, text in enumerate(texts) if chapter in text)
        assert index not in landscape, chapter
    assert 0 not in landscape and 1 not in landscape


def test_recovered_prompt_and_day_groups_are_rendered(tmp_path: Path) -> None:
    _, texts, _ = _render(tmp_path, prompt="경쟁사 제안서를 요약해줘")
    body = "\n".join(texts)
    assert "경쟁사 제안서를 요약해줘" in body
    assert "세션 s1" in body
    assert "2026-03-01 (2건)" in body and "일자 미상 (1건)" in body


def test_serif_body_font_is_embedded(tmp_path: Path) -> None:
    path, _, _ = _render(tmp_path)
    data = path.read_bytes()
    assert b"NanumMyeongjo" in data
    assert b"Courier" not in data


def test_english_pdf_renders(tmp_path: Path) -> None:
    _, texts, _ = _render(tmp_path, lang="en")
    assert "Chapter 1" in "\n".join(texts)
    assert "Document No. T-1-01 | Confidential" in texts[2]


def test_short_chapters_share_a_page_instead_of_each_taking_one(tmp_path: Path) -> None:
    blocks = []
    for n in range(1, 4):
        blocks += [Heading(1, f"제{n}장", f"짧은 장 {n}", f"h{n}"), Para("해당 발견 사항 없음.")]
    doc = Document(
        lang="ko", title="시험", header_text="시험", cover=[("사건번호", "X")], notice="", blocks=blocks
    )
    pdf = pdfium.PdfDocument(render_document_pdf(doc, tmp_path / "short.pdf"))
    assert len(pdf) == 3
