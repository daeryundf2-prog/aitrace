from __future__ import annotations

import html as htmllib
import importlib.util
import re
from pathlib import Path

from aitrace.report.html import render_html, render_html_string

_SPEC = importlib.util.spec_from_file_location("report_sample", Path(__file__).with_name("sample.py"))
assert _SPEC is not None and _SPEC.loader is not None
sample = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sample)

XSS = "<script>alert('x')</script>"
ALLOWED_COLORS = {"#000", "#fff", "#efefef", "#666"}


def _find(pattern: str, text: str, group: int = 0) -> str:
    match = re.search(pattern, text, re.DOTALL)
    assert match is not None, pattern
    return match.group(group)


def _style(html: str) -> str:
    return _find(r"<style>(.*?)</style>", html, 1)


def _visible_text(html: str) -> str:
    body = html.split("</style>", 1)[1]
    body = re.sub(r'<td class="raw">.*?</td>', "", body, flags=re.DOTALL)
    return htmllib.unescape(re.sub(r"<[^>]+>", " ", body))


def test_chapter_headings_follow_the_required_order() -> None:
    html = render_html_string(sample.make_model("ko"))
    found = re.findall(r'<h2 id="h\d+"><span class="no">(.*?)</span>(.*?)</h2>', html)
    assert [f"{no} {title}" for no, title in found] == sample.KO_CHAPTERS


def test_toc_links_every_chapter() -> None:
    html = render_html_string(sample.make_model("ko"))
    nav = _find(r"<nav.*?</nav>", html)
    for chapter in sample.KO_CHAPTERS:
        assert chapter in htmllib.unescape(nav)
    assert nav.count("href=") >= 12


def test_banned_expressions_do_not_appear_in_ko_text() -> None:
    text = _visible_text(render_html_string(sample.make_model("ko")))
    assert sample.find_banned(text) == []


def test_recovered_text_is_not_scanned_but_is_kept_verbatim() -> None:
    html = render_html_string(sample.make_model("ko", prompt="좋아요!\n둘째 줄"))
    assert '<td class="raw">좋아요!\n둘째 줄</td>' in html
    assert sample.find_banned(_visible_text(html)) == []


def test_plain_styling_only() -> None:
    css = _style(render_html_string(sample.make_model("ko")))
    for token in ("gradient", "box-shadow", "border-radius", "badge", "text-transform", "emoji"):
        assert token not in css
    colors = {c.lower() for c in re.findall(r"#[0-9a-fA-F]{3,6}\b", css)}
    assert colors <= ALLOWED_COLORS
    assert "#efefef" in css
    assert '"Noto Serif KR", "Nanum Myeongjo", "AppleMyungjo", "Batang", serif' in css
    assert "font-size: 10.5pt" in css and "font-size: 9pt" in css
    assert "0.5pt solid #000" in css
    assert "nth-child" not in css


def test_timeline_and_exports_use_landscape_pages() -> None:
    html = render_html_string(sample.make_model("ko"))
    assert html.count('<section class="chapter landscape">') == 2
    assert "size: A4 landscape" in html and "margin: 25mm" in html
    assert "문서번호 T-1-01 | 대외비" in html
    assert 'counter(page) " / " counter(pages)' in html


def test_markup_in_recovered_text_is_escaped() -> None:
    html = render_html_string(sample.make_model("ko", prompt=XSS))
    assert XSS not in html
    assert "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;" in html


def test_english_report_uses_english_chapters() -> None:
    html = render_html_string(sample.make_model("en"))
    assert 'lang="en"' in html
    for title in ("Overview", "Summary of Findings", "Timeline", "Examiner&#39;s Opinion"):
        assert title in html


def test_render_html_writes_a_single_file(tmp_path: Path) -> None:
    path = render_html(sample.make_model("ko"), tmp_path / "out" / "report.html")
    text = path.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "http://" not in text and "https://" not in text
    assert "<script" not in text
