from __future__ import annotations

import pytest

from aitrace.core.kinds import OsFamily
from aitrace.core.paths import basename, normalize, same_path


@pytest.mark.parametrize(
    ("raw", "os_family", "home", "expected"),
    [
        (r"C:\Users\kim\work\proposal.md", OsFamily.WINDOWS, None, "/Users/kim/work/proposal.md"),
        (r"\\?\C:\Users\kim\x.txt", OsFamily.WINDOWS, None, "/Users/kim/x.txt"),
        (r"c:/Users//kim/./work/../a.md", OsFamily.WINDOWS, None, "/Users/kim/a.md"),
        ("~/proj/parser.py", OsFamily.MACOS, "/Users/lee", "/Users/lee/proj/parser.py"),
        ("~", OsFamily.LINUX, "/home/park/", "/home/park"),
        (r"~\Documents\a.docx", OsFamily.WINDOWS, r"C:\Users\kim", "/Users/kim/Documents/a.docx"),
        ("home/park/app/dump.py", OsFamily.LINUX, None, "/home/park/app/dump.py"),
        ("//home///park/", OsFamily.LINUX, None, "/home/park"),
        ("/../../etc/passwd", OsFamily.LINUX, None, "/etc/passwd"),
        ("/", OsFamily.LINUX, None, "/"),
    ],
)
def test_normalize(raw: str, os_family: OsFamily, home: str | None, expected: str) -> None:
    assert normalize(raw, os_family, home) == expected


def test_normalize_keeps_tilde_without_home() -> None:
    assert normalize("~/x", OsFamily.LINUX) == "/~/x"


def test_normalize_preserves_case() -> None:
    assert normalize(r"C:\Users\Kim\File.TXT", OsFamily.WINDOWS) == "/Users/Kim/File.TXT"


def test_same_path_case_rules() -> None:
    assert same_path(r"C:\Users\KIM\work\Proposal.md", "/Users/kim/work/proposal.md", OsFamily.WINDOWS)
    assert same_path("/Users/Lee/A.py", "/users/lee/a.py", OsFamily.MACOS)
    assert not same_path("/home/Park/a.py", "/home/park/a.py", OsFamily.LINUX)
    assert same_path("/home/park/./a.py", "/home/park/a.py", OsFamily.LINUX)


def test_basename() -> None:
    assert basename(r"C:\Users\kim\Downloads\DALL·E 2026-10-01 00.35.00 - a red logo.png") == (
        "DALL·E 2026-10-01 00.35.00 - a red logo.png"
    )
    assert basename("/home/park/app/") == "app"
    assert basename("file.txt") == "file.txt"
