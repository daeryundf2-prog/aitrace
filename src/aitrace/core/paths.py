from __future__ import annotations

import posixpath
import re

from aitrace.core.kinds import OsFamily

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_CASE_INSENSITIVE = frozenset({OsFamily.WINDOWS, OsFamily.MACOS})


def normalize(path: str, os_family: OsFamily, home: str | None = None) -> str:
    """Volume POSIX path: no `\\\\?\\` prefix or drive letter, `/` separators, `~` expanded, always absolute.

    A leading `~` is only expanded when `home` is given. Case is preserved; use `same_path` to compare.
    """
    text = path.strip()
    if text.startswith(("\\\\?\\", "//?/")):
        text = text[4:]
    text = _DRIVE_RE.sub("", text, count=1)
    text = text.replace("\\", "/")
    if home is not None and (text == "~" or text.startswith("~/")):
        text = normalize(home, os_family) + "/" + text[1:]
    collapsed = posixpath.normpath("/" + text.lstrip("/"))
    return "/" + collapsed.lstrip("/")


def same_path(a: str, b: str, os_family: OsFamily) -> bool:
    left = normalize(a, os_family)
    right = normalize(b, os_family)
    if os_family in _CASE_INSENSITIVE:
        return left.casefold() == right.casefold()
    return left == right


def basename(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
