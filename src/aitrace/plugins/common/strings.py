from __future__ import annotations

import re

_PRINTABLE_ASCII = re.compile(rb"[\x20-\x7e\t]+")


def printable_runs(data: bytes, min_len: int = 8) -> list[str]:
    return [
        match.group().decode("ascii")
        for match in _PRINTABLE_ASCII.finditer(data)
        if len(match.group()) >= min_len
    ]
