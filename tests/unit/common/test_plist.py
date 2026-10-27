from __future__ import annotations

import plistlib
from plistlib import UID

import pytest

from aitrace.plugins.common.plist import load_plist, unarchive


def _nskeyed_archive() -> dict[str, object]:
    objects: list[object] = [
        "$null",
        {
            "$class": UID(8),
            "NS.keys": [UID(2), UID(3), UID(4)],
            "NS.objects": [UID(5), UID(0), UID(6)],
        },
        "title",
        "note",
        "tools",
        "dump",
        {"$class": UID(7), "NS.objects": [UID(9), UID(10)]},
        {"$classname": "NSArray", "$classes": ["NSArray", "NSObject"]},
        {"$classname": "NSDictionary", "$classes": ["NSDictionary", "NSObject"]},
        "Claude Code",
        "Ollama",
    ]
    return {
        "$archiver": "NSKeyedArchiver",
        "$version": 100000,
        "$top": {"root": UID(1)},
        "$objects": objects,
    }


def test_load_plist_reads_binary_plist() -> None:
    payload = {"name": "chat", "count": 2, "tags": ["a", "b"]}
    data = plistlib.dumps(payload, fmt=plistlib.FMT_BINARY)

    assert data.startswith(b"bplist00")
    assert load_plist(data) == payload


def test_unarchive_resolves_nskeyedarchiver_references() -> None:
    data = plistlib.dumps(_nskeyed_archive(), fmt=plistlib.FMT_BINARY)

    assert unarchive(load_plist(data)) == {"title": "dump", "note": None, "tools": ["Claude Code", "Ollama"]}


def test_load_plist_rejects_non_plist_bytes() -> None:
    with pytest.raises(plistlib.InvalidFileException):
        load_plist(b"not a plist at all")


def test_unarchive_rejects_input_that_is_not_an_archive() -> None:
    with pytest.raises(ValueError, match="NSKeyedArchiver"):
        unarchive({"plain": "dict"})
