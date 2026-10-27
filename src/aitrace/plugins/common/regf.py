from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, BinaryIO

from dissect.regf import RegistryHive
from dissect.regf.regf import KeyNode


def open_hive(fileobj: BinaryIO) -> RegistryHive:
    return RegistryHive(fileobj)


def _resolve_key(hive: RegistryHive, key_path: str) -> KeyNode:
    key = hive.root()
    for part in key_path.split("\\"):
        if part:
            key = key.subkey(part)
    return key


def iter_values(hive: RegistryHive, key_path: str) -> Iterator[tuple[str, Any]]:
    for value in _resolve_key(hive, key_path).values():
        yield value.name, value.value


def key_last_write(key: KeyNode) -> datetime:
    return key.timestamp.astimezone(UTC)
