from __future__ import annotations

import plistlib
from plistlib import UID
from typing import Any

_NIL = "$null"


def load_plist(data: bytes) -> Any:
    return plistlib.loads(data)


def unarchive(archive: Any) -> Any:
    if not isinstance(archive, dict) or archive.get("$archiver") != "NSKeyedArchiver":
        raise ValueError("not an NSKeyedArchiver archive")
    objects = archive.get("$objects")
    top = archive.get("$top")
    if not isinstance(objects, list) or not isinstance(top, dict) or "root" not in top:
        raise ValueError("NSKeyedArchiver archive lacks $objects or $top.root")
    return _resolve(objects, top["root"], frozenset())


def _resolve(objects: list[Any], value: Any, active: frozenset[int]) -> Any:
    if isinstance(value, UID):
        index = value.data
        if not 0 <= index < len(objects):
            raise ValueError(f"UID {index} is outside $objects")
        if index in active:
            raise ValueError(f"cyclic reference to $objects[{index}]")
        return _resolve(objects, objects[index], active | {index})
    if isinstance(value, str):
        return None if value == _NIL else value
    if isinstance(value, list):
        return [_resolve(objects, item, active) for item in value]
    if isinstance(value, dict):
        if "NS.keys" in value and "NS.objects" in value:
            keys = _resolve(objects, value["NS.keys"], active)
            values = _resolve(objects, value["NS.objects"], active)
            return dict(zip(keys, values, strict=True))
        if "NS.objects" in value:
            return _resolve(objects, value["NS.objects"], active)
        return {key: _resolve(objects, item, active) for key, item in value.items() if key != "$class"}
    return value
