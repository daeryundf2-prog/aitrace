from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64
_ENTRY_KEYS = frozenset({"seq", "ts_utc", "actor", "action", "detail", "prev_hash", "entry_hash"})


def _canonical(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _entry_hash(body: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(body)).hexdigest()


class CustodyLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def append(self, actor: str, action: str, detail: Mapping[str, Any]) -> dict[str, Any]:
        existing = self.entries()
        prev_hash = existing[-1]["entry_hash"] if existing else GENESIS_HASH
        body: dict[str, Any] = {
            "seq": len(existing) + 1,
            "ts_utc": datetime.now(UTC).isoformat(timespec="microseconds"),
            "actor": actor,
            "action": action,
            "detail": dict(detail),
            "prev_hash": prev_hash,
        }
        entry = {**body, "entry_hash": _entry_hash(body)}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
        return entry

    def verify_chain(self) -> bool:
        if not self.path.exists():
            return True
        prev_hash = GENESIS_HASH
        with self.path.open(encoding="utf-8") as fh:
            lines = [line for line in fh if line.strip()]
        for index, line in enumerate(lines, start=1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False
            if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
                return False
            body = {key: value for key, value in entry.items() if key != "entry_hash"}
            if entry["seq"] != index or entry["prev_hash"] != prev_hash:
                return False
            if entry["entry_hash"] != _entry_hash(body):
                return False
            prev_hash = entry["entry_hash"]
        return True
