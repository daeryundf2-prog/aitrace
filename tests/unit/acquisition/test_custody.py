from __future__ import annotations

import json
from pathlib import Path

from aitrace.acquisition.custody import GENESIS_HASH, CustodyLog


def _seed(path: Path) -> CustodyLog:
    log = CustodyLog(path)
    log.append("examiner", "intake", {"file": "x.E01"})
    log.append("examiner", "verify", {"result": "match"})
    log.append("system", "report", {"format": "json"})
    return log


def test_append_links_entries_into_a_valid_chain(tmp_path: Path) -> None:
    log = _seed(tmp_path / "custody.jsonl")
    entries = log.entries()
    assert [e["seq"] for e in entries] == [1, 2, 3]
    assert entries[0]["prev_hash"] == GENESIS_HASH
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    assert entries[2]["prev_hash"] == entries[1]["entry_hash"]
    assert set(entries[0]) == {"seq", "ts_utc", "actor", "action", "detail", "prev_hash", "entry_hash"}
    assert log.verify_chain() is True


def test_chain_survives_reopening_the_file(tmp_path: Path) -> None:
    path = tmp_path / "custody.jsonl"
    _seed(path)
    reopened = CustodyLog(path)
    reopened.append("examiner", "export", {"count": 2})
    assert [e["seq"] for e in reopened.entries()] == [1, 2, 3, 4]
    assert reopened.verify_chain() is True


def test_missing_log_verifies_as_empty_chain(tmp_path: Path) -> None:
    assert CustodyLog(tmp_path / "absent.jsonl").verify_chain() is True


def test_tampered_custody_line_fails_verification(tmp_path: Path) -> None:
    path = tmp_path / "custody.jsonl"
    log = _seed(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["action"] = "forged"
    lines[1] = json.dumps(tampered, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert log.verify_chain() is False


def test_deleted_custody_line_fails_verification(tmp_path: Path) -> None:
    path = tmp_path / "custody.jsonl"
    log = _seed(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    assert log.verify_chain() is False


def test_non_json_line_fails_verification(tmp_path: Path) -> None:
    path = tmp_path / "custody.jsonl"
    log = _seed(path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write("not json\n")
    assert log.verify_chain() is False
