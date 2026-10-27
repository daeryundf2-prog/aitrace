from __future__ import annotations

from datetime import UTC
from pathlib import Path

from aitrace.plugins.common.regf import iter_values, key_last_write, open_hive

HIVE = (
    Path(__file__).resolve().parents[3]
    / "tests/fixtures/files/third_party/dissect/plugins/os/windows/amcache/amcache-new.hve"
)


def test_key_last_write_is_utc() -> None:
    with HIVE.open("rb") as fh:
        key = open_hive(fh).root().subkey("Root")

        assert key_last_write(key).tzinfo == UTC
        assert key_last_write(key) == key.timestamp


def test_iter_values_reads_named_key_values() -> None:
    with HIVE.open("rb") as fh:
        hive = open_hive(fh)
        named = next(sub for sub in hive.root().subkey("Root").subkeys() if any(True for _ in sub.values()))

        values = list(iter_values(hive, f"Root\\{named.name}"))

        assert values
        assert all(isinstance(name, str) for name, _ in values)
