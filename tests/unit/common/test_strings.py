from __future__ import annotations

from aitrace.plugins.common.strings import printable_runs


def test_printable_runs_keeps_only_runs_at_least_min_len() -> None:
    data = b"\x00\x01hello world ok\x02short\x00ABCDEFGH"
    assert printable_runs(data) == ["hello world ok", "ABCDEFGH"]


def test_printable_runs_honours_custom_min_len() -> None:
    assert printable_runs(b"abc\x00defgh", min_len=3) == ["abc", "defgh"]
