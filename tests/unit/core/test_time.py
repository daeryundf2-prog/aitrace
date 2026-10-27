from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aitrace.core.time import (
    fmt_local,
    fmt_utc,
    from_cocoa,
    from_filetime,
    from_iso,
    from_local_naive,
    from_unix,
    from_unix_ms,
    from_unix_us,
    from_webkit,
    to_local,
)

EPOCH_2023 = datetime(2023, 11, 14, 22, 13, 20, tzinfo=UTC)


@pytest.mark.parametrize(
    ("func", "value", "expected"),
    [
        (from_unix, 1700000000, EPOCH_2023),
        (from_unix, 1700000000.0, EPOCH_2023),
        (from_unix_ms, 1700000000000, EPOCH_2023),
        (from_unix_us, 1700000000000000, EPOCH_2023),
        (from_webkit, 13300000000000000, datetime(2022, 6, 18, 4, 26, 40, tzinfo=UTC)),
        (from_cocoa, 800000000, datetime(2026, 5, 9, 6, 13, 20, tzinfo=UTC)),
        (from_filetime, 132000000000000000, datetime(2019, 4, 17, 18, 40, 0, tzinfo=UTC)),
    ],
)
def test_epoch_conversions_produce_exact_utc(func, value, expected: datetime) -> None:
    result = func(value)
    assert result == expected
    assert result is not None
    assert result.utcoffset() is not None
    assert result.utcoffset().total_seconds() == 0


@pytest.mark.parametrize(
    ("func", "value"),
    [
        (from_unix, None),
        (from_unix, 0),
        (from_unix, float("nan")),
        (from_unix, float("inf")),
        (from_unix, 4200000000),
        (from_unix_ms, 0),
        (from_unix_us, None),
        (from_webkit, None),
        (from_webkit, 0),
        (from_cocoa, None),
        (from_cocoa, 10**20),
        (from_filetime, None),
        (from_filetime, 116444736000000000),
    ],
)
def test_out_of_range_or_missing_returns_none(func, value) -> None:
    assert func(value) is None


def test_from_iso_accepts_z_and_offsets_as_utc() -> None:
    assert from_iso("2024-03-01T12:00:00Z") == datetime(2024, 3, 1, 12, 0, tzinfo=UTC)
    assert from_iso("2024-03-01T21:00:00+09:00") == datetime(2024, 3, 1, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize("text", [None, "", "2024-03-01T12:00:00", "not a date", "2024-13-45T99:00:00Z"])
def test_from_iso_returns_none_for_naive_or_garbage(text: str | None) -> None:
    assert from_iso(text) is None


def test_from_local_naive_converts_wall_clock_to_utc() -> None:
    result = from_local_naive(datetime(2024, 3, 1, 21, 0), "Asia/Seoul")
    assert result == datetime(2024, 3, 1, 12, 0, tzinfo=UTC)


def test_from_local_naive_rejects_aware_input() -> None:
    with pytest.raises(ValueError):
        from_local_naive(datetime(2024, 3, 1, 21, 0, tzinfo=UTC), "Asia/Seoul")


def test_to_local_shifts_to_zone() -> None:
    result = to_local(datetime(2024, 3, 1, 12, 0, tzinfo=UTC), "Asia/Tokyo")
    assert result.replace(tzinfo=None) == datetime(2024, 3, 1, 21, 0)
    assert result.utcoffset().total_seconds() == 9 * 3600


def test_to_local_rejects_naive_input() -> None:
    with pytest.raises(ValueError):
        to_local(datetime(2024, 3, 1, 12, 0), "Asia/Tokyo")


def test_fmt_utc_renders_fixed_format() -> None:
    assert fmt_utc(datetime(2024, 3, 1, 12, 0, tzinfo=UTC)) == "2024-03-01 12:00:00 UTC"


def test_fmt_local_renders_positive_offset() -> None:
    dt = datetime(2024, 3, 1, 12, 0, tzinfo=UTC)
    assert fmt_local(dt, "Asia/Seoul") == "2024-03-01 21:00:00 (+09:00)"


def test_fmt_local_renders_negative_offset() -> None:
    dt = datetime(2024, 1, 15, 12, 0, tzinfo=UTC)
    assert fmt_local(dt, "America/New_York") == "2024-01-15 07:00:00 (-05:00)"
