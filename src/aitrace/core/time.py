from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=UTC)
_MIN_VALID = datetime(1980, 1, 1, tzinfo=UTC)
_MAX_VALID = datetime(2100, 1, 1, tzinfo=UTC)


def _in_range(dt: datetime) -> datetime | None:
    return dt if _MIN_VALID <= dt <= _MAX_VALID else None


def _shift(base: datetime, **delta: float) -> datetime | None:
    try:
        dt = base + timedelta(**delta)
    except (OverflowError, ValueError):
        return None
    return _in_range(dt)


def from_unix(unix_seconds: float | None) -> datetime | None:
    if unix_seconds is None:
        return None
    return _shift(_UNIX_EPOCH, seconds=unix_seconds)


def from_unix_ms(unix_milliseconds: float | None) -> datetime | None:
    if unix_milliseconds is None:
        return None
    return _shift(_UNIX_EPOCH, milliseconds=unix_milliseconds)


def from_unix_us(unix_microseconds: int | None) -> datetime | None:
    if unix_microseconds is None:
        return None
    return _shift(_UNIX_EPOCH, microseconds=unix_microseconds)


def from_webkit(webkit_microseconds: int | None) -> datetime | None:
    if webkit_microseconds is None:
        return None
    return _shift(_WEBKIT_EPOCH, microseconds=webkit_microseconds)


def from_cocoa(cocoa_seconds: float | None) -> datetime | None:
    if cocoa_seconds is None:
        return None
    return _shift(_COCOA_EPOCH, seconds=cocoa_seconds)


def from_filetime(filetime_100ns: int | None) -> datetime | None:
    if filetime_100ns is None:
        return None
    return _shift(_WEBKIT_EPOCH, microseconds=filetime_100ns // 10)


def from_iso(text: str | None) -> datetime | None:
    if text is None:
        return None
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return _in_range(dt.astimezone(UTC))


def from_local_naive(naive: datetime, tz: str) -> datetime | None:
    if naive.tzinfo is not None:
        raise ValueError("from_local_naive expects a naive datetime")
    try:
        utc = naive.replace(tzinfo=ZoneInfo(tz)).astimezone(UTC)
    except OverflowError:
        return None
    return _in_range(utc)


def to_local(dt: datetime, tz: str) -> datetime:
    if dt.tzinfo is None:
        raise ValueError("to_local expects a timezone-aware datetime")
    return dt.astimezone(ZoneInfo(tz))


def fmt_utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_local(dt: datetime, tz: str) -> str:
    local = to_local(dt, tz)
    offset = local.utcoffset() or timedelta(0)
    minutes = int(offset.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    hours, mins = divmod(abs(minutes), 60)
    return f"{local:%Y-%m-%d %H:%M:%S} ({sign}{hours:02d}:{mins:02d})"
