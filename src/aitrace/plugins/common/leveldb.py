from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass

import cramjam

from aitrace.fs.base import EntryRef, EvidenceFS

LOG_BLOCK_SIZE = 32 * 1024
LOG_HEADER_SIZE = 7
_LOG_FULL = 1
_LOG_FIRST = 2
_LOG_MIDDLE = 3
_LOG_LAST = 4
_LOG_TYPES = frozenset({_LOG_FULL, _LOG_FIRST, _LOG_MIDDLE, _LOG_LAST})
_TAG_DELETION = 0
_TAG_VALUE = 1
_SSTABLE_MAGIC = 0xDB4775248B80FB57
_FOOTER_SIZE = 48
_BLOCK_TRAILER_SIZE = 5
_COMPRESSION_NONE = 0
_COMPRESSION_SNAPPY = 1
_MIN_TEXT_RUN = 8
_TEXT_WHITESPACE = "\n\t\r"
_REPLACEMENT_CHAR = "\ufffd"

Record = tuple[str, bytes, bytes, int]


@dataclass
class LevelDBStats:
    corrupt_blocks: int = 0


class _Corrupt(Exception):
    pass


def _build_crc_table() -> tuple[int, ...]:
    table: list[int] = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC_TABLE = _build_crc_table()


def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _masked_crc(data: bytes) -> int:
    crc = _crc32c(data)
    rotated = ((crc >> 15) | (crc << 17)) & 0xFFFFFFFF
    return (rotated + 0xA282EAD8) & 0xFFFFFFFF


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 64, 7):
        if pos >= len(buf):
            raise _Corrupt("truncated varint")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
    raise _Corrupt("varint too long")


def _take(buf: bytes, pos: int, length: int) -> bytes:
    if pos + length > len(buf):
        raise _Corrupt("truncated field")
    return buf[pos : pos + length]


def _log_payloads(data: bytes, stats: LevelDBStats) -> Iterator[bytes]:
    fragments: list[bytes] | None = None
    for block_start in range(0, len(data), LOG_BLOCK_SIZE):
        block = data[block_start : block_start + LOG_BLOCK_SIZE]
        pos = 0
        while len(block) - pos >= LOG_HEADER_SIZE:
            stored_crc, length, rtype = struct.unpack_from("<IHB", block, pos)
            if rtype == 0 and length == 0:
                break
            start = pos + LOG_HEADER_SIZE
            payload = block[start : start + length]
            if (
                rtype not in _LOG_TYPES
                or start + length > len(block)
                or stored_crc != _masked_crc(bytes((rtype,)) + payload)
            ):
                stats.corrupt_blocks += 1
                fragments = None
                break
            pos = start + length
            if rtype in (_LOG_FULL, _LOG_FIRST) and fragments is not None:
                stats.corrupt_blocks += 1
                fragments = None
            if rtype == _LOG_FULL:
                yield payload
            elif rtype == _LOG_FIRST:
                fragments = [payload]
            elif fragments is None:
                stats.corrupt_blocks += 1
            else:
                fragments.append(payload)
                if rtype == _LOG_LAST:
                    yield b"".join(fragments)
                    fragments = None


def _parse_batch(payload: bytes) -> list[tuple[bytes, bytes, int]]:
    if len(payload) < 12:
        raise _Corrupt("short batch header")
    seq, count = struct.unpack_from("<QI", payload, 0)
    pos = 12
    entries: list[tuple[bytes, bytes, int]] = []
    for index in range(count):
        if pos >= len(payload):
            raise _Corrupt("batch ends before its declared entry count")
        tag = payload[pos]
        pos += 1
        key_len, pos = _read_varint(payload, pos)
        key = _take(payload, pos, key_len)
        pos += key_len
        if tag == _TAG_VALUE:
            value_len, pos = _read_varint(payload, pos)
            value = _take(payload, pos, value_len)
            pos += value_len
            entries.append((key, value, seq + index))
        elif tag != _TAG_DELETION:
            raise _Corrupt("unknown batch entry tag")
    return entries


def _iter_log_file(name: str, data: bytes, stats: LevelDBStats) -> Iterator[Record]:
    for payload in _log_payloads(data, stats):
        try:
            entries = _parse_batch(payload)
        except _Corrupt:
            stats.corrupt_blocks += 1
            continue
        for key, value, seq in entries:
            yield (name, key, value, seq)


def _read_handle(buf: bytes, pos: int) -> tuple[int, int, int]:
    offset, pos = _read_varint(buf, pos)
    size, pos = _read_varint(buf, pos)
    return offset, size, pos


def _read_block(data: bytes, offset: int, size: int) -> bytes:
    end = offset + size
    if end + _BLOCK_TRAILER_SIZE > len(data):
        raise _Corrupt("block extends past end of file")
    body = data[offset:end]
    compression = data[end]
    (stored_crc,) = struct.unpack_from("<I", data, end + 1)
    if stored_crc != _masked_crc(body + bytes((compression,))):
        raise _Corrupt("bad block checksum")
    if compression == _COMPRESSION_NONE:
        return body
    if compression == _COMPRESSION_SNAPPY:
        try:
            return bytes(cramjam.snappy.decompress_raw(body))
        except cramjam.DecompressionError as exc:
            raise _Corrupt("snappy decompression failed") from exc
    raise _Corrupt("unknown block compression")


def _block_entries(block: bytes) -> list[tuple[bytes, bytes]]:
    if len(block) < 4:
        raise _Corrupt("block too short")
    (restart_count,) = struct.unpack_from("<I", block, len(block) - 4)
    limit = len(block) - 4 - 4 * restart_count
    if limit < 0:
        raise _Corrupt("restart array exceeds block")
    entries: list[tuple[bytes, bytes]] = []
    pos = 0
    key = b""
    while pos < limit:
        shared, pos = _read_varint(block, pos)
        non_shared, pos = _read_varint(block, pos)
        value_len, pos = _read_varint(block, pos)
        if shared > len(key):
            raise _Corrupt("shared prefix longer than previous key")
        key = key[:shared] + _take(block, pos, non_shared)
        pos += non_shared
        value = _take(block, pos, value_len)
        pos += value_len
        if pos > limit:
            raise _Corrupt("entry overruns block")
        entries.append((key, value))
    return entries


def _sstable_values(entries: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes, int]]:
    values: list[tuple[bytes, bytes, int]] = []
    for internal_key, value in entries:
        if len(internal_key) < 8:
            raise _Corrupt("internal key shorter than its trailer")
        trailer = int.from_bytes(internal_key[-8:], "little")
        if trailer & 0xFF == _TAG_VALUE:
            values.append((internal_key[:-8], value, trailer >> 8))
    return values


def _iter_sstable_file(name: str, data: bytes, stats: LevelDBStats) -> Iterator[Record]:
    if len(data) < _FOOTER_SIZE or struct.unpack_from("<Q", data, len(data) - 8)[0] != _SSTABLE_MAGIC:
        stats.corrupt_blocks += 1
        return
    footer = data[len(data) - _FOOTER_SIZE :]
    try:
        _, _, pos = _read_handle(footer, 0)
        index_offset, index_size, _ = _read_handle(footer, pos)
        index_entries = _block_entries(_read_block(data, index_offset, index_size))
        handles = [_read_handle(handle, 0)[:2] for _, handle in index_entries]
    except _Corrupt:
        stats.corrupt_blocks += 1
        return
    for offset, size in handles:
        try:
            values = _sstable_values(_block_entries(_read_block(data, offset, size)))
        except _Corrupt:
            stats.corrupt_blocks += 1
            continue
        for key, value, seq in values:
            yield (name, key, value, seq)


def iter_leveldb_records(
    fs: EvidenceFS, dir_ref: EntryRef, stats: LevelDBStats | None = None
) -> Iterator[Record]:
    counters = LevelDBStats() if stats is None else stats
    if not fs.is_dir(dir_ref):
        return
    for child in fs.listdir(dir_ref):
        if fs.is_dir(child):
            continue
        name = child.path.rsplit("/", 1)[-1]
        lowered = name.lower()
        if lowered.endswith(".log"):
            parse = _iter_log_file
        elif lowered.endswith(".ldb"):
            parse = _iter_sstable_file
        else:
            continue
        yield from parse(name, fs.read_bytes(child), counters)


def _text_runs(text: str) -> list[str]:
    runs: list[str] = []
    current: list[str] = []
    for char in text:
        if (char.isprintable() and char != _REPLACEMENT_CHAR) or char in _TEXT_WHITESPACE:
            current.append(char)
            continue
        candidate = "".join(current).strip()
        if len(candidate) >= _MIN_TEXT_RUN:
            runs.append(candidate)
        current = []
    candidate = "".join(current).strip()
    if len(candidate) >= _MIN_TEXT_RUN:
        runs.append(candidate)
    return runs


def extract_text(value: bytes) -> list[str]:
    runs = _text_runs(value.decode("utf-8", errors="replace"))
    even_length = value[: len(value) - len(value) % 2]
    runs.extend(_text_runs(even_length.decode("utf-16-le", errors="replace")))
    return runs
