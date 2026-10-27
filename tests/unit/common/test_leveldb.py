from __future__ import annotations

import struct

from aitrace.core.kinds import OsFamily
from aitrace.fs.base import EntryRef
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.common.leveldb import LevelDBStats, _masked_crc, extract_text, iter_leveldb_records

PLANTED = "planted session text for recovery"
DB_DIR = EntryRef(0, "/db")
SSTABLE_MAGIC = 0xDB4775248B80FB57


def _varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _log_record(payload: bytes, rtype: int = 1) -> bytes:
    crc = _masked_crc(bytes((rtype,)) + payload)
    return struct.pack("<IHB", crc, len(payload), rtype) + payload


def _batch(seq: int, entries: list[tuple[bytes, bytes]]) -> bytes:
    body = struct.pack("<QI", seq, len(entries))
    for key, value in entries:
        body += b"\x01" + _varint(len(key)) + key + _varint(len(value)) + value
    return body


def _block(entries: list[tuple[bytes, bytes]]) -> bytes:
    body = b"".join(
        _varint(0) + _varint(len(key)) + _varint(len(value)) + key + value for key, value in entries
    )
    return body + struct.pack("<II", 0, 1)


def _with_trailer(block: bytes) -> bytes:
    return block + b"\x00" + struct.pack("<I", _masked_crc(block + b"\x00"))


def _handle(offset: int, size: int) -> bytes:
    return _varint(offset) + _varint(size)


def _sstable(entries: list[tuple[bytes, bytes, int]]) -> bytes:
    data_block = _block(
        [(key + ((seq << 8) | 1).to_bytes(8, "little"), value) for key, value, seq in entries]
    )
    data = _with_trailer(data_block)
    index_block = _block([(b"z", _handle(0, len(data_block)))])
    index_offset = len(data)
    data += _with_trailer(index_block)
    footer = (_handle(0, 0) + _handle(index_offset, len(index_block))).ljust(40, b"\x00")
    return data + footer + struct.pack("<Q", SSTABLE_MAGIC)


def _fs(name: str, data: bytes) -> MemoryFS:
    return MemoryFS({f"/db/{name}": data}, volume_os=OsFamily.LINUX)


def test_log_recovers_planted_value_with_sequence() -> None:
    value = PLANTED.encode()
    fs = _fs("000003.log", _log_record(_batch(7, [(b"k1", value)])))

    records = list(iter_leveldb_records(fs, DB_DIR))

    assert records == [("000003.log", b"k1", value, 7)]
    assert PLANTED in extract_text(records[0][2])


def test_ldb_recovers_planted_value_from_uncompressed_block() -> None:
    value = PLANTED.encode()
    fs = _fs("000005.ldb", _sstable([(b"k2", value, 9)]))

    records = list(iter_leveldb_records(fs, DB_DIR))

    assert records == [("000005.ldb", b"k2", value, 9)]


def test_truncated_ldb_yields_no_records_and_no_exception() -> None:
    full = _sstable([(b"k2", PLANTED.encode(), 9)])
    fs = _fs("000005.ldb", full[: len(full) // 2])
    stats = LevelDBStats()

    records = list(iter_leveldb_records(fs, DB_DIR, stats))

    assert records == []
    assert stats.corrupt_blocks == 1


def test_extract_text_recovers_utf16le_runs() -> None:
    assert extract_text(PLANTED.encode("utf-16-le")) == [PLANTED]
