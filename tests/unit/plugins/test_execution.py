from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aitrace.core.kinds import ArtifactKind, EventCategory, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.windows.execution import PLUGIN, srum_app_rows, srum_network_rows

SAMPLES = (
    Path(__file__).resolve().parents[2] / "fixtures/files/third_party/dissect/plugins/os/windows"
)
PREFETCH = SAMPLES / "prefetch/MPCMDRUN.EXE-962E6200.pf"
AMCACHE = SAMPLES / "amcache/amcache-new.hve"
SRUDB = SAMPLES / "sru/SRUDB.dat"
PREFETCH_PATH = "/Windows/Prefetch/MPCMDRUN.EXE-962E6200.pf"
AMCACHE_PATH = "/Windows/AppCompat/Programs/Amcache.hve"
SRUM_PATH = "/Windows/System32/sru/SRUDB.dat"
LOG = logging.getLogger("tests.execution")
OLE_UNIX_DAYS = 25569.0


def _run(files: dict[str, bytes]) -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=OsFamily.WINDOWS)
    ctx = ParseContext(fs=fs, evidence_id=fs.evidence_id, tz="Asia/Seoul", log=LOG)
    records: list[Artifact | Event] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _artifacts(records: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [r for r in records if isinstance(r, Artifact) and r.kind == kind]


def _events(records: list[Artifact | Event]) -> list[Event]:
    return [r for r in records if isinstance(r, Event)]


def _ole_days(ts: datetime) -> float:
    return ts.timestamp() / 86400 + OLE_UNIX_DAYS


def test_prefetch_sample_yields_mpcmdrun_with_run_times() -> None:
    records = _run({PREFETCH_PATH: PREFETCH.read_bytes()})

    executions = _artifacts(records, ArtifactKind.EXECUTION)
    assert len(executions) == 1
    data = executions[0].data
    assert data["program"] == "MPCMDRUN.EXE"
    assert data["source"] == "prefetch"
    assert data["extra"]["referenced_files"]
    runs = [e for e in _events(records) if e.category == EventCategory.EXECUTION]
    assert len(runs) >= 1
    assert all(e.ts_utc is not None for e in runs)
    assert not _artifacts(records, ArtifactKind.PARSE_WARNING)


def test_corrupt_prefetch_yields_warning_not_exception() -> None:
    corrupt = PREFETCH.read_bytes()[:12] + b"\xff" * 64

    records = _run({PREFETCH_PATH: corrupt})

    assert not _artifacts(records, ArtifactKind.EXECUTION)
    assert len(_artifacts(records, ArtifactKind.PARSE_WARNING)) == 1


def test_garbage_prefetch_yields_warning() -> None:
    records = _run({PREFETCH_PATH: b"not a prefetch file at all"})

    assert len(_artifacts(records, ArtifactKind.PARSE_WARNING)) == 1


def test_amcache_sample_yields_executions_with_key_write_events() -> None:
    records = _run({AMCACHE_PATH: AMCACHE.read_bytes()})

    executions = _artifacts(records, ArtifactKind.EXECUTION)
    assert len(executions) > 100
    viewer = next(a for a in executions if a.data["program"] == "3DViewer.exe")
    assert viewer.data["source"] == "amcache"
    assert viewer.data["path"].endswith("/3dviewer.exe")
    assert viewer.data["path"].startswith("/program files/windowsapps/")
    assert viewer.data["extra"]["file_id"] == "00008e01cdeb9a1c23cee421a647f29c45f67623be97"
    assert viewer.data["extra"]["link_date"] == "05/04/2021 17:43:39"
    events = [e for e in _events(records) if e.artifact_id == viewer.id]
    assert len(events) == 1
    assert events[0].ts_utc == datetime(2021, 7, 18, 16, 22, 41, 762238, tzinfo=UTC)


def test_corrupt_amcache_yields_warning() -> None:
    records = _run({AMCACHE_PATH: b"regf" + b"\x00" * 100})

    assert not _artifacts(records, ArtifactKind.EXECUTION)
    assert len(_artifacts(records, ArtifactKind.PARSE_WARNING)) == 1


def test_srudb_sample_yields_app_usage_and_no_network_rows(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger=LOG.name):
        records = _run({SRUM_PATH: SRUDB.read_bytes()})

    executions = _artifacts(records, ArtifactKind.EXECUTION)
    assert len(executions) > 0
    assert all(a.data["source"] == "srum" for a in executions)
    assert all(e.ts_utc is not None for e in _events(records))
    assert not _artifacts(records, ArtifactKind.NETWORK_USAGE)
    assert not _artifacts(records, ArtifactKind.PARSE_WARNING)
    absent = [r for r in caplog.records if r.levelno == logging.DEBUG and "absent" in r.getMessage()]
    assert absent
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_corrupt_srudb_yields_warning() -> None:
    records = _run({SRUM_PATH: b"\x00" * 4096})

    assert len(_artifacts(records, ArtifactKind.PARSE_WARNING)) == 1


def test_srum_network_rows_maps_bytes_program_and_time() -> None:
    stamp = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
    id_map = {
        7: "\\device\\harddiskvolume3\\users\\kim\\appdata\\local\\programs\\ollama\\ollama.exe",
        8: "Microsoft.WindowsStore_8wekyb3d8bbwe",
    }
    rows = [
        {"AutoIncId": 1, "AppId": 7, "TimeStamp": _ole_days(stamp), "BytesSent": 1500, "BytesRecvd": 9000},
        {"AutoIncId": 2, "AppId": 8, "TimeStamp": _ole_days(stamp), "BytesSent": 0, "BytesRecvd": 42},
        {"AutoIncId": 3, "AppId": 99, "TimeStamp": _ole_days(stamp), "BytesSent": 1, "BytesRecvd": 1},
    ]

    out = srum_network_rows(rows, id_map)

    assert [r["program"] for r in out] == ["ollama.exe", "Microsoft.WindowsStore_8wekyb3d8bbwe"]
    assert out[0]["path"] == "/users/kim/appdata/local/programs/ollama/ollama.exe"
    assert out[0]["bytes_sent"] == 1500
    assert out[0]["bytes_received"] == 9000
    assert out[0]["ts"] == stamp
    assert out[1]["path"] is None
    assert out[1]["bytes_received"] == 42


def test_srum_app_rows_accepts_ese_int_bit_pattern_timestamp() -> None:
    import struct

    stamp = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
    (bits,) = struct.unpack("<Q", struct.pack("<d", _ole_days(stamp)))

    out = srum_app_rows([{"AutoIncId": 5, "AppId": 1, "TimeStamp": bits}], {1: "\\device\\harddiskvolume2\\windows\\system32\\cmd.exe"})

    assert out == [
        {
            "program": "cmd.exe",
            "path": "/windows/system32/cmd.exe",
            "raw_app": "\\device\\harddiskvolume2\\windows\\system32\\cmd.exe",
            "ts": stamp,
            "row_id": 5,
        }
    ]


def test_srum_rows_with_missing_timestamp_keep_none() -> None:
    out = srum_app_rows([{"AppId": 1, "TimeStamp": None}], {1: "a.exe"})

    assert out[0]["ts"] is None


def test_ai_program_sets_ai_tool_on_prefetch_like_data() -> None:
    from aitrace.plugins.windows.execution import _with_ai_tool

    assert _with_ai_tool({}, "OLLAMA.EXE") == {"ai_tool": "Ollama"}
    assert _with_ai_tool({}, "notepad.exe") == {}
