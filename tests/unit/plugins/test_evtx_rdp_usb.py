from __future__ import annotations

import logging
from pathlib import Path

from aitrace.core.kinds import ArtifactKind, OsFamily
from aitrace.core.model import Artifact
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.windows.evtx_rdp_usb import PLUGIN, iter_evtx

SECURITY_EVTX = (
    Path(__file__).resolve().parents[2]
    / "fixtures/files/third_party/dissect/plugins/os/windows/log/evtx/Security.evtx"
)
SECURITY_PATH = "/Windows/System32/winevt/Logs/Security.evtx"
SETUPAPI_PATH = "/Windows/INF/setupapi.dev.log"
SETUPAPI_TEXT = """\
>>>  Section start 2025/03/04 11:26:37.040
>>>  [Device Install (UpdateDriverForPlugAndPlayDevices) - USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\\4C530001011234567890&0]
<<<  Section end 2025/03/04 11:26:38.000
<<<  [Exit status: SUCCESS]
"""


def _run(fs: MemoryFS) -> list[object]:
    ctx = ParseContext(fs=fs, evidence_id=fs.evidence_id, tz="Asia/Seoul", log=logging.getLogger("test"))
    records: list[object] = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def test_security_evtx_sample_yields_records() -> None:
    with SECURITY_EVTX.open("rb") as fh:
        rows = list(iter_evtx(fh))

    assert len(rows) > 0


def test_setupapi_usbstor_block_yields_one_usb_device() -> None:
    fs = MemoryFS({SETUPAPI_PATH: SETUPAPI_TEXT.encode()}, volume_os=OsFamily.WINDOWS)

    records = _run(fs)
    usb = [r for r in records if isinstance(r, Artifact) and r.kind == ArtifactKind.USB_DEVICE]

    assert len(usb) == 1
    assert usb[0].data["vendor"] == "SANDISK"
    assert usb[0].data["product"] == "ULTRA"
    assert usb[0].data["serial"] == "4C530001011234567890&0"


def test_truncated_evtx_yields_parse_warning() -> None:
    data = SECURITY_EVTX.read_bytes()
    fs = MemoryFS({SECURITY_PATH: data[: len(data) // 4]}, volume_os=OsFamily.WINDOWS)

    records = _run(fs)
    warnings = [r for r in records if isinstance(r, Artifact) and r.kind == ArtifactKind.PARSE_WARNING]

    assert len(warnings) == 1
