from __future__ import annotations

import io
import logging
import struct
import zlib

from PIL import Image
from PIL.PngImagePlugin import PngInfo

from aitrace.core.kinds import ArtifactKind, OsFamily
from aitrace.core.model import Artifact
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.base import ParseContext
from aitrace.plugins.provenance.images import PLUGIN

LEE_PICTURES = "/Users/lee/Pictures"


def _png(text: dict[str, str] | None = None) -> bytes:
    info = PngInfo()
    for key, value in (text or {}).items():
        info.add_text(key, value)
    buf = io.BytesIO()
    Image.new("RGB", (4, 4), "white").save(buf, "PNG", pnginfo=info)
    return buf.getvalue()


def _chunk(ctype: bytes, body: bytes) -> bytes:
    crc = zlib.crc32(ctype + body) & 0xFFFFFFFF
    return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", crc)


def _insert_before_iend(png: bytes, chunk: bytes) -> bytes:
    cut = png.rfind(b"IEND") - 4
    return png[:cut] + chunk + png[cut:]


def _jpeg_with_app1(payload: bytes) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (4, 4), "white").save(buf, "JPEG")
    jpeg = buf.getvalue()
    segment = b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload
    return jpeg[:2] + segment + jpeg[2:]


def _run(fs: MemoryFS) -> list[Artifact]:
    ctx = ParseContext(fs=fs, evidence_id=fs.evidence_id, tz="Asia/Seoul", log=logging.getLogger("test"))
    records = []
    for cand in PLUGIN.locate(fs):
        records.extend(PLUGIN.parse(ctx, cand))
    return records


def _signals(artifact: Artifact) -> list[tuple[str, str]]:
    return [(s["type"], s["value"]) for s in artifact.data["signals"]]


def test_png_parameters_chunk_yields_sd_parameters_signal() -> None:
    fs = MemoryFS(
        {f"{LEE_PICTURES}/render.png": _png({"parameters": "a castle, steps: 20, Sampler: Euler"})},
        volume_os=OsFamily.MACOS,
    )

    records = _run(fs)

    assert [r.kind for r in records] == [ArtifactKind.MEDIA_PROVENANCE]
    assert _signals(records[0]) == [("sd_parameters", "png:parameters")]
    assert records[0].user == "lee"
    assert records[0].data["path"] == f"{LEE_PICTURES}/render.png"


def test_non_image_bytes_named_png_yield_no_record() -> None:
    fs = MemoryFS({"/Users/lee/Desktop/fake.png": b"plain text, not an image"}, volume_os=OsFamily.MACOS)

    assert _run(fs) == []


def test_corrupt_png_with_valid_signature_yields_parse_warning() -> None:
    truncated = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 100) + b"IHDR" + b"short"
    fs = MemoryFS({"/Users/lee/Desktop/broken.png": truncated}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    assert [r.kind for r in records] == [ArtifactKind.PARSE_WARNING]
    assert "unreadable" in records[0].data["message"]


def test_c2pa_caby_chunk_yields_c2pa_and_digital_source_signals() -> None:
    manifest = (
        b"claim_generator\x61\x0bAcme Gen 1.0\x00"
        b"digitalSourceType\x00http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
    )
    png = _insert_before_iend(_png(), _chunk(b"caBX", manifest))
    fs = MemoryFS({f"{LEE_PICTURES}/signed.png": png}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    assert _signals(records[0]) == [
        ("c2pa", "Acme Gen 1.0"),
        (
            "iptc_digital_source",
            "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
        ),
    ]


def test_jpeg_xmp_packet_yields_iptc_source_and_ai_creator_tool() -> None:
    xmp = (
        b"http://ns.adobe.com/xap/1.0/\x00"
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:Description '
        b'Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia" '
        b'xmp:CreatorTool="Midjourney"/></x:xmpmeta>'
    )
    fs = MemoryFS({f"{LEE_PICTURES}/art.jpg": _jpeg_with_app1(xmp)}, volume_os=OsFamily.MACOS)

    records = _run(fs)

    assert _signals(records[0]) == [
        (
            "iptc_digital_source",
            "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
        ),
        ("metadata_hint", "Midjourney"),
    ]


def test_ai_style_file_name_yields_filename_pattern_signal() -> None:
    fs = MemoryFS(
        {f"{LEE_PICTURES}/ChatGPT Image 2026-10-01 09.png": _png()},
        volume_os=OsFamily.MACOS,
    )

    records = _run(fs)

    assert _signals(records[0]) == [("ai_filename_pattern", "ChatGPT")]


def test_plain_photo_without_signals_yields_no_record() -> None:
    fs = MemoryFS({f"{LEE_PICTURES}/vacation.png": _png()}, volume_os=OsFamily.MACOS)

    assert _run(fs) == []


def test_locate_skips_caches_and_files_deeper_than_six_levels() -> None:
    fs = MemoryFS(
        {
            "/Users/lee/Library/Caches/thumb.png": _png(),
            "/Users/lee/a/b/c/d/e/f.png": _png(),
            "/Users/lee/a/b/c/d/e/f/g.png": _png(),
        },
        volume_os=OsFamily.MACOS,
    )

    located = sorted(cand.ref.path for cand in PLUGIN.locate(fs))

    assert located == ["/Users/lee/a/b/c/d/e/f.png"]
