"""Image provenance: AI-generation signals in PNG, JPEG, WebP and HEIC files.

Signals come from PNG text chunks (A1111 `parameters`, ComfyUI `prompt`/`workflow`, NovelAI `Comment`,
`Software`), C2PA manifests (PNG `caBX`, JPEG APP11 JUMBF), XMP packets (IPTC DigitalSourceType,
xmp:CreatorTool), EXIF Software and AI-style file names. C2PA signatures are not validated; claim and
source-type strings are extracted by byte regex, so the values are best-effort.
"""

from __future__ import annotations

import io
import posixpath
import re
import struct
import zlib
from collections.abc import Iterator

from PIL import Image

from aitrace.core.catalog import AI_FILENAME_PATTERNS
from aitrace.core.kinds import ArtifactKind, OsFamily, SignalType
from aitrace.core.model import Artifact
from aitrace.core.paths import basename, normalize
from aitrace.fs.base import EntryRef, EvidenceFS
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

MAX_BYTES = 50 * 1024 * 1024
MAX_DEPTH = 6
IMAGE_EXTS = frozenset({"png", "jpg", "jpeg", "webp", "heic"})
SKIP_DIRS = frozenset({"Caches", "Cache", "caches", ".cache"})

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_HEIC_BRANDS = frozenset({b"heic", b"heix", b"heim", b"heis", b"mif1", b"msf1", b"hevc"})
_SD_TEXT_KEYS = frozenset({"parameters", "prompt", "workflow"})
_EXIF_SOFTWARE = 0x0131
_AI_SOFTWARE = re.compile(
    r"stable diffusion|automatic1111|comfyui|invokeai|novelai|midjourney|dall-?e|firefly|chatgpt"
    r"|openai|gemini|copilot|imagen|leonardo|ideogram|sdxl",
    re.IGNORECASE,
)
_XMP_RE = re.compile(rb"<x:xmpmeta.*?</x:xmpmeta>", re.DOTALL)
_XMP_DST_RE = re.compile(
    r'Iptc4xmpExt:DigitalSourceType\s*=\s*"([^"]+)"|Iptc4xmpExt:DigitalSourceType>\s*([^<\s]+)\s*<'
)
_XMP_TOOL_RE = re.compile(r'xmp:CreatorTool\s*=\s*"([^"]+)"|xmp:CreatorTool>\s*([^<]+?)\s*<')
_C2PA_CLAIM_RE = re.compile(rb"claim_generator[\x00-\xff]{1,3}?([A-Za-z][\x20-\x7e]{2,199})")
_C2PA_DST_URL_RE = re.compile(rb"https?://cv\.iptc\.org/newscodes/digitalsourcetype/[A-Za-z]+")


def _sniff(data: bytes) -> str | None:
    if data.startswith(_PNG_MAGIC):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[4:8] == b"ftyp" and data[8:12] in _HEIC_BRANDS:
        return "heic"
    return None


def _inflate(blob: bytes) -> bytes:
    try:
        return zlib.decompress(blob)
    except zlib.error as exc:
        raise ValueError(f"corrupt compressed PNG text: {exc}") from exc


def _png_parts(data: bytes) -> tuple[dict[str, str], bytes | None]:
    text: dict[str, str] = {}
    c2pa: bytes | None = None
    pos = len(_PNG_MAGIC)
    while pos < len(data):
        if pos + 8 > len(data):
            raise ValueError("truncated PNG chunk header")
        length, ctype = struct.unpack(">I4s", data[pos : pos + 8])
        body = data[pos + 8 : pos + 8 + length]
        if len(body) != length:
            raise ValueError(f"truncated PNG {ctype.decode('ascii', 'replace')} chunk")
        pos += 12 + length
        if ctype == b"tEXt":
            key, _, value = body.partition(b"\0")
            text.setdefault(key.decode("latin-1"), value.decode("latin-1"))
        elif ctype == b"zTXt":
            key, _, rest = body.partition(b"\0")
            if len(rest) < 2:
                raise ValueError("malformed zTXt chunk")
            text.setdefault(key.decode("latin-1"), _inflate(rest[1:]).decode("latin-1"))
        elif ctype == b"iTXt":
            key, _, rest = body.partition(b"\0")
            if len(rest) < 2:
                raise ValueError("malformed iTXt chunk")
            compressed, rest = rest[0], rest[2:]
            _language, _, rest = rest.partition(b"\0")
            _translated, _, value = rest.partition(b"\0")
            if compressed:
                value = _inflate(value)
            text.setdefault(key.decode("latin-1"), value.decode("utf-8", "replace"))
        elif ctype == b"caBX":
            c2pa = body
        elif ctype == b"IEND":
            break
    return text, c2pa


def _jpeg_c2pa(data: bytes) -> bytes | None:
    segments: list[bytes] = []
    pos = 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker == 0xDA:
            break
        if marker == 0xFF:
            pos += 1
            continue
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:
            pos += 2
            continue
        (length,) = struct.unpack(">H", data[pos + 2 : pos + 4])
        if length < 2:
            raise ValueError("malformed JPEG segment length")
        if marker == 0xEB:
            segments.append(data[pos + 4 : pos + 2 + length])
        pos += 2 + length
    blob = b"".join(segments)
    return blob if b"jumb" in blob and b"c2pa" in blob else None


def _exif_software(data: bytes) -> str | None:
    with Image.open(io.BytesIO(data)) as image:
        value = image.getexif().get(_EXIF_SOFTWARE)
    return str(value) if value else None


def _signals(kind: str, data: bytes, filename: str) -> list[tuple[SignalType, str]]:
    found: list[tuple[SignalType, str]] = []
    text: dict[str, str] = {}
    c2pa: bytes | None = None
    if kind == "png":
        text, c2pa = _png_parts(data)
    elif kind == "jpeg":
        c2pa = _jpeg_c2pa(data)

    for key, value in text.items():
        if key in _SD_TEXT_KEYS:
            found.append((SignalType.SD_PARAMETERS, f"png:{key}"))
        elif key == "Comment" and "NovelAI" in value:
            found.append((SignalType.SD_PARAMETERS, "NovelAI"))
        elif key == "Software" and _AI_SOFTWARE.search(value):
            found.append((SignalType.METADATA_HINT, value.strip()[:200]))

    if kind != "heic":
        software = _exif_software(data)
        if software and _AI_SOFTWARE.search(software):
            found.append((SignalType.METADATA_HINT, software[:200]))

    if c2pa is not None:
        claim = _C2PA_CLAIM_RE.search(c2pa)
        found.append((SignalType.C2PA, claim.group(1).decode("ascii") if claim else "present"))
        source = _C2PA_DST_URL_RE.search(c2pa)
        if source and b"AlgorithmicMedia" in source.group(0):
            found.append((SignalType.IPTC_DIGITAL_SOURCE, source.group(0).decode("ascii")))

    xmp = _XMP_RE.search(data)
    if xmp:
        packet = xmp.group(0).decode("utf-8", "replace")
        source_type = _XMP_DST_RE.search(packet)
        if source_type:
            value = source_type.group(1) or source_type.group(2)
            if "AlgorithmicMedia" in value:
                found.append((SignalType.IPTC_DIGITAL_SOURCE, value))
        tool = _XMP_TOOL_RE.search(packet)
        if tool:
            name = tool.group(1) or tool.group(2)
            if _AI_SOFTWARE.search(name):
                found.append((SignalType.METADATA_HINT, name))

    for pattern, service in AI_FILENAME_PATTERNS:
        if pattern.search(filename):
            found.append((SignalType.AI_FILENAME_PATTERN, service))
            break
    return list(dict.fromkeys(found))


class Plugin(PluginBase):
    name = "provenance.images"
    version = "1.0"
    description = "AI generation signals in image files: PNG/JPEG text, C2PA, XMP, EXIF and file names"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for user in fs.users():
            for ref in fs.walk(EntryRef(user.volume, user.home), max_depth=MAX_DEPTH, skip_names=SKIP_DIRS):
                if posixpath.splitext(ref.path)[1].lower().lstrip(".") not in IMAGE_EXTS:
                    continue
                size = fs.stat(ref).size
                if size is None or size > MAX_BYTES:
                    continue
                yield Candidate(ref=ref, role="image", user=user)

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact]:
        data = ctx.fs.read_bytes(cand.ref)
        kind = _sniff(data)
        if kind is None:
            return
        try:
            signals = _signals(kind, data, basename(cand.ref.path))
        except (OSError, ValueError, SyntaxError, struct.error) as exc:
            yield self.warning(ctx, cand, f"image metadata unreadable: {exc}")
            return
        if not signals:
            return
        os_family = cand.user.os_family if cand.user is not None else OsFamily.UNKNOWN
        payload = {
            "path": normalize(cand.ref.path, os_family),
            "signals": [{"type": signal.value, "value": value} for signal, value in signals],
        }
        yield self.artifact(ctx, cand, ArtifactKind.MEDIA_PROVENANCE, payload)


PLUGIN = Plugin()
