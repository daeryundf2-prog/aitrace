from __future__ import annotations

import json
import os
import plistlib
import random
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IMAGES_DIR = ROOT / "tests" / "fixtures" / "images"
IMAGE_BASE = IMAGES_DIR / "macos"
EXPECTED_PATH = ROOT / "tests" / "fixtures" / "expected" / "macos.json"

MAC_EPOCH_OFFSET = 978307200
GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "lee",
    "GIT_AUTHOR_EMAIL": "lee@example.invalid",
    "GIT_COMMITTER_NAME": "lee",
    "GIT_COMMITTER_EMAIL": "lee@example.invalid",
}

EXPECTED: dict[str, object] = {
    "users": ["lee"],
    "tools": ["ChatGPT Desktop", "Cursor", "Codex CLI", "Gemini"],
    "prompts_contain": ["csv로 바꾸는 파이썬 코드", "이 함수 리팩터링해줘", "IP만 추출하는"],
    "deleted_files": [],
    "exfil": ["198.51.100.7"],
    "attributions": {},
    "vcs_ai_trailers": ["Claude"],
    "coverage_contains": ["encrypted_not_decoded"],
}


def utc(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def write(path: Path, data: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")


def sqlite_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(path)


def populate(stage: Path) -> None:
    lee = stage / "Users" / "lee"

    chat_root = lee / "Library" / "Application Support" / "com.openai.chat"
    t0 = utc("2026-10-02T00:00:00Z")
    conv = {
        "title": "Excel 매크로",
        "create_time": t0,
        "update_time": t0 + 30,
        "mapping": {
            "root": {"id": "root", "message": None, "parent": None, "children": ["u1"]},
            "u1": {
                "id": "u1",
                "parent": "root",
                "children": ["a1"],
                "message": {
                    "id": "u1",
                    "author": {"role": "user"},
                    "create_time": t0,
                    "content": {"content_type": "text", "parts": ["엑셀 데이터를 csv로 바꾸는 파이썬 코드 짜줘"]},
                },
            },
            "a1": {
                "id": "a1",
                "parent": "u1",
                "children": [],
                "message": {
                    "id": "a1",
                    "author": {"role": "assistant"},
                    "create_time": t0 + 30,
                    "content": {"content_type": "text", "parts": ["다음 코드를 사용하세요: import csv"]},
                },
            },
        },
    }
    write(chat_root / "conversations-11111111-2222" / "conv1.json", json.dumps(conv, ensure_ascii=False, indent=2))
    write(chat_root / "conversations-v2-11111111-2222" / "abc.data", random.Random(7).randbytes(256))

    composer = {
        "composerId": "c1",
        "name": "refactor",
        "createdAt": int(utc("2026-10-02T01:00:00Z") * 1000),
        "conversation": [
            {"type": 1, "text": "이 함수 리팩터링해줘", "bubbleId": "b1"},
            {"type": 2, "text": "리팩터링한 코드입니다", "bubbleId": "b2"},
        ],
    }
    cursor_db = lee / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage" / "state.vscdb"
    with closing(sqlite_db(cursor_db)) as con, con:
        con.execute("CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
        con.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?, ?)",
            ("composerData:c1", json.dumps(composer, ensure_ascii=False)),
        )

    safari_db = lee / "Library" / "Safari" / "History.db"
    with closing(sqlite_db(safari_db)) as con, con:
        con.execute(
            "CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE, "
            "domain_expansion TEXT, visit_count INTEGER NOT NULL DEFAULT 0)"
        )
        con.execute(
            "CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER NOT NULL, "
            "visit_time REAL NOT NULL, title TEXT)"
        )
        con.execute(
            "INSERT INTO history_items (id, url, domain_expansion, visit_count) "
            "VALUES (1, 'https://gemini.google.com/app', 'gemini.google.com', 1)"
        )
        con.execute(
            "INSERT INTO history_visits (id, history_item, visit_time, title) VALUES (1, 1, ?, 'Gemini')",
            (utc("2026-10-02T02:00:00Z") - MAC_EPOCH_OFFSET,),
        )

    quarantine_db = lee / "Library" / "Preferences" / "com.apple.LaunchServices.QuarantineEventsV2"
    with closing(sqlite_db(quarantine_db)) as con, con:
        con.execute(
            "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL, "
            "LSQuarantineTimeStamp REAL, LSQuarantineAgentBundleIdentifier TEXT, LSQuarantineAgentName TEXT, "
            "LSQuarantineDataURLString TEXT, LSQuarantineSenderName TEXT, LSQuarantineSenderAddress TEXT, "
            "LSQuarantineTypeNumber INTEGER, LSQuarantineOriginTitle TEXT, LSQuarantineOriginURLString TEXT, "
            "LSQuarantineOriginAlias BLOB)"
        )
        con.execute(
            "INSERT INTO LSQuarantineEvent (LSQuarantineEventIdentifier, LSQuarantineTimeStamp, "
            "LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString) "
            "VALUES (?, ?, 'Safari', 'https://gemini.google.com/app/download', 'https://gemini.google.com/')",
            ("A1B2C3D4-0000-4000-8000-000000000001", utc("2026-10-02T02:05:00Z") - MAC_EPOCH_OFFSET),
        )

    rollout = [
        {
            "timestamp": "2026-10-02T03:00:00Z",
            "type": "session_meta",
            "payload": {"id": "abc", "cwd": "/Users/lee", "originator": "codex_cli"},
        },
        {
            "timestamp": "2026-10-02T03:00:01Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "로그 파일에서 IP만 추출하는 스크립트"}],
            },
        },
        {
            "timestamp": "2026-10-02T03:00:20Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' app.log"}],
            },
        },
    ]
    rollout_lines = "\n".join(json.dumps(line, ensure_ascii=False) for line in rollout)
    write(
        lee / ".codex" / "sessions" / "2026" / "10" / "02" / "rollout-2026-10-02T03-00-00-abc.jsonl",
        rollout_lines + "\n",
    )

    epoch = int(utc("2026-10-02T04:00:00Z"))
    write(
        lee / ".zsh_history",
        f": {epoch}:0;codex\n: {epoch + 100}:0;rsync -av ~/proj lee@198.51.100.7:/backup\n",
    )

    proj = lee / "proj"
    write(proj / "parser.py", "def parse(line):\n    return line.split()\n")
    commit_date = f"{int(utc('2026-10-02T05:00:00Z'))} +0000"
    git_env = {**os.environ, **GIT_IDENTITY, "GIT_AUTHOR_DATE": commit_date, "GIT_COMMITTER_DATE": commit_date}
    run(["git", "init", "-q", "-b", "main"], cwd=proj)
    run(["git", "add", "parser.py"], cwd=proj)
    run(
        ["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "add parser",
         "-m", "Co-Authored-By: Claude <noreply@anthropic.com>"],
        cwd=proj,
        env=git_env,
    )

    write(
        stage / "System" / "Library" / "CoreServices" / "SystemVersion.plist",
        plistlib.dumps({"ProductName": "macOS", "ProductVersion": "15.0"}, fmt=plistlib.FMT_XML),
    )


def build_image(work: Path) -> None:
    stage = work / "stage"
    populate(stage)
    cdr = work / "macos.cdr"
    run([
        "hdiutil", "create", "-quiet", "-fs", "APFS", "-volname", "Macintosh",
        "-srcfolder", str(stage), "-format", "UDTO", "-size", "64m", str(cdr),
    ])
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    for stale in IMAGES_DIR.glob("macos.E*"):
        stale.unlink()
    run([
        "ewfacquire", "-u", "-t", str(IMAGE_BASE), "-f", "encase6", "-c", "deflate:fast",
        "-C", "AITRACE-MAC", "-D", "aitrace macos fixture", "-E", "MAC-001", "-e", "aitrace",
        "-N", "fixture", "-d", "sha256", "-q", str(cdr),
    ])


def main() -> int:
    if sys.platform != "darwin":
        print(f"build_macos.py requires macOS (hdiutil, APFS); this host is {sys.platform}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="aitrace-macos-") as tmp:
        build_image(Path(tmp))
    EXPECTED_PATH.parent.mkdir(parents=True, exist_ok=True)
    EXPECTED_PATH.write_text(json.dumps(EXPECTED, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {IMAGE_BASE}.E01 and {EXPECTED_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
