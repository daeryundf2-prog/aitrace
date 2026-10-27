from __future__ import annotations

import logging

from aitrace.core.kinds import ArtifactKind, OsFamily
from aitrace.core.model import Artifact, Event
from aitrace.fs.memory_fs import MemoryFS
from aitrace.plugins.ai.sdk_keys import PLUGIN
from aitrace.plugins.base import ParseContext

OPENAI_KEY = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
ANTHROPIC_KEY = "sk-ant-api03-ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210"
HOME = "/Users/lee"


def _run(files: dict[str, bytes]) -> list[Artifact | Event]:
    fs = MemoryFS(files, volume_os=OsFamily.MACOS)
    ctx = ParseContext(fs=fs, evidence_id="ev-test", tz="UTC", log=logging.getLogger("test.sdk_keys"))
    return [item for cand in PLUGIN.locate(fs) for item in PLUGIN.parse(ctx, cand)]


def _artifacts(items: list[Artifact | Event], kind: ArtifactKind) -> list[Artifact]:
    return [item for item in items if isinstance(item, Artifact) and item.kind is kind]


def test_env_key_is_found_and_redacted() -> None:
    env = f"# comment\nOPENAI_API_KEY={OPENAI_KEY}\n".encode()
    items = _run({f"{HOME}/proj/.env": env})

    creds = _artifacts(items, ArtifactKind.AI_CREDENTIAL)
    assert len(creds) == 1
    assert creds[0].data["provider"] == "OpenAI"
    assert creds[0].data["line"] == 2
    assert creds[0].data["redacted"].startswith("sk-pro…sha256:")
    assert creds[0].provenance.source_path == f"{HOME}/proj/.env"


def test_full_secret_never_in_any_record() -> None:
    files = {
        f"{HOME}/.env": f"OPENAI_API_KEY={OPENAI_KEY}\n".encode(),
        f"{HOME}/.zshrc": f"export ANTHROPIC_API_KEY='{ANTHROPIC_KEY}'\n".encode(),
        f"{HOME}/cfg/app.json": f'{{"key": "{OPENAI_KEY}"}}'.encode(),
        f"{HOME}/.codex/auth.json": f'{{"OPENAI_API_KEY": "{OPENAI_KEY}"}}'.encode(),
    }
    items = _run(files)

    assert len(_artifacts(items, ArtifactKind.AI_CREDENTIAL)) >= 4
    for item in items:
        assert OPENAI_KEY not in str(item)
        assert ANTHROPIC_KEY not in str(item)


def test_same_line_key_reported_once() -> None:
    items = _run({f"{HOME}/.env": f"OPENAI_API_KEY={OPENAI_KEY}\n".encode()})
    assert len(_artifacts(items, ArtifactKind.AI_CREDENTIAL)) == 1


def test_credential_stores_are_presence_only() -> None:
    items = _run(
        {
            f"{HOME}/.codex/auth.json": f'{{"OPENAI_API_KEY": "{OPENAI_KEY}"}}'.encode(),
            f"{HOME}/.claude/.credentials.json": b'{"claudeAiOauth": {"accessToken": "tok"}}',
        }
    )

    creds = _artifacts(items, ArtifactKind.AI_CREDENTIAL)
    assert {(c.data["tool"], c.data["provider"]) for c in creds} == {
        ("Codex", "OpenAI"),
        ("Claude Code", "Anthropic"),
    }
    assert all("line" not in c.data and "sha256" not in c.data["redacted"] for c in creds)


def test_sdk_directories_yield_presence() -> None:
    files = {
        f"{HOME}/venv/lib/python3.12/site-packages/openai/__init__.py": b"",
        f"{HOME}/venv/lib/python3.12/site-packages/google/generativeai/__init__.py": b"",
        f"{HOME}/app/node_modules/openai/package.json": b"{}",
        f"{HOME}/app/node_modules/@anthropic-ai/sdk/package.json": b"{}",
    }
    items = _run(files)

    presence = _artifacts(items, ArtifactKind.AI_APP_PRESENCE)
    assert {p.data["tool"] for p in presence} == {
        "openai (python)",
        "google-generativeai (python)",
        "openai (node)",
        "@anthropic-ai (node)",
    }
    assert all(p.data["kind"] == "sdk" and p.data["status"] == "present" for p in presence)


def test_skipped_locations_and_large_files_are_ignored() -> None:
    line = f"OPENAI_API_KEY={OPENAI_KEY}\n".encode()
    files = {
        f"{HOME}/app/node_modules/pkg/.env": line,
        f"{HOME}/repo/.git/config.json": line,
        f"{HOME}/Library/Caches/x/.env": line,
        f"{HOME}/a/b/c/d/e/f/.env": line,  # depth 7
        f"{HOME}/big.json": line + b" " * (1024 * 1024),
    }
    assert _artifacts(_run(files), ArtifactKind.AI_CREDENTIAL) == []


def test_non_utf8_file_gives_parse_warning() -> None:
    items = _run({f"{HOME}/bad.json": b"\xff\xfe\x00 OPENAI_API_KEY=x"})
    assert len(_artifacts(items, ArtifactKind.PARSE_WARNING)) == 1


def test_placeholder_generic_value_is_not_reported() -> None:
    items = _run({f"{HOME}/.env": b"OPENAI_API_KEY=${OPENAI_API_KEY}\nMISTRAL_API_KEY=changeme-real-1234\n"})
    creds = _artifacts(items, ArtifactKind.AI_CREDENTIAL)
    assert [(c.data["provider"], c.data["line"]) for c in creds] == [("Mistral", 2)]
