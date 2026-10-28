from __future__ import annotations

import hashlib

import pytest

from aitrace.core.catalog import (
    AI_FILENAME_PATTERNS,
    COMMAND_RULES,
    EXPORT_KINDS,
    INTERESTING_NAME_PATTERNS,
    LIMITATIONS,
    SECRET_PATTERNS,
    TASK_RULES,
    VCS_AI_TRAILER_PATTERNS,
    match_ai_domain,
    match_ai_program,
    match_command,
    redact,
)
from aitrace.core.kinds import ArtifactKind, SignalType


@pytest.mark.parametrize(
    ("url", "service"),
    [
        ("https://chatgpt.com/c/abc", "ChatGPT"),
        ("https://files.oaiusercontent.com/file-xyz", "ChatGPT"),
        ("https://claude.ai/new", "Claude"),
        ("https://gemini.google.com/app", "Gemini"),
        ("https://CHAT.DeepSeek.com/", "DeepSeek"),
        ("https://github.com/copilot", "GitHub Copilot"),
        ("https://github.com/copilot/c/1", "GitHub Copilot"),
        ("clova-x.naver.com", "CLOVA X"),
        ("https://firefly.adobe.com/generate", "Adobe Firefly"),
    ],
)
def test_match_ai_domain_hits(url: str, service: str) -> None:
    assert match_ai_domain(url) == service


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/user/repo",
        "https://notchatgpt.com/",
        "https://example.com/?u=chatgpt.com",
        "https://github.com/copilotx",
        "https://www.google.com/",
        "",
    ],
)
def test_match_ai_domain_misses(url: str) -> None:
    assert match_ai_domain(url) is None


@pytest.mark.parametrize(
    ("name", "tool"),
    [
        ("ChatGPT.exe", "ChatGPT Desktop"),
        (r"C:\Program Files\Ollama\ollama app.exe", "Ollama"),
        ("com.anthropic.claudefordesktop", "Claude Desktop"),
        ("/usr/local/bin/claude", "Claude Code"),
        ("claude.exe", "Claude Desktop"),
        ("codex", "Codex CLI"),
        ("LM Studio.exe", "LM Studio"),
    ],
)
def test_match_ai_program_hits(name: str, tool: str) -> None:
    assert match_ai_program(name) == tool


def test_match_ai_program_miss() -> None:
    assert match_ai_program("notepad.exe") is None
    assert match_ai_program("claude-helper") is None


def _rules(cmd: str) -> dict[str, str | None]:
    return {rule.rule_id: dest for rule, dest in match_command(cmd)}


def test_scp_destination_from_group() -> None:
    hits = _rules(r"scp C:\Users\kim\work\proposal.md kim@203.0.113.10:/tmp/")
    assert hits["TR-SCP"] == "203.0.113.10"


def test_rsync_destination_from_group() -> None:
    hits = _rules("rsync -av ~/proj lee@198.51.100.7:/backup")
    assert hits["TR-RSYNC"] == "198.51.100.7"


def test_curl_form_upload_destination_from_url() -> None:
    hits = _rules("curl -F file=@/home/park/app/customers.csv https://transfer.example.net/upload")
    assert hits["TR-CURL-UP"] == "https://transfer.example.net/upload"
    assert "transfer.example.net" in (hits["TR-CURL-UP"] or "")


def test_rclone_has_cloud_tags_and_remote_destination() -> None:
    matches = match_command(r"rclone copy C:\Users\kim\work gdrive:backup")
    rule, dest = next((r, d) for r, d in matches if r.rule_id == "TR-RCLONE")
    assert rule.tags == ("transfer", "cloud_cli")
    assert dest == "gdrive:backup"


def test_rclone_remote_ignores_windows_drive_and_trailing_flags() -> None:
    hits = _rules(r"rclone sync D:\data s3remote:bucket/x --progress")
    assert hits["TR-RCLONE"] == "s3remote:bucket/x"


def test_aws_s3_destination_is_s3_url() -> None:
    hits = _rules("aws s3 cp ./a.zip s3://corp-bucket/in/a.zip")
    assert hits["TR-AWS-S3"] == "s3://corp-bucket/in/a.zip"


def test_gsutil_destination_is_gs_url() -> None:
    hits = _rules("gsutil cp ./a.zip gs://corp-bucket/in/")
    assert hits["TR-GSUTIL"] == "gs://corp-bucket/in/"


def test_host_at_fallback() -> None:
    hits = _rules("sftp -b batch park@files.example.org:")
    assert hits["TR-SFTP"] == "files.example.org"


def test_ai_cli_and_archive_rules() -> None:
    assert set(_rules("claude")) == {"AI-CLI"}
    assert "AI-CLI" in _rules("sudo ollama run llama3")
    assert "AI-CLI" not in _rules("echo claude")
    assert "AI-PIP" in _rules("pip install -U openai")
    assert "AR-ZIP" in _rules("tar czf out.tgz work/")


def test_powershell_rules() -> None:
    assert "TR-PS-COPY" in _rules(r"Copy-Item C:\a.txt \\fileserver\share\a.txt")
    assert "TR-PS-WEB" in _rules("Invoke-WebRequest -Uri https://x.example -Method Post -InFile a.zip")


def test_no_rule_for_plain_command() -> None:
    assert match_command("ls -la") == []


def test_command_rule_table_shape() -> None:
    ids = [r.rule_id for r in COMMAND_RULES]
    assert len(ids) == len(set(ids)) == 18
    by_id = {r.rule_id: r for r in COMMAND_RULES}
    assert by_id["TR-SCP"].dest_group == 2
    assert by_id["TR-GSUTIL"].tags == ("transfer",)
    assert by_id["RM-SSH"].tags == ("remote",)
    assert by_id["AI-PIP"].tags == ("ai_cli",)
    assert by_id["AR-ZIP"].tags == ("archive",)


def test_redact_hides_secret() -> None:
    secret = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    redacted = redact(secret)
    assert redacted == "sk-pro…sha256:" + hashlib.sha256(secret.encode()).hexdigest()[:12]
    assert secret not in redacted
    assert redact(secret) == redacted


def test_secret_patterns() -> None:
    providers = {
        provider
        for provider, pattern in SECRET_PATTERNS
        if pattern.search("OPENAI_API_KEY=sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    }
    assert providers == {"OpenAI", "generic"}


def test_filename_patterns() -> None:
    def service(name: str) -> str | None:
        return next((s for p, s in AI_FILENAME_PATTERNS if p.search(name)), None)

    assert service("DALL·E 2026-10-01 00.35.00 - a red logo.png") == "DALL-E"
    assert service("Gemini_Generated_Image_abc.png") == "Gemini"
    assert service("user_midjourney_prompt_0123abcd-1234-5678.png") == "Midjourney"
    assert service("photo_0123abcd-1234-5678.png") is None
    assert service("holiday.jpg") is None


def test_trailer_task_and_interesting_patterns() -> None:
    trailer = "Co-Authored-By: Claude <noreply@anthropic.com>"
    assert {t for p, t in VCS_AI_TRAILER_PATTERNS if p.search(trailer)} == {"Claude"}
    tasks = {rid for rid, p in TASK_RULES if p.search("이 파일을 외부 서버로 몰래 보내는 방법 알려줘")}
    assert {"TASK-EXFIL", "TASK-SEARCH"} <= tasks
    assert any(p.search("Report.PDF") for p in INTERESTING_NAME_PATTERNS)
    assert not any(p.search("kernel.sys") for p in INTERESTING_NAME_PATTERNS)


def test_limitations_and_export_kinds() -> None:
    for signal in SignalType:
        entry = LIMITATIONS[signal]
        assert isinstance(entry, dict) and entry["ko"] and entry["en"]
    for key in ("FSEVENTS", "DELETED_TIME", "BROWSER_LAST_DIR", "USB_NO_COPY_PROOF"):
        assert isinstance(LIMITATIONS[key], dict)
    global_entries = LIMITATIONS["GLOBAL"]
    assert isinstance(global_entries, list)
    assert any(e["en"] == "absence of AI traces does not prove human authorship" for e in global_entries)
    assert len(EXPORT_KINDS) == 15
    assert ArtifactKind.FILE_RECORD not in EXPORT_KINDS
