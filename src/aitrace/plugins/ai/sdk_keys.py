from __future__ import annotations

from collections.abc import Iterator

from aitrace.core.catalog import SECRET_PATTERNS, redact
from aitrace.core.kinds import ArtifactKind
from aitrace.core.model import Artifact, Event, UserProfile
from aitrace.core.paths import basename
from aitrace.fs.base import EntryRef, EvidenceFS, user_glob
from aitrace.plugins.base import Candidate, ParseContext, PluginBase

_MAX_DEPTH = 5
_MAX_BYTES = 1024 * 1024
_SKIP_NAMES = frozenset({"node_modules", ".git"})
_SKIP_FRAGMENTS = ("/library/caches/", "/appdata/local/temp/")
_SUFFIXES = (".toml", ".json", ".yaml", ".yml")
_NAMES = frozenset(
    {".zshrc", ".bashrc", ".bash_profile", ".profile", "config.fish", "microsoft.powershell_profile.ps1"}
)
_CRED_STORES: tuple[tuple[str, str, str], ...] = (
    (".codex/auth.json", "Codex", "OpenAI"),
    (".claude/.credentials.json", "Claude Code", "Anthropic"),
)
_SDK_PATTERNS: tuple[tuple[str, str], ...] = (
    ("**/site-packages/openai/__init__.py", "openai (python)"),
    ("**/site-packages/anthropic/__init__.py", "anthropic (python)"),
    ("**/site-packages/google/generativeai/__init__.py", "google-generativeai (python)"),
    ("**/site-packages/langchain/__init__.py", "langchain (python)"),
    ("**/site-packages/ollama/__init__.py", "ollama (python)"),
    ("**/node_modules/openai/package.json", "openai (node)"),
    ("**/node_modules/@anthropic-ai/*/package.json", "@anthropic-ai (node)"),
)
_GENERIC_PROVIDERS = {
    "OPENAI": "OpenAI",
    "ANTHROPIC": "Anthropic",
    "GEMINI": "Google",
    "GOOGLE": "Google",
    "MISTRAL": "Mistral",
    "COHERE": "Cohere",
    "AZURE_OPENAI": "Azure OpenAI",
}
_PLACEHOLDER_PREFIXES = ("$", "<", "{")


def _is_scan_target(name: str) -> bool:
    low = name.casefold()
    return low.startswith(".env") or low in _NAMES or low.endswith(_SUFFIXES)


def _clean_value(raw: str) -> str:
    return raw.strip().strip("'\",;")


def _line_secrets(line: str) -> list[tuple[str, str]]:
    """(provider, secret value) pairs for one line; provider patterns win over the generic env pattern."""
    found: list[tuple[str, str]] = []
    for provider, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(line):
            if provider == "DeepSeek":
                secret = _clean_value(match.group(0).split("=", 1)[1])
            elif provider == "generic":
                secret = _clean_value(match.group(2))
                provider = _GENERIC_PROVIDERS.get(match.group(1), match.group(1).title())
                if secret.startswith(_PLACEHOLDER_PREFIXES) or len(secret) < 8:
                    continue
            else:
                secret = match.group(0)
            if secret and not any(secret in known or known in secret for _, known in found):
                found.append((provider, secret))
    return found


class Plugin(PluginBase):
    name = "sdk_keys"
    version = "1.0"
    description = "AI provider API keys in config/env/shell files (redacted), CLI credential stores, installed AI SDKs"

    def locate(self, fs: EvidenceFS) -> Iterator[Candidate]:
        for user in fs.users():
            yield from self._locate_user(fs, user)

    def _locate_user(self, fs: EvidenceFS, user: UserProfile) -> Iterator[Candidate]:
        store_paths: set[str] = set()
        for rel, tool, provider in _CRED_STORES:
            ref = EntryRef(user.volume, f"{user.home.rstrip('/')}/{rel}")
            store_paths.add(ref.path.casefold())
            if fs.exists(ref) and not fs.is_dir(ref):
                yield Candidate(ref, "credential_store", user, {"tool": tool, "provider": provider})
        root = EntryRef(user.volume, user.home)
        for ref in fs.walk(root, max_depth=_MAX_DEPTH, skip_names=_SKIP_NAMES):
            if ref.path.casefold() in store_paths or not _is_scan_target(basename(ref.path)):
                continue
            if any(fragment in ref.path.casefold() + "/" for fragment in _SKIP_FRAGMENTS):
                continue
            size = fs.stat(ref).size
            if size is not None and size > _MAX_BYTES:
                continue
            yield Candidate(ref, "secret_scan", user)
        for pattern, label in _SDK_PATTERNS:
            for ref in user_glob(fs, user, pattern):
                yield Candidate(ref, "sdk", user, {"sdk": label})

    def parse(self, ctx: ParseContext, cand: Candidate) -> Iterator[Artifact | Event]:
        if cand.role == "credential_store":
            yield self.artifact(
                ctx,
                cand,
                ArtifactKind.AI_CREDENTIAL,
                {
                    "tool": str(cand.extra["tool"]),
                    "provider": str(cand.extra["provider"]),
                    "redacted": "[credential file present; value not read]",
                },
                locator="presence",
            )
            return
        if cand.role == "sdk":
            label = str(cand.extra["sdk"])
            yield self.artifact(
                ctx,
                cand,
                ArtifactKind.AI_APP_PRESENCE,
                {"tool": label, "kind": "sdk", "status": "present", "detail": cand.ref.path},
                locator="sdk",
            )
            return
        try:
            text = ctx.fs.read_bytes(cand.ref, _MAX_BYTES).decode("utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            yield self.warning(ctx, cand, f"cannot read as UTF-8 text: {exc}")
            return
        for number, line in enumerate(text.splitlines(), start=1):
            for provider, secret in _line_secrets(line):
                redacted = redact(secret)
                yield self.artifact(
                    ctx,
                    cand,
                    ArtifactKind.AI_CREDENTIAL,
                    {"provider": provider, "redacted": redacted, "line": number},
                    locator=f"line:{number}:{redacted}",
                )


PLUGIN = Plugin()
