"""Check that every relative `](target)` link in the repository's Markdown files resolves.

Usage: check_links.py [ROOT] [--self-test]

Exits 0 when all links resolve, 1 when at least one is broken.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path

LINK_RE = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
SKIP_DIRS = frozenset({".git", ".venv", "node_modules", ".pytest_cache", ".ruff_cache", "__pycache__"})
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "ftp://", "data:", "tel:")


def markdown_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*.md")):
        if not SKIP_DIRS.intersection(path.relative_to(root).parts):
            yield path


def relative_targets(text: str) -> Iterator[tuple[int, str]]:
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in LINK_RE.finditer(line):
            target = match.group(1)
            if target.startswith(("#", *EXTERNAL_PREFIXES)):
                continue
            yield number, target


def broken_links(root: Path) -> list[str]:
    problems: list[str] = []
    for md in markdown_files(root):
        text = md.read_text(encoding="utf-8")
        for number, target in relative_targets(text):
            path_part = target.split("#", 1)[0].split("?", 1)[0]
            if not path_part:
                continue
            base = root if path_part.startswith("/") else md.parent
            if not (base / path_part.lstrip("/")).exists():
                problems.append(f"{md.relative_to(root)}:{number}: missing target {target}")
    return problems


def run(root: Path) -> int:
    files = list(markdown_files(root))
    problems = broken_links(root)
    for problem in problems:
        print(problem)
    print(f"checked {len(files)} markdown files, {len(problems)} broken links")
    return 1 if problems else 0


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "a.md").write_text("[ok](b.md) [web](https://example.com) [top](#x)\n", encoding="utf-8")
        (root / "b.md").write_text("fine\n", encoding="utf-8")
        if run(root) != 0:
            print("self-test failed: good tree reported broken")
            return 1
        (root / "a.md").write_text("[bad](missing.md)\n", encoding="utf-8")
        if run(root) != 1:
            print("self-test failed: broken link not detected")
            return 1
    print("self-test passed")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    return run(args.root.resolve())


if __name__ == "__main__":
    sys.exit(main())
