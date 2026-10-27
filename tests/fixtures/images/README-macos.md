# macos.E01

macOS APFS E01 fixture for plan Appendix C.2 (user `lee`, ChatGPT Desktop / Cursor / Codex CLI / Gemini traces).

## Build

Run from the repo root on macOS (`hdiutil` and `ewfacquire` on PATH):

```sh
.venv/bin/python tools/fixtures/build_macos.py
```

The builder stages the planted files under a temp directory, runs
`hdiutil create -quiet -fs APFS -volname Macintosh -srcfolder <stage> -format UDTO -size 64m macos.cdr`,
then `ewfacquire -u -t tests/fixtures/images/macos -f encase6 -c deflate:fast -C AITRACE-MAC -D "aitrace macos fixture" -E MAC-001 -e aitrace -N fixture -d sha256 -q macos.cdr`,
and rewrites `tests/fixtures/expected/macos.json`. On a non-macOS host it exits 2 without writing anything.

## Artifact

- File: `tests/fixtures/images/macos.E01` (379982 bytes)
- SHA-256: `78abe0a49e811d97f666c64e7c1d5238d38e10ce1edae181fa477f2725d1686a`
