# linux.E01

Linux ext4 E01 fixture for plan Appendix C.3 (user `park`, Claude Code / Ollama / Aider traces).

## Build

Run from the repo root on macOS with e2fsprogs (`mke2fs`) and libewf (`ewfacquire`) on PATH:

```sh
.venv/bin/python tools/fixtures/build_linux.py
```

The builder stages the planted files under a temp directory, runs
`mke2fs -q -t ext4 -E root_owner=0:0 -d <stage> linux.raw 32M`, then
`ewfacquire -u -t tests/fixtures/images/linux -f encase6 -c deflate:fast -C AITRACE-LNX -D "aitrace linux fixture" -E LNX-001 -e aitrace -N fixture -d sha256 -q linux.raw`,
and rewrites `tests/fixtures/expected/linux.json`.

## Artifact

- File: `tests/fixtures/images/linux.E01` (184595 bytes)
- SHA-256: `f5ef7261cf9eb5fd5baad9a3df44230bebf7dcbde8766dcbc578fa8a0a0a0c02`

The E01 embeds an acquisition timestamp, so rebuilding changes the hash. The planted-file set does not change.
