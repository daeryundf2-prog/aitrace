# Validation

aitrace is checked against three synthetic disk images, one per operating system, built by scripts in `tools/fixtures/` and committed under `tests/fixtures/images/`. All planted content, times and expected results are fixed, so any examiner can rebuild and compare.

## Fixture hashes

SHA-256 of each committed E01 file:

| Image | SHA-256 |
| --- | --- |
| `windows.E01` | `0e4842d655f58fa29143933b22d79d70ee5a8ff1fa874a8643d094abcb902272` |
| `macos.E01` | `3c103a905bcd0e5d0ce70cc12446efc0ad2828bb7f8ee475d2c24450330069ea` |
| `linux.E01` | `f5ef7261cf9eb5fd5baad9a3df44230bebf7dcbde8766dcbc578fa8a0a0a0c02` |

Check them yourself:

```
shasum -a 256 tests/fixtures/images/*.E01
uv run aitrace verify tests/fixtures/images/windows.E01
```

Expected results for each image are in `tests/fixtures/expected/{windows,macos,linux}.json`. What each image contains is described in `tests/fixtures/images/README-windows.md`, `README-macos.md` and `README-linux.md`.

## Tests that validate the tool

End-to-end, in `tests/e2e/test_fixtures.py`, parametrized over `windows`, `macos` and `linux`:

- runs `aitrace analyze` on each E01 with all output formats;
- asserts every fact in the matching expected file: users, tools, prompts, deleted files, exfil channels, attributions;
- runs each image twice into separate case directories and asserts `report.json` is identical once the `run` key is removed;
- checks the timeline rows have source paths and the exported files match their manifest hashes;
- checks the macOS run lists the encrypted ChatGPT store as `encrypted_not_decoded` in its coverage.

Unit tests that cover the same ground piece by piece:

- `tests/unit/cli/test_cli.py`: full output layout, integrity mismatch (exit 3), refused case directories (exit 4), edited custody log (exit 6), re-render.
- `tests/unit/acquisition/test_custody.py` and `test_verify.py`: custody chain and hashing.
- `tests/unit/analyzers/test_attribution.py`: the rubric in [attribution](attribution.md).
- `tests/unit/export/test_exporter.py`: exported hashes and manifests.
- `tests/unit/plugins/`: one test file per plugin.

## Run everything

```
uv run pytest -m "not realdata"
uv run ruff check .
python tools/check_links.py
```

The last command checks that every relative link in the Markdown files points to a file that exists. `python tools/check_links.py --self-test` proves the checker fails on a broken link.
