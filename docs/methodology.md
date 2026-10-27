# Methodology

This page explains why an aitrace result can be trusted and how another examiner can check it.

## Read-only access

Images are opened through the dissect library. Nothing is mounted, and nothing is written to the evidence path. `aitrace analyze` refuses a `--case-dir` inside the evidence directory (exit 4). SQLite files found in an image are copied to a temporary directory before they are opened, so the original bytes stay untouched.

## Hashing

At intake, every image segment file is hashed with MD5, SHA-1 and SHA-256, and the media stream is hashed too (skip it with `--no-media-hash`). Before the report is written, the segments are hashed again. A mismatch stops the run with exit 3, and the report still gets written with an INTEGRITY finding, so the reader sees the problem instead of a silent failure. `aitrace verify IMAGE` prints the same hashes on demand. The stored E01 hash is shown when dissect exposes it.

Exported files carry a SHA-256 in `export/manifest.csv` and `manifest.json`, along with size, source path and artifact id.

## Chain of custody

Each action is appended to `custody.jsonl` as an entry that includes the hash of the previous entry. `aitrace report` verifies the chain first and exits 6 when someone edited the log. The report lists the ordered actions without timestamps in the top-level `custody` field, and the full entries with times and hashes under `run.custody`.

## Plugins fail alone

Every plugin runs on its own. A parse failure becomes a PARSE_WARNING artifact and a coverage line. Encrypted, unsupported or corrupt stores are reported as "present, not decoded" with the reason. One bad file never aborts the run.

## Secrets

API keys and tokens are redacted in every output: the first 6 characters, an ellipsis, then `sha256:` and the first 12 hex digits of the hash. The analysis makes no network calls.

## Reproducibility

Two runs on the same image give a byte-identical `report.json` except for the `run` object. Anything that changes between runs (creation time, durations, full custody entries, case directory) lives under `run`. IDs are derived from content, not from random values. The end-to-end tests check this by running each fixture twice ([validation](validation.md)).

## Standards and guidance

aitrace was designed with these in mind. It doesn't claim certification against any of them.

- ISO/IEC 27037: identification, collection, acquisition and preservation of digital evidence. Matches the read-only handling, hashing and documentation steps.
- ISO/IEC 27042: analysis and interpretation of digital evidence. Matches the stated rules, the confidence bands and the explicit limitations ([attribution](attribution.md)).
- NIST SP 800-86: guide to integrating forensic techniques into incident response. Matches the collect, examine, analyze and report flow.
- ACPO Good Practice Guide principles: do not change original data (principle 1), keep a record of every process applied (principle 3), and let a third party repeat the work and reach the same result. These map to read-only access, the custody log and the determinism rule above.

## What the tool does not do

No decryption, no password cracking, no memory forensics, no machine-learning text detector. Where a source can't be read, the report says so in its coverage section.
