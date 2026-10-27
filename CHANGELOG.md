# Changelog

All notable changes to aitrace are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - Unreleased

### Added

- Read-only image intake for E01, raw and directory evidence, with MD5, SHA-1 and SHA-256 hashing and a re-check before the report is written.
- Hash-chained custody log (`custody.jsonl`) and the `aitrace report` command that verifies it before re-rendering.
- 20 artifact plugins (see [docs/artifacts.md](docs/artifacts.md)) for AI tools, browsers, shells, NTFS, macOS activity, remote access, cloud sync, provenance and file inventory.
- Rule-based human versus AI attribution ([docs/attribution.md](docs/attribution.md)).
- Super-timeline, HTML, PDF, DOCX, JSON and CSV reports, Korean by default, English with `--lang en`.
- Evidence export with `manifest.csv` and `manifest.json`.
- Synthetic Windows, macOS and Linux E01 fixtures and end-to-end tests ([docs/validation.md](docs/validation.md)).
- Documentation in English and Korean, and `tools/check_links.py` to check relative Markdown links.
