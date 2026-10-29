# aitrace

aitrace reads a disk image and answers the questions an examiner gets asked about AI use on a computer: which AI tools ran, what was asked, which files appeared, changed or vanished, where data may have gone, and whether a person or an AI wrote a given file. It reads Windows, macOS and Linux images without mounting them and without writing to the evidence.

Korean version: [README.ko.md](README.ko.md)

## Quick start on Windows

Clone or download the repository, double-click `run-windows.bat`, and answer the prompts (evidence path, case name, case number, examiner, organisation). The script installs uv if needed, runs the analysis and opens the `report` folder. Details: [AGENTS.md](AGENTS.md).

## Purpose

- Inventory AI desktop apps, AI websites, IDE assistants, CLI agents, local models and API keys.
- Extract prompts and responses with tool, session, role, UTC and local time, and source path.
- Rebuild file create, modify, delete and rename events and link them to AI sessions when the evidence supports it.
- Find transfer channels: browser downloads, cloud sync, USB, RDP, AnyDesk, TeamViewer, ssh, scp, rsync, rclone, curl.
- Label each relevant file as `ai_generated`, `ai_assisted`, `human_authored` or `undetermined` using stated rules, never a text "AI detector".
- Write one timeline and a report in HTML, PDF, DOCX, JSON and CSV, plus a hashed copy of the cited files.

## Install

You need Python 3.12 or 3.13 and [uv](https://docs.astral.sh/uv/). No admin rights, FUSE or system packages.

```
uv sync
uv run aitrace version
```

## Usage

```
uv run aitrace analyze evidence/case.E01 --case-dir out/case1 \
    --case-number 2026-0042 --examiner "Kim" --org "Lab" --lang ko --formats html,pdf,docx,json,csv

uv run aitrace verify evidence/case.E01
uv run aitrace report --case-dir out/case1 --lang en
uv run aitrace plugins
```

The report is Korean by default. Use `--lang en` for English and `--tz` to change the local time column (default `Asia/Seoul`). Times are stored in UTC.

Exit codes: 0 success, 2 usage error, 3 integrity mismatch (the report is still written and says so), 4 refused case directory, 5 evidence unreadable or unsupported, 6 custody chain broken.

## Output layout

```
case/
  case.sqlite
  custody.jsonl
  logs/aitrace.log
  report/report.html
  report/report.pdf
  report/report.docx
  report/report.json
  report/csv/{timeline,ai_queries,findings,attributions,file_lifecycle,exfil}.csv
  export/files/...
  export/manifest.csv
  export/manifest.json
```

Paths inside `report.json` and the manifests are relative to the case directory. Details of each section are in [docs/artifacts.md](docs/artifacts.md) and [docs/methodology.md](docs/methodology.md).

## Supported artifacts

Plugins run in this order. Each one is an independent module, and a failure in one never stops the run.

| # | Module | Name | What it reads |
| --- | --- | --- | --- |
| 1 | `aitrace.plugins.ai.claude_code` | `claude_code` | Claude Code session transcripts, prompt history, config and settings |
| 2 | `aitrace.plugins.ai.cli_agents` | `cli_agents` | Session and prompt logs of CLI coding agents: Codex, Gemini CLI, Aider, Copilot CLI, Continue |
| 3 | `aitrace.plugins.ai.desktop_apps` | `desktop_apps` | ChatGPT, Claude, Copilot and Perplexity desktop apps: presence, chats, logs, MCP config |
| 4 | `aitrace.plugins.ai.ide_assistants` | `ide_assistants` | Cursor, VS Code Copilot Chat, Windsurf and VSCodium chat state and Cursor agent transcripts |
| 5 | `aitrace.plugins.ai.local_llm` | `local_llm` | Ollama, LM Studio, Jan and GPT4All: prompt history, server logs, models, conversations |
| 6 | `aitrace.plugins.ai.sdk_keys` | `sdk_keys` | AI provider API keys in config/env/shell files (redacted), CLI credential stores, installed AI SDKs |
| 7 | `aitrace.plugins.browser.history_downloads` | `history_downloads` | Chromium-family, Firefox and Safari history and downloads, plus the Chromium last file-dialog directory |
| 8 | `aitrace.plugins.shell.history` | `history` | Shell command history (bash, zsh, fish, PowerShell) with transfer/remote/AI-CLI tagging |
| 9 | `aitrace.plugins.windows.mft` | `mft` | NTFS $MFT file records, including deleted (not in use) records |
| 10 | `aitrace.plugins.windows.usn` | `usn` | NTFS USN change journal ($Extend/$UsnJrnl:$J): file create, delete, rename, modify records |
| 11 | `aitrace.plugins.windows.recycle_lnk_jumplist` | `recycle_lnk_jumplist` | Recycle Bin $I records, LNK shortcuts and JumpLists |
| 12 | `aitrace.plugins.windows.execution` | `execution` | Prefetch, Amcache and SRUM program-execution evidence |
| 13 | `aitrace.plugins.windows.evtx_rdp_usb` | `evtx_rdp_usb` | Windows event logs (RDP, PowerShell, USB) and setupapi device-install blocks |
| 14 | `aitrace.plugins.macos.activity` | `activity` | macOS quarantine downloads, knowledgeC app usage, TCC grants and FSEvents journals |
| 15 | `aitrace.plugins.unix.remote_auth` | `remote_auth` | SSH and remote logins from auth logs and wtmp, SSH client hosts, rclone remotes; journald detected |
| 16 | `aitrace.plugins.remote.remote_tools` | `remote_tools` | AnyDesk file transfers, TeamViewer incoming connections and saved RDP connection files |
| 17 | `aitrace.plugins.remote.cloud_sync` | `cloud_sync` | Cloud sync clients: OneDrive, Google Drive DriveFS items, Dropbox accounts and iCloud Drive |
| 18 | `aitrace.plugins.provenance.images` | `images` | AI generation signals in image files: PNG/JPEG text, C2PA, XMP, EXIF and file names |
| 19 | `aitrace.plugins.provenance.docs_git` | `docs_git` | Office/PDF document metadata, git commit history, and repo-level AI config presence |
| 20 | `aitrace.plugins.fsmeta.file_inventory` | `file_inventory` | Per-user file inventory (depth 8) with timestamps, content hashes and text samples |

More detail and sources: [docs/artifacts.md](docs/artifacts.md).

## Limitations

- Encrypted stores (BitLocker or FileVault without a key, the encrypted ChatGPT Mac store) are listed as present but not decoded.
- No trace of AI use does not prove a person wrote a file. Absence gives `undetermined`.
- AI apps change storage formats often. Unknown formats become coverage notes and parse warnings, not guesses.
- The NTFS fixture has no USN journal, so USN parsing is proven on a real sample file instead.
- There is no graphical app. The HTML report is the viewing surface.

See [docs/attribution.md](docs/attribution.md) for the human versus AI rules and their limits.

## Legal note

aitrace is a tool that supports an examiner. It doesn't replace the examiner's judgment, and it gives no legal advice. Make sure you have lawful authority to examine an image, and follow your own jurisdiction's rules on evidence handling. The report states what was found, from which file, and what the tool could not read.

## Docs

- [Methodology](docs/methodology.md)
- [Attribution](docs/attribution.md)
- [Artifacts](docs/artifacts.md)
- [Adding a plugin](docs/adding-a-plugin.md)
- [Validation](docs/validation.md)
- [Changelog](CHANGELOG.md)

## License

AGPL-3.0-or-later, see `LICENSE`. Third-party notices are in `NOTICE`.
