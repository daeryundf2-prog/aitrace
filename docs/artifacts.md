# Artifacts

The plugin list below is the registry order. Each plugin reads its own paths and emits typed artifacts and events. Where a plugin can't decode a store, it records the store as present with a status of `encrypted_not_decoded` or `unsupported`.

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

## Artifact kinds

Artifacts use these kinds. The exact data keys for each are fixed in the code and checked by tests.

- AI: `AI_CHAT_MESSAGE`, `AI_TOOL_CALL`, `AI_APP_PRESENCE`, `AI_CREDENTIAL`, `AI_MODEL`.
- Browser and shell: `BROWSER_VISIT`, `BROWSER_DOWNLOAD`, `SHELL_COMMAND`, `DOWNLOAD_ORIGIN`.
- Files: `FILE_RECORD`, `FILE_JOURNAL`, `RECYCLED_FILE`, `SHORTCUT`.
- Execution: `EXECUTION`, `NETWORK_USAGE`, `PERMISSION_GRANT`.
- Channels: `REMOTE_SESSION`, `FILE_TRANSFER`, `USB_DEVICE`, `CLOUD_SYNC`.
- Provenance: `MEDIA_PROVENANCE`, `DOC_METADATA`, `VCS_COMMIT`.
- Problems: `PARSE_WARNING`.

## Sources

These public references guided which artifacts to look for:

- IRFlow AI artifacts documentation: <https://r3nzsec.github.io/irflow-timeline/dfir-tips/ai-query-history>
- DFIRHub, AI coding agents artifact: <https://dfirhub.com/artifact/aicodingagents>
- arXiv 2505.23938: <https://arxiv.org/abs/2505.23938>
- pvieito, ChatGPT for Mac stored conversations without encryption (and the later encrypted store): <https://pvieito.com/2024/07/chatgpt-unprotected-conversations>

AI apps change where and how they store data, so check a result against the version of the app on the image. Newer versions of the ChatGPT Mac app encrypt conversations. aitrace reports that store as present but not decoded.
