# aitrace

aitrace는 디스크 이미지를 읽고 컴퓨터의 AI 사용에 대해 감정인이 받는 질문에 답합니다. 어떤 AI 도구를 썼는지, 무엇을 물었는지, 어떤 파일이 생기고 바뀌고 사라졌는지, 데이터가 어디로 나갔는지, 그리고 파일을 사람이 썼는지 AI가 썼는지를 다룹니다. Windows, macOS, Linux 이미지를 마운트하지 않고 읽으며 증거에는 아무것도 쓰지 않습니다.

English version: [README.md](README.md)

## Windows에서 바로 실행

1. 저장소를 받습니다: `git clone https://github.com/daeryundf2-prog/aitrace.git` (또는 Code → Download ZIP 후 압축 해제)
2. 받은 폴더의 `run-windows.bat`을 더블클릭합니다.
3. 증거 이미지(E01) 또는 폴더 경로, 사건명, 사건번호, 분석관 성명, 기관을 입력합니다.
4. 끝나면 결과 폴더의 `report`가 열립니다(`brief.pdf` 요약서, `report.pdf` 감정서, `questions.html` 사람 입력 목록).

uv가 없으면 스크립트가 설치합니다. 처음 한 번은 인터넷이 필요합니다. 자세한 옵션과 주의 사항은 [AGENTS.md](AGENTS.md)에 있습니다.

## 목적

- AI 데스크톱 앱, AI 웹사이트, IDE 어시스턴트, CLI 에이전트, 로컬 모델, API 키를 목록화합니다.
- 프롬프트와 응답을 도구, 세션, 역할, UTC 및 현지 시각, 원본 경로와 함께 추출합니다.
- 파일 생성, 수정, 삭제, 이름 변경 이벤트를 복원하고, 증거가 뒷받침하면 AI 세션과 연결합니다.
- 반출 경로를 찾습니다: 브라우저 다운로드, 클라우드 동기화, USB, RDP, AnyDesk, TeamViewer, ssh, scp, rsync, rclone, curl.
- 관련 파일마다 `ai_generated`, `ai_assisted`, `human_authored`, `undetermined` 중 하나로 판정합니다. 근거는 명시된 규칙이며 텍스트 "AI 탐지기"는 쓰지 않습니다.
- 통합 타임라인과 HTML, PDF, DOCX, JSON, CSV 보고서, 그리고 해시가 기록된 인용 파일 사본을 만듭니다.

## 설치

Python 3.12 또는 3.13과 [uv](https://docs.astral.sh/uv/)가 필요합니다. 관리자 권한, FUSE, 시스템 패키지는 필요 없습니다.

```
uv sync
uv run aitrace version
```

## 사용법

```
uv run aitrace analyze evidence/case.E01 --case-dir out/case1 \
    --case-number 2026-0042 --examiner "김감정" --org "연구소" --lang ko --formats html,pdf,docx,json,csv

uv run aitrace verify evidence/case.E01
uv run aitrace report --case-dir out/case1 --lang ko
uv run aitrace plugins
```

보고서는 기본적으로 한국어입니다. 영어는 `--lang en`, 현지 시각 열은 `--tz`(기본 `Asia/Seoul`)로 바꿉니다. 시각은 UTC로 저장됩니다.

종료 코드: 0 성공, 2 사용법 오류, 3 무결성 불일치(보고서는 작성되며 그 사실이 적힙니다), 4 케이스 디렉터리 거부, 5 증거를 읽을 수 없거나 미지원, 6 보관 연속성(custody) 체인 손상.

## 출력 구조

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

`report.json`과 매니페스트의 경로는 케이스 디렉터리 기준 상대 경로입니다. 섹션별 설명은 [docs/artifacts.md](docs/artifacts.md)와 [docs/methodology.md](docs/methodology.md)에 있습니다.

## 지원 아티팩트

플러그인은 아래 순서로 실행됩니다. 각각 독립 모듈이며 하나가 실패해도 전체 분석은 멈추지 않습니다.

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

자세한 설명과 출처: [docs/artifacts.md](docs/artifacts.md).

## 한계

- 암호화된 저장소(키 없는 BitLocker/FileVault, 암호화된 ChatGPT Mac 저장소)는 "존재함, 해독 안 됨"으로만 기록합니다.
- AI 흔적이 없다고 해서 사람이 썼다는 뜻은 아닙니다. 이 경우 판정은 `undetermined`입니다.
- AI 앱은 저장 형식을 자주 바꿉니다. 모르는 형식은 추측하지 않고 범위 항목과 파싱 경고로 남깁니다.
- NTFS 테스트 이미지에는 USN 저널이 없어서 USN 파싱은 실제 샘플 파일로 검증합니다.
- 그래픽 앱은 없습니다. HTML 보고서가 열람 화면입니다.

사람/AI 판정 규칙과 한계는 [docs/attribution.md](docs/attribution.md)를 보세요.

## 법적 고지

aitrace는 감정인을 돕는 도구이며 감정인의 판단을 대신하지 않고 법률 자문도 제공하지 않습니다. 이미지를 분석할 적법한 권한이 있는지 확인하고, 각 관할의 증거 취급 규정을 따르세요. 보고서에는 무엇을 어떤 파일에서 찾았는지, 도구가 무엇을 읽지 못했는지가 적힙니다.

## 문서

- [분석 방법론](docs/methodology.md)
- [판정 기준](docs/attribution.md)
- [아티팩트](docs/artifacts.md)
- [플러그인 추가](docs/adding-a-plugin.md)
- [검증](docs/validation.md)
- [변경 이력](CHANGELOG.md)

## 라이선스

AGPL-3.0-or-later, `LICENSE` 참고. 서드파티 고지는 `NOTICE`에 있습니다.
