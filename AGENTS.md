# aitrace 작업 안내 (사람·AI 에이전트 공통)

이 저장소를 받은 사람이나 AI 에이전트는 아래 순서만 따르면 분석이 끝납니다.

## Windows에서 분석하기

1. 저장소 맨 위의 `run-windows.bat`을 실행합니다(더블클릭 또는 명령창에서 실행).
2. 증거 이미지(E01) 또는 폴더 경로, 사건명, 사건번호, 분석관 성명, 기관을 물으면 입력합니다.
3. 끝나면 결과 폴더(기본 `%USERPROFILE%\aitrace-cases\<이미지이름>-<시각>\report`)가 열립니다.

질문 없이 한 번에 실행하려면:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\windows\run.ps1 `
  -Evidence D:\증거\case.E01 -CaseName "사건명" -CaseNumber 2026-0042 `
  -Examiner "성명" -Org "기관" -NoPrompt
```

스크립트는 uv가 없으면 설치하고(`uv sync --frozen`), `aitrace analyze`를 실행한 뒤 `brief.pdf`, `report.pdf`, `questions.html`이 생겼는지 확인합니다. 처음 한 번은 인터넷이 필요합니다.

## macOS·Linux에서 분석하기

```
uv sync --frozen
uv run aitrace analyze <이미지 또는 폴더> --case-dir <새 결과 폴더> --case-name "사건명" --examiner "성명" --org "기관"
```

## 분석관·기관을 나중에 넣기

분석을 다시 하지 않고 보고서만 새로 만듭니다. 바꾼 값은 `custody.jsonl`에 기록됩니다.

```
uv run aitrace report --case-dir <결과 폴더> --examiner "성명" --org "기관"
```

## 결과 파일

| 파일 | 내용 |
|---|---|
| `report/brief.pdf`, `brief.docx` | 감사·법무 검토용 요약서 |
| `report/report.pdf`, `report.docx`, `report.html` | 감정서 |
| `report/questions.html`, `csv/questions.csv` | 사람이 직접 입력한 목록 |
| `report/prompts.html`, `prompts/part-*.html` | 대화 전문(목차와 분할 파일) |
| `report/csv/*.csv` | 엑셀용 표 |
| `custody.jsonl` | 증거 취급 기록(해시 체인) |
| `logs/aitrace.log` | 실행 로그. 오류가 나면 이 파일을 전달 |

## 지켜야 할 것

- 증거 원본에는 쓰지 않습니다. aitrace는 읽기만 하고 분석 전후 해시를 비교합니다.
- 결과 폴더(보고서, csv, case.sqlite)는 개인정보를 담고 있으므로 이 저장소나 다른 공개 저장소에 커밋하지 않습니다.
- 결과 폴더는 매번 새로 지정합니다. 이미 있는 폴더는 `--force` 없이는 거부됩니다.
- 코드를 고친 뒤에는 `uv run ruff check .`과 `uv run pytest -m "not realdata"`가 통과해야 합니다.
