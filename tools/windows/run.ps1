# aitrace Windows 실행 스크립트: uv 설치(없을 때) -> 의존성 설치 -> 분석 -> 보고서 폴더 열기.
# 사용: 저장소 맨 위의 run-windows.bat 을 더블클릭하거나
#   powershell -ExecutionPolicy Bypass -File tools\windows\run.ps1 -Evidence D:\증거\case.E01 -Examiner 홍길동 -Org 감사팀
param(
    [string]$Evidence = "",
    [string]$CaseDir = "",
    [string]$CaseName = "",
    [string]$CaseNumber = "",
    [string]$Examiner = "",
    [string]$Org = "",
    [string]$Lang = "ko",
    [switch]$NoPrompt,
    [switch]$NoOpen
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$env:PYTHONUTF8 = "1"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "[1/4] uv 가 없어 설치합니다 (인터넷 필요)."
    Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
}

Write-Host "[2/4] 필요한 패키지를 설치합니다."
uv sync --frozen
if ($LASTEXITCODE -ne 0) { throw "uv sync 실패 (종료 코드 $LASTEXITCODE)" }

if (-not $Evidence) { $Evidence = Read-Host "증거 이미지(E01) 또는 폴더 경로" }
$Evidence = $Evidence.Trim().Trim('"')
if (-not (Test-Path -LiteralPath $Evidence)) { throw "증거를 찾을 수 없습니다: $Evidence" }
$Evidence = (Resolve-Path -LiteralPath $Evidence).Path

if (-not $NoPrompt) {
    if (-not $CaseName) { $CaseName = Read-Host "사건명 (없으면 Enter)" }
    if (-not $CaseNumber) { $CaseNumber = Read-Host "사건번호 (없으면 Enter)" }
    if (-not $Examiner) { $Examiner = Read-Host "분석관 성명 (없으면 Enter)" }
    if (-not $Org) { $Org = Read-Host "기관 (없으면 Enter)" }
}

if (-not $CaseDir) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($Evidence.TrimEnd('\'))
    $CaseDir = Join-Path $HOME ("aitrace-cases\" + $stem + "-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}

Write-Host "[3/4] 분석합니다: $Evidence -> $CaseDir"
$cmd = @("run", "aitrace", "analyze", $Evidence, "--case-dir", $CaseDir, "--lang", $Lang)
if ($CaseName) { $cmd += @("--case-name", $CaseName) }
if ($CaseNumber) { $cmd += @("--case-number", $CaseNumber) }
if ($Examiner) { $cmd += @("--examiner", $Examiner) }
if ($Org) { $cmd += @("--org", $Org) }
uv @cmd
$code = $LASTEXITCODE
if ($code -eq 3) {
    Write-Warning "증거 해시가 기록된 값과 다릅니다. 보고서는 작성되었고 그 사실이 보고서에 적혀 있습니다."
} elseif ($code -ne 0) {
    throw "분석 실패 (종료 코드 $code). 로그: $CaseDir\logs\aitrace.log"
}

$report = Join-Path $CaseDir "report"
foreach ($name in @("brief.pdf", "report.pdf", "questions.html")) {
    if (-not (Test-Path -LiteralPath (Join-Path $report $name))) { throw "보고서 파일이 없습니다: $report\$name" }
}
Write-Host "[4/4] 완료. 결과 폴더: $report"
Write-Host "  brief.pdf      검토용 요약서 (감사·법무)"
Write-Host "  report.pdf     감정서"
Write-Host "  questions.html 사람이 직접 입력한 목록"
Write-Host "분석관·기관을 나중에 바꾸려면: uv run aitrace report --case-dir `"$CaseDir`" --examiner 성명 --org 기관"
if (-not $NoOpen) { Invoke-Item $report }
