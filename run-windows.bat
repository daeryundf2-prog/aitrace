@echo off
rem aitrace: double-click to install and analyze an evidence image on Windows.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\windows\run.ps1" %*
pause
