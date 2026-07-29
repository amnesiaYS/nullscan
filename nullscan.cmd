@echo off
REM nullscan launcher for Windows.
REM Bypasses PowerShell execution policy so the script can run without
REM requiring the user to run Set-ExecutionPolicy first.

powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0nullscan.ps1" %*