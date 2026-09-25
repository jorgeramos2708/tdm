@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\VERIFY-TDM-READINESS.ps1"
exit /b %errorlevel%
