@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================================
echo TDM FIX93 - Gate de validacion Windows
echo ============================================================
call ".\VERIFY-TDM-READINESS.cmd"
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo [PASS] Gate FIX93 completado correctamente.
) else (
  echo [FAIL] Gate FIX93 devolvio codigo %RC%.
)
echo.
pause
exit /b %RC%
