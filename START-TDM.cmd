@echo off
cd /d "%~dp0"
if not exist "src\TDM.Gui.Avalonia\bin\Release\net8.0-windows\TDM.Application.exe" (
  echo ERROR: TDM no esta compilado. Ejecute BUILD-TDM.cmd o VERIFY-TDM-READINESS.cmd.
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='src\TDM.Notifier.Avalonia\bin\Release\net8.0-windows\TDM.Notifier.dll'; if(-not (Test-Path -LiteralPath $p)){exit 74}; $b=[IO.File]::ReadAllBytes($p); $u8=[Text.Encoding]::UTF8.GetString($b); $u16=[Text.Encoding]::Unicode.GetString($b); if(-not ($u8.Contains('FIX93_EXPLICIT_ALERTS_NO_RECOVERED') -or $u16.Contains('FIX93_EXPLICIT_ALERTS_NO_RECOVERED'))){exit 74}"
if errorlevel 1 (
  echo ERROR: El Notifier compilado es anterior a FIX74. Ejecute BUILD-TDM.cmd.
  exit /b 1
)
if exist "src\TDM.Notifier.Avalonia\bin\Release\net8.0-windows\TDM.Notifier.exe" (
  rem Replace every notifier loaded from an earlier delivery.
  taskkill /IM TDM.Notifier.exe /T /F >nul 2>nul
  taskkill /IM TDM.Notifier.Avalonia.exe /T /F >nul 2>nul
  start "" "src\TDM.Notifier.Avalonia\bin\Release\net8.0-windows\TDM.Notifier.exe"
)
start "" "src\TDM.Gui.Avalonia\bin\Release\net8.0-windows\TDM.Application.exe"
exit /b 0
