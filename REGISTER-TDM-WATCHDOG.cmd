@echo off
rem Watchdog externo de TDM.Service (requiere permisos de administrador).
rem Uso: REGISTER-TDM-WATCHDOG.cmd [-Unregister]
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Register-TdmWatchdog.ps1" %*
