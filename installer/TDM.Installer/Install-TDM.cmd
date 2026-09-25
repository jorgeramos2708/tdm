@echo off
setlocal EnableExtensions
set "TARGET=%ProgramFiles%\TDM"
set "PAYLOAD=%TEMP%\TDM-Payload-%RANDOM%-%RANDOM%"

echo Preparando instalacion de TDM...
if exist "%PAYLOAD%" rmdir /s /q "%PAYLOAD%"
mkdir "%PAYLOAD%" || goto :fail

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%~dp0payload.zip' -DestinationPath '%PAYLOAD%' -Force"
if errorlevel 1 goto :fail

if not exist "%PAYLOAD%\App\TDM.Application.exe" goto :missing_payload
if not exist "%PAYLOAD%\Service\TDM.Service.exe" goto :missing_payload
if not exist "%PAYLOAD%\Notifier\TDM.Notifier.exe" goto :missing_payload

echo Cerrando componentes TDM anteriores...
taskkill /IM TDM.Application.exe /T /F >nul 2>&1
taskkill /IM TDM.Notifier.exe /T /F >nul 2>&1
taskkill /IM TDM.Notifier.Avalonia.exe /T /F >nul 2>&1

echo Deteniendo servicio TDM...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$s=Get-Service -Name 'TDM.Service' -ErrorAction SilentlyContinue; if ($null -ne $s -and $s.Status -ne 'Stopped') { Stop-Service -Name 'TDM.Service' -Force -ErrorAction Stop; $s.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(30)) }"
if errorlevel 1 goto :fail

echo Copiando componentes...
if not exist "%TARGET%" mkdir "%TARGET%" || goto :fail

robocopy "%PAYLOAD%\App" "%TARGET%\App" /MIR /R:2 /W:1 /NFL /NDL /NJH /NJS /NP
if errorlevel 8 goto :fail
robocopy "%PAYLOAD%\Service" "%TARGET%\Service" /MIR /R:2 /W:1 /NFL /NDL /NJH /NJS /NP
if errorlevel 8 goto :fail
robocopy "%PAYLOAD%\Notifier" "%TARGET%\Notifier" /MIR /R:2 /W:1 /NFL /NDL /NJH /NJS /NP
if errorlevel 8 goto :fail

echo Configurando servicio TDM...
sc.exe query TDM.Service >nul 2>&1
if errorlevel 1 (
  sc.exe create TDM.Service binPath= "\"%TARGET%\Service\TDM.Service.exe\"" start= auto DisplayName= "TSplus Diagnostic Monitor" >nul
) else (
  sc.exe config TDM.Service binPath= "\"%TARGET%\Service\TDM.Service.exe\"" start= auto DisplayName= "TSplus Diagnostic Monitor" >nul
)
if errorlevel 1 goto :fail

sc.exe description TDM.Service "Monitoreo y diagnostico operativo de TSplus" >nul
sc.exe start TDM.Service >nul
if errorlevel 1 goto :fail

echo Creando acceso directo...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('Desktop')+'\TDM.lnk');$s.TargetPath='%TARGET%\App\TDM.Application.exe';$s.WorkingDirectory='%TARGET%\App';$s.IconLocation='%TARGET%\App\TDM.Application.exe,0';$s.Save()"
if errorlevel 1 goto :fail

if exist "%PAYLOAD%" rmdir /s /q "%PAYLOAD%"
start "" "%TARGET%\Notifier\TDM.Notifier.exe"
start "" "%TARGET%\App\TDM.Application.exe"
echo Instalacion completada correctamente.
exit /b 0

:missing_payload
echo ERROR: El paquete no contiene App, Service y Notifier completos.

:fail
if exist "%PAYLOAD%" rmdir /s /q "%PAYLOAD%"
echo ERROR: La instalacion de TDM no pudo completarse.
exit /b 1
