@echo off
setlocal EnableExtensions
cd /d "%~dp0"

where dotnet >nul 2>&1
if errorlevel 1 (
  echo ERROR: No se encontro dotnet SDK 8 en PATH.
  exit /b 1
)

echo Cerrando procesos TDM que bloquean archivos de compilacion...
taskkill /IM TDM.Application.exe /T /F >nul 2>&1
taskkill /IM TDM.Notifier.exe /T /F >nul 2>&1
taskkill /IM TDM.Notifier.Avalonia.exe /T /F >nul 2>&1
tasklist /FI "IMAGENAME eq TDM.Application.exe" 2>nul | find /I "TDM.Application.exe" >nul
if not errorlevel 1 (
  echo ERROR: No se pudo cerrar TDM.Application.exe. Cierre TDM o ejecute este script como administrador.
  exit /b 1
)
tasklist /FI "IMAGENAME eq TDM.Notifier.exe" 2>nul | find /I "TDM.Notifier.exe" >nul
if not errorlevel 1 (
  echo ERROR: No se pudo cerrar TDM.Notifier.exe. Ejecute este script como administrador.
  exit /b 1
)

echo [0/3] Limpiando binarios anteriores...
dotnet clean ".\TDM.sln" -c Release -v:minimal
if errorlevel 1 exit /b 1

set "OUT=%CD%\dist\TDM-win-x64"
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%" || exit /b 1

echo [1/3] Restaurando y publicando interfaz TDM...
dotnet restore ".\src\TDM.Gui.Avalonia\TDM.Gui.Avalonia.csproj" -r win-x64 --force-evaluate -p:RestorePackagesWithLockFile=true -p:RestoreLockedMode=false -p:SelfContained=true -p:PublishSingleFile=true -p:PublishReadyToRun=true -p:PublishReadyToRunComposite=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false
if errorlevel 1 exit /b 1
dotnet publish ".\src\TDM.Gui.Avalonia\TDM.Gui.Avalonia.csproj" -c Release -r win-x64 --self-contained true --no-restore -p:PublishSingleFile=true -p:PublishReadyToRun=true -p:PublishReadyToRunComposite=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false -o "%OUT%\App"
if errorlevel 1 exit /b 1
if not exist "%OUT%\App\TDM.Application.exe" (
  echo ERROR: No se genero TDM.Application.exe.
  exit /b 1
)

echo [2/3] Restaurando y publicando servicio TDM...
dotnet restore ".\src\TDM.Service\TDM.Service.csproj" -r win-x64 --force-evaluate -p:SelfContained=true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false
if errorlevel 1 exit /b 1
dotnet publish ".\src\TDM.Service\TDM.Service.csproj" -c Release -r win-x64 --self-contained true --no-restore -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false -o "%OUT%\Service"
if errorlevel 1 exit /b 1
if not exist "%OUT%\Service\TDM.Service.exe" (
  echo ERROR: No se genero TDM.Service.exe.
  exit /b 1
)

echo [3/3] Restaurando y publicando notificador TDM...
dotnet restore ".\src\TDM.Notifier.Avalonia\TDM.Notifier.Avalonia.csproj" -r win-x64 --force-evaluate -p:SelfContained=true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false
if errorlevel 1 exit /b 1
dotnet publish ".\src\TDM.Notifier.Avalonia\TDM.Notifier.Avalonia.csproj" -c Release -r win-x64 --self-contained true --no-restore -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false -o "%OUT%\Notifier"
if errorlevel 1 exit /b 1
if not exist "%OUT%\Notifier\TDM.Notifier.exe" (
  echo ERROR: No se genero TDM.Notifier.exe.
  exit /b 1
)

 echo.
echo Publicacion completada en:
echo %OUT%
exit /b 0
