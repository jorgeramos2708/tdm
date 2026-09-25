@echo off
setlocal EnableExtensions
cd /d "%~dp0"

where dotnet.exe >nul 2>&1
if errorlevel 1 (
  echo ERROR: No se encontro dotnet SDK 8 en PATH.
  exit /b 1
)

echo Cerrando una instancia portable anterior...
taskkill /IM TDM.exe /T /F >nul 2>&1
tasklist /FI "IMAGENAME eq TDM.exe" 2>nul | find /I "TDM.exe" >nul
if not errorlevel 1 (
  echo ERROR: No se pudo cerrar TDM.exe.
  exit /b 1
)

set "PROJECT=%CD%\src\TDM.Gui.Avalonia\TDM.Gui.Avalonia.csproj"
set "OUT=%CD%\dist\TDM-portable-win-x64"

if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%" || exit /b 1

echo [1/2] Restaurando TDM Portable win-x64...
dotnet restore "%PROJECT%" -r win-x64 --force-evaluate -p:RestorePackagesWithLockFile=true -p:RestoreLockedMode=false -p:TdmPortable=true -p:SelfContained=true -p:PublishSingleFile=true -p:PublishReadyToRun=true -p:PublishReadyToRunComposite=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false
if errorlevel 1 exit /b 1

echo [2/2] Generando ejecutable portable optimizado...
dotnet publish "%PROJECT%" -c Release -r win-x64 --self-contained true --no-restore -p:TdmPortable=true -p:PublishSingleFile=true -p:PublishReadyToRun=true -p:PublishReadyToRunComposite=true -p:PublishTrimmed=false -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=false -p:DebugType=None -p:DebugSymbols=false -o "%OUT%"
if errorlevel 1 exit /b 1

if not exist "%OUT%\TDM.exe" (
  echo ERROR: No se genero TDM.exe.
  exit /b 1
)

for %%F in ("%OUT%\TDM.exe") do if %%~zF LEQ 0 (
  echo ERROR: TDM.exe esta vacio.
  exit /b 1
)

echo.
echo ============================================================
echo [OK] EJECUTABLE PORTABLE CREADO
echo %OUT%\TDM.exe
for %%F in ("%OUT%\TDM.exe") do echo Tamano: %%~zF bytes
echo ============================================================
exit /b 0
