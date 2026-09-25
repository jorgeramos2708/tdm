@echo off
setlocal EnableExtensions
cd /d "%~dp0"

call ".\PUBLISH-DISTRIBUCION-WIN-X64.cmd"
if errorlevel 1 exit /b 1

where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo ERROR: Windows PowerShell no esta disponible.
  exit /b 1
)

where dotnet.exe >nul 2>&1
if errorlevel 1 (
  echo ERROR: No se encontro dotnet SDK 8 en PATH.
  exit /b 1
)

set "DIST=%CD%\dist"
set "PUB=%DIST%\TDM-win-x64"
set "PKG=%DIST%\installer-work"
set "PROJECT=%CD%\installer\TDM.Installer\TDM.Installer.csproj"
set "BUILT=%PKG%\publish\TDM-Setup-x64.exe"
set "OUT=%DIST%\TDM-Setup-x64.exe"

if exist "%OUT%" del /f /q "%OUT%"
if exist "%DIST%\TDM-Setup-x64.sed" del /f /q "%DIST%\TDM-Setup-x64.sed"
if exist "%PKG%" rmdir /s /q "%PKG%"
mkdir "%PKG%" || exit /b 1

echo [4/6] Comprimiendo App, Service y Notifier...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -LiteralPath @('%PUB%\App','%PUB%\Service','%PUB%\Notifier') -DestinationPath '%PKG%\payload.zip' -CompressionLevel Optimal -Force"
if errorlevel 1 exit /b 1
if not exist "%PKG%\payload.zip" (
  echo ERROR: No se genero payload.zip.
  exit /b 1
)

echo [5/6] Restaurando generador del instalador...
dotnet restore "%PROJECT%" -r win-x64 --force-evaluate
if errorlevel 1 exit /b 1

echo [6/6] Generando TDM-Setup-x64.exe sin IExpress...
dotnet publish "%PROJECT%" -c Release -r win-x64 --self-contained true --no-restore -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=None -p:DebugSymbols=false -o "%PKG%\publish"
if errorlevel 1 exit /b 1

if not exist "%BUILT%" (
  echo ERROR: dotnet publish no genero el instalador.
  exit /b 1
)

copy /y "%BUILT%" "%OUT%" >nul
if errorlevel 1 exit /b 1
if not exist "%OUT%" (
  echo ERROR: No se pudo copiar TDM-Setup-x64.exe a dist.
  exit /b 1
)

for %%F in ("%OUT%") do if %%~zF LEQ 0 (
  echo ERROR: TDM-Setup-x64.exe esta vacio.
  exit /b 1
)

echo.
echo ============================================================
echo [OK] INSTALADOR CREADO CORRECTAMENTE
echo %OUT%
for %%F in ("%OUT%") do echo Tamano: %%~zF bytes
echo ============================================================
exit /b 0
