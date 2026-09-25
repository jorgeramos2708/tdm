@echo off
REM Genera SBOM (Software Bill of Materials) para TDM
REM Requiere: syft (https://github.com/anchore/syft) en PATH

chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo TDM SBOM Generator
echo ============================================================

REM Verificar syft
where syft >nul 2>&1
if errorlevel 1 (
    echo [ERROR] syft no encontrado en PATH.
    echo Descargar desde: https://github.com/anchore/syft/releases
    exit /b 1
)

echo [1/4] Restaurando dependencias (locked mode)...
dotnet restore TDM.sln --locked-mode
if errorlevel 1 exit /b 1

echo [2/4] Compilando Release...
dotnet build TDM.sln -c Release --no-restore -warnaserror
if errorlevel 1 exit /b 1

echo [3/4] Generando SBOM (SPDX JSON)...
syft packages dir:. -o spdx-json=sbom.spdx.json
if errorlevel 1 exit /b 1

echo [4/4] Generando SBOM (CycloneDX JSON)...
syft packages dir:. -o cyclonedx-json=sbom.cyclonedx.json
if errorlevel 1 exit /b 1

echo.
echo ============================================================
echo [OK] SBOM generado correctamente
echo    sbom.spdx.json
echo    sbom.cyclonedx.json
echo ============================================================

REM Verificar vulnerabilidades
echo.
echo [INFO] Verificando vulnerabilidades...
dotnet list TDM.sln package --vulnerable --include-transitive

echo.
echo [INFO] Verificando paquetes desactualizados...
dotnet list TDM.sln package --outdated --include-transitive

echo.
echo ============================================================
echo SBOM COMPLETO
echo ============================================================