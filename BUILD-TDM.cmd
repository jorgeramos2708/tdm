@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"
dotnet clean ".\TDM.sln" -c Release || exit /b 1
dotnet restore ".\TDM.sln" --force-evaluate || exit /b 1
dotnet build ".\TDM.sln" -c Release --no-restore -warnaserror || exit /b 1
echo [OK] TDM compilado en Release.
