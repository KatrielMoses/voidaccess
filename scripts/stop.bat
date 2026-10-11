@echo off
:: Restart in a fresh cmd session so ANSI escape codes render correctly
if not defined VA_COLORS_ENABLED (
    set VA_COLORS_ENABLED=1
    reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1
    cmd /c "%~f0" %*
    exit /b
)

setlocal enabledelayedexpansion
chcp 65001 >nul
for %%I in ("%~dp0..") do set "REPO_ROOT=%%~fI"
cd /d "%REPO_ROOT%"

:: -- Color setup --------------------------------------------------------------
set "ESC="
for /f %%a in ('echo prompt $E^| cmd') do set "ESC=%%a"
set "GREEN=%ESC%[0;32m"
set "RED=%ESC%[0;31m"
set "YELLOW=%ESC%[1;33m"
set "CYAN=%ESC%[0;36m"
set "BOLD=%ESC%[1m"
set "DIM=%ESC%[2m"
set "NC=%ESC%[0m"

:: -- Banner --------------------------------------------------------------------
echo.
echo %CYAN%  +===================================+%NC%
echo %CYAN%  ^|  VoidAccess  -  Shutting down     ^|%NC%
echo %CYAN%  +===================================+%NC%
echo.

:: -- Docker permission check ---------------------------------------------------
docker info >nul 2>&1
if errorlevel 1 (
    echo %YELLOW%  [^!^!]%NC%  Docker not running or not found.
    echo   %DIM%-^>%NC%  Start Docker Desktop and try again.
    pause
    exit /b 1
)

:: -- Stop containers -----------------------------------------------------------
echo %DIM%   -^>%NC%  Stopping containers...
docker compose -f "%REPO_ROOT%\docker-compose.yml" --project-directory "%REPO_ROOT%" --env-file "%REPO_ROOT%\.env" down >nul 2>&1
if errorlevel 1 (
    echo %RED%  [^!^!]%NC%  Failed to stop containers.
    pause
    exit /b 1
)
echo %GREEN%  [OK]%NC%  All services stopped
echo.

exit /b 0
