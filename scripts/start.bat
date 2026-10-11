@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
for %%I in ("%~dp0..") do set "REPO_ROOT=%%~fI"
cd /d "%REPO_ROOT%"

:: Enable ANSI colors
for /f %%a in ('echo prompt $E^| cmd') ^
    do set "ESC=%%a"
set "GREEN=%ESC%[0;32m"
set "RED=%ESC%[0;31m"
set "YELLOW=%ESC%[1;33m"
set "CYAN=%ESC%[0;36m"
set "BOLD=%ESC%[1m"
set "DIM=%ESC%[2m"
set "NC=%ESC%[0m"

:: Docker check
docker info >nul 2>&1
if errorlevel 1 (
    echo.
    echo   %YELLOW%[!!]%NC%  Docker not running.
    echo   %DIM% -> %NC% Start Docker Desktop first.
    exit /b 1
)

:: .env check
if not exist .env (
    echo.
    echo   %RED%[!!]%NC%  .env not found.
    echo   %DIM% -> %NC% Run setup.bat first.
    exit /b 1
)

:: Banner
echo.
echo   %CYAN%+===================================+%NC%
echo   %CYAN%^|%NC%  %BOLD%VoidAccess%NC%  -  Starting up       %CYAN%^|%NC%
echo   %CYAN%+===================================+%NC%
echo.

:: Detect compose file (absolute path)
set "COMPOSE_FILE=%REPO_ROOT%\docker-compose.yml"

echo   %DIM% -> %NC% Building and starting containers...
echo   %DIM%    (first run: 3-5 min, cached after)%NC%
echo.

:: Run docker compose - detached mode
:: --env-file uses absolute path so POSTGRES_PASSWORD, JWT_SECRET, etc.
:: always reach the containers regardless of cwd.
docker compose -f "%COMPOSE_FILE%" ^
    --project-directory "%REPO_ROOT%" ^
    --env-file "%REPO_ROOT%\.env" ^
    up --build -d
if errorlevel 1 (
    echo   %RED%[!!]%NC%  Build/start failed.
    echo   %DIM% -> %NC% Run for details:
    echo   %DIM%   docker compose -f "%COMPOSE_FILE%" --project-directory "%REPO_ROOT%" --env-file "%REPO_ROOT%\.env" up --build%NC%
    exit /b 1
)

echo   %GREEN%[OK]%NC%  Build complete
echo.
echo   %DIM% -> %NC% Checking services...
echo.

:: Check each service
for %%S in (postgres tor fastapi nextjs) do (
    set "HEALTHY=0"
    set "ATTEMPTS=0"
    :wait_%%S
    set /a ATTEMPTS+=1
    if !ATTEMPTS! gtr 30 goto timeout_%%S

    for /f "tokens=*" %%H in ('docker inspect ^
        --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}" ^
        voidaccess-%%S 2^>nul') do (
        if "%%H"=="healthy" set "HEALTHY=1"
        if "%%H"=="running" set "HEALTHY=1"
    )

    if "!HEALTHY!"=="1" (
        echo   %GREEN%[OK]%NC%  %%S
        goto done_%%S
    )
    timeout /t 3 /nobreak >nul
    goto wait_%%S

    :timeout_%%S
    echo   %YELLOW%[!!]%NC%  %%S - slow to start
    :done_%%S
)

echo.
echo   %GREEN%+===================================+%NC%
echo   %GREEN%^|%NC%                                   %GREEN%^|%NC%
echo   %GREEN%^|%NC%   %GREEN%[OK]%NC%  %BOLD%VoidAccess is ready!%NC%         %GREEN%^|%NC%
echo   %GREEN%^|%NC%                                   %GREEN%^|%NC%
echo   %GREEN%+===================================+%NC%
echo   %GREEN%^|%NC%  UI   ->  http://localhost:3001   %GREEN%^|%NC%
echo   %GREEN%^|%NC%  API  ->  http://localhost:8000   %GREEN%^|%NC%
echo   %GREEN%+===================================+%NC%
echo.

endlocal
