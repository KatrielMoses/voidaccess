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
cd /d "%~dp0"

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

:: -- Opening banner -----------------------------------------------------------
echo.
echo %CYAN%  +===================================+%NC%
echo %CYAN%  ^|                                   ^|%NC%
echo %CYAN%  ^|     V O I D A C C E S S           ^|%NC%
echo %CYAN%  ^|     Setup Wizard                  ^|%NC%
echo %CYAN%  ^|                                   ^|%NC%
echo %CYAN%  +===================================+%NC%
echo.

:: -- Docker permission check ---------------------------------------------------
docker info >nul 2>&1
if errorlevel 1 (
    echo %YELLOW%  [^!^!]%NC%  Docker not running or not found.
    echo   %DIM%-^>%NC%  Start Docker Desktop and try again.
    echo   %DIM%-^>%NC%  Download: https://docs.docker.com/get-docker/
    pause
    exit /b 1
)

:: ===========================================================================
:: Pre-flight: detect existing state, offer Start / Reset / Cancel.
:: ===========================================================================
:: Without this, a re-clone or a half-finished prior run leaves stale state
:: (a .env, Docker volumes, leftover containers) that conflicts with a fresh
:: setup and doesn't surface until ~5 min into the build.
set HAS_ENV=0
set HAS_VOLUMES=0
set HAS_CONTAINERS=0

if exist "%~dp0.env" set HAS_ENV=1

for /f %%V in ('docker volume ls --format "{{.Name}}" 2^>nul ^| findstr /r "^voidaccess_postgres_data$ ^voidaccess_chroma_data$ ^voidaccess_monitors_data$ ^voidaccess_tor_data$"') do set HAS_VOLUMES=1

for /f %%C in ('docker ps -a --format "{{.Names}}" 2^>nul ^| findstr /r "^voidaccess-postgres$ ^voidaccess-tor$ ^voidaccess-fastapi$ ^voidaccess-nextjs$"') do set HAS_CONTAINERS=1

if !HAS_ENV!==0 if !HAS_VOLUMES!==0 if !HAS_CONTAINERS!==0 goto SKIP_PREFLIGHT

echo.
echo %CYAN%  +-----------------------------------+%NC%
echo %CYAN%  ^|%NC%  %BOLD%Existing setup detected%NC%            %CYAN%^|%NC%
echo %CYAN%  +-----------------------------------+%NC%
echo.
if !HAS_ENV!==1        echo %DIM%   -^>%NC%  .env file:       present
if !HAS_VOLUMES!==1    echo %DIM%   -^>%NC%  Docker volumes:  present (database may have data)
if !HAS_CONTAINERS!==1 echo %DIM%   -^>%NC%  Containers:      present
echo.
echo   %BOLD%What would you like to do?%NC%
echo.
echo   %CYAN%[1]%NC% %BOLD%Start VoidAccess%NC%  %DIM%-- use existing config%NC%
echo       Skips configuration and runs %BOLD%scripts\start.bat%NC%.
echo       %DIM%Choose this if your setup was working before.%NC%
echo.
echo   %CYAN%[2]%NC% %BOLD%Reset and reconfigure%NC%  %DIM%-- clean slate%NC%
echo       Stops voidaccess containers, deletes voidaccess Docker volumes,
echo       removes .env, then runs the full setup wizard.
echo       %DIM%Choose this if anything is broken or you want fresh API keys.%NC%
echo.
echo   %CYAN%[3]%NC% %BOLD%Cancel%NC%
echo       Exit without changes.
echo.

:PREFLIGHT_PROMPT
set PREFLIGHT_CHOICE=
set /p PREFLIGHT_CHOICE=  Choice [1-3]:
if "!PREFLIGHT_CHOICE!"=="1" goto PREFLIGHT_START
if "!PREFLIGHT_CHOICE!"=="2" goto PREFLIGHT_RESET
if "!PREFLIGHT_CHOICE!"=="3" goto PREFLIGHT_CANCEL
echo %YELLOW%  [^!^!]%NC%  Invalid choice -- enter 1, 2, or 3
goto PREFLIGHT_PROMPT

:PREFLIGHT_START
echo.
echo %DIM%   -^>%NC%  Handing off to scripts\start.bat...
echo.
call "%~dp0scripts\start.bat"
exit /b !errorlevel!

:PREFLIGHT_RESET
echo.
echo %YELLOW%  [^!^!]%NC%  This will permanently delete:
echo %YELLOW%  [^!^!]%NC%    - voidaccess Docker volumes (postgres data, chroma, monitors, tor)
echo %YELLOW%  [^!^!]%NC%    - The current .env file
echo %YELLOW%  [^!^!]%NC%    - Any voidaccess containers
echo.
set RESET_CONFIRM=
set /p RESET_CONFIRM=  Continue with reset? [y/N]:
if /i not "!RESET_CONFIRM!"=="y" (
    echo %DIM%   -^>%NC%  Reset cancelled
    goto PREFLIGHT_PROMPT
)
echo %DIM%   -^>%NC%  Resetting...
docker compose -f "%~dp0docker-compose.yml" --project-directory "%~dp0" down -v >nul 2>&1
docker rm -f voidaccess-postgres voidaccess-tor voidaccess-fastapi voidaccess-nextjs >nul 2>&1
docker volume rm -f voidaccess_postgres_data voidaccess_chroma_data voidaccess_monitors_data voidaccess_tor_data >nul 2>&1
if exist "%~dp0.env" del /q "%~dp0.env"
set HAS_ENV=0
set HAS_VOLUMES=0
set HAS_CONTAINERS=0
echo %GREEN%  [OK]%NC%  Reset complete -- proceeding with fresh setup
echo.
goto SKIP_PREFLIGHT

:PREFLIGHT_CANCEL
echo.
echo %DIM%   -^>%NC%  Cancelled. To start manually: %BOLD%scripts\start.bat%NC%
exit /b 0

:SKIP_PREFLIGHT

:: -- STEP 1: Prerequisites -----------------------------------------------------
echo.
echo %CYAN%  +-----------------------------------+%NC%
echo %CYAN%  ^|%NC%  %BOLD%  1 / 7  -  Prerequisites%NC%
echo %CYAN%  +-----------------------------------+%NC%
echo.

where docker >nul 2>&1
if errorlevel 1 (
    echo %RED%  [^!^!]%NC%  Docker not found.
    echo   %DIM%-^>%NC%  Install Docker Desktop: https://docs.docker.com/desktop/install/windows-install/
    pause
    exit /b 1
)
echo %GREEN%  [OK]%NC%  Docker found.

docker compose version >nul 2>&1
if errorlevel 1 (
    echo %RED%  [^!^!]%NC%  Docker Compose not found. Update Docker Desktop to a recent version.
    pause
    exit /b 1
)
echo %GREEN%  [OK]%NC%  Docker Compose found.

set PYTHON=
python --version >nul 2>&1 && set PYTHON=python
if not defined PYTHON (
    python3 --version >nul 2>&1 && set PYTHON=python3
)
if not defined PYTHON (
    echo %RED%  [^!^!]%NC%  Python not found. Install from https://python.org
    echo   %DIM%-^>%NC%  Python is required to generate secure secrets.
    pause
    exit /b 1
)
echo %GREEN%  [OK]%NC%  Python found.
echo.

:: -- STEP 2: Environment -------------------------------------------------------
echo.
echo %CYAN%  +-----------------------------------+%NC%
echo %CYAN%  ^|%NC%  %BOLD%  2 / 7  -  Environment%NC%
echo %CYAN%  +-----------------------------------+%NC%
echo.

:: Pre-flight already handled the existing-.env case (Reset deleted it,
:: Start exited, Cancel exited). If a .env is still here, back it up.
if exist "%~dp0.env" (
    set BACKUP=%~dp0.env.backup
    move /y "%~dp0.env" "!BACKUP!" >nul
    echo %YELLOW%  [^!^!]%NC%  Existing .env backed up to .env.backup
)

if exist "%~dp0.env.example" (
    copy /y "%~dp0.env.example" "%~dp0.env" >nul
    echo %GREEN%  [OK]%NC%  Created .env from .env.example
) else (
    type nul > "%~dp0.env"
    echo %DIM%   -^>%NC%  Created empty .env
)
call :lock_env_file
echo.

:: -- STEP 3: Secrets -----------------------------------------------------------
echo.
echo %CYAN%  +-----------------------------------+%NC%
echo %CYAN%  ^|%NC%  %BOLD%  3 / 7  -  Secrets%NC%
echo %CYAN%  +-----------------------------------+%NC%
echo.

for /f "delims=" %%i in ('!PYTHON! -c "import secrets; print(secrets.token_hex(32))"') do set JWT_SECRET=%%i
for /f "delims=" %%i in ('!PYTHON! -c "import secrets; print(secrets.token_hex(16))"') do set POSTGRES_PASSWORD=%%i

:: Safety net: pre-flight should have already wiped stale volumes via the
:: Reset path. If a postgres volume snuck back in, nuke it now -- the new
:: password won't authenticate against it.
docker volume ls --format "{{.Name}}" 2>nul | findstr /r "^voidaccess_postgres_data$" >nul 2>&1
if not errorlevel 1 (
    echo %YELLOW%  [^!^!]%NC%  Stale postgres volume detected after pre-flight -- wiping
    docker compose -f "%~dp0docker-compose.yml" --project-directory "%~dp0" down -v >nul 2>&1
    docker rm -f voidaccess-postgres voidaccess-tor voidaccess-fastapi voidaccess-nextjs >nul 2>&1
    docker volume rm -f voidaccess_postgres_data voidaccess_chroma_data voidaccess_monitors_data voidaccess_tor_data >nul 2>&1
)

call :env_set "JWT_SECRET" "!JWT_SECRET!"
call :env_set "POSTGRES_PASSWORD" "!POSTGRES_PASSWORD!"
echo %GREEN%  [OK]%NC%  Generated JWT_SECRET and POSTGRES_PASSWORD
echo.

:: -- STEP 4: LLM Provider -----------------------------------------------------
echo.
echo %CYAN%  +-----------------------------------+%NC%
echo %CYAN%  ^|%NC%  %BOLD%  4 / 7  -  LLM Provider%NC%
echo %CYAN%  +-----------------------------------+%NC%
echo.

echo   %BOLD%Choose your LLM provider:%NC%
echo.
echo   %CYAN%[1]%NC% %BOLD%Groq%NC%          %GREEN%FREE%NC% - No credit card needed
echo       Llama 3.3 70B - console.groq.com
echo.
echo   %CYAN%[2]%NC% %BOLD%OpenRouter%NC%    %GREEN%FREE%NC% models available
echo       100+ models - openrouter.ai
echo.
echo   %CYAN%[3]%NC% %BOLD%Anthropic%NC%     %YELLOW%Paid%NC%
echo       Claude models - console.anthropic.com
echo.
echo   %CYAN%[4]%NC% %BOLD%OpenAI%NC%        %YELLOW%Paid%NC%
echo       GPT-4o - platform.openai.com
echo.
echo   %CYAN%[5]%NC% %BOLD%Google Gemini%NC% %GREEN%FREE%NC% tier available
echo       Gemini 1.5 Flash - aistudio.google.com
echo.
echo   %CYAN%[6]%NC% %BOLD%Ollama%NC%        %GREEN%FREE%NC% - Fully local
echo       ollama.ai
echo.
echo   %DIM%[7]  Skip for now%NC%
echo.
set /p LLM_CHOICE=  Choose [1-7]:

if "!LLM_CHOICE!"=="1" (
    set /p LLM_KEY=  Groq API key:
    if defined LLM_KEY call :env_set "GROQ_API_KEY" "!LLM_KEY!"
)
if "!LLM_CHOICE!"=="2" (
    set /p LLM_KEY=  OpenRouter API key:
    if defined LLM_KEY call :env_set "OPENROUTER_API_KEY" "!LLM_KEY!"
)
if "!LLM_CHOICE!"=="3" (
    set /p LLM_KEY=  Anthropic API key:
    if defined LLM_KEY call :env_set "ANTHROPIC_API_KEY" "!LLM_KEY!"
)
if "!LLM_CHOICE!"=="4" (
    set /p LLM_KEY=  OpenAI API key:
    if defined LLM_KEY call :env_set "OPENAI_API_KEY" "!LLM_KEY!"
)
if "!LLM_CHOICE!"=="5" (
    set /p LLM_KEY=  Google AI API key:
    if defined LLM_KEY call :env_set "GOOGLE_API_KEY" "!LLM_KEY!"
)
if "!LLM_CHOICE!"=="6" (
    call :env_set "OLLAMA_BASE_URL" "http://127.0.0.1:11434"
    echo %GREEN%  [OK]%NC%  Ollama configured. Make sure Ollama is running before starting.
)
echo.

:: -- STEP 5: Enrichment Keys ---------------------------------------------------
echo.
echo %CYAN%  +-----------------------------------+%NC%
echo %CYAN%  ^|%NC%  %BOLD%  5 / 7  -  Enrichment Keys%NC%
echo %CYAN%  +-----------------------------------+%NC%
echo.

echo %DIM%   -^>%NC%  Threat intelligence enrichment keys
echo %DIM%   -^>%NC%  Press Enter to skip any
echo.
set /p OTX_KEY=  AlienVault OTX API key:
if defined OTX_KEY call :env_set "OTX_API_KEY" "!OTX_KEY!"
set /p VT_KEY=  VirusTotal API key:
if defined VT_KEY call :env_set "VT_API_KEY" "!VT_KEY!"
echo.

:: -- STEP 6: Start Stack -------------------------------------------------------
echo.
echo %CYAN%  +-----------------------------------+%NC%
echo %CYAN%  ^|%NC%  %BOLD%  6 / 7  -  Start Stack%NC%
echo %CYAN%  +-----------------------------------+%NC%
echo.

echo %DIM%   -^>%NC%  Services: PostgreSQL, Tor, FastAPI, Next.js
echo %DIM%   -^>%NC%  First run takes 3-5 minutes.
echo.
set /p START_NOW=  Start now? [Y/n]:
if /i "!START_NOW!"=="n" (
    echo %DIM%   -^>%NC%  Start manually with: scripts\start.bat
    goto DONE
)

echo.
echo %DIM%   -^>%NC%  Building containers...
set DOCKER_BUILDKIT=1
docker compose -f docker-compose.yml --project-directory "%~dp0" --env-file "%~dp0.env" up --build -d > "%TEMP%\va_setup.log" 2>&1
if errorlevel 1 (
    echo %RED%  [^!^!]%NC%  Build failed -- check %TEMP%\va_setup.log
    pause
    exit /b 1
)
echo %GREEN%  [OK]%NC%  Containers started

echo.
echo %DIM%   -^>%NC%  Waiting for services to be ready...
set STATUS=
set /a COUNT=0
:WAIT
if !COUNT! geq 60 goto TIMEOUT
for /f "delims=" %%i in ('curl -s --max-time 5 http://localhost:8000/healthz/ready 2^>nul') do set RESPONSE=%%i
echo !RESPONSE! | findstr /c:"ready" >nul 2>&1
if not errorlevel 1 set STATUS=ready
if "!STATUS!"=="ready" goto STEP7
set /a COUNT+=1
<nul set /p=.
timeout /t 5 /nobreak >nul
goto WAIT

:TIMEOUT
echo.
echo %YELLOW%  [^!^!]%NC%  Services still starting. Continuing with password setup.

:: -- STEP 7: Admin Password ----------------------------------------------------
:STEP7
echo.
echo %CYAN%  +-----------------------------------+%NC%
echo %CYAN%  ^|%NC%  %BOLD%  7 / 7  -  Admin Password%NC%
echo %CYAN%  +-----------------------------------+%NC%
echo.

set /p ADMIN_EMAIL=  Admin email [admin@voidaccess.tech]:
if not defined ADMIN_EMAIL set ADMIN_EMAIL=admin@voidaccess.tech

:PWD_LOOP
set /p ADMIN_PASS=  Admin password (min 8 chars, letters + numbers):
if not defined ADMIN_PASS goto PWD_LOOP

!PYTHON! -c "p='!ADMIN_PASS!'; exit(0 if len(p)>=8 and any(c.isalpha() for c in p) and any(c.isdigit() for c in p) else 1)" 2>nul
if errorlevel 1 (
    echo %RED%  [^!^!]%NC%  Password must be at least 8 characters with letters and numbers.
    goto PWD_LOOP
)

set /p ADMIN_CONFIRM=  Confirm password:
if "!ADMIN_PASS!" neq "!ADMIN_CONFIRM!" (
    echo %RED%  [^!^!]%NC%  Passwords do not match.
    goto PWD_LOOP
)

for /f "delims=" %%i in ('docker compose -f docker-compose.yml exec -T fastapi !PYTHON! -c "from passlib.context import CryptContext; ctx=CryptContext(schemes=[\"bcrypt\"]); print(ctx.hash(\"!ADMIN_PASS!\"))" 2^>nul') do set HASH=%%i
if defined HASH (
    docker compose -f docker-compose.yml exec -T postgres psql -U voidaccess -d voidaccess -c "UPDATE users SET hashed_password='!HASH!', must_reset_password=false, email='!ADMIN_EMAIL!' WHERE email='admin@voidaccess.tech' OR email='!ADMIN_EMAIL!';" >nul 2>&1
    echo %GREEN%  [OK]%NC%  Admin password set.
) else (
    echo %YELLOW%  [^!^!]%NC%  Could not set password automatically. Log in and change it via Settings.
)

:: -- Done ---------------------------------------------------------------------
:DONE
echo.
echo %GREEN%  +===================================+%NC%
echo %GREEN%  ^|                                   ^|%NC%
echo %GREEN%  ^|   [OK]  VoidAccess is ready       ^|%NC%
echo %GREEN%  ^|                                   ^|%NC%
echo %GREEN%  ^|   UI  -^>  http://localhost:3001   ^|%NC%
echo %GREEN%  ^|   API -^>  http://localhost:8000   ^|%NC%
echo %GREEN%  ^|                                   ^|%NC%
echo %GREEN%  +===================================+%NC%
echo.
pause
exit /b 0

:: =============================================================================
:: Subroutine: set or update a key=value line in .env
:: =============================================================================
:lock_env_file
if not exist "%~dp0.env" exit /b 0
icacls "%~dp0.env" /inheritance:r >nul 2>&1
icacls "%~dp0.env" /grant:r "%USERDOMAIN%\%USERNAME%":F >nul 2>&1
exit /b 0

:env_set
set "_KEY=%~1"
set "_VAL=%~2"
set "_ENV=%~dp0.env"
set "_TMP=%~dp0.env.tmp"

if not exist "!_ENV!" type nul > "!_ENV!"

:: Check if key already exists
findstr /b "!_KEY!=" "!_ENV!" >nul 2>&1
if not errorlevel 1 (
    :: Replace existing line
    (for /f "delims=" %%L in ('type "!_ENV!"') do (
        set "LINE=%%L"
        echo !LINE! | findstr /b "!_KEY!=" >nul 2>&1
        if not errorlevel 1 (
            echo !_KEY!=!_VAL!
        ) else (
            echo %%L
        )
    )) > "!_TMP!"
    move /y "!_TMP!" "!_ENV!" >nul
) else (
    :: Append new line
    echo !_KEY!=!_VAL! >> "!_ENV!"
)
call :lock_env_file
exit /b 0
