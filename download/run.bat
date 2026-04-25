@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

:: ═══════════════════════════════════════════════════════════════════════════════
::  STORM_VX — One-Click Pipeline Runner (Windows)
::  FINDER (Recon) → TESTER (Attack)
::
::  Just double-click this file, or run from CMD:
::    run.bat https://target.com
::    run.bat https://target.com --deep --dns
::    run.bat                          (will prompt for URL)
::
::  FOR AUTHORIZED TESTING ONLY!
:: ═══════════════════════════════════════════════════════════════════════════════

:: ─── Banner ────────────────────────────────────────────────────────────────────
echo.
echo   ╔═══════════════════════════════════════════════════════╗
echo   ║          STORM_VX — Attack Pipeline Runner            ║
echo   ║     FINDER (Recon) =^> TESTER (Attack)                ║
echo   ╚═══════════════════════════════════════════════════════╝
echo.

:: ─── Check Python ─────────────────────────────────────────────────────────────
set "PYTHON="
where python >nul 2>&1
if %errorlevel%==0 (
    set "PYTHON=python"
) else (
    where python3 >nul 2>&1
    if %errorlevel%==0 (
        set "PYTHON=python3"
    ) else (
        echo   [ERROR] Python not found! Install Python 3.
        echo.
        pause
        exit /b 1
    )
)

:: ─── Check Files ──────────────────────────────────────────────────────────────
set "SCRIPT_DIR=%~dp0"
if not exist "%SCRIPT_DIR%VF_FINDER.py" (
    echo   [ERROR] VF_FINDER.py not found in %SCRIPT_DIR%
    echo.
    pause
    exit /b 1
)
if not exist "%SCRIPT_DIR%VF_TESTER.py" (
    echo   [ERROR] VF_TESTER.py not found in %SCRIPT_DIR%
    echo.
    pause
    exit /b 1
)

:: ─── Parse URL from arguments ────────────────────────────────────────────────
set "TARGET_URL="
set "FINDER_FLAGS="
set "MAX_WORKERS="
set "STEP_OVERRIDE="
set "CRASH_MODE="

:parse_args
if "%~1"=="" goto :done_parsing
if "%~1"=="--deep" (
    set "FINDER_FLAGS=!FINDER_FLAGS! --deep"
    shift
    goto :parse_args
)
if "%~1"=="--dns" (
    set "FINDER_FLAGS=!FINDER_FLAGS! --dns"
    shift
    goto :parse_args
)
if "%~1"=="--subdomains" (
    set "FINDER_FLAGS=!FINDER_FLAGS! --subdomains"
    shift
    goto :parse_args
)
if "%~1"=="--max-workers" (
    shift
    set "MAX_WORKERS=%~1"
    shift
    goto :parse_args
)
if "%~1"=="--step" (
    shift
    set "STEP_OVERRIDE=%~1"
    shift
    goto :parse_args
)
if "%~1"=="--crash-mode" (
    set "CRASH_MODE=1"
    shift
    goto :parse_args
)
:: Treat anything else as URL
set "TARGET_URL=%~1"
shift
goto :parse_args

:done_parsing

:: ─── Interactive URL Prompt (if no URL given) ────────────────────────────────
if "%TARGET_URL%"=="" (
    echo   Enter target URL ^(e.g. https://target.com^):
    set /p "TARGET_URL=   URL: "
    if "!TARGET_URL!"=="" (
        echo   [ERROR] No URL provided. Exiting.
        echo.
        pause
        exit /b 1
    )
)

:: Auto-add https:// if missing
echo !TARGET_URL! | findstr /r "^https\?://" >nul 2>&1
if %errorlevel% neq 0 (
    set "TARGET_URL=https://!TARGET_URL!"
)

:: ─── Phase 1: Run FINDER ─────────────────────────────────────────────────────
echo.
echo   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   [PHASE 1] Running VF_FINDER — Reconnaissance
echo   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   Target: %TARGET_URL%
echo.

cd /d "%SCRIPT_DIR%"

%PYTHON% VF_FINDER.py "%TARGET_URL%" %FINDER_FLAGS% --output VF_PROFILE.json

if not exist "VF_PROFILE.json" (
    echo.
    echo   [ERROR] Profile file not created! FINDER may have failed.
    echo.
    pause
    exit /b 1
)

echo.
echo   [OK] Profile saved to: VF_PROFILE.json
echo.

:: ─── Phase 2: Run TESTER ─────────────────────────────────────────────────────
echo   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   [PHASE 2] Running VF_TESTER — Attack
echo   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   Profile: VF_PROFILE.json
echo.

set "TESTER_CMD=%PYTHON% VF_TESTER.py --profile VF_PROFILE.json"

if not "%MAX_WORKERS%"=="" (
    set "TESTER_CMD=!TESTER_CMD! --max-workers %MAX_WORKERS%"
)
if not "%STEP_OVERRIDE%"=="" (
    set "TESTER_CMD=!TESTER_CMD! --step %STEP_OVERRIDE%"
)
if "%CRASH_MODE%"=="1" (
    set "TESTER_CMD=!TESTER_CMD! --crash-mode"
)

:: Run TESTER
%TESTER_CMD%

echo.
echo   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   [DONE] Pipeline completed.
echo   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo.
pause
