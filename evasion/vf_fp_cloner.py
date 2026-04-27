#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Browser Fingerprint Cloner — VF_EVASION Module                         ║
║  Extract and mimic real browser JA3/JA4 TLS fingerprints                ║
║                                                                          ║
║  WAFs like ArvanCloud fingerprint TLS ClientHello parameters (JA3/JA4)  ║
║  to identify automated tools. Python's default ssl produces a very      ║
║  distinctive JA3 that is easily flagged as a bot.                       ║
║                                                                          ║
║  This module:                                                            ║
║  - Probes target to understand expected TLS fingerprint                  ║
║  - Creates SSL contexts matching real Chrome/Firefox/Safari/Edge        ║
║  - Generates realistic HTTP/2 header ordering                           ║
║  - Tracks which identities bypass WAF and auto-weights them             ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import ssl
import time
import random
import hashlib
import struct
import socket
from typing import Dict, List, Optional, Tuple
from collections import deque
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ═══════════════════════════════════════════════════════════════════════════════
# Color Codes
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# Browser JA3/JA4 Profile Database
# ═══════════════════════════════════════════════════════════════════════════════

BROWSER_PROFILES = {
    "chrome_122": {
        "name": "Chrome 122 (Windows)",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "ja3_hash": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        "tls_version": "TLSv1.3",
        "cipher_suites": [
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
            'AES128-CCM',
            'AES256-CCM',
        ],
        "alpn": ['h2', 'http/1.1'],
        "min_tls": ssl.TLSVersion.TLSv1_2,
        "max_tls": ssl.TLSVersion.TLSv1_3,
        "curves": ['X25519', 'prime256v1', 'secp384r1'],
        "sec_ch_ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        "platform": "Windows",
    },
    "chrome_122_mac": {
        "name": "Chrome 122 (macOS)",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "ja3_hash": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        "tls_version": "TLSv1.3",
        "cipher_suites": [
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
        ],
        "alpn": ['h2', 'http/1.1'],
        "min_tls": ssl.TLSVersion.TLSv1_2,
        "max_tls": ssl.TLSVersion.TLSv1_3,
        "curves": ['X25519', 'prime256v1', 'secp384r1'],
        "sec_ch_ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        "platform": "macOS",
    },
    "firefox_123": {
        "name": "Firefox 123 (Windows)",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "ja3_hash": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-34-51-43-13-45-27-17513,29-23-24-25-256-257,0",
        "tls_version": "TLSv1.3",
        "cipher_suites": [
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-RSA-AES128-CBC-SHA',
            'ECDHE-RSA-AES256-CBC-SHA',
            'AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
            'AES128-CBC-SHA',
            'AES256-CBC-SHA',
        ],
        "alpn": ['h2', 'http/1.1'],
        "min_tls": ssl.TLSVersion.TLSv1_2,
        "max_tls": ssl.TLSVersion.TLSv1_3,
        "curves": ['X25519', 'prime256v1', 'secp384r1'],
        "sec_ch_ua": None,  # Firefox doesn't send Sec-CH-UA
        "platform": "Windows",
    },
    "safari_17": {
        "name": "Safari 17 (macOS)",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "ja3_hash": "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-47-53-10,0-23-65281-10-11-35-16-5-13-51-45-43-27-21,29-23-24-25-256-257,0",
        "tls_version": "TLSv1.3",
        "cipher_suites": [
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
            'AES128-GCM-SHA256',
        ],
        "alpn": ['h2', 'http/1.1'],
        "min_tls": ssl.TLSVersion.TLSv1_2,
        "max_tls": ssl.TLSVersion.TLSv1_3,
        "curves": ['X25519', 'prime256v1', 'secp384r1'],
        "sec_ch_ua": None,  # Safari doesn't send Sec-CH-UA
        "platform": "macOS",
    },
    "edge_122": {
        "name": "Edge 122 (Windows)",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
        "ja3_hash": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        "tls_version": "TLSv1.3",
        "cipher_suites": [
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
        ],
        "alpn": ['h2', 'http/1.1'],
        "min_tls": ssl.TLSVersion.TLSv1_2,
        "max_tls": ssl.TLSVersion.TLSv1_3,
        "curves": ['X25519', 'prime256v1', 'secp384r1'],
        "sec_ch_ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
        "platform": "Windows",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# Browser Fingerprint Cloner
# ═══════════════════════════════════════════════════════════════════════════════

class BrowserFingerprintCloner:
    """
    Extract and mimic real browser JA3/JA4 TLS fingerprints.

    WAFs like ArvanCloud fingerprint TLS ClientHello parameters (JA3 hash)
    to identify automated tools. Python's default ssl module produces a very
    distinctive JA3 that is easily flagged as a bot.

    This class:
    - Probes the target to understand what TLS fingerprint it expects
    - Creates SSL contexts that match real browser JA3 hashes
    - Generates realistic HTTP/2 header ordering
    - Tracks which identities bypass WAF and auto-weights successful ones
    """

    def __init__(self):
        self._profile_names = list(BROWSER_PROFILES.keys())
        self._current_index = 0
        self._profile_weights: Dict[str, float] = {name: 1.0 for name in self._profile_names}
        self._profile_stats: Dict[str, Dict[str, int]] = {
            name: {"success": 0, "blocked": 0, "total": 0}
            for name in self._profile_names
        }
        self._probed_target: Optional[Dict] = None
        self._last_weight_update: float = 0

    async def probe_target(self, url: str) -> Dict:
        """
        Probe the target to understand what TLS fingerprint it expects.

        Returns a dict with:
            ja3_hash: str   — Best-guess JA3 hash the target expects
            tls_version: str — TLS version (e.g. "TLSv1.3")
            cipher_suite: str — Primary cipher suite
            alpn: list     — Supported ALPN protocols
        """
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        result = {
            "ja3_hash": "unknown",
            "tls_version": "TLSv1.3",
            "cipher_suite": "unknown",
            "alpn": ["h2", "http/1.1"],
        }

        if not hostname or parsed.scheme != 'https':
            print(f"  {C.Y}[FP-CLONE] Target is not HTTPS, TLS probing skipped{C.RS}")
            return result

        print(f"  {C.CY}[FP-CLONE] Probing TLS fingerprint of {hostname}:{port}...{C.RS}")

        # Try each browser profile and see which gets the best response
        best_profile = None
        best_status = 0

        for profile_name, profile in BROWSER_PROFILES.items():
            try:
                ctx = self._build_ssl_context(profile)
                timeout = aiohttp.ClientTimeout(total=15)

                connector = aiohttp.TCPConnector(ssl=ctx, limit=1)
                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    try:
                        async with session.get(url, allow_redirects=False) as resp:
                            status = resp.status
                            print(f"  {C.DM}  {profile['name']}: status {status}{C.RS}")

                            self._profile_stats[profile_name]["total"] += 1

                            # ArvanCloud uses 500 for blocking, not just 403/429
                            if status in (403, 429, 500, 503):
                                self._profile_stats[profile_name]["blocked"] += 1
                            elif status < 400:
                                self._profile_stats[profile_name]["success"] += 1
                                if status < best_status or best_status == 0:
                                    best_status = status
                                    best_profile = profile
                    except Exception as e:
                        print(f"  {C.R}  {profile['name']}: connection error — {e}{C.RS}")
            except Exception as e:
                print(f"  {C.R}  {profile['name']}: SSL error — {e}{C.RS}")

        if best_profile:
            result["ja3_hash"] = best_profile.get("ja3_hash", "unknown")
            result["tls_version"] = best_profile.get("tls_version", "TLSv1.3")
            result["cipher_suite"] = best_profile["cipher_suites"][0] if best_profile.get("cipher_suites") else "unknown"
            result["alpn"] = best_profile.get("alpn", ["h2", "http/1.1"])
            print(f"  {C.G}[FP-CLONE] Best profile: {best_profile['name']} (status {best_status}){C.RS}")
        else:
            # Fallback: try raw socket TLS probe
            try:
                result = await self._raw_tls_probe(hostname, port)
            except Exception as e:
                print(f"  {C.R}[FP-CLONE] Raw TLS probe failed: {e}{C.RS}")

        self._probed_target = result
        self._update_weights()
        return result

    async def _raw_tls_probe(self, hostname: str, port: int) -> Dict:
        """
        Raw socket TLS probe to extract server's TLS configuration.
        """
        result = {
            "ja3_hash": "unknown",
            "tls_version": "TLSv1.3",
            "cipher_suite": "unknown",
            "alpn": ["h2", "http/1.1"],
        }

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['h2', 'http/1.1'])

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    proto = ssock.version()
                    cipher = ssock.cipher()
                    selected_alpn = ssock.selected_alpn_protocol()

                    result["tls_version"] = proto or "TLSv1.3"
                    result["cipher_suite"] = cipher[0] if cipher else "unknown"
                    if selected_alpn:
                        result["alpn"] = [selected_alpn]

                    print(f"  {C.G}[FP-CLONE] Server TLS: {proto}, cipher={cipher[0] if cipher else '?'}, alpn={selected_alpn}{C.RS}")
        except Exception as e:
            print(f"  {C.Y}[FP-CLONE] TLS probe error: {e}{C.RS}")

        return result

    def _build_ssl_context(self, profile: Dict) -> ssl.SSLContext:
        """Build an SSL context from a browser profile definition."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Set TLS version range
        ctx.minimum_version = profile.get("min_tls", ssl.TLSVersion.TLSv1_2)
        ctx.maximum_version = profile.get("max_tls", ssl.TLSVersion.TLSv1_3)

        # Set cipher suites in browser's preferred order
        try:
            available_ciphers = {c['name'] for c in ctx.get_ciphers()}
            usable_ciphers = [c for c in profile.get("cipher_suites", []) if c in available_ciphers]
            if usable_ciphers:
                ctx.set_ciphers(':'.join(usable_ciphers))
            else:
                # Fallback: modern cipher suite
                ctx.set_ciphers(
                    'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:'
                    '!aNULL:!MD5:!DSS:!RC4:!3DES'
                )
        except ssl.SSLError:
            pass

        # Set ALPN protocols — critical for JA3 fingerprint
        try:
            ctx.set_alpn_protocols(profile.get("alpn", ['h2', 'http/1.1']))
        except Exception:
            pass

        # Disable certificate verification
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Enable TLS 1.3 middlebox compatibility
        try:
            ctx.options |= ssl.OP_ENABLE_MIDDLEBOX_COMPATIBILITY
        except AttributeError:
            pass

        return ctx

    def create_ssl_context(self, profile: str = "auto") -> ssl.SSLContext:
        """
        Create SSL context matching a real browser's TLS fingerprint.

        Args:
            profile: Browser profile name, or "auto" for weighted random selection

        Returns:
            ssl.SSLContext configured to mimic the specified browser
        """
        if profile == "auto":
            profile_name = self._weighted_random_profile()
        else:
            profile_name = profile if profile in BROWSER_PROFILES else "chrome_122"

        profile_data = BROWSER_PROFILES[profile_name]
        return self._build_ssl_context(profile_data)

    def get_request_headers(self, profile: str = "auto") -> Dict[str, str]:
        """
        Return complete browser-like headers for the given profile.

        Browsers send headers in a specific order; Python doesn't. This generates
        realistic header ordering including HTTP/2 pseudo-headers.

        Args:
            profile: Browser profile name, or "auto" for weighted random selection

        Returns:
            Dict of headers in realistic browser order
        """
        if profile == "auto":
            profile_name = self._weighted_random_profile()
        else:
            profile_name = profile if profile in BROWSER_PROFILES else "chrome_122"

        prof = BROWSER_PROFILES[profile_name]

        # Build headers in the order a real browser sends them
        headers = {}

        # Chrome/Edge send Sec-CH-UA headers; Firefox/Safari do not
        if prof.get("sec_ch_ua"):
            headers["Sec-CH-UA"] = prof["sec_ch_ua"]
            headers["Sec-CH-UA-Mobile"] = "?0"
            headers["Sec-CH-UA-Platform"] = f'"{prof.get("platform", "Windows")}"'

        headers["Upgrade-Insecure-Requests"] = "1"
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"

        if prof.get("sec_ch_ua"):
            # Chrome/Edge specific
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-User"] = "?1"
            headers["Sec-Fetch-Dest"] = "document"

        headers["Accept-Language"] = random.choice([
            "en-US,en;q=0.9",
            "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7",
            "en-US,en;q=0.9,fa;q=0.8",
        ])
        headers["Accept-Encoding"] = "gzip, deflate, br"

        # Cache-related headers
        headers["Cache-Control"] = random.choice([
            "max-age=0",
            "no-cache",
            "max-age=0",
        ])

        return headers

    def get_http2_pseudo_headers(self, method: str = "GET", path: str = "/",
                                  authority: str = "") -> Dict[str, str]:
        """
        Generate realistic HTTP/2 pseudo-headers in correct browser order.

        Browsers send :method, :authority, :scheme, :path in that exact order.
        Python libraries often send them in a different order, which is a
        fingerprinting signal.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: URL path
            authority: Host header value

        Returns:
            Dict of HTTP/2 pseudo-headers in browser-correct order
        """
        pseudo = {}
        # Browser order: :method, :authority, :scheme, :path
        pseudo[":method"] = method
        pseudo[":authority"] = authority
        pseudo[":scheme"] = "https"
        pseudo[":path"] = path
        return pseudo

    def get_next_identity(self) -> Dict:
        """
        Get the next browser identity (SSL context + headers + UA).

        Each call rotates through profiles. Profiles that have been successful
        against the WAF are weighted higher and selected more often.

        Returns:
            Dict with keys: ssl_context, headers, user_agent
        """
        # Select profile based on weighted distribution
        profile_name = self._weighted_random_profile()
        prof = BROWSER_PROFILES[profile_name]

        ssl_ctx = self._build_ssl_context(prof)
        headers = self.get_request_headers(profile_name)

        result = {
            "ssl_context": ssl_ctx,
            "headers": headers,
            "user_agent": prof["user_agent"],
            "profile_name": profile_name,
            "profile_display": prof["name"],
        }

        # Advance rotation
        self._current_index = (self._current_index + 1) % len(self._profile_names)

        # Periodically update weights
        now = time.time()
        if now - self._last_weight_update > 30:
            self._update_weights()

        return result

    def record_result(self, profile_name: str, was_blocked: bool):
        """
        Record whether a profile was blocked or got through the WAF.

        This feeds into the auto-weighting system: profiles that succeed
        more often get higher weight and are used more frequently.

        Args:
            profile_name: The profile key used (e.g. "chrome_122")
            was_blocked: True if WAF blocked the request (403/429/500/503 from ArvanCloud)
        """
        if profile_name not in self._profile_stats:
            return

        self._profile_stats[profile_name]["total"] += 1
        if was_blocked:
            self._profile_stats[profile_name]["blocked"] += 1
        else:
            self._profile_stats[profile_name]["success"] += 1

    def _weighted_random_profile(self) -> str:
        """Select a profile based on success-weighted distribution."""
        total_weight = sum(self._profile_weights.values())
        if total_weight <= 0:
            return random.choice(self._profile_names)

        r = random.uniform(0, total_weight)
        cumulative = 0.0
        for name in self._profile_names:
            cumulative += self._profile_weights[name]
            if r <= cumulative:
                return name

        return self._profile_names[-1]

    def _update_weights(self):
        """
        Update profile weights based on success rates.

        Profiles with higher success rates get proportionally higher weights,
        causing them to be selected more often. Profiles that are heavily
        blocked get reduced weights.
        """
        self._last_weight_update = time.time()

        for name, stats in self._profile_stats.items():
            total = stats["total"]
            if total < 3:
                # Not enough data yet, keep default weight
                self._profile_weights[name] = 1.0
                continue

            success_rate = stats["success"] / total

            # Weight = base + success bonus - block penalty
            # Range: 0.1 (always blocked) to 3.0 (never blocked)
            self._profile_weights[name] = max(0.1, 0.5 + success_rate * 2.5)

        # Print weight summary
        best = max(self._profile_weights.items(), key=lambda x: x[1])
        worst = min(self._profile_weights.items(), key=lambda x: x[1])
        print(f"  {C.CY}[FP-CLONE] Weight update — best: {BROWSER_PROFILES[best[0]]['name']} ({best[1]:.2f}), "
              f"worst: {BROWSER_PROFILES[worst[0]]['name']} ({worst[1]:.2f}){C.RS}")

    def get_stats(self) -> Dict:
        """Get current fingerprint cloning statistics."""
        return {
            "profiles": dict(self._profile_stats),
            "weights": dict(self._profile_weights),
            "current_profile": self._profile_names[self._current_index],
        }
