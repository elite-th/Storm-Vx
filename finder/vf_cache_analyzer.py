#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  vf_cache_analyzer.py — Cache Analyzer Module                           ║
║  Part of the STORM_VX Toolkit                                           ║
║                                                                          ║
║  Analyzes CDN/WAF caching behavior, detects cacheable endpoints,         ║
║  measures TTL, tests cache deception attacks, and checks if              ║
║  authenticated content gets cached. ArvanCloud-specific tests included.  ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import re
import time
from typing import Dict, List, Tuple
from urllib.parse import urlparse, urljoin

import aiohttp

from vf_common import C, ssl_param
from utils.response_helpers import safe_read_text
from utils.session_helpers import scanner_timeout
from config.defaults import CACHE_ANALYSIS_SEMAPHORE


class CacheAnalyzer:
    """
    Cache analyzer for STORM_VX.

    Analyzes CDN/WAF caching behavior including cacheable endpoints,
    TTL values, cache deception possibilities, and authenticated content
    caching issues. Includes ArvanCloud-specific tests.
    """

    # Cache-related headers to inspect
    CACHE_HEADERS = [
        "X-Cache", "CF-Cache-Status", "X-Arvan-Cache", "Age",
        "Cache-Control", "Vary", "ETag", "Last-Modified",
        "X-Cache-Lookup", "X-Squid-Error", "X-Akamai-Cache",
        "X-CDN-Origin", "X-Varnish", "Via",
    ]

    # User agents for cache differentiation tests
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
    ]

    # Cache deception test paths
    DECEPTION_PATHS = [
        "/style.css",
        "/image.png",
        "/script.js",
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
    ]

    # ArvanCloud-specific cache test paths
    ARVAN_CACHE_TESTS = [
        "?arvanpfz=1",
        "/arvan-test.css",
        "?__arvan_cache=1",
    ]

    def __init__(
        self,
        url: str,
        scripts: List[str],
        images: List[str],
        timeout: int = 10,
        verify_ssl: bool = True
    ):
        """
        Initialize CacheAnalyzer.

        Args:
            url: Target URL
            scripts: List of script URLs found on page
            images: List of image URLs found on page
            timeout: HTTP request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.url = url
        self.scripts = scripts
        self.images = images
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._ssl = ssl_param(self.verify_ssl)
        parsed = urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

    async def run(self) -> Dict:
        """
        Run cache analysis.

        Returns:
            Dictionary with:
                - cacheable_endpoints: Endpoints that appear cacheable
                - cached_endpoints: Endpoints confirmed cached (X-Cache: HIT)
                - cache_ttl: Dict of URL -> estimated TTL
                - deception_possible: Whether cache deception is possible
                - deception_urls: List of deception URLs to try
        """
        print(f"\n  {C.BD}{C.CY}[*] Cache Analyzer — {self.url}{C.RS}")
        print(f"  {C.DM}    Timeout: {self.timeout}s | Scripts: {len(self.scripts)} | Images: {len(self.images)}{C.RS}")

        t0 = time.time()

        # Step 1: Check main page cache headers (verbose — this is the main page)
        print(f"  {C.B}  [1/5] Checking main page cache headers...{C.RS}")
        main_cache_info = await self._check_cache_headers(self.url, verbose=True)

        # Step 2: Check static assets (scripts + images) — quiet mode
        print(f"  {C.B}  [2/5] Checking static assets cache behavior...{C.RS}")
        asset_urls = self._build_asset_urls()
        asset_results = await self._check_assets(asset_urls)

        # Step 3: Test cache differentiation (different User-Agents)
        print(f"  {C.B}  [3/5] Testing cache differentiation (User-Agent)...{C.RS}")
        diff_results = await self._test_user_agent_differentiation(self.url)

        # Step 4: Test cache deception
        print(f"  {C.B}  [4/5] Testing cache deception attacks...{C.RS}")
        deception_results = await self._test_cache_deception()

        # Step 5: Test authenticated content caching
        print(f"  {C.B}  [5/5] Testing authenticated content caching...{C.RS}")
        auth_results = await self._test_authenticated_caching()

        elapsed = time.time() - t0

        # Compile results
        cacheable = self._identify_cacheable(main_cache_info, asset_results)
        cached = self._identify_cached(main_cache_info, asset_results)
        ttl = self._extract_ttls(main_cache_info, asset_results)
        deception_possible = deception_results.get("deception_possible", False)
        deception_urls = deception_results.get("deception_urls", [])

        # Print summary
        self._print_summary(
            cacheable, cached, ttl, deception_possible, deception_urls,
            diff_results, auth_results, elapsed
        )

        return {
            "cacheable_endpoints": cacheable,
            "cached_endpoints": cached,
            "cache_ttl": ttl,
            "deception_possible": deception_possible,
            "deception_urls": deception_urls,
        }

    async def _check_cache_headers(self, url: str, verbose: bool = True) -> Dict:
        """Check cache-related headers for a URL.

        Args:
            url: URL to check
            verbose: If True, print per-asset details. If False, suppress output.
                     Regardless of this flag, headers are only printed for HIT/EXPIRED.
        """
        result = {
            "url": url,
            "headers": {},
            "cache_status": "UNKNOWN",
            "cacheable": False,
            "ttl": None,
        }

        timeout_cfg = scanner_timeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                async with session.get(
                    url, ssl=self._ssl, allow_redirects=False
                ) as resp:
                    all_headers = dict(resp.headers)

                    # Extract cache-relevant headers
                    for header in self.CACHE_HEADERS:
                        if header in all_headers:
                            result["headers"][header] = all_headers[header]

                    # Determine cache status
                    x_cache = all_headers.get("X-Cache", "").upper()
                    cf_cache = all_headers.get("CF-Cache-Status", "").upper()
                    arvan_cache = all_headers.get("X-Arvan-Cache", "").upper()

                    if "HIT" in x_cache or "HIT" in cf_cache or "HIT" in arvan_cache:
                        result["cache_status"] = "HIT"
                    elif "MISS" in x_cache or "MISS" in cf_cache or "MISS" in arvan_cache:
                        result["cache_status"] = "MISS"
                    elif "EXPIRED" in cf_cache:
                        result["cache_status"] = "EXPIRED"
                    elif "BYPASS" in x_cache or "BYPASS" in cf_cache:
                        result["cache_status"] = "BYPASS"

                    # Determine cacheability
                    cache_control = all_headers.get("Cache-Control", "").lower()
                    if "no-store" in cache_control or "private" in cache_control:
                        result["cacheable"] = False
                    elif "max-age" in cache_control:
                        result["cacheable"] = True
                        # Extract max-age
                        match = re.search(r'max-age=(\d+)', cache_control)
                        if match:
                            result["ttl"] = int(match.group(1))
                    elif result["cache_status"] in ("HIT", "MISS"):
                        result["cacheable"] = True

                    # Extract Age header for TTL estimation
                    age = all_headers.get("Age", "")
                    if age and age.isdigit():
                        result["age"] = int(age)

                    # Print findings only in verbose mode
                    if verbose:
                        status_color = C.G if result["cache_status"] == "HIT" else C.Y
                        print(
                            f"  {status_color}    Cache: {result['cache_status']:<10}{C.RS} "
                            f"| Cacheable: {str(result['cacheable']):<6} "
                            f"| TTL: {result['ttl'] or 'N/A'}"
                        )
                        # Only print individual headers for HIT or EXPIRED —
                        # these are the interesting ones worth inspecting
                        if result["cache_status"] in ("HIT", "EXPIRED") and result["headers"]:
                            for h, v in result["headers"].items():
                                print(f"  {C.DM}      {h}: {v[:60]}{C.RS}")

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if verbose:
                print(f"  {C.Y}    Error checking {url[:50]}: {type(e).__name__}{C.RS}")

        return result

    def _build_asset_urls(self) -> List[str]:
        """Build full URLs for all asset files."""
        urls = []
        for script in self.scripts[:10]:  # Limit to 10 scripts (reduced from 20)
            if script.startswith(('http://', 'https://')):
                urls.append(script)
            elif script.startswith('//'):
                urls.append(f"https:{script}")
            else:
                urls.append(urljoin(self.url, script))

        for img in self.images[:5]:  # Limit to 5 images (reduced from 20)
            if img.startswith(('http://', 'https://')):
                urls.append(img)
            elif img.startswith('//'):
                urls.append(f"https:{img}")
            else:
                urls.append(urljoin(self.url, img))

        return urls

    async def _check_assets(self, urls: List[str]) -> List[Dict]:
        """Check cache headers for multiple asset URLs concurrently (quiet mode)."""
        results = []
        semaphore = asyncio.Semaphore(CACHE_ANALYSIS_SEMAPHORE)  # W2.4

        async def check_one(url: str) -> Dict | None:
            async with semaphore:
                # verbose=False — suppress per-asset printing
                return await self._check_cache_headers(url, verbose=False)

        tasks = [check_one(url) for url in urls]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for r in responses:
            if isinstance(r, dict):
                results.append(r)

        # Print a compact summary line
        cacheable = [r for r in results if r.get("cacheable")]
        cached = [r for r in results if r.get("cache_status") == "HIT"]
        ttl_values = [r["ttl"] for r in results if r.get("ttl") is not None]
        avg_ttl = sum(ttl_values) / len(ttl_values) if ttl_values else 0

        if ttl_values:
            avg_str = f"{avg_ttl:.0f}s"
        else:
            avg_str = "N/A"

        print(
            f"  {C.CY}    {len(cacheable)}/{len(urls)} assets cacheable "
            f"| {len(cached)} confirmed cached "
            f"| avg TTL: {avg_str}{C.RS}"
        )

        # Show detailed info only for confirmed cached assets (HIT)
        for r in cached:
            url_short = r["url"][:55]
            ttl_str = r.get("ttl", "N/A")
            print(
                f"  {C.G}    [HIT] {url_short}{C.RS} TTL: {ttl_str}"
            )
            # Print headers for HIT assets — these are worth inspecting
            if r.get("headers"):
                for h, v in r["headers"].items():
                    print(f"  {C.DM}      {h}: {v[:60]}{C.RS}")

        return results

    async def _test_user_agent_differentiation(self, url: str) -> Dict:
        """Test if different User-Agents get different cached content."""
        results = {
            "different_responses": False,
            "googlebot_cached": False,
            "user_agent_vary": False,
        }

        timeout_cfg = scanner_timeout(total=self.timeout)

        async def _check_one_ua(session, ua):
            """Check a single User-Agent and return result info."""
            try:
                headers = {"User-Agent": ua}
                async with session.get(
                    url, headers=headers, ssl=self._ssl, allow_redirects=False
                ) as resp:
                    body = await safe_read_text(resp)  # W1.10: bounded read
                    cache_headers = {
                        "X-Cache": resp.headers.get("X-Cache", ""),
                        "CF-Cache-Status": resp.headers.get("CF-Cache-Status", ""),
                        "X-Arvan-Cache": resp.headers.get("X-Arvan-Cache", ""),
                        "Vary": resp.headers.get("Vary", ""),
                    }
                    result_info = {
                        "status": resp.status,
                        "size": len(body),
                        "x_cache": cache_headers["X-Cache"],
                        "vary": cache_headers.get("Vary", ""),
                        "is_googlebot": "Googlebot" in ua,
                        "ua_short": ua[:20],
                    }
                    return ua, result_info
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return ua, None

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            tasks = [_check_one_ua(session, ua) for ua in self.USER_AGENTS]
            ua_results = await asyncio.gather(*tasks, return_exceptions=True)

        bodies = {}
        for r in ua_results:
            if isinstance(r, Exception) or r is None:
                continue
            ua, info = r
            if info is None:
                continue
            bodies[info["ua_short"]] = info

            # Check Vary header for User-Agent
            if "user-agent" in info.get("vary", "").lower():
                results["user_agent_vary"] = True

            # Check if Googlebot gets cached
            if info.get("is_googlebot"):
                if "HIT" in info.get("x_cache", "").upper():
                    results["googlebot_cached"] = True

        # Check if responses differ
        sizes = set(v["size"] for v in bodies.values())
        if len(sizes) > 1:
            results["different_responses"] = True

        # Only print when something interesting is found
        if results["different_responses"]:
            print(f"  {C.Y}    [!] Different User-Agents get different responses{C.RS}")
            # Show per-UA details only when differentiation is detected
            for ua_short, info in bodies.items():
                print(
                    f"  {C.DM}    {ua_short:<22}{C.RS} → "
                    f"HTTP {info['status']} | Size: {info['size']:,}B | "
                    f"Cache: {info['x_cache'] or 'N/A'}"
                )
        if results["googlebot_cached"]:
            print(f"  {C.R}    [!] Googlebot responses get cached — potential cache poisoning{C.RS}")
        if results["user_agent_vary"]:
            print(f"  {C.G}    Vary: User-Agent — cache differentiates by UA{C.RS}")

        # If nothing interesting, print a quiet confirmation
        if not results["different_responses"] and not results["googlebot_cached"] and not results["user_agent_vary"]:
            print(f"  {C.DM}    No User-Agent differentiation detected{C.RS}")

        return results

    async def _test_cache_deception(self) -> Dict:
        """Test cache deception by appending non-existent paths."""
        results = {
            "deception_possible": False,
            "deception_urls": [],
        }

        timeout_cfg = scanner_timeout(total=self.timeout)
        sem = asyncio.Semaphore(CACHE_ANALYSIS_SEMAPHORE)  # W2.4

        # Build deception test URLs
        test_urls = []
        parsed = urlparse(self.url)
        base_path = parsed.path or "/"

        # Standard cache deception: append static file extension
        for suffix in self.DECEPTION_PATHS:
            test_urls.append({
                "url": f"{self.base_url}{base_path.rstrip('/')}/{suffix.lstrip('/')}",
                "type": "path_appension",
                "suffix": suffix,
            })

        # Path traversal with static extension
        test_urls.append({
            "url": f"{self.base_url}{base_path.rstrip('/')}/..%2f..%2fetc%2fpasswd",
            "type": "path_traversal",
            "suffix": "/..%2f..%2fetc%2fpasswd",
        })

        # ArvanCloud-specific tests
        for arvan_suffix in self.ARVAN_CACHE_TESTS:
            test_urls.append({
                "url": f"{self.base_url}{base_path.rstrip('/')}{arvan_suffix}",
                "type": "arvancloud_cache",
                "suffix": arvan_suffix,
            })

        # API cache deception
        api_paths = ["/api/data", "/api/user", "/api/config"]
        for api_path in api_paths:
            test_urls.append({
                "url": f"{self.base_url}{api_path}",
                "type": "api_endpoint",
                "suffix": api_path,
            })

        async def _test_one_deception(session, test):
            async with sem:
                try:
                    # First request
                    async with session.get(
                        test["url"], ssl=self._ssl, allow_redirects=False
                    ) as resp1:
                        body1 = await safe_read_text(resp1)
                        headers1 = dict(resp1.headers)
                        status1 = resp1.status

                    # Second request with different User-Agent
                    headers = {"User-Agent": "CacheDeceptionTest/1.0"}
                    async with session.get(
                        test["url"], headers=headers, ssl=self._ssl,
                        allow_redirects=False
                    ) as resp2:
                        body2 = await safe_read_text(resp2)
                        headers2 = dict(resp2.headers)
                        status2 = resp2.status

                    # Check if second request was cached
                    x_cache_2 = headers2.get("X-Cache", "").upper()
                    cf_cache_2 = headers2.get("CF-Cache-Status", "").upper()
                    arvan_cache_2 = headers2.get("X-Arvan-Cache", "").upper()

                    is_cached = (
                        "HIT" in x_cache_2 or
                        "HIT" in cf_cache_2 or
                        "HIT" in arvan_cache_2
                    )

                    # Check if content is different from what we'd expect
                    # for a static file
                    body_contains_dynamic = bool(
                        re.search(r'(user|email|token|session|auth)', body1, re.IGNORECASE)
                    )

                    return {
                        "test": test,
                        "is_cached": is_cached,
                        "body_contains_dynamic": body_contains_dynamic,
                        "status1": status1,
                        "error": None,
                    }

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    return {
                        "test": test,
                        "is_cached": False,
                        "body_contains_dynamic": False,
                        "status1": 0,
                        "error": type(e).__name__,
                    }

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            tasks = [_test_one_deception(session, test) for test in test_urls]
            deception_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in deception_results:
            if isinstance(r, Exception):
                continue
            if r["error"]:
                # Don't print error lines — they're noise
                continue

            test = r["test"]
            is_cached = r["is_cached"]
            body_contains_dynamic = r["body_contains_dynamic"]
            status1 = r["status1"]

            if is_cached and body_contains_dynamic:
                # Confirmed vulnerability: dynamic content is being cached
                results["deception_possible"] = True
                results["deception_urls"].append({
                    "url": test["url"],
                    "type": test["type"],
                    "status": status1,
                    "cached": True,
                    "dynamic_content": True,
                })
                print(
                    f"  {C.R}    [DECEPTION] {test['url'][:60]} "
                    f"→ Cached with dynamic content!{C.RS}"
                )
            elif is_cached:
                # Cached but static content — record but don't print (not interesting)
                results["deception_urls"].append({
                    "url": test["url"],
                    "type": test["type"],
                    "status": status1,
                    "cached": True,
                    "dynamic_content": False,
                })
            # [NOT CACHED] and [ERROR] lines are suppressed — they're noise

        # Quiet summary if no deception found
        if not results["deception_urls"]:
            print(f"  {C.DM}    No cache deception detected{C.RS}")

        return results

    async def _test_authenticated_caching(self) -> Dict:
        """Test if authenticated content gets improperly cached."""
        results = {
            "auth_content_cached": False,
            "details": [],
        }

        timeout_cfg = scanner_timeout(total=self.timeout)

        # Test with common session cookies
        test_cookies = [
            {"session": "test_session_12345"},
            {"PHPSESSID": "test_php_session"},
            {"laravel_session": "test_laravel_session"},
            {"connect.sid": "test_connect_sid"},
        ]

        async def _check_one_cookie(session, cookie_set):
            """Check a single cookie for auth caching."""
            cookie_name = list(cookie_set.keys())[0]
            try:
                async with session.get(
                    self.url, cookies=cookie_set, ssl=self._ssl,
                    allow_redirects=False
                ) as resp:
                    body = await safe_read_text(resp)  # W1.10: bounded read
                    headers = dict(resp.headers)
                    status = resp.status

                    # Check if response was cached despite having auth cookie
                    x_cache = headers.get("X-Cache", "").upper()
                    cf_cache = headers.get("CF-Cache-Status", "").upper()
                    arvan_cache = headers.get("X-Arvan-Cache", "").upper()

                    is_cached = (
                        "HIT" in x_cache or
                        "HIT" in cf_cache or
                        "HIT" in arvan_cache
                    )

                    return {
                        "cookie_name": cookie_name,
                        "is_cached": is_cached,
                        "status": status,
                        "error": None,
                    }
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return {
                    "cookie_name": cookie_name,
                    "is_cached": False,
                    "status": 0,
                    "error": True,
                }

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            tasks = [_check_one_cookie(session, cs) for cs in test_cookies]
            cookie_results = await asyncio.gather(*tasks, return_exceptions=True)

        found_issue = False
        for r in cookie_results:
            if isinstance(r, Exception) or r.get("error"):
                continue

            cookie_name = r["cookie_name"]
            is_cached = r["is_cached"]
            status = r["status"]

            if is_cached:
                found_issue = True
                results["auth_content_cached"] = True
                results["details"].append({
                    "cookie": cookie_name,
                    "cached": True,
                    "status": status,
                })
                # Only print for security issues
                print(
                    f"  {C.R}    [AUTH CACHED] Cookie '{cookie_name}' → "
                    f"Cached! (Security Issue){C.RS}"
                )
            # Don't print [AUTH OK] lines — they're noise

        # Quiet confirmation if all OK
        if not found_issue:
            print(f"  {C.DM}    No authenticated content caching detected{C.RS}")

        return results

    def _identify_cacheable(
        self, main_info: Dict, asset_results: List[Dict]
    ) -> List[Dict]:
        """Identify cacheable endpoints."""
        cacheable = []

        if main_info.get("cacheable"):
            cacheable.append({
                "url": main_info["url"],
                "cache_status": main_info.get("cache_status", "UNKNOWN"),
                "ttl": main_info.get("ttl"),
            })

        for asset in asset_results:
            if asset.get("cacheable"):
                cacheable.append({
                    "url": asset["url"],
                    "cache_status": asset.get("cache_status", "UNKNOWN"),
                    "ttl": asset.get("ttl"),
                })

        return cacheable

    def _identify_cached(
        self, main_info: Dict, asset_results: List[Dict]
    ) -> List[Dict]:
        """Identify confirmed cached endpoints (HIT)."""
        cached = []

        if main_info.get("cache_status") == "HIT":
            cached.append({
                "url": main_info["url"],
                "cache_status": "HIT",
                "ttl": main_info.get("ttl"),
            })

        for asset in asset_results:
            if asset.get("cache_status") == "HIT":
                cached.append({
                    "url": asset["url"],
                    "cache_status": "HIT",
                    "ttl": asset.get("ttl"),
                })

        return cached

    def _extract_ttls(
        self, main_info: Dict, asset_results: List[Dict]
    ) -> Dict[str, int]:
        """Extract TTL values for URLs."""
        ttls = {}

        if main_info.get("ttl") is not None:
            ttls[main_info["url"]] = main_info["ttl"]

        for asset in asset_results:
            if asset.get("ttl") is not None:
                ttls[asset["url"]] = asset["ttl"]

        return ttls

    def _print_summary(
        self,
        cacheable: List[Dict],
        cached: List[Dict],
        ttl: Dict,
        deception_possible: bool,
        deception_urls: List,
        diff_results: Dict,
        auth_results: Dict,
        elapsed: float
    ):
        """Print formatted summary."""
        deception_color = C.R if deception_possible else C.G
        auth_color = C.R if auth_results.get("auth_content_cached") else C.G

        print(f"\n  {C.G}  ╔════════════════════════════════════════════════════════╗{C.RS}")
        print(f"  {C.G}  ║  Cache Analysis Results                               ║{C.RS}")
        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Cacheable Endpoints:  {C.CY}{len(cacheable):<28}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Confirmed Cached:     {C.G}{len(cached):<28}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Cache Deception:      {deception_color}{str(deception_possible):<28}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Auth Content Cached:  {auth_color}{str(auth_results.get('auth_content_cached', False)):<28}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Deception URLs:       {C.Y}{len(deception_urls):<28}{C.G}║{C.RS}")
        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")

        if ttl:
            print(f"  {C.G}  ║  TTL Values:{C.RS}")
            for url, ttl_val in ttl.items():
                if ttl_val > 3600:
                    ttl_str = f"{ttl_val/3600:.1f}h"
                elif ttl_val > 60:
                    ttl_str = f"{ttl_val/60:.1f}m"
                else:
                    ttl_str = f"{ttl_val}s"
                print(f"  {C.G}  ║{C.RS}    {C.DM}{url[:50]:<50}{C.RS} TTL: {ttl_str}")

        if deception_urls:
            print(f"  {C.G}  ║  Deception URLs:{C.RS}")
            for du in deception_urls:
                print(
                    f"  {C.G}  ║{C.RS}    {C.R}{du.get('url', '')[:55]}{C.RS} "
                    f"({'CACHED' if du.get('cached') else 'NOT CACHED'})"
                )

        if auth_results.get("auth_content_cached"):
            print(f"  {C.G}  ║{C.RS}  {C.R}  [!] SECURITY: Authenticated content is being cached!{C.RS}")

        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Time: {C.CY}{elapsed:.1f}s{C.RS}")
        print(f"  {C.G}  ╚════════════════════════════════════════════════════════╝{C.RS}")
