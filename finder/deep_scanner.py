"""Deep scanning module — path discovery, performance baseline, security audit.

Handles deep path scanning, performance baseline measurement,
rate limit probing, and security header auditing.
"""
from __future__ import annotations
import asyncio
import re
import time
from typing import Dict, List, Any
from urllib.parse import urljoin, urlparse

import aiohttp


from vf_common import C, ssl_param
from utils.response_helpers import safe_read_text, safe_read_js
from utils.session_helpers import scanner_timeout
from config.defaults import DEEP_SCAN_TIMEOUT, DEEP_SCAN_SEMAPHORE, SCRIPT_ANALYSIS_SEMAPHORE
from finder.site_profile import SiteProfile
from finder.signatures import DEEP_PATHS, CDN_KEYWORDS


async def deep_scan(url: str, profile: SiteProfile, verify_ssl: bool = True) -> SiteProfile:
    """Scan for common paths and sensitive files.

    Args:
        url: Target URL.
        profile: SiteProfile to populate with found paths.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        Updated SiteProfile.
    """
    timeout = scanner_timeout(total=DEEP_SCAN_TIMEOUT)  # W2.4
    _ssl = ssl_param(verify_ssl)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        found = []
        sem = asyncio.Semaphore(DEEP_SCAN_SEMAPHORE)  # W2.4

        async def check_path(path: str, _ssl):
            full_url = f"{profile.scheme}://{profile.host}{path}"
            async with sem:
                try:
                    async with session.get(full_url, ssl=_ssl, allow_redirects=False) as resp:
                        if resp.status in (200, 301, 302, 403):
                            size = 0
                            try:
                                body = await safe_read_text(resp)  # W1.10: bounded read
                                size = len(body)
                            except (UnicodeDecodeError, aiohttp.ClientError):
                                pass
                            info = {
                                "path": path,
                                "status": resp.status,
                                "size": size,
                            }
                            found.append(info)

                            # Check for sensitive files
                            sensitive = ['.env', '.git', 'Web.config', 'wp-config',
                                         'phpinfo', 'server-status', '.htaccess']
                            if any(s in path for s in sensitive):
                                profile.sensitive_files.append(path)

                            status_color = C.G if resp.status == 200 else C.Y
                            print(f"  {status_color}    {resp.status} {path} ({size:,}B){C.RS}")
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

        # Scan in batches
        for i in range(0, len(DEEP_PATHS), 10):
            batch = DEEP_PATHS[i:i + 10]
            await asyncio.gather(*[check_path(p, _ssl) for p in batch])

    profile.found_paths = found
    print(f"  {C.G}  Paths found: {len(found)} | Sensitive: {len(profile.sensitive_files)}{C.RS}")
    if profile.sensitive_files:
        for sf in profile.sensitive_files:
            print(f"  {C.R}  !! Sensitive: {sf}{C.RS}")

    return profile


async def performance_baseline(url: str, profile: SiteProfile, verify_ssl: bool = True) -> SiteProfile:
    """Measure baseline performance: response times, rate limits.

    Args:
        url: Target URL.
        profile: SiteProfile to populate with performance data.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        Updated SiteProfile.
    """
    timeout = scanner_timeout(total=15)
    _ssl = ssl_param(verify_ssl)
    rts = []

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # v15: Send 10 baseline requests IN PARALLEL instead of sequential + sleep
            async def _baseline_request(_ssl):
                t0 = time.monotonic()
                try:
                    async with session.get(url, ssl=_ssl, allow_redirects=True) as resp:
                        elapsed = time.monotonic() - t0
                        return elapsed
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    return None

            baseline_results = await asyncio.gather(*[_baseline_request(_ssl) for _ in range(10)])
            rts = [rt for rt in baseline_results if rt is not None]

            if rts:
                profile.baseline_rt = sum(rts) / len(rts)
                profile.baseline_rts = rts

            # Rate limit detection: send 20 rapid requests
            # v15: Also parallelized
            print(f"  {C.CY}  Testing rate limits (20 rapid requests)...{C.RS}", end='', flush=True)
            rl_detected = False
            rl_threshold = None

            async def _rate_test_request(idx, _ssl):
                try:
                    async with session.get(url, ssl=_ssl, allow_redirects=True) as resp:
                        is_limited = False
                        if resp.status == 429:
                            is_limited = True
                        elif resp.status == 503:
                            body = await safe_read_text(resp)  # W1.10: bounded read
                            if any(x in body.lower() for x in ['rate', 'limit', 'too many', 'challenge']):
                                is_limited = True
                        return idx, is_limited, resp.status
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    return idx, False, 0

            rate_results = await asyncio.gather(*[_rate_test_request(i, _ssl) for i in range(20)])
            for idx, is_limited, status in rate_results:
                if is_limited:
                    rl_detected = True
                    rl_threshold = idx + 1
                    status_color = C.R if status == 429 else C.Y
                    print(f"  {status_color}  Rate limit at request #{idx+1} ({status}){C.RS}")
                    break

            profile.rate_limit_detected = rl_detected
            profile.rate_limit_threshold = rl_threshold

            if rts:
                avg_rt = sum(rts) / len(rts)
                min_rt = min(rts)
                max_rt = max(rts)
                print(f"  {C.G}  Baseline RT: avg={avg_rt*1000:.0f}ms min={min_rt*1000:.0f}ms max={max_rt*1000:.0f}ms{C.RS}")

            if rl_detected:
                print(f"  {C.Y}  Rate Limit: DETECTED at ~{rl_threshold} requests{C.RS}")
            else:
                print(f"  {C.G}  Rate Limit: Not detected in 20 requests{C.RS}")

    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"  {C.Y}  Performance test error: {e}{C.RS}")

    return profile


def audit_security_headers(profile: SiteProfile) -> SiteProfile:
    """Check for presence and correctness of security headers.

    Args:
        profile: SiteProfile with populated headers.

    Returns:
        Updated SiteProfile with security_headers populated.
    """
    headers = profile.headers
    security = {
        "Strict-Transport-Security": {
            "present": "Strict-Transport-Security" in headers,
            "value": headers.get("Strict-Transport-Security", "MISSING"),
            "importance": "HIGH",
        },
        "Content-Security-Policy": {
            "present": "Content-Security-Policy" in headers,
            "value": headers.get("Content-Security-Policy", "MISSING"),
            "importance": "HIGH",
        },
        "X-Frame-Options": {
            "present": "X-Frame-Options" in headers,
            "value": headers.get("X-Frame-Options", "MISSING"),
            "importance": "MEDIUM",
        },
        "X-Content-Type-Options": {
            "present": "X-Content-Type-Options" in headers,
            "value": headers.get("X-Content-Type-Options", "MISSING"),
            "importance": "MEDIUM",
        },
        "X-XSS-Protection": {
            "present": "X-XSS-Protection" in headers,
            "value": headers.get("X-XSS-Protection", "MISSING"),
            "importance": "LOW",
        },
        "Referrer-Policy": {
            "present": "Referrer-Policy" in headers,
            "value": headers.get("Referrer-Policy", "MISSING"),
            "importance": "MEDIUM",
        },
        "Permissions-Policy": {
            "present": "Permissions-Policy" in headers,
            "value": headers.get("Permissions-Policy", "MISSING"),
            "importance": "LOW",
        },
    }
    profile.security_headers = security

    missing = [k for k, v in security.items() if not v["present"]]
    present = [k for k, v in security.items() if v["present"]]

    if present:
        print(f"  {C.G}  Present: {', '.join(present)}{C.RS}")
    if missing:
        print(f"  {C.R}  Missing:  {', '.join(missing)}{C.RS}")

    return profile


async def analyze_js_bundles(url: str, html: str, profile: SiteProfile, verify_ssl: bool = True) -> SiteProfile:
    """Download and analyze JS bundles to extract API endpoints from SPA apps.

    React/Vue/Angular apps hide their API calls inside compiled JS bundles.
    This method downloads script files and scans them for API patterns.

    Args:
        url: Target URL.
        html: Raw HTML content (for _is_origin_resource checks).
        profile: SiteProfile with scripts populated.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        Updated SiteProfile with discovered API endpoints.
    """
    p = profile
    if not p.scripts:
        return p

    print(f"  {C.CY}  Analyzing JS bundles for API endpoints...{C.RS}")
    timeout = scanner_timeout(total=15)
    _ssl = ssl_param(verify_ssl)
    new_endpoints = []

    # Helper: check if resource is from origin (not CDN)
    def _is_origin_resource(resource_url: str) -> bool:
        try:
            parsed = urlparse(resource_url)
            resource_host = parsed.netloc.split(':')[0]
            if resource_host == p.domain:
                return True
            resource_lower = resource_host.lower()
            for kw in CDN_KEYWORDS:
                if kw in resource_lower:
                    return False
            return True
        except (ValueError, TypeError):
            return False

    async with aiohttp.ClientSession(timeout=timeout) as session:
        scripts_to_analyze = p.scripts[:5]
        sem = asyncio.Semaphore(SCRIPT_ANALYSIS_SEMAPHORE)  # W2.4

        async def analyze_script(script_url: str, _ssl):
            # v23: Skip non-HTTP schemes (data:, blob:, javascript:, etc.)
            if any(script_url.startswith(pfx) for pfx in ('data:', 'blob:', 'javascript:', 'file:', 'about:')):
                return

            if script_url.startswith('//'):
                script_url_full = f"{p.scheme}:{script_url}"
            elif script_url.startswith('/'):
                script_url_full = f"{p.scheme}://{p.domain}{script_url}"
            elif not script_url.startswith('http'):
                script_url_full = urljoin(p.url, script_url)
            else:
                script_url_full = script_url

            if not _is_origin_resource(script_url_full):
                return

            async with sem:
                try:
                    async with session.get(script_url_full, ssl=_ssl,
                                          allow_redirects=True) as resp:
                        if resp.status != 200:
                            return
                        # v23: Check Content-Length before downloading body
                        cl = resp.headers.get('Content-Length')
                        if cl:
                            try:
                                if int(cl) > 1_000_000:  # Skip files > 1MB
                                    return
                            except (ValueError, TypeError):
                                pass
                        js_content = await safe_read_js(resp)  # W1.10: bounded read (5MB for JS)
                        if len(js_content) > 1_000_000:  # v23: was 5MB, too large
                            return

                        js_api_patterns = [
                            r'["\'](/api/[^"\']+)["\']',
                            r'["\'](/v\d+/[^"\']+)["\']',
                            r'["\'](/graphql)["\']',
                            r'fetch\(["\']([^"\']+)["\']',
                            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                            r'\.get\(["\']([^"\']+)["\']',
                            r'\.post\(["\']([^"\']+)["\']',
                            r'\.put\(["\']([^"\']+)["\']',
                            r'\.delete\(["\']([^"\']+)["\']',
                            r'url:\s*["\']([^"\']+)["\']',
                            r'baseURL:\s*["\']([^"\']+)["\']',
                            r'endpoint:\s*["\']([^"\']+)["\']',
                            r'/_next/data/[^"\']+(/[^"\']+)',
                            r'["\'](/\w*graphql\w*)["\']',
                        ]

                        for pattern in js_api_patterns:
                            for m in re.finditer(pattern, js_content, re.IGNORECASE):
                                endpoint = m.group(1)
                                skip = ['.js', '.css', '.png', '.jpg', '.svg',
                                       '.woff', '.ico', '.map', '.chunk', '.bundle']
                                if any(endpoint.endswith(s) for s in skip):
                                    continue
                                if not endpoint.startswith('/'):
                                    if not endpoint.startswith('http'):
                                        continue
                                if endpoint not in p.api_endpoints and endpoint not in new_endpoints:
                                    new_endpoints.append(endpoint)
                except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError):
                    pass

        await asyncio.gather(*[analyze_script(s, _ssl) for s in scripts_to_analyze])

    if new_endpoints:
        p.api_endpoints.extend(new_endpoints)
        p.api_endpoints = list(dict.fromkeys(p.api_endpoints))
        print(f"  {C.G}  JS Bundle Analysis: Found {len(new_endpoints)} new API endpoints{C.RS}")
        for ep in new_endpoints[:10]:
            print(f"  {C.Y}    {ep}{C.RS}")
    else:
        print(f"  {C.DM}  JS Bundle Analysis: No new API endpoints found{C.RS}")

    return profile
