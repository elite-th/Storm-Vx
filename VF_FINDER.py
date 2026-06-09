#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF_FINDER — Reconnaissance Engine CLI                                ║
║     Part of the VF (Vector-Finder) Architecture                         ║
║                                                                           ║
║  Scans a target website and builds a complete technology profile:         ║
║  - Server fingerprinting (Apache, Nginx, IIS, LiteSpeed, etc.)           ║
║  - Backend detection (ASP.NET, PHP, Node.js, Python, Java, Ruby, etc.)   ║
║  - WAF identification (Cloudflare, ArvanCloud, ModSecurity, etc.)        ║
║  - CMS detection (WordPress, Drupal, Joomla, DNN, etc.)                  ║
║  - Framework detection (React, Angular, Vue, Laravel, Django, etc.)      ║
║  - SSL/TLS analysis                                                       ║
║  - DNS & subdomain enumeration                                            ║
║  - Content analysis (forms, hidden fields, endpoints)                     ║
║  - Performance baseline (response times, payload sizes, rate limits)      ║
║  - Security headers audit                                                 ║
║                                                                           ║
║  Output: VF_PROFILE.json → Feed to VF_TESTER for adaptive attack         ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage:
  python VF_FINDER.py https://target.com
  python VF_FINDER.py https://target.com --deep
  python VF_FINDER.py https://target.com --output my_profile.json
  python VF_FINDER.py https://target.com --dns --subdomains

Requirements:
  pip install aiohttp httpx beautifulsoup4
  Optional: pip install dnspython (for DNS enumeration)
"""
from __future__ import annotations

import asyncio
import argparse
import json
import os
import platform
import sys
import time
from typing import Dict
from urllib.parse import urlparse

# Ensure UTF-8 console on Windows (migrated from _bootstrap.py)
from logging_config import ensure_utf8_console, get_logger
ensure_utf8_console()

logger = get_logger(__name__)

from vf_common import C
from vf_common import T, set_theme
from ui.terminal import TerminalUI
from ui.report import ScanReporter
from finder.engine import VFFinder
from finder.site_profile import SiteProfile

IS_WINDOWS = platform.system() == 'Windows'

if IS_WINDOWS:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except (OSError, AttributeError, RuntimeError) as e:
        logger.debug(f"Windows console mode setup failed (non-critical): {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Report Renderer — Delegates to ui.report.ScanReporter
# ═══════════════════════════════════════════════════════════════════════════════

def render_report(profile: SiteProfile):
    """Render a beautiful hacker-style scan report to the terminal.

    Delegates to ScanReporter for UI/logging separation.
    Kept as a module-level function for backward compatibility.
    """
    from config.defaults import UI_THEME, DASHBOARD_WIDTH
    ui = TerminalUI(UI_THEME, DASHBOARD_WIDTH)
    reporter = ScanReporter(ui)
    reporter.render(profile)


# ═══════════════════════════════════════════════════════════════════════════════
# Cache System — Save/Load scan results per domain
# ═══════════════════════════════════════════════════════════════════════════════

CACHE_FILE = "VF_CACHE.json"

# S3: Async-safe cache lock and debounce
_cache_lock: asyncio.Lock | None = None

def _get_cache_lock() -> asyncio.Lock:
    """Lazy-initialize cache lock within running event loop."""
    global _cache_lock
    if _cache_lock is None:
        _cache_lock = asyncio.Lock()
    return _cache_lock
_last_cache_write: float = 0.0
_CACHE_DEBOUNCE_SECONDS: float = 5.0
_CACHE_RETRY_ATTEMPTS: int = 2
_CACHE_RETRY_DELAY: float = 0.5


def _extract_domain(url: str) -> str:
    """Extract domain from URL for cache key"""
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0].lower()
    return domain[4:] if domain.startswith('www.') else domain


async def _cache_read_with_retry(filepath: str) -> Dict | None:
    """Read cache file with retry logic (C10).

    Retries up to _CACHE_RETRY_ATTEMPTS times with _CACHE_RETRY_DELAY
    between attempts on transient I/O errors.
    """
    for attempt in range(_CACHE_RETRY_ATTEMPTS + 1):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError) as e:
            # Corrupted file — no point retrying
            print(f"  {C.Y}[CACHE] Cache file corrupted, ignoring: {e}{C.RS}")
            return None
        except (OSError, IOError) as e:
            if attempt < _CACHE_RETRY_ATTEMPTS:
                print(f"  {C.Y}[CACHE] Read failed (attempt {attempt + 1}), retrying...{C.RS}")
                await asyncio.sleep(_CACHE_RETRY_DELAY)
            else:
                print(f"  {C.Y}[CACHE] Cannot read cache file after {attempt + 1} attempts: {e}{C.RS}")
                return None
    return None


async def _cache_write_with_retry(filepath: str, data: Dict) -> bool:
    """Write cache file with retry logic (C10).

    Retries up to _CACHE_RETRY_ATTEMPTS times with _CACHE_RETRY_DELAY
    between attempts on transient I/O errors.
    """
    for attempt in range(_CACHE_RETRY_ATTEMPTS + 1):
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except (OSError, IOError) as e:
            if attempt < _CACHE_RETRY_ATTEMPTS:
                print(f"  {C.Y}[CACHE] Write failed (attempt {attempt + 1}), retrying...{C.RS}")
                await asyncio.sleep(_CACHE_RETRY_DELAY)
            else:
                print(f"  {C.Y}[CACHE] Failed to save cache after {attempt + 1} attempts: {e}{C.RS}")
                return False
    return False


async def load_cached_profile(url: str) -> Dict | None:
    """Check if we have a cached scan result for this domain.

    S3: Uses asyncio.Lock for async-safe file access.
    C10: Uses retry logic for transient I/O errors.
    """
    async with _get_cache_lock():
        domain = _extract_domain(url)
        if not os.path.exists(CACHE_FILE):
            return None
        cache = await _cache_read_with_retry(CACHE_FILE)
        if cache is None:
            return None
        entry = cache.get(domain)
        if not entry:
            return None
        cached_time = entry.get('cached_at', 0)
        age_hours = (time.time() - cached_time) / 3600
        if age_hours > 24:
            print(f"  {C.Y}[CACHE] Cached data for {domain} is {age_hours:.1f}h old (expired){C.RS}")
            return None
        return entry


async def save_to_cache(url: str, profile_data: Dict):
    """Save scan result to cache file, keyed by domain.

    S3: Uses asyncio.Lock for async-safe file access.
    S3: Debounces writes — won't write more than once per 5 seconds.
    C10: Uses retry logic for transient I/O errors.
    """
    global _last_cache_write
    async with _get_cache_lock():
        # Debounce: skip write if we just wrote within the debounce window
        now = time.time()
        if now - _last_cache_write < _CACHE_DEBOUNCE_SECONDS:
            return
        domain = _extract_domain(url)
        cache = {}
        if os.path.exists(CACHE_FILE):
            cache = await _cache_read_with_retry(CACHE_FILE) or {}
        cache[domain] = {
            **profile_data,
            'cached_at': time.time(),
            'cached_domain': domain,
        }
        success = await _cache_write_with_retry(CACHE_FILE, cache)
        if success:
            _last_cache_write = time.time()
            # SEC-06: Restrict cache file permissions to owner-only
            try:
                import stat as _stat
                os.chmod(CACHE_FILE, _stat.S_IRUSR | _stat.S_IWUSR)
            except OSError:
                pass


def show_cached_info(entry: Dict):
    """Display cached scan summary for user"""
    p = entry
    age_hours = (time.time() - p.get('cached_at', 0)) / 3600
    domain = p.get('cached_domain', '?')

    print(f"\n  {C.BD}{C.Y}╔════════════════════════════════════════════════════════════╗{C.RS}")
    print(f"  {C.BD}{C.Y}║            CACHED SCAN FOUND                             ║{C.RS}")
    print(f"  {C.BD}{C.Y}╚════════════════════════════════════════════════════════════╝{C.RS}")
    print(f"  {C.W}  Domain   : {C.G}{domain}{C.RS}")
    print(f"  {C.W}  Server   : {C.CY}{p.get('server', 'unknown')}{C.RS}")
    print(f"  {C.W}  CDN      : {C.Y}{p.get('cdn') or 'none'}{C.RS}")
    print(f"  {C.W}  WAF      : {C.R}{p.get('waf') or 'none'}{C.RS}")
    print(f"  {C.W}  Strategy : {C.M}{p.get('attack_profile', {}).get('recommended_strategy', '?')}{C.RS}")
    print(f"  {C.W}  Vectors  : {C.CY}{', '.join(p.get('attack_profile', {}).get('attack_vectors', []))}{C.RS}")
    print(f"  {C.W}  Origins  : {C.G}{len(p.get('origin_ips', []))} IPs{C.RS}", end='')
    if p.get('origin_ips'):
        print(f"  {C.DM}{p['origin_ips'][:3]}{C.RS}")
    else:
        print(f"  {C.Y}(not found){C.RS}")
    print(f"  {C.W}  Age      : {age_hours:.1f} hours ago{C.RS}")
    print(f"  {C.W}  Scan Time: {p.get('scan_time', 0):.1f}s{C.RS}")
    techs = [t['name'] for t in p.get('technologies', []) if t.get('confidence', 0) > 0.2]
    if techs:
        print(f"  {C.W}  Tech     : {C.DM}{', '.join(techs[:8])}{C.RS}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="VF_FINDER — Reconnaissance Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Output: VF_PROFILE.json (feed to VF_TESTER)\n\n"
                "If no URL is provided, you will be prompted to enter one interactively.\n")
    p.add_argument("url", nargs="?", default=None, help="Target URL to scan (will prompt if omitted)")
    p.add_argument("--deep", action="store_true", help="Deep path scanning")
    p.add_argument("--dns", action="store_true", help="DNS enumeration")
    p.add_argument("--subdomains", action="store_true", help="Subdomain enumeration")
    p.add_argument("--output", default="VF_PROFILE.json", help="Output file (default: VF_PROFILE.json)")
    p.add_argument("--no-report", action="store_true", help="Skip terminal report (JSON only)")
    p.add_argument("--fresh", action="store_true", help="Force fresh scan (ignore cache)")
    p.add_argument("--verify-ssl", action="store_true", help="Enable SSL certificate verification (default: disabled for testing)")
    return p.parse_args()


async def main():
    args = parse_args()

    url = args.url
    if not url:
        print(f"\n{'='*72}")
        print(f"  {C.BD}{C.R}VF_FINDER — Reconnaissance Engine{C.RS}")
        print(f"{'='*72}")
        url = input(f"  {C.CY}Enter target URL: {C.RS}").strip()
        if not url:
            print(f"  {C.R}[ERROR] No URL provided. Exiting.{C.RS}")
            return
    if not url.startswith("http"):
        url = "https://" + url

    # Validate target URL
    from vf_validator import validate_target_url, ValidationError
    try:
        url, url_warnings = validate_target_url(url)
        for w in url_warnings:
            print(f"  {C.Y}[WARN] {w}{C.RS}")
    except ValidationError as e:
        print(f"  {C.R}[ERROR] Invalid target: {e}{C.RS}")
        return

    # ═══ CACHE CHECK ═══
    profile = None
    if not args.fresh:
        cached = await load_cached_profile(url)
        if cached:
            show_cached_info(cached)
            print(f"  {C.CY}[?] Use cached scan result?{C.RS}")
            print(f"      {C.G}Y{C.RS} = Use cache (skip scan)")
            print(f"      {C.R}N{C.RS} = Fresh scan (rescan target)")
            choice = input(f"  {C.Y}> {C.RS}").strip().upper()
            if choice != 'N':
                print(f"\n  {C.G}[CACHE] Using cached scan for {_extract_domain(url)}{C.RS}")
                profile_data = cached
                profile_data.pop('cached_at', None)
                profile_data.pop('cached_domain', None)
                output_path = args.output
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(profile_data, f, ensure_ascii=False, indent=2)
                # SEC-06: Restrict profile file permissions to owner-only
                try:
                    import stat as _stat
                    os.chmod(output_path, _stat.S_IRUSR | _stat.S_IWUSR)
                except OSError:
                    pass
                print(f"  {C.G}Profile saved to: {output_path}{C.RS}")

                if not args.no_report:
                    tmp_profile = SiteProfile(url)
                    for k, v in profile_data.items():
                        if hasattr(tmp_profile, k):
                            try:
                                setattr(tmp_profile, k, v)
                            except (AttributeError, TypeError, ValueError):
                                pass
                    render_report(tmp_profile)

                print(f"  {C.CY}Feed this file to VF_TESTER: python VF_TESTER.py --profile {output_path}{C.RS}")
                return
            else:
                print(f"  {C.Y}[FINDER] Starting fresh scan...{C.RS}")

    # ═══ RUN FINDER SCAN ═══
    # S1b: Pass verify_ssl flag from CLI to engine
    finder = VFFinder(url, deep=args.deep, dns_scan=args.dns,
                      subdomain_scan=args.subdomains,
                      verify_ssl=args.verify_ssl)
    profile = await finder.scan()

    # Render report
    if not args.no_report:
        render_report(profile)

    # Save JSON profile — flat structure so VFTester can read it directly
    output_data = profile.to_dict()
    output_path = args.output
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    # SEC-06: Restrict profile file permissions to owner-only
    try:
        import stat as _stat
        os.chmod(output_path, _stat.S_IRUSR | _stat.S_IWUSR)
    except OSError:
        pass
    print(f"  {C.G}Profile saved to: {output_path}{C.RS}")

    # Save to cache for future runs
    await save_to_cache(url, output_data)
    print(f"  {C.G}Cache saved to: {CACHE_FILE}{C.RS}")

    print(f"  {C.CY}Feed this file to VF_TESTER: python VF_TESTER.py --profile {output_path}{C.RS}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
