"""Finder enhancement module runner.

Runs optional finder enhancement modules with safe error handling.
Extracted from engine.py for separation of concerns.

Architecture: Phase 2 — FinderEnhancerRunner Extraction
"""

from __future__ import annotations

import asyncio
from typing import Any

from vf_common import live_ok, live_warn
from logging_config import get_logger
from config.defaults import MAX_DISCOVERED_ENDPOINTS

logger = get_logger(__name__)


class FinderEnhancerRunner:
    """Run optional finder enhancement modules safely.

    Each enhancement method imports its target module lazily (so missing
    optional modules don't crash the scan), runs the enhancement, and
    updates the profile in-place.  The ``_run_module`` wrapper ensures
    that failures are logged without aborting the overall scan.
    """

    async def _run_module(self, name: str, coro: Any) -> None:
        """Run a single module with error handling.

        Catches all exceptions so the main scan continues even if an
        optional enhancement module fails or is missing.

        Args:
            name: Human-readable module name for log messages.
            coro: Awaitable (coroutine) to execute safely.
        """
        try:
            await coro
        except Exception as exc:
            live_warn(f"{name}: Module error — {type(exc).__name__}: {exc}")
            logger.warning(
                f"Finder module {name} error: {type(exc).__name__}: {exc}",
                exc_info=True,
            )

    # ─── Individual Enhancement Methods ──────────────────────────────────

    async def enhance_waf(self, profile: Any, url: str,
                          verify_ssl: bool = True) -> None:
        """Enhance WAF detection using vf_waf_probe module.

        Args:
            profile: SiteProfile to update with WAF findings.
            url: Target URL.
            verify_ssl: Whether to verify SSL certificates.
        """
        try:
            from finder.vf_waf_probe import WAFProber
        except ImportError:
            return
        prober = WAFProber(url, waf_name=profile.waf or "", verify_ssl=verify_ssl)
        result = await prober.run()
        # v30: Always update WAF from prober result (it's more thorough than
        # tech_detector). Old logic only updated if profile.waf was empty,
        # meaning tech_detector's less-accurate result was never overridden.
        # Also filter out "Unknown" — prober returns "None" when no WAF found.
        waf_result = result.get("waf_name", "")
        if waf_result and waf_result != "Unknown":
            profile.waf = waf_result
            if waf_result != "None":
                live_ok(f"WAF Probe identified: {waf_result}")
            else:
                live_ok("WAF Probe: No WAF detected")
        if result.get("bypass_hints"):
            profile.attack_profile.setdefault("waf_bypass_hints", result["bypass_hints"])

    async def enhance_js(self, profile: Any, url: str,
                         verify_ssl: bool = True) -> None:
        """Enhance JS analysis using vf_js_scanner module.

        Args:
            profile: SiteProfile with scripts attribute; updated with
                     discovered API keys, hidden endpoints, and secrets.
            url: Target URL.
            verify_ssl: Whether to verify SSL certificates.
        """
        try:
            from finder.vf_js_scanner import JSSecretScanner
        except ImportError:
            return
        scanner = JSSecretScanner(url, profile.scripts, verify_ssl=verify_ssl)
        result = await scanner.run()
        if result.get("api_keys"):
            profile.attack_profile.setdefault("js_api_keys", result["api_keys"])
        if result.get("hidden_endpoints"):
            for ep in result["hidden_endpoints"]:
                ep_url = ep.get("endpoint", ep.get("url", ""))
                if ep_url and ep_url not in profile.api_endpoints:
                    if len(profile.api_endpoints) < MAX_DISCOVERED_ENDPOINTS:
                        profile.api_endpoints.append(ep_url)
                    elif len(profile.api_endpoints) == MAX_DISCOVERED_ENDPOINTS:
                        logger.warning(f"BUG-043: Truncating api_endpoints at {MAX_DISCOVERED_ENDPOINTS}")
        if result.get("secrets"):
            profile.attack_profile.setdefault("js_secrets", result["secrets"])

    async def enhance_subdomain(self, profile: Any,
                                verify_ssl: bool = True) -> None:
        """Enhance subdomain enumeration using vf_subdomain module.

        Args:
            profile: SiteProfile with domain, subdomains, and origin_ips
                     attributes; updated with discovered subdomains/IPs.
            verify_ssl: Whether to verify SSL certificates.
        """
        try:
            from finder.vf_subdomain import SubdomainBruteforcer
        except ImportError:
            return
        bruteforcer = SubdomainBruteforcer(profile.domain, verify_ssl=verify_ssl)
        result = await bruteforcer.run()
        new_subs = result.get("subdomains", [])
        if new_subs:
            existing = set(profile.subdomains)
            added = [s for s in new_subs if s not in existing]
            if added:
                profile.subdomains.extend(added)
                live_ok(f"Subdomain bruteforce found {len(added)} new subdomains")
        new_origin_ips = result.get("new_origin_ips", [])
        if new_origin_ips:
            existing_ips = set(profile.origin_ips)
            for ip in new_origin_ips:
                if ip not in existing_ips:
                    profile.origin_ips.append(ip)

    async def enhance_dir_fuzz(self, profile: Any, url: str,
                               verify_ssl: bool = True) -> None:
        """Enhance deep scan using vf_dir_fuzzer module.

        Args:
            profile: SiteProfile with found_paths and attack_profile
                     attributes; updated with discovered paths/files.
            url: Target URL.
            verify_ssl: Whether to verify SSL certificates.
        """
        try:
            from finder.vf_dir_fuzzer import DirectoryFuzzer
        except ImportError:
            return
        fuzzer = DirectoryFuzzer(url, verify_ssl=verify_ssl)
        result = await fuzzer.run()
        found = result.get("found_paths", [])
        if found:
            existing_paths = {p.get("path") for p in profile.found_paths}
            for p in found:
                if p.get("path") not in existing_paths:
                    profile.found_paths.append(p)
        interesting = result.get("interesting_files", [])
        if interesting:
            profile.attack_profile.setdefault("interesting_files", interesting)

    async def enhance_rate(self, profile: Any, url: str,
                           verify_ssl: bool = True) -> None:
        """Enhance rate limit detection using vf_rate_probe module.

        Args:
            profile: SiteProfile with rate_limit_detected, rate_limit_threshold,
                     and attack_profile attributes; updated with findings.
            url: Target URL.
            verify_ssl: Whether to verify SSL certificates.
        """
        try:
            from finder.vf_rate_probe import RateLimitProber
        except ImportError:
            return
        prober = RateLimitProber(url, verify_ssl=verify_ssl)
        result = await prober.run()
        if result.get("rate_limit_detected"):
            profile.rate_limit_detected = True
            profile.rate_limit_threshold = result.get("threshold_rps")
            live_ok(f"Rate limit detected: {result.get('threshold_rps')} RPS threshold")
            profile.attack_profile.setdefault("rate_limit_details", result)

    async def enhance_cache(self, profile: Any, url: str,
                            verify_ssl: bool = True) -> None:
        """Analyze CDN caching behavior using vf_cache_analyzer module.

        Args:
            profile: SiteProfile with scripts, images, and attack_profile
                     attributes; updated with cache deception findings.
            url: Target URL.
            verify_ssl: Whether to verify SSL certificates.
        """
        try:
            from finder.vf_cache_analyzer import CacheAnalyzer
        except ImportError:
            return
        analyzer = CacheAnalyzer(
            url, profile.scripts, profile.images, verify_ssl=verify_ssl,
            session=getattr(self, '_shared_session', None),  # BUG-031: pass shared session
        )
        result = await analyzer.run()
        if result.get("deception_possible"):
            profile.attack_profile.setdefault("cache_deception", result)
            live_warn(
                f"Cache deception possible: {len(result.get('deception_urls', []))} URLs"
            )
        if result.get("cacheable_endpoints"):
            profile.attack_profile.setdefault(
                "cacheable_endpoints", result["cacheable_endpoints"]
            )
