"""VF_FINDER Engine — Orchestrates all reconnaissance phases.

This is the main engine that coordinates all finder modules
in the correct phase order for maximum efficiency.
"""
from __future__ import annotations
import asyncio
import ssl
import time
from typing import Any

import aiohttp


from vf_common import C, live_log, live_ok, live_warn, live_eta
from logging_config import get_logger
logger = get_logger(__name__)
from config.defaults import FINDER_ENGINE_TIMEOUT
from finder.site_profile import SiteProfile
from finder.http_fingerprint import http_fingerprint
from finder.tech_detector import analyze_content, detect_technologies
from finder.ssl_analyzer import analyze_ssl
from finder.dns_scanner import dns_enumerate, find_origin_ips
from finder.deep_scanner import deep_scan, performance_baseline, audit_security_headers, analyze_js_bundles
from finder.vf_attack_profile import AttackProfileGenerator
from finder.vf_finder_enhancer import FinderEnhancerRunner


def live_phase(phase_num: int, total: int, name: str):
    """Log a phase header with progress indicator"""
    pct = int((phase_num / total) * 100)
    logger.info(f"[{phase_num}/{total}] {name} ({pct}%)")


class VFFinder:
    """Reconnaissance Engine — coordinates all scan phases.

    Phase execution order:
      Phase 1: HTTP Fingerprinting (sequential — all others depend on it)
      Parallel Group A: Content → Tech Detection → WAF Probe → JS → Headers
      Parallel Group B: SSL/TLS Analysis
      Parallel Group C: DNS Enumeration → Subdomains
      Sequential: Deep Scan → Performance → Rate Probe → Origin IP → Cache
    """

    def __init__(self, url: str, deep: bool = False, dns_scan: bool = False,
                 subdomain_scan: bool = False, verify_ssl: bool = True):
        self.url = url
        self.deep = deep
        self.dns_scan = dns_scan
        self.subdomain_scan = subdomain_scan
        self.verify_ssl = verify_ssl  # S1b: Pass through from CLI
        self.profile = SiteProfile(url)
        self._html: str | None = None
        self._enhancer = FinderEnhancerRunner()

    async def scan(self) -> SiteProfile:
        """Run full reconnaissance scan with parallel phase groups."""
        t0 = time.time()
        logger.info(f"VF_FINDER — Reconnaissance Engine")
        logger.info(f"Target: {self.url}")
        logger.info(f"Deep: {'ON' if self.deep else 'OFF'} | DNS: {'ON' if self.dns_scan else 'OFF'} | Mode: Parallel Phases")

        # Calculate total phases for progress bar
        _total_phases = 5  # Always: HTTP Fingerprinting, Content Analysis, Technology Detection, Security Headers, Performance Baseline
        _total_phases += 1  # JS Bundle Analysis (may not run)
        if self.profile.scheme == 'https':
            _total_phases += 1  # SSL/TLS Analysis
        if self.dns_scan:
            _total_phases += 1  # DNS Enumeration
        if self.deep:
            _total_phases += 1  # Deep Path Scanning
        _total_phases += 1  # Origin IP Discovery (may not run)

        # ═══ Phase 1: HTTP Fingerprinting (sequential — all other phases depend on it) ═══
        logger.info("Starting Phase 1: HTTP Fingerprinting")
        live_phase(1, _total_phases, "HTTP Fingerprinting")
        self._html, self.profile = await http_fingerprint(self.url, self.profile, verify_ssl=self.verify_ssl)

        # ETA after HTTP Fingerprinting
        elapsed_so_far = time.time() - t0
        live_eta(elapsed_so_far, 1 / _total_phases, "scan")

        # ═══ Parallel Phase Groups ═══
        async def _content_pipeline():
            try:
                # Phase 2: Content Analysis
                live_phase(2, _total_phases, "[A] Content Analysis")
                self.profile = analyze_content(self._html or '', self.url, self.profile)

                # Phase 3: Technology Detection
                live_phase(3, _total_phases, "[A] Technology Detection")
                self.profile = detect_technologies(self._html or '', self.profile)

                # WAF Probe
                await self._run_finder_module('WAF Probe', self._enhance_waf_detection)

                # JS Bundle Analysis
                if self.profile.scripts:
                    live_phase(4, _total_phases, "[A] JS Bundle Analysis (API Discovery)")
                    self.profile = await analyze_js_bundles(self.url, self._html or '', self.profile, verify_ssl=self.verify_ssl)
                    await self._run_finder_module('JS Secret Scan', self._enhance_js_scan)
                else:
                    live_warn("JS Bundle Analysis: No scripts found")

                # Security Headers Audit
                live_phase(5, _total_phases, "[A] Security Headers Audit")
                self.profile = audit_security_headers(self.profile)
            except (aiohttp.ClientError, ValueError) as exc:
                live_warn(f"Content pipeline error: {type(exc).__name__}: {exc}")
                logger.warning(f"Content pipeline error: {type(exc).__name__}: {exc}", exc_info=True)

        async def _ssl_pipeline():
            try:
                if self.profile.scheme == 'https':
                    live_phase(6, _total_phases, "[B] SSL/TLS Analysis")
                    ssl_result = await analyze_ssl(
                        self.profile.host,
                        self.profile.port,
                        timeout=FINDER_ENGINE_TIMEOUT,  # W2.4
                        verify_ssl=self.verify_ssl,
                    )
                    # Map result dict to SiteProfile attributes
                    self.profile.ssl_enabled = ssl_result.get("ssl_enabled")
                    self.profile.ssl_info = {
                        "protocol": ssl_result.get("ssl_version", ""),
                        "cipher": ssl_result.get("cipher_name", "Unknown"),
                        "cipher_bits": ssl_result.get("cipher_bits", 0),
                        "issuer_org": ssl_result.get("issuer_org", "Unknown"),
                        "subject_cn": ssl_result.get("subject_cn", "Unknown"),
                        "valid_from": ssl_result.get("valid_from", "Unknown"),
                        "valid_to": ssl_result.get("expire_date", "Unknown"),
                    }
                else:
                    live_warn("SSL: Not HTTPS, skipping")
            except (ssl.SSLError, OSError) as exc:
                live_warn(f"SSL pipeline error: {type(exc).__name__}: {exc}")
                logger.warning(f"SSL pipeline error: {type(exc).__name__}: {exc}", exc_info=True)

        async def _dns_pipeline():
            try:
                if self.dns_scan:
                    live_phase(7, _total_phases, "[C] DNS Enumeration")
                    self.profile = await dns_enumerate(self.profile, subdomain_scan=self.subdomain_scan, verify_ssl=self.verify_ssl)
                    await self._run_finder_module('Subdomain Bruteforce', self._enhance_subdomain_scan)
                else:
                    live_warn("DNS: Skipped (use --dns to enable)")
            except (OSError, ValueError) as exc:
                live_warn(f"DNS pipeline error: {type(exc).__name__}: {exc}")
                logger.warning(f"DNS pipeline error: {type(exc).__name__}: {exc}", exc_info=True)

        logger.info("Launching parallel phase groups (A: Content, B: SSL, C: DNS)")
        pipeline_results = await asyncio.gather(
            _content_pipeline(),
            _ssl_pipeline(),
            _dns_pipeline(),
            return_exceptions=True
        )

        group_names = ['Content', 'SSL', 'DNS']
        for i, result in enumerate(pipeline_results):
            if isinstance(result, Exception):
                live_warn(f"{group_names[i]} pipeline unhandled error: {result}")
                logger.error(f"{group_names[i]} pipeline unhandled error: {result}", exc_info=True)

        elapsed_so_far = time.time() - t0
        live_eta(elapsed_so_far, 7 / _total_phases, "scan")

        # ═══ Sequential Phases — v15: Performance + Rate + Cache run in parallel ═══
        if self.deep:
            logger.info("Starting Phase 8: Deep Path Scanning")
            live_phase(8, _total_phases, "Deep Path Scanning")
            self.profile = await deep_scan(self.url, self.profile, verify_ssl=self.verify_ssl)
            await self._run_finder_module('Directory Fuzzing', self._enhance_dir_fuzz)
        else:
            live_warn("Deep Scan: Skipped (use --deep to enable)")

        # v15: Run Performance Baseline, Rate Probe, and Cache Analysis IN PARALLEL
        logger.info("Starting Phase 9: Performance Baseline + Rate Probe + Cache (parallel)")
        live_phase(9, _total_phases, "Performance + Rate + Cache (parallel)")

        async def _perf_pipeline():
            self.profile = await performance_baseline(self.url, self.profile, verify_ssl=self.verify_ssl)
            await self._run_finder_module('Rate Limit Probe', self._enhance_rate_probe)

        await asyncio.gather(
            _perf_pipeline(),
            self._run_finder_module('Cache Analysis', self._enhance_cache_analysis),
            return_exceptions=True
        )

        elapsed_so_far = time.time() - t0
        live_eta(elapsed_so_far, 9 / _total_phases)

        # Phase 10: Origin IP Discovery
        if self.profile.waf or self.profile.cdn:
            logger.info("Starting Phase 10: Origin IP Discovery (CDN Bypass)")
            live_phase(10, _total_phases, "Origin IP Discovery (CDN Bypass)")
            self.profile = await find_origin_ips(self.url, self.profile, verify_ssl=self.verify_ssl)
        else:
            live_warn("Origin IP: Skipped (no CDN/WAF detected)")

        # Generate Attack Profile
        logger.info("Generating attack profile")
        self._generate_attack_profile()

        self.profile.scan_time = time.time() - t0
        logger.info(f"Scan completed in {self.profile.scan_time:.1f}s")

        return self.profile

    async def _run_finder_module(self, name: str, coro_fn):
        """Safely run a finder enhancement module. Delegates to FinderEnhancerRunner."""
        await self._enhancer._run_module(name, coro_fn())

    # ─── Finder Module Enhancements ─────────────────────────────────────────

    async def _enhance_waf_detection(self):
        """Enhance WAF detection. Delegates to FinderEnhancerRunner."""
        await self._enhancer.enhance_waf(self.profile, self.url, self.verify_ssl)

    async def _enhance_js_scan(self):
        """Enhance JS analysis. Delegates to FinderEnhancerRunner."""
        await self._enhancer.enhance_js(self.profile, self.url, self.verify_ssl)

    async def _enhance_subdomain_scan(self):
        """Enhance subdomain enumeration. Delegates to FinderEnhancerRunner."""
        await self._enhancer.enhance_subdomain(self.profile, self.verify_ssl)

    async def _enhance_dir_fuzz(self):
        """Enhance deep scan with directory fuzzer. Delegates to FinderEnhancerRunner."""
        await self._enhancer.enhance_dir_fuzz(self.profile, self.url, self.verify_ssl)

    async def _enhance_rate_probe(self):
        """Enhance rate limit detection. Delegates to FinderEnhancerRunner."""
        await self._enhancer.enhance_rate(self.profile, self.url, self.verify_ssl)

    async def _enhance_cache_analysis(self):
        """Analyze CDN caching behavior. Delegates to FinderEnhancerRunner."""
        await self._enhancer.enhance_cache(self.profile, self.url, self.verify_ssl)

    # ─── Attack Profile Generation (delegated) ──────────────────────────────

    def _generate_attack_profile(self) -> dict[str, Any]:
        """Generate a customized attack profile based on detected technologies.

        Delegates to AttackProfileGenerator for profile generation logic.
        """
        generator = AttackProfileGenerator(self.profile, self._html or "", self.verify_ssl)
        profile = generator.generate()
        self._surgical_analysis = getattr(generator, '_surgical_analysis', [])
        return profile
