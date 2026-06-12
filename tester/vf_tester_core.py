#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VF_TESTER core — VFTester base class with init, properties, and lifecycle helpers.

Split from VF_TESTER.py for Law 14 compliance (500-line limit).
This module contains the core VFTesterCore class with the constructor,
all properties, stop/start lifecycle, and helper methods.
Strategy and dashboard loop methods are in vf_tester_strategy.py.
"""

from __future__ import annotations

import asyncio
import os
import platform
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Ensure UTF-8 console on Windows (migrated from _bootstrap.py)
from logging_config import ensure_utf8_console
# BUG-048: ensure_utf8_console() moved into main() to prevent side effects
# when importing this module for testing.

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

# Phase 1: Effectiveness tracking + connection pool lifecycle
from tester.plugin_effectiveness import PluginEffectivenessTracker
from engine.connection_pool import PoolLifecycleManager
# Phase 2: Smart timeout
from tester.smart_timeout import SmartTimeoutEngine


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
    from exceptions import ConfigurationError as _ConfigurationError
    raise _ConfigurationError(
        f"Missing required dependencies: {', '.join(_missing)}. "
        f"Install with: pip install {' '.join(_missing)}"
    )

# ═══ Plugin System ═══
from plugin_system import PluginRegistry, PluginInterface, AttackContext, AttackExtras

# VFTesterCore — Base class with init, properties, and lifecycle helpers

__all__ = ["VFTesterCore"]


class VFTesterCore:
    """
    VFTester base class — constructor, properties, and lifecycle helpers.

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

    Strategy and dashboard loop methods are in VFTesterStrategy
    (vf_tester_strategy.py). The public VFTester class inherits from
    both VFTesterStrategy and VFTesterCore.
    """

    def __init__(self, profile_path: str | None = None,
                 target_url: str | None = None,
                 behavior_mode: str = "default"):
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
        # BUG-022 FIX: Create behavior prober based on mode
        self._behavior_mode = behavior_mode
        self._behavior_prober = None
        try:
            from evasion.behavior_prober import create_behavior_prober
            self._behavior_prober = create_behavior_prober(
                mode=behavior_mode,
                url=self.url,
                page_targets=self.page_targets or [],
                resource_targets=self.resource_targets or [],
            )
        except ImportError:
            logger.debug("[VF-EVASION] behavior_prober not available, using defaults")

        self._evasion = _EvasionManagerStub(
            self.domain, self.url, self.page_targets or [], self.resource_targets or [],
            self.enable_header_random, self.enable_ua_rotation,
            behavior_prober=self._behavior_prober,  # BUG-022 FIX: Wire prober into evasion
        )
        self._evasion_active = self._evasion.is_active
        if self._evasion_active:
            mode_str = f" (behavior: {behavior_mode})" if behavior_mode != "default" else ""
            logger.info(f"[VF-EVASION] Evasion active (UA rotation + header randomization){mode_str}")

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

        # Phase 2: Auto-select toggle (default: enabled)
        self._auto_select_enabled: bool = True

        # Phase 1: Create effectiveness tracker and wire to orchestrator + scaling engine
        if self._auto_select_enabled:
            self._effectiveness_tracker = PluginEffectivenessTracker()
            self._orchestrator.effectiveness_tracker = self._effectiveness_tracker
        else:
            self._effectiveness_tracker = None  # type: ignore[assignment]

        # Phase 2: Smart timeout engine
        self._smart_timeout = SmartTimeoutEngine()

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
            effectiveness_tracker=self._effectiveness_tracker,  # Phase 2
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
            effectiveness_tracker=self._effectiveness_tracker,  # Phase 1
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
    def effectiveness_tracker(self) -> PluginEffectivenessTracker | None:
        """Phase 1: Access the effectiveness tracker."""
        return self._effectiveness_tracker

    @property
    def auto_select_enabled(self) -> bool:
        """Phase 2: Whether auto-select effectiveness tracking is enabled."""
        return self._auto_select_enabled

    @auto_select_enabled.setter
    def auto_select_enabled(self, value: bool) -> None:
        """Phase 2: Toggle auto-select on/off. Re-creates tracker on enable."""
        self._auto_select_enabled = value
        if value:
            if self._effectiveness_tracker is None:
                self._effectiveness_tracker = PluginEffectivenessTracker()
                self._orchestrator.effectiveness_tracker = self._effectiveness_tracker
                if hasattr(self, '_dashboard') and self._dashboard is not None:
                    self._dashboard._effectiveness_tracker = self._effectiveness_tracker
                if hasattr(self, '_scaling_engine') and self._scaling_engine is not None:
                    self._scaling_engine._effectiveness_tracker = self._effectiveness_tracker
        else:
            if self._effectiveness_tracker is not None:
                self._effectiveness_tracker.reset()
            self._effectiveness_tracker = None
            self._orchestrator.effectiveness_tracker = None
            if hasattr(self, '_dashboard') and self._dashboard is not None:
                self._dashboard._effectiveness_tracker = None
            if hasattr(self, '_scaling_engine') and self._scaling_engine is not None:
                self._scaling_engine._effectiveness_tracker = None

    @property
    def smart_timeout(self) -> SmartTimeoutEngine:
        """Phase 2: Access the smart timeout engine."""
        return self._smart_timeout

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
