#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PluginOrchestrator — Extracted from VFTester God Class.

Handles plugin selection, context building, plugin launching,
and worker scaling delegation.

Worker balancing and auto-disable logic is delegated to WorkerBalancer
(vf_worker_balancer.py) for Law 14 compliance (500-line limit).

This module is responsible for:
  - Selecting which plugins to activate based on attack vectors
  - Building AttackContext objects for each plugin
  - Launching plugins as async tasks
  - Delegating worker scaling and auto-disable to WorkerBalancer
"""

from __future__ import annotations

import asyncio
import ssl
import aiohttp
from typing import Dict, List, Any, Callable, Optional, Union
from urllib.parse import urlparse


from logging_config import get_logger
logger = get_logger(__name__)

from vf_common import C
from plugin_system import PluginRegistry, PluginInterface, AttackContext, AttackExtras
from finder.site_profile import SiteProfile
from tester.plugin_effectiveness import PluginEffectivenessTracker
from tester.vf_worker_balancer import WorkerBalancer, ORIGIN_PLUGINS, STRICT_ORIGIN_PLUGINS, VECTOR_PLUGIN_MAP

# Phase 4: Observability imports (safe no-ops when disabled)
from observability.metrics import metrics as _metrics
from observability.metrics_ext import ext_metrics


class PluginOrchestrator:
    """Manages plugin lifecycle: selection, launching, and scaling.

    Extracted from VFTester to separate plugin orchestration concerns
    from the main attack coordination logic.

    The orchestrator holds the plugin registry, active/disabled plugin
    tracking, and plugin task management. VFTester delegates plugin
    operations to this class.

    Worker balancing (compute_plugin_workers, scale_all_plugins,
    scale_plugins, auto_disable_plugin, redistribute_workers) is
    delegated to WorkerBalancer for Law 14 compliance.
    """

    def __init__(self, registry: PluginRegistry,
                 initial_workers: int = 5,
                 max_workers: int = 5000):
        """Initialize the plugin orchestrator.

        Args:
            registry: PluginRegistry instance with discovered plugins.
            initial_workers: Default initial worker count.
            max_workers: Maximum total worker count.
        """
        self._registry = registry
        self._initial_workers = initial_workers
        self._max_workers = max_workers
        self._active_plugins: Dict[str, PluginInterface] = {}
        self._disabled_plugins: Dict[str, int] = {}  # v19: plugin_name → error_count at disable time
        self._plugin_tasks: List[asyncio.Task] = []
        self._total_workers: int = 0
        self._effectiveness_tracker: PluginEffectivenessTracker | None = None
        self._balancer = WorkerBalancer(self)

    @property
    def registry(self) -> PluginRegistry:
        """Access the plugin registry."""
        return self._registry

    @property
    def active_plugins(self) -> Dict[str, PluginInterface]:
        """Currently active plugins."""
        return self._active_plugins

    @property
    def disabled_plugins(self) -> Dict[str, int]:
        """Currently disabled plugins with error counts."""
        return self._disabled_plugins

    @property
    def plugin_tasks(self) -> List[asyncio.Task]:
        """Running plugin tasks."""
        return self._plugin_tasks

    @property
    def total_workers(self) -> int:
        """Total workers across all active plugins."""
        return self._total_workers

    @total_workers.setter
    def total_workers(self, value: int):
        self._total_workers = value

    @property
    def effectiveness_tracker(self) -> PluginEffectivenessTracker | None:
        """Phase 0: Plugin effectiveness tracker."""
        return self._effectiveness_tracker

    @effectiveness_tracker.setter
    def effectiveness_tracker(self, tracker: PluginEffectivenessTracker | None) -> None:
        self._effectiveness_tracker = tracker

    # ─── Delegated Worker Balancer Methods ───────────────────────────────

    def compute_plugin_workers(self, plugin_name: str, total_max: int,
                                origin_ips: List[str]) -> int:
        """Compute how many workers to assign to a plugin.

        Delegated to WorkerBalancer. See vf_worker_balancer.py for details.
        """
        return self._balancer.compute_plugin_workers(plugin_name, total_max, origin_ips)

    def scale_all_plugins(self, delta: int) -> int:
        """Scale ALL active plugins (including origin) by delta.

        Delegated to WorkerBalancer. See vf_worker_balancer.py for details.
        """
        return self._balancer.scale_all_plugins(delta)

    def scale_plugins(self, delta: int) -> int:
        """Scale HTTP plugins by delta (for scaling UP).

        Delegated to WorkerBalancer. See vf_worker_balancer.py for details.
        """
        return self._balancer.scale_plugins(delta)

    def auto_disable_plugin(self, plugin_name: str, reason: str = "high_error_rate") -> bool:
        """Phase 0: Auto-disable a plugin with high error rate.

        Delegated to WorkerBalancer. See vf_worker_balancer.py for details.
        """
        return self._balancer.auto_disable_plugin(plugin_name, reason)

    def redistribute_workers(self, from_plugin: str, to_plugins: List[str], workers: int) -> None:
        """Phase 0: Move workers from a disabled plugin to active ones.

        Delegated to WorkerBalancer. See vf_worker_balancer.py for details.
        """
        return self._balancer.redistribute_workers(from_plugin, to_plugins, workers)

    # ─── Core Orchestrator Methods ───────────────────────────────────────

    def select_plugins(self, vectors: List[str],
                       origin_ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Select which plugins to activate based on attack vectors.

        F5-06: DEPRECATED (Tier 3) plugins are still loaded but flagged
        with minimum workers. The effectiveness tracker will further
        reduce their allocation in FOCUS phase.
        """
        self._registry.discover()

        # Determine which plugin names are needed
        needed_plugins: Dict[str, Dict[str, Any]] = {}

        for vector in vectors:
            plugin_name = VECTOR_PLUGIN_MAP.get(vector)
            if plugin_name and plugin_name not in needed_plugins:
                needed_plugins[plugin_name] = {"vector": vector}

        # If no vectors matched, default to page_flood
        if not needed_plugins:
            needed_plugins["page_flood"] = {"vector": "PAGE_FLOOD"}

        # Only add origin IP plugins if origin IPs are available
        if origin_ips:
            for origin_plugin in ORIGIN_PLUGINS:
                if origin_plugin not in needed_plugins:
                    needed_plugins[origin_plugin] = {"vector": "ORIGIN_IP_DIRECT"}

        # F5-06: DEPRECATED (Tier 3) plugins get minimum workers via
        # WorkerBalancer.compute_plugin_workers() which checks PLUGIN_TIER_MAP
        # directly — no override config key needed.

        # Filter to only plugins that exist in the registry
        available = {}
        for name, config in needed_plugins.items():
            if name in self._registry:
                available[name] = config
            else:
                # Try to find a plugin with a similar name (with warning)
                for reg_name in self._registry.names:
                    if name in reg_name or reg_name in name:
                        logger.warning(f"Plugin '{name}' not found, using fuzzy match '{reg_name}'")
                        available[reg_name] = config
                        break

        # Phase 0: Register selected plugins with effectiveness tracker
        if self._effectiveness_tracker:
            from plugin_system import PluginTier
            from config.defaults import PLUGIN_TIER_MAP
            for plugin_name in available:
                tier_val = PLUGIN_TIER_MAP.get(plugin_name, 2)
                self._effectiveness_tracker.register_plugin(plugin_name, PluginTier(tier_val))

        return available

    def build_attack_context(self, plugin_name: str, session,
                              workers: int, *,
                              url: str, site_root: str, domain: str,
                              stop_event, stats_callback,
                              profile: Optional[SiteProfile],
                              origin_ips: List[str],
                              page_targets: List[str],
                              resource_targets: List[str],
                              verify_ssl: bool,
                              ssl_ctx,
                              evasion,
                              base_headers_fn: Callable,
                              detected_waf: str | None = None,
                              request_delay_ms: int = 10,
                              enable_cache_bust: bool = True,
                              username_field: str = "username",
                              password_field: str = "password",
                              health_callback=None) -> AttackContext:
        """Build an AttackContext for a specific plugin.

        v24: Passes evasion manager to plugins for smart header generation.
        All parameters are passed through to AttackContext/AttackExtras.
        """
        target_is_https = urlparse(url).scheme == 'https'

        # v24: Use type-specific headers based on plugin type
        request_type_map = {
            "page_flood": "document",
            "resource_flood": "resource",
            "login_flood": "login",
            "basic_api_flood": "api",
            "cache_poison": "document",
            "graphql_introspection": "api",
            "ws_flood": "document",
            "header_bomb": "document",
            "multipart_upload": "api",
            "json_bomb": "api",
            "origin_http": "document",
        }
        request_type = request_type_map.get(plugin_name, "document")

        # v24: Get smart headers from evasion manager
        if hasattr(evasion, 'request_headers'):
            headers = evasion.request_headers(request_type)
        else:
            headers = base_headers_fn()

        context = AttackContext(
            url=url,
            site_root=site_root,
            domain=domain,
            session=session,
            headers=headers,
            stop_event=stop_event,
            stats_callback=stats_callback,
            live_log_callback=lambda m, c, r, e, u, h: None,  # Handled by stats_callback
            health_callback=health_callback or (lambda r: None),
            profile=profile,
            origin_ips=origin_ips,
            page_targets=page_targets or [url],
            resource_targets=resource_targets or [f"{site_root}/favicon.ico"],
            verify_ssl=verify_ssl,
            ssl_ctx=ssl_ctx,
            extra=AttackExtras(
                workers=workers,
                delay_ms=request_delay_ms,
                cache_bust=enable_cache_bust,
                username_field=username_field,
                password_field=password_field,
                use_tls=target_is_https,
                evasion_manager=evasion,  # v24: Pass evasion for per-request header rotation
                waf_name=detected_waf or "",  # v24: Pass WAF info to plugins
            ),
        )
        return context

    async def launch_plugins(self, selected_plugins: Dict[str, Dict[str, Any]],
                              session, *,
                              url: str, site_root: str, domain: str,
                              stop_event, stats_callback,
                              profile: Optional[SiteProfile],
                              origin_ips: List[str],
                              page_targets: List[str],
                              resource_targets: List[str],
                              verify_ssl: bool,
                              ssl_ctx,
                              evasion,
                              base_headers_fn: Callable,
                              detected_waf: str | None = None,
                              request_delay_ms: int = 10,
                              enable_cache_bust: bool = True,
                              username_field: str = "username",
                              password_field: str = "password",
                              health_callback=None,
                              preflight_check_fn=None) -> int:
        """Launch all selected plugins with AttackContext.

        v19: Runs pre-flight check on origin IPs before launching origin plugins.
        If no origin IPs are reachable, origin plugins are skipped.

        Args:
            selected_plugins: Dict of {plugin_name: config} from select_plugins().
            session: aiohttp.ClientSession.
            (remaining args: same as build_attack_context)
            preflight_check_fn: Optional async callable for origin IP validation.
                                If provided, called when origin plugins are selected.

        Returns:
            Total workers launched.
        """
        total_launched = 0

        # v19: Pre-flight check origin IPs
        # v26 FIX: Only remove STRICT_ORIGIN_PLUGINS (origin_http, tls_handshake)
        # when pre-flight fails. Flexible plugins (slowloris, conn_exhaust, slow_read)
        # can work without origin IPs (they connect directly to the target).
        origin_plugins_to_launch = {k: v for k, v in selected_plugins.items()
                                     if k in ORIGIN_PLUGINS}
        if origin_plugins_to_launch and origin_ips:
            if preflight_check_fn:
                reachable = await preflight_check_fn()
                if not reachable:
                    # Only remove STRICT origin plugins — flexible ones still work
                    for pname in list(origin_plugins_to_launch.keys()):
                        if pname in STRICT_ORIGIN_PLUGINS:
                            self._disabled_plugins[pname] = 0  # v19: no errors yet (pre-flight skip)
                            selected_plugins.pop(pname, None)
                            logger.warning(f"[SKIP] {pname} — origin IPs unreachable (strict)")
                        else:
                            logger.info(f"[KEEP] {pname} — works without origin IPs (flexible)")
                    origin_ips = []

        # BUG-FIX v32: Two-pass worker budget allocation.
        # Pass 1: Compute initial workers per plugin independently.
        # Pass 2: If total exceeds max_workers, scale down proportionally.
        # This prevents the sum of per-plugin minimums from exceeding the global cap.
        plugin_workers: Dict[str, int] = {}

        for plugin_name, config in selected_plugins.items():
            # v29: Skip STRICT_ORIGIN_PLUGINS when no origin IPs are available.
            if plugin_name in STRICT_ORIGIN_PLUGINS and not origin_ips:
                self._disabled_plugins[plugin_name] = 0
                logger.warning(f"[SKIP] {plugin_name} — no origin IPs available (strict requirement)")
                continue

            workers = self.compute_plugin_workers(plugin_name, self._max_workers, origin_ips)
            if workers > 0:
                plugin_workers[plugin_name] = workers

        # Pass 2: Budget enforcement — scale down if sum exceeds max_workers
        total_requested = sum(plugin_workers.values())
        if total_requested > self._max_workers and total_requested > 0:
            scale_factor = self._max_workers / total_requested
            logger.info(
                f"[BUDGET] Total workers requested ({total_requested}) exceeds "
                f"max_workers ({self._max_workers}). Scaling down by {scale_factor:.2f}x"
            )
            # Scale each plugin proportionally, ensuring at least 1 worker each
            scaled_workers: Dict[str, int] = {}
            remaining_budget = self._max_workers
            for pname, w in plugin_workers.items():
                scaled_w = max(1, int(w * scale_factor))
                scaled_workers[pname] = scaled_w
            # Final adjustment: if scaled total still exceeds (due to max(1,...)), trim largest
            while sum(scaled_workers.values()) > self._max_workers and len(scaled_workers) > 1:
                largest = max(scaled_workers, key=scaled_workers.get)  # type: ignore[arg-type]
                if scaled_workers[largest] > 1:
                    scaled_workers[largest] -= 1
                else:
                    break
            plugin_workers = scaled_workers

        # Launch plugins with budgeted worker counts
        for plugin_name, workers in plugin_workers.items():
            # BUG-8 fix: Create a new instance per launch instead of reusing cached instance.
            plugin_cls = self._registry.get_class(plugin_name)
            if plugin_cls:
                try:
                    plugin_instance = plugin_cls()
                except (TypeError, AttributeError) as e:
                    logger.warning(f"Plugin '{plugin_name}' instantiation failed: {e}")
                    continue
            else:
                # Fallback: try getting the cached instance (backward compat)
                plugin_instance = self._registry.get(plugin_name)
                if not plugin_instance:
                    logger.warning(f"Plugin '{plugin_name}' not found in registry")
                    continue

            context = self.build_attack_context(
                plugin_name, session, workers,
                url=url, site_root=site_root, domain=domain,
                stop_event=stop_event, stats_callback=stats_callback,
                profile=profile, origin_ips=origin_ips,
                page_targets=page_targets, resource_targets=resource_targets,
                verify_ssl=verify_ssl, ssl_ctx=ssl_ctx,
                evasion=evasion, base_headers_fn=base_headers_fn,
                detected_waf=detected_waf,
                request_delay_ms=request_delay_ms,
                enable_cache_bust=enable_cache_bust,
                username_field=username_field,
                password_field=password_field,
                health_callback=health_callback,
            )

            # Store active plugin
            self._active_plugins[plugin_name] = plugin_instance

            # BUG-FIX v32: Set _workers immediately so dashboard shows correct
            # count before async run() coroutine executes (fixes "0 active" bug).
            plugin_instance._workers = workers

            # Phase 4: Track plugin start in metrics
            _metrics.workers_spawned_total.labels(plugin=plugin_name).inc()
            _metrics.workers_active.labels(plugin=plugin_name).set(workers)

            # Launch plugin as async task
            async def _run_plugin(inst=plugin_instance, ctx=context, name=plugin_name,
                                  worker_count=workers):
                try:
                    await inst.run(ctx)
                except asyncio.CancelledError:
                    return
                except (RuntimeError, OSError, ConnectionError, asyncio.TimeoutError) as exc:
                    logger.warning(f"Plugin {name} error: {exc}", exc_info=True)
                    # A10-continued: Clean up crashed plugin
                    self._active_plugins.pop(name, None)
                    self._disabled_plugins[name] = self._disabled_plugins.get(name, 0) + 1
                    # BUG-FIX v34: Update total_workers when plugin crashes
                    # to prevent inaccurate worker count reporting
                    self._total_workers = max(0, self._total_workers - worker_count)
                    # Phase 4: Track plugin crash in metrics
                    _metrics.workers_crashed_total.labels(plugin=name).inc()
                    ext_metrics.plugin_stop_total.labels(plugin=name, reason="crash").inc()

            task = asyncio.create_task(_run_plugin())
            self._plugin_tasks.append(task)
            total_launched += workers

        return total_launched

    def stop_all(self):
        """Stop all active plugins and cancel all plugin tasks."""
        # Phase 4: Track plugin stops in metrics
        for name in list(self._active_plugins.keys()):
            ext_metrics.plugin_stop_total.labels(plugin=name, reason="stop_all").inc()
        # Stop all active plugins
        for name, plugin in self._active_plugins.items():
            try:
                plugin.stop()
            except (AttributeError, RuntimeError):
                pass

        # Cancel all plugin tasks
        for task in self._plugin_tasks:
            if not task.done():
                task.cancel()

    async def stop_and_wait(self, timeout: float = 10.0):
        """Async version of stop_all() that awaits task cancellation."""
        # Stop all active plugins
        for name, plugin in list(self._active_plugins.items()):
            try:
                plugin.stop()
            except (AttributeError, RuntimeError):
                pass

        # Cancel all plugin tasks and await their completion
        if self._plugin_tasks:
            for t in self._plugin_tasks:
                if not t.done():
                    t.cancel()
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._plugin_tasks, return_exceptions=True),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.debug("Plugin tasks did not finish within timeout")
            except (asyncio.CancelledError, RuntimeError):
                pass

    def reset(self):
        """Reset all orchestrator state for a fresh run."""
        self._active_plugins = {}
        self._disabled_plugins = {}
        self._plugin_tasks = []
        self._total_workers = 0
