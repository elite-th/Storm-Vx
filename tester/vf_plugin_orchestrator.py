#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PluginOrchestrator — Extracted from VFTester God Class.

Handles plugin selection, worker allocation, context building,
plugin launching, and worker scaling.
This module is responsible for:
  - Selecting which plugins to activate based on attack vectors
  - Computing per-plugin worker counts from config
  - Building AttackContext objects for each plugin
  - Launching plugins as async tasks
  - Scaling workers up/down across plugins
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


# ═══ Vector-to-Plugin Mapping ═══
# Maps strategy vector names to plugin names
VECTOR_PLUGIN_MAP = {
    "PAGE_FLOOD": "page_flood",
    "LOGIN_FLOOD": "login_flood",
    "RESOURCE_FLOOD": "resource_flood",
    "API_FLOOD": "basic_api_flood",
    "SLOWLORIS": "slowloris",
    "CACHE_DECEPTION_BYPASS": "cache_poison",
    "HTTP2_MULTIPLEX": "http2_rapid_reset",
    "ORIGIN_IP_DIRECT": "origin_http",
    "SSR_RENDER_FLOOD": "page_flood",
    "GRAPHQL_FLOOD": "graphql_introspection",
    "SPA_ROUTE_FLOOD": "page_flood",
    "VIEWSTATE_FLOOD": "viewstate_burn",
    "SESSION_FLOOD": "aspnet_session_flood",
    "WP_XMLRPC": "wp_xmlrpc_bomb",
    "WP_XMLRPC_BOMB": "wp_xmlrpc_bomb",
    "WP_PINGBACK": "wp_pingback_amplify",
    "WP_PINGBACK_AMPLIFY": "wp_pingback_amplify",
    # WordPress-specific attack vectors (v34: new plugins)
    "WP_CRON_BOMB": "wp_cron_bomb",
    "WP_AJAX_FLOOD": "wp_ajax_flood",
    "WP_REST_FLOOD": "wp_rest_flood",
    "WP_SEARCH_BOMB": "wp_search_bomb",
    "WP_WOOCOMMERCE_FLOOD": "wp_woocommerce_flood",
    "HEADER_BOMB": "header_bomb",
    "MULTIPART_UPLOAD": "multipart_upload",
    "SLOW_READ": "slow_read",
    "HTTP2_RAPID_RESET": "http2_rapid_reset",
    "GRAPHQL_INTROSPECTION": "graphql_introspection",
    "CACHE_POISON": "cache_poison",
    "WS_FLOOD": "ws_flood",
    "JSON_BOMB": "json_bomb",
    "SLOW_POST_READ": "slow_read",
    "WP_LOGIN": "login_flood",
    "EDU_API_FLOOD": "basic_api_flood",
    "CHUNKED_BOMB": "json_bomb",
    "COOKIE_POISON": "cache_poison",
    "CONN_EXHAUST": "conn_exhaust",
}

# Plugins that benefit from origin IPs (CDN bypass) but don't strictly require them
# v24: slowloris and conn_exhaust now work without origin IPs (connect directly to target)
ORIGIN_PLUGINS = {"origin_http", "slowloris", "conn_exhaust", "tls_handshake", "slow_read"}
# Plugins that strictly require origin IPs (cannot function without them)
STRICT_ORIGIN_PLUGINS = {"origin_http", "tls_handshake"}  # v25 P1: slow_read now works without origin IPs


class PluginOrchestrator:
    """Manages plugin lifecycle: selection, launching, and scaling.

    Extracted from VFTester to separate plugin orchestration concerns
    from the main attack coordination logic.

    The orchestrator holds the plugin registry, active/disabled plugin
    tracking, and plugin task management. VFTester delegates plugin
    operations to this class.
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

    def select_plugins(self, vectors: List[str],
                       origin_ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Select which plugins to activate based on attack vectors.

        Returns: Dict of {plugin_name: config} for each plugin to launch.
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
        # BUG-FIX v32: Removed unconditional injection of slowloris/conn_exhaust/slow_read
        # when no origin IPs exist. These connection-holding plugins saturate the
        # server's connection pool, causing 100% failure rate for HTTP flood plugins.
        # Now only origin IP plugins (for CDN bypass) are auto-added when origin IPs exist.
        if origin_ips:
            for origin_plugin in ORIGIN_PLUGINS:
                if origin_plugin not in needed_plugins:
                    needed_plugins[origin_plugin] = {"vector": "ORIGIN_IP_DIRECT"}

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

        return available

    def compute_plugin_workers(self, plugin_name: str, total_max: int,
                                origin_ips: List[str]) -> int:
        """Compute how many workers to assign to a plugin.

        Worker allocation is driven by config/defaults.py constants.
        Each plugin category has a (max, min, divisor) tuple that
        determines worker count: min(max, max(min, total_max // divisor)).
        """
        from config.defaults import (
            PLUGIN_WORKER_SLOWLORIS, PLUGIN_WORKER_CONN_EXHAUST,
            PLUGIN_WORKER_TLS_HANDSHAKE, PLUGIN_WORKER_ORIGIN_HTTP,
            PLUGIN_WORKER_SLOW_READ, PLUGIN_WORKER_GENERIC_ORIGIN,
            PLUGIN_WORKER_MEMORY_HEAVY, PLUGIN_WORKER_WS_FLOOD,
            PLUGIN_WORKER_WP_AMPLIFY, PLUGIN_WORKER_ASPNET,
            PLUGIN_WORKER_CPU_HEAVY, PLUGIN_WORKER_CACHE_POISON,
            PLUGIN_WORKER_HTTP_MIN,
            PLUGIN_WORKER_WP_CRON, PLUGIN_WORKER_WP_AJAX,
            PLUGIN_WORKER_WP_REST, PLUGIN_WORKER_WP_SEARCH,
            PLUGIN_WORKER_WP_WOOCOMMERCE,
        )

        def _alloc(cfg: Dict[str, int]) -> int:
            """Compute workers from a config dict with max/min/divisor keys."""
            return min(cfg["max"], max(cfg["min"], total_max // cfg["divisor"]))

        # Origin plugins get fewer workers (they use raw TCP)
        if plugin_name in ORIGIN_PLUGINS:
            if plugin_name == "slowloris":
                return _alloc(PLUGIN_WORKER_SLOWLORIS)
            elif plugin_name == "conn_exhaust":
                return _alloc(PLUGIN_WORKER_CONN_EXHAUST)
            elif plugin_name == "tls_handshake":
                return _alloc(PLUGIN_WORKER_TLS_HANDSHAKE) if origin_ips else 0
            elif plugin_name == "origin_http":
                return _alloc(PLUGIN_WORKER_ORIGIN_HTTP)
            elif plugin_name == "slow_read":
                # v25 P1: slow_read now works without origin IPs (connects directly to target domain)
                return _alloc(PLUGIN_WORKER_SLOW_READ)
            else:
                return _alloc(PLUGIN_WORKER_GENERIC_ORIGIN)

        # Memory-heavy plugins get fewer workers (large payloads)
        if plugin_name in ("header_bomb", "multipart_upload", "json_bomb"):
            return _alloc(PLUGIN_WORKER_MEMORY_HEAVY)

        # WebSocket flood gets moderate workers (persistent connections)
        if plugin_name == "ws_flood":
            return _alloc(PLUGIN_WORKER_WS_FLOOD)

        # WordPress XML-RPC bomb gets moderate workers (very high amplification per request)
        if plugin_name in ("wp_xmlrpc_bomb", "wp_pingback_amplify"):
            return _alloc(PLUGIN_WORKER_WP_AMPLIFY)

        # WordPress-specific high-amplification plugins (v34)
        if plugin_name == "wp_cron_bomb":
            return _alloc(PLUGIN_WORKER_WP_CRON)
        if plugin_name == "wp_ajax_flood":
            return _alloc(PLUGIN_WORKER_WP_AJAX)
        if plugin_name == "wp_rest_flood":
            return _alloc(PLUGIN_WORKER_WP_REST)
        if plugin_name == "wp_search_bomb":
            return _alloc(PLUGIN_WORKER_WP_SEARCH)
        if plugin_name == "wp_woocommerce_flood":
            return _alloc(PLUGIN_WORKER_WP_WOOCOMMERCE)

        # ASP.NET CPU-heavy plugins get moderate workers
        if plugin_name in ("viewstate_burn", "aspnet_session_flood"):
            return _alloc(PLUGIN_WORKER_ASPNET)

        # CPU-heavy plugins get moderate workers
        if plugin_name in ("http2_rapid_reset", "graphql_introspection"):
            return _alloc(PLUGIN_WORKER_CPU_HEAVY)

        # Cache poisoning gets moderate workers
        if plugin_name == "cache_poison":
            return _alloc(PLUGIN_WORKER_CACHE_POISON)

        # HTTP plugins share the main worker pool
        return max(self._initial_workers, PLUGIN_WORKER_HTTP_MIN)

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

        Args:
            plugin_name: Name of the plugin to build context for.
            session: aiohttp.ClientSession.
            workers: Number of workers for this plugin.
            url: Target URL.
            site_root: Scheme + netloc.
            domain: Domain name.
            stop_event: asyncio.Event for stop signal.
            stats_callback: Callback for recording hits.
            profile: SiteProfile with target technology profile.
            origin_ips: List of CDN bypass IPs.
            page_targets: Page URLs to attack.
            resource_targets: Resource URLs to attack.
            verify_ssl: SSL verification flag.
            ssl_ctx: Pre-built SSL context.
            evasion: EvasionManagerStub instance.
            base_headers_fn: Callable returning base headers dict.
            detected_waf: Detected WAF name (or None/empty).
            request_delay_ms: Delay between requests.
            enable_cache_bust: Whether to bust cache.
            username_field: Form field name for username.
            password_field: Form field name for password.
            health_callback: Callback for health monitoring.

        Returns:
            AttackContext ready for the plugin.
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

            task = asyncio.create_task(_run_plugin())
            self._plugin_tasks.append(task)
            total_launched += workers

        return total_launched

    def scale_all_plugins(self, delta: int) -> int:
        """Scale ALL active plugins (including origin) by delta. v18: Used for shrink."""
        if not self._active_plugins:
            return 0

        total_applied = 0
        all_plugins = dict(self._active_plugins)
        plugin_count = max(len(all_plugins), 1)

        # v31 FIX: When delta is NEGATIVE (shrink), distribute the reduction
        # fairly. The old code used integer division which could lose remainder
        # entries, and the remainder was distributed as +1 to the first N plugins
        # regardless of whether they could absorb that much reduction.
        # More importantly, the old per_plugin could be 0 for small |delta|/N,
        # meaning scale_all_plugins(-3) with 10 plugins would do NOTHING
        # (per_plugin = -3 // 10 = 0, remainder = 3, only 3 plugins get -1).
        # This caused shrink commands to be silently swallowed.
        if delta >= 0:
            per_plugin = delta // plugin_count
            remainder = delta % plugin_count
        else:
            # For negative delta, ensure at least some plugins are scaled
            # per_plugin is the minimum guaranteed reduction per plugin
            per_plugin = -((-delta) // plugin_count)
            # Remainder is how many extra reductions we need beyond per_plugin
            remainder = (-delta) % plugin_count

        for name, plugin in all_plugins.items():
            # Each plugin gets per_plugin, first 'remainder' plugins get ±1 extra
            if remainder > 0:
                plugin_delta = per_plugin - 1  # For negative delta, extra = more negative
                remainder -= 1
            else:
                plugin_delta = per_plugin
            actual = plugin.scale(plugin_delta)
            total_applied += actual

        return total_applied

    def scale_plugins(self, delta: int) -> int:
        """Scale HTTP plugins by delta (for scaling UP). Returns actual change."""
        if not self._active_plugins:
            return 0

        total_applied = 0
        # Only scale HTTP plugins up (not origin plugins which have fixed counts)
        http_plugins = {k: v for k, v in self._active_plugins.items()
                       if k not in ORIGIN_PLUGINS}

        if not http_plugins:
            return 0

        per_plugin = delta // max(len(http_plugins), 1)
        remainder = delta % max(len(http_plugins), 1)

        for name, plugin in http_plugins.items():
            plugin_delta = per_plugin + (1 if remainder > 0 else 0)
            if remainder > 0:
                remainder -= 1
            actual = plugin.scale(plugin_delta)
            total_applied += actual

        return total_applied

    def stop_all(self):
        """Stop all active plugins and cancel all plugin tasks."""
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
        """Reset all orchestrator state for a fresh run.

        Called at the beginning of VFTester.run() to ensure clean state.
        """
        self._active_plugins = {}
        self._disabled_plugins = {}
        self._plugin_tasks = []
        self._total_workers = 0
