#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WorkerBalancer — Worker balancing and auto-disable logic.

Extracted from PluginOrchestrator for Law 14 compliance (500-line limit).
Handles:
  - Computing per-plugin worker counts from config
  - Scaling workers up/down across plugins
  - Auto-disabling plugins with high error rates
  - Redistributing workers from disabled to active plugins

The balancer is instantiated by PluginOrchestrator and accesses the
orchestrator's internal state through a reference. All public methods
are delegated by the orchestrator for backward compatibility.
"""

from __future__ import annotations

from typing import Dict, List, Any

from logging_config import get_logger
logger = get_logger(__name__)


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

# ═══ Plugin Category Constants ═══

# Plugins that benefit from origin IPs (CDN bypass) but don't strictly require them
# v24: slowloris and conn_exhaust now work without origin IPs (connect directly to target)
ORIGIN_PLUGINS = {"origin_http", "slowloris", "conn_exhaust", "tls_handshake", "slow_read"}
# Plugins that strictly require origin IPs (cannot function without them)
STRICT_ORIGIN_PLUGINS = {"origin_http", "tls_handshake"}  # v25 P1: slow_read now works without origin IPs


__all__ = ["WorkerBalancer", "ORIGIN_PLUGINS", "STRICT_ORIGIN_PLUGINS", "VECTOR_PLUGIN_MAP"]


class WorkerBalancer:
    """Worker balancing and auto-disable logic for PluginOrchestrator.

    Extracted from PluginOrchestrator for Law 14 compliance.
    Delegated by the orchestrator for all worker scaling and
    auto-disable decisions.

    The balancer accesses the orchestrator's internal state through
    a reference to the orchestrator instance:
      - _active_plugins: Dict of currently running plugins
      - _disabled_plugins: Dict of disabled plugins with error counts
      - _effectiveness_tracker: PluginEffectivenessTracker or None
      - _initial_workers: Default initial worker count
    """

    def __init__(self, orchestrator: Any) -> None:
        """Initialize the worker balancer.

        Args:
            orchestrator: Reference to the PluginOrchestrator instance.
        """
        self._orchestrator = orchestrator

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
        return max(self._orchestrator._initial_workers, PLUGIN_WORKER_HTTP_MIN)

    def scale_all_plugins(self, delta: int) -> int:
        """Scale ALL active plugins (including origin) by delta. v18: Used for shrink."""
        orch = self._orchestrator
        if not orch._active_plugins:
            return 0

        total_applied = 0
        all_plugins = dict(orch._active_plugins)
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
        orch = self._orchestrator
        if not orch._active_plugins:
            return 0

        total_applied = 0
        # Only scale HTTP plugins up (not origin plugins which have fixed counts)
        http_plugins = {k: v for k, v in orch._active_plugins.items()
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

    def auto_disable_plugin(self, plugin_name: str, reason: str = "high_error_rate") -> bool:
        """Phase 0: Auto-disable a plugin with high error rate."""
        orch = self._orchestrator
        if plugin_name not in orch._active_plugins:
            return False
        plugin = orch._active_plugins.pop(plugin_name)
        if hasattr(plugin, '_stop_event') and plugin._stop_event:
            plugin._stop_event.set()
        orch._disabled_plugins[plugin_name] = plugin._error_count if hasattr(plugin, '_error_count') else 0
        if orch._effectiveness_tracker:
            orch._effectiveness_tracker.mark_disabled(plugin_name, reason)
        logger.warning(f"[AUTO-DISABLE] Plugin '{plugin_name}' disabled: {reason}")
        return True

    def redistribute_workers(self, from_plugin: str, to_plugins: List[str], workers: int) -> None:
        """Phase 0: Move workers from a disabled plugin to active ones."""
        orch = self._orchestrator
        if not to_plugins or workers <= 0:
            return
        per_plugin = max(1, workers // len(to_plugins))
        remaining = workers - (per_plugin * len(to_plugins))
        for i, plugin_name in enumerate(to_plugins):
            if plugin_name not in orch._active_plugins:
                continue
            plugin = orch._active_plugins[plugin_name]
            add = per_plugin + (1 if i < remaining else 0)
            plugin._workers = getattr(plugin, '_workers', 0) + add
            logger.info(f"[REDISTRIBUTE] +{add} workers to '{plugin_name}' (from '{from_plugin}')")
