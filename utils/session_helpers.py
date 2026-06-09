#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""utils.session_helpers — Shared session & connector factory with resource controls.

W3.2 FIX: Centralizes aiohttp session creation with proper resource controls.

Previously, each module created its own ClientSession with inconsistent
timeout configurations:
  - VF_TESTER: 3-way timeout (total=15, connect=3, sock_read=10)
  - vf_api_flood: hardcoded (total=10, connect=5, sock_read=8)
  - 12 finder modules: only total timeout (no connect/sock_read)
  - config/settings.py: dead code with wrong values (connect=5, read=8)

This module provides factory functions that enforce:
  1. 3-way timeouts (total + connect + sock_read) on every session
  2. Connection pool limits (total + per-host) on every connector
  3. DNS caching and keepalive settings from central config
  4. SSL context from ssl_helpers
  5. Consistent CookieJar settings

Usage:
    from utils.session_helpers import create_session, scanner_timeout

    # For scanner modules (reconnaissance):
    async with create_session(timeout=scanner_timeout()) as session:
        ...

    # For attack modules (with custom connector):
    async with create_session(
        timeout=attack_timeout(),
        connector=create_connector(max_connections=500),
    ) as session:
        ...
"""
from __future__ import annotations

from typing import Any

import aiohttp

from config.defaults import (
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_READ_TIMEOUT_SECONDS,
    DEFAULT_KEEPALIVE_TIMEOUT,
    DEFAULT_DNS_CACHE_TTL,
    DEFAULT_CONNECTION_LIMIT,
    DEFAULT_PER_HOST_LIMIT,
)
from utils.ssl_helpers import ssl_param
from logging_config import get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Timeout presets — all enforce 3-way timeouts
# ═══════════════════════════════════════════════════════════════════════════════

def scanner_timeout(
    total: int | float = DEFAULT_TIMEOUT_SECONDS,
    connect: int | float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
    sock_read: int | float = DEFAULT_READ_TIMEOUT_SECONDS,
) -> aiohttp.ClientTimeout:
    """Create a 3-way timeout for scanner/reconnaissance modules.

    W3.2 FIX: Ensures all scanner sessions have separate connect and
    sock_read timeouts, preventing a stalled DNS resolution or slow
    connect from consuming the entire timeout budget.

    Args:
        total: Overall request timeout (default: 15s).
        connect: Connection establishment timeout (default: 3s).
        sock_read: Socket read timeout (default: 10s).

    Returns:
        Configured ClientTimeout instance.
    """
    return aiohttp.ClientTimeout(
        total=total,
        connect=connect,
        sock_read=sock_read,
    )


def fast_scanner_timeout() -> aiohttp.ClientTimeout:
    """Fast timeout for quick probes (subdomain check, DNS scan).

    Returns:
        ClientTimeout(total=5, connect=3, sock_read=3)
    """
    return aiohttp.ClientTimeout(total=5, connect=3, sock_read=3)


def attack_timeout(
    total: int | float = DEFAULT_TIMEOUT_SECONDS,
    connect: int | float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
    sock_read: int | float = DEFAULT_READ_TIMEOUT_SECONDS,
) -> aiohttp.ClientTimeout:
    """Create a 3-way timeout for attack modules.

    Same as scanner_timeout() but named differently for semantic clarity.
    Attack modules may override with shorter timeouts for aggressive
    pacing.

    Args:
        total: Overall request timeout (default: 15s).
        connect: Connection establishment timeout (default: 3s).
        sock_read: Socket read timeout (default: 10s).

    Returns:
        Configured ClientTimeout instance.
    """
    return aiohttp.ClientTimeout(
        total=total,
        connect=connect,
        sock_read=sock_read,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Connector factory — enforces connection pool limits
# ═══════════════════════════════════════════════════════════════════════════════

def create_connector(
    max_connections: int = DEFAULT_CONNECTION_LIMIT,
    per_host_limit: int = DEFAULT_PER_HOST_LIMIT,
    keepalive_timeout: float = DEFAULT_KEEPALIVE_TIMEOUT,
    dns_cache_ttl: int = DEFAULT_DNS_CACHE_TTL,
    enable_cleanup: bool = True,
    pool_stats: Any = None,
) -> aiohttp.TCPConnector:
    """Create a TCPConnector with resource limits from central config.

    W3.2 FIX: All connector creation should go through this factory
    to ensure consistent resource limits. Uses DEFAULT_* constants
    from config/defaults.py as defaults.

    W2.7: Merged DNS trace callbacks from vf_network.build_resilient_connector().
    When pool_stats is provided, on_dns_resolvehost_start and on_dns_cache_hit
    callbacks are now wired into the TraceConfig, tracking dns_resolves and
    dns_cache_hits respectively.

    For single-target attack tools, per_host_limit=0 (unlimited) is
    intentional and correct — the attack targets one host.

    Args:
        max_connections: Total connection pool limit (default: 2000).
        per_host_limit: Per-host connection limit (default: 0=unlimited).
            Intentionally 0 for single-target attack tools.
        keepalive_timeout: Keep-alive timeout in seconds (default: 30).
        dns_cache_ttl: DNS cache TTL in seconds (default: 120).
        enable_cleanup: Enable cleanup of closed connections.
        pool_stats: Optional ConnectionPoolStats for tracing. When provided,
            registers TraceConfig callbacks for request/connection/DNS events.

    Returns:
        Configured aiohttp.TCPConnector.
    """
    # Cap at 10000 to prevent unreasonable resource usage
    safe_limit = min(max_connections, 10_000)

    connector = aiohttp.TCPConnector(
        limit=safe_limit,
        limit_per_host=per_host_limit,
        enable_cleanup_closed=enable_cleanup,
        ttl_dns_cache=dns_cache_ttl,
        keepalive_timeout=keepalive_timeout,
        use_dns_cache=True,
    )

    # Wire up pool_stats trace config if provided
    if pool_stats is not None:
        async def _on_request_start(session, ctx, params):
            pool_stats._inc_active()

        async def _on_request_end(session, ctx, params):
            pool_stats.total_connections += 1
            pool_stats.ok_connections += 1
            pool_stats._dec_active()

        async def _on_request_exception(session, ctx, params):
            pool_stats.total_connections += 1
            pool_stats.failed_connections += 1
            pool_stats._dec_active()

        async def _on_connection_reuse(session, ctx, params):
            pool_stats.reused_connections += 1

        async def _on_dns_resolvehost_start(session, ctx, params):
            pool_stats.dns_resolves += 1

        async def _on_dns_cache_hit(session, ctx, params):
            pool_stats.dns_cache_hits += 1

        trace_config = aiohttp.TraceConfig()
        trace_config.on_request_start.append(_on_request_start)
        trace_config.on_request_end.append(_on_request_end)
        trace_config.on_request_exception.append(_on_request_exception)
        trace_config.on_connection_reuseconn.append(_on_connection_reuse)
        trace_config.on_dns_resolvehost_start.append(_on_dns_resolvehost_start)
        trace_config.on_dns_cache_hit.append(_on_dns_cache_hit)
        connector._vf_trace_config = trace_config

    return connector


# ═══════════════════════════════════════════════════════════════════════════════
# Session factory — enforces 3-way timeouts + connector limits
# ═══════════════════════════════════════════════════════════════════════════════

def create_session(
    timeout: aiohttp.ClientTimeout | None = None,
    connector: aiohttp.TCPConnector | None = None,
    verify_ssl: bool = True,
    max_connections: int = DEFAULT_CONNECTION_LIMIT,
    per_host_limit: int = DEFAULT_PER_HOST_LIMIT,
    unsafe_cookie_jar: bool = False,
    enable_tracing: bool = True,
) -> aiohttp.ClientSession:
    """Create a ClientSession with proper resource controls.

    W3.2 FIX: Centralized session factory that enforces:
      - 3-way timeout (total + connect + sock_read) — never total-only
      - Connection pool limits from config/defaults.py
      - SSL verification from ssl_helpers
      - Consistent CookieJar configuration

    W5.6: Now auto-instruments HTTP requests with OpenTelemetry
    tracing when STORM_VX_TRACING_ENABLED=true. The OTel TraceConfig
    is appended to the session's trace_configs list alongside any
    existing pool_stats TraceConfig.

    Use this instead of directly creating ClientSession to ensure
    all sessions have proper resource controls.

    Args:
        timeout: ClientTimeout instance. Defaults to scanner_timeout().
        connector: Pre-built connector. If None, creates one via
            create_connector() with the given max_connections/per_host_limit.
        verify_ssl: Whether to verify SSL certificates (default: True).
        max_connections: Total connection limit for auto-created connector.
        per_host_limit: Per-host limit for auto-created connector (0=unlimited).
        unsafe_cookie_jar: Use unsafe CookieJar for cross-domain cookies.
            Required for session harvesting and origin discovery.
        enable_tracing: Whether to add OTel TraceConfig (default: True).

    Returns:
        Configured aiohttp.ClientSession.

    Examples:
        >>> # Scanner module (default timeouts)
        >>> async with create_session() as session:
        ...     async with session.get(url) as resp:
        ...         ...

        >>> # Attack module (custom connector)
        >>> conn = create_connector(max_connections=500)
        >>> async with create_session(
        ...     timeout=attack_timeout(),
        ...     connector=conn,
        ...     unsafe_cookie_jar=True,
        ... ) as session:
        ...     ...
    """
    if timeout is None:
        timeout = scanner_timeout()

    if connector is None:
        connector = create_connector(
            max_connections=max_connections,
            per_host_limit=per_host_limit,
        )

    cookie_jar: aiohttp.CookieJar | None = None
    if unsafe_cookie_jar:
        cookie_jar = aiohttp.CookieJar(unsafe=True)

    trace_configs = []
    if hasattr(connector, '_vf_trace_config'):
        trace_configs = [connector._vf_trace_config]

    # W5.6: Add OTel TraceConfig for auto-instrumenting HTTP requests
    if enable_tracing:
        try:
            from observability.tracing import create_otel_trace_config
            otel_tc = create_otel_trace_config()
            if otel_tc is not None:
                trace_configs.append(otel_tc)
        except ImportError:
            pass

    session = aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        cookie_jar=cookie_jar,
        trace_configs=trace_configs,
    )

    return session
