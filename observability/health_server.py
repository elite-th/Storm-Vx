"""observability.health_server — Authenticated HTTP health endpoint for Storm-Vx.

Extracted from health.py to keep files under 500 lines (Law 14).

Provides a lightweight aiohttp-based health server with optional Bearer token
authentication. Designed for:

  1. Kubernetes liveness/readiness probes
  2. Load balancer health checks
  3. Operational diagnostics dashboards
  4. Crash diagnostics and post-mortem analysis

ENDPOINTS:
  - /health  → Liveness: is the process alive and the event loop running?
  - /ready   → Readiness: is the system ready to accept work?
  - /metrics → Prometheus metrics export
  - /diag    → Detailed diagnostics (optional, for debugging)

AUTHENTICATION:
  Controlled via environment variables:
  - STORM_VX_HEALTH_TOKEN: If set, ALL endpoints require
    ``Authorization: Bearer <token>`` header. Uses hmac.compare_digest
    for timing-safe comparison (Law 5).
  - STORM_VX_HEALTH_NO_AUTH_PATHS: Comma-separated paths excluded from
    auth (e.g. "/health" for K8s liveness probes that can't send headers).

  If STORM_VX_HEALTH_TOKEN is NOT set, the server runs without
  authentication and logs a warning (backward compatible).
"""
from __future__ import annotations

import hmac
import logging
import os
from typing import Any, Callable, Optional

from observability.health import (
    HealthCheckManager,
    HealthStatus,
    health_manager,
)

logger = logging.getLogger("storm_vx.health_server")


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication Configuration
# ═══════════════════════════════════════════════════════════════════════════════

_HEALTH_TOKEN_ENV = "STORM_VX_HEALTH_TOKEN"
_HEALTH_NO_AUTH_PATHS_ENV = "STORM_VX_HEALTH_NO_AUTH_PATHS"


def _get_health_token() -> str | None:
    """Get the health server authentication token from environment.

    Returns None if the token is unset, empty, or whitespace-only
    so that the middleware can fall through to allow-all mode.
    """
    value = os.environ.get(_HEALTH_TOKEN_ENV, "")
    # Strip whitespace — a token of only whitespace is treated as "not set"
    return value.strip() or None


def _get_no_auth_paths() -> set[str]:
    """Get paths excluded from authentication requirement.

    Parses the STORM_VX_HEALTH_NO_AUTH_PATHS env var as a
    comma-separated list.  Empty or unset → no exclusions.
    """
    paths_str = os.environ.get(_HEALTH_NO_AUTH_PATHS_ENV, "").strip()
    if not paths_str:
        return set()
    return {p.strip() for p in paths_str.split(",") if p.strip()}


# ═══════════════════════════════════════════════════════════════════════════════
# Bearer Token Middleware
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from aiohttp import web
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False


if _HAS_AIOHTTP:

    @web.middleware
    async def _auth_middleware(
        request: web.Request,
        handler: Callable[..., Any],
    ) -> web.Response:
        """Bearer token authentication middleware for health server.

        Behaviour:
          - No token configured → allow all requests (backward compatible).
          - Token configured but path in no-auth set → allow.
          - Token configured and path requires auth → validate Bearer header
            using hmac.compare_digest (timing-safe, Law 5).
          - Invalid / missing token → 401 with WWW-Authenticate header.
        """
        token = _get_health_token()

        # No token configured — allow all (backward compatible)
        if token is None:
            return await handler(request)

        # Check if this path is excluded from auth
        no_auth_paths = _get_no_auth_paths()
        if request.path in no_auth_paths:
            return await handler(request)

        # Validate Bearer token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            provided_token = auth_header[7:]
            # hmac.compare_digest prevents timing attacks (Law 5)
            if hmac.compare_digest(provided_token, token):
                return await handler(request)

        # Unauthorized — return 401 with proper challenge header
        return web.json_response(
            {"error": "Unauthorized", "message": "Valid Bearer token required"},
            status=401,
            headers={"WWW-Authenticate": "Bearer"},
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Health Server
# ═══════════════════════════════════════════════════════════════════════════════

async def start_health_server(
    host: str = "127.0.0.1",
    port: int = 9090,
    manager: Optional[HealthCheckManager] = None,
) -> Optional[Any]:
    """Start a minimal aiohttp server for health/metrics endpoints.

    This is designed to be started alongside the main application as
    a separate task. It provides:
      - GET /health   → Liveness probe
      - GET /ready    → Readiness probe
      - GET /metrics  → Prometheus metrics
      - GET /diag     → Diagnostics

    Returns the aiohttp web.Application, or None if aiohttp is not available.

    Args:
        host: Bind address (default: 127.0.0.1 — localhost only for security).
            Previous default was 0.0.0.0; changed to reduce attack surface.
        port: Bind port (default: 9090).
        manager: HealthCheckManager instance (default: global singleton).

    Authentication:
        If the ``STORM_VX_HEALTH_TOKEN`` environment variable is set, all
        endpoints require an ``Authorization: Bearer <token>`` header.
        Paths listed in ``STORM_VX_HEALTH_NO_AUTH_PATHS`` (comma-separated)
        are exempt — useful for K8s liveness probes on /health.

        If the token is NOT set, the server runs without authentication
        and logs a warning (SEC-001) for backward compatibility.
    """
    if not _HAS_AIOHTTP:
        return None

    _manager = manager or health_manager

    from observability.metrics import generate_metrics, metrics_content_type

    # ── Auth Configuration Check ──────────────────────────────────────
    health_token = _get_health_token()
    if health_token is None:
        logger.warning(
            "SEC-001: Health server running WITHOUT authentication. "
            "Set %s environment variable to enable Bearer token auth.",
            _HEALTH_TOKEN_ENV,
        )
    else:
        logger.info("Health server authentication enabled (Bearer token)")
        no_auth = _get_no_auth_paths()
        if no_auth:
            logger.info(
                "Health server auth-exempt paths: %s", sorted(no_auth),
            )

    # ── Request Handlers ──────────────────────────────────────────────

    async def handle_health(request: web.Request) -> web.Response:
        report = await _manager.check_health()
        status_code = (
            200 if report.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)
            else 503
        )
        return web.json_response(report.to_dict(), status=status_code)

    async def handle_ready(request: web.Request) -> web.Response:
        status = await _manager.readiness()
        code = 200 if status == HealthStatus.HEALTHY else 503
        return web.json_response({"status": status.value}, status=code)

    async def handle_metrics(request: web.Request) -> web.Response:
        return web.Response(
            text=generate_metrics(),
            content_type=metrics_content_type(),
        )

    async def handle_diag(request: web.Request) -> web.Response:
        diag = _manager.get_diagnostics()
        return web.json_response(diag)

    # ── Application Setup ─────────────────────────────────────────────

    app = web.Application(middlewares=[_auth_middleware])
    app.router.add_get("/health", handle_health)
    app.router.add_get("/ready", handle_ready)
    app.router.add_get("/metrics", handle_metrics)
    app.router.add_get("/diag", handle_diag)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    logger.info("Health server listening on %s:%d", host, port)
    return app


__all__ = [
    "start_health_server",
    "_get_health_token",
    "_get_no_auth_paths",
]
