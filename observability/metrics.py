"""observability.metrics — Prometheus-compatible metrics for Storm-Vx.

W5.2 PROMETHEUS METRICS INSTRUMENTATION:

  Provides a centralized metrics registry and pre-defined counters,
  gauges, and histograms for core Storm-Vx subsystems. All metrics
  follow Prometheus naming conventions (snake_case, _total suffix for
  counters, _seconds suffix for time histograms).

DESIGN PRINCIPLES:
  - Lazy initialization: metrics are created on first access
  - Zero-overhead when disabled: if prometheus_client is not installed,
    all operations are no-ops
  - No coupling to aiohttp or any web framework
  - Labels follow Prometheus best practices (low cardinality)

METRIC CATEGORIES:
  - HTTP requests: total, duration, in-flight
  - Attack engine: requests, successes, failures, RPS
  - Response classification: WAF blocks, challenges, rate limits
  - Target selection: alive, dead, discovered
  - Connection pool: active, created, failed, timeouts
  - Workers: spawned, crashed, active
  - Evasion: rotation, WAF bypass attempts
  - Health: health_score, crash_mode

USAGE:
  from observability.metrics import metrics

  # Increment a counter
  metrics.http_requests_total.labels(method="GET", status="200").inc()

  # Observe a duration
  metrics.http_request_duration_seconds.labels(method="GET").observe(0.5)

  # Set a gauge
  metrics.active_workers.set(10)

  # Export for Prometheus
  from observability.metrics import generate_metrics
  text = generate_metrics()
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Info, Registry,
        CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST,
    )
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False


# ═══════════════════════════════════════════════════════════════════════════════
# Metrics Registry — Isolated from the default registry
# ═══════════════════════════════════════════════════════════════════════════════

if HAS_PROMETHEUS:
    REGISTRY = CollectorRegistry()
else:
    REGISTRY = None  # type: ignore[assignment]


def generate_metrics() -> str:
    """Generate Prometheus text-format metrics output.

    Returns:
        Prometheus text-format metrics string.
    """
    if not HAS_PROMETHEUS or REGISTRY is None:
        return "# prometheus_client not installed\n"
    return generate_latest(REGISTRY).decode("utf-8")


def metrics_content_type() -> str:
    """Return the content type for Prometheus metrics response."""
    if HAS_PROMETHEUS:
        return CONTENT_TYPE_LATEST
    return "text/plain"


# ═══════════════════════════════════════════════════════════════════════════════
# No-op Metric Stubs — When prometheus_client is not installed
# ═══════════════════════════════════════════════════════════════════════════════

class _NoopCounter:
    """No-op counter when prometheus_client is not available."""
    def labels(self, **kw: Any) -> "_NoopCounter": return self
    def inc(self, amount: float = 1.0) -> None: pass
    def count(self) -> float: return 0.0


class _NoopGauge:
    """No-op gauge when prometheus_client is not available."""
    def labels(self, **kw: Any) -> "_NoopGauge": return self
    def set(self, value: float) -> None: pass
    def inc(self, amount: float = 1.0) -> None: pass
    def dec(self, amount: float = 1.0) -> None: pass
    def set_to_current_time(self) -> None: pass


class _NoopHistogram:
    """No-op histogram when prometheus_client is not available."""
    def labels(self, **kw: Any) -> "_NoopHistogram": return self
    def observe(self, amount: float) -> None: pass
    def time(self) -> "_NoopTimer":
        return _NoopTimer()


class _NoopTimer:
    """No-op timer context manager."""
    def __enter__(self) -> "_NoopTimer": return self
    def __exit__(self, *args: Any) -> None: pass


class _NoopInfo:
    """No-op info when prometheus_client is not available."""
    def info(self, val: Dict[str, str]) -> None: pass


# ═══════════════════════════════════════════════════════════════════════════════
# Metrics Collection — Singleton with all Storm-Vx metrics
# ═══════════════════════════════════════════════════════════════════════════════

class StormVxMetrics:
    """Centralized metrics collection for Storm-Vx.

    All metrics are lazily created on first access. When prometheus_client
    is not installed, all operations are no-ops with zero overhead.

    Usage:
        from observability.metrics import metrics

        # Count an HTTP request
        metrics.http_requests_total.labels(method="GET", status="200").inc()

        # Time an operation
        with metrics.http_request_duration_seconds.labels(method="GET").time():
            await make_request()
    """

    def __init__(self, registry: Optional[Any] = None) -> None:
        self._registry = registry
        self._init_done: bool = False

        # Lazy-created metric instances
        self._http_requests_total: Any = None
        self._http_request_duration: Any = None
        self._http_requests_inflight: Any = None
        self._attack_requests_total: Any = None
        self._attack_failures_total: Any = None
        self._response_classifications_total: Any = None
        self._target_alive: Any = None
        self._target_dead: Any = None
        self._target_discovered_total: Any = None
        self._connection_pool_active: Any = None
        self._connection_pool_created_total: Any = None
        self._connection_pool_failed_total: Any = None
        self._connection_pool_timeouts_total: Any = None
        self._workers_active: Any = None
        self._workers_spawned_total: Any = None
        self._workers_crashed_total: Any = None
        self._evasion_rotations_total: Any = None
        self._evasion_waf_bypass_attempts_total: Any = None
        self._health_score: Any = None
        self._crash_mode: Any = None
        self._build_info: Any = None
        self._uptime_seconds: Any = None
        self._start_time: float = time.time()

    def _ensure_init(self) -> None:
        """Lazily create all metrics on first access."""
        if self._init_done:
            return
        self._init_done = True

        if not HAS_PROMETHEUS or self._registry is None:
            return  # Will use no-op stubs

        reg = self._registry

        # ─── HTTP Request Metrics ─────────────────────────────
        self._http_requests_total = Counter(
            "storm_vx_http_requests_total",
            "Total number of HTTP requests made",
            ["method", "status_code", "target"],
            registry=reg,
        )
        self._http_request_duration = Histogram(
            "storm_vx_http_request_duration_seconds",
            "HTTP request duration in seconds",
            ["method"],
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
            registry=reg,
        )
        self._http_requests_inflight = Gauge(
            "storm_vx_http_requests_inflight",
            "Number of currently in-flight HTTP requests",
            registry=reg,
        )

        # ─── Attack Engine Metrics ─────────────────────────────
        self._attack_requests_total = Counter(
            "storm_vx_attack_requests_total",
            "Total attack requests sent",
            ["plugin", "mode"],
            registry=reg,
        )
        self._attack_failures_total = Counter(
            "storm_vx_attack_failures_total",
            "Total attack request failures",
            ["plugin", "error_category"],
            registry=reg,
        )

        # ─── Response Classification Metrics ─────────────────────
        self._response_classifications_total = Counter(
            "storm_vx_response_classifications_total",
            "Response classifications by type",
            ["class", "waf_name"],
            registry=reg,
        )

        # ─── Target Selection Metrics ─────────────────────────────
        self._target_alive = Gauge(
            "storm_vx_target_alive",
            "Number of alive (active) targets",
            registry=reg,
        )
        self._target_dead = Gauge(
            "storm_vx_target_dead",
            "Number of dead/blacklisted targets",
            registry=reg,
        )
        self._target_discovered_total = Counter(
            "storm_vx_target_discovered_total",
            "Total newly discovered targets",
            registry=reg,
        )

        # ─── Connection Pool Metrics ─────────────────────────────
        self._connection_pool_active = Gauge(
            "storm_vx_connection_pool_active",
            "Active connections in pool",
            registry=reg,
        )
        self._connection_pool_created_total = Counter(
            "storm_vx_connection_pool_created_total",
            "Total connections created",
            registry=reg,
        )
        self._connection_pool_failed_total = Counter(
            "storm_vx_connection_pool_failed_total",
            "Total connection failures",
            ["error_type"],
            registry=reg,
        )
        self._connection_pool_timeouts_total = Counter(
            "storm_vx_connection_pool_timeouts_total",
            "Total connection timeouts",
            registry=reg,
        )

        # ─── Worker Metrics ─────────────────────────────────────
        self._workers_active = Gauge(
            "storm_vx_workers_active",
            "Currently active workers",
            ["plugin"],
            registry=reg,
        )
        self._workers_spawned_total = Counter(
            "storm_vx_workers_spawned_total",
            "Total workers spawned",
            ["plugin"],
            registry=reg,
        )
        self._workers_crashed_total = Counter(
            "storm_vx_workers_crashed_total",
            "Total worker crashes",
            ["plugin"],
            registry=reg,
        )

        # ─── Evasion Metrics ─────────────────────────────────────
        self._evasion_rotations_total = Counter(
            "storm_vx_evasion_rotations_total",
            "Total UA/profile rotations",
            registry=reg,
        )
        self._evasion_waf_bypass_attempts_total = Counter(
            "storm_vx_evasion_waf_bypass_attempts_total",
            "Total WAF bypass attempts",
            ["waf_name", "technique"],
            registry=reg,
        )

        # ─── Health Metrics ─────────────────────────────────────
        self._health_score = Gauge(
            "storm_vx_health_score",
            "Server health score (0-100)",
            registry=reg,
        )
        self._crash_mode = Gauge(
            "storm_vx_crash_mode",
            "Whether crash mode is active (0 or 1)",
            registry=reg,
        )

        # ─── Build & Uptime ─────────────────────────────────────
        self._build_info = Info(
            "storm_vx_build",
            "Build and version information",
            registry=reg,
        )
        self._uptime_seconds = Gauge(
            "storm_vx_uptime_seconds",
            "Process uptime in seconds",
            registry=reg,
        )

    # ─── Property Accessors ────────────────────────────────────────

    @property
    def http_requests_total(self) -> Any:
        self._ensure_init()
        return self._http_requests_total or _NoopCounter()

    @property
    def http_request_duration_seconds(self) -> Any:
        self._ensure_init()
        return self._http_request_duration or _NoopHistogram()

    @property
    def http_requests_inflight(self) -> Any:
        self._ensure_init()
        return self._http_requests_inflight or _NoopGauge()

    @property
    def attack_requests_total(self) -> Any:
        self._ensure_init()
        return self._attack_requests_total or _NoopCounter()

    @property
    def attack_failures_total(self) -> Any:
        self._ensure_init()
        return self._attack_failures_total or _NoopCounter()

    @property
    def response_classifications_total(self) -> Any:
        self._ensure_init()
        return self._response_classifications_total or _NoopCounter()

    @property
    def target_alive(self) -> Any:
        self._ensure_init()
        return self._target_alive or _NoopGauge()

    @property
    def target_dead(self) -> Any:
        self._ensure_init()
        return self._target_dead or _NoopGauge()

    @property
    def target_discovered_total(self) -> Any:
        self._ensure_init()
        return self._target_discovered_total or _NoopCounter()

    @property
    def connection_pool_active(self) -> Any:
        self._ensure_init()
        return self._connection_pool_active or _NoopGauge()

    @property
    def connection_pool_created_total(self) -> Any:
        self._ensure_init()
        return self._connection_pool_created_total or _NoopCounter()

    @property
    def connection_pool_failed_total(self) -> Any:
        self._ensure_init()
        return self._connection_pool_failed_total or _NoopCounter()

    @property
    def connection_pool_timeouts_total(self) -> Any:
        self._ensure_init()
        return self._connection_pool_timeouts_total or _NoopCounter()

    @property
    def workers_active(self) -> Any:
        self._ensure_init()
        return self._workers_active or _NoopGauge()

    @property
    def workers_spawned_total(self) -> Any:
        self._ensure_init()
        return self._workers_spawned_total or _NoopCounter()

    @property
    def workers_crashed_total(self) -> Any:
        self._ensure_init()
        return self._workers_crashed_total or _NoopCounter()

    @property
    def evasion_rotations_total(self) -> Any:
        self._ensure_init()
        return self._evasion_rotations_total or _NoopCounter()

    @property
    def evasion_waf_bypass_attempts_total(self) -> Any:
        self._ensure_init()
        return self._evasion_waf_bypass_attempts_total or _NoopCounter()

    @property
    def health_score(self) -> Any:
        self._ensure_init()
        return self._health_score or _NoopGauge()

    @property
    def crash_mode(self) -> Any:
        self._ensure_init()
        return self._crash_mode or _NoopGauge()

    @property
    def build_info(self) -> Any:
        self._ensure_init()
        return self._build_info or _NoopInfo()

    @property
    def uptime_seconds(self) -> Any:
        self._ensure_init()
        return self._uptime_seconds or _NoopGauge()

    # ─── Convenience Methods ────────────────────────────────────────

    def set_build_info(self, version: str = "22.0.0") -> None:
        """Set build version information."""
        self.build_info.info({"version": version})

    def update_uptime(self) -> None:
        """Update the uptime gauge to current elapsed time."""
        self.uptime_seconds.set(time.time() - self._start_time)

    def record_http_request(
        self, method: str, status_code: int, duration: float,
        target: str = "",
    ) -> None:
        """Record a completed HTTP request with metrics.

        Convenience method that updates multiple metrics at once.

        Args:
            method: HTTP method (GET, POST, etc.)
            status_code: HTTP status code
            duration: Request duration in seconds
            target: Target host (for labeling)
        """
        self.http_requests_total.labels(
            method=method, status_code=str(status_code), target=target,
        ).inc()
        self.http_request_duration_seconds.labels(method=method).observe(duration)

    def record_response_classification(
        self, response_class: str, waf_name: str = "",
    ) -> None:
        """Record a response classification.

        Args:
            response_class: ResponseClass value (ok, waf_blocked, etc.)
            waf_name: Detected WAF name (empty if none)
        """
        self.response_classifications_total.labels(
            class_=response_class, waf_name=waf_name or "none",
        ).inc()

    def record_worker_lifecycle(
        self, plugin: str, event: str,
    ) -> None:
        """Record a worker lifecycle event.

        Args:
            plugin: Plugin name
            event: "spawned" or "crashed"
        """
        if event == "spawned":
            self.workers_spawned_total.labels(plugin=plugin).inc()
        elif event == "crashed":
            self.workers_crashed_total.labels(plugin=plugin).inc()


# ═══════════════════════════════════════════════════════════════════════════════
# Global Singleton
# ═══════════════════════════════════════════════════════════════════════════════

metrics = StormVxMetrics(registry=REGISTRY)


__all__ = [
    "metrics",
    "StormVxMetrics",
    "generate_metrics",
    "metrics_content_type",
    "REGISTRY",
    "HAS_PROMETHEUS",
]
