"""observability.metrics_ext — Extended Prometheus metrics for Phase 4.

Adds scaling, circuit breaker, finder scan, and attack lifecycle metrics
that complement the base metrics in observability/metrics.py.

Separated for Law 14 compliance (500-line limit on metrics.py).

METRIC CATEGORIES:
  - Scaling: scale_up/scale_down events, escalation state
  - Circuit breaker: per-plugin state (CLOSED=0, HALF_OPEN=1, OPEN=2)
  - Finder: scan phase duration and count
  - Attack lifecycle: start/stop events

USAGE:
    from observability.metrics_ext import ext_metrics

    ext_metrics.scaling_events_total.labels(direction="scale_up").inc()
    ext_metrics.circuit_breaker_state.labels(plugin="page_flood").set(0)
"""
from __future__ import annotations

from typing import Any, Optional

from observability.metrics import (
    HAS_PROMETHEUS, REGISTRY,
    _NoopCounter, _NoopGauge, _NoopHistogram,
)

try:
    from prometheus_client import Counter, Gauge, Histogram
except ImportError:
    Counter = None  # type: ignore[assignment,misc]
    Gauge = None  # type: ignore[assignment,misc]
    Histogram = None  # type: ignore[assignment,misc]


# ═══════════════════════════════════════════════════════════════════════════════
# Extended Metrics Collection
# ═══════════════════════════════════════════════════════════════════════════════

class StormVxExtMetrics:
    """Extended metrics for scaling, circuit breaker, finder, and attack lifecycle.

    Lazy initialization like StormVxMetrics — zero-overhead when prometheus_client
    is not installed. All properties return no-op stubs in that case.

    Usage:
        from observability.metrics_ext import ext_metrics
        ext_metrics.scaling_events_total.labels(direction="scale_up").inc()
    """

    def __init__(self, registry: Optional[Any] = None) -> None:
        self._registry = registry
        self._init_done: bool = False
        self._scaling_events_total: Any = None
        self._escalation_state: Any = None
        self._circuit_breaker_state: Any = None
        self._scan_phase_duration: Any = None
        self._scan_phase_total: Any = None
        self._attack_lifecycle_total: Any = None
        self._plugin_stop_total: Any = None
        self._response_classifications_total: Any = None

    def _ensure_init(self) -> None:
        """Lazily create all metrics on first access."""
        if self._init_done:
            return
        self._init_done = True
        if not HAS_PROMETHEUS or self._registry is None:
            return
        reg = self._registry

        # ─── Scaling Metrics ─────────────────────────────────
        self._scaling_events_total = Counter(
            "storm_vx_scaling_events_total",
            "Total worker scaling events",
            ["direction"],
            registry=reg,
        )
        self._escalation_state = Gauge(
            "storm_vx_escalation_state",
            "Escalation state: 0=running, 1=paused",
            registry=reg,
        )

        # ─── Circuit Breaker Metrics ─────────────────────────
        self._circuit_breaker_state = Gauge(
            "storm_vx_circuit_breaker_state",
            "Circuit breaker state per plugin: 0=CLOSED, 1=HALF_OPEN, 2=OPEN",
            ["plugin"],
            registry=reg,
        )

        # ─── Finder Scan Metrics ─────────────────────────────
        self._scan_phase_duration = Histogram(
            "storm_vx_scan_phase_duration_seconds",
            "Duration of each finder scan phase",
            ["phase"],
            buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0),
            registry=reg,
        )
        self._scan_phase_total = Counter(
            "storm_vx_scan_phase_total",
            "Total number of scan phases executed",
            ["phase"],
            registry=reg,
        )

        # ─── Attack Lifecycle Metrics ────────────────────────
        self._attack_lifecycle_total = Counter(
            "storm_vx_attack_lifecycle_total",
            "Attack lifecycle events",
            ["event"],
            registry=reg,
        )
        self._plugin_stop_total = Counter(
            "storm_vx_plugin_stop_total",
            "Plugin stop events",
            ["plugin", "reason"],
            registry=reg,
        )
        self._response_classifications_total = Counter(
            "storm_vx_response_classifications_total",
            "Response classifications by type and source (http/raw_connection)",
            ["classification", "source"],
            registry=reg,
        )

    # ─── Property Accessors ────────────────────────────────────────

    @property
    def scaling_events_total(self) -> Any:
        """Counter for scaling events (direction: scale_up/scale_down)."""
        self._ensure_init()
        return self._scaling_events_total or _NoopCounter()

    @property
    def escalation_state(self) -> Any:
        """Gauge for escalation state: 0=running, 1=paused."""
        self._ensure_init()
        return self._escalation_state or _NoopGauge()

    @property
    def circuit_breaker_state(self) -> Any:
        """Gauge for per-plugin circuit breaker state: 0=CLOSED, 1=HALF_OPEN, 2=OPEN."""
        self._ensure_init()
        return self._circuit_breaker_state or _NoopGauge()

    @property
    def scan_phase_duration_seconds(self) -> Any:
        """Histogram for finder scan phase duration."""
        self._ensure_init()
        return self._scan_phase_duration or _NoopHistogram()

    @property
    def scan_phase_total(self) -> Any:
        """Counter for scan phases executed."""
        self._ensure_init()
        return self._scan_phase_total or _NoopCounter()

    @property
    def attack_lifecycle_total(self) -> Any:
        """Counter for attack lifecycle events (event: start/stop)."""
        self._ensure_init()
        return self._attack_lifecycle_total or _NoopCounter()

    @property
    def plugin_stop_total(self) -> Any:
        """Counter for plugin stop events (plugin, reason)."""
        self._ensure_init()
        return self._plugin_stop_total or _NoopCounter()

    @property
    def response_classifications_total(self) -> Any:
        """Counter for response classifications (classification, source)."""
        self._ensure_init()
        return self._response_classifications_total or _NoopCounter()


# ═══════════════════════════════════════════════════════════════════════════════
# Global Singleton
# ═══════════════════════════════════════════════════════════════════════════════

ext_metrics = StormVxExtMetrics(registry=REGISTRY)


__all__ = [
    "ext_metrics",
    "StormVxExtMetrics",
]
