"""engine.atomic_metrics — Lock-free hot-path counters with benchmark instrumentation.

Replaces engine.atomic_counters with a production-grade metrics system that
adds benchmark-ready instrumentation, histogram tracking, and structured
snapshots while preserving the zero-lock GIL-atomic hot path.

DESIGN PRINCIPLES:
  - GIL-ATOMIC hot path: `record()` is <1μs, no locks, no yields, no allocations
  - Lock-free reads: individual field reads are GIL-atomic, snapshots are
    "consistent enough" (microseconds stale at most)
  - O(1) memory: rolling windows use fixed-size circular buffers
  - Benchmark-ready: every counter has wall-clock timing instrumentation
  - Structured snapshots: typed dataclass output for serialization

PERFORMANCE TARGETS (at 10k+ req/sec):
  - record(): <1μs per call (GIL-atomic increment)
  - snapshot(): <5μs (field reads + window rate computation)
  - Memory: O(1) per counter regardless of request rate

GIL-ATOMICITY GUARANTEE (same as engine.atomic_counters):
  Under CPython, `x += 1` compiles to LOAD_FAST + INPLACE_ADD + STORE_FAST.
  The GIL ensures no other thread can interleave, making these effectively
  atomic for single-value reads and writes. Compound operations across
  multiple fields are NOT atomic but are "consistent enough" for monitoring.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════════════════════════
# Rolling Window — Fixed-size circular buffer for rate computation
# ═══════════════════════════════════════════════════════════════════════════════

class RollingWindow:
    """Fixed-size circular buffer for computing rolling rates.

    Maintains a window of recent timestamps to compute requests-per-second
    without storing individual request records. Memory-efficient: O(window_size)
    regardless of request rate.

    BENCHMARK INSTRUMENTATION:
      - `record_count`: total events ever recorded (for throughput reporting)
      - `record_time_ns`: cumulative nanoseconds spent in record() (for overhead measurement)
    """

    __slots__ = ('_buckets', '_bucket_count', '_bucket_duration',
                 '_current_bucket', '_current_bucket_time', '_total',
                 'record_count', 'record_time_ns')

    def __init__(self, window_seconds: float = 60.0, bucket_count: int = 60) -> None:
        self._bucket_count = bucket_count
        self._bucket_duration = window_seconds / bucket_count
        self._buckets: list[int] = [0] * bucket_count
        self._current_bucket: int = 0
        self._current_bucket_time: float = time.monotonic()
        self._total: int = 0
        # Benchmark instrumentation
        self.record_count: int = 0
        self.record_time_ns: int = 0

    def record(self) -> None:
        """Record one event in the current bucket (GIL-atomic increment).

        BENCHMARK: Measures wall-clock time per call for overhead reporting.
        Target: <1μs per call at 10k+ req/sec.
        """
        t0 = time.perf_counter_ns()
        self._advance()
        self._buckets[self._current_bucket] += 1
        self._total += 1
        self.record_count += 1
        self.record_time_ns += (time.perf_counter_ns() - t0)

    def rate(self) -> float:
        """Compute events per second over the rolling window."""
        self._advance()
        window_total = sum(self._buckets)
        window_seconds = self._bucket_count * self._bucket_duration
        return window_total / window_seconds if window_seconds > 0 else 0.0

    def _advance(self) -> None:
        """Advance to the current time bucket, clearing expired buckets."""
        now = time.monotonic()
        elapsed = now - self._current_bucket_time
        buckets_to_advance = int(elapsed / self._bucket_duration)

        if buckets_to_advance <= 0:
            return

        if buckets_to_advance >= self._bucket_count:
            self._buckets = [0] * self._bucket_count
            self._total = 0
        else:
            for i in range(buckets_to_advance):
                idx = (self._current_bucket + 1 + i) % self._bucket_count
                self._total -= self._buckets[idx]
                self._buckets[idx] = 0

        self._current_bucket = (self._current_bucket + buckets_to_advance) % self._bucket_count
        self._current_bucket_time = now

    @property
    def avg_record_ns(self) -> float:
        """Average nanoseconds per record() call (benchmark metric)."""
        return self.record_time_ns / max(self.record_count, 1)

    def reset(self) -> None:
        """Reset all window state."""
        self._buckets = [0] * self._bucket_count
        self._current_bucket = 0
        self._current_bucket_time = time.monotonic()
        self._total = 0
        self.record_count = 0
        self.record_time_ns = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Latency Histogram — Fixed-bandwidth latency tracker
# ═══════════════════════════════════════════════════════════════════════════════

class LatencyHistogram:
    """Fixed-bandwidth latency histogram for response time tracking.

    Uses predefined bucket boundaries to avoid dynamic allocation.
    Memory: O(num_buckets) regardless of request rate.
    Record: GIL-atomic counter increment (O(1)).

    Bucket boundaries (in seconds):
      [0, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s, +inf]
    """

    BUCKET_BOUNDS: tuple[float, ...] = (
        0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0,
    )
    NUM_BUCKETS: int = len(BUCKET_BOUNDS) + 1  # +1 for the +inf bucket

    __slots__ = ('_buckets', '_count', '_sum', '_min', '_max')

    def __init__(self) -> None:
        self._buckets: list[int] = [0] * self.NUM_BUCKETS
        self._count: int = 0
        self._sum: float = 0.0
        self._min: float = float('inf')
        self._max: float = 0.0

    def record(self, value: float) -> None:
        """Record a latency value (GIL-atomic, O(1)).

        Args:
            value: Response time in seconds.
        """
        # Find bucket via linear scan (11 buckets → trivial cost)
        bucket_idx = 0
        for bound in self.BUCKET_BOUNDS:
            if value > bound:
                bucket_idx += 1
            else:
                break

        self._buckets[bucket_idx] += 1
        self._count += 1
        self._sum += value
        if value < self._min:
            self._min = value
        if value > self._max:
            self._max = value

    @property
    def count(self) -> int:
        """Total number of recorded values."""
        return self._count

    @property
    def avg(self) -> float:
        """Average of all recorded values."""
        return self._sum / max(self._count, 1)

    @property
    def min_val(self) -> float:
        """Minimum recorded value."""
        return self._min if self._count > 0 else 0.0

    @property
    def max_val(self) -> float:
        """Maximum recorded value."""
        return self._max

    def percentile(self, p: float) -> float:
        """Approximate percentile using histogram buckets.

        Args:
            p: Percentile value (0.0 to 1.0). e.g., 0.5 for p50, 0.99 for p99.

        Returns:
            Approximate value at the given percentile.
        """
        if self._count == 0:
            return 0.0
        target = int(self._count * p)
        cumulative = 0
        for i, count in enumerate(self._buckets):
            cumulative += count
            if cumulative >= target:
                if i < len(self.BUCKET_BOUNDS):
                    return self.BUCKET_BOUNDS[i]
                return self.BUCKET_BOUNDS[-1] * 2  # +inf bucket
        return self._max

    @property
    def p50(self) -> float:
        return self.percentile(0.50)

    @property
    def p90(self) -> float:
        return self.percentile(0.90)

    @property
    def p95(self) -> float:
        return self.percentile(0.95)

    @property
    def p99(self) -> float:
        return self.percentile(0.99)

    def as_dict(self) -> Dict[str, Any]:
        """Serialize histogram to dict."""
        return {
            "count": self._count,
            "avg_ms": round(self.avg * 1000, 2),
            "min_ms": round(self.min_val * 1000, 2),
            "max_ms": round(self.max_val * 1000, 2),
            "p50_ms": round(self.p50 * 1000, 2),
            "p90_ms": round(self.p90 * 1000, 2),
            "p95_ms": round(self.p95 * 1000, 2),
            "p99_ms": round(self.p99 * 1000, 2),
            "buckets": {
                f"<={int(b*1000)}ms": c
                for b, c in zip(self.BUCKET_BOUNDS, self._buckets[:len(self.BUCKET_BOUNDS)])
            } | {f">{int(self.BUCKET_BOUNDS[-1]*1000)}ms": self._buckets[-1]}
        }

    def reset(self) -> None:
        """Reset histogram state."""
        self._buckets = [0] * self.NUM_BUCKETS
        self._count = 0
        self._sum = 0.0
        self._min = float('inf')
        self._max = 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# Metrics Snapshot — Typed, immutable, serializable
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class MetricsSnapshot:
    """Immutable point-in-time snapshot of all counter values.

    Frozen dataclass: once created, cannot be mutated.
    Safe to pass across tasks, log, serialize, or store.

    Individual field reads are GIL-atomic, but the snapshot as a whole
    may be slightly inconsistent (microseconds stale). This is acceptable
    for monitoring and scaling decisions.
    """
    total: int = 0
    ok: int = 0
    fail: int = 0
    timeout_errors: int = 0
    server_errors: int = 0
    total_rt: float = 0.0
    users: int = 0
    rps_rolling: float = 0.0
    rps_instant: float = 0.0
    avg_response_time: float = 0.0
    fail_rate: float = 0.0
    timeout_rate: float = 0.0
    non_timeout_fail_rate: float = 0.0
    server_error_rate: float = 0.0
    duration: float = 0.0
    latency: Dict[str, Any] = field(default_factory=dict)
    benchmark: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        """Convert to plain dict for JSON serialization."""
        return {
            "total": self.total,
            "ok": self.ok,
            "fail": self.fail,
            "timeout_errors": self.timeout_errors,
            "server_errors": self.server_errors,
            "total_rt": round(self.total_rt, 4),
            "users": self.users,
            "rps_rolling": round(self.rps_rolling, 2),
            "rps_instant": round(self.rps_instant, 2),
            "avg_response_time": round(self.avg_response_time, 4),
            "fail_rate": round(self.fail_rate, 4),
            "timeout_rate": round(self.timeout_rate, 4),
            "non_timeout_fail_rate": round(self.non_timeout_fail_rate, 4),
            "server_error_rate": round(self.server_error_rate, 4),
            "duration": round(self.duration, 2),
            "latency": self.latency,
            "benchmark": self.benchmark,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# AtomicMetrics — Lock-free request metrics with histogram + instrumentation
# ═══════════════════════════════════════════════════════════════════════════════

class AtomicMetrics:
    """Lock-free request metrics with histogram tracking and benchmark instrumentation.

    Replaces AtomicCounters with enhanced metrics that add:
    1. LatencyHistogram for response time distribution (p50/p90/p95/p99)
    2. Benchmark instrumentation (record overhead, snapshot overhead)
    3. Typed immutable snapshots (MetricsSnapshot)
    4. Structured dict output for serialization

    HOT PATH: `record()` is <1μs — GIL-atomic increments, no locks, no yields.
    All counter increments compile to single bytecode sequences protected by GIL.

    Usage:
        metrics = AtomicMetrics()
        metrics.record(ok=True, code=200, rt=0.05)
        metrics.record(ok=False, code=0, rt=10.0)  # timeout
        snap = metrics.snapshot()  # Returns immutable MetricsSnapshot
    """

    __slots__ = ('total', 'ok', 'fail', 'timeout_errors',
                 'server_errors', 'total_rt', 'users',
                 '_rps_window', '_latency', '_t0',
                 '_record_count', '_record_time_ns',
                 '_snapshot_count', '_snapshot_time_ns')

    def __init__(self) -> None:
        # GIL-atomic counters — no lock needed for single-value operations
        self.total: int = 0
        self.ok: int = 0
        self.fail: int = 0
        self.timeout_errors: int = 0
        self.server_errors: int = 0
        self.total_rt: float = 0.0
        self.users: int = 0

        # Rolling RPS window (1-minute, 60 buckets = 1 bucket per second)
        self._rps_window: RollingWindow = RollingWindow(window_seconds=60.0, bucket_count=60)
        # Latency histogram for response time distribution
        self._latency: LatencyHistogram = LatencyHistogram()
        # Start time for instant RPS computation
        self._t0: float = time.monotonic()

        # Benchmark instrumentation
        self._record_count: int = 0
        self._record_time_ns: int = 0
        self._snapshot_count: int = 0
        self._snapshot_time_ns: int = 0

    def record(self, ok: bool, code: int, rt: float) -> None:
        """Record a hit result. GIL-atomic — no lock needed.

        This is the HOT PATH — called on every request (10k+ times/sec).
        Must be as fast as possible: no allocations, no locks, no yields.

        Args:
            ok: Whether the request was successful (2xx/3xx).
            code: HTTP status code (0 for connection errors/timeouts).
            rt: Response time in seconds.
        """
        t0 = time.perf_counter_ns()

        self.total += 1
        self.total_rt += rt
        self._rps_window.record()
        self._latency.record(rt)

        if ok:
            self.ok += 1
        else:
            self.fail += 1
            if code == 0:
                self.timeout_errors += 1
            elif 500 <= code < 600:
                self.server_errors += 1

        # Benchmark tracking
        self._record_count += 1
        self._record_time_ns += (time.perf_counter_ns() - t0)

    def snapshot(self) -> MetricsSnapshot:
        """Return an immutable point-in-time snapshot of all metrics.

        BENCHMARK: Measures wall-clock time per call for overhead reporting.
        Target: <5μs per call at 1Hz monitoring rate.

        Returns:
            Frozen MetricsSnapshot dataclass.
        """
        t0 = time.perf_counter_ns()

        total = max(self.total, 1)
        snap = MetricsSnapshot(
            total=self.total,
            ok=self.ok,
            fail=self.fail,
            timeout_errors=self.timeout_errors,
            server_errors=self.server_errors,
            total_rt=self.total_rt,
            users=self.users,
            rps_rolling=self.rps,
            rps_instant=self.requests_per_second,
            avg_response_time=self.avg_response_time,
            fail_rate=self.fail / total,
            timeout_rate=self.timeout_errors / total,
            non_timeout_fail_rate=max(self.fail - self.timeout_errors, 0) / total,
            server_error_rate=self.server_errors / total,
            duration=self.duration,
            latency=self._latency.as_dict(),
            benchmark=self._benchmark_stats(),
        )

        self._snapshot_count += 1
        self._snapshot_time_ns += (time.perf_counter_ns() - t0)
        return snap

    def reset(self) -> None:
        """Reset all metrics to zero."""
        self.total = 0
        self.ok = 0
        self.fail = 0
        self.timeout_errors = 0
        self.server_errors = 0
        self.total_rt = 0.0
        self.users = 0
        self._rps_window = RollingWindow(window_seconds=60.0, bucket_count=60)
        self._latency = LatencyHistogram()
        self._t0 = time.monotonic()
        self._record_count = 0
        self._record_time_ns = 0
        self._snapshot_count = 0
        self._snapshot_time_ns = 0

    # ── Computed Properties (O(1) reads) ──

    @property
    def rps(self) -> float:
        """Rolling requests-per-second (60-second window)."""
        return self._rps_window.rate()

    @property
    def requests_per_second(self) -> float:
        """Instant requests-per-second (since start)."""
        elapsed = time.monotonic() - self._t0 if self._t0 > 0 else 1.0
        return self.total / max(elapsed, 0.001)

    @property
    def avg_response_time(self) -> float:
        """Average response time across all recorded hits."""
        return self.total_rt / max(self.total, 1)

    @property
    def fail_rate(self) -> float:
        """Fraction of requests that failed (0.0 to 1.0)."""
        return self.fail / max(self.total, 1)

    @property
    def timeout_rate(self) -> float:
        """Fraction of requests that timed out (0.0 to 1.0)."""
        return self.timeout_errors / max(self.total, 1)

    @property
    def non_timeout_fail_rate(self) -> float:
        """Fraction of requests that failed for non-timeout reasons."""
        non_timeout_fail = max(self.fail - self.timeout_errors, 0)
        return non_timeout_fail / max(self.total, 1)

    @property
    def server_error_rate(self) -> float:
        """Fraction of requests that returned 5xx (0.0 to 1.0)."""
        return self.server_errors / max(self.total, 1)

    @property
    def duration(self) -> float:
        """Seconds since the metrics were started."""
        return time.monotonic() - self._t0 if self._t0 > 0 else 0.0

    @property
    def latency(self) -> LatencyHistogram:
        """Direct access to the latency histogram for percentile queries."""
        return self._latency

    # ── Benchmark Instrumentation ──

    def _benchmark_stats(self) -> Dict[str, Any]:
        """Compute benchmark overhead statistics."""
        return {
            "record_count": self._record_count,
            "record_avg_ns": round(self._record_time_ns / max(self._record_count, 1), 1),
            "record_total_ms": round(self._record_time_ns / 1_000_000, 3),
            "snapshot_count": self._snapshot_count,
            "snapshot_avg_ns": round(self._snapshot_time_ns / max(self._snapshot_count, 1), 1),
            "rps_window_avg_ns": round(self._rps_window.avg_record_ns, 1),
            "overhead_pct": round(
                (self._record_time_ns / 1_000_000) / max(self.duration, 0.001) * 100, 4
            ),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# PerTargetMetrics — Per-target isolated metrics collection
# ═══════════════════════════════════════════════════════════════════════════════

class PerTargetMetrics:
    """Per-target isolated metrics collection.

    Prevents cross-target contamination. Each target gets its own
    AtomicMetrics instance, so WAF blocks on one target don't
    inflate failure rates for other targets.

    BOUNDED MEMORY: Target count is bounded by a configurable max.
    New targets beyond the limit share an overflow metrics instance.

    Usage:
        metrics = PerTargetMetrics()
        metrics.record("example.com", ok=True, code=200, rt=0.05)
        metrics.record("192.168.1.1", ok=False, code=0, rt=10.0)

        # Per-target health
        health = metrics.target_health("example.com")

        # Aggregate (sum of all targets)
        snap = metrics.aggregate_snapshot()
    """

    __slots__ = ('_targets', '_aggregate', '_max_targets', '_overflow')

    def __init__(self, max_targets: int = 100) -> None:
        self._targets: Dict[str, AtomicMetrics] = {}
        self._aggregate: AtomicMetrics = AtomicMetrics()
        self._max_targets: int = max_targets
        self._overflow: AtomicMetrics = AtomicMetrics()  # Shared overflow for excess targets

    def record(self, target: str, ok: bool, code: int, rt: float) -> None:
        """Record a hit for a specific target (GIL-atomic).

        Args:
            target: Target identifier (domain or IP).
            ok: Whether the request was successful.
            code: HTTP status code.
            rt: Response time in seconds.
        """
        # Get or create per-target metrics
        if target not in self._targets:
            if len(self._targets) < self._max_targets:
                self._targets[target] = AtomicMetrics()
            else:
                # Overflow: record in shared overflow metrics
                self._overflow.record(ok, code, rt)
                self._aggregate.record(ok, code, rt)
                return

        self._targets[target].record(ok, code, rt)
        self._aggregate.record(ok, code, rt)

    def target_snapshot(self, target: str) -> MetricsSnapshot:
        """Get metrics snapshot for a specific target."""
        if target in self._targets:
            return self._targets[target].snapshot()
        return MetricsSnapshot()

    def aggregate_snapshot(self) -> MetricsSnapshot:
        """Get aggregate metrics snapshot across all targets."""
        return self._aggregate.snapshot()

    def target_health(self, target: str) -> float:
        """Compute health score for a specific target (0.0 to 1.0).

        Health = ok / total. Unknown targets = assume healthy (1.0).
        """
        if target not in self._targets:
            return 1.0
        c = self._targets[target]
        if c.total == 0:
            return 1.0
        return c.ok / c.total

    @property
    def targets(self) -> list[str]:
        """List of all known targets."""
        return list(self._targets.keys())

    @property
    def target_count(self) -> int:
        """Number of tracked targets."""
        return len(self._targets)

    def reset(self) -> None:
        """Reset all metrics."""
        self._targets.clear()
        self._aggregate.reset()
        self._overflow.reset()


# ═══════════════════════════════════════════════════════════════════════════════
# Global Metrics Registry — Named metrics collection for subsystem monitoring
# ═══════════════════════════════════════════════════════════════════════════════

class MetricsRegistry:
    """Named metrics collection for subsystem monitoring.

    Provides named AtomicMetrics instances for different subsystems:
    - "request": HTTP request metrics
    - "scheduler": Scheduler tick metrics
    - "shutdown": Shutdown phase metrics
    - "observability": Bus/queue metrics

    All instances are created on first access (lazy init).
    BOUNDED: max_subsystems limits total named instances.
    """

    __slots__ = ('_metrics', '_max_subsystems')

    def __init__(self, max_subsystems: int = 32) -> None:
        self._metrics: Dict[str, AtomicMetrics] = {}
        self._max_subsystems = max_subsystems

    def get(self, name: str) -> AtomicMetrics:
        """Get or create a named metrics instance."""
        if name not in self._metrics:
            if len(self._metrics) >= self._max_subsystems:
                raise RuntimeError(
                    f"MetricsRegistry full ({self._max_subsystems}). "
                    f"Cannot create metrics for '{name}'."
                )
            self._metrics[name] = AtomicMetrics()
        return self._metrics[name]

    def all_snapshots(self) -> Dict[str, MetricsSnapshot]:
        """Get snapshots of all registered metrics."""
        return {name: m.snapshot() for name, m in self._metrics.items()}

    @property
    def names(self) -> list[str]:
        """List of registered metric names."""
        return list(self._metrics.keys())

    def reset(self) -> None:
        """Reset all registered metrics."""
        for m in self._metrics.values():
            m.reset()


__all__ = [
    "AtomicMetrics",
    "MetricsSnapshot",
    "PerTargetMetrics",
    "MetricsRegistry",
    "RollingWindow",
    "LatencyHistogram",
]
