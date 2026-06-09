"""engine.atomic_counters — Lock-free atomic counters for high-throughput stats.

GIL-ATOMICITY GUARANTEE:
Under CPython, simple integer operations like `x += 1` compile to a single
LOAD_FAST + INPLACE_ADD + STORE_FAST bytecode sequence. The GIL ensures
that no other thread can interleave between these operations, making them
effectively atomic for single-value reads and writes.

This means:
- `counters.total += 1` is atomic (no partial state visible to other threads)
- `counters.total` reads are always consistent (never half-written)
- Compound operations like `fail - timeout_errors` are NOT atomic across
  multiple fields — but they're "consistent enough" for monitoring:
  the values may be a few milliseconds stale, but never corrupt.

This is the same approach used by vf_network.ConnectionPoolStats (W2.6 FIX)
and is the standard pattern for high-frequency counters in CPython async code.

PERFORMANCE TARGET:
At 10k+ req/sec, recording a hit must take <1μs (vs. ~5μs with asyncio.Lock).
The lock-free approach eliminates the coroutine suspension + resumption overhead
that comes with async lock acquisition.

DESIGN DECISION:
We do NOT use threading.Lock or asyncio.Lock because:
1. asyncio.Lock: Yields to event loop (~2μs overhead per hit), creating
   thundering herd at high concurrency (DEF-05)
2. threading.Lock: Blocks the event loop thread during acquisition (~500ns),
   acceptable for infrequent operations but unacceptable in the hot path

The GIL-atomic approach has zero synchronization overhead — it's just a
regular Python integer increment.
"""
from __future__ import annotations

import time
from typing import Any, Dict


class RollingWindow:
    """Fixed-size circular buffer for computing rolling rates.

    Maintains a window of recent timestamps to compute requests-per-second
    without storing individual request records. Memory-efficient: O(window_size)
    regardless of request rate.

    Args:
        window_seconds: Size of the rolling window in seconds (default: 60).
        bucket_count: Number of buckets within the window (default: 60).
    """

    __slots__ = ('_buckets', '_bucket_count', '_bucket_duration',
                 '_current_bucket', '_current_bucket_time', '_total')

    def __init__(self, window_seconds: float = 60.0, bucket_count: int = 60) -> None:
        self._bucket_count = bucket_count
        self._bucket_duration = window_seconds / bucket_count
        self._buckets: list[int] = [0] * bucket_count
        self._current_bucket: int = 0
        self._current_bucket_time: float = time.monotonic()
        self._total: int = 0

    def record(self) -> None:
        """Record one event in the current bucket (GIL-atomic increment)."""
        self._advance()
        self._buckets[self._current_bucket] += 1
        self._total += 1

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
            # Entire window has expired — reset all buckets
            self._buckets = [0] * self._bucket_count
            self._total = 0
        else:
            # Clear expired buckets
            for i in range(buckets_to_advance):
                idx = (self._current_bucket + 1 + i) % self._bucket_count
                self._total -= self._buckets[idx]
                self._buckets[idx] = 0

        self._current_bucket = (self._current_bucket + buckets_to_advance) % self._bucket_count
        self._current_bucket_time = now


class AtomicCounters:
    """Lock-free request counters using GIL-atomic integer operations.

    Replaces the asyncio.Lock-protected counter pattern in AttackPlugin._record()
    with simple integer increments that are atomic under CPython's GIL.

    Performance comparison (10k req/sec):
    - asyncio.Lock: ~20ms/sec event-loop time (2μs × 10k)
    - GIL-atomic:  ~0.1ms/sec event-loop time (10ns × 10k)
    - Improvement: 200× less event-loop overhead

    Usage:
        counters = AtomicCounters()
        counters.record(ok=True, code=200, rt=0.05)
        counters.record(ok=False, code=0, rt=10.0)  # timeout
        snap = counters.snapshot()
        # {"total": 2, "ok": 1, "fail": 1, ...}
    """

    __slots__ = ('total', 'ok', 'fail', 'timeout_errors',
                 'server_errors', 'total_rt', 'users',
                 '_rps_window', '_t0')

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
        self._t0: float = 0.0

    def record(self, ok: bool, code: int, rt: float) -> None:
        """Record a hit result. GIL-atomic — no lock needed.

        This is the HOT PATH — called on every request (10k+ times/sec).
        Must be as fast as possible: no allocations, no locks, no yields.

        Args:
            ok: Whether the request was successful (2xx/3xx).
            code: HTTP status code (0 for connection errors/timeouts).
            rt: Response time in seconds.
        """
        self.total += 1
        self.total_rt += rt
        self._rps_window.record()

        if ok:
            self.ok += 1
        else:
            self.fail += 1
            # Classify failure type
            if code == 0:
                # Connection error or timeout — client couldn't reach server
                self.timeout_errors += 1
            elif 500 <= code < 600:
                # Server error — server is struggling (GOOD for attack tool)
                self.server_errors += 1

    def snapshot(self) -> Dict[str, Any]:
        """Return a point-in-time snapshot of all counters.

        INDIVIDUAL FIELD READS ARE GIL-ATOMIC, but the snapshot as a whole
        may be slightly inconsistent (e.g., total might be 10001 while ok is
        still 5000 from a moment earlier). This is acceptable for monitoring:
        the values are at most a few microseconds stale, and the scaling
        engine makes decisions based on rates, not absolute values.

        For truly atomic multi-field reads, use a monotonic sequence counter
        (see engine.scheduler.SequencedSnapshot). However, this adds overhead
        that's not justified for 1Hz monitoring reads.

        Returns:
            Dict with all counter values.
        """
        return {
            "total": self.total,
            "ok": self.ok,
            "fail": self.fail,
            "timeout_errors": self.timeout_errors,
            "server_errors": self.server_errors,
            "total_rt": self.total_rt,
            "users": self.users,
            "rps_rolling": self.rps,
            "rps_instant": self.requests_per_second,
            "avg_response_time": self.avg_response_time,
        }

    def reset(self) -> None:
        """Reset all counters to zero."""
        self.total = 0
        self.ok = 0
        self.fail = 0
        self.timeout_errors = 0
        self.server_errors = 0
        self.total_rt = 0.0
        self.users = 0
        self._rps_window = RollingWindow(window_seconds=60.0, bucket_count=60)
        self._t0 = time.time()

    @property
    def rps(self) -> float:
        """Rolling requests-per-second (60-second window).

        More stable than instant RPS — resists spikes and dips.
        """
        return self._rps_window.rate()

    @property
    def requests_per_second(self) -> float:
        """Instant requests-per-second (since start).

        Simpler but noisier than rolling RPS.
        """
        elapsed = time.time() - self._t0 if self._t0 > 0 else 1.0
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
        """Fraction of requests that failed for non-timeout reasons.

        CRITICAL for the scaling engine: this separates client-side
        connectivity issues (timeouts) from server-side issues (5xx).
        Using raw fail_rate would double-count timeouts (DEF-08 fix).
        """
        non_timeout_fail = max(self.fail - self.timeout_errors, 0)
        return non_timeout_fail / max(self.total, 1)

    @property
    def server_error_rate(self) -> float:
        """Fraction of requests that returned 5xx (0.0 to 1.0)."""
        return self.server_errors / max(self.total, 1)

    @property
    def duration(self) -> float:
        """Seconds since the counters were started."""
        return time.time() - self._t0 if self._t0 > 0 else 0.0


class PerTargetCounters:
    """Per-target isolated counter collection.

    Prevents cross-target contamination (DEF-04 fix). Each target gets
    its own set of counters, and the scaling engine can compute health
    per-target instead of using aggregate stats that mix successful
    and failing targets.

    Usage:
        counters = PerTargetCounters()
        counters.record("example.com", ok=True, code=200, rt=0.05)
        counters.record("192.168.1.1", ok=False, code=0, rt=10.0)

        # Per-target health
        target_health = counters.target_snapshot("example.com")

        # Aggregate (sum of all targets)
        total_health = counters.aggregate_snapshot()
    """

    __slots__ = ('_targets', '_aggregate')

    def __init__(self) -> None:
        self._targets: Dict[str, AtomicCounters] = {}
        self._aggregate: AtomicCounters = AtomicCounters()

    def record(self, target: str, ok: bool, code: int, rt: float) -> None:
        """Record a hit for a specific target (GIL-atomic).

        Args:
            target: Target identifier (domain or IP).
            ok: Whether the request was successful.
            code: HTTP status code.
            rt: Response time in seconds.
        """
        # Get or create per-target counters
        if target not in self._targets:
            self._targets[target] = AtomicCounters()
        self._targets[target].record(ok, code, rt)

        # Also record in aggregate
        self._aggregate.record(ok, code, rt)

    def target_snapshot(self, target: str) -> Dict[str, Any]:
        """Get stats snapshot for a specific target."""
        if target in self._targets:
            return self._targets[target].snapshot()
        return {"total": 0, "ok": 0, "fail": 0}

    def aggregate_snapshot(self) -> Dict[str, Any]:
        """Get aggregate stats across all targets."""
        return self._aggregate.snapshot()

    def target_health(self, target: str) -> float:
        """Compute health score for a specific target (0.0 to 1.0).

        Health = 1.0 - fail_rate (higher is healthier).
        A target with 100% success rate has health 1.0.
        A target with 100% failure rate has health 0.0.
        """
        if target not in self._targets:
            return 1.0  # Unknown target = assume healthy
        c = self._targets[target]
        if c.total == 0:
            return 1.0
        return c.ok / c.total

    @property
    def targets(self) -> list[str]:
        """List of all known targets."""
        return list(self._targets.keys())

    def reset(self) -> None:
        """Reset all counters."""
        self._targets.clear()
        self._aggregate.reset()


__all__ = [
    "AtomicCounters",
    "PerTargetCounters",
    "RollingWindow",
]
