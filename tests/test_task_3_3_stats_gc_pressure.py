#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for Task 3.3 — Fix Stats Rolling Window / GC Pressure.

Verifies that:
1. _rps_window is a deque, not a list
2. Rolling RPS calculation produces correct results
3. Pruning uses popleft() (zero-allocation), not list comprehension
4. deque maxlen bound prevents unbounded growth
5. High-frequency record() calls don't create GC pressure
6. Thread-safety under concurrent record() calls
7. RPS window accuracy over time
8. Backward compatibility with get_snapshot()
9. Empty/edge case handling
10. Cancellation safety (record() called during cancellation)
"""
from __future__ import annotations

import asyncio
import time
import threading
from collections import deque
from unittest.mock import MagicMock

import pytest

from tester.vf_data import Stats, HitResult


# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: Data structure is deque, not list
# ═══════════════════════════════════════════════════════════════════════════════

def test_rps_window_is_deque():
    """W3.3: _rps_window must be a deque, not a list."""
    stats = Stats()
    assert isinstance(stats._rps_window, deque), \
        f"Expected deque, got {type(stats._rps_window)}"


def test_rps_window_has_maxlen():
    """W3.3: _rps_window deque must have maxlen for safety bound."""
    stats = Stats()
    assert stats._rps_window.maxlen == 10_000, \
        f"Expected maxlen=10000, got {stats._rps_window.maxlen}"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: Rolling RPS calculation is correct
# ═══════════════════════════════════════════════════════════════════════════════

def test_rps_rolling_basic():
    """W3.3: Rolling RPS is computed correctly from window entries."""
    stats = Stats()
    stats.t0 = time.monotonic() - 10
    stats._first_request_time = stats.t0

    # Record 10 hits
    for i in range(10):
        stats.record(HitResult(ok=True, code=200, rt=0.1))

    # Should have some RPS value > 0
    assert stats.rps_rolling > 0, f"rps_rolling should be > 0, got {stats.rps_rolling}"


def test_rps_rolling_window_prunes_old_entries():
    """W3.3: Entries older than _RPS_WINDOW_SECONDS are pruned."""
    stats = Stats()
    stats.t0 = time.monotonic() - 10
    stats._first_request_time = stats.t0

    # Record some hits
    for i in range(5):
        stats.record(HitResult(ok=True, code=200, rt=0.1))

    initial_window_len = len(stats._rps_window)
    assert initial_window_len == 5

    # Manually inject old entries to test pruning
    old_time = time.monotonic() - 10  # 10 seconds ago — way beyond 3s window
    with stats._lock:
        stats._rps_window.appendleft((old_time, 1))

    # Record a new hit — this should trigger pruning of the old entry
    stats.record(HitResult(ok=True, code=200, rt=0.1))

    # The old entry should have been pruned
    # Window should only contain recent entries
    for ts, cnt in stats._rps_window:
        assert ts > time.monotonic() - 4, "Old entries should have been pruned"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: Zero-allocation pruning (no list comprehension)
# ═══════════════════════════════════════════════════════════════════════════════

def test_prune_uses_popleft_not_reassignment():
    """W3.3: Pruning uses popleft(), not list comprehension reassignment.

    Verify by checking the source code that the old pattern
    `self._rps_window = [...]` is gone.
    """
    import inspect
    source = inspect.getsource(Stats.record)

    # Old pattern: creates a new list
    assert "self._rps_window = [" not in source, \
        "Should not create new list via comprehension"

    # New pattern: uses popleft
    assert "popleft()" in source, \
        "Should use popleft() for zero-allocation pruning"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: deque maxlen bound prevents unbounded growth
# ═══════════════════════════════════════════════════════════════════════════════

def test_maxlen_prevents_unbounded_growth():
    """W3.3: deque maxlen ensures window never exceeds 10000 entries."""
    stats = Stats()
    stats.t0 = time.monotonic() - 100
    stats._first_request_time = stats.t0

    # Record many hits — more than maxlen
    for i in range(15_000):
        stats.record(HitResult(ok=True, code=200, rt=0.01))

    # deque maxlen should prevent growth beyond 10_000
    assert len(stats._rps_window) <= 10_000, \
        f"Window exceeded maxlen: {len(stats._rps_window)}"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: High-frequency record() — no GC pressure
# ═══════════════════════════════════════════════════════════════════════════════

def test_high_frequency_record_no_gc_pressure():
    """W3.3: 10k+ record() calls should not create excessive list objects.

    This test verifies that the deque-based approach doesn't create
    new container objects during pruning (unlike the old list comprehension).
    """
    import gc

    stats = Stats()
    stats.t0 = time.monotonic() - 100
    stats._first_request_time = stats.t0

    # Force GC and count list objects before
    gc.collect()
    list_count_before = sum(1 for obj in gc.get_objects() if isinstance(obj, list))

    # Simulate 10k RPS for 0.5 seconds
    for i in range(5_000):
        stats.record(HitResult(ok=True, code=200, rt=0.01))

    gc.collect()
    list_count_after = sum(1 for obj in gc.get_objects() if isinstance(obj, list))

    # The old code would create ~10 new list objects (prune every 500).
    # The new code should create 0.
    # Allow some slack for Python internals, but should be much less than 10.
    new_lists = list_count_after - list_count_before
    assert new_lists < 5, \
        f"Too many new list objects created: {new_lists} " \
        f"(before={list_count_before}, after={list_count_after})"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: Thread-safety under concurrent record() calls
# ═══════════════════════════════════════════════════════════════════════════════

def test_concurrent_record_thread_safety():
    """W3.3: Stats.record() is thread-safe under concurrent access."""
    stats = Stats()
    stats.t0 = time.monotonic() - 10
    stats._first_request_time = stats.t0

    num_threads = 10
    records_per_thread = 500

    def record_hits():
        for _ in range(records_per_thread):
            stats.record(HitResult(ok=True, code=200, rt=0.01))

    threads = [threading.Thread(target=record_hits) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert stats.total == num_threads * records_per_thread
    assert stats.ok == num_threads * records_per_thread
    assert len(stats._rps_window) <= 10_000


def test_concurrent_record_deque_consistency():
    """W3.3: Deque remains consistent under concurrent writes.

    No data corruption or IndexError should occur.
    """
    stats = Stats()
    stats.t0 = time.monotonic() - 10
    stats._first_request_time = stats.t0

    num_threads = 5
    records_per_thread = 1000

    errors = []

    def record_hits():
        try:
            for _ in range(records_per_thread):
                stats.record(HitResult(ok=True, code=200, rt=0.01))
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=record_hits) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Errors during concurrent access: {errors}"
    assert stats.total == num_threads * records_per_thread


# ═══════════════════════════════════════════════════════════════════════════════
# Test 7: RPS window accuracy over time
# ═══════════════════════════════════════════════════════════════════════════════

def test_rps_window_seconds_constant():
    """W3.3: _RPS_WINDOW_SECONDS should be 3.0."""
    stats = Stats()
    assert stats._RPS_WINDOW_SECONDS == 3.0


def test_rps_rolling_reflects_recent_activity():
    """W3.3: rps_rolling reflects only recent (3s) activity, not lifetime."""
    stats = Stats()
    base_time = time.monotonic()
    stats.t0 = base_time - 30
    stats._first_request_time = base_time - 30

    # Record 100 hits "in the past" by manipulating window directly
    # (simulate that they were recorded 10 seconds ago)
    with stats._lock:
        for i in range(100):
            stats._rps_window.append((base_time - 10, 1))
        stats.total = 100
        stats.ok = 100

    # Now record a few recent hits
    stats.record(HitResult(ok=True, code=200, rt=0.1))
    stats.record(HitResult(ok=True, code=200, rt=0.1))
    stats.record(HitResult(ok=True, code=200, rt=0.1))

    # After pruning, old entries should be gone
    # The window should only contain the 3 recent entries
    assert len(stats._rps_window) == 3, \
        f"Expected 3 entries after prune, got {len(stats._rps_window)}"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 8: Backward compatibility with get_snapshot()
# ═══════════════════════════════════════════════════════════════════════════════

def test_get_snapshot_still_works():
    """W3.3: get_snapshot() returns all expected fields."""
    stats = Stats()
    stats.t0 = time.monotonic() - 5
    stats._first_request_time = stats.t0
    stats.record(HitResult(ok=True, code=200, rt=0.1))
    stats.record(HitResult(ok=False, code=500, rt=0.5))
    stats.record(HitResult(ok=False, code=0, rt=0, err="TimeoutError"))

    snapshot = stats.get_snapshot()
    assert snapshot["total"] == 3
    assert snapshot["ok"] == 1
    assert snapshot["fail"] == 2
    assert snapshot["timeout_errors"] == 1
    assert snapshot["server_errors"] == 1
    assert snapshot["avg_response_time"] > 0


def test_get_snapshot_returns_same_keys():
    """W3.3: get_snapshot() returns consistent keys."""
    stats = Stats()
    result = stats.get_snapshot()
    expected_keys = {
        "total", "ok", "fail", "timeout_errors",
        "server_errors", "client_errors", "rate_limited",
        "avg_response_time",
    }
    assert set(result.keys()) == expected_keys


# ═══════════════════════════════════════════════════════════════════════════════
# Test 9: Edge cases
# ═══════════════════════════════════════════════════════════════════════════════

def test_empty_window_rps_is_zero():
    """W3.3: rps_rolling is 0 when no requests have been recorded."""
    stats = Stats()
    assert stats.rps_rolling == 0.0


def test_single_hit_no_rolling_rps():
    """W3.3: Single hit doesn't produce a meaningful rolling RPS (need >= 2)."""
    stats = Stats()
    stats.t0 = time.monotonic()
    stats._first_request_time = stats.t0
    stats.record(HitResult(ok=True, code=200, rt=0.1))
    # With only 1 entry, rps_rolling should stay 0 (need >= 2 for duration calc)
    assert stats.rps_rolling == 0.0


def test_hit_result_dataclass():
    """W3.3: HitResult dataclass works correctly."""
    hit = HitResult(ok=True, code=200, rt=0.5, mode="PAGE", err="", url="/test")
    assert hit.ok is True
    assert hit.code == 200
    assert hit.rt == 0.5
    assert hit.mode == "PAGE"


def test_window_prunes_on_every_record():
    """W3.3: Pruning happens on every record() call (no throttle)."""
    stats = Stats()
    stats.t0 = time.monotonic() - 10
    stats._first_request_time = stats.t0

    # Inject an old entry
    with stats._lock:
        stats._rps_window.append((time.monotonic() - 5, 1))  # 5s ago

    # Record a new hit — should prune the old entry (> 3s window)
    stats.record(HitResult(ok=True, code=200, rt=0.1))

    # Only the new entry should remain
    assert len(stats._rps_window) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Test 10: Cancellation safety
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_record_during_cancellation():
    """W3.3: Stats.record() doesn't interfere with CancelledError."""
    stats = Stats()
    stats.t0 = time.monotonic()
    stats._first_request_time = stats.t0

    async def record_many():
        for i in range(100_000):
            stats.record(HitResult(ok=True, code=200, rt=0.01))
            await asyncio.sleep(0)  # Yield to allow cancellation
            # Add a longer sleep every 100 iterations to give cancel a chance
            if i % 100 == 0:
                await asyncio.sleep(0.01)

    task = asyncio.create_task(record_many())
    await asyncio.sleep(0.05)  # Let some records happen
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    # Stats should still be consistent
    assert stats.total > 0
    assert stats.ok == stats.total
    assert isinstance(stats._rps_window, deque)


# ═══════════════════════════════════════════════════════════════════════════════
# Test 11: Stress test — rapid record() calls
# ═══════════════════════════════════════════════════════════════════════════════

def test_stress_rapid_record():
    """W3.3: 50k rapid record() calls complete without errors."""
    stats = Stats()
    stats.t0 = time.monotonic() - 100
    stats._first_request_time = stats.t0

    for i in range(50_000):
        stats.record(HitResult(ok=(i % 5 != 0), code=200 if i % 5 != 0 else 500, rt=0.01))

    assert stats.total == 50_000
    assert stats.ok == 40_000  # 4/5 success
    assert stats.fail == 10_000  # 1/5 fail
    assert len(stats._rps_window) <= 10_000  # maxlen bound


# ═══════════════════════════════════════════════════════════════════════════════
# Test 12: Verify source code has no list comprehension reassignment
# ═══════════════════════════════════════════════════════════════════════════════

def test_no_list_reassignment_in_source():
    """W3.3: Source file should not contain `self._rps_window = [` pattern."""
    with open("/home/z/my-project/upload/storm-vx-extracted/tester/vf_data.py", "r") as f:
        source = f.read()

    # The old pattern that creates GC pressure
    assert "self._rps_window = [" not in source, \
        "Found list comprehension reassignment — should use popleft() instead"

    # The new pattern that avoids GC pressure
    assert "popleft()" in source, \
        "Missing popleft() call — should use zero-allocation pruning"


def test_deque_import_in_source():
    """W3.3: Source file should import deque from collections."""
    with open("/home/z/my-project/upload/storm-vx-extracted/tester/vf_data.py", "r") as f:
        source = f.read()

    assert "from collections import deque" in source, \
        "Missing deque import from collections"
