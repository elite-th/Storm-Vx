#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for Task 2.6: Fix Async/Concurrency Model.

Covers:
1. Bounded gather in vf_origin_discovery (semaphore enforcement)
2. Task list pruning in AttackPlugin._spawn_worker_task
3. Lock-free ConnectionPoolStats (atomic counters, active gauge)
4. Concurrency stress tests
5. Cancellation safety
6. Regression tests
"""
from __future__ import annotations

import asyncio
import sys
import os
import time
import threading
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: Bounded Gather — _bounded_gather() in vf_origin_discovery
# ═══════════════════════════════════════════════════════════════════════════════

class TestBoundedGather:
    """Tests for the bounded_gather() concurrency limiter."""

    @pytest.mark.asyncio
    async def test_bounded_gather_empty(self):
        """_bounded_gather with no coroutines returns empty list."""
        from utils.async_helpers import bounded_gather
        result = await bounded_gather()
        assert result == []

    @pytest.mark.asyncio
    async def test_bounded_gather_preserves_order(self):
        """_bounded_gather returns results in input order."""
        from utils.async_helpers import bounded_gather

        async def coro(n):
            await asyncio.sleep(0.01 * (5 - n))  # Later items finish first
            return n

        results = await bounded_gather(
            coro(1), coro(2), coro(3), coro(4), coro(5)
        )
        assert results == [1, 2, 3, 4, 5]

    @pytest.mark.asyncio
    async def test_bounded_gather_enforces_semaphore(self):
        """_bounded_gather limits max concurrent tasks."""
        from utils.async_helpers import bounded_gather, DEFAULT_MAX_CONCURRENCY

        peak_concurrent = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        async def tracked_coro(n):
            nonlocal peak_concurrent, current_concurrent
            async with lock:
                current_concurrent += 1
                peak_concurrent = max(peak_concurrent, current_concurrent)
            await asyncio.sleep(0.05)
            async with lock:
                current_concurrent -= 1
            return n

        # Create more coroutines than the semaphore allows
        num_coros = DEFAULT_MAX_CONCURRENCY * 3
        results = await bounded_gather(
            *[tracked_coro(i) for i in range(num_coros)]
        )

        assert len(results) == num_coros
        assert results == list(range(num_coros))
        # Peak concurrency should not exceed the semaphore limit
        assert peak_concurrent <= DEFAULT_MAX_CONCURRENCY

    @pytest.mark.asyncio
    async def test_bounded_gather_custom_concurrency(self):
        """_bounded_gather respects max_concurrency override."""
        from utils.async_helpers import bounded_gather

        peak_concurrent = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        async def tracked_coro(n):
            nonlocal peak_concurrent, current_concurrent
            async with lock:
                current_concurrent += 1
                peak_concurrent = max(peak_concurrent, current_concurrent)
            await asyncio.sleep(0.05)
            async with lock:
                current_concurrent -= 1
            return n

        results = await bounded_gather(
            *[tracked_coro(i) for i in range(10)],
            max_concurrency=3
        )

        assert len(results) == 10
        assert peak_concurrent <= 3

    @pytest.mark.asyncio
    async def test_bounded_gather_propagates_exceptions(self):
        """_bounded_gather propagates exceptions from coroutines."""
        from utils.async_helpers import bounded_gather

        async def fail_coro():
            raise ValueError("test error")

        async def ok_coro():
            return 42

        with pytest.raises(ValueError, match="test error"):
            await bounded_gather(ok_coro(), fail_coro())

    @pytest.mark.asyncio
    async def test_bounded_gather_cancellation_safety(self):
        """_bounded_gather handles CancelledError correctly."""
        from utils.async_helpers import bounded_gather

        started = asyncio.Event()
        cancel_sent = asyncio.Event()

        async def slow_coro():
            started.set()
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                cancel_sent.set()
                raise

        task = asyncio.create_task(
            bounded_gather(slow_coro())
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert cancel_sent.is_set()

    @pytest.mark.asyncio
    async def test_semaphore_lazy_init(self):
        """_get_semaphore creates a valid semaphore."""
        from utils.async_helpers import _get_semaphore, DEFAULT_MAX_CONCURRENCY

        sem = _get_semaphore(DEFAULT_MAX_CONCURRENCY)
        assert sem is not None
        assert sem._value == DEFAULT_MAX_CONCURRENCY


# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: Task List Pruning — AttackPlugin._spawn_worker_task
# ═══════════════════════════════════════════════════════════════════════════════

class TestTaskListPruning:
    """Tests for completed task pruning in AttackPlugin._spawn_worker_task."""

    @pytest.mark.asyncio
    async def test_prune_completed_tasks(self):
        """_spawn_worker_task prunes completed tasks when list > 50."""
        from tester.vf_attack_base import AttackPlugin

        class TestPlugin(AttackPlugin):
            async def _worker_loop(self, context, worker_id):
                pass

        plugin = TestPlugin()
        plugin._context = MagicMock()
        plugin._stop_event = asyncio.Event()

        # Create many completed tasks
        for i in range(55):
            async def quick():
                pass
            t = asyncio.create_task(quick())
            await t  # Complete immediately
            plugin._tasks.append(t)

        assert len(plugin._tasks) == 55

        # Now spawn a new worker — should trigger pruning (> 50)
        plugin._spawn_worker_task(0)

        # Completed tasks should have been pruned, only active ones remain + new task
        assert len(plugin._tasks) <= 5  # Only the new task

    @pytest.mark.asyncio
    async def test_no_prune_below_threshold(self):
        """No pruning when task list is small (< 50)."""
        from tester.vf_attack_base import AttackPlugin

        class TestPlugin(AttackPlugin):
            async def _worker_loop(self, context, worker_id):
                pass

        plugin = TestPlugin()
        plugin._context = MagicMock()
        plugin._stop_event = asyncio.Event()

        # Add a few completed tasks (below threshold)
        for i in range(10):
            async def quick():
                pass
            t = asyncio.create_task(quick())
            await t
            plugin._tasks.append(t)

        initial_len = len(plugin._tasks)
        plugin._spawn_worker_task(0)

        # All tasks should still be there (below 50 threshold)
        assert len(plugin._tasks) == initial_len + 1  # +1 for the new task

    @pytest.mark.asyncio
    async def test_prune_only_removes_done_tasks(self):
        """Pruning only removes completed tasks, not running ones."""
        from tester.vf_attack_base import AttackPlugin

        class TestPlugin(AttackPlugin):
            async def _worker_loop(self, context, worker_id):
                pass

        plugin = TestPlugin()
        plugin._context = MagicMock()
        plugin._stop_event = asyncio.Event()

        # Create 50 completed tasks
        for i in range(50):
            async def quick():
                pass
            t = asyncio.create_task(quick())
            await t
            plugin._tasks.append(t)

        # Create 5 running tasks that won't complete
        running_event = asyncio.Event()
        running_tasks = []
        async def long_running():
            await running_event.wait()

        for i in range(5):
            t = asyncio.create_task(long_running())
            running_tasks.append(t)

        plugin._tasks.extend(running_tasks)
        assert len(plugin._tasks) == 55

        # Spawn new task — should prune completed, keep running
        plugin._spawn_worker_task(0)

        # Running tasks should survive + the new one
        assert len(plugin._tasks) == 5 + 1  # 5 running + 1 new

        # Clean up
        running_event.set()
        await asyncio.gather(*running_tasks, return_exceptions=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: Lock-Free ConnectionPoolStats
# ═══════════════════════════════════════════════════════════════════════════════

class TestLockFreeConnectionPoolStats:
    """Tests for the refactored lock-free ConnectionPoolStats."""

    def test_record_connection_success(self):
        """record_connection(success=True) increments total and ok."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        stats.record_connection(success=True)
        assert stats.total_connections == 1
        assert stats.ok_connections == 1
        assert stats.failed_connections == 0

    def test_record_connection_failure(self):
        """record_connection(success=False) increments total and failed."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        stats.record_connection(success=False)
        assert stats.total_connections == 1
        assert stats.failed_connections == 1
        assert stats.ok_connections == 0

    def test_record_timeout(self):
        """record_timeout increments timeout counter."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        stats.record_timeout()
        assert stats.timeouts == 1

    def test_record_reuse(self):
        """record_reuse increments reuse counter."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        stats.record_reuse()
        assert stats.reused_connections == 1

    def test_active_connections_inc_dec(self):
        """_inc_active and _dec_active correctly track gauge."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        assert stats._get_active() == 0

        stats._inc_active()
        assert stats._get_active() == 1

        stats._inc_active()
        assert stats._get_active() == 2

        stats._dec_active()
        assert stats._get_active() == 1

    def test_active_never_goes_negative(self):
        """_dec_active floors at 0 to prevent negative gauge."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        stats._dec_active()
        assert stats._get_active() == 0  # Not -1

    def test_get_stats_returns_all_fields(self):
        """get_stats returns a complete stats dict."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        stats.record_connection(success=True)
        stats.record_connection(success=False)
        stats.record_timeout()
        stats.record_reuse()
        stats._inc_active()

        result = stats.get_stats()
        assert result["total"] == 2
        assert result["ok"] == 1
        assert result["failed"] == 1
        assert result["active"] == 1
        assert result["reused"] == 1
        assert result["timeouts"] == 1
        assert "reuse_rate" in result
        assert "failure_rate" in result

    def test_concurrent_counter_safety(self):
        """Lock-free counters are safe under concurrent access (GIL)."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        num_threads = 10
        increments_per_thread = 1000

        def increment_counters():
            for _ in range(increments_per_thread):
                stats.record_connection(success=True)

        threads = [threading.Thread(target=increment_counters) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert stats.total_connections == num_threads * increments_per_thread
        assert stats.ok_connections == num_threads * increments_per_thread

    def test_active_gauge_concurrent_safety(self):
        """Active gauge is safe under concurrent increment/decrement."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        num_threads = 10
        ops_per_thread = 500

        def inc_dec():
            for _ in range(ops_per_thread):
                stats._inc_active()
                stats._dec_active()

        threads = [threading.Thread(target=inc_dec) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # After all inc/dec pairs, gauge should be 0
        assert stats._get_active() == 0

    def test_dns_counters_increment(self):
        """DNS counters increment correctly."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        stats.dns_resolves += 5
        stats.dns_cache_hits += 3

        result = stats.get_stats()
        assert result["dns_resolves"] == 5
        assert result["dns_cache_hits"] == 3


# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: Concurrency Stress Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestConcurrencyStress:
    """Stress tests for async concurrency safety."""

    @pytest.mark.asyncio
    async def test_bounded_gather_high_concurrency(self):
        """_bounded_gather handles 100+ coroutines without exhausting resources."""
        from utils.async_helpers import bounded_gather

        async def micro_coro(n):
            await asyncio.sleep(0.001)
            return n

        results = await bounded_gather(*[micro_coro(i) for i in range(100)])
        assert len(results) == 100
        assert results == list(range(100))

    @pytest.mark.asyncio
    async def test_bounded_gather_mixed_success_failure(self):
        """_bounded_gather with mix of succeeding and failing coroutines."""
        from utils.async_helpers import bounded_gather

        async def maybe_fail(n):
            if n % 3 == 0:
                raise RuntimeError(f"fail-{n}")
            return n

        with pytest.raises(RuntimeError, match="fail-0"):
            await bounded_gather(*[maybe_fail(i) for i in range(10)])

    @pytest.mark.asyncio
    async def test_nested_bounded_gather(self):
        """_bounded_gather can be nested (discovery methods calling resolve)."""
        from utils.async_helpers import bounded_gather

        async def inner_coro(n):
            return n * 2

        async def outer_coro(n):
            inner = await bounded_gather(
                inner_coro(n), inner_coro(n + 1),
                max_concurrency=2
            )
            return sum(inner)

        results = await bounded_gather(
            outer_coro(1), outer_coro(10),
            max_concurrency=2
        )
        # outer_coro(1): inner=[1*2, (1+1)*2] = [2, 4] -> sum=6
        # outer_coro(10): inner=[10*2, (10+1)*2] = [20, 22] -> sum=42
        assert results == [6, 42]


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: Cancellation Safety
# ═══════════════════════════════════════════════════════════════════════════════

class TestCancellationSafety:
    """Tests for proper CancelledError propagation."""

    @pytest.mark.asyncio
    async def test_bounded_gather_cancel_mid_execution(self):
        """Cancelling _bounded_gather while coroutines are running."""
        from utils.async_helpers import bounded_gather

        started = asyncio.Event()
        cancelled_count = 0

        async def slow_coro(n):
            nonlocal cancelled_count
            started.set()
            try:
                await asyncio.sleep(10)
                return n
            except asyncio.CancelledError:
                cancelled_count += 1
                raise

        task = asyncio.create_task(
            bounded_gather(*[slow_coro(i) for i in range(5)])
        )
        await started.wait()
        # Give a moment for all coroutines to start
        await asyncio.sleep(0.05)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        # At least one coroutine should have received CancelledError
        assert cancelled_count >= 1

    @pytest.mark.asyncio
    async def test_connection_pool_stats_under_cancellation(self):
        """ConnectionPoolStats remains consistent under task cancellation."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        stats._inc_active()
        stats._inc_active()

        # Simulate a cancelled request: active should decrement
        stats._dec_active()

        assert stats._get_active() == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: Regression Tests — Verify existing behavior preserved
# ═══════════════════════════════════════════════════════════════════════════════

class TestRegression:
    """Regression tests ensuring existing behavior is preserved."""

    def test_connection_pool_stats_interface_unchanged(self):
        """ConnectionPoolStats public API is backward compatible."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()

        # All original public methods must exist
        assert hasattr(stats, 'record_connection')
        assert hasattr(stats, 'record_timeout')
        assert hasattr(stats, 'record_reuse')
        assert hasattr(stats, 'get_stats')

        # All original fields must exist
        assert hasattr(stats, 'total_connections')
        assert hasattr(stats, 'active_connections')
        assert hasattr(stats, 'ok_connections')
        assert hasattr(stats, 'failed_connections')
        assert hasattr(stats, 'reused_connections')
        assert hasattr(stats, 'timeouts')
        assert hasattr(stats, 'dns_resolves')
        assert hasattr(stats, 'dns_cache_hits')

    def test_get_stats_returns_same_keys(self):
        """get_stats() returns the same dict keys as before."""
        from vf_network import ConnectionPoolStats

        stats = ConnectionPoolStats()
        result = stats.get_stats()

        expected_keys = {
            "total", "active", "ok", "failed",
            "reused", "timeouts", "dns_resolves", "dns_cache_hits",
            "reuse_rate", "failure_rate"
        }
        assert set(result.keys()) == expected_keys

    @pytest.mark.asyncio
    async def test_bounded_gather_single_coroutine(self):
        """_bounded_gather with a single coroutine works like asyncio.gather."""
        from utils.async_helpers import bounded_gather

        async def coro():
            return 42

        result = await bounded_gather(coro())
        assert result == [42]

    def test_attack_plugin_tasks_list_still_works(self):
        """AttackPlugin._tasks is still a regular list (backward compatible)."""
        from tester.vf_attack_base import AttackPlugin

        class TestPlugin(AttackPlugin):
            async def _worker_loop(self, context, worker_id):
                pass

        plugin = TestPlugin()
        assert isinstance(plugin._tasks, list)
        assert len(plugin._tasks) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Test 7: Memory Safety — Verify unbounded growth is prevented
# ═══════════════════════════════════════════════════════════════════════════════

class TestMemorySafety:
    """Tests verifying unbounded growth is prevented."""

    @pytest.mark.asyncio
    async def test_task_list_bounded_after_pruning(self):
        """Task list stays bounded even with many spawn/prune cycles."""
        from tester.vf_attack_base import AttackPlugin

        class TestPlugin(AttackPlugin):
            async def _worker_loop(self, context, worker_id):
                await asyncio.sleep(0.01)  # Quick exit

        plugin = TestPlugin()
        plugin._context = MagicMock()
        plugin._stop_event = asyncio.Event()

        # Simulate many scaling events (spawn → complete → spawn)
        for cycle in range(20):
            # Spawn 10 workers
            for i in range(10):
                plugin._spawn_worker_task(i)

            # Wait for all tasks to complete
            await asyncio.sleep(0.05)  # Give them time to finish

        # After many cycles, the list should not grow unboundedly
        # The pruning in _spawn_worker_task kicks in at >50
        # Without pruning: 20*10 = 200 tasks
        # With pruning: should be much less
        # But some tasks from the last cycle may still be alive, so allow some slack
        assert len(plugin._tasks) < 100  # Should be much less than 200 without pruning

    @pytest.mark.asyncio
    async def test_bounded_gather_doesnt_exhaust_semaphore(self):
        """Semaphore is properly released after each coroutine completes."""
        from utils.async_helpers import bounded_gather, _get_semaphore, DEFAULT_MAX_CONCURRENCY

        async def quick():
            return 1

        # Run multiple rounds to verify semaphore isn't leaked
        for _ in range(10):
            await bounded_gather(*[quick() for _ in range(30)])

        # Semaphore should still be usable
        sem = _get_semaphore(DEFAULT_MAX_CONCURRENCY)
        assert sem._value > 0
