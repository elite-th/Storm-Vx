#!/usr/bin/env python3
"""Tests for Task 1.6 — Add Concurrency Semaphores (W1.6).

Verifies that:
1. bounded_gather() limits concurrency
2. bounded_gather() preserves result order
3. bounded_gather() handles empty input
4. bounded_gather() handles return_exceptions
5. Semaphore cache works correctly
6. dns_scanner uses bounded_gather
7. Pre-existing semaphores (vf_subdomain, vf_dir_fuzzer) still work
"""
import asyncio
import pytest
import time
from unittest.mock import AsyncMock, patch, MagicMock


# ── Import the utility directly ──

from utils.async_helpers import (
    bounded_gather,
    clear_semaphore_cache,
    DEFAULT_MAX_CONCURRENCY,
    DNS_MAX_CONCURRENCY,
    SCAN_MAX_CONCURRENCY,
    _get_semaphore,
    _semaphore_cache,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    """Clear semaphore cache before each test."""
    clear_semaphore_cache()
    yield
    clear_semaphore_cache()


# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: bounded_gather limits concurrency
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_bounded_gather_limits_concurrency():
    """W1.6: bounded_gather should cap concurrent execution."""
    max_seen = 0
    current = 0

    async def tracked_task(delay: float = 0.01):
        nonlocal max_seen, current
        current += 1
        max_seen = max(max_seen, current)
        await asyncio.sleep(delay)
        current -= 1
        return True

    # Launch 50 tasks with max_concurrency=5
    results = await bounded_gather(
        *[tracked_task() for _ in range(50)],
        max_concurrency=5,
    )

    assert max_seen <= 5, f"Concurrency exceeded limit: max_seen={max_seen}"
    assert len(results) == 50
    assert all(r is True for r in results)


@pytest.mark.asyncio
async def test_bounded_gather_concurrency_10():
    """W1.6: Different concurrency limits are respected."""
    max_seen = 0
    current = 0

    async def tracked_task():
        nonlocal max_seen, current
        current += 1
        max_seen = max(max_seen, current)
        await asyncio.sleep(0.01)
        current -= 1
        return True

    results = await bounded_gather(
        *[tracked_task() for _ in range(30)],
        max_concurrency=10,
    )

    assert max_seen <= 10, f"Concurrency exceeded limit: max_seen={max_seen}"
    assert len(results) == 30


# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: Result order is preserved
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_result_order_preserved():
    """W1.6: Results should be in the same order as input coroutines."""
    async def return_index(idx: int):
        await asyncio.sleep(0.001 * (idx % 5))  # Variable delay
        return idx

    results = await bounded_gather(
        *[return_index(i) for i in range(20)],
        max_concurrency=5,
    )

    assert results == list(range(20))


# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: Empty input
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_empty_input():
    """W1.6: Empty input returns empty list."""
    results = await bounded_gather()
    assert results == []


# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: return_exceptions
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_return_exceptions():
    """W1.6: return_exceptions=True captures exceptions instead of raising."""
    async def fail_task():
        raise ValueError("test error")

    async def success_task():
        return "ok"

    results = await bounded_gather(
        success_task(), fail_task(), success_task(),
        max_concurrency=2,
        return_exceptions=True,
    )

    assert results[0] == "ok"
    assert isinstance(results[1], ValueError)
    assert results[2] == "ok"


@pytest.mark.asyncio
async def test_return_exceptions_false_raises():
    """W1.6: return_exceptions=False (default) raises first exception."""
    async def fail_task():
        raise ValueError("test error")

    with pytest.raises(ValueError, match="test error"):
        await bounded_gather(
            fail_task(),
            max_concurrency=2,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: Semaphore cache
# ═══════════════════════════════════════════════════════════════════════════════

def test_semaphore_cache_reuses():
    """W1.6: Same loop + concurrency should reuse semaphore."""
    sem1 = _get_semaphore(20)
    sem2 = _get_semaphore(20)
    assert sem1 is sem2, "Semaphore should be cached and reused"


def test_semaphore_cache_different_concurrency():
    """W1.6: Different concurrency creates different semaphores."""
    sem1 = _get_semaphore(10)
    sem2 = _get_semaphore(20)
    assert sem1 is not sem2, "Different concurrency should create different semaphores"


def test_clear_semaphore_cache():
    """W1.6: clear_semaphore_cache clears the cache."""
    _get_semaphore(20)
    assert len(_semaphore_cache) > 0
    clear_semaphore_cache()
    assert len(_semaphore_cache) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: Default constants
# ═══════════════════════════════════════════════════════════════════════════════

def test_default_constants():
    """W1.6: Default concurrency constants are reasonable."""
    assert DEFAULT_MAX_CONCURRENCY == 20
    assert DNS_MAX_CONCURRENCY == 15
    assert SCAN_MAX_CONCURRENCY == 10
    # DNS should be more conservative than default
    assert DNS_MAX_CONCURRENCY < DEFAULT_MAX_CONCURRENCY
    # Scan should be most conservative
    assert SCAN_MAX_CONCURRENCY < DNS_MAX_CONCURRENCY


# ═══════════════════════════════════════════════════════════════════════════════
# Test 7: Single coroutine
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_single_coroutine():
    """W1.6: Single coroutine works correctly."""
    async def single():
        return "single"

    result = await bounded_gather(single(), max_concurrency=5)
    assert result == ["single"]


# ═══════════════════════════════════════════════════════════════════════════════
# Test 8: Cancellation safety
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_cancellation_propagates():
    """W1.6: CancelledError should propagate through bounded_gather."""
    async def slow_task():
        await asyncio.sleep(10)  # Will be cancelled
        return "never"

    task = asyncio.create_task(
        bounded_gather(slow_task(), max_concurrency=5)
    )
    await asyncio.sleep(0.01)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


# ═══════════════════════════════════════════════════════════════════════════════
# Test 9: dns_scanner imports bounded_gather
# ═══════════════════════════════════════════════════════════════════════════════

def test_dns_scanner_uses_bounded_gather():
    """W1.6: dns_scanner should import bounded_gather from utils.async_helpers."""
    import importlib
    spec = importlib.util.spec_from_file_location(
        "dns_scanner",
        "/home/z/my-project/upload/storm-vx-extracted/finder/dns_scanner.py",
    )
    # We just check the source code contains the import
    with open("/home/z/my-project/upload/storm-vx-extracted/finder/dns_scanner.py", "r") as f:
        source = f.read()
    assert "bounded_gather" in source
    assert "utils.async_helpers" in source
    assert "DNS_MAX_CONCURRENCY" in source


# ═══════════════════════════════════════════════════════════════════════════════
# Test 10: Stress test — many tasks with small concurrency
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_stress_many_tasks():
    """W1.6: Stress test with 100 tasks and concurrency=3."""
    max_seen = 0
    current = 0

    async def quick_task():
        nonlocal max_seen, current
        current += 1
        max_seen = max(max_seen, current)
        await asyncio.sleep(0.001)
        current -= 1
        return 1

    results = await bounded_gather(
        *[quick_task() for _ in range(100)],
        max_concurrency=3,
    )

    assert max_seen <= 3, f"Concurrency exceeded limit: max_seen={max_seen}"
    assert sum(results) == 100


# ═══════════════════════════════════════════════════════════════════════════════
# Test 11: Regression — existing module semaphores still work
# ═══════════════════════════════════════════════════════════════════════════════

def test_vf_dir_fuzzer_has_semaphore():
    """W1.6: vf_dir_fuzzer should still have its own semaphore."""
    with open("/home/z/my-project/upload/storm-vx-extracted/finder/vf_dir_fuzzer.py", "r") as f:
        source = f.read()
    assert "_semaphore" in source
    assert "asyncio.Semaphore" in source


def test_vf_subdomain_has_semaphore():
    """W1.6: vf_subdomain should still have its own semaphore."""
    with open("/home/z/my-project/upload/storm-vx-extracted/finder/vf_subdomain.py", "r") as f:
        source = f.read()
    assert "_semaphore" in source
    assert "asyncio.Semaphore" in source


def test_vf_cache_analyzer_has_semaphore():
    """W1.6: vf_cache_analyzer should still have its own semaphores."""
    with open("/home/z/my-project/upload/storm-vx-extracted/finder/vf_cache_analyzer.py", "r") as f:
        source = f.read()
    assert "Semaphore" in source
