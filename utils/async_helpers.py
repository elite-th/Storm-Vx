#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""utils.async_helpers — Shared async concurrency utilities.

W1.6 FIX: Centralized bounded_gather() function for capping
concurrent async operations across all finder/infra modules.

Previously, each module implemented its own semaphore pattern (or none).
This module provides a single source of truth for bounded concurrency.

DEFAULT CONCURRENCY: 20 concurrent tasks — matches the pattern used
in vf_origin_discovery.py (W2.6) and is safe for DNS/HTTP operations.
"""
from __future__ import annotations

import asyncio
from typing import Any, Coroutine, List


# ═══════════════════════════════════════════════════════════════════════════════
# Default concurrency limits
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_MAX_CONCURRENCY: int = 20
DNS_MAX_CONCURRENCY: int = 15  # DNS lookups — more conservative to avoid throttling
SCAN_MAX_CONCURRENCY: int = 10  # Directory/path scanning — avoid overwhelming target


# ═══════════════════════════════════════════════════════════════════════════════
# Semaphore cache — one semaphore per (loop_id, concurrency_level)
# ═══════════════════════════════════════════════════════════════════════════════

_semaphore_cache: dict[tuple[int, int], asyncio.Semaphore] = {}


def _get_semaphore(max_concurrency: int) -> asyncio.Semaphore:
    """Get or create a cached semaphore for the current event loop.

    Reuses semaphores across calls within the same event loop and
    concurrency level, avoiding unnecessary object creation.

    Thread-safe under CPython's GIL (dict operations are atomic).
    """
    try:
        loop_id = id(asyncio.get_running_loop())
    except RuntimeError:
        loop_id = 0

    key = (loop_id, max_concurrency)
    if key not in _semaphore_cache:
        _semaphore_cache[key] = asyncio.Semaphore(max_concurrency)
    return _semaphore_cache[key]


async def bounded_gather(
    *coros: Coroutine[Any, Any, Any],
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
    return_exceptions: bool = False,
) -> List[Any]:
    """Run coroutines concurrently with a semaphore cap.

    Unlike bare ``asyncio.gather()`` which runs ALL coroutines
    simultaneously, this bounds concurrency to prevent resource
    exhaustion (connection pools, DNS throttling, file descriptors).

    Each coroutine acquires the semaphore before executing, so at
    most ``max_concurrency`` run at once.

    Args:
        *coros: Coroutine objects to execute.
        max_concurrency: Maximum concurrent tasks (default 20).
        return_exceptions: If True, exceptions are returned as results
            instead of being raised (same as asyncio.gather).

    Returns:
        List of results in the same order as input coroutines.

    Examples:
        >>> # Safe: at most 20 concurrent requests
        >>> results = await bounded_gather(*[fetch(url) for url in urls])
        >>> # Custom concurrency for DNS (more conservative)
        >>> results = await bounded_gather(*[lookup(d) for d in domains],
        ...                                max_concurrency=10)
    """
    if not coros:
        return []

    sem = _get_semaphore(max_concurrency)

    async def _wrap(coro: Coroutine[Any, Any, Any]) -> Any:
        async with sem:
            return await coro

    return await asyncio.gather(
        *[_wrap(c) for c in coros],
        return_exceptions=return_exceptions,
    )


def clear_semaphore_cache() -> None:
    """Clear the semaphore cache (useful in tests)."""
    _semaphore_cache.clear()
