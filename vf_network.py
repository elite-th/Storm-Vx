"""Storm-Vx Network Utilities.

Provides connection retry logic, adaptive timeouts, and network
helper functions for robust HTTP operations.
"""
from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, Any, Callable, TypeVar, Awaitable
from dataclasses import dataclass, field

import threading

from vf_common import C

# W2.6 FIX: Use threading atomics for lock-free counter increments.
# Python's threading module provides add/sub operations that are atomic
# under CPython's GIL. For simple integer counters this is safe and
# avoids blocking the event loop with threading.Lock.acquire() inside
# aiohttp TraceConfig async callbacks.
#
# Note: active_connections is a GAUGE (can go up and down) so it
# requires a read-modify-write. We protect it with a dedicated
# threading.Lock since it's the only field that truly needs it.
# All other fields are monotonic counters that only increment.


T = TypeVar('T')


@dataclass
class RetryConfig:
    """Configuration for connection retry behavior."""
    max_retries: int = 3
    base_delay: float = 0.5  # seconds
    max_delay: float = 10.0  # seconds
    exponential_base: float = 2.0
    jitter: bool = True  # Add random jitter to prevent thundering herd


@dataclass
class AdaptiveTimeout:
    """Tracks response times and adjusts timeout dynamically.
    
    Uses exponential moving average (EMA) to track typical response
    times and sets timeout as a multiple of the EMA.
    """
    initial_timeout: float = 10.0
    ema_alpha: float = 0.1  # EMA smoothing factor
    timeout_multiplier: float = 3.0  # timeout = EMA * multiplier
    min_timeout: float = 3.0
    max_timeout: float = 30.0
    
    _ema: float = 0.0
    _sample_count: int = 0
    
    def record(self, response_time: float) -> None:
        """Record a response time sample and update EMA."""
        if self._sample_count == 0:
            self._ema = response_time
        else:
            self._ema = self.ema_alpha * response_time + (1 - self.ema_alpha) * self._ema
        self._sample_count += 1
    
    @property
    def current_timeout(self) -> float:
        """Get the current adaptive timeout value."""
        if self._sample_count < 3:
            return self.initial_timeout
        
        adaptive = self._ema * self.timeout_multiplier
        return max(self.min_timeout, min(adaptive, self.max_timeout))
    
    @property
    def average_response_time(self) -> float:
        """Get the current EMA response time."""
        return self._ema if self._sample_count > 0 else 0.0


async def retry_async(
    func: Callable[..., Awaitable[T]],
    *args,
    retry_config: RetryConfig = RetryConfig(),
    retryable_exceptions: tuple = (asyncio.TimeoutError, ConnectionError, OSError),
    on_retry: Callable[[int, Exception], None] | None = None,
    **kwargs,
) -> T:
    """Execute an async function with retry logic.
    
    Args:
        func: Async callable to execute.
        *args: Positional arguments for func.
        retry_config: Retry configuration.
        retryable_exceptions: Exceptions that trigger a retry.
        on_retry: Optional callback(attempt, exception) called before each retry.
        **kwargs: Keyword arguments for func.
        
    Returns:
        Result of successful function call.
        
    Raises:
        Last exception if all retries exhausted.
    """
    last_exception = None
    
    for attempt in range(retry_config.max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except retryable_exceptions as e:
            last_exception = e
            if attempt < retry_config.max_retries:
                # Calculate delay with exponential backoff
                delay = min(
                    retry_config.base_delay * (retry_config.exponential_base ** attempt),
                    retry_config.max_delay
                )
                # Add jitter
                if retry_config.jitter:
                    delay *= random.uniform(0.5, 1.5)
                
                if on_retry:
                    on_retry(attempt + 1, e)
                
                await asyncio.sleep(delay)
        except asyncio.CancelledError:
            raise
        # Non-retryable exceptions (not matching retryable_exceptions) propagate immediately
    
    raise last_exception  # type: ignore


class ConnectionPoolStats:
    """Tracks connection pool statistics for monitoring.
    
    W2.6 FIX: Refactored to minimize lock contention in async callbacks.
    
    - Monotonic counters (total, ok, failed, reused, timeouts, dns_*)
      only ever increment, so under CPython's GIL they are safe without
      a lock. Each += compiles to a single LOAD_FAST + INPLACE_ADD +
      STORE_FAST, which is atomic under the GIL.
    - active_connections is a GAUGE that increments AND decrements,
      so it still needs synchronization. We use a dedicated lightweight
      threading.Lock ONLY for active_connections, not the whole object.
    - get_stats() reads all fields without a lock. Monotonic counters
      may be slightly stale (a few ms old) but never inconsistent.
      active_connections is snapshotted under its own lock.
    """

    def __init__(self):
        # W2.6 FIX: Dedicated lock ONLY for active_connections gauge
        self._active_lock = threading.Lock()
        
        # Monotonic counters — no lock needed (GIL-atomic under CPython)
        self.total_connections: int = 0
        self.active_connections: int = 0
        self.ok_connections: int = 0
        self.failed_connections: int = 0
        self.reused_connections: int = 0
        self.timeouts: int = 0
        self.dns_resolves: int = 0
        self.dns_cache_hits: int = 0

    def _inc_active(self) -> None:
        """Atomically increment active_connections gauge."""
        with self._active_lock:
            self.active_connections += 1

    def _dec_active(self) -> None:
        """Atomically decrement active_connections gauge (floor at 0)."""
        with self._active_lock:
            self.active_connections = max(0, self.active_connections - 1)

    def _get_active(self) -> int:
        """Atomically read active_connections gauge."""
        with self._active_lock:
            return self.active_connections

    def record_connection(self, success: bool) -> None:
        """Record a connection attempt.

        BUG-FIX v33: When success=True, increment ok_connections (a counter
        for completed successful connections) instead of active_connections
        (a gauge for in-flight connections). The old code caused ok_connections
        to always report 0 in get_stats(), and active_connections to grow
        without bound when both this method and the trace-config callback
        modified it.

        W2.6 FIX: No lock needed for monotonic counters (+= is GIL-atomic).
        """
        self.total_connections += 1
        if success:
            self.ok_connections += 1
        else:
            self.failed_connections += 1

    def record_timeout(self) -> None:
        """Record a connection timeout. No lock needed (monotonic counter)."""
        self.timeouts += 1

    def record_reuse(self) -> None:
        """Record a connection reuse. No lock needed (monotonic counter)."""
        self.reused_connections += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics.

        W2.6 FIX: Reads monotonic counters without lock (slightly stale
        but never inconsistent). Active gauge is snapshotted under lock.
        """
        return {
            "total": self.total_connections,
            "active": self._get_active(),
            "ok": self.ok_connections,
            "failed": self.failed_connections,
            "reused": self.reused_connections,
            "timeouts": self.timeouts,
            "dns_resolves": self.dns_resolves,
            "dns_cache_hits": self.dns_cache_hits,
            "reuse_rate": self.reused_connections / max(self.total_connections, 1),
            "failure_rate": self.failed_connections / max(self.total_connections, 1),
        }


def build_resilient_connector(
    max_connections: int = 2000,
    per_host_limit: int = 0,
    keepalive_timeout: float = 15.0,
    dns_cache_ttl: int = 120,
    enable_cleanup: bool = True,
    pool_stats: ConnectionPoolStats | None = None,
) -> Any:
    """Build an aiohttp.TCPConnector with optimized settings.

    Args:
        max_connections: Total connection limit.
        per_host_limit: Per-host connection limit (0 = unlimited).
        keepalive_timeout: Keep-alive timeout in seconds.
        dns_cache_ttl: DNS cache TTL in seconds.
        enable_cleanup: Enable cleanup of closed connections.
        pool_stats: Optional ConnectionPoolStats instance to track pool metrics.

    Returns:
        Configured aiohttp.TCPConnector instance.

    W2.7: Now delegates to utils.session_helpers.create_connector().
    """
    from utils.session_helpers import create_connector as _create_connector
    return _create_connector(
        max_connections=max_connections,
        per_host_limit=per_host_limit,
        keepalive_timeout=keepalive_timeout,
        dns_cache_ttl=dns_cache_ttl,
        enable_cleanup=enable_cleanup,
        pool_stats=pool_stats,
    )
