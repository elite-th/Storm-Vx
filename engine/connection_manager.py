"""engine.connection_manager — Connection pool management with pre-warming.

Addresses:
- DEF-09: Connection pool mismatch with worker count
- Connection pre-warming for rapid scaling
- Per-origin circuit breakers
- Adaptive timeout (EMA-based)

DESIGN PRINCIPLES:
1. Pool scales AHEAD of workers (pre-warm connections before they're needed)
2. Per-origin circuit breakers prevent cascading failures
3. Adaptive timeout uses EMA for dynamic adjustment
4. Connection stats are GIL-atomic (no asyncio.Lock)
"""
from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

from observability.resilience import CircuitBreaker, CircuitOpenError


# ═══════════════════════════════════════════════════════════════════════════════
# Adaptive Timeout — EMA-based dynamic timeout
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AdaptiveTimeout:
    """Tracks response times and adjusts timeout dynamically.

    Uses exponential moving average (EMA) to track typical response
    times and sets timeout as a multiple of the EMA.

    GIL-ATOMIC: _ema and _sample_count are simple floats/ints,
    safe for concurrent reads under CPython's GIL.
    """
    initial_timeout: float = 10.0
    ema_alpha: float = 0.1
    timeout_multiplier: float = 3.0
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


# ═══════════════════════════════════════════════════════════════════════════════
# Connection Pool Manager
# ═══════════════════════════════════════════════════════════════════════════════

class ConnectionPoolManager:
    """Manages connection pools with pre-warming and per-origin circuit breakers.

    DEF-09 FIX: Connections are pre-warmed BEFORE workers need them.
    The current system creates connections lazily, causing timeouts during
    rapid scaling (workers wait for connections, timeout timer starts ticking).

    Key improvements:
    1. Pre-warm: Establish connections before workers need them
    2. Scale pool: Update connector limit dynamically to match worker count
    3. Per-origin breakers: Isolate failing origins
    4. Adaptive timeout: EMA-based dynamic adjustment
    """

    def __init__(
        self,
        base_pool_size: int = 100,
        max_pool_size: int = 10000,
        per_host_limit: int = 0,
        keepalive_timeout: float = 15.0,
        dns_cache_ttl: int = 120,
        verify_ssl: bool = False,
        ssl_ctx: Optional[ssl.SSLContext] = None,
    ) -> None:
        self._base_size = base_pool_size
        self._max_size = max_pool_size
        self._per_host_limit = per_host_limit
        self._keepalive_timeout = keepalive_timeout
        self._dns_cache_ttl = dns_cache_ttl
        self._verify_ssl = verify_ssl
        self._ssl_ctx = ssl_ctx

        self._connector: Optional[Any] = None
        self._session: Optional[Any] = None
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._adaptive_timeout = AdaptiveTimeout()
        self._target_url: str = ""

    async def initialize(self, target_url: str) -> None:
        """Initialize the connection pool and session.

        Must be called before any requests are made.

        Args:
            target_url: Primary target URL for pre-warming.
        """
        if not HAS_AIOHTTP:
            raise RuntimeError("aiohttp is required for ConnectionPoolManager")

        self._target_url = target_url

        # Build connector with initial pool size
        self._connector = aiohttp.TCPConnector(
            limit=self._base_size,
            limit_per_host=self._per_host_limit or 0,
            keepalive_timeout=self._keepalive_timeout,
            enable_cleanup_closed=True,
            ssl=self._ssl_ctx if self._ssl_ctx else (None if self._verify_ssl else False),
        )

        # Create session with adaptive timeout
        timeout = aiohttp.ClientTimeout(total=self._adaptive_timeout.initial_timeout)
        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=timeout,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
        )

    async def prewarm(self, count: int) -> int:
        """Pre-warm connections by making lightweight HEAD requests.

        DEF-09 FIX: Ensures connections exist before workers try to use them.
        Called when scaling UP — prevents the timeout cascade where:
        1. Workers spawn → try to make requests
        2. No connections available → wait for connection
        3. Timeout timer starts → request times out before connection
        4. Scaling engine shrinks → death spiral

        Args:
            count: Number of connections to pre-warm.

        Returns:
            Number of connections successfully pre-warmed.
        """
        if not self._session or not self._target_url:
            return 0

        prewarmed = 0
        # Pre-warm in batches of 50 to avoid overwhelming the connector
        batch_size = min(count, 50)

        for _ in range(0, count, batch_size):
            tasks = []
            for _ in range(min(batch_size, count - prewarmed)):
                tasks.append(self._warmup_request())
            results = await asyncio.gather(*tasks, return_exceptions=True)
            prewarmed += sum(1 for r in results if not isinstance(r, Exception))

        return prewarmed

    async def _warmup_request(self) -> bool:
        """Make a single warmup request."""
        try:
            async with self._session.head(self._target_url, timeout=aiohttp.ClientTimeout(total=5.0)) as resp:
                return True
        except Exception:
            return False

    def scale_pool(self, target_workers: int) -> None:
        """Scale the connection pool to match target worker count.

        DEF-09 FIX: Pool must always have at least as many connections
        as there are workers. Otherwise workers queue for connections,
        and the timeout timer starts ticking while waiting.
        """
        if not self._connector:
            return

        # Ensure pool size >= worker count
        new_limit = max(target_workers, self._base_size)
        new_limit = min(new_limit, self._max_size)

        # Update connector limit dynamically
        self._connector._limit = new_limit

    def get_circuit_breaker(self, origin: str) -> CircuitBreaker:
        """Get or create a circuit breaker for a specific origin.

        Per-origin breakers prevent cascading failures: if one origin IP
        becomes unreachable, its breaker opens, but other origins continue.
        """
        if origin not in self._circuit_breakers:
            self._circuit_breakers[origin] = CircuitBreaker(
                name=f"origin_{origin}",
                failure_threshold=5,
                recovery_timeout=30.0,
            )
        return self._circuit_breakers[origin]

    def update_timeout(self, response_time: float) -> None:
        """Update the adaptive timeout based on a response time sample."""
        self._adaptive_timeout.record(response_time)
        # Update session timeout
        if self._session:
            self._session._default_timeout = aiohttp.ClientTimeout(
                total=self._adaptive_timeout.current_timeout
            )

    @property
    def session(self) -> Optional[Any]:
        """Get the current aiohttp session."""
        return self._session

    @property
    def pool_size(self) -> int:
        """Current connection pool limit."""
        if self._connector:
            return self._connector._limit
        return 0

    @property
    def stats(self) -> Dict[str, Any]:
        """Connection pool statistics."""
        result = {
            "pool_limit": self.pool_size,
            "adaptive_timeout": self._adaptive_timeout.current_timeout,
            "avg_response_time": self._adaptive_timeout.average_response_time,
            "circuit_breakers": {
                origin: breaker.stats
                for origin, breaker in self._circuit_breakers.items()
            },
        }
        if self._connector:
            result["connections"] = len(self._connector._conns) if hasattr(self._connector, '_conns') else 0
        return result

    async def close(self) -> None:
        """Close the session and connector."""
        if self._session:
            await self._session.close()
            self._session = None
        if self._connector:
            await self._connector.close()
            self._connector = None


__all__ = [
    "ConnectionPoolManager",
    "AdaptiveTimeout",
]
