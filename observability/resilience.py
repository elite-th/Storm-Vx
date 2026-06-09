"""observability.resilience — Circuit breaker, retry with backoff.

W5.4 RESILIENCE PATTERNS:

  1. CircuitBreaker — Prevent cascading failures by stopping requests
     to a failing dependency. Three states: CLOSED → OPEN → HALF_OPEN.

  2. AsyncRetry — Retry async operations with exponential backoff,
     jitter, and configurable stop conditions.

  3. Fallback — Execute a fallback function when the primary fails.

DESIGN PRINCIPLES:
  - Thread-safe via asyncio.Lock (single event loop assumption)
  - Low overhead: state checks are O(1)
  - Observable: state changes are logged with error codes
  - Composable: circuit breaker + retry + fallback can be combined
  - No external dependencies (no tenacity/backoff libraries)

CIRCUIT BREAKER STATE MACHINE:

  CLOSED (normal) → failures >= threshold → OPEN (blocking)
  OPEN (blocking) → timeout elapsed → HALF_OPEN (probing)
  HALF_OPEN (probing) → success → CLOSED
  HALF_OPEN (probing) → failure → OPEN
"""
from __future__ import annotations

import asyncio
import random
import time
from enum import Enum
from logging_config import get_logger
from typing import Any, Callable, Optional, TypeVar, Awaitable

from observability.logging_ext import (
    log_error, log_warning, log_with_context,
    ERR_CONNECTION_REFUSED, ERR_POOL_EXHAUSTED, ERR_WAF_BLOCKED,
)
from observability.metrics import metrics as _metrics

logger = get_logger(__name__)

T = TypeVar("T")


# ═══════════════════════════════════════════════════════════════════════════════
# Circuit Breaker
# ═══════════════════════════════════════════════════════════════════════════════

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"        # Normal operation — requests flow through
    OPEN = "open"            # Circuit tripped — requests are rejected
    HALF_OPEN = "half_open"  # Probing — allow one request to test recovery


class CircuitBreaker:
    """Async circuit breaker for preventing cascading failures.

    Usage:
        breaker = CircuitBreaker(name="api_endpoint", failure_threshold=5)

        async with breaker:
            result = await make_request()

    When the circuit is OPEN, attempting to enter the context manager
    raises CircuitOpenError immediately, without calling the protected
    function.

    Args:
        name: Identifier for this circuit breaker (used in logs/metrics)
        failure_threshold: Number of consecutive failures before opening
        recovery_timeout: Seconds to wait before trying half-open
        success_threshold: Consecutive successes in half-open to close (default: 2)
    """

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        success_threshold: int = 2,
    ) -> None:
        self.name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._success_threshold = success_threshold

        self._state = CircuitState.CLOSED
        self._failure_count: int = 0
        self._success_count: int = 0
        self._last_failure_time: float = 0.0
        self._last_state_change: float = time.monotonic()
        self._total_trips: int = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        """Current circuit state (may auto-transition from OPEN to HALF_OPEN)."""
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self._recovery_timeout:
                self._transition(CircuitState.HALF_OPEN)
        return self._state

    @property
    def is_open(self) -> bool:
        """Whether the circuit is currently blocking requests."""
        return self.state == CircuitState.OPEN

    @property
    def stats(self) -> dict[str, Any]:
        """Return circuit breaker statistics."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "total_trips": self._total_trips,
            "last_failure_time": self._last_failure_time,
            "recovery_timeout": self._recovery_timeout,
        }

    def _transition(self, new_state: CircuitState) -> None:
        """Transition to a new state and log the change."""
        old_state = self._state
        if old_state == new_state:
            return
        self._state = new_state
        self._last_state_change = time.monotonic()

        if new_state == CircuitState.OPEN:
            self._total_trips += 1
            log_warning(
                logger,
                f"Circuit '{self.name}' OPENED after {self._failure_count} failures",
                ERR_POOL_EXHAUSTED,
                circuit=self.name,
                old_state=old_state.value,
                total_trips=self._total_trips,
            )
            _metrics.connection_pool_failed_total.labels(
                error_type="circuit_open",
            ).inc()
        elif new_state == CircuitState.CLOSED:
            logger.info(f"Circuit '{self.name}' CLOSED — recovered")
        elif new_state == CircuitState.HALF_OPEN:
            logger.info(f"Circuit '{self.name}' HALF_OPEN — probing")

    async def __aenter__(self) -> "CircuitBreaker":
        """Enter the circuit breaker context.

        Raises:
            CircuitOpenError: If the circuit is OPEN.
        """
        async with self._lock:
            current = self.state  # May auto-transition
            if current == CircuitState.OPEN:
                raise CircuitOpenError(
                    f"Circuit '{self.name}' is OPEN — rejecting request"
                )
        return self

    async def __aexit__(self, exc_type: type | None, exc_val: BaseException | None,
                        exc_tb: Any) -> bool:
        """Exit the circuit breaker context, recording success or failure."""
        if exc_type is None:
            await self._record_success()
        else:
            await self._record_failure()
        # Don't suppress the exception
        return False

    async def _record_success(self) -> None:
        """Record a successful operation."""
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self._success_threshold:
                    self._success_count = 0
                    self._failure_count = 0
                    self._transition(CircuitState.CLOSED)
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0
                self._success_count += 1

    async def _record_failure(self) -> None:
        """Record a failed operation."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                # Failed during probing — go back to OPEN
                self._success_count = 0
                self._transition(CircuitState.OPEN)
            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self._failure_threshold:
                    self._success_count = 0
                    self._transition(CircuitState.OPEN)

    async def call(self, func: Callable[..., Awaitable[T]], *args: Any,
                   **kwargs: Any) -> T:
        """Call an async function through the circuit breaker.

        Alternative to using the context manager:

            result = await breaker.call(make_request, url)

        Args:
            func: Async function to call.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            The function's return value.

        Raises:
            CircuitOpenError: If the circuit is OPEN.
        """
        async with self:
            return await func(*args, **kwargs)


class CircuitOpenError(Exception):
    """Raised when a circuit breaker is OPEN and rejects a request."""
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# Async Retry with Backoff
# ═══════════════════════════════════════════════════════════════════════════════

class AsyncRetry:
    """Configurable async retry with exponential backoff and jitter.

    Usage:
        retry = AsyncRetry(max_attempts=3, base_delay=0.5, max_delay=10.0)

        result = await retry.run(make_request, url)

    Args:
        max_attempts: Maximum number of attempts (including the first)
        base_delay: Base delay in seconds for exponential backoff
        max_delay: Maximum delay cap in seconds
        exponential_base: Base for exponential calculation (default: 2.0)
        jitter: Whether to add random jitter (default: True)
        jitter_factor: Jitter range factor (default: 0.25, ±25%)
        retryable_exceptions: Tuple of exception types to retry on
            (default: retry on all exceptions)
    """

    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 0.5,
        max_delay: float = 10.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
        jitter_factor: float = 0.25,
        retryable_exceptions: tuple[type[Exception], ...] = (Exception,),
    ) -> None:
        self._max_attempts = max_attempts
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._exponential_base = exponential_base
        self._jitter = jitter
        self._jitter_factor = jitter_factor
        self._retryable = retryable_exceptions

        # Stats
        self._total_attempts: int = 0
        self._total_retries: int = 0
        self._total_failures: int = 0

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "total_attempts": self._total_attempts,
            "total_retries": self._total_retries,
            "total_failures": self._total_failures,
        }

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate the delay for a given attempt number (0-indexed)."""
        delay = self._base_delay * (self._exponential_base ** attempt)
        delay = min(delay, self._max_delay)
        if self._jitter:
            jitter_range = delay * self._jitter_factor
            delay += random.uniform(-jitter_range, jitter_range)
        return max(0.0, delay)

    async def run(
        self,
        func: Callable[..., Awaitable[T]],
        *args: Any,
        on_retry: Optional[Callable[[int, Exception, float], Awaitable[None]]] = None,
        **kwargs: Any,
    ) -> T:
        """Execute an async function with retry logic.

        Args:
            func: Async function to execute.
            *args: Positional arguments for the function.
            on_retry: Optional async callback called before each retry:
                on_retry(attempt_number, exception, delay_seconds)
            **kwargs: Keyword arguments for the function.

        Returns:
            The function's return value on success.

        Raises:
            The last exception if all attempts fail.
        """
        last_exception: Optional[Exception] = None

        for attempt in range(self._max_attempts):
            self._total_attempts += 1
            try:
                return await func(*args, **kwargs)
            except self._retryable as exc:
                last_exception = exc

                if attempt < self._max_attempts - 1:
                    # More attempts available
                    delay = self._calculate_delay(attempt)
                    self._total_retries += 1

                    logger.debug(
                        f"Retry {attempt + 1}/{self._max_attempts} for "
                        f"{func.__name__ if hasattr(func, '__name__') else 'func'}: "
                        f"{exc} — waiting {delay:.3f}s"
                    )

                    if on_retry:
                        try:
                            await on_retry(attempt, exc, delay)
                        except Exception:
                            pass  # Don't let callback errors break retry logic

                    await asyncio.sleep(delay)
                else:
                    self._total_failures += 1

        # All attempts exhausted
        if last_exception is not None:
            raise last_exception
        raise RuntimeError("Retry loop ended without exception")  # Should never happen


# ═══════════════════════════════════════════════════════════════════════════════
# Fallback Pattern
# ═══════════════════════════════════════════════════════════════════════════════

async def with_fallback(
    primary: Callable[..., Awaitable[T]],
    fallback: Callable[..., Awaitable[T]],
    *args: Any,
    **kwargs: Any,
) -> T:
    """Execute primary function, falling back to fallback on failure.

    Args:
        primary: Primary async function to try first.
        fallback: Fallback async function if primary fails.
        *args: Arguments passed to both functions.
        **kwargs: Keyword arguments passed to both functions.

    Returns:
        Result from primary on success, or fallback on primary failure.
    """
    try:
        return await primary(*args, **kwargs)
    except Exception as exc:
        logger.debug(f"Primary failed, using fallback: {exc}")
        return await fallback(*args, **kwargs)


async def with_circuit_breaker_and_retry(
    breaker: CircuitBreaker,
    retry: AsyncRetry,
    func: Callable[..., Awaitable[T]],
    *args: Any,
    fallback: Optional[Callable[..., Awaitable[T]]] = None,
    **kwargs: Any,
) -> T:
    """Combine circuit breaker + retry + optional fallback.

    This is the full resilience stack:
    1. Circuit breaker checks if the dependency is healthy
    2. Retry handles transient failures with backoff
    3. Fallback provides a graceful degradation path

    Args:
        breaker: CircuitBreaker instance.
        retry: AsyncRetry instance.
        func: Async function to execute.
        *args: Positional arguments for the function.
        fallback: Optional fallback function if all else fails.
        **kwargs: Keyword arguments for the function.

    Returns:
        The function's return value.

    Raises:
        CircuitOpenError: If the circuit is OPEN and no fallback.
        The last exception: If all retries fail and no fallback.
    """
    try:
        async with breaker:
            return await retry.run(func, *args, **kwargs)
    except CircuitOpenError:
        if fallback:
            logger.debug(f"Circuit '{breaker.name}' open, using fallback")
            return await fallback(*args, **kwargs)
        raise
    except Exception:
        if fallback:
            logger.debug(f"All retries exhausted, using fallback")
            return await fallback(*args, **kwargs)
        raise


__all__ = [
    "CircuitState",
    "CircuitBreaker",
    "CircuitOpenError",
    "AsyncRetry",
    "with_fallback",
    "with_circuit_breaker_and_retry",
]
