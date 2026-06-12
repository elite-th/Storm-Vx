"""Tests for Task 5.4: Circuit Breaker & Retry with Backoff.

Validates:
  - CircuitBreaker state transitions (CLOSED → OPEN → HALF_OPEN → CLOSED)
  - CircuitBreaker failure tracking and threshold
  - CircuitBreaker context manager usage
  - CircuitBreaker.call() method
  - CircuitOpenError raised when circuit is open
  - AsyncRetry exponential backoff
  - AsyncRetry max attempts
  - AsyncRetry retryable exceptions filtering
  - AsyncRetry on_retry callback
  - with_fallback pattern
  - with_circuit_breaker_and_retry full stack
  - Stats tracking
"""
from __future__ import annotations

import asyncio
import pytest
import time


# ═══════════════════════════════════════════════════════════════════════════════
# Circuit Breaker Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestCircuitBreakerStates:
    """Test circuit breaker state machine."""

    def test_initial_state_is_closed(self):
        from observability.resilience import CircuitBreaker, CircuitState
        cb = CircuitBreaker(name="test")
        assert cb.state == CircuitState.CLOSED

    def test_is_open_false_initially(self):
        from observability.resilience import CircuitBreaker
        cb = CircuitBreaker(name="test")
        assert not cb.is_open

    def test_state_transitions_to_open(self):
        from observability.resilience import CircuitBreaker, CircuitState
        cb = CircuitBreaker(name="test", failure_threshold=3)
        # Manually transition by recording failures
        for _ in range(3):
            asyncio.get_event_loop().run_until_complete(cb._record_failure())
        assert cb.state == CircuitState.OPEN
        assert cb.is_open

    def test_state_auto_transitions_to_half_open(self):
        from observability.resilience import CircuitBreaker, CircuitState
        cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0.01)
        # Trip the circuit
        for _ in range(2):
            asyncio.get_event_loop().run_until_complete(cb._record_failure())
        assert cb.state == CircuitState.OPEN
        # Wait for recovery timeout
        time.sleep(0.02)
        # Accessing .state should auto-transition
        assert cb.state == CircuitState.HALF_OPEN


class TestCircuitBreakerContextManager:
    """Test circuit breaker as async context manager."""

    @pytest.mark.asyncio
    async def test_context_manager_success(self):
        from observability.resilience import CircuitBreaker, CircuitState
        cb = CircuitBreaker(name="test", failure_threshold=3)
        async with cb:
            pass  # Success
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_context_manager_failure(self):
        from observability.resilience import CircuitBreaker, CircuitState
        cb = CircuitBreaker(name="test", failure_threshold=2)
        try:
            async with cb:
                raise ValueError("test error")
        except ValueError:
            pass
        assert cb._failure_count == 1
        assert cb.state == CircuitState.CLOSED  # Not enough failures yet

    @pytest.mark.asyncio
    async def test_context_manager_trips_on_threshold(self):
        from observability.resilience import CircuitBreaker, CircuitState
        cb = CircuitBreaker(name="test", failure_threshold=2)
        for _ in range(2):
            try:
                async with cb:
                    raise ValueError("fail")
            except ValueError:
                pass
        assert cb.state == CircuitState.OPEN

    @pytest.mark.asyncio
    async def test_context_manager_rejects_when_open(self):
        from observability.resilience import CircuitBreaker, CircuitOpenError
        cb = CircuitBreaker(name="test", failure_threshold=1)
        # Trip it
        try:
            async with cb:
                raise ValueError("fail")
        except ValueError:
            pass
        # Should reject now
        with pytest.raises(CircuitOpenError):
            async with cb:
                pass

    @pytest.mark.asyncio
    async def test_context_manager_half_open_to_closed(self):
        from observability.resilience import CircuitBreaker, CircuitState
        cb = CircuitBreaker(
            name="test", failure_threshold=1,
            recovery_timeout=0.01, success_threshold=1,
        )
        # Trip it
        try:
            async with cb:
                raise ValueError("fail")
        except ValueError:
            pass
        assert cb.state == CircuitState.OPEN
        # Wait for recovery
        await asyncio.sleep(0.02)
        # One success in HALF_OPEN should close it (success_threshold=1)
        async with cb:
            pass
        assert cb.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_context_manager_half_open_failure_reopens(self):
        from observability.resilience import CircuitBreaker, CircuitState
        cb = CircuitBreaker(
            name="test", failure_threshold=1,
            recovery_timeout=0.01,
        )
        # Trip it
        try:
            async with cb:
                raise ValueError("fail")
        except ValueError:
            pass
        # Wait for recovery
        await asyncio.sleep(0.02)
        # Failure in HALF_OPEN should re-open
        try:
            async with cb:
                raise ValueError("still failing")
        except ValueError:
            pass
        assert cb.state == CircuitState.OPEN


class TestCircuitBreakerCall:
    """Test circuit breaker .call() method."""

    @pytest.mark.asyncio
    async def test_call_success(self):
        from observability.resilience import CircuitBreaker
        cb = CircuitBreaker(name="test")

        async def my_func():
            return 42

        result = await cb.call(my_func)
        assert result == 42

    @pytest.mark.asyncio
    async def test_call_with_args(self):
        from observability.resilience import CircuitBreaker
        cb = CircuitBreaker(name="test")

        async def add(a, b):
            return a + b

        result = await cb.call(add, 3, 4)
        assert result == 7

    @pytest.mark.asyncio
    async def test_call_rejects_when_open(self):
        from observability.resilience import CircuitBreaker, CircuitOpenError
        cb = CircuitBreaker(name="test", failure_threshold=1)
        # Trip it
        try:
            async with cb:
                raise ValueError("fail")
        except ValueError:
            pass
        # Should reject
        with pytest.raises(CircuitOpenError):
            await cb.call(lambda: None)


class TestCircuitBreakerStats:
    """Test circuit breaker statistics."""

    @pytest.mark.asyncio
    async def test_stats_include_name(self):
        from observability.resilience import CircuitBreaker
        cb = CircuitBreaker(name="test_stats")
        assert cb.stats["name"] == "test_stats"

    @pytest.mark.asyncio
    async def test_stats_track_trips(self):
        from observability.resilience import CircuitBreaker
        cb = CircuitBreaker(name="test", failure_threshold=1)
        try:
            async with cb:
                raise ValueError("fail")
        except ValueError:
            pass
        assert cb.stats["total_trips"] == 1

    @pytest.mark.asyncio
    async def test_stats_track_failure_count(self):
        from observability.resilience import CircuitBreaker
        cb = CircuitBreaker(name="test", failure_threshold=5)
        try:
            async with cb:
                raise ValueError("fail")
        except ValueError:
            pass
        assert cb.stats["failure_count"] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Async Retry Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestAsyncRetry:
    """Test async retry with backoff."""

    @pytest.mark.asyncio
    async def test_success_no_retry(self):
        from observability.resilience import AsyncRetry
        retry = AsyncRetry(max_attempts=3, base_delay=0.01)

        call_count = 0
        async def success_func():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = await retry.run(success_func)
        assert result == "ok"
        assert call_count == 1
        assert retry.stats["total_retries"] == 0

    @pytest.mark.asyncio
    async def test_retry_on_failure_then_success(self):
        from observability.resilience import AsyncRetry
        retry = AsyncRetry(max_attempts=3, base_delay=0.01)

        call_count = 0
        async def fail_then_succeed():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("fail")
            return "ok"

        result = await retry.run(fail_then_succeed)
        assert result == "ok"
        assert call_count == 2
        assert retry.stats["total_retries"] == 1

    @pytest.mark.asyncio
    async def test_retry_exhausted(self):
        from observability.resilience import AsyncRetry
        retry = AsyncRetry(max_attempts=2, base_delay=0.01)

        async def always_fail():
            raise ConnectionError("always fails")

        with pytest.raises(ConnectionError, match="always fails"):
            await retry.run(always_fail)
        assert retry.stats["total_failures"] == 1
        assert retry.stats["total_retries"] == 1

    @pytest.mark.asyncio
    async def test_retryable_exception_filtering(self):
        from observability.resilience import AsyncRetry
        # Only retry on ConnectionError, not ValueError
        retry = AsyncRetry(
            max_attempts=3, base_delay=0.01,
            retryable_exceptions=(ConnectionError,),
        )

        async def raise_value_error():
            raise ValueError("not retryable")

        # Should fail immediately without retrying
        with pytest.raises(ValueError, match="not retryable"):
            await retry.run(raise_value_error)
        assert retry.stats["total_retries"] == 0

    @pytest.mark.asyncio
    async def test_on_retry_callback(self):
        from observability.resilience import AsyncRetry
        retry = AsyncRetry(max_attempts=3, base_delay=0.01)

        callback_calls: list[tuple] = []

        async def on_retry(attempt, exc, delay):
            callback_calls.append((attempt, str(exc), delay))

        call_count = 0
        async def fail_twice():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError(f"fail {call_count}")
            return "ok"

        result = await retry.run(fail_twice, on_retry=on_retry)
        assert result == "ok"
        assert len(callback_calls) == 2

    @pytest.mark.asyncio
    async def test_delay_calculation(self):
        from observability.resilience import AsyncRetry
        retry = AsyncRetry(
            max_attempts=5, base_delay=0.1,
            max_delay=1.0, exponential_base=2.0,
            jitter=False,
        )
        # attempt 0: 0.1 * 2^0 = 0.1
        assert retry._calculate_delay(0) == 0.1
        # attempt 1: 0.1 * 2^1 = 0.2
        assert retry._calculate_delay(1) == 0.2
        # attempt 2: 0.1 * 2^2 = 0.4
        assert retry._calculate_delay(2) == 0.4
        # attempt 10: 0.1 * 2^10 = 102.4 → capped at 1.0
        assert retry._calculate_delay(10) == 1.0

    @pytest.mark.asyncio
    async def test_stats_tracking(self):
        from observability.resilience import AsyncRetry
        retry = AsyncRetry(max_attempts=2, base_delay=0.01)

        async def always_fail():
            raise ConnectionError("fail")

        with pytest.raises(ConnectionError):
            await retry.run(always_fail)

        assert retry.stats["total_attempts"] == 2
        assert retry.stats["total_retries"] == 1
        assert retry.stats["total_failures"] == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Fallback Pattern Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestFallback:
    """Test with_fallback pattern."""

    @pytest.mark.asyncio
    async def test_primary_succeeds(self):
        from observability.resilience import with_fallback

        async def primary():
            return "primary_result"

        async def fallback():
            return "fallback_result"

        result = await with_fallback(primary, fallback)
        assert result == "primary_result"

    @pytest.mark.asyncio
    async def test_fallback_on_primary_failure(self):
        from observability.resilience import with_fallback

        async def primary():
            raise ConnectionError("primary down")

        async def fallback():
            return "fallback_result"

        result = await with_fallback(primary, fallback)
        assert result == "fallback_result"

    @pytest.mark.asyncio
    async def test_fallback_with_args(self):
        from observability.resilience import with_fallback

        async def primary(x, y):
            raise ConnectionError("down")

        async def fallback(x, y):
            return x + y

        result = await with_fallback(primary, fallback, 3, 4)
        assert result == 7


# ═══════════════════════════════════════════════════════════════════════════════
# Full Stack Tests (Circuit Breaker + Retry + Fallback)
# ═══════════════════════════════════════════════════════════════════════════════

class TestFullStack:
    """Test with_circuit_breaker_and_retry."""

    @pytest.mark.asyncio
    async def test_success_path(self):
        from observability.resilience import (
            CircuitBreaker, AsyncRetry, with_circuit_breaker_and_retry,
        )
        cb = CircuitBreaker(name="test", failure_threshold=3)
        retry = AsyncRetry(max_attempts=2, base_delay=0.01)

        async def my_func():
            return "success"

        result = await with_circuit_breaker_and_retry(cb, retry, my_func)
        assert result == "success"

    @pytest.mark.asyncio
    async def test_circuit_open_uses_fallback(self):
        from observability.resilience import (
            CircuitBreaker, AsyncRetry, CircuitOpenError,
            with_circuit_breaker_and_retry,
        )
        cb = CircuitBreaker(name="test", failure_threshold=1)
        retry = AsyncRetry(max_attempts=1, base_delay=0.01)

        # Trip the circuit
        try:
            async with cb:
                raise ValueError("fail")
        except ValueError:
            pass

        async def my_func():
            return "should not reach"

        async def fallback_func():
            return "fallback"

        result = await with_circuit_breaker_and_retry(
            cb, retry, my_func, fallback=fallback_func,
        )
        assert result == "fallback"

    @pytest.mark.asyncio
    async def test_all_retries_fail_uses_fallback(self):
        from observability.resilience import (
            CircuitBreaker, AsyncRetry, with_circuit_breaker_and_retry,
        )
        cb = CircuitBreaker(name="test", failure_threshold=10)
        retry = AsyncRetry(max_attempts=2, base_delay=0.01)

        async def my_func():
            raise ConnectionError("always fails")

        async def fallback_func():
            return "fallback"

        result = await with_circuit_breaker_and_retry(
            cb, retry, my_func, fallback=fallback_func,
        )
        assert result == "fallback"

    @pytest.mark.asyncio
    async def test_circuit_open_no_fallback_raises(self):
        from observability.resilience import (
            CircuitBreaker, AsyncRetry, CircuitOpenError,
            with_circuit_breaker_and_retry,
        )
        cb = CircuitBreaker(name="test", failure_threshold=1)
        retry = AsyncRetry(max_attempts=1, base_delay=0.01)

        # Trip the circuit
        try:
            async with cb:
                raise ValueError("fail")
        except ValueError:
            pass

        async def my_func():
            return "should not reach"

        with pytest.raises(CircuitOpenError):
            await with_circuit_breaker_and_retry(cb, retry, my_func)
