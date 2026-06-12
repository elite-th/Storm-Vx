#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vf_data — Data classes for attack statistics and hit results.

Provides the HitResult dataclass and Stats tracker used by the VF_TESTER
adaptive attack engine.

v17: Added timeout_errors counter for code=0 connection/socket errors.
"""
from __future__ import annotations

import time
import threading
from collections import deque
from dataclasses import dataclass
from typing import Dict

from config.defaults import STATS_EMA_ALPHA, STATS_RPS_WINDOW_SIZE, STATS_RPS_WINDOW_SECONDS


@dataclass
class HitResult:
    """Result of a single HTTP hit."""
    ok: bool = False
    code: int = 0
    rt: float = 0.0
    mode: str = ""
    err: str = ""
    url: str = ""
    hint: str = ""


class Stats:
    """Tracks aggregate statistics for the attack.

    v17: Now tracks timeout_errors separately from server/client errors.
    code=0 with an error message (ConnectionTimeoutError, SocketTimeoutError,
    etc.) is classified as a timeout error — this is critical for health
    monitoring because timeouts mean the server is unresponsive.

    Thread-safe: record() uses threading.Lock for dict updates, making it
    safe for concurrent calls from multiple threads (e.g. high worker counts).
    
    ARCH-6 note: threading.Lock is intentionally used instead of asyncio.Lock
    because Stats.record() is called from BOTH sync and async contexts.
    asyncio.Lock would break synchronous callers (e.g. dashboard reads).
    threading.Lock works in both contexts since the critical section is very
    short (integer increments + dict updates), so it never blocks the event
    loop for a noticeable duration.
    """

    # EMA smoothing factor — higher = more responsive to recent samples
    _EMA_ALPHA: float = STATS_EMA_ALPHA  # W2.4

    def __init__(self):
        self.t0: float = 0.0
        self.total: int = 0
        self.ok: int = 0
        self.fail: int = 0
        self.rate_limited: int = 0
        self.users: int = 0
        self.duration: float = 0.0  # Elapsed duration in seconds
        self.requests_per_second: float = 0.0  # Requests per second (overall average)
        self.rps_rolling: float = 0.0  # v26: Rolling window RPS (last 3s)
        # W3.3 FIX: Replaced list with deque(maxlen=10000) to eliminate GC pressure.
        # Old code: list comprehension prune created a NEW list every 500 records
        # → at 10k+ RPS, massive GC pressure from discarded list objects.
        # New code: deque with popleft() loop — no new list allocation, O(k) prune
        # where k = expired entries (typically small).
        self._rps_window: deque = deque(maxlen=STATS_RPS_WINDOW_SIZE)  # W2.4: Bounded; ~30s at 300 RPS
        self._rps_window_last_prune: float = 0.0  # v31: throttle pruning for O(1) amortized cost
        self._RPS_WINDOW_SECONDS: float = STATS_RPS_WINDOW_SECONDS  # W2.4: Rolling window duration
        self.avg_response_time: float = 0.0  # Average response time (EMA)
        self.mode_hits: Dict[str, int] = {}
        self.codes: Dict[int, int] = {}
        self.error_types: Dict[str, int] = {}
        self.server_errors: int = 0
        self.client_errors: int = 0
        self.timeout_errors: int = 0  # v17: track timeout/connection errors (code=0)
        self.ssl_errors: int = 0  # Phase 0: track SSL cert verification errors
        # _response_times deque removed (M4): replaced by rolling EMA in _rart_ema
        self._rart_ema: float = 0.0  # Rolling EMA for average response time
        self._rart_samples: int = 0   # Number of samples fed into EMA
        self._first_request_time: float = 0.0  # v29: Time of first recorded request (for accurate RPS)
        self._lock = threading.Lock()

    def record(self, hit: HitResult):
        """Record a hit result.

        v17: code=0 with an error message is now classified as timeout_errors.
        This is crucial because ConnectionTimeoutError, SocketTimeoutError,
        ServerDisconnectedError, etc. all have code=0 but indicate the server
        cannot handle the load.

        Thread-safe: ALL mutable state updates are protected by threading.Lock.
        BUG-FIX: Integer increments (+=) are NOT atomic under high concurrency —
        they are read-modify-write operations that can lose updates when
        multiple threads/coroutines call record() simultaneously.
        Moving ALL updates inside the lock ensures consistency.
        """
        with self._lock:
            # Integer updates — must be inside lock (+= is read-modify-write, not atomic)
            self.total += 1
            if hit.ok:
                self.ok += 1
            else:
                self.fail += 1

            if hit.code in (429, 503):
                self.rate_limited += 1

            # v17: Classify errors properly
            if hit.code >= 500:
                self.server_errors += 1
            elif hit.code >= 400:
                self.client_errors += 1
            elif hit.code == 0 and hit.err:
                self.timeout_errors += 1
                # Phase 0: Track SSL errors separately for adjusted health scoring
                if 'SSL' in hit.err or 'ssl' in hit.err.lower():
                    self.ssl_errors += 1

            # Dict updates
            self.codes[hit.code] = self.codes.get(hit.code, 0) + 1
            if hit.mode:
                self.mode_hits[hit.mode] = self.mode_hits.get(hit.mode, 0) + 1
            if hit.err:
                self.error_types[hit.err] = self.error_types.get(hit.err, 0) + 1

            # EMA update (must be inside lock to prevent lost samples)
            if hit.rt > 0:
                self._rart_samples += 1
                if self._rart_samples == 1:
                    self._rart_ema = hit.rt
                else:
                    self._rart_ema = (self._EMA_ALPHA * hit.rt
                                      + (1 - self._EMA_ALPHA) * self._rart_ema)
                self.avg_response_time = self._rart_ema

            # Update running averages
            # v29: Track time of first request to exclude startup dead time
            # from RPS calculation. Without this, the 100+ seconds of FINDER
            # phase with 0 requests drags down the average RPS significantly.
            now = time.monotonic()
            if self.total == 1:
                self._first_request_time = now
            elapsed = now - self.t0 if self.t0 else 1
            self.duration = elapsed
            # v29: Use effective elapsed time (from first request) for RPS
            # to avoid counting startup dead time
            effective_elapsed = now - self._first_request_time if self._first_request_time else elapsed
            self.requests_per_second = self.total / max(effective_elapsed, 0.001)

            # W3.3 FIX: Rolling window RPS with zero-allocation pruning.
            #
            # Old approach (v31): list comprehension prune created a NEW list
            # every 500 records → at 10k+ RPS, massive GC pressure from
            # discarded list objects + O(n) lock hold time during prune.
            #
            # New approach: deque with popleft() loop.
            # - Append: O(1), no allocation (deque uses a circular buffer)
            # - Prune: popleft() loop removes expired entries from the left.
            #   No new container is created; O(k) where k = expired entries.
            # - Bounded: deque(maxlen=10000) prevents unbounded growth even
            #   if pruning is delayed.
            # - Lock hold time: proportional to k (expired entries), not n (total)
            self._rps_window.append((now, 1))
            cutoff = now - self._RPS_WINDOW_SECONDS
            # Prune expired entries from the left (zero-allocation)
            while self._rps_window and self._rps_window[0][0] < cutoff:
                self._rps_window.popleft()
            if len(self._rps_window) >= 2:
                window_duration = now - self._rps_window[0][0]
                window_count = len(self._rps_window)
                self.rps_rolling = window_count / max(window_duration, 0.001)

    def get_snapshot(self) -> Dict[str, int | float]:
        """Return an atomic snapshot of key rate-calculation fields.

        v31 FIX: The adaptive scaling engine reads stats.fail and
        stats.timeout_errors separately to compute non_timeout_fail_rate.
        Without a snapshot, these two reads can be inconsistent (fail
        updated between reads), causing non_timeout_fail_rate to go
        negative. The max(..., 0) clamp in the scaling engine catches
        this, but an atomic snapshot is more correct and avoids the
        edge case entirely.

        Returns:
            Dict with total, ok, fail, timeout_errors, server_errors,
            client_errors, rate_limited, avg_response_time.
        """
        with self._lock:
            return {
                "total": self.total,
                "ok": self.ok,
                "fail": self.fail,
                "timeout_errors": self.timeout_errors,
                "server_errors": self.server_errors,
                "client_errors": self.client_errors,
                "rate_limited": self.rate_limited,
                "avg_response_time": self.avg_response_time,
                "ssl_errors": self.ssl_errors,
            }


__all__ = ['HitResult', 'Stats']
