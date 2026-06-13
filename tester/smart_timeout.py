#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smart_timeout — RTT-adaptive dynamic timeout calculator.  (v1, Phase 2)

Uses exponential moving average (EMA) of observed RTTs to compute optimal
connect and read timeouts.  Replaces static timeout values with ones that
adapt to actual network conditions.

Design decisions:
  - EMA alpha=0.3: balances responsiveness vs noise (industry standard)
  - Per-host tracking: different targets may have different RTTs
  - All thresholds from config.defaults (Law 15: no magic numbers)
  - Default RTT estimate: 500ms (reasonable for initial requests)
  - Law 5: all inputs validated; Law 6: boundary cases handled

@version 1.0.0
@since Phase 2
"""

from __future__ import annotations

import math
import threading
from typing import Dict, Optional
from urllib.parse import urlparse

from config.defaults import (
    SMART_TIMEOUT_ENABLED,
    SMART_TIMEOUT_RTT_MULTIPLIER_CONNECT,
    SMART_TIMEOUT_RTT_MULTIPLIER_READ,
    SMART_TIMEOUT_MIN_CONNECT,
    SMART_TIMEOUT_MIN_READ,
    SMART_TIMEOUT_MAX_CONNECT,
    SMART_TIMEOUT_MAX_READ,
)

from logging_config import get_logger

logger = get_logger(__name__)

__all__ = ["SmartTimeoutEngine"]

# ─── Constants ────────────────────────────────────────────────────────────────

_EMA_ALPHA: float = 0.3          # Smoothing factor for EMA
_DEFAULT_RTT_MS: float = 500.0   # Initial RTT estimate (ms) when no data yet
_MIN_RTT_MS: float = 1.0         # Floor for RTT measurements (1ms)


class _HostRTT:
    """Per-host RTT tracking state.  Internal use only.

    Attributes:
        ema: Current exponential moving average of RTT in ms.
        samples: Number of RTT samples recorded for this host.
    """

    __slots__ = ("ema", "samples")

    def __init__(self, initial_ema: float = _DEFAULT_RTT_MS) -> None:
        self.ema: float = initial_ema
        self.samples: int = 0


class SmartTimeoutEngine:
    """RTT-adaptive dynamic timeout calculator.

    Uses exponential moving average (EMA) of observed RTTs to compute
    optimal connect and read timeouts.  Replaces static timeout values
    with ones that adapt to actual network conditions.

    Thread-safe: all mutations are protected by a threading.Lock so
    the engine can be shared across asyncio tasks and threads.

    Usage::

        engine = SmartTimeoutEngine()
        engine.update_rtt("example.com", 120.5)
        params = engine.get_timeout_params("example.com")
        # => {"connect": 0.36, "sock_read": 0.60}

    @version 1.0.0
    @since Phase 2
    """

    def __init__(
        self,
        enabled: bool = SMART_TIMEOUT_ENABLED,
        rtt_multiplier_connect: float = SMART_TIMEOUT_RTT_MULTIPLIER_CONNECT,
        rtt_multiplier_read: float = SMART_TIMEOUT_RTT_MULTIPLIER_READ,
        min_connect: float = SMART_TIMEOUT_MIN_CONNECT,
        min_read: float = SMART_TIMEOUT_MIN_READ,
        max_connect: float = SMART_TIMEOUT_MAX_CONNECT,
        max_read: float = SMART_TIMEOUT_MAX_READ,
        default_rtt_ms: float = _DEFAULT_RTT_MS,
        ema_alpha: float = _EMA_ALPHA,
    ) -> None:
        """Initialize the smart timeout engine.

        All parameters default to config.defaults values (Law 9, Law 15).

        Args:
            enabled: Whether smart timeout is active.
            rtt_multiplier_connect: Multiplier for connect timeout.
            rtt_multiplier_read: Multiplier for read timeout.
            min_connect: Minimum connect timeout in seconds.
            min_read: Minimum read timeout in seconds.
            max_connect: Maximum connect timeout in seconds.
            max_read: Maximum read timeout in seconds.
            default_rtt_ms: Default RTT estimate in ms (before any data).
            ema_alpha: EMA smoothing factor (0 < alpha <= 1).
        """
        # Law 5: Validate constructor arguments
        if ema_alpha <= 0 or ema_alpha > 1:
            raise ValueError(f"ema_alpha must be in (0, 1], got {ema_alpha}")
        if default_rtt_ms <= 0:
            raise ValueError(f"default_rtt_ms must be > 0, got {default_rtt_ms}")
        if min_connect <= 0 or min_read <= 0:
            raise ValueError("min_connect and min_read must be > 0")
        if max_connect < min_connect:
            raise ValueError(
                f"max_connect ({max_connect}) must be >= min_connect ({min_connect})"
            )
        if max_read < min_read:
            raise ValueError(
                f"max_read ({max_read}) must be >= min_read ({min_read})"
            )

        self._enabled: bool = enabled
        self._rtt_multiplier_connect: float = rtt_multiplier_connect
        self._rtt_multiplier_read: float = rtt_multiplier_read
        self._min_connect: float = min_connect
        self._min_read: float = min_read
        self._max_connect: float = max_connect
        self._max_read: float = max_read
        self._default_rtt_ms: float = default_rtt_ms
        self._ema_alpha: float = ema_alpha

        # Per-host RTT tracking
        self._hosts: Dict[str, _HostRTT] = {}
        self._lock: threading.Lock = threading.Lock()

    # ─── Public API ──────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        """Whether smart timeout calculations are active."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Enable or disable smart timeout at runtime."""
        self._enabled = value

    def update_rtt(self, host: str, rtt_ms: float) -> None:
        """Record an observed RTT and update the EMA for this host.

        Uses EMA formula:  rtt_ema = alpha * rtt + (1 - alpha) * rtt_ema
        With alpha=0.3, new samples have 30% weight — responsive but
        not overly sensitive to outliers.

        Law 5: Invalid inputs are silently skipped (no exception raised
        to avoid disrupting the attack flow).

        Args:
            host: The target hostname.  Must be a non-empty string.
            rtt_ms: Observed round-trip time in milliseconds.  Must be > 0.
        """
        # Law 5: Validate inputs
        if not isinstance(host, str) or not host.strip():
            return
        if not isinstance(rtt_ms, (int, float)) or rtt_ms <= 0 or math.isnan(rtt_ms):
            return

        # Floor extremely low RTTs (sub-millisecond noise)
        rtt_ms = max(rtt_ms, _MIN_RTT_MS)

        with self._lock:
            entry = self._hosts.get(host)
            if entry is None:
                # First sample for this host — initialize EMA to the sample
                # (not default) so the first timeout is based on real data.
                self._hosts[host] = _HostRTT(initial_ema=rtt_ms)
                entry = self._hosts[host]
            else:
                # EMA update
                entry.ema = self._ema_alpha * rtt_ms + (1 - self._ema_alpha) * entry.ema
            entry.samples += 1

    def get_connect_timeout(self, host: str) -> float:
        """Compute adaptive connect timeout for a host.

        Formula: max(MIN, min(MAX, RTT_ema * CONNECT_MULTIPLIER))

        The connect timeout is typically shorter than the read timeout
        because a TCP handshake is a single round trip.

        Args:
            host: The target hostname.

        Returns:
            Connect timeout in seconds.
        """
        if not self._enabled:
            return self._min_connect

        rtt_ema_s = self._get_rtt_ema_seconds(host)
        computed = rtt_ema_s * self._rtt_multiplier_connect
        return max(self._min_connect, min(self._max_connect, computed))

    def get_read_timeout(self, host: str) -> float:
        """Compute adaptive read timeout for a host.

        Formula: max(MIN, min(MAX, RTT_ema * READ_MULTIPLIER))

        The read timeout is typically larger than connect because
        the server needs time to generate a response.

        Args:
            host: The target hostname.

        Returns:
            Read timeout in seconds.
        """
        if not self._enabled:
            return self._min_read

        rtt_ema_s = self._get_rtt_ema_seconds(host)
        computed = rtt_ema_s * self._rtt_multiplier_read
        return max(self._min_read, min(self._max_read, computed))

    def get_timeout_params(self, host: str) -> Dict[str, float]:
        """Return aiohttp-compatible timeout parameters for a host.

        Returns:
            Dict with ``connect`` and ``sock_read`` keys, both in seconds.
            Suitable for passing to ``aiohttp.ClientTimeout()``.

        Example::

            params = engine.get_timeout_params("example.com")
            timeout = aiohttp.ClientTimeout(
                connect=params["connect"],
                sock_read=params["sock_read"],
            )
        """
        return {
            "connect": self.get_connect_timeout(host),
            "sock_read": self.get_read_timeout(host),
        }

    def get_stats(self) -> Dict[str, object]:
        """Return current engine stats for dashboard display.

        Returns:
            Dict with keys:
              - hosts_tracked (int): Number of hosts with RTT data.
              - avg_rtt_ms (float): Average RTT across all hosts (0 if none).
              - min_rtt_ms (float): Minimum host RTT (0 if none).
              - max_rtt_ms (float): Maximum host RTT (0 if none).
              - enabled (bool): Whether smart timeout is active.
              - total_samples (int): Total RTT samples across all hosts.
        """
        with self._lock:
            hosts_count = len(self._hosts)
            rtt_values = [h.ema for h in self._hosts.values()]
            total_samples = sum(h.samples for h in self._hosts.values())

        if rtt_values:
            avg_rtt = sum(rtt_values) / len(rtt_values)
            min_rtt = min(rtt_values)
            max_rtt = max(rtt_values)
        else:
            avg_rtt = 0.0
            min_rtt = 0.0
            max_rtt = 0.0

        return {
            "hosts_tracked": hosts_count,
            "avg_rtt_ms": round(avg_rtt, 2),
            "min_rtt_ms": round(min_rtt, 2),
            "max_rtt_ms": round(max_rtt, 2),
            "enabled": self._enabled,
            "total_samples": total_samples,
        }

    def reset(self) -> None:
        """Reset all per-host RTT data.

        Should be called at the start of a new attack run to clear
        stale RTT data from previous runs.
        """
        with self._lock:
            self._hosts.clear()
        logger.debug("SmartTimeoutEngine: reset all RTT data")

    # ─── Internal helpers ────────────────────────────────────────────────

    def _get_rtt_ema_seconds(self, host: str) -> float:
        """Get the RTT EMA for a host, converted to seconds.

        Law 6 boundary cases:
          - Empty host string → use default RTT
          - Unknown host → use default RTT
          - Any error → fallback to default RTT

        Args:
            host: The target hostname.

        Returns:
            RTT EMA in seconds.
        """
        if not isinstance(host, str) or not host.strip():
            return self._default_rtt_ms / 1000.0

        with self._lock:
            entry = self._hosts.get(host)
            if entry is None or entry.samples == 0:
                return self._default_rtt_ms / 1000.0
            return entry.ema / 1000.0

    @staticmethod
    def extract_host(url: str) -> str:
        """Extract hostname from a URL for RTT tracking.

        Law 5: Returns empty string for invalid URLs (caller handles
        the default case).

        Args:
            url: Full URL string.

        Returns:
            Hostname, or empty string if extraction fails.
        """
        if not isinstance(url, str) or not url.strip():
            return ""
        try:
            parsed = urlparse(url)
            return parsed.hostname or ""
        except (ValueError, AttributeError):
            return ""
