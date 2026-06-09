#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tester.adaptive_pacer — Global WAF-aware request pacing.

W4.2 EXTRACTION: Extracted from vf_attack_base.py for single responsibility.
All existing `from vf_attack_base import AdaptivePacer` continues to work
via re-export facade. New code should import directly:
`from tester.adaptive_pacer import AdaptivePacer`.
"""
from __future__ import annotations

import time
from typing import Dict, List, Any, Tuple

from tester.response_classifier import ResponseClass  # W4.2: canonical source


class AdaptivePacer:
    """v26 P2: Global WAF-aware request pacing.

    Instead of just per-worker adaptive backoff, this provides a
    plugin-level pacing mechanism that responds to WAF behavior:

    - WAF challenge detected → all workers slow down for 30s
      (gives time for challenge cookies to propagate)
    - WAF block rate > 30% → reduce request rate by 50%
    - Rate limit rate > 20% → reduce request rate by 30%
    - Normal operation → resume base rate

    This prevents the common pattern where workers blindly
    hammer a WAF-protected target, generating 100% blocks.

    BUG-FIX: Replaced O(n) list iteration on every record_response() call
    with O(1) incremental counters. The old code iterated the entire
    _recent_classes list (up to 1000 entries) on EVERY call to count
    WAF blocks, challenges, rate limits, and OKs. At high RPS (thousands),
    this became a significant performance bottleneck.

    The new approach maintains running counters that are incremented
    on each record_response() call and decremented during periodic pruning.
    This makes rate calculation O(1) instead of O(n).
    """

    def __init__(self, base_delay_ms: float = 10.0):
        self._base_delay_ms = base_delay_ms
        self._current_multiplier: float = 1.0
        self._waf_challenge_until: float = 0.0  # Timestamp until which we slow down
        self._last_waf_block_time: float = 0.0
        self._recent_classes: List[Tuple[float, ResponseClass]] = []  # (timestamp, class)
        self._window_seconds: float = 10.0  # Sliding window for rate calculation
        self._max_recent_classes: int = 1000  # Cap to prevent unbounded growth
        self._prune_counter: int = 0

        # BUG-FIX: O(1) incremental counters instead of O(n) list scan
        self._count_waf_blocked: int = 0
        self._count_challenge: int = 0
        self._count_rate_limited: int = 0
        self._count_ok: int = 0
        self._count_total: int = 0

    @property
    def current_delay_ms(self) -> float:
        """Current effective delay between requests in ms."""
        now = time.time()
        base = self._base_delay_ms * self._current_multiplier

        # If we're in a WAF challenge cooldown, increase delay significantly
        if now < self._waf_challenge_until:
            remaining = self._waf_challenge_until - now
            # Scale delay: up to 5x during challenge cooldown
            challenge_multiplier = min(1.0 + remaining * 0.2, 5.0)
            base *= challenge_multiplier

        return base

    def _decrement_counter(self, response_class: ResponseClass):
        """Decrement the appropriate counter for a pruned response class."""
        self._count_total -= 1
        if response_class == ResponseClass.WAF_BLOCKED:
            self._count_waf_blocked -= 1
        elif response_class == ResponseClass.CHALLENGE:
            self._count_challenge -= 1
        elif response_class == ResponseClass.RATE_LIMITED:
            self._count_rate_limited -= 1
        elif response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED):
            self._count_ok -= 1

    def _prune_recent_classes(self):
        """Prune old and overflow entries from _recent_classes.

        C1 FIX: Single-pass pruning that properly separates time-pruned and
        size-pruned entries to prevent double-decrement of counters.
        Previously, entries that were both old AND in the overflow could be
        decremented twice. Now, we first identify time-pruned entries from
        the ORIGINAL list, then handle size overflow from the KEPT entries.
        """
        now = time.time()
        cutoff = now - self._window_seconds

        # Step 1: Identify entries pruned by TIME (from original list)
        old_entries = [(t, c) for t, c in self._recent_classes if t <= cutoff]
        for _, c in old_entries:
            self._decrement_counter(c)

        # Step 2: Build kept list (time-filtered)
        new_list = [(t, c) for t, c in self._recent_classes if t > cutoff]

        # Step 3: Handle SIZE overflow (only among kept entries)
        if len(new_list) > self._max_recent_classes:
            new_list.sort(key=lambda x: x[0])  # Oldest first
            overflow = new_list[:len(new_list) - self._max_recent_classes]
            for _, c in overflow:
                self._decrement_counter(c)
            new_list = new_list[-self._max_recent_classes:]

        self._recent_classes = new_list

        # Safety guards (should not be needed with correct single-pass)
        self._count_total = max(0, self._count_total)
        self._count_waf_blocked = max(0, self._count_waf_blocked)
        self._count_challenge = max(0, self._count_challenge)
        self._count_rate_limited = max(0, self._count_rate_limited)
        self._count_ok = max(0, self._count_ok)
        self._prune_counter = 0

    def record_response(self, response_class: ResponseClass) -> None:
        """Record a response classification for pacing decisions.

        BUG-FIX: Uses O(1) incremental counters instead of O(n) list scan.
        Counters are incremented here and decremented during periodic pruning.

        Args:
            response_class: The classified response from the server
        """
        now = time.time()

        # Track recent classifications in sliding window
        self._recent_classes.append((now, response_class))

        # BUG-FIX: Increment counters (O(1))
        self._count_total += 1
        if response_class == ResponseClass.WAF_BLOCKED:
            self._count_waf_blocked += 1
        elif response_class == ResponseClass.CHALLENGE:
            self._count_challenge += 1
        elif response_class == ResponseClass.RATE_LIMITED:
            self._count_rate_limited += 1
        elif response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED):
            self._count_ok += 1

        # BUG-111: Use consolidated prune method (handles both time-based and size-based)
        self._prune_counter += 1
        if self._prune_counter >= 50:
            self._prune_recent_classes()
        elif len(self._recent_classes) > self._max_recent_classes:
            # Overflow outside periodic prune — also use consolidated method
            self._prune_recent_classes()

        # Handle WAF challenge — global slowdown for 30 seconds
        if response_class == ResponseClass.CHALLENGE:
            self._waf_challenge_until = now + 30.0
            self._last_waf_block_time = now

        # Handle WAF block — note the time
        if response_class == ResponseClass.WAF_BLOCKED:
            self._last_waf_block_time = now

        # BUG-FIX: Calculate rates from O(1) counters instead of O(n) list scan
        total = self._count_total
        if total < 5:
            return  # Not enough data yet

        waf_rate = (self._count_waf_blocked + self._count_challenge) / total
        rate_limit_rate = self._count_rate_limited / total
        ok_rate = self._count_ok / total

        # Adaptive multiplier calculation
        # BUG-FIX: Reduced multiplier values — old values (3.0x/2.0x) were too
        # aggressive. With base_delay=10ms and multiplier=3.0, the pacer alone
        # would add 30ms delay, and combined with per-worker backoff this could
        # reach several seconds, effectively stalling the attack.
        if waf_rate > 0.3:
            # Heavy WAF blocking — moderate slowdown (was 3.0x)
            self._current_multiplier = 1.8
        elif waf_rate > 0.15:
            # Moderate WAF blocking — slight slowdown (was 2.0x)
            self._current_multiplier = 1.4
        elif rate_limit_rate > 0.2:
            # Rate limiting — slight slowdown (was 1.5x)
            self._current_multiplier = 1.3
        elif rate_limit_rate > 0.1:
            # Some rate limiting — minimal slowdown
            self._current_multiplier = 1.1
        elif ok_rate > 0.7 and waf_rate < 0.05:
            # Good success rate, minimal WAF — can speed up
            self._current_multiplier = max(self._current_multiplier * 0.95, 1.0)
        else:
            # Default — gradually return to normal
            self._current_multiplier = max(self._current_multiplier * 0.98, 1.0)

    def get_stats(self) -> Dict[str, Any]:
        """Return pacer statistics."""
        return {
            "base_delay_ms": self._base_delay_ms,
            "current_multiplier": round(self._current_multiplier, 2),
            "effective_delay_ms": round(self.current_delay_ms, 1),
            "in_challenge_cooldown": time.time() < self._waf_challenge_until,
        }


__all__ = ["AdaptivePacer"]
