#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tester.target_selector — Weighted URL rotation with dead-URL detection.

W4.2 EXTRACTION: Extracted from vf_attack_base.py for single responsibility.
All existing `from vf_attack_base import TargetSelector` continues to work
via re-export facade. New code should import directly:
`from tester.target_selector import TargetSelector`.
"""
from __future__ import annotations

import random
import heapq
from typing import Dict, List, Any

from tester.response_classifier import ResponseClass  # W4.2: canonical source
from config.defaults import (
    TARGET_WEIGHT_SUCCESS_MULTIPLIER, TARGET_WEIGHT_SUCCESS_BONUS, TARGET_WEIGHT_CAP,
    TARGET_WEIGHT_WAF_BLOCK_MULTIPLIER, TARGET_WEIGHT_CHALLENGE_MULTIPLIER,
    TARGET_WEIGHT_NOT_FOUND_MULTIPLIER, TARGET_WEIGHT_RATE_LIMITED_MULTIPLIER,
    TARGET_WEIGHT_SERVER_ERROR_MULTIPLIER, TARGET_WEIGHT_OTHER_FAIL_MULTIPLIER,
    TARGET_WEIGHT_FLOOR, TARGET_WEIGHT_DISCOVERED_INITIAL, TARGET_WEIGHT_REVIVED,
)


class TargetSelector:
    """v26 P2: Weighted URL selector that avoids dead/blocked URLs.

    Tracks success/failure rates per URL and uses weighted random
    selection to prefer URLs that return successful responses.
    URLs that consistently fail (404, WAF block) are deprioritized
    and eventually removed from rotation.

    This is the single biggest factor in HIT improvement:
    - Stop wasting 30-50% of hits on dead/404 URLs
    - Concentrate fire on URLs that return 200/302/401
    - Auto-blacklist WAF-blocked URLs after threshold
    """

    def __init__(self, urls: List[str], dead_threshold: int = 5):
        """Initialize with a list of target URLs.

        Args:
            urls: List of target URLs to select from
            dead_threshold: Number of consecutive failures before a URL is dead
        """
        # Deduplicate URLs while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            if url and url not in seen:
                seen.add(url)
                unique_urls.append(url)
        self._original_urls: List[str] = unique_urls
        self._weights: Dict[str, float] = {url: 1.0 for url in unique_urls}
        self._hit_counts: Dict[str, int] = {url: 0 for url in unique_urls}
        self._ok_counts: Dict[str, int] = {url: 0 for url in unique_urls}
        self._fail_counts: Dict[str, int] = {url: 0 for url in unique_urls}
        self._dead_threshold = dead_threshold
        self._dead_urls: set = set()
        # REL-2: No lock needed — all access is from single event loop thread (asyncio)
        # threading.Lock was causing potential deadlock on task cancellation
        # v26 P2: Track redirect targets — add them to rotation
        self._discovered_urls: List[str] = []

    @property
    def alive_count(self) -> int:
        """Number of URLs still in active rotation (not dead)."""
        return sum(1 for u in self._weights if u not in self._dead_urls)

    @property
    def dead_count(self) -> int:
        """Number of dead/blacklisted URLs."""
        return len(self._dead_urls)

    def select(self) -> str | None:
        """Select a URL using weighted random selection.

        URLs with higher success rates get selected more often.
        Dead URLs are completely excluded.

        All access is from the single asyncio event loop thread.

        Returns:
            A URL string, or None if all URLs are dead.
        """
        # Filter alive URLs
        alive = {url: w for url, w in self._weights.items()
                 if url not in self._dead_urls}
        if not alive:
            # All URLs are dead — reset least-dead ones so attack continues
            # (prevents complete attack stall)
            self._emergency_revive()
            alive = {url: w for url, w in self._weights.items()
                     if url not in self._dead_urls}
            if not alive:
                return None

        # Weighted random selection
        urls = list(alive.keys())
        weights = list(alive.values())
        total = sum(weights)
        if total <= 0:
            # All weights are zero — use uniform selection
            return random.choice(urls)

        # Normalize and select
        r = random.uniform(0, total)
        cumulative = 0.0
        for url, weight in zip(urls, weights):
            cumulative += weight
            if r < cumulative:
                return url

        return urls[-1]  # Fallback

    def record_result(self, url: str, ok: bool, response_class: ResponseClass | None = None) -> None:
        """Record a hit result for a URL to update its weight.

        All access is from the single asyncio event loop thread.

        Args:
            url: The URL that was hit
            ok: Whether the request was successful (2xx/3xx)
            response_class: Classified response type for finer-grained weighting
        """
        if url not in self._weights:
            # New URL (discovered from redirect) — add it
            self._weights[url] = 1.0
            self._hit_counts[url] = 0
            self._ok_counts[url] = 0
            self._fail_counts[url] = 0

        self._hit_counts[url] = self._hit_counts.get(url, 0) + 1

        if ok:
            self._ok_counts[url] = self._ok_counts.get(url, 0) + 1
            self._fail_counts[url] = 0  # Reset consecutive fails on success
            # Increase weight — but cap to prevent one URL dominating
            self._weights[url] = min(
                self._weights[url] * TARGET_WEIGHT_SUCCESS_MULTIPLIER + TARGET_WEIGHT_SUCCESS_BONUS,
                TARGET_WEIGHT_CAP
            )
        else:
            self._fail_counts[url] = self._fail_counts.get(url, 0) + 1

            # Adjust weight based on response class
            if response_class == ResponseClass.WAF_BLOCKED:
                # WAF block — sharp decrease (this URL is being blocked)
                self._weights[url] *= TARGET_WEIGHT_WAF_BLOCK_MULTIPLIER
            elif response_class == ResponseClass.CHALLENGE:
                # WAF challenge — sharp decrease (need to wait for cookies)
                self._weights[url] *= TARGET_WEIGHT_CHALLENGE_MULTIPLIER
            elif response_class == ResponseClass.NOT_FOUND:
                # 404 — decrease and mark dead after threshold
                self._weights[url] *= TARGET_WEIGHT_NOT_FOUND_MULTIPLIER
                if self._fail_counts[url] >= self._dead_threshold:
                    self._dead_urls.add(url)
            elif response_class == ResponseClass.RATE_LIMITED:
                # Rate limited — slight decrease (server is still responding)
                self._weights[url] *= TARGET_WEIGHT_RATE_LIMITED_MULTIPLIER
            elif response_class == ResponseClass.SERVER_ERROR:
                # Server error — moderate decrease (server under stress)
                self._weights[url] *= TARGET_WEIGHT_SERVER_ERROR_MULTIPLIER
            else:
                # Other failure — moderate decrease
                self._weights[url] *= TARGET_WEIGHT_OTHER_FAIL_MULTIPLIER

            # Floor weight so URL isn't completely excluded unless dead
            self._weights[url] = max(self._weights[url], TARGET_WEIGHT_FLOOR)

            # Mark as dead if too many consecutive failures
            if self._fail_counts[url] >= self._dead_threshold and url not in self._dead_urls:
                self._dead_urls.add(url)

    def discover_url(self, url: str) -> None:
        """v26 P2: Add a newly discovered URL to the rotation.

        All access is from the single asyncio event loop thread.

        Args:
            url: New URL to add to rotation
        """
        if url and url not in self._weights:
            self._weights[url] = TARGET_WEIGHT_DISCOVERED_INITIAL  # High initial weight — test it quickly
            self._hit_counts[url] = 0
            self._ok_counts[url] = 0
            self._fail_counts[url] = 0
            self._discovered_urls.append(url)

    def _emergency_revive(self) -> None:
        """Revive the least-dead URLs when all are marked dead.

        This prevents the attack from completely stalling. We revive
        the URLs with the lowest fail counts (they might work again
        after a cooldown period).

        P4: Uses heapq.nsmallest for O(n log k) efficiency instead
        of sorting all URLs O(n log n), where k = number to revive.
        """
        if not self._weights:
            return

        # Use heapq.nsmallest for O(n log k) instead of sorted() O(n log n)
        revive_count = max(len(self._weights) // 2, 1)
        least_failed = heapq.nsmallest(
            revive_count,
            self._weights.keys(),
            key=lambda u: self._fail_counts.get(u, 0)
        )
        for url in least_failed:
            self._dead_urls.discard(url)
            self._weights[url] = TARGET_WEIGHT_REVIVED  # Start with lower weight
            self._fail_counts[url] = 0  # Reset fails

    def get_stats(self) -> Dict[str, Any]:
        """Return target selection statistics."""
        top_urls = sorted(self._weights.items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            "total_urls": len(self._weights),
            "alive_urls": self.alive_count,
            "dead_urls": self.dead_count,
            "discovered_urls": len(self._discovered_urls),
            "top_targets": [(url[:40], round(w, 2)) for url, w in top_urls],
        }


__all__ = ["TargetSelector"]
