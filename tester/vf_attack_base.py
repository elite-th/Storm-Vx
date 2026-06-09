#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_attack_base — Base class for all attack plugins (v26 P2).

Provides shared worker management, scaling, stats tracking,
v24: adaptive retry with header rotation on rate-limit responses.
v25 P1: Response classification engine, cookie feedback loop,
        WAF runtime detection from responses.
v26 P2: Smart URL rotation with weighted targets, response-driven
        attack adaptation, adaptive request pacing (global WAF-aware),
        path obfuscation integration, auto-recovery hints.

All attack plugins should extend AttackPlugin instead of PluginInterface
directly to get these features for free.
"""

from __future__ import annotations

import asyncio
import time
import random
import aiohttp
from typing import Dict, List, Any
from abc import abstractmethod


from logging_config import get_logger
from utils.ssl_helpers import create_ssl_context
from observability.metrics import metrics as _metrics
logger = get_logger(__name__)

from plugin_system import PluginInterface, PluginMeta, AttackContext
from vf_common import C
from vf_validator import validate_cookie
from config.defaults import (
    WAF_BLOCKS_MAX, WORKER_CLEANUP_TIMEOUT,
)


__all__ = ["AttackPlugin", "ResponseClass", "ResponseClassifier", "TargetSelector", "AdaptivePacer"]


# ═══════════════════════════════════════════════════════════════════════════════
# Response Classification — CANONICAL SOURCE: tester.response_classifier
# ═══════════════════════════════════════════════════════════════════════════════
# W4.2 EXTRACTION: Moved to tester/response_classifier.py for single responsibility.
# These re-exports preserve backward compatibility — existing
# `from vf_attack_base import ResponseClass` continues to work.
# New code should import directly: `from tester.response_classifier import ResponseClass`.
from tester.response_classifier import ResponseClass, ResponseClassifier  # noqa: F401 — re-export for backward compat


# ═══════════════════════════════════════════════════════════════════════════════
# Target Selection — CANONICAL SOURCE: tester.target_selector
# ═══════════════════════════════════════════════════════════════════════════════
# W4.2 EXTRACTION: Moved to tester/target_selector.py for single responsibility.
# This re-export preserves backward compatibility — existing
# `from vf_attack_base import TargetSelector` continues to work.
# New code should import directly: `from tester.target_selector import TargetSelector`.
from tester.target_selector import TargetSelector  # noqa: F401 — re-export for backward compat


# ═══════════════════════════════════════════════════════════════════════════════
# Adaptive Pacing — CANONICAL SOURCE: tester.adaptive_pacer
# ═══════════════════════════════════════════════════════════════════════════════
# W4.2 EXTRACTION: Moved to tester/adaptive_pacer.py for single responsibility.
# This re-export preserves backward compatibility — existing
# `from vf_attack_base import AdaptivePacer` continues to work.
# New code should import directly: `from tester.adaptive_pacer import AdaptivePacer`.
from tester.adaptive_pacer import AdaptivePacer  # noqa: F401 — re-export for backward compat


# ═══════════════════════════════════════════════════════════════════════════════
# AttackPlugin — Base class for all attack plugins
# ═══════════════════════════════════════════════════════════════════════════════

class AttackPlugin(PluginInterface):
    """Base class for attack plugins with built-in worker management.

    Subclasses only need to implement:
    - _worker_loop(context, worker_id) — the per-worker attack logic
    - meta — PluginMeta with name, description, tags, etc.

    Everything else (run, scale, stop, get_stats, worker_count) is handled here.

    v24: Added _get_fresh_headers() for per-request header rotation,
    and _adaptive_sleep() for backoff on consecutive failures.

    v25 P1: Added _capture_response_cookies() for cookie feedback loop,
    _classify_response() for response intelligence, and
    shared ResponseClassifier instance for WAF runtime detection.

    v26 P2: Added TargetSelector for smart URL rotation,
    AdaptivePacer for global WAF-aware pacing, response-driven
    adaptation (_process_response), and auto-recovery hints.
    """

    meta = PluginMeta(name='unnamed_attack', plugin_type='attack')

    def __init__(self) -> None:
        self._workers: int = 0
        self._tasks: List[asyncio.Task] = []
        self._stop_event: asyncio.Event | None = None
        self._context: AttackContext | None = None

        # Stats
        self._total_requests: int = 0
        self._success_count: int = 0
        self._error_count: int = 0
        self._start_time: float = 0.0
        self._lock: asyncio.Lock | None = None  # Created lazily in run() to avoid event loop issues

        # v24: Per-worker consecutive failure tracking for adaptive backoff
        self._consecutive_fails: Dict[int, int] = {}

        # v25 P1: Response classifier (shared across all workers in this plugin)
        self._classifier = ResponseClassifier()

        # v25 P1: Track WAF block count per URL for auto-blacklisting
        self._url_waf_blocks: Dict[str, int] = {}
        self._WAF_BLOCKS_MAX = WAF_BLOCKS_MAX  # W2.4: Cap dict size to prevent unbounded memory growth

        # v26 P2: Smart URL rotation
        self._target_selector: TargetSelector | None = None

        # v26 P2: Adaptive request pacing
        self._pacer: AdaptivePacer | None = None

        # v26 P2: Auto-recovery hint (set by dashboard, checked by plugins)
        self._recovery_hint: str = ""  # "" = no hint, "waf_bypass" = try WAF bypass, etc.

        # v26 P2: Track if we're in WAF challenge cooldown
        self._waf_challenge_cooldown_until: float = 0.0

    async def run(self, context: AttackContext) -> Dict[str, Any]:
        """Launch workers and run until stopped."""
        self._context = context
        self._stop_event = context.stop_event or asyncio.Event()
        self._workers = context.extra.workers
        self._start_time = time.time()
        self._lock = asyncio.Lock()  # Create lock inside event loop

        # v26 P2: Initialize TargetSelector with page AND resource targets
        page_targets = context.page_targets or [context.url]
        resource_targets = context.resource_targets or []
        all_targets = list(dict.fromkeys(page_targets + resource_targets))  # Dedupe preserving order
        self._target_selector = TargetSelector(all_targets)

        # v26 P2: Initialize AdaptivePacer
        base_delay = context.extra.delay_ms
        self._pacer = AdaptivePacer(base_delay_ms=base_delay)

        # Launch initial workers
        for i in range(self._workers):
            self._spawn_worker_task(i)

        # Wait for stop signal
        try:
            await self._stop_event.wait()
        except asyncio.CancelledError:
            pass

        # Cancel remaining tasks
        for t in self._tasks:
            if not t.done():
                t.cancel()
        if self._tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._tasks, return_exceptions=True),
                    timeout=WORKER_CLEANUP_TIMEOUT  # W2.4
                )
            except asyncio.TimeoutError:
                logger.debug(f"Plugin {self.meta.name}: worker tasks did not finish within 15s timeout")

        return self.get_stats()

    def _spawn_worker_task(self, worker_id: int) -> None:
        """Create and track a single worker task."""
        if self._context is None or self._stop_event is None:
            return

        # BUG-205 fix: Clear stale failure count from previous worker
        # that may have used this same ID. Without this, freshly spawned
        # workers inherit heavy backoff from previous failed workers.
        self._consecutive_fails.pop(worker_id, None)

        # W2.6 FIX: Prune completed tasks before appending new ones.
        # With adaptive scaling, workers are created/destroyed frequently.
        # Without pruning, self._tasks grows monotonically, holding
        # references to thousands of completed asyncio.Task objects.
        # This causes memory leaks and slows the cancellation loop in run().
        if len(self._tasks) > 50:
            self._tasks = [t for t in self._tasks if not t.done()]

        # W5.2: Track worker spawn in metrics
        _metrics.workers_spawned_total.labels(plugin=self.meta.name).inc()

        async def _worker_wrapper(wid=worker_id):
            try:
                await self._worker_loop(self._context, wid)
            except asyncio.CancelledError:
                return
            except (RuntimeError, OSError, ConnectionError, asyncio.TimeoutError) as exc:
                logger.debug(f"Worker {wid} in {self.meta.name} crashed: {exc}")
                # W5.2: Track worker crash in metrics
                _metrics.workers_crashed_total.labels(plugin=self.meta.name).inc()

        task = asyncio.create_task(_worker_wrapper())
        self._tasks.append(task)

    @abstractmethod
    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Per-worker attack loop. Runs until stop_event is set.

        Args:
            context: Shared attack context
            worker_id: Unique worker identifier for this plugin
        """
        ...

    # ─── v26 P2: Smart Target Selection ──────────────────────────────────

    def _select_target(self) -> str | None:
        """v26 P2: Select a target URL using weighted rotation.

        Uses the TargetSelector to pick URLs that have higher success
        rates. Dead URLs are automatically excluded.

        Returns:
            A target URL, or None if all URLs are dead.
        """
        if self._target_selector:
            return self._target_selector.select()
        # Fallback: use context page_targets
        if self._context and self._context.page_targets:
            return random.choice(self._context.page_targets)
        return self._context.url if self._context else None

    def _select_resource_target(self) -> str | None:
        """v26 P2: Select a resource URL.

        For resource flood plugins. Uses the context resource_targets
        directly (they're typically fewer and all valid).

        Returns:
            A resource URL, or None if none available.
        """
        if self._context and self._context.resource_targets:
            return random.choice(self._context.resource_targets)
        return None

    # ─── v26 P2: Unified Response Processing ─────────────────────────────

    def _process_response(self, status_code: int, headers: Dict[str, str],
                          url: str = "", body_snippet: str = "",
                          worker_id: int = 0) -> ResponseClass:
        """v26 P2: Unified response processing pipeline.

        Combines classification, target weighting, pacing, and adaptation
        into a single method that plugins should call after each request.

        This replaces the separate calls to _classify_response,
        _handle_classified_response, and _on_request_result.

        Args:
            status_code: HTTP status code
            headers: Response headers dict
            url: The URL that was hit (for weighting)
            body_snippet: First ~500 chars of response body
            worker_id: Worker ID for adaptive backoff

        Returns:
            ResponseClass enum value for the plugin to use
        """
        # Step 1: Classify
        response_class = self._classifier.classify(status_code, headers, body_snippet)

        # Step 2: Determine success
        ok = response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED,
                                ResponseClass.REDIRECT)

        # Step 3: Update per-worker failure tracking
        self._on_request_result(worker_id, ok, status_code)

        # Step 4: Update target selector weights
        if url and self._target_selector:
            self._target_selector.record_result(url, ok, response_class)

        # Step 5: Update global pacer
        if self._pacer:
            self._pacer.record_response(response_class)

        # Step 6: Handle classified response (WAF feedback, etc.)
        self._handle_classified_response(response_class, self._context, url)

        # Step 7: Discover redirect targets
        if response_class == ResponseClass.REDIRECT and url:
            location = headers.get("Location", headers.get("location", ""))
            if location and self._target_selector:
                # BUG-203 fix: Resolve relative URLs to absolute before adding
                # Many servers return relative paths (e.g., /login, ./dashboard)
                # which would break when used with session.get()
                if not location.startswith(("http://", "https://")):
                    from urllib.parse import urljoin
                    location = urljoin(url, location)
                self._target_selector.discover_url(location)

        # Step 8: WAF challenge cooldown tracking
        if response_class == ResponseClass.CHALLENGE:
            self._waf_challenge_cooldown_until = time.time() + 15.0

        # W5.2: Record response classification in metrics
        _metrics.response_classifications_total.labels(
            class_=response_class.value,
            waf_name=self._classifier.detected_waf or "none",
        ).inc()

        return response_class

    # ─── v26 P2: Adaptive Pacing Sleep ───────────────────────────────────

    async def _paced_sleep(self, worker_id: int, base_delay_ms: float = 0.0) -> None:
        """v26 P2: Combined adaptive + global pacing sleep.

        Uses both the per-worker adaptive backoff and the global
        WAF-aware pacer to determine the optimal delay.

        Args:
            worker_id: The worker ID
            base_delay_ms: Base delay (overrides pacer base if > 0)
        """
        # Get effective delay from pacer (M3: use max of pacer and base, not one-or-the-other)
        if self._pacer:
            effective_delay = max(self._pacer.current_delay_ms, base_delay_ms)
        else:
            effective_delay = base_delay_ms

        # Apply per-worker adaptive backoff on top
        # BUG-FIX: Reduced backoff multipliers — old values (8x/4x) would cause
        # workers to sleep for seconds, effectively killing the attack. When many
        # workers hit consecutive failures (e.g. during WAF challenge), they ALL
        # enter heavy backoff simultaneously, causing RPS to drop to near-zero.
        # New max backoff is 500ms (was 2000ms) — still backs off but doesn't stall.
        fails = self._consecutive_fails.get(worker_id, 0)
        if fails > 10:
            # Heavy backoff: 4x + jitter (capped at 500ms)
            jitter = random.uniform(0.8, 1.5)
            effective_delay = min(max(effective_delay * 4, 200) * jitter, 500)
        elif fails > 5:
            # Medium backoff: 2x + jitter
            jitter = random.uniform(0.5, 1.2)
            effective_delay = min(max(effective_delay * 2, 100) * jitter, 300)
        elif fails > 2:
            # Mild backoff: 1.5x
            effective_delay = min(max(effective_delay * 1.5, 50), 200)
        elif fails > 0:
            # Slight backoff: 1.2x
            effective_delay = min(max(effective_delay * 1.2, 30), 100)

        # WAF challenge cooldown: additional delay
        now = time.time()
        if now < self._waf_challenge_cooldown_until:
            # In challenge cooldown — add extra delay
            remaining = self._waf_challenge_cooldown_until - now
            extra = min(remaining * 100, 500)  # Up to 500ms extra
            effective_delay += extra

        # BUG-FIX: Cap at 1 second max delay (was 3 seconds — too long, stalls attack)
        effective_delay = min(effective_delay, 1000)

        if effective_delay > 0:
            await asyncio.sleep(effective_delay / 1000.0)

    # ─── Legacy methods (kept for backward compatibility) ────────────────

    @staticmethod
    def _create_ssl_context(context: AttackContext) -> Any:
        """B1 FIX: Shared SSL context creation for plugins.
        
        Extracted from duplicated code in vf_slowloris.py and vf_conn_exhaust.py.
        Creates an SSL context based on the attack context settings:
        - If context already has ssl_ctx, use it
        - Otherwise create based on verify_ssl and use_tls settings
        
        Args:
            context: Attack context with SSL configuration.
            
        Returns:
            SSL context object, or None if TLS is not needed.
        """
        ssl_ctx = context.ssl_ctx
        use_tls = context.extra.use_tls
        if ssl_ctx is not None:
            return ssl_ctx
        if use_tls:
            return create_ssl_context(context.verify_ssl)
        return None

    def _get_fresh_headers(self, context: AttackContext, request_type: str = "document") -> Dict[str, str]:
        """v24: Get fresh headers with rotated fingerprint for this request.

        Uses the evasion manager if available, otherwise falls back to
        the context headers. This is the key to bypassing WAF rate limits:
        each request looks like it comes from a different browser.

        Args:
            context: Attack context (contains evasion_manager in extra)
            request_type: "document", "api", "resource", or "login"

        Returns:
            Fresh headers dict with rotated User-Agent and Sec-Fetch headers.
        """
        evasion = context.extra.evasion_manager
        if evasion and hasattr(evasion, 'request_headers'):
            # v26 P2: If evasion has path obfuscation, apply it
            headers = evasion.request_headers(request_type)
            return headers
        return dict(context.headers)

    def _on_request_result(self, worker_id: int, ok: bool, code: int = 0) -> None:
        """v24: Track consecutive failures for adaptive backoff.

        Call this after each request to update the failure tracking.
        Use _adaptive_sleep() or _paced_sleep() to apply the backoff.

        Args:
            worker_id: The worker ID
            ok: Whether the request was successful
            code: HTTP status code (0 for connection errors)
        """
        if ok:
            self._consecutive_fails[worker_id] = 0
        else:
            self._consecutive_fails[worker_id] = self._consecutive_fails.get(worker_id, 0) + 1

    async def _adaptive_sleep(self, worker_id: int, base_delay_ms: float) -> None:
        """v24: Adaptive sleep with exponential backoff on consecutive failures.

        Instead of a fixed delay, this increases the delay exponentially
        when a worker is experiencing consecutive failures. This prevents
        wasting resources on a server that's rate-limiting or down.

        v26 P2: Delegates to _paced_sleep for combined pacing.

        Args:
            worker_id: The worker ID
            base_delay_ms: Base delay between requests in milliseconds
        """
        await self._paced_sleep(worker_id, base_delay_ms)

    def _capture_response_cookies(self, resp, context: AttackContext) -> None:
        """v25 P1: Capture Set-Cookie from response and feed to evasion manager.

        Many WAFs (Cloudflare, ArvanCloud) set challenge cookies that must
        be present on subsequent requests. Without these cookies, every
        request gets blocked with 403/503.

        This method extracts cookies from the response and feeds them to
        the evasion manager so future requests include them.

        Args:
            resp: aiohttp ClientResponse object
            context: Attack context (contains evasion_manager in extra)
        """
        try:
            evasion = context.extra.evasion_manager
            if not evasion or not hasattr(evasion, 'update_cookies'):
                return

            # Extract Set-Cookie headers from the response with validation
            new_cookies = {}
            for cookie in resp.cookies.values():
                key = cookie.key
                value = cookie.value
                # Use centralized validation from vf_validator
                if validate_cookie(key, value):
                    new_cookies[key] = value

            if new_cookies:
                evasion.update_cookies(new_cookies)
        except (AttributeError, TypeError, ValueError) as exc:
            logger.debug(f"Cookie capture failed: {exc}")
        except (KeyError, RuntimeError) as exc:
            logger.debug(f"Unexpected error in cookie capture: {exc}")

    def _classify_response(self, status_code: int, headers: Dict[str, str],
                           body_snippet: str = "") -> ResponseClass:
        """v25 P1: Classify an HTTP response for attack intelligence.

        Uses the shared ResponseClassifier to categorize responses.
        v26 P2: Consider using _process_response() instead for full pipeline.

        Args:
            status_code: HTTP status code
            headers: Response headers dict
            body_snippet: First ~500 chars of response body

        Returns:
            ResponseClass enum value
        """
        return self._classifier.classify(status_code, headers, body_snippet)

    def _handle_classified_response(self, response_class: ResponseClass,
                                     context: AttackContext,
                                     url: str = "") -> None:
        """v25 P1: Take action based on classified response.

        This is the intelligence layer that auto-tunes the attack
        based on what the server is telling us.

        Args:
            response_class: The classified response type
            context: Attack context
            url: The URL that got this response (full URL, not truncated)
        """
        if context is None:
            return

        evasion = context.extra.evasion_manager

        if response_class == ResponseClass.WAF_BLOCKED:
            # Feed WAF info to evasion manager if we detected a new WAF
            if self._classifier.detected_waf and evasion and hasattr(evasion, 'set_waf'):
                evasion.set_waf(self._classifier.detected_waf)
            # Track WAF blocks per URL (use full URL as key for accurate dead-checking)
            if url:
                self._url_waf_blocks[url] = self._url_waf_blocks.get(url, 0) + 1
                # Evict low-count entries when dict exceeds cap to bound memory
                if len(self._url_waf_blocks) > self._WAF_BLOCKS_MAX:
                    self._url_waf_blocks = {
                        k: v for k, v in self._url_waf_blocks.items() if v >= 2
                    }

        elif response_class == ResponseClass.CHALLENGE:
            # WAF challenge detected — feed WAF info to evasion manager
            if self._classifier.detected_waf and evasion and hasattr(evasion, 'set_waf'):
                evasion.set_waf(self._classifier.detected_waf)

        elif response_class == ResponseClass.RATE_LIMITED:
            # Rate limited — evasion manager should rotate faster
            # (This is handled by _paced_sleep + AdaptivePacer)
            pass

        elif response_class == ResponseClass.NOT_FOUND:
            # URL doesn't exist — track it so we can avoid it
            # (Plugins can check _is_url_dead to skip dead URLs)
            if url:
                self._url_waf_blocks[url] = self._url_waf_blocks.get(url, 0) + 1
                # Same eviction logic as WAF_BLOCKED branch
                if len(self._url_waf_blocks) > self._WAF_BLOCKS_MAX:
                    self._url_waf_blocks = {
                        k: v for k, v in self._url_waf_blocks.items() if v >= 2
                    }

    def _is_url_dead(self, url: str, threshold: int = 5) -> bool:
        """v25 P1: Check if a URL has been blocked/404'd too many times.

        v26 P2: Also checks TargetSelector dead set.

        Args:
            url: The URL to check
            threshold: Number of blocks/404s before considering it dead

        Returns:
            True if the URL should be avoided
        """
        if self._target_selector and url in self._target_selector._dead_urls:
            return True
        return self._url_waf_blocks.get(url, 0) >= threshold

    async def _record(self, mode: str, ok: bool, code: int, rt: float,
                      err: str = '', url: str = '', hint: str = '') -> None:
        """Record a hit result atomically and report via context callbacks.

        v31 FIX: Added stop_event check. When the attack is stopping, stats
        callbacks (like health_monitor.record and live_log.add) may reference
        objects that have already been cleaned up (closed sessions, None
        contexts). The old code blindly called context.stats_callback even
        when the stop event was set, which caused AttributeError/NoneType
        errors during graceful shutdown. Now we skip the callback when
        stopping, but still record local stats for the final report.
        """
        if self._lock is not None:
            async with self._lock:
                self._total_requests += 1
                if ok:
                    self._success_count += 1
                else:
                    self._error_count += 1
        else:
            # Lock not yet initialized (before run()) — update without lock
            self._total_requests += 1
            if ok:
                self._success_count += 1
            else:
                self._error_count += 1

        # v31: Skip external callbacks when stopping to avoid referencing
        # cleaned-up objects (closed sessions, None contexts, etc.)
        if self._stop_event is not None and self._stop_event.is_set():
            return

        # Report via context callbacks (unified — single call, not duplicated)
        if self._context and self._context.stats_callback:
            try:
                self._context.stats_callback(mode, ok, code, rt, err, url, hint)
            except (RuntimeError, TypeError, AttributeError, ValueError) as exc:
                logger.debug(f"Stats callback error in {self.meta.name}: {exc}")

    def scale(self, delta: int) -> int:
        """Scale workers by delta. Returns actual change applied.

        BUG-109: After scaling, removes done tasks from self._tasks
        to prevent unbounded growth from cancelled/crashed workers.
        Also adjusts worker_count to stay accurate after crashes.
        """
        if self._context is None or self._stop_event is None:
            return 0

        # BUG-109: Always clean up done tasks first
        self._tasks = [t for t in self._tasks if not t.done()]

        if delta > 0:
            for i in range(delta):
                self._spawn_worker_task(self._workers + i)
            self._workers += delta
            return delta
        elif delta < 0:
            to_remove = min(abs(delta), len(self._tasks))
            removed = 0
            # Cancel from the end
            while removed < to_remove and self._tasks:
                t = self._tasks.pop()
                if not t.done():
                    t.cancel()
                    removed += 1
            self._workers = max(0, self._workers - removed)
            # BUG-109: Clean up any done tasks that accumulated
            self._tasks = [t for t in self._tasks if not t.done()]
            return removed
        return 0

    @property
    def worker_count(self) -> int:
        """Current number of active workers.

        BUG-FIX v33: Computes from live task count instead of using
        stale self._workers counter. When workers crash (uncaught
        exception in _worker_loop), the _worker_wrapper catches it
        and the task completes, but self._workers was never decremented.
        This caused the scaling engine to overcount workers, leading to
        incorrect scaling decisions and dashboard display.
        """
        if self._tasks:
            # Count only running/pending tasks (not done/crashed/cancelled)
            active = sum(1 for t in self._tasks if not t.done())
            if active > 0:
                return active
        # Fallback to stored count if no tasks (e.g. pre-run)
        return self._workers

    def get_stats(self) -> Dict[str, Any]:
        """Return current plugin statistics."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        stats = {
            'total_requests': self._total_requests,
            'success_count': self._success_count,
            'error_count': self._error_count,
            'workers': self._workers,
            'elapsed': round(elapsed, 2),
            'rps': round(self._total_requests / max(elapsed, 1), 2),
        }
        # v25 P1: Include classification stats
        cls_stats = self._classifier.get_stats()
        if cls_stats.get("detected_waf"):
            stats["detected_waf"] = cls_stats["detected_waf"]

        # v26 P2: Include target selector stats
        if self._target_selector:
            ts = self._target_selector.get_stats()
            stats["alive_targets"] = ts["alive_urls"]
            stats["dead_targets"] = ts["dead_urls"]

        # v26 P2: Include pacer stats
        if self._pacer:
            ps = self._pacer.get_stats()
            stats["pacer_multiplier"] = ps["current_multiplier"]
            stats["effective_delay_ms"] = ps["effective_delay_ms"]

        return stats

    def stop(self) -> None:
        """Signal all workers to stop."""
        if self._stop_event:
            self._stop_event.set()
