#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vf_attack_base — Base class for all attack plugins.

Provides worker management, scaling, stats, adaptive retry with
header rotation, response classification, cookie feedback, WAF
detection, smart URL rotation, adaptive pacing, and auto-recovery.

All attack plugins should extend AttackPlugin instead of PluginInterface.
"""
from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, List, Any
from abc import abstractmethod

from logging_config import get_logger
from utils.ssl_helpers import create_ssl_context
from utils.unicode_helpers import _strip_null_bytes
from observability.metrics import metrics as _metrics
from observability.tracing import async_span  # Phase 4: safe no-op when disabled
logger = get_logger(__name__)

from plugin_system import PluginInterface, PluginMeta, AttackContext
from vf_common import C
from config.defaults import WORKER_CLEANUP_TIMEOUT
from tester.smart_timeout import SmartTimeoutEngine
from tester.response_pipeline import (
    ResponsePipeline, HttpResponsePipeline, RawConnectionPipeline, ProcessingResult,
)
from tester.vf_attack_response_handler import ResponseHandler


__all__ = [
    "AttackPlugin", "ResponseClass", "ResponseClassifier",
    "TargetSelector", "AdaptivePacer", "SmartTimeoutEngine",
    "ResponsePipeline", "HttpResponsePipeline", "RawConnectionPipeline", "ProcessingResult",
]


# ═══════════════════════════════════════════════════════════════════════════════
# Re-exports — CANONICAL SOURCE: tester.response_classifier
# ═══════════════════════════════════════════════════════════════════════════════
from tester.response_classifier import ResponseClass, ResponseClassifier  # noqa: F401
from tester.target_selector import TargetSelector  # noqa: F401
from tester.adaptive_pacer import AdaptivePacer  # noqa: F401


# ═══════════════════════════════════════════════════════════════════════════════
# AttackPlugin — Base class for all attack plugins
# ═══════════════════════════════════════════════════════════════════════════════

class AttackPlugin(PluginInterface):
    """Base class for attack plugins with built-in worker management.

    Subclasses only need to implement:
    - _worker_loop(context, worker_id) — the per-worker attack logic
    - meta — PluginMeta with name, description, tags, etc.

    Everything else (run, scale, stop, get_stats, worker_count) is handled here.
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
        self._lock: asyncio.Lock | None = None

        # Per-worker consecutive failure tracking for adaptive backoff
        self._consecutive_fails: Dict[int, int] = {}

        # W4.3: Response handler (composition — URL blocks, cookies, delay, cooldown)
        self._response_handler = ResponseHandler()

        # Smart URL rotation
        self._target_selector: TargetSelector | None = None

        # Adaptive request pacing
        self._pacer: AdaptivePacer | None = None

        # Auto-recovery hint (set by dashboard, checked by plugins)
        self._recovery_hint: str = ""

        # Smart timeout engine (initialized in run())
        self._smart_timeout: SmartTimeoutEngine | None = None

        # Response pipeline (initialized in run())
        self._response_pipeline: ResponsePipeline | None = None

    async def run(self, context: AttackContext) -> Dict[str, Any]:
        """Launch workers and run until stopped."""
        self._context = context
        self._stop_event = context.stop_event or asyncio.Event()
        self._workers = context.extra.workers
        self._start_time = time.monotonic()
        self._lock = asyncio.Lock()

        # Initialize TargetSelector with page AND resource targets
        page_targets = context.page_targets or [context.url]
        resource_targets = context.resource_targets or []
        all_targets = list(dict.fromkeys(page_targets + resource_targets))
        self._target_selector = TargetSelector(all_targets)

        # Initialize AdaptivePacer
        base_delay = context.extra.delay_ms
        self._pacer = AdaptivePacer(base_delay_ms=base_delay)

        # Initialize SmartTimeoutEngine
        self._smart_timeout = SmartTimeoutEngine()

        # Share classifier with response handler (same instance used by pipeline)
        self._response_handler = ResponseHandler(classifier=self._classifier)

        # Initialize response pipeline
        self._response_pipeline = self._create_response_pipeline()

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
                    timeout=WORKER_CLEANUP_TIMEOUT,
                )
            except asyncio.TimeoutError:
                logger.debug(f"Plugin {self.meta.name}: worker tasks did not finish within 15s timeout")

        return self.get_stats()

    def _spawn_worker_task(self, worker_id: int) -> None:
        """Create and track a single worker task."""
        if self._context is None or self._stop_event is None:
            return

        # BUG-205: Clear stale failure count from previous worker
        self._consecutive_fails.pop(worker_id, None)

        # W2.6: Prune completed tasks before appending
        if len(self._tasks) > 50:
            self._tasks = [t for t in self._tasks if not t.done()]

        _metrics.workers_spawned_total.labels(plugin=self.meta.name).inc()

        async def _worker_wrapper(wid=worker_id):
            try:
                # Phase 4: Trace each worker loop iteration
                async with async_span("storm_vx.attack.request", plugin=self.meta.name, worker_id=wid):
                    await self._worker_loop(self._context, wid)
            except asyncio.CancelledError:
                return
            except (RuntimeError, OSError, ConnectionError, asyncio.TimeoutError) as exc:
                logger.debug(f"Worker {wid} in {self.meta.name} crashed: {exc}")
                _metrics.workers_crashed_total.labels(plugin=self.meta.name).inc()

        task = asyncio.create_task(_worker_wrapper())
        self._tasks.append(task)

    @abstractmethod
    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Per-worker attack loop. Runs until stop_event is set."""
        ...

    # ─── Smart Target Selection ─────────────────────────────────────────

    def _select_target(self) -> str | None:
        """Select a target URL using weighted rotation."""
        if self._target_selector:
            return self._target_selector.select()
        if self._context and self._context.page_targets:
            return random.choice(self._context.page_targets)
        return self._context.url if self._context else None

    def _select_resource_target(self) -> str | None:
        """Select a resource URL."""
        if self._context and self._context.resource_targets:
            return random.choice(self._context.resource_targets)
        return None

    # ─── Response Pipeline Creation ─────────────────────────────────────

    def _create_response_pipeline(self) -> ResponsePipeline:
        """Create the appropriate response pipeline for this plugin.

        Returns HttpResponsePipeline by default. TCP-based plugins
        should override this to return a RawConnectionPipeline.
        """
        return HttpResponsePipeline(
            classifier=self._classifier,
            target_selector=self._target_selector,
            pacer=self._pacer,
            smart_timeout=self._smart_timeout,
            context=self._context,
        )

    # ─── Unified Response Processing ────────────────────────────────────

    def _process_response(self, status_code: int, headers: Dict[str, str],
                          url: str = "", body_snippet: str = "",
                          worker_id: int = 0,
                          elapsed_ms: float = 0.0) -> ResponseClass:
        """Unified response processing pipeline.

        Delegates to ResponsePipeline for classification/weighting/pacing,
        then updates per-worker tracking and response handler state.
        """
        if isinstance(self._response_pipeline, HttpResponsePipeline):
            result = self._response_pipeline.process(
                status_code=status_code, headers=headers, url=url,
                body_snippet=body_snippet, worker_id=worker_id,
                elapsed_ms=elapsed_ms,
            )
            # Update per-worker failure tracking
            self._on_request_result(worker_id, result.is_success, status_code)
            # Record URL blocks, cooldown, WAF feedback via response handler
            self._response_handler.record_url_block(result.response_class, url)
            self._response_handler.feed_waf_to_evasion(result.response_class, self._context)
            # Record metrics
            ResponseHandler.record_metrics(result.response_class, result.waf_detected)
            # Sync cooldown from pipeline
            if result.cooldown_until > 0:
                self._response_handler._waf_challenge_cooldown_until = max(
                    self._response_handler.cooldown_until, result.cooldown_until,
                )
            return result.response_class

        # Fallback: inline pipeline for non-HTTP pipelines
        return self._process_response_inline(
            status_code, headers, url, body_snippet, worker_id, elapsed_ms)

    def _process_response_inline(self, status_code: int, headers: Dict[str, str],
                                  url: str = "", body_snippet: str = "",
                                  worker_id: int = 0,
                                  elapsed_ms: float = 0.0) -> ResponseClass:
        """Inline response processing when no pipeline is available."""
        # Track RTT for smart timeout
        if elapsed_ms > 0 and self._smart_timeout is not None and url:
            host = SmartTimeoutEngine.extract_host(url)
            if host:
                self._smart_timeout.update_rtt(host, elapsed_ms)

        # Classify
        response_class = self._response_handler.classify(status_code, headers, body_snippet)
        ok = response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED, ResponseClass.REDIRECT)

        # Update tracking
        self._on_request_result(worker_id, ok, status_code)
        if url and self._target_selector:
            self._target_selector.record_result(url, ok, response_class)
        if self._pacer:
            self._pacer.record_response(response_class)

        # Record URL blocks, cooldown, WAF feedback
        self._response_handler.record_url_block(response_class, url)
        self._response_handler.feed_waf_to_evasion(response_class, self._context)

        # Discover redirect targets
        if response_class == ResponseClass.REDIRECT and url:
            location = headers.get("Location", headers.get("location", ""))
            if location and self._target_selector:
                if not location.startswith(("http://", "https://")):
                    from urllib.parse import urljoin
                    location = urljoin(url, location)
                self._target_selector.discover_url(location)

        # Record metrics
        ResponseHandler.record_metrics(response_class, self._response_handler.detected_waf or "")
        return response_class

    # ─── Adaptive Pacing Sleep ──────────────────────────────────────────

    async def _paced_sleep(self, worker_id: int, base_delay_ms: float = 0.0) -> None:
        """Combined adaptive + global pacing sleep."""
        pacer_delay = self._pacer.current_delay_ms if self._pacer else 0.0
        fails = self._consecutive_fails.get(worker_id, 0)
        effective_delay = self._response_handler.calculate_paced_delay(
            base_delay_ms, pacer_delay, fails,
        )
        if effective_delay > 0:
            await asyncio.sleep(effective_delay / 1000.0)

    # ─── Smart Timeout ──────────────────────────────────────────────────

    def get_timeout_for_host(self, host: str) -> Dict[str, float]:
        """Get adaptive timeout parameters for a specific host."""
        if self._smart_timeout is None:
            return {}
        return self._smart_timeout.get_timeout_params(host)

    # ─── Legacy methods (backward compatibility wrappers) ───────────────

    @staticmethod
    def _create_ssl_context(context: AttackContext) -> Any:
        """Shared SSL context creation for plugins."""
        ssl_ctx = context.ssl_ctx
        use_tls = context.extra.use_tls
        if ssl_ctx is not None:
            return ssl_ctx
        if use_tls:
            return create_ssl_context(context.verify_ssl)
        return None

    def _get_fresh_headers(self, context: AttackContext, request_type: str = "document") -> Dict[str, str]:
        """Get fresh headers with rotated fingerprint for this request."""
        evasion = context.extra.evasion_manager
        if evasion and hasattr(evasion, 'request_headers'):
            return evasion.request_headers(request_type)
        return dict(context.headers)

    def _on_request_result(self, worker_id: int, ok: bool, code: int = 0) -> None:
        """Track consecutive failures for adaptive backoff."""
        if ok:
            self._consecutive_fails[worker_id] = 0
        else:
            self._consecutive_fails[worker_id] = self._consecutive_fails.get(worker_id, 0) + 1

    async def _adaptive_sleep(self, worker_id: int, base_delay_ms: float) -> None:
        """Adaptive sleep — delegates to _paced_sleep for combined pacing."""
        await self._paced_sleep(worker_id, base_delay_ms)

    def _capture_response_cookies(self, resp, context: AttackContext) -> None:
        """Capture Set-Cookie from response and feed to evasion manager."""
        ResponseHandler.capture_response_cookies(resp, context)

    def _classify_response(self, status_code: int, headers: Dict[str, str],
                           body_snippet: str = "") -> ResponseClass:
        """Classify an HTTP response for attack intelligence."""
        return self._response_handler.classify(status_code, headers, body_snippet)

    def _handle_classified_response(self, response_class: ResponseClass,
                                     context: AttackContext,
                                     url: str = "") -> None:
        """Take action based on classified response (WAF feedback, URL tracking)."""
        self._response_handler.record_url_block(response_class, url)
        self._response_handler.feed_waf_to_evasion(response_class, context)

    def _is_url_dead(self, url: str, threshold: int = 5) -> bool:
        """Check if a URL has been blocked/404'd too many times."""
        return self._response_handler.is_url_dead(url, self._target_selector, threshold)

    # ─── Stats Recording ────────────────────────────────────────────────

    async def _record(self, mode: str, ok: bool, code: int, rt: float,
                      err: str = '', url: str = '', hint: str = '') -> None:
        """Record a hit result atomically and report via context callbacks.

        v31 FIX: Skip external callbacks when stopping to avoid
        referencing cleaned-up objects.

        Null-byte fix: ``err``, ``url``, and ``hint`` are sanitized with
        ``_strip_null_bytes()`` to prevent ``ValueError: embedded null
        character`` on Windows when the dashboard tries to ``print()``
        these strings.
        """
        err = _strip_null_bytes(err)
        url = _strip_null_bytes(url)
        hint = _strip_null_bytes(hint)

        if self._lock is not None:
            async with self._lock:
                self._total_requests += 1
                if ok:
                    self._success_count += 1
                else:
                    self._error_count += 1
        else:
            self._total_requests += 1
            if ok:
                self._success_count += 1
            else:
                self._error_count += 1

        # Skip external callbacks when stopping
        if self._stop_event is not None and self._stop_event.is_set():
            return

        if self._context and self._context.stats_callback:
            try:
                self._context.stats_callback(mode, ok, code, rt, err, url, hint)
            except (RuntimeError, TypeError, AttributeError, ValueError) as exc:
                logger.debug(f"Stats callback error in {self.meta.name}: {exc}")

    # ─── Worker Management ──────────────────────────────────────────────

    def scale(self, delta: int) -> int:
        """Scale workers by delta. Returns actual change applied.

        BUG-109: After scaling, removes done tasks from self._tasks
        to prevent unbounded growth.
        """
        if self._context is None or self._stop_event is None:
            return 0

        self._tasks = [t for t in self._tasks if not t.done()]

        if delta > 0:
            for i in range(delta):
                self._spawn_worker_task(self._workers + i)
            self._workers += delta
            return delta
        elif delta < 0:
            to_remove = min(abs(delta), len(self._tasks))
            removed = 0
            while removed < to_remove and self._tasks:
                t = self._tasks.pop()
                if not t.done():
                    t.cancel()
                    removed += 1
            self._workers = max(0, self._workers - removed)
            self._tasks = [t for t in self._tasks if not t.done()]
            return removed
        return 0

    @property
    def worker_count(self) -> int:
        """Current number of active workers.

        BUG-FIX v33: Computes from live task count instead of stale counter.
        """
        if self._tasks:
            active = sum(1 for t in self._tasks if not t.done())
            if active > 0:
                return active
        return self._workers

    # ─── Classifier access (backward compat) ────────────────────────────

    @property
    def _classifier(self) -> ResponseClassifier:
        """Access the shared ResponseClassifier via response handler."""
        return self._response_handler.classifier

    @property
    def _waf_challenge_cooldown_until(self) -> float:
        """Access WAF challenge cooldown via response handler."""
        return self._response_handler.cooldown_until

    @_waf_challenge_cooldown_until.setter
    def _waf_challenge_cooldown_until(self, value: float) -> None:
        """Set WAF challenge cooldown on response handler."""
        self._response_handler._waf_challenge_cooldown_until = value

    @property
    def _url_waf_blocks(self) -> Dict[str, int]:
        """Access URL WAF blocks via response handler."""
        return self._response_handler._url_waf_blocks

    @_url_waf_blocks.setter
    def _url_waf_blocks(self, value: Dict[str, int]) -> None:
        """Set URL WAF blocks on response handler."""
        self._response_handler._url_waf_blocks = value

    # ─── Statistics ──────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return current plugin statistics."""
        elapsed = time.monotonic() - self._start_time if self._start_time else 0
        stats: Dict[str, Any] = {
            'total_requests': self._total_requests,
            'success_count': self._success_count,
            'error_count': self._error_count,
            'workers': self._workers,
            'elapsed': round(elapsed, 2),
            'rps': round(self._total_requests / max(elapsed, 1), 2),
        }
        # Include classification stats
        cls_stats = self._response_handler.get_classifier_stats()
        if cls_stats.get("detected_waf"):
            stats["detected_waf"] = cls_stats["detected_waf"]

        # Include target selector stats
        if self._target_selector:
            ts = self._target_selector.get_stats()
            stats["alive_targets"] = ts["alive_urls"]
            stats["dead_targets"] = ts["dead_urls"]

        # Include pacer stats
        if self._pacer:
            ps = self._pacer.get_stats()
            stats["pacer_multiplier"] = ps["current_multiplier"]
            stats["effective_delay_ms"] = ps["effective_delay_ms"]

        return stats

    def stop(self) -> None:
        """Signal all workers to stop."""
        if self._stop_event:
            self._stop_event.set()
