#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tester.vf_attack_response_handler — Response adaptation handler.

W4.3 EXTRACTION: Extracted from vf_attack_base.py for Law 14 compliance.
Handles response-driven adaptation concerns NOT covered by response_pipeline.py:
- URL WAF block tracking (per-URL block counts with eviction)
- Cookie capture from responses (feedback to evasion manager)
- URL death checking (combines WAF blocks + TargetSelector dead set)
- Pacing delay calculation (combined pacer + backoff + cooldown)
- Metrics recording for response classifications

AttackPlugin uses composition: self._response_handler = ResponseHandler().
Thin wrapper methods on AttackPlugin preserve backward compatibility.
"""
from __future__ import annotations

import time
import random
from typing import Dict, Any

from logging_config import get_logger
logger = get_logger(__name__)

from plugin_system import AttackContext
from vf_validator import validate_cookie
from config.defaults import WAF_BLOCKS_MAX
from tester.response_classifier import ResponseClass, ResponseClassifier
from tester.target_selector import TargetSelector
from observability.metrics import metrics as _metrics


__all__ = ["ResponseHandler"]


class ResponseHandler:
    """Handles response-driven adaptation for AttackPlugin.

    Complements the response_pipeline by managing concerns that are
    specific to the attack plugin's adaptive behavior:
    - Which URLs are being blocked by WAF (and should be avoided)
    - Cookie feedback from responses
    - Pacing delay calculation combining multiple factors
    - Response classification metrics

    Usage in AttackPlugin::

        self._response_handler = ResponseHandler()

        # After pipeline processes a response:
        self._response_handler.record_url_block(response_class, url)
        self._response_handler.record_metrics(response_class, waf_name)
        delay = self._response_handler.calculate_paced_delay(...)
    """

    def __init__(self, classifier: ResponseClassifier | None = None) -> None:
        self._classifier = classifier or ResponseClassifier()
        self._url_waf_blocks: Dict[str, int] = {}
        self._WAF_BLOCKS_MAX = WAF_BLOCKS_MAX
        self._waf_challenge_cooldown_until: float = 0.0

    # ─── Properties ─────────────────────────────────────────────────────

    @property
    def classifier(self) -> ResponseClassifier:
        """Underlying ResponseClassifier instance."""
        return self._classifier

    @property
    def detected_waf(self) -> str | None:
        """WAF name detected from responses (None if not detected)."""
        return self._classifier.detected_waf

    @property
    def cooldown_until(self) -> float:
        """Timestamp when WAF challenge cooldown ends (monotonic)."""
        return self._waf_challenge_cooldown_until

    @property
    def cooldown_remaining_ms(self) -> float:
        """Remaining WAF challenge cooldown in milliseconds."""
        now = time.monotonic()
        if now < self._waf_challenge_cooldown_until:
            return (self._waf_challenge_cooldown_until - now) * 1000.0
        return 0.0

    # ─── Classification ─────────────────────────────────────────────────

    def classify(self, status_code: int, headers: Dict[str, str],
                 body_snippet: str = "") -> ResponseClass:
        """Classify an HTTP response for attack intelligence.

        Args:
            status_code: HTTP status code
            headers: Response headers dict
            body_snippet: First ~500 chars of response body

        Returns:
            ResponseClass enum value
        """
        return self._classifier.classify(status_code, headers, body_snippet)

    # ─── URL WAF Block Tracking ─────────────────────────────────────────

    def record_url_block(self, response_class: ResponseClass, url: str) -> None:
        """Record URL-level WAF block/404 tracking and cooldown.

        Tracks per-URL block counts for WAF_BLOCKED and NOT_FOUND responses,
        and updates WAF challenge cooldown for CHALLENGE responses.

        Args:
            response_class: Classified response type
            url: The URL that received this response
        """
        if response_class == ResponseClass.WAF_BLOCKED:
            if url:
                self._url_waf_blocks[url] = self._url_waf_blocks.get(url, 0) + 1
                if len(self._url_waf_blocks) > self._WAF_BLOCKS_MAX:
                    self._url_waf_blocks = {
                        k: v for k, v in self._url_waf_blocks.items() if v >= 2
                    }

        elif response_class == ResponseClass.NOT_FOUND:
            if url:
                self._url_waf_blocks[url] = self._url_waf_blocks.get(url, 0) + 1
                if len(self._url_waf_blocks) > self._WAF_BLOCKS_MAX:
                    self._url_waf_blocks = {
                        k: v for k, v in self._url_waf_blocks.items() if v >= 2
                    }

        elif response_class == ResponseClass.CHALLENGE:
            self._waf_challenge_cooldown_until = time.monotonic() + 15.0

    def is_url_dead(self, url: str, target_selector: TargetSelector | None = None,
                    threshold: int = 5) -> bool:
        """Check if a URL has been blocked/404'd too many times.

        Args:
            url: The URL to check
            target_selector: TargetSelector to check its dead set
            threshold: Number of blocks/404s before considering it dead

        Returns:
            True if the URL should be avoided
        """
        if target_selector and target_selector.is_url_dead(url):
            return True
        return self._url_waf_blocks.get(url, 0) >= threshold

    # ─── WAF Feedback to Evasion Manager ────────────────────────────────

    def feed_waf_to_evasion(self, response_class: ResponseClass,
                            context: AttackContext | None) -> None:
        """Feed WAF detection info to the evasion manager.

        Called when a WAF-related response is detected (WAF_BLOCKED or
        CHALLENGE). If a WAF was detected by the classifier, this
        feeds it to the evasion manager for strategy adaptation.

        Args:
            response_class: Classified response type
            context: Attack context (for evasion manager access)
        """
        if context is None:
            return
        if response_class not in (ResponseClass.WAF_BLOCKED, ResponseClass.CHALLENGE):
            return

        evasion = context.extra.evasion_manager
        if self._classifier.detected_waf and evasion and hasattr(evasion, 'set_waf'):
            evasion.set_waf(self._classifier.detected_waf)

    # ─── Cookie Capture ─────────────────────────────────────────────────

    @staticmethod
    def capture_response_cookies(resp: Any, context: AttackContext) -> None:
        """Capture Set-Cookie from response and feed to evasion manager.

        Many WAFs set challenge cookies that must be present on
        subsequent requests. This extracts and validates cookies from
        the response, then feeds them to the evasion manager.

        Args:
            resp: aiohttp ClientResponse object
            context: Attack context (contains evasion_manager in extra)
        """
        try:
            evasion = context.extra.evasion_manager
            if not evasion or not hasattr(evasion, 'update_cookies'):
                return

            new_cookies: Dict[str, str] = {}
            for cookie in resp.cookies.values():
                key = cookie.key.replace('\x00', '')
                value = cookie.value.replace('\x00', '')
                if validate_cookie(key, value):
                    new_cookies[key] = value

            if new_cookies:
                evasion.update_cookies(new_cookies)
        except (AttributeError, TypeError, ValueError) as exc:
            logger.debug(f"Cookie capture failed: {exc}")
        except (KeyError, RuntimeError) as exc:
            logger.debug(f"Unexpected error in cookie capture: {exc}")

    # ─── Pacing Delay Calculation ───────────────────────────────────────

    def calculate_paced_delay(self, base_delay_ms: float,
                              pacer_delay_ms: float,
                              consecutive_fails: int) -> float:
        """Calculate effective delay combining pacer, backoff, and cooldown.

        Args:
            base_delay_ms: Base delay from context (0 to use pacer)
            pacer_delay_ms: Current delay from AdaptivePacer
            consecutive_fails: Number of consecutive failures for this worker

        Returns:
            Effective delay in milliseconds (capped at 1000ms)
        """
        # M3: Use max of pacer and base, not one-or-the-other
        effective_delay = max(pacer_delay_ms, base_delay_ms)

        # Per-worker adaptive backoff
        if consecutive_fails > 10:
            jitter = random.uniform(0.8, 1.5)
            effective_delay = min(max(effective_delay * 4, 200) * jitter, 500)
        elif consecutive_fails > 5:
            jitter = random.uniform(0.5, 1.2)
            effective_delay = min(max(effective_delay * 2, 100) * jitter, 300)
        elif consecutive_fails > 2:
            effective_delay = min(max(effective_delay * 1.5, 50), 200)
        elif consecutive_fails > 0:
            effective_delay = min(max(effective_delay * 1.2, 30), 100)

        # WAF challenge cooldown: additional delay
        cooldown_ms = self.cooldown_remaining_ms
        if cooldown_ms > 0:
            extra = min(cooldown_ms * 0.1, 500)
            effective_delay += extra

        return min(effective_delay, 1000)

    # ─── Metrics ────────────────────────────────────────────────────────

    @staticmethod
    def record_metrics(response_class: ResponseClass, waf_name: str = "") -> None:
        """Record response classification metrics.

        Args:
            response_class: The classified response type
            waf_name: Detected WAF name (empty if none)
        """
        _metrics.response_classifications_total.labels(
            class_=response_class.value,
            waf_name=waf_name or "none",
        ).inc()

    # ─── Stats ──────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return response handler statistics for plugin stats."""
        cls_stats = self._classifier.get_stats()
        stats: Dict[str, Any] = {
            "url_waf_blocks_count": len(self._url_waf_blocks),
        }
        if cls_stats.get("detected_waf"):
            stats["detected_waf"] = cls_stats["detected_waf"]
        return stats

    def get_classifier_stats(self) -> Dict[str, Any]:
        """Return classifier statistics (for get_stats backward compat)."""
        return self._classifier.get_stats()
