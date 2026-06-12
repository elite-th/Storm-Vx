#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tester.response_pipeline — Unified response processing pipeline.

BUG-016 FIX: Extracts response processing from AttackPlugin._process_response()
into a composable pipeline that ALL plugins can use, including TCP-based ones
that don't have aiohttp responses.

Previously, _process_response() was a method on AttackPlugin that handled:
- Response classification (WAF detection, error detection)
- TargetSelector weight updates
- AdaptivePacer feedback
- Redirect URL discovery

12/20 plugins bypassed this pipeline entirely because they operate on
raw TCP connections, not HTTP responses. This meant no WAF detection,
no target weighting, and no adaptive pacing for those plugins.

Architecture:
- ProcessingResult: Dataclass with classification, WAF detection, weight hints, pacing
- ResponsePipeline: Protocol defining the process() interface
- HttpResponsePipeline: Wraps existing _process_response logic for HTTP plugins
- RawConnectionPipeline: Simplified pipeline for TCP/connection-based plugins

Law 15 compliance: Inter-module dependency only through interfaces.
Law 14 compliance: This file is under 500 lines.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Protocol, runtime_checkable, Any

from logging_config import get_logger
from tester.response_classifier import ResponseClass, ResponseClassifier
from tester.target_selector import TargetSelector
from tester.adaptive_pacer import AdaptivePacer
from tester.smart_timeout import SmartTimeoutEngine

logger = get_logger(__name__)


__all__ = [
    "ProcessingResult",
    "ResponsePipeline",
    "HttpResponsePipeline",
    "RawConnectionPipeline",
]


# ═══════════════════════════════════════════════════════════════════════════════
# Processing Result — the output of any pipeline
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ProcessingResult:
    """Result of processing a response through the pipeline.

    Contains all the information a plugin needs to adapt its behavior,
    regardless of whether the response came from HTTP or a raw connection.

    Attributes:
        response_class: Classified response type (OK, WAF_BLOCKED, etc.)
        waf_detected: Name of detected WAF, or empty string if none
        weight_update: Whether target weights were updated (for logging)
        pacing_hint: Suggested pacing adjustment ('slow', 'normal', 'fast')
        redirect_url: Discovered redirect URL, or empty string
        is_success: Whether the response indicates a successful hit
        cooldown_until: Timestamp until which to apply extra delay (0.0 = none)
    """
    response_class: ResponseClass = ResponseClass.OK
    waf_detected: str = ""
    weight_update: bool = False
    pacing_hint: str = "normal"  # 'slow', 'normal', 'fast'
    redirect_url: str = ""
    is_success: bool = True
    cooldown_until: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# ResponsePipeline Protocol — the interface all pipelines implement
# ═══════════════════════════════════════════════════════════════════════════════

@runtime_checkable
class ResponsePipeline(Protocol):
    """Protocol defining the response processing interface.

    Law 15: Inter-module dependency only through interfaces.
    All response pipelines must implement this protocol, enabling
    plugins to use any pipeline implementation without coupling.

    HTTP plugins use HttpResponsePipeline for full classification.
    TCP plugins use RawConnectionPipeline for simplified tracking.
    Custom pipelines can be created for specialized protocols.
    """

    def process(self, **kwargs: Any) -> ProcessingResult:
        """Process a response and return a ProcessingResult.

        Args:
            **kwargs: Pipeline-specific parameters. HTTP pipelines expect
                status_code, headers, url, body_snippet, worker_id, elapsed_ms.
                Raw pipelines expect success, url, worker_id, error_type.

        Returns:
            ProcessingResult with classification and adaptation hints.
        """
        ...

    def get_classifier_stats(self) -> Dict[str, Any]:
        """Return classification statistics from the pipeline.

        Returns:
            Dict with classifier stats (detected_waf, classification_counts, etc.)
        """
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# HttpResponsePipeline — for HTTP-based plugins (wraps existing logic)
# ═══════════════════════════════════════════════════════════════════════════════

class HttpResponsePipeline:
    """Full response processing pipeline for HTTP-based plugins.

    Wraps the existing _process_response logic from AttackPlugin:
    1. Classify response (WAF detection, error detection)
    2. Update TargetSelector weights based on success/failure
    3. Feed AdaptivePacer for global pacing
    4. Discover redirect targets
    5. Track WAF challenge cooldowns

    This is the canonical pipeline for plugins that receive aiohttp
    responses or have access to HTTP status codes and headers.
    """

    def __init__(
        self,
        classifier: ResponseClassifier,
        target_selector: TargetSelector | None = None,
        pacer: AdaptivePacer | None = None,
        smart_timeout: SmartTimeoutEngine | None = None,
        context: Any = None,
    ) -> None:
        """Initialize the HTTP response pipeline.

        Args:
            classifier: ResponseClassifier for response classification
            target_selector: TargetSelector for weight updates (optional)
            pacer: AdaptivePacer for global pacing feedback (optional)
            smart_timeout: SmartTimeoutEngine for RTT tracking (optional)
            context: AttackContext for evasion manager WAF feedback (optional)
        """
        self._classifier = classifier
        self._target_selector = target_selector
        self._pacer = pacer
        self._smart_timeout = smart_timeout
        self._context = context
        self._waf_challenge_cooldown_until: float = 0.0

    def process(
        self,
        *,
        status_code: int = 0,
        headers: Optional[Dict[str, str]] = None,
        url: str = "",
        body_snippet: str = "",
        worker_id: int = 0,
        elapsed_ms: float = 0.0,
        **kwargs: Any,
    ) -> ProcessingResult:
        """Process an HTTP response through the full pipeline.

        Args:
            status_code: HTTP status code
            headers: Response headers dict
            url: The URL that was hit (for weighting)
            body_snippet: First ~500 chars of response body
            worker_id: Worker ID for adaptive backoff
            elapsed_ms: Request elapsed time in ms

        Returns:
            ProcessingResult with full classification and adaptation hints
        """
        headers = headers or {}

        # Step 1: Track RTT for smart timeout
        if elapsed_ms > 0 and self._smart_timeout is not None and url:
            host = SmartTimeoutEngine.extract_host(url)
            if host:
                self._smart_timeout.update_rtt(host, elapsed_ms)

        # Step 2: Classify
        response_class = self._classifier.classify(status_code, headers, body_snippet)

        # Step 3: Determine success
        is_success = response_class in (
            ResponseClass.OK,
            ResponseClass.AUTH_REQUIRED,
            ResponseClass.REDIRECT,
        )

        # Step 4: Update target selector weights
        weight_updated = False
        if url and self._target_selector:
            self._target_selector.record_result(url, is_success, response_class)
            weight_updated = True

        # Step 5: Update global pacer
        pacing_hint = "normal"
        if self._pacer:
            self._pacer.record_response(response_class)
            # Derive pacing hint from pacer state
            pacing_hint = self._derive_pacing_hint(response_class)

        # Step 6: Handle WAF feedback
        self._handle_waf_feedback(response_class, url)

        # Step 7: Discover redirect targets
        redirect_url = ""
        if response_class == ResponseClass.REDIRECT and url:
            location = headers.get("Location", headers.get("location", ""))
            if location and self._target_selector:
                if not location.startswith(("http://", "https://")):
                    from urllib.parse import urljoin
                    location = urljoin(url, location)
                self._target_selector.discover_url(location)
                redirect_url = location

        # Step 8: WAF challenge cooldown
        cooldown_until = 0.0
        if response_class == ResponseClass.CHALLENGE:
            self._waf_challenge_cooldown_until = time.monotonic() + 15.0
            cooldown_until = self._waf_challenge_cooldown_until

        return ProcessingResult(
            response_class=response_class,
            waf_detected=self._classifier.detected_waf or "",
            weight_update=weight_updated,
            pacing_hint=pacing_hint,
            redirect_url=redirect_url,
            is_success=is_success,
            cooldown_until=cooldown_until,
        )

    def _derive_pacing_hint(self, response_class: ResponseClass) -> str:
        """Derive a pacing hint from the response classification.

        Returns:
            'slow' if WAF blocked/challenge, 'fast' if OK, 'normal' otherwise
        """
        if response_class in (ResponseClass.WAF_BLOCKED, ResponseClass.CHALLENGE):
            return "slow"
        if response_class == ResponseClass.RATE_LIMITED:
            return "slow"
        if response_class == ResponseClass.OK and self._pacer is not None:
            # If pacer multiplier is low, we can go faster
            stats = self._pacer.get_stats()
            if stats.get("current_multiplier", 1.0) < 0.8:
                return "fast"
        return "normal"

    def _handle_waf_feedback(self, response_class: ResponseClass, url: str) -> None:
        """Feed WAF detection back to the evasion manager.

        Args:
            response_class: Classified response type
            url: The URL that got this response
        """
        if self._context is None:
            return

        evasion = self._context.extra.evasion_manager
        if response_class in (ResponseClass.WAF_BLOCKED, ResponseClass.CHALLENGE):
            if self._classifier.detected_waf and evasion and hasattr(evasion, 'set_waf'):
                evasion.set_waf(self._classifier.detected_waf)

    def get_classifier_stats(self) -> Dict[str, Any]:
        """Return classification statistics."""
        return self._classifier.get_stats()

    @property
    def waf_challenge_cooldown_until(self) -> float:
        """Timestamp until which WAF challenge cooldown is active."""
        return self._waf_challenge_cooldown_until


# ═══════════════════════════════════════════════════════════════════════════════
# RawConnectionPipeline — for TCP/connection-based plugins
# ═══════════════════════════════════════════════════════════════════════════════

class RawConnectionPipeline:
    """Simplified response processing for TCP/connection-based plugins.

    TCP plugins (slowloris, conn_exhaust, tls_handshake, etc.) don't
    have HTTP status codes or headers. They only know whether a
    connection succeeded or failed. This pipeline provides:
    1. Simplified classification (success vs. failure)
    2. TargetSelector weight updates (when URL is provided)
    3. AdaptivePacer feedback based on success rate
    4. Basic WAF detection from connection patterns

    This ensures that ALL plugins, even TCP-based ones, participate
    in the adaptive pacing and target weighting systems.
    """

    def __init__(
        self,
        target_selector: TargetSelector | None = None,
        pacer: AdaptivePacer | None = None,
        context: Any = None,
    ) -> None:
        """Initialize the raw connection pipeline.

        Args:
            target_selector: TargetSelector for weight updates (optional)
            pacer: AdaptivePacer for global pacing feedback (optional)
            context: AttackContext for evasion manager WAF feedback (optional)
        """
        self._target_selector = target_selector
        self._pacer = pacer
        self._context = context
        self._classifier = ResponseClassifier()  # Simplified classifier for stats
        self._consecutive_failures: int = 0
        self._total_connections: int = 0
        self._successful_connections: int = 0

    def process(
        self,
        *,
        success: bool = True,
        url: str = "",
        worker_id: int = 0,
        error_type: str = "",
        **kwargs: Any,
    ) -> ProcessingResult:
        """Process a raw connection result through the pipeline.

        Args:
            success: Whether the connection was successful
            url: Target URL (for weight tracking)
            worker_id: Worker ID for tracking
            error_type: Error class name if failed (e.g., 'SSLError', 'TimeoutError')

        Returns:
            ProcessingResult with simplified classification
        """
        self._total_connections += 1

        # Step 1: Classify based on success/failure
        if success:
            response_class = ResponseClass.OK
            self._consecutive_failures = 0
            self._successful_connections += 1
        else:
            # Try to infer more specific classification from error type
            response_class = self._classify_error(error_type)
            self._consecutive_failures += 1

        # Step 2: Determine success
        is_success = success

        # Step 2.5: Record Prometheus metrics for TCP plugins
        try:
            from observability.metrics_ext import ext_metrics
            ext_metrics.response_classifications_total.labels(
                classification=response_class.value,
                source="raw_connection",
            ).inc()
        except ImportError:
            pass

        # Step 3: Update target selector weights
        weight_updated = False
        if url and self._target_selector:
            self._target_selector.record_result(url, is_success, response_class)
            weight_updated = True

        # Step 4: Update global pacer
        pacing_hint = "normal"
        if self._pacer:
            self._pacer.record_response(response_class)
            pacing_hint = "slow" if not success else "normal"

        # Step 5: Derive WAF detection hint from patterns
        waf_detected = ""
        if self._consecutive_failures >= 5 and self._context:
            evasion = self._context.extra.evasion_manager
            # Law 15: Use public detected_waf property instead of _waf_name
            if evasion and hasattr(evasion, 'detected_waf') and evasion.detected_waf:
                waf_detected = evasion.detected_waf

        # Step 6: Cooldown on repeated failures
        cooldown_until = 0.0
        if self._consecutive_failures >= 10:
            cooldown_until = time.monotonic() + 5.0

        return ProcessingResult(
            response_class=response_class,
            waf_detected=waf_detected,
            weight_update=weight_updated,
            pacing_hint=pacing_hint,
            redirect_url="",
            is_success=is_success,
            cooldown_until=cooldown_until,
        )

    def _classify_error(self, error_type: str) -> ResponseClass:
        """Classify a connection error into a ResponseClass.

        Maps common TCP/TLS error types to response classifications
        for adaptive pacing and targeting.

        Args:
            error_type: Exception class name (e.g., 'SSLError', 'TimeoutError')

        Returns:
            ResponseClass that best represents the error
        """
        error_lower = error_type.lower()

        # TLS-related errors may indicate WAF interception
        if any(t in error_lower for t in ('ssl', 'tls', 'cert')):
            return ResponseClass.CONNECTION_ERROR

        # Timeout may indicate server under stress
        if 'timeout' in error_lower:
            return ResponseClass.SERVER_ERROR

        # Connection refused/reset may indicate rate limiting
        if any(t in error_lower for t in ('refused', 'reset', 'pool')):
            return ResponseClass.RATE_LIMITED

        # Generic connection error
        return ResponseClass.CONNECTION_ERROR

    def get_classifier_stats(self) -> Dict[str, Any]:
        """Return connection statistics."""
        return {
            "total_connections": self._total_connections,
            "successful_connections": self._successful_connections,
            "consecutive_failures": self._consecutive_failures,
            "success_rate": self._successful_connections / max(self._total_connections, 1),
        }
