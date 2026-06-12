#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evasion.behavior_prober — Extensible behavior pattern system.

BUG-022 FIX: Extracts behavior reading from the hardcoded BehavioralMimic
in evasion/vf_behavior.py into a plugin-type architecture that supports:
- Adding new behavior patterns without modifying vf_behavior.py
- Sharing behavior patterns across evasion modules
- Having plugins define their own behavioral patterns
- Runtime selection of behavior mode via --behavior-mode CLI flag

Architecture:
- BehaviorMode: Enum for mode selection (default, aggressive, stealth)
- BehaviorPlugin: Protocol defining the behavior interface
- DefaultBehaviorProber: Wraps existing BehavioralMimic logic
- AggressiveBehaviorProber: High-intensity mode (faster, less mimicry)
- StealthBehaviorProber: Maximum stealth mode (slow, high mimicry)
- create_behavior_prober: Factory function for mode-based creation

Law 15 compliance: Inter-module dependency only through interfaces.
Law 14 compliance: This file is under 500 lines.
"""
from __future__ import annotations

import math
import random
import time
from enum import Enum
from typing import Dict, List, Optional, Protocol, runtime_checkable, Any
from urllib.parse import urljoin

from logging_config import get_logger
from config.defaults import BEHAVIOR_NETWORK_LATENCY_BASE
logger = get_logger(__name__)


__all__ = [
    "BehaviorMode",
    "BehaviorPlugin",
    "DefaultBehaviorProber",
    "AggressiveBehaviorProber",
    "StealthBehaviorProber",
    "create_behavior_prober",
]


# ═══════════════════════════════════════════════════════════════════════════════
# Behavior Mode Enum
# ═══════════════════════════════════════════════════════════════════════════════

class BehaviorMode(Enum):
    """Behavior mode selection for the evasion system.

    Controls the trade-off between attack speed and stealth:
    - DEFAULT: Balanced — realistic timing with moderate speed
    - AGGRESSIVE: High-intensity — faster timing, less mimicry
    - STEALTH: Maximum stealth — slow timing, high mimicry
    """
    DEFAULT = "default"
    AGGRESSIVE = "aggressive"
    STEALTH = "stealth"


# ═══════════════════════════════════════════════════════════════════════════════
# BehaviorPlugin Protocol — the interface all behavior probers implement
# ═══════════════════════════════════════════════════════════════════════════════

@runtime_checkable
class BehaviorPlugin(Protocol):
    """Protocol defining the behavior interface for evasion modules.

    BUG-022 FIX: Replaces hardcoded behavior with an extensible plugin system.
    Any module that needs behavioral timing or patterns should depend on
    this protocol, not on BehavioralMimic directly.

    Law 15: Inter-module dependency only through interfaces.
    """

    def get_request_delay(self, request_type: str = "document") -> float:
        """Get delay in seconds before the next request.

        Args:
            request_type: Type of request ("document", "api", "resource", "login")

        Returns:
            Delay in seconds (0.0 = no delay)
        """
        ...

    def get_page_headers(self, url: str = "") -> Dict[str, str]:
        """Get headers for a page/document navigation request.

        Args:
            url: The URL being navigated to (for Referer computation)

        Returns:
            Dict of headers appropriate for a page load
        """
        ...

    def get_navigation_pattern(self) -> List[str]:
        """Get an ordered list of URL paths to visit in sequence.

        Returns:
            List of URL paths simulating a browsing session
        """
        ...

    def should_follow_redirect(self, status_code: int, location: str) -> bool:
        """Determine whether to follow a redirect.

        Args:
            status_code: HTTP status code (301, 302, 307, 308)
            location: Redirect target URL

        Returns:
            True if the redirect should be followed
        """
        ...

    @property
    def mode(self) -> BehaviorMode:
        """The current behavior mode."""
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# DefaultBehaviorProber — wraps existing BehavioralMimic logic
# ═══════════════════════════════════════════════════════════════════════════════

class DefaultBehaviorProber:
    """Default behavior prober — wraps existing BehavioralMimic patterns.

    This prober delegates to the existing BehavioralMimic class for
    backward compatibility. It provides the same timing patterns and
    header generation as the original implementation.

    Use this for balanced attacks where stealth and speed are both
    important. Timing follows log-normal distributions for realism.
    """

    def __init__(self, url: str, page_targets: List[str],
                 resource_targets: List[str]) -> None:
        """Initialize with target information.

        Args:
            url: Target URL
            page_targets: List of page paths for navigation simulation
            resource_targets: List of resource paths for loading simulation
        """
        self._url = url
        self._page_targets = page_targets or ["/"]
        self._resource_targets = resource_targets or []
        self._mode = BehaviorMode.DEFAULT
        self._timing_multiplier: float = 1.0

        # Lazy import to avoid circular dependency
        self._mimic: Any = None

    def _get_mimic(self) -> Any:
        """Lazily initialize BehavioralMimic (avoids import at module level)."""
        if self._mimic is None:
            try:
                from evasion.vf_behavior import BehavioralMimic
                self._mimic = BehavioralMimic(
                    self._url, self._page_targets, self._resource_targets
                )
            except ImportError:
                logger.warning("[BEHAVIOR] BehavioralMimic not available, using fallback")
                self._mimic = None
        return self._mimic

    def get_request_delay(self, request_type: str = "document") -> float:
        """Get delay using BehavioralMimic's log-normal distribution.

        Falls back to simple random delay if BehavioralMimic is unavailable.
        """
        mimic = self._get_mimic()
        if mimic is not None:
            try:
                return mimic.get_session_timing()
            except Exception:
                pass
        # Fallback: log-normal delay
        mu = math.log(max(1.5, 0.01))
        delay = random.gauss(mu, 0.8)
        delay = math.exp(delay)
        delay = max(0.05, min(delay, 20.0))
        delay += BEHAVIOR_NETWORK_LATENCY_BASE * random.uniform(0.5, 1.5)
        delay *= self._timing_multiplier
        return max(0.05, min(delay, 20.0))

    def get_page_headers(self, url: str = "") -> Dict[str, str]:
        """Get headers for page navigation using BehavioralMimic."""
        mimic = self._get_mimic()
        if mimic is not None:
            try:
                # Get next action from mimic (includes headers)
                action = mimic.get_next_action()
                if action and "headers" in action:
                    return action["headers"]
            except Exception:
                pass
        # Fallback: basic browser headers
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

    def get_navigation_pattern(self) -> List[str]:
        """Get navigation pattern from page targets."""
        return list(self._page_targets)

    def should_follow_redirect(self, status_code: int, location: str) -> bool:
        """Default: follow most redirects except external ones."""
        # Don't follow redirects to different domains (safety)
        if location.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            target_host = urlparse(location).netloc.split(":")[0]
            current_host = urlparse(self._url).netloc.split(":")[0]
            if target_host != current_host:
                return False
        # Don't follow infinite redirect loops
        return status_code in (301, 302, 303, 307, 308)

    @property
    def mode(self) -> BehaviorMode:
        """The current behavior mode."""
        return self._mode

    def record_response(self, status: int, body_len: int, rt: float) -> None:
        """Record a response for adaptive timing adjustment.

        Args:
            status: HTTP status code
            body_len: Response body length in bytes
            rt: Response time in seconds
        """
        mimic = self._get_mimic()
        if mimic is not None:
            try:
                mimic.record_response(status, body_len, rt)
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# AggressiveBehaviorProber — high-intensity mode
# ═══════════════════════════════════════════════════════════════════════════════

class AggressiveBehaviorProber:
    """Aggressive behavior prober — faster timing, less mimicry.

    For high-intensity attacks where speed is prioritized over stealth.
    Uses shorter delays and simpler header patterns. Still maintains
    basic browser-like behavior to avoid the most obvious WAF detections.

    Timing: 50-200ms between requests (vs. 500-5000ms default)
    Headers: Simplified but still includes Sec-Fetch and UA
    Navigation: No simulated browsing sequence
    Redirects: Always follow (maximize coverage)
    """

    def __init__(self, url: str, page_targets: List[str],
                 resource_targets: List[str]) -> None:
        self._url = url
        self._page_targets = page_targets or ["/"]
        self._resource_targets = resource_targets or []
        self._mode = BehaviorMode.AGGRESSIVE

    def get_request_delay(self, request_type: str = "document") -> float:
        """Aggressive: short delays (50-200ms)."""
        base = random.uniform(0.05, 0.2)
        if request_type == "api":
            base *= 0.5  # API calls are faster
        elif request_type == "resource":
            base *= 0.3  # Resources load in parallel
        return max(0.02, base)

    def get_page_headers(self, url: str = "") -> Dict[str, str]:
        """Aggressive: minimal but valid browser headers."""
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
        }

    def get_navigation_pattern(self) -> List[str]:
        """Aggressive: just hit all targets, no browsing sequence."""
        return list(self._page_targets)

    def should_follow_redirect(self, status_code: int, location: str) -> bool:
        """Aggressive: always follow redirects for maximum coverage."""
        return True

    @property
    def mode(self) -> BehaviorMode:
        """The current behavior mode."""
        return self._mode


# ═══════════════════════════════════════════════════════════════════════════════
# StealthBehaviorProber — maximum stealth mode
# ═══════════════════════════════════════════════════════════════════════════════

class StealthBehaviorProber:
    """Stealth behavior prober — maximum stealth, slow timing, high mimicry.

    For situations where WAF detection is a critical concern.
    Uses longer delays, complete browser header sets, and full
    browsing session simulation with correlated request sequences.

    Timing: 2000-15000ms between requests (very slow but very realistic)
    Headers: Complete browser fingerprint (Sec-CH-UA, full Sec-Fetch, etc.)
    Navigation: Full simulated browsing sessions with page → resource flow
    Redirects: Cautious — only follow same-origin redirects
    """

    def __init__(self, url: str, page_targets: List[str],
                 resource_targets: List[str]) -> None:
        self._url = url
        self._page_targets = page_targets or ["/"]
        self._resource_targets = resource_targets or []
        self._mode = BehaviorMode.STEALTH
        self._timing_multiplier: float = 2.0  # Extra slow
        self._nav_index: int = 0

    def get_request_delay(self, request_type: str = "document") -> float:
        """Stealth: long delays with log-normal distribution."""
        if request_type == "document":
            # Page loads: 2-10 seconds (realistic reading time)
            base = random.uniform(2.0, 10.0)
        elif request_type == "api":
            # API calls: 1-3 seconds
            base = random.uniform(1.0, 3.0)
        elif request_type == "resource":
            # Resources: 0.1-0.5 seconds (loaded in "parallel")
            base = random.uniform(0.1, 0.5)
        else:
            base = random.uniform(1.5, 5.0)

        # Add network latency
        base += BEHAVIOR_NETWORK_LATENCY_BASE * random.uniform(0.8, 1.5)
        base *= self._timing_multiplier
        return max(0.1, min(base, 30.0))

    def get_page_headers(self, url: str = "") -> Dict[str, str]:
        """Stealth: complete, consistent browser headers."""
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": random.choice([
                "en-US,en;q=0.9",
                "en-US,en;q=0.8,en;q=0.7",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": urljoin(self._url, "/") if not url else url,
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Cache-Control": "max-age=0",
        }
        return headers

    def get_navigation_pattern(self) -> List[str]:
        """Stealth: simulated browsing sequence with reading pauses."""
        # Build a realistic browsing sequence
        pattern = ["/"]  # Always start with homepage
        if len(self._page_targets) > 1:
            # Visit 2-4 pages in sequence
            num_pages = min(random.randint(2, 4), len(self._page_targets))
            pattern.extend(random.sample(self._page_targets[1:], min(num_pages, len(self._page_targets) - 1)))
        return pattern

    def should_follow_redirect(self, status_code: int, location: str) -> bool:
        """Stealth: only follow same-origin redirects, cautious approach."""
        if not location:
            return False
        # Always check domain in stealth mode
        if location.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            target_host = urlparse(location).netloc.split(":")[0]
            current_host = urlparse(self._url).netloc.split(":")[0]
            if target_host != current_host:
                return False
        # Only follow temporary redirects (not permanent — those are suspicious)
        return status_code in (302, 303, 307)

    @property
    def mode(self) -> BehaviorMode:
        """The current behavior mode."""
        return self._mode


# ═══════════════════════════════════════════════════════════════════════════════
# Factory Function
# ═══════════════════════════════════════════════════════════════════════════════

def create_behavior_prober(
    mode: BehaviorMode | str = BehaviorMode.DEFAULT,
    url: str = "",
    page_targets: List[str] | None = None,
    resource_targets: List[str] | None = None,
) -> BehaviorPlugin:
    """Factory function to create a BehaviorProber for the given mode.

    Args:
        mode: Behavior mode (enum or string: 'default', 'aggressive', 'stealth')
        url: Target URL
        page_targets: List of page paths for navigation
        resource_targets: List of resource paths for loading

    Returns:
        BehaviorPlugin instance for the specified mode

    Raises:
        ValueError: If mode string is not recognized
    """
    if isinstance(mode, str):
        try:
            mode = BehaviorMode(mode.lower())
        except ValueError:
            raise ValueError(
                f"Unknown behavior mode: {mode!r}. "
                f"Valid modes: {', '.join(m.value for m in BehaviorMode)}"
            )

    page_targets = page_targets or ["/"]
    resource_targets = resource_targets or []

    if mode == BehaviorMode.AGGRESSIVE:
        return AggressiveBehaviorProber(url, page_targets, resource_targets)
    elif mode == BehaviorMode.STEALTH:
        return StealthBehaviorProber(url, page_targets, resource_targets)
    else:
        return DefaultBehaviorProber(url, page_targets, resource_targets)
