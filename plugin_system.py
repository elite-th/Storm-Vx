#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     plugin_system — Dynamic Plugin Architecture for Storm-Vx             ║
║                                                                           ║
║  Provides:                                                                ║
║  - PluginMeta: Metadata descriptor for each plugin                       ║
║  - PluginInterface: Abstract base class all plugins must implement       ║
║  - AttackContext: Shared context object passed to attack plugins         ║
║  - AttackExtras: Typed configuration for plugins                         ║
║  - PluginTier: Plugin effectiveness tier enum                            ║
║  - PluginEffectivenessScore: Effectiveness tracking dataclass            ║
║  - PluginRegistry: Auto-discovery and management (lazy import)           ║
║  - LegacyPluginAdapter: Backward compat wrapper (lazy import)            ║
║                                                                           ║
║  PluginRegistry and LegacyPluginAdapter are defined in plugin_registry.py ║
║  and re-exported here via __getattr__ for backward compatibility.        ║
║                                                                           ║
║  Adding a new attack module = creating one .py file.                     ║
║  No changes to VF_TESTER.py, vf_data.py, or __init__.py needed!         ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Callable, Any, Optional, TYPE_CHECKING

from logging_config import get_logger
from config.defaults import VERIFY_SSL
logger = get_logger(__name__)


class PluginTier(IntEnum):
    """Plugin effectiveness tier (80/20 rule)."""
    ESSENTIAL = 1
    SITUATIONAL = 2
    DEPRECATED = 3


@dataclass
class PluginEffectivenessScore:
    """Tracks real-time effectiveness of a plugin during attack."""
    plugin_name: str = ""
    tier: PluginTier = PluginTier.SITUATIONAL
    total_requests: int = 0
    success_count: int = 0
    error_count: int = 0
    avg_rtt_ms: float = 0.0
    error_rate: float = 0.0
    success_rate: float = 0.0
    effectiveness_score: float = 0.0
    is_active: bool = True
    disabled_at: float = 0.0
    disable_reason: str = ""

    def update(self, total: int, success: int, errors: int, avg_rtt_ms: float) -> None:
        self.total_requests = total
        self.success_count = success
        self.error_count = errors
        self.avg_rtt_ms = max(avg_rtt_ms, 0.001)
        self.error_rate = errors / max(total, 1)
        self.success_rate = success / max(total, 1)
        rtt_factor = 1000.0 / self.avg_rtt_ms
        self.effectiveness_score = self.success_rate * rtt_factor

    @property
    def should_disable(self) -> bool:
        from config.defaults import PLUGIN_AUTO_DISABLE_ERROR_RATE, PLUGIN_AUTO_DISABLE_MIN_REQUESTS
        return (
            self.total_requests >= PLUGIN_AUTO_DISABLE_MIN_REQUESTS
            and self.error_rate >= PLUGIN_AUTO_DISABLE_ERROR_RATE
        )


if TYPE_CHECKING:
    import asyncio
    import aiohttp
    from finder.site_profile import SiteProfile


__all__ = [
    "PluginTier",
    "PluginEffectivenessScore",
    "PluginMeta",
    "PluginInterface",
    "AttackExtras",
    "AttackContext",
    "PluginRegistry",
    "LegacyPluginAdapter",
]


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Metadata
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PluginMeta:
    """Metadata descriptor for a plugin module.

    Every plugin must define a `meta` class attribute with these fields.
    The registry uses this metadata for discovery, filtering, and ordering.

    Attributes:
        name: Unique identifier (e.g. 'ws_flood', 'cookie_poison')
        version: Semantic version string (e.g. '1.0.0')
        plugin_type: One of 'attack', 'finder', 'evasion'
        description: Human-readable description of what this plugin does
        tags: List of tags for filtering (e.g. ['websocket', 'conference'])
        priority: Execution order — lower = runs first (default 50)
        compatible_profiles: Target types this plugin works with
                             (e.g. ['conference', 'student_portal'])
        requirements: Python packages required (e.g. ['aiohttp', 'httpx'])
    """
    name: str
    version: str = '1.0.0'
    plugin_type: str = 'attack'  # 'attack' | 'finder' | 'evasion'
    description: str = ''
    tags: List[str] = field(default_factory=list)
    priority: int = 50
    compatible_profiles: List[str] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)
    tier: PluginTier = PluginTier.SITUATIONAL


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Interface (Abstract Base Class)
# ═══════════════════════════════════════════════════════════════════════════════

class PluginInterface(ABC):
    """Abstract base class for all Storm-Vx plugins.

    Every plugin must:
    1. Define a `meta` class attribute (PluginMeta instance)
    2. Implement `run()` — the main async execution method
    3. Implement `get_stats()` — return current statistics as a dict
    4. Optionally override `stop()` for custom cleanup

    The `run()` method receives an AttackContext object that provides
    access to the shared session, URL, headers, stop event, and stats callback.
    """

    meta: PluginMeta = PluginMeta(name='unnamed')

    @abstractmethod
    async def run(self, context: AttackContext) -> Dict[str, Any]:
        """Execute the plugin's main logic.

        Args:
            context: Shared attack context with session, URL, headers, etc.

        Returns:
            Dict with final statistics after execution completes.
        """
        ...

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Return current plugin statistics.

        Must include at minimum:
        - 'total_requests': int
        - 'success_count': int
        - 'error_count': int
        """
        ...

    def stop(self) -> None:
        """Signal the plugin to stop gracefully. Override if needed."""
        if hasattr(self, '_stop_event') and self._stop_event is not None:
            self._stop_event.set()

    def scale(self, delta: int) -> int:
        """Scale the number of workers by delta.

        Positive delta adds workers, negative removes them.
        Returns the actual change applied (may be less than requested).

        Override in subclasses that support dynamic worker scaling.
        The default implementation does nothing and returns 0.
        """
        return 0

    @property
    def worker_count(self) -> int:
        """Return the current number of active workers.

        Override in subclasses that track workers.
        """
        return 0

    def __repr__(self) -> str:
        return f"<Plugin:{self.meta.name} v{self.meta.version}>"


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Extras — Typed Configuration for Plugins
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackExtras:
    """Typed container for plugin-specific attack configuration.

    Replaces the untyped Dict[str, Any] that was previously passed
    via AttackContext.extra. Every field is explicitly typed and
    documented, providing IDE autocompletion and type-checker safety.

    Attributes:
        workers: Number of concurrent workers for this plugin
        delay_ms: Base delay between requests in milliseconds
        cache_bust: Whether to append cache-busting query params
        username_field: Form field name for username (login attacks)
        password_field: Form field name for password (login attacks)
        use_tls: Whether to use TLS for raw TCP connections
        evasion_manager: EvasionManagerStub for header rotation (Any to avoid circular import at runtime; typed as Any because the stub lives in tester/ and importing it here would create a circular dependency)
        waf_name: Name of the detected WAF (empty string if none)
        ssl_ctx: Pre-built SSL context (Any to avoid stdlib import overhead)
    """
    workers: int = 10
    delay_ms: float = 10.0
    cache_bust: bool = True
    username_field: str = "username"
    password_field: str = "password"
    use_tls: bool = False
    evasion_manager: Any = None  # EvasionManagerStub — avoid circular import
    waf_name: str = ""
    ssl_ctx: Any = None  # ssl.SSLContext — avoid stdlib import


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Context — Shared State Object
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackContext:
    """Shared context object passed to all attack plugins.

    This replaces the implicit dependency on VFTester's `self.*` attributes.
    Every plugin receives everything it needs through this single object,
    making plugins decoupled from the orchestrator's internal state.

    Attributes:
        url: Primary target URL
        site_root: Scheme + netloc (e.g. 'https://example.com')
        domain: Domain name without port
        session: aiohttp.ClientSession for making requests
        headers: Base headers dict (with evasion if active)
        stop_event: asyncio.Event — set when attack should stop
        stats_callback: Function to call with (mode, HitResult) for stats recording
        live_log_callback: Function to call with (mode, code, rt, err, url, hint) for logging
        health_callback: Function to call with HitResult for health monitoring
        profile: SiteProfile with target technology profile (or None)
        origin_ips: List of CDN bypass IPs
        page_targets: List of page URLs to attack
        resource_targets: List of resource URLs to attack
        verify_ssl: Whether to verify SSL certificates (default False)
        ssl_ctx: Pre-built SSL context (takes precedence over verify_ssl)
        extra: Typed container for plugin-specific configuration (AttackExtras)
    """
    url: str = ''
    site_root: str = ''
    domain: str = ''
    session: aiohttp.ClientSession | None = None  # type: ignore[name-defined]
    headers: Dict[str, str] = field(default_factory=dict)
    stop_event: asyncio.Event | None = None
    stats_callback: Callable[[str, bool, int, float, str, str, str], None] | None = None  # Called with (mode, ok, code, rt, err, url, hint)
    live_log_callback: Callable[[str, int, float, str | None, str, str], None] | None = None
    health_callback: Callable[[Any], None] | None = None
    profile: Optional[SiteProfile] = None  # type: ignore[type-arg]
    origin_ips: List[str] = field(default_factory=list)
    page_targets: List[str] = field(default_factory=list)
    resource_targets: List[str] = field(default_factory=list)
    verify_ssl: bool = VERIFY_SSL  # Phase 0: defaults from config
    ssl_ctx: Any = None
    extra: AttackExtras = field(default_factory=AttackExtras)

    @property
    def ssl_param(self) -> Any:
        """Get the correct ssl parameter for aiohttp requests.

        Returns the pre-built SSL context if available, otherwise
        returns None (verify) or False (no verify) based on verify_ssl.
        """
        if self.ssl_ctx is not None:
            return self.ssl_ctx
        return None if self.verify_ssl else False

    def record(self, mode: str, ok: bool, code: int = 0, rt: float = 0.0,
                err: str = "", url: str = "", hint: str = "") -> None:
        """Record a hit result through the stats callback.

        Signature matches VFTester._record_hit(mode, ok, code, rt, err, url, hint).
        """
        if self.stats_callback:
            self.stats_callback(mode, ok, code, rt, err, url, hint)

    def log(self, mode: str, code: int = 0, rt: float = 0,
            err: str = '', url: str = '', hint: str = '') -> None:
        """Log a request result through the live log callback."""
        if self.live_log_callback:
            self.live_log_callback(mode, code, rt, err, url, hint)

    def health(self, result: Any) -> None:
        """Report a result to the health monitor."""
        if self.health_callback:
            self.health_callback(result)


# ═══════════════════════════════════════════════════════════════════════════════
# Lazy Re-Exports from plugin_registry.py
# ═══════════════════════════════════════════════════════════════════════════════
# PluginRegistry and LegacyPluginAdapter are defined in plugin_registry.py
# to comply with Law 14 (500-line limit). They are re-exported here via
# __getattr__ so that existing imports continue to work:
#     from plugin_system import PluginRegistry, LegacyPluginAdapter

_LAZY_REGISTRY_EXPORTS = {"PluginRegistry", "LegacyPluginAdapter"}


def __getattr__(name: str):
    """Lazy re-export from plugin_registry for backward compatibility.

    Avoids circular import: plugin_registry.py imports from plugin_system.py,
    so we cannot import from plugin_registry at module level here.
    Instead, we lazily import when the name is first accessed.
    """
    if name in _LAZY_REGISTRY_EXPORTS:
        from plugin_registry import PluginRegistry, LegacyPluginAdapter
        if name == "PluginRegistry":
            return PluginRegistry
        return LegacyPluginAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
