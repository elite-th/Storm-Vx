"""engine.runtime_context — Typed immutable config + per-target isolated runtime state.

Provides the execution context for the entire STORM VX runtime. Every
configuration object is a frozen dataclass (immutable after construction),
and every target gets its own isolated RuntimeContext with separate metrics,
WAF state, and failure tracking.

DESIGN PRINCIPLES:
  - Immutable config: frozen dataclasses, zero global mutable state
  - Per-target isolation: separate metrics, WAF state, failure tracking
  - Zero shared mutable state between targets
  - No blocking I/O in construction path
  - Typed: every field has a type annotation, IDE-autocompletable
  - Serializable: all config objects can be converted to dict for logging

ARCHITECTURE:
  EngineConfig (frozen, global)
    ├── ConnectionConfig
    ├── WorkerConfig
    ├── SchedulerConfig
    ├── BackpressureConfig
    ├── ObservabilityConfig
    └── SecurityConfig

  RuntimeContext (per-target, isolated)
    ├── TargetIdentity (frozen)
    ├── AtomicMetrics (per-target, lock-free)
    ├── WAFState (per-target)
    ├── FailureTracker (per-target)
    ├── BoundedMailbox (per-target, bounded channel)
    └── asyncio.Event (stop signal)

USAGE:
    config = EngineConfig.from_env()
    ctx = RuntimeContext.from_config(config, target=TargetIdentity(url="https://example.com"))
    # ctx is now fully isolated — no shared mutable state with other targets
"""
from __future__ import annotations

import asyncio
import os
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from engine.atomic_metrics import AtomicMetrics, MetricsSnapshot


# ═══════════════════════════════════════════════════════════════════════════════
# Immutable Configuration — Frozen dataclasses, no global mutable state
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ConnectionConfig:
    """Network and connection configuration (immutable).

    All timeout values are in seconds. Once created, cannot be modified.
    """
    timeout: float = 15.0
    connect_timeout: float = 3.0
    read_timeout: float = 10.0
    keepalive_timeout: float = 30.0
    dns_cache_ttl: int = 120
    connection_limit: int = 2000
    per_host_limit: int = 0  # 0 = unlimited
    verify_ssl: bool = True
    follow_redirects: bool = True
    pool_prewarm_batch: int = 50
    max_pool_size: int = 10_000


@dataclass(frozen=True)
class WorkerConfig:
    """Worker scaling configuration (immutable)."""
    initial_workers: int = 5
    max_workers: int = 5000
    step: int = 50
    step_duration: int = 5
    request_delay_ms: float = 10.0
    cache_bust: bool = True
    ua_rotation: bool = True
    username_field: str = "username"
    password_field: str = "password"


@dataclass(frozen=True)
class SchedulerConfig:
    """Scheduler tick and scaling configuration (immutable)."""
    tick_interval: float = 1.0
    min_workers: int = 10
    max_workers: int = 5000
    # Shrink thresholds (CLIENT connectivity only)
    shrink_extreme_timeout: float = 0.60
    shrink_extreme_fail: float = 0.30
    shrink_high_timeout: float = 0.45
    shrink_high_fail: float = 0.20
    shrink_moderate_timeout: float = 0.30
    shrink_moderate_fail: float = 0.15
    # Pause thresholds
    pause_timeout_rate: float = 0.65
    pause_fail_rate: float = 0.40
    # HOLD mode
    hold_consecutive_threshold: int = 8
    hold_expiry_seconds: float = 30.0
    hold_recovery_step: int = 5
    # Pressure mode (server under load)
    pressure_5xx_min: float = 0.15
    pressure_5xx_max: float = 0.50
    pressure_timeout_max: float = 0.30


@dataclass(frozen=True)
class BackpressureConfig:
    """Event-loop saturation detection configuration (immutable)."""
    max_lag_ms: float = 50.0
    min_samples: int = 5
    cooldown_ticks: int = 3


@dataclass(frozen=True)
class ObservabilityConfig:
    """Observability bus and sink configuration (immutable)."""
    bus_channel_size: int = 4096
    metrics_drain_interval: float = 0.1
    log_drain_interval: float = 0.1
    drain_batch_size: int = 1024
    batch_logging: bool = True


@dataclass(frozen=True)
class SecurityConfig:
    """Security hardening configuration (immutable)."""
    strict_mode: bool = False
    ssrf_protection: bool = True
    redact_secrets: bool = True
    json_max_depth: int = 20
    json_max_size: int = 10_000_000
    url_max_length: int = 8192
    plugin_max_size: int = 500_000


@dataclass(frozen=True)
class CrashRecoveryConfig:
    """Plugin crash recovery configuration (immutable)."""
    max_crashes: int = 3
    base_backoff: float = 5.0
    max_backoff: float = 60.0


@dataclass(frozen=True)
class ShutdownConfig:
    """Graceful shutdown configuration (immutable)."""
    timeout_seconds: float = 30.0
    drain_timeout_seconds: float = 10.0
    cancel_timeout_seconds: float = 5.0


@dataclass(frozen=True)
class EngineConfig:
    """Root configuration object — immutable, no global mutable state.

    All sub-configs are frozen dataclasses. Once constructed, the entire
    config tree is read-only. To change config, create a new EngineConfig.

    Construct via EngineConfig.from_env() or EngineConfig() for defaults.
    """
    connection: ConnectionConfig = field(default_factory=ConnectionConfig)
    workers: WorkerConfig = field(default_factory=WorkerConfig)
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)
    backpressure: BackpressureConfig = field(default_factory=BackpressureConfig)
    observability: ObservabilityConfig = field(default_factory=ObservabilityConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    crash_recovery: CrashRecoveryConfig = field(default_factory=CrashRecoveryConfig)
    shutdown: ShutdownConfig = field(default_factory=ShutdownConfig)
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> EngineConfig:
        """Load configuration from environment variables.

        All STORM_VX_* environment variables are read once at startup.
        No environment access after construction — immutable config.
        """
        connection = ConnectionConfig(
            timeout=float(os.environ.get("STORM_VX_TIMEOUT", "15")),
            connect_timeout=float(os.environ.get("STORM_VX_CONNECT_TIMEOUT", "3")),
            read_timeout=float(os.environ.get("STORM_VX_READ_TIMEOUT", "10")),
            verify_ssl=os.environ.get("STORM_VX_VERIFY_SSL", "true").lower() in ("true", "1"),
        )
        workers = WorkerConfig(
            initial_workers=int(os.environ.get("STORM_VX_INITIAL_WORKERS", "5")),
            max_workers=int(os.environ.get("STORM_VX_MAX_WORKERS", "5000")),
        )
        scheduler = SchedulerConfig(
            tick_interval=float(os.environ.get("STORM_VX_TICK_INTERVAL", "1.0")),
        )
        security = SecurityConfig(
            strict_mode=os.environ.get("STORM_VX_SECURITY_STRICT", "").lower() in ("true", "1"),
            ssrf_protection=os.environ.get("STORM_VX_SSRF_PROTECTION", "true").lower() not in ("false", "0"),
            redact_secrets=os.environ.get("STORM_VX_REDACT_SECRETS", "true").lower() not in ("false", "0"),
        )
        log_level = os.environ.get("STORM_VX_LOG_LEVEL", "INFO").upper()

        return cls(
            connection=connection,
            workers=workers,
            scheduler=scheduler,
            security=security,
            log_level=log_level,
        )

    def as_dict(self) -> Dict[str, Any]:
        """Serialize entire config tree to dict for logging/debugging."""
        return {
            "connection": {
                "timeout": self.connection.timeout,
                "connect_timeout": self.connection.connect_timeout,
                "read_timeout": self.connection.read_timeout,
                "verify_ssl": self.connection.verify_ssl,
            },
            "workers": {
                "initial_workers": self.workers.initial_workers,
                "max_workers": self.workers.max_workers,
                "step": self.workers.step,
                "step_duration": self.workers.step_duration,
            },
            "scheduler": {
                "tick_interval": self.scheduler.tick_interval,
                "min_workers": self.scheduler.min_workers,
                "max_workers": self.scheduler.max_workers,
            },
            "security": {
                "strict_mode": self.security.strict_mode,
                "ssrf_protection": self.security.ssrf_protection,
                "redact_secrets": self.security.redact_secrets,
            },
            "log_level": self.log_level,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Target Identity — Immutable per-target identification
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class TargetIdentity:
    """Immutable target identification and metadata.

    Frozen: once created, cannot be modified. Safe to share across tasks.
    """
    url: str
    site_root: str = ""
    domain: str = ""
    target_id: str = ""  # Unique identifier (e.g., "example.com")
    origin_ips: Tuple[str, ...] = ()  # Frozen tuple — immutable, zero-copy sharing
    page_targets: Tuple[str, ...] = ()
    resource_targets: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Derive missing fields from URL."""
        if not self.site_root and self.url:
            # Extract scheme + netloc
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            object.__setattr__(self, 'site_root', f"{parsed.scheme}://{parsed.netloc}")
        if not self.domain and self.url:
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            object.__setattr__(self, 'domain', parsed.hostname or "")
        if not self.target_id and self.domain:
            object.__setattr__(self, 'target_id', self.domain)


# ═══════════════════════════════════════════════════════════════════════════════
# WAF State — Per-target WAF detection state
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class WAFState:
    """Per-target WAF detection state.

    Isolates WAF detection per-target: when one target has Cloudflare,
    another target without WAF shouldn't switch to WAF evasion mode.
    """
    detected_waf: str = ""
    block_count: int = 0
    challenge_count: int = 0
    last_waf_time: float = 0.0
    cooldown_until: float = 0.0

    def record_waf_block(self, waf_name: str = "") -> None:
        """Record a WAF block response."""
        self.block_count += 1
        self.last_waf_time = time.time()
        if waf_name and waf_name != self.detected_waf:
            self.detected_waf = waf_name

    def record_challenge(self) -> None:
        """Record a WAF challenge response."""
        self.challenge_count += 1
        self.cooldown_until = time.time() + 15.0

    @property
    def in_cooldown(self) -> bool:
        """Whether we're in WAF challenge cooldown."""
        return time.time() < self.cooldown_until

    @property
    def is_waf_detected(self) -> bool:
        """Whether a WAF has been detected for this target."""
        return bool(self.detected_waf) and self.detected_waf.lower() != "none"


# ═══════════════════════════════════════════════════════════════════════════════
# Failure Tracker — Per-worker consecutive failure tracking
# ═══════════════════════════════════════════════════════════════════════════════

class FailureTracker:
    """Per-worker consecutive failure tracking for adaptive backoff.

    BOUNDED: max_workers caps the dict size. Overflow entries share
    a single "overflow" counter. GIL-atomic: no lock needed.
    """

    __slots__ = ('_fails', '_max_workers', '_overflow_count')

    def __init__(self, max_workers: int = 1000) -> None:
        self._fails: Dict[int, int] = {}
        self._max_workers = max_workers
        self._overflow_count: int = 0

    def record(self, worker_id: int, ok: bool) -> None:
        """Record a request result for adaptive backoff."""
        if ok:
            self._fails.pop(worker_id, None)
        else:
            if len(self._fails) < self._max_workers:
                self._fails[worker_id] = self._fails.get(worker_id, 0) + 1
            else:
                self._overflow_count += 1

    def get_fails(self, worker_id: int) -> int:
        """Get consecutive failure count for a worker."""
        return self._fails.get(worker_id, 0)

    def clear(self, worker_id: int) -> None:
        """Clear failure count for a worker."""
        self._fails.pop(worker_id, None)

    def reset(self) -> None:
        """Reset all failure tracking."""
        self._fails.clear()
        self._overflow_count = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Bounded Mailbox — Channel for plugin → observability communication
# ═══════════════════════════════════════════════════════════════════════════════

class BoundedMailbox:
    """Bounded async channel for plugin → observability communication.

    BOUNDED: If the consumer can't keep up, oldest events are dropped.
    This ensures the mailbox never blocks the hot path (10k+ req/sec).

    ZERO ALLOCATION HOT PATH: send_nowait() only calls put_nowait().
    No dict creation, no string formatting, no allocations.
    """

    __slots__ = ('_queue', '_dropped', '_sent')

    def __init__(self, maxsize: int = 4096) -> None:
        self._queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize)
        self._dropped: int = 0
        self._sent: int = 0

    def send_nowait(self, event: Dict[str, Any]) -> bool:
        """Non-blocking send. Drops oldest if full.

        Returns:
            True if sent, False if dropped.
        """
        self._sent += 1
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait()  # Drop oldest
                self._dropped += 1
                self._queue.put_nowait(event)
                return True
            except (asyncio.QueueFull, asyncio.QueueEmpty):
                self._dropped += 1
                return False

    async def drain(self, batch_size: int = 1024) -> list[Dict[str, Any]]:
        """Drain up to batch_size events from the mailbox."""
        events: list[Dict[str, Any]] = []
        for _ in range(batch_size):
            try:
                events.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return events

    @property
    def dropped_count(self) -> int:
        return self._dropped

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    @property
    def drop_rate(self) -> float:
        return self._dropped / max(self._sent, 1)


# ═══════════════════════════════════════════════════════════════════════════════
# Runtime Context — Per-target isolated execution context
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class RuntimeContext:
    """Per-target execution context with fully isolated state.

    NO SHARED MUTABLE STATE between RuntimeContext instances.
    Each target gets its own:
      - AtomicMetrics (lock-free counters)
      - WAFState (WAF detection)
      - FailureTracker (per-worker failure tracking)
      - BoundedMailbox (bounded async channel)
      - asyncio.Event (stop signal)

    The only shared references are to IMMUTABLE config objects
    (frozen dataclasses) which are safe to share.

    Usage:
        config = EngineConfig()
        target = TargetIdentity(url="https://example.com")
        ctx = RuntimeContext.from_config(config, target)
        # ctx is fully isolated — no shared mutable state
    """
    # Immutable identity (frozen)
    target: TargetIdentity = field(default_factory=lambda: TargetIdentity(url=""))

    # Immutable config references (frozen dataclasses — safe to share)
    config: EngineConfig = field(default_factory=EngineConfig)

    # Isolated mutable state (per-target)
    metrics: AtomicMetrics = field(default_factory=AtomicMetrics)
    waf_state: WAFState = field(default_factory=WAFState)
    failure_tracker: FailureTracker = field(default_factory=FailureTracker)
    mailbox: BoundedMailbox = field(default_factory=lambda: BoundedMailbox(4096))

    # Stop signal (per-target — can stop one target without affecting others)
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)

    # SSL context (created once, read-only after construction)
    ssl_ctx: Any = None

    # Creation timestamp for duration computation
    created_at: float = field(default_factory=time.time)

    # Worker management (derived from config, but mutable for scaling)
    _current_workers: int = 0

    @classmethod
    def from_config(cls, config: EngineConfig, target: TargetIdentity) -> RuntimeContext:
        """Create a fully isolated RuntimeContext from config and target.

        Args:
            config: Immutable engine configuration.
            target: Immutable target identity.

        Returns:
            Fully initialized RuntimeContext with isolated state.
        """
        # Build SSL context (once, read-only)
        ssl_ctx: Any = None
        if not config.connection.verify_ssl:
            ssl_ctx = False  # aiohttp convention: False = no verification
        else:
            ssl_ctx = ssl.create_default_context()

        return cls(
            target=target,
            config=config,
            metrics=AtomicMetrics(),
            waf_state=WAFState(),
            failure_tracker=FailureTracker(max_workers=config.workers.max_workers),
            mailbox=BoundedMailbox(config.observability.bus_channel_size),
            stop_event=asyncio.Event(),
            ssl_ctx=ssl_ctx,
            created_at=time.time(),
            _current_workers=config.workers.initial_workers,
        )

    @property
    def current_workers(self) -> int:
        """Current worker count."""
        return self._current_workers

    @current_workers.setter
    def current_workers(self, value: int) -> None:
        """Update worker count (bounded by config)."""
        self._current_workers = max(
            self.config.scheduler.min_workers,
            min(value, self.config.scheduler.max_workers),
        )

    @property
    def is_stopping(self) -> bool:
        """Whether this target has been signaled to stop."""
        return self.stop_event.is_set()

    @property
    def health(self) -> float:
        """Current health score (0.0 to 1.0)."""
        if self.metrics.total == 0:
            return 1.0
        return self.metrics.ok / self.metrics.total

    @property
    def uptime(self) -> float:
        """Seconds since this context was created."""
        return time.time() - self.created_at

    def request_stop(self) -> None:
        """Signal this target to stop gracefully."""
        self.stop_event.set()

    def snapshot(self) -> Dict[str, Any]:
        """Capture a point-in-time snapshot of the runtime context."""
        metrics_snap = self.metrics.snapshot()
        return {
            "target_id": self.target.target_id,
            "url": self.target.url,
            "health": round(self.health, 4),
            "uptime": round(self.uptime, 2),
            "current_workers": self._current_workers,
            "is_stopping": self.is_stopping,
            "waf_detected": self.waf_state.is_waf_detected,
            "waf_name": self.waf_state.detected_waf,
            "mailbox_pending": self.mailbox.pending_count,
            "mailbox_dropped": self.mailbox.dropped_count,
            "metrics": metrics_snap.as_dict(),
        }


__all__ = [
    "EngineConfig",
    "ConnectionConfig",
    "WorkerConfig",
    "SchedulerConfig",
    "BackpressureConfig",
    "ObservabilityConfig",
    "SecurityConfig",
    "CrashRecoveryConfig",
    "ShutdownConfig",
    "TargetIdentity",
    "RuntimeContext",
    "WAFState",
    "FailureTracker",
    "BoundedMailbox",
]
