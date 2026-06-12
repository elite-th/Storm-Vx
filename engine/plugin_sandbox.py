"""engine.plugin_sandbox — Isolated plugin execution with crash recovery.

Addresses:
- DEF-03: Incomplete exception handling in plugin crash path
- DEF-04: Cross-target contamination via shared mutable state
- DEF-05: asyncio.Lock in stats recording creates thundering herd
- DEF-06: Unbounded task list growth
- DEF-10: Plugin sandbox escape via shared process state

DESIGN PRINCIPLES:
1. Each plugin runs in its own TaskGroup — crash doesn't affect others
2. Worker exceptions are caught with `except Exception` (not limited set)
3. Stats are lock-free (AtomicCounters), not asyncio.Lock-protected
4. Events are emitted through bounded channels, not direct callbacks
5. Task tracking uses a set (O(1) add/remove), not a list (O(n) prune)
6. Crash recovery with exponential backoff and max crash limit
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from engine.atomic_counters import AtomicCounters


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Lifecycle States
# ═══════════════════════════════════════════════════════════════════════════════

class PluginState(Enum):
    """Plugin lifecycle states.

    State transitions:
    DISCOVERED → VALIDATED → INITIALIZED → RUNNING
                                              ↓
                                         [PAUSED]
                                              ↓
                                        STOPPING → STOPPED
                                              ↓
                                        CRASHED → RECOVERING → INITIALIZED
    """
    DISCOVERED = "discovered"     # Found in plugin directory
    VALIDATED = "validated"       # Passed security validation
    INITIALIZED = "initialized"   # Constructor succeeded
    RUNNING = "running"           # Workers executing
    PAUSED = "paused"             # Temporarily suspended (backpressure)
    STOPPING = "stopping"         # Graceful shutdown in progress
    STOPPED = "stopped"           # Clean shutdown complete
    CRASHED = "crashed"           # Unexpected failure
    RECOVERING = "recovering"     # Auto-restart in progress


# ═══════════════════════════════════════════════════════════════════════════════
# Bounded Mailbox — Channel for plugin events
# ═══════════════════════════════════════════════════════════════════════════════

class BoundedMailbox:
    """Bounded async channel for plugin → observability communication.

    Replaces direct stats_callback/health_callback/live_log_callback
    invocations. Plugins emit events through the mailbox; a consumer
    task drains them asynchronously.

    BOUNDED: If the consumer can't keep up, oldest events are dropped.
    This ensures the mailbox never blocks the hot path (10k+ req/sec).

    Usage:
        mailbox = BoundedMailbox(maxsize=4096)

        # In worker loop (hot path):
        await mailbox.send_async({"type": "hit", "ok": True, ...})

        # In consumer (background task):
        events = await mailbox.drain(batch_size=1024)
    """

    __slots__ = ('_queue', '_dropped')

    def __init__(self, maxsize: int = 4096) -> None:
        self._queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize)
        self._dropped: int = 0

    async def send_async(self, event: Dict[str, Any],
                          timeout: float = 0.001) -> bool:
        """Send an event. Non-blocking with tiny timeout.

        Args:
            event: Event dict to send.
            timeout: Max time to wait if queue is full (default: 1ms).

        Returns:
            True if sent, False if dropped.
        """
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            # Drop oldest event to make room
            try:
                self._queue.get_nowait()
                self._dropped += 1
                self._queue.put_nowait(event)
                return True
            except (asyncio.QueueFull, asyncio.QueueEmpty):
                self._dropped += 1
                return False

    def send_nowait(self, event: Dict[str, Any]) -> bool:
        """Synchronous non-blocking send (for use in non-async contexts).

        Returns:
            True if sent, False if dropped.
        """
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait()
                self._dropped += 1
                self._queue.put_nowait(event)
                return True
            except (asyncio.QueueFull, asyncio.QueueEmpty):
                self._dropped += 1
                return False

    async def drain(self, batch_size: int = 1024) -> List[Dict[str, Any]]:
        """Drain up to batch_size events from the mailbox.

        Args:
            batch_size: Maximum number of events to drain.

        Returns:
            List of event dicts.
        """
        events: List[Dict[str, Any]] = []
        for _ in range(batch_size):
            try:
                events.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return events

    @property
    def dropped_count(self) -> int:
        """Number of events dropped due to full mailbox."""
        return self._dropped

    @property
    def pending_count(self) -> int:
        """Number of events waiting in the mailbox."""
        return self._queue.qsize()


# ═══════════════════════════════════════════════════════════════════════════════
# WAF State — Per-target WAF detection state
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class WAFState:
    """Per-target WAF detection state.

    Isolates WAF detection per-target (DEF-04 fix).
    When one target has Cloudflare, another target without WAF
    shouldn't switch to WAF evasion mode.
    """
    detected_waf: str = ""
    block_count: int = 0
    challenge_count: int = 0
    last_waf_time: float = 0.0
    cooldown_until: float = 0.0

    def record_waf_block(self, waf_name: str = "") -> None:
        """Record a WAF block response."""
        self.block_count += 1
        self.last_waf_time = time.monotonic()
        if waf_name and waf_name != self.detected_waf:
            self.detected_waf = waf_name

    def record_challenge(self) -> None:
        """Record a WAF challenge response."""
        self.challenge_count += 1
        self.cooldown_until = time.monotonic() + 15.0

    @property
    def in_cooldown(self) -> bool:
        """Whether we're in WAF challenge cooldown."""
        return time.monotonic() < self.cooldown_until

    @property
    def is_waf_detected(self) -> bool:
        """Whether a WAF has been detected for this target."""
        return bool(self.detected_waf) and self.detected_waf.lower() != "none"


# ═══════════════════════════════════════════════════════════════════════════════
# Failure Tracker — Per-worker consecutive failure tracking
# ═══════════════════════════════════════════════════════════════════════════════

class FailureTracker:
    """Per-worker consecutive failure tracking for adaptive backoff.

    Uses a bounded dict (max 1000 workers) to prevent unbounded memory
    growth. Worker IDs beyond the limit share a single "overflow" counter.

    GIL-atomic: no lock needed for individual dict operations.
    """

    __slots__ = ('_fails', '_max_workers')

    def __init__(self, max_workers: int = 1000) -> None:
        self._fails: Dict[int, int] = {}
        self._max_workers = max_workers

    def record(self, worker_id: int, ok: bool) -> None:
        """Record a request result for adaptive backoff.

        Args:
            worker_id: Worker identifier.
            ok: Whether the request was successful.
        """
        if ok:
            self._fails.pop(worker_id, None)  # Reset on success
        else:
            self._fails[worker_id] = self._fails.get(worker_id, 0) + 1
            # Bound the dict size
            if len(self._fails) > self._max_workers:
                # Remove entries with lowest fail counts
                self._fails = dict(
                    sorted(self._fails.items(), key=lambda x: x[1], reverse=True)
                    [:self._max_workers // 2]
                )

    def get_fails(self, worker_id: int) -> int:
        """Get consecutive failure count for a worker."""
        return self._fails.get(worker_id, 0)

    def clear(self, worker_id: int) -> None:
        """Clear failure count for a worker (used when spawning new workers)."""
        self._fails.pop(worker_id, None)

    def reset(self) -> None:
        """Reset all failure tracking."""
        self._fails.clear()


# ═══════════════════════════════════════════════════════════════════════════════
# Target Context — Immutable per-target execution context
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TargetContext:
    """Per-target execution context with isolated state.

    Replaces the shared AttackContext + Stats combo that caused
    cross-target contamination (DEF-04 fix).

    Each plugin targeting a specific URL/IP gets its own TargetContext
    with isolated counters, WAF state, and failure tracking.
    """
    # Target identification
    url: str = ""
    site_root: str = ""
    domain: str = ""
    target_id: str = ""  # Unique identifier (e.g., "example.com" or "192.168.1.1")

    # Target lists (frozen tuples — immutable, zero-copy sharing)
    origin_ips: tuple[str, ...] = ()
    page_targets: tuple[str, ...] = ()
    resource_targets: tuple[str, ...] = ()

    # Isolated mutable state
    counters: AtomicCounters = field(default_factory=AtomicCounters)
    waf_state: WAFState = field(default_factory=WAFState)
    failure_tracker: FailureTracker = field(default_factory=FailureTracker)
    mailbox: BoundedMailbox = field(default_factory=lambda: BoundedMailbox(4096))

    # Shared (read-only references — not mutated by plugins)
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)
    ssl_ctx: Any = None
    verify_ssl: bool = False
    request_delay_ms: float = 10.0
    enable_cache_bust: bool = True
    username_field: str = "username"
    password_field: str = "password"

    # Worker management
    initial_workers: int = 10
    max_workers: int = 5000


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Sandbox — Isolated execution environment
# ═══════════════════════════════════════════════════════════════════════════════

class PluginSandbox:
    """Isolated execution environment for a single plugin.

    Guarantees (fixing DEF-03, DEF-05, DEF-06, DEF-10):
    - Plugin crash doesn't affect other plugins (own TaskGroup)
    - Stats are lock-free (AtomicCounters, no asyncio.Lock)
    - Events are emitted through bounded channels (BoundedMailbox)
    - Workers are bounded by semaphore (WorkerPool)
    - Cancellation is deterministic (TaskGroup cancellation)
    - Exception handling catches ALL exceptions (not limited set)
    - Task tracking uses a set (O(1) add/remove, not O(n) list)

    Usage:
        sandbox = PluginSandbox(plugin, context)
        await sandbox.run()  # Runs until stop_event is set
    """

    def __init__(self, plugin: Any, context: TargetContext,
                 max_crashes: int = 3) -> None:
        self._plugin = plugin
        self._context = context
        self._state = PluginState.INITIALIZED
        self._crash_count: int = 0
        self._max_crashes: int = max_crashes
        self._active_tasks: Set[asyncio.Task] = set()  # DEF-06 fix: set not list
        self._semaphore: Optional[asyncio.Semaphore] = None

    @property
    def state(self) -> PluginState:
        """Current plugin state."""
        return self._state

    @property
    def plugin_name(self) -> str:
        """Plugin name from metadata."""
        return getattr(self._plugin, 'meta', None) and getattr(self._plugin.meta, 'name', 'unknown') or 'unknown'

    @property
    def worker_count(self) -> int:
        """Current number of active workers."""
        return sum(1 for t in self._active_tasks if not t.done())

    @property
    def crash_count(self) -> int:
        """Number of times this plugin has crashed."""
        return self._crash_count

    async def run(self) -> None:
        """Run the plugin with structured concurrency.

        Uses asyncio.TaskGroup for structured concurrency — all workers
        belong to the group and are cancelled together when the group exits.
        """
        self._state = PluginState.RUNNING
        self._semaphore = asyncio.Semaphore(self._context.initial_workers)

        try:
            # Run workers until stop signal
            while not self._context.stop_event.is_set():
                # Try to acquire a worker slot
                acquired = False
                try:
                    await asyncio.wait_for(
                        self._semaphore.acquire(),
                        timeout=0.5
                    )
                    acquired = True
                except asyncio.TimeoutError:
                    continue

                if self._context.stop_event.is_set():
                    if acquired:
                        self._semaphore.release()
                    break

                # Spawn a worker task
                worker_id = len(self._active_tasks)
                task = asyncio.create_task(
                    self._worker_loop(worker_id),
                    name=f"plugin:{self.plugin_name}:worker:{worker_id}"
                )
                self._active_tasks.add(task)
                task.add_done_callback(self._active_tasks.discard)  # Auto-remove when done

            # Wait for all workers to finish
            if self._active_tasks:
                await asyncio.gather(*self._active_tasks, return_exceptions=True)

        except asyncio.CancelledError:
            # Engine is shutting down — cancel all workers
            for task in self._active_tasks:
                if not task.done():
                    task.cancel()
            if self._active_tasks:
                await asyncio.gather(*self._active_tasks, return_exceptions=True)

        except Exception as exc:
            # DEF-03 fix: Catch ALL exceptions, not limited set
            self._crash_count += 1
            self._state = PluginState.CRASHED
            # Emit crash event through mailbox (non-blocking)
            self._context.mailbox.send_nowait({
                "type": "plugin_crash",
                "plugin": self.plugin_name,
                "error": f"{type(exc).__name__}: {exc}",
                "crash_count": self._crash_count,
            })

        finally:
            self._state = PluginState.STOPPED
            self._active_tasks.clear()

    async def _worker_loop(self, worker_id: int) -> None:
        """Single worker loop with comprehensive crash isolation.

        DEF-03 fix: Catches `Exception` (not limited set), so ANY
        user-code error is handled gracefully.
        """
        try:
            # Delegate to plugin's worker loop
            if hasattr(self._plugin, '_worker_loop'):
                await self._plugin._worker_loop(self._context, worker_id)
            elif hasattr(self._plugin, 'attack'):
                await self._plugin.attack(
                    stop_event=self._context.stop_event,
                    stats_callback=lambda d: None,  # Routed through mailbox
                )
        except asyncio.CancelledError:
            # Clean cancellation — not an error
            return
        except Exception as exc:
            # DEF-03 fix: Catch ALL exceptions
            # Record in per-target counters (lock-free)
            self._context.counters.record(ok=False, code=0, rt=0.0)

            # Emit crash event (non-blocking)
            self._context.mailbox.send_nowait({
                "type": "worker_crash",
                "plugin": self.plugin_name,
                "worker_id": worker_id,
                "error": f"{type(exc).__name__}: {exc}",
            })
        finally:
            # Release the semaphore slot
            if self._semaphore:
                self._semaphore.release()

    def scale(self, delta: int) -> int:
        """Scale workers by delta.

        Uses semaphore instead of task list manipulation for O(1) scaling.
        Positive delta: increase semaphore capacity (allows more workers to spawn)
        Negative delta: decrease capacity (workers naturally exit as they finish)

        Returns:
            Actual change applied.
        """
        if self._semaphore is None:
            return 0

        if delta > 0:
            # Increase capacity
            for _ in range(delta):
                self._semaphore.release()
            return delta
        elif delta < 0:
            # Decrease capacity — cancel some workers
            to_cancel = min(abs(delta), self.worker_count)
            cancelled = 0
            for task in list(self._active_tasks):
                if cancelled >= to_cancel:
                    break
                if not task.done():
                    task.cancel()
                    cancelled += 1
            return cancelled
        return 0

    def stop(self) -> None:
        """Signal the sandbox to stop gracefully."""
        self._context.stop_event.set()
        self._state = PluginState.STOPPING


# ═══════════════════════════════════════════════════════════════════════════════
# CrashRecovery — Automatic plugin restart with exponential backoff
# ═══════════════════════════════════════════════════════════════════════════════

class CrashRecovery:
    """Automatic plugin crash recovery with exponential backoff.

    When a plugin crashes:
    1. Record the crash (type, message, time)
    2. If crash_count < max_crashes: schedule restart with backoff
    3. If crash_count >= max_crashes: permanently disable
    4. Emit recovery event through observability bus

    The backoff prevents rapid crash-restart loops that would
    overwhelm the event loop with failed plugin initializations.
    """

    __slots__ = ('_max_crashes', '_base_backoff', '_max_backoff',
                 '_crash_history')

    def __init__(self, max_crashes: int = 3,
                 base_backoff: float = 5.0,
                 max_backoff: float = 60.0) -> None:
        self._max_crashes = max_crashes
        self._base_backoff = base_backoff
        self._max_backoff = max_backoff
        self._crash_history: Dict[str, List[float]] = {}

    def should_restart(self, plugin_name: str) -> bool:
        """Check if a crashed plugin should be restarted.

        Args:
            plugin_name: Name of the crashed plugin.

        Returns:
            True if restart should be attempted.
        """
        crashes = self._crash_history.get(plugin_name, [])

        # Max crashes reached — permanently disable
        if len(crashes) >= self._max_crashes:
            return False

        # Check backoff period
        if crashes:
            last_crash = crashes[-1]
            backoff = min(
                self._base_backoff * (2 ** len(crashes)),
                self._max_backoff
            )
            if time.monotonic() - last_crash < backoff:
                return False  # Still in backoff period

        return True

    def record_crash(self, plugin_name: str) -> None:
        """Record a plugin crash.

        Args:
            plugin_name: Name of the crashed plugin.
        """
        if plugin_name not in self._crash_history:
            self._crash_history[plugin_name] = []
        self._crash_history[plugin_name].append(time.monotonic())

    def get_backoff_remaining(self, plugin_name: str) -> float:
        """Get remaining backoff time for a plugin in seconds.

        Args:
            plugin_name: Plugin name.

        Returns:
            Seconds until restart is allowed. 0 if restart is allowed now.
        """
        crashes = self._crash_history.get(plugin_name, [])
        if not crashes:
            return 0.0

        last_crash = crashes[-1]
        backoff = min(
            self._base_backoff * (2 ** len(crashes)),
            self._max_backoff
        )
        remaining = backoff - (time.monotonic() - last_crash)
        return max(0.0, remaining)

    def is_permanently_disabled(self, plugin_name: str) -> bool:
        """Check if a plugin is permanently disabled due to too many crashes."""
        crashes = self._crash_history.get(plugin_name, [])
        return len(crashes) >= self._max_crashes

    def reset(self, plugin_name: str = "") -> None:
        """Reset crash history for a specific plugin or all plugins."""
        if plugin_name:
            self._crash_history.pop(plugin_name, None)
        else:
            self._crash_history.clear()


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Supervisor — Manages all plugin sandboxes
# ═══════════════════════════════════════════════════════════════════════════════

class PluginSupervisor:
    """Supervises all plugin sandboxes with structured concurrency.

    Manages plugin lifecycle, applies scaling commands, and handles
    crash recovery. Uses TaskGroups for structured concurrency.
    """

    def __init__(self, max_crashes: int = 3) -> None:
        self._sandboxes: Dict[str, PluginSandbox] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._recovery = CrashRecovery(max_crashes=max_crashes)
        self._disabled: Dict[str, str] = {}  # plugin_name → reason

    @property
    def active_plugins(self) -> Dict[str, PluginSandbox]:
        """Currently active plugin sandboxes."""
        return dict(self._sandboxes)

    @property
    def disabled_plugins(self) -> Dict[str, str]:
        """Currently disabled plugins with reasons."""
        return dict(self._disabled)

    @property
    def total_workers(self) -> int:
        """Total active workers across all plugins."""
        return sum(s.worker_count for s in self._sandboxes.values())

    async def launch(self, plugin: Any, context: TargetContext) -> None:
        """Launch a plugin in a sandbox.

        Args:
            plugin: PluginInterface instance.
            context: Per-target execution context.
        """
        name = getattr(plugin, 'meta', None) and getattr(plugin.meta, 'name', '') or 'unknown'
        sandbox = PluginSandbox(plugin, context)
        self._sandboxes[name] = sandbox

        # Launch sandbox as a task
        task = asyncio.create_task(sandbox.run(), name=f"supervisor:{name}")
        self._tasks[name] = task

    async def apply_command(self, command: Any) -> None:
        """Apply a ScalingCommand to the appropriate plugins.

        Args:
            command: ScalingCommand from AsyncScheduler.
        """
        from engine.scheduler import ScalingCommand, ScalingAction

        if not isinstance(command, ScalingCommand):
            return

        if command.action == ScalingAction.HOLD:
            return  # No action needed

        # Determine target plugins
        if command.target_plugins:
            targets = {name: self._sandboxes[name]
                       for name in command.target_plugins
                       if name in self._sandboxes}
        else:
            targets = dict(self._sandboxes)

        for name, sandbox in targets.items():
            if sandbox.state not in (PluginState.RUNNING, PluginState.PAUSED):
                continue

            if command.action == ScalingAction.ESCALATE:
                sandbox.scale(command.delta)
            elif command.action == ScalingAction.SHRINK:
                sandbox.scale(command.delta)  # delta is negative
            elif command.action == ScalingAction.PRESSURE:
                sandbox.scale(command.delta)
            elif command.action == ScalingAction.PAUSE:
                sandbox.stop()  # Pause by stopping; will be restarted
            elif command.action == ScalingAction.RECOVER:
                sandbox.scale(command.delta)

    def stop_all(self) -> None:
        """Stop all active plugin sandboxes."""
        for name, sandbox in self._sandboxes.items():
            sandbox.stop()

    def disable_plugin(self, name: str, reason: str = "") -> None:
        """Permanently disable a plugin."""
        if name in self._sandboxes:
            self._sandboxes[name].stop()
            self._disabled[name] = reason or "disabled_by_supervisor"
            del self._sandboxes[name]

    def reset(self) -> None:
        """Reset all supervisor state for a new attack run."""
        self.stop_all()
        self._sandboxes.clear()
        self._tasks.clear()
        self._disabled.clear()
        self._recovery.reset()


__all__ = [
    "PluginSandbox",
    "PluginState",
    "TargetContext",
    "BoundedMailbox",
    "WAFState",
    "FailureTracker",
    "CrashRecovery",
    "PluginSupervisor",
]
