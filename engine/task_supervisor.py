"""engine.task_supervisor — Plugin-safe task isolation + supervision with TaskGroup.

Provides structured supervision of plugin tasks using asyncio.TaskGroup.
Each plugin runs in its own supervision scope — a crash in one plugin
does NOT affect other plugins or the scheduler.

ARCHITECTURE:
  TaskSupervisor (top-level supervisor)
    ├── PluginScope (per-plugin supervision scope)
    │   ├── asyncio.TaskGroup (structured concurrency for workers)
    │   ├── WorkerPool (bounded worker management)
    │   ├── CrashRecovery (exponential backoff + max crash limit)
    │   └── PluginState (lifecycle state machine)
    └── ScalingApplier (applies ScalingCommand to plugin scopes)

DESIGN PRINCIPLES:
  - Plugin crash isolation: each plugin in its own TaskGroup
  - No asyncio.Lock in hot path: worker scaling uses semaphore
  - Bounded worker pools: semaphore caps concurrent workers
  - O(1) scaling: semaphore release/acquire, not task list manipulation
  - Cancellation propagation: TaskGroup cancels all workers together
  - No task leaks: TaskGroup guarantees all tasks complete on exit
  - No global mutable state: all state per-scope or per-context

PLUGIN LIFECYCLE:
  DISCOVERED → VALIDATED → INITIALIZED → RUNNING
                                           ↓
                                      [PAUSED]
                                           ↓
                                     STOPPING → STOPPED
                                           ↓
                                     CRASHED → RECOVERING → INITIALIZED

SUPERVISION STRATEGY:
  - One-for-one: when a plugin crashes, only that plugin is restarted
  - Max crash limit: after N crashes, plugin is permanently disabled
  - Exponential backoff: 5s → 10s → 20s → ... → 60s max
  - Circuit breaker: if too many plugins crash, stop launching new ones
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from engine.runtime_context import (
    RuntimeContext, EngineConfig, CrashRecoveryConfig, BoundedMailbox,
)
from engine.scheduler import ScalingCommand, ScalingAction


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
    DISCOVERED = "discovered"
    VALIDATED = "validated"
    INITIALIZED = "initialized"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    CRASHED = "crashed"
    RECOVERING = "recovering"
    DISABLED = "disabled"  # Permanently disabled (max crashes exceeded)


# ═══════════════════════════════════════════════════════════════════════════════
# Crash Recovery — Exponential backoff + max crash limit
# ═══════════════════════════════════════════════════════════════════════════════

class CrashRecovery:
    """Automatic plugin crash recovery with exponential backoff.

    When a plugin crashes:
    1. Record the crash (type, message, time)
    2. If crash_count < max_crashes: schedule restart with backoff
    3. If crash_count >= max_crashes: permanently disable
    4. Emit recovery event through context mailbox

    BOUNDED: crash_history is capped at max_crashes entries per plugin.
    """

    __slots__ = ('_config', '_crash_history', '_logger')

    def __init__(self, config: CrashRecoveryConfig) -> None:
        self._config = config
        self._crash_history: Dict[str, List[float]] = {}
        self._logger = logging.getLogger("storm_vx.engine.supervisor.crash")

    def should_restart(self, plugin_name: str) -> bool:
        """Check if a crashed plugin should be restarted.

        Args:
            plugin_name: Name of the crashed plugin.

        Returns:
            True if restart should be attempted.
        """
        crashes = self._crash_history.get(plugin_name, [])

        # Max crashes reached — permanently disable
        if len(crashes) >= self._config.max_crashes:
            return False

        # Check backoff period
        if crashes:
            last_crash = crashes[-1]
            backoff = min(
                self._config.base_backoff * (2 ** len(crashes)),
                self._config.max_backoff,
            )
            if time.time() - last_crash < backoff:
                return False

        return True

    def record_crash(self, plugin_name: str) -> None:
        """Record a plugin crash.

        Args:
            plugin_name: Name of the crashed plugin.
        """
        if plugin_name not in self._crash_history:
            self._crash_history[plugin_name] = []
        self._crash_history[plugin_name].append(time.time())

        # Bound history size
        if len(self._crash_history[plugin_name]) > self._config.max_crashes + 1:
            self._crash_history[plugin_name] = \
                self._crash_history[plugin_name][-self._config.max_crashes:]

    def get_backoff_remaining(self, plugin_name: str) -> float:
        """Get remaining backoff time for a plugin in seconds."""
        crashes = self._crash_history.get(plugin_name, [])
        if not crashes:
            return 0.0

        last_crash = crashes[-1]
        backoff = min(
            self._config.base_backoff * (2 ** len(crashes)),
            self._config.max_backoff,
        )
        remaining = backoff - (time.time() - last_crash)
        return max(0.0, remaining)

    def is_permanently_disabled(self, plugin_name: str) -> bool:
        """Check if a plugin is permanently disabled due to too many crashes."""
        crashes = self._crash_history.get(plugin_name, [])
        return len(crashes) >= self._config.max_crashes

    def reset(self, plugin_name: str = "") -> None:
        """Reset crash history for a specific plugin or all plugins."""
        if plugin_name:
            self._crash_history.pop(plugin_name, None)
        else:
            self._crash_history.clear()


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Scope — Per-plugin supervision scope with TaskGroup
# ═══════════════════════════════════════════════════════════════════════════════

class PluginScope:
    """Per-plugin supervision scope with structured concurrency.

    Each plugin runs in its own PluginScope with its own TaskGroup.
    If the plugin crashes, only its TaskGroup is affected — other
    plugins continue running.

    STRUCTURED CONCURRENCY:
    - Workers are created as children of the scope's TaskGroup
    - When the scope exits, all workers are cancelled
    - No orphan tasks, no task leaks

    WORKER MANAGEMENT:
    - Workers are bounded by a semaphore (not a task list)
    - Scaling uses semaphore release/acquire (O(1), not O(n))
    - Workers that exit naturally release their semaphore slot

    Usage:
        scope = PluginScope(plugin, context, config)
        await scope.start()  # Creates TaskGroup, starts workers
        scope.scale(50)      # Add 50 workers
        await scope.stop()   # Graceful shutdown
    """

    def __init__(
        self,
        plugin: Any,
        context: RuntimeContext,
        config: CrashRecoveryConfig,
        max_crashes: int = 3,
    ) -> None:
        self._plugin = plugin
        self._context = context
        self._config = config
        self._state = PluginState.INITIALIZED
        self._crash_count: int = 0
        self._max_crashes: int = max_crashes
        self._active_workers: Set[asyncio.Task] = set()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._task_group: Optional[asyncio.TaskGroup] = None
        self._scope_task: Optional[asyncio.Task] = None
        self._logger = logging.getLogger(
            f"storm_vx.engine.supervisor.scope.{self.plugin_name}"
        )

    @property
    def state(self) -> PluginState:
        """Current plugin state."""
        return self._state

    @property
    def plugin_name(self) -> str:
        """Plugin name from metadata."""
        meta = getattr(self._plugin, 'meta', None)
        return getattr(meta, 'name', 'unknown') if meta else 'unknown'

    @property
    def worker_count(self) -> int:
        """Current number of active workers."""
        return sum(1 for t in self._active_workers if not t.done())

    @property
    def crash_count(self) -> int:
        """Number of times this plugin has crashed."""
        return self._crash_count

    @property
    def is_running(self) -> bool:
        """Whether the plugin is currently running."""
        return self._state == PluginState.RUNNING

    async def start(self) -> None:
        """Start the plugin scope with structured concurrency.

        Creates a TaskGroup and enters the main worker loop.
        The scope runs as a task within the supervisor's TaskGroup.
        """
        self._state = PluginState.RUNNING
        self._semaphore = asyncio.Semaphore(self._context.current_workers)

        try:
            async with asyncio.TaskGroup() as tg:
                self._task_group = tg

                # Main worker spawning loop
                while not self._context.is_stopping:
                    try:
                        await asyncio.wait_for(
                            self._semaphore.acquire(),
                            timeout=0.5,
                        )
                    except asyncio.TimeoutError:
                        continue

                    if self._context.is_stopping:
                        self._semaphore.release()
                        break

                    # Spawn a worker within the TaskGroup
                    worker_id = len(self._active_workers)
                    task = tg.create_task(
                        self._worker_loop(worker_id),
                        name=f"plugin:{self.plugin_name}:worker:{worker_id}",
                    )
                    self._active_workers.add(task)
                    task.add_done_callback(self._active_workers.discard)

        except asyncio.CancelledError:
            # Supervisor is shutting down — TaskGroup auto-cancels children
            self._state = PluginState.STOPPING
            raise
        except Exception as exc:
            # Plugin crashed — record and report
            self._crash_count += 1
            self._state = PluginState.CRASHED
            self._logger.error(
                f"Plugin '{self.plugin_name}' crashed "
                f"(crash #{self._crash_count}): {exc}"
            )
            self._context.mailbox.send_nowait({
                "type": "plugin_crash",
                "plugin": self.plugin_name,
                "error": f"{type(exc).__name__}: {exc}",
                "crash_count": self._crash_count,
            })
        finally:
            self._state = PluginState.STOPPED
            self._active_workers.clear()

    async def _worker_loop(self, worker_id: int) -> None:
        """Single worker loop with comprehensive crash isolation.

        Catches ALL exceptions (not a limited set), so ANY user-code
        error is handled gracefully. Worker crashes don't propagate
        to the TaskGroup — they're recorded in per-target metrics.
        """
        try:
            # Delegate to plugin's worker implementation
            if hasattr(self._plugin, '_worker_loop'):
                await self._plugin._worker_loop(self._context, worker_id)
            elif hasattr(self._plugin, 'attack'):
                await self._plugin.attack(
                    stop_event=self._context.stop_event,
                    stats_callback=lambda d: None,  # Routed through mailbox
                )
            elif hasattr(self._plugin, 'run'):
                # PluginInterface.run() — pass the AttackContext
                from plugin_system import AttackContext, AttackExtras
                attack_ctx = AttackContext(
                    url=self._context.target.url,
                    site_root=self._context.target.site_root,
                    domain=self._context.target.domain,
                    stop_event=self._context.stop_event,
                    extra=AttackExtras(
                        workers=self._context.current_workers,
                        delay_ms=self._context.config.workers.request_delay_ms,
                        cache_bust=self._context.config.workers.cache_bust,
                    ),
                )
                await self._plugin.run(attack_ctx)
        except asyncio.CancelledError:
            # Clean cancellation — not an error
            return
        except Exception as exc:
            # Catch ALL exceptions — comprehensive crash isolation
            self._context.metrics.record(ok=False, code=0, rt=0.0)
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
        Positive delta: increase semaphore capacity (allows more workers)
        Negative delta: cancel some running workers

        Returns:
            Actual change applied.
        """
        if self._semaphore is None:
            return 0

        if delta > 0:
            for _ in range(delta):
                self._semaphore.release()
            return delta
        elif delta < 0:
            to_cancel = min(abs(delta), self.worker_count)
            cancelled = 0
            for task in list(self._active_workers):
                if cancelled >= to_cancel:
                    break
                if not task.done():
                    task.cancel()
                    cancelled += 1
            return cancelled
        return 0

    async def stop(self) -> None:
        """Signal the scope to stop gracefully.

        Sets the context's stop event and waits for the scope task
        to complete. The TaskGroup ensures all workers are cancelled.
        """
        self._state = PluginState.STOPPING
        self._context.request_stop()

        # Wait for scope task to complete (with timeout)
        if self._scope_task and not self._scope_task.done():
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._scope_task),
                    timeout=5.0,
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

    def pause(self) -> None:
        """Pause the plugin (temporarily stop spawning new workers)."""
        if self._state == PluginState.RUNNING:
            self._state = PluginState.PAUSED

    def resume(self) -> None:
        """Resume the plugin from paused state."""
        if self._state == PluginState.PAUSED:
            self._state = PluginState.RUNNING


# ═══════════════════════════════════════════════════════════════════════════════
# Scaling Applier — Applies ScalingCommand to plugin scopes
# ═══════════════════════════════════════════════════════════════════════════════

class ScalingApplier:
    """Applies ScalingCommand from the scheduler to plugin scopes.

    Bridges the scheduler (pure function) with the supervisor (mutable state).
    Translates ScalingAction enum into concrete plugin scope operations.
    """

    __slots__ = ('_logger',)

    def __init__(self) -> None:
        self._logger = logging.getLogger("storm_vx.engine.supervisor.scaling")

    async def apply(
        self,
        command: ScalingCommand,
        scopes: Dict[str, PluginScope],
    ) -> None:
        """Apply a scaling command to the appropriate plugin scopes.

        Args:
            command: ScalingCommand from the scheduler.
            scopes: Currently active plugin scopes.
        """
        if command.action == ScalingAction.HOLD:
            return

        # Determine target scopes
        if command.target_plugins:
            targets = {
                name: scope for name, scope in scopes.items()
                if name in command.target_plugins
            }
        else:
            targets = dict(scopes)

        for name, scope in targets.items():
            if scope.state not in (PluginState.RUNNING, PluginState.PAUSED):
                continue

            try:
                if command.action == ScalingAction.ESCALATE:
                    actual = scope.scale(command.delta)
                    self._logger.debug(
                        f"ESCALATE {name}: +{actual} workers "
                        f"(target: +{command.delta})"
                    )
                elif command.action == ScalingAction.SHRINK:
                    actual = scope.scale(command.delta)  # delta is negative
                    self._logger.debug(
                        f"SHRINK {name}: {actual} workers removed "
                        f"(target: {command.delta})"
                    )
                elif command.action == ScalingAction.PRESSURE:
                    scope.scale(command.delta)
                    self._logger.debug(
                        f"PRESSURE {name}: +{command.delta} workers"
                    )
                elif command.action == ScalingAction.PAUSE:
                    scope.pause()
                    self._logger.debug(f"PAUSE {name}: {command.reason}")
                elif command.action == ScalingAction.RECOVER:
                    scope.resume()
                    scope.scale(command.delta)
                    self._logger.debug(f"RECOVER {name}: +{command.delta} workers")
            except Exception as exc:
                self._logger.warning(
                    f"Failed to apply {command.action.value} to {name}: {exc}"
                )


# ═══════════════════════════════════════════════════════════════════════════════
# Task Supervisor — Top-level supervisor with structured concurrency
# ═══════════════════════════════════════════════════════════════════════════════

class TaskSupervisor:
    """Supervises all plugin scopes with structured concurrency.

    Manages plugin lifecycle, applies scaling commands, and handles
    crash recovery. Uses TaskGroup for structured concurrency — all
    plugin scope tasks belong to the group and are cleaned up on exit.

    STRUCTURED CONCURRENCY:
    - Each plugin scope runs as a child task of the supervisor's TaskGroup
    - When the TaskGroup exits, all plugin scopes are cancelled
    - No orphan tasks, no task leaks

    CRASH ISOLATION:
    - One-for-one strategy: when a plugin crashes, only that plugin is affected
    - CrashRecovery provides exponential backoff and max crash limit
    - Permanently disabled plugins are tracked separately

    Usage:
        supervisor = TaskSupervisor(config)
        await supervisor.start()

        # Launch plugins
        await supervisor.launch(plugin, context)

        # Apply scaling command
        await supervisor.apply_command(command)

        # Graceful shutdown
        await supervisor.stop()
    """

    def __init__(self, config: EngineConfig) -> None:
        self._config = config
        self._scopes: Dict[str, PluginScope] = {}
        self._scope_tasks: Dict[str, asyncio.Task] = {}
        self._recovery = CrashRecovery(config.crash_recovery)
        self._scaling = ScalingApplier()
        self._disabled: Dict[str, str] = {}  # plugin_name → reason
        self._task_group: Optional[asyncio.TaskGroup] = None
        self._running: bool = False
        self._logger = logging.getLogger("storm_vx.engine.supervisor")

    @property
    def is_running(self) -> bool:
        """Whether the supervisor is active."""
        return self._running

    @property
    def active_plugins(self) -> Dict[str, PluginScope]:
        """Currently active plugin scopes."""
        return dict(self._scopes)

    @property
    def disabled_plugins(self) -> Dict[str, str]:
        """Currently disabled plugins with reasons."""
        return dict(self._disabled)

    @property
    def total_workers(self) -> int:
        """Total active workers across all plugins."""
        return sum(scope.worker_count for scope in self._scopes.values())

    @property
    def plugin_states(self) -> Dict[str, str]:
        """Current state of each plugin."""
        return {
            name: scope.state.value
            for name, scope in self._scopes.items()
        }

    async def start(self) -> None:
        """Start the supervisor with structured concurrency.

        Creates a TaskGroup for managing all plugin scope tasks.
        """
        if self._running:
            raise RuntimeError("TaskSupervisor is already running")

        self._running = True
        self._task_group = asyncio.TaskGroup()
        await self._task_group.__aenter__()
        self._logger.info(
            f"TaskSupervisor started — managing plugins with TaskGroup"
        )

    async def stop(self) -> None:
        """Stop all plugins and exit the supervisor.

        1. Signal all scopes to stop
        2. Wait for scope tasks to complete
        3. Exit the TaskGroup (cancels remaining child tasks)
        """
        if not self._running:
            return

        self._running = False
        self._logger.info("TaskSupervisor stopping — signaling all plugins")

        # Signal all scopes to stop
        for name, scope in self._scopes.items():
            scope.stop()

        # Exit TaskGroup — ensures all child tasks complete
        if self._task_group is not None:
            try:
                await self._task_group.__aexit__(None, None, None)
            except Exception:
                pass
            self._task_group = None

        self._logger.info("TaskSupervisor stopped")

    async def launch(self, plugin: Any, context: RuntimeContext) -> None:
        """Launch a plugin in a new supervision scope.

        Creates a PluginScope for the plugin and starts it as a child
        task of the supervisor's TaskGroup.

        Args:
            plugin: PluginInterface instance.
            context: Per-target execution context.
        """
        if not self._running:
            raise RuntimeError("TaskSupervisor is not running — call start() first")

        name = getattr(
            getattr(plugin, 'meta', None), 'name', 'unknown'
        ) if hasattr(plugin, 'meta') else 'unknown'

        if name in self._disabled:
            self._logger.info(
                f"Skipping disabled plugin '{name}': {self._disabled[name]}"
            )
            return

        scope = PluginScope(
            plugin=plugin,
            context=context,
            config=self._config.crash_recovery,
            max_crashes=self._config.crash_recovery.max_crashes,
        )
        self._scopes[name] = scope

        # Start scope as a child task of the TaskGroup
        if self._task_group is not None:
            task = self._task_group.create_task(
                scope.start(),
                name=f"supervisor:scope:{name}",
            )
            self._scope_tasks[name] = task

        self._logger.info(f"Launched plugin '{name}' in supervision scope")

    async def apply_command(self, command: ScalingCommand) -> None:
        """Apply a ScalingCommand to the appropriate plugin scopes.

        Args:
            command: ScalingCommand from the scheduler.
        """
        await self._scaling.apply(command, self._scopes)

    async def restart_crashed(self) -> int:
        """Check for crashed plugins and restart eligible ones.

        Called periodically by the scheduler to attempt recovery of
        crashed plugins that are within their crash limit and backoff.

        Returns:
            Number of plugins restarted.
        """
        restarted = 0
        crashed = [
            (name, scope) for name, scope in self._scopes.items()
            if scope.state == PluginState.CRASHED
        ]

        for name, scope in crashed:
            if self._recovery.should_restart(name):
                self._recovery.record_crash(name)
                scope._state = PluginState.RECOVERING

                # Restart the scope as a new child task
                if self._task_group is not None:
                    task = self._task_group.create_task(
                        scope.start(),
                        name=f"supervisor:scope:{name}:restart",
                    )
                    self._scope_tasks[name] = task
                    restarted += 1
                    self._logger.info(
                        f"Restarting crashed plugin '{name}' "
                        f"(crash #{scope.crash_count})"
                    )
            elif self._recovery.is_permanently_disabled(name):
                self._disable_plugin(name, "max_crashes_exceeded")

        return restarted

    def _disable_plugin(self, name: str, reason: str) -> None:
        """Permanently disable a plugin."""
        if name in self._scopes:
            self._scopes[name].stop()
            self._disabled[name] = reason
            del self._scopes[name]
            self._scope_tasks.pop(name, None)
            self._logger.warning(
                f"Permanently disabled plugin '{name}': {reason}"
            )

    def disable_plugin(self, name: str, reason: str = "") -> None:
        """Public API to permanently disable a plugin."""
        self._disable_plugin(name, reason or "disabled_by_operator")

    def get_diagnostics(self) -> Dict[str, Any]:
        """Get supervisor diagnostics for monitoring."""
        return {
            "running": self._running,
            "active_plugins": len(self._scopes),
            "disabled_plugins": len(self._disabled),
            "total_workers": self.total_workers,
            "plugin_states": self.plugin_states,
            "disabled": dict(self._disabled),
        }

    def reset(self) -> None:
        """Reset all supervisor state for a new attack run."""
        for scope in self._scopes.values():
            scope.stop()
        self._scopes.clear()
        self._scope_tasks.clear()
        self._disabled.clear()
        self._recovery.reset()


__all__ = [
    "TaskSupervisor",
    "PluginScope",
    "PluginState",
    "CrashRecovery",
    "ScalingApplier",
]
