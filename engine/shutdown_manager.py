"""engine.shutdown_manager — Graceful shutdown with cancellation propagation.

Manages the orderly shutdown of the STORM VX runtime, ensuring:
  - All in-flight requests complete or are cancelled within timeout
  - Cancellation propagates from parent tasks to child tasks
  - Resources (sessions, connectors, file handles) are released
  - Final metrics snapshots are captured before exit
  - No task leaks — every task is accounted for

ARCHITECTURE:
  ShutdownManager (orchestrator)
    ├── ShutdownPhase enum (ORDERED → DRAINING → CANCELLING → FINALIZING)
    ├── CancellationPropagator (ensures parent cancellation reaches children)
    ├── ResourceDrainer (drains bounded queues before closing)
    └── CleanupRegistry (tracked cleanup callbacks)

SHUTDOWN PHASES:
  1. ORDERED    — Signal all targets to stop, wait for natural completion
  2. DRAINING   — Drain bounded queues (observability bus, mailboxes)
  3. CANCELLING — Cancel remaining tasks with timeout
  4. FINALIZING — Close resources, capture final metrics, log summary

DESIGN PRINCIPLES:
  - No blocking I/O during shutdown
  - Cancellation is deterministic: every task is cancelled or completes
  - Timeouts prevent shutdown from hanging indefinitely
  - Final state is observable (metrics snapshots, task counts)
  - Cleanup callbacks are idempotent (safe to call multiple times)
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from engine.runtime_context import RuntimeContext, ShutdownConfig


# ═══════════════════════════════════════════════════════════════════════════════
# Shutdown Phases
# ═══════════════════════════════════════════════════════════════════════════════

class ShutdownPhase(Enum):
    """Ordered shutdown phases.

    Transitions are one-way: ORDERED → DRAINING → CANCELLING → FINALIZING.
    Each phase has a configurable timeout. If the timeout expires, the
    manager advances to the next phase automatically.
    """
    RUNNING = "running"         # Normal operation
    ORDERED = "ordered"         # Signal stop, wait for natural completion
    DRAINING = "draining"       # Drain bounded queues
    CANCELLING = "cancelling"   # Cancel remaining tasks
    FINALIZING = "finalizing"   # Close resources, capture final state
    COMPLETE = "complete"       # Shutdown finished


@dataclass
class ShutdownReport:
    """Summary of the shutdown process.

    Captured at the end of shutdown for logging and diagnostics.
    """
    phase_reached: ShutdownPhase = ShutdownPhase.RUNNING
    total_duration: float = 0.0
    ordered_duration: float = 0.0
    draining_duration: float = 0.0
    cancelling_duration: float = 0.0
    finalizing_duration: float = 0.0
    tasks_completed: int = 0
    tasks_cancelled: int = 0
    tasks_timed_out: int = 0
    resources_cleaned: int = 0
    final_metrics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# Cleanup Registry — Tracked cleanup callbacks
# ═══════════════════════════════════════════════════════════════════════════════

class CleanupRegistry:
    """Registry of cleanup callbacks to call during shutdown.

    Callbacks are called in REVERSE registration order (LIFO — like __del__).
    Each callback receives no arguments and returns Awaitable[None].
    Callbacks are idempotent: safe to call multiple times.

    BOUNDED: Max 128 callbacks to prevent unbounded registration.
    """

    __slots__ = ('_callbacks', '_max_callbacks', '_called')

    def __init__(self, max_callbacks: int = 128) -> None:
        self._callbacks: List[Callable[[], Awaitable[None]]] = []
        self._max_callbacks = max_callbacks
        self._called: Set[int] = set()  # Track which callbacks have been called

    def register(self, callback: Callable[[], Awaitable[None]], name: str = "") -> None:
        """Register a cleanup callback.

        Args:
            callback: Async callable to invoke during cleanup.
            name: Optional name for logging.
        """
        if len(self._callbacks) >= self._max_callbacks:
            raise RuntimeError(
                f"CleanupRegistry full ({self._max_callbacks}). "
                f"Cannot register callback '{name}'."
            )
        self._callbacks.append(callback)

    async def run_all(self, timeout: float = 10.0) -> int:
        """Run all registered cleanup callbacks in reverse order.

        Args:
            timeout: Maximum total time for all callbacks.

        Returns:
            Number of callbacks successfully executed.
        """
        cleaned = 0
        for callback in reversed(self._callbacks):
            cb_id = id(callback)
            if cb_id in self._called:
                continue  # Idempotent: skip already-called callbacks

            try:
                await asyncio.wait_for(callback(), timeout=timeout / max(len(self._callbacks), 1))
                self._called.add(cb_id)
                cleaned += 1
            except asyncio.TimeoutError:
                pass  # Don't let one slow callback block shutdown
            except Exception:
                pass  # Don't let one failing callback block shutdown

        return cleaned

    @property
    def count(self) -> int:
        """Number of registered callbacks."""
        return len(self._callbacks)

    @property
    def called_count(self) -> int:
        """Number of callbacks that have been called."""
        return len(self._called)


# ═══════════════════════════════════════════════════════════════════════════════
# Cancellation Propagator — Ensures parent cancellation reaches children
# ═══════════════════════════════════════════════════════════════════════════════

class CancellationPropagator:
    """Propagates cancellation from parent tasks to child tasks.

    When the shutdown manager decides to cancel tasks, this component
    ensures cancellation is applied deterministically:
    1. Cancel all tracked tasks
    2. Wait for tasks to respond to cancellation
    3. Report which tasks didn't respond within timeout

    NO TASK LEAKS: Every tracked task is either completed, cancelled,
    or reported as timed out.
    """

    __slots__ = ('_tracked_tasks', '_logger')

    def __init__(self) -> None:
        self._tracked_tasks: Set[asyncio.Task] = set()
        self._logger = logging.getLogger("storm_vx.engine.shutdown.cancellation")

    def track(self, task: asyncio.Task) -> None:
        """Track a task for cancellation propagation."""
        self._tracked_tasks.add(task)
        task.add_done_callback(self._tracked_tasks.discard)

    def untrack(self, task: asyncio.Task) -> None:
        """Stop tracking a task."""
        self._tracked_tasks.discard(task)

    @property
    def active_count(self) -> int:
        """Number of active tracked tasks."""
        return sum(1 for t in self._tracked_tasks if not t.done())

    async def cancel_all(self, timeout: float = 5.0) -> tuple[int, int]:
        """Cancel all tracked tasks and wait for completion.

        Args:
            timeout: Maximum time to wait for each task to respond.

        Returns:
            Tuple of (completed_count, timed_out_count).
        """
        active = [t for t in self._tracked_tasks if not t.done()]
        if not active:
            return 0, 0

        # Cancel all active tasks
        for task in active:
            task.cancel()

        # Wait for all to complete (with timeout)
        completed = 0
        timed_out = 0

        results = await asyncio.gather(
            *[self._wait_for_task(t, timeout) for t in active],
            return_exceptions=True,
        )

        for result in results:
            if result is True:
                completed += 1
            else:
                timed_out += 1

        return completed, timed_out

    async def _wait_for_task(self, task: asyncio.Task, timeout: float) -> bool:
        """Wait for a task to complete after cancellation.

        Returns:
            True if task completed, False if timed out.
        """
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
            return True
        except (asyncio.TimeoutError, asyncio.CancelledError):
            return False
        except Exception:
            return True  # Task completed with exception — still completed

    @property
    def tracked_tasks(self) -> Set[asyncio.Task]:
        """Set of currently tracked tasks (for diagnostics)."""
        return {t for t in self._tracked_tasks if not t.done()}


# ═══════════════════════════════════════════════════════════════════════════════
# Resource Drainer — Drains bounded queues before closing
# ═══════════════════════════════════════════════════════════════════════════════

class ResourceDrainer:
    """Drains bounded queues (observability bus, mailboxes) before closing.

    Ensures no events are lost during shutdown. Drains each queue in
    batch mode, then marks it as closed.

    BOUNDED: Draining has a maximum time limit to prevent hanging.
    """

    __slots__ = ('_drain_targets', '_logger')

    def __init__(self) -> None:
        self._drain_targets: Dict[str, Callable[[], Awaitable[List[Any]]]] = {}
        self._logger = logging.getLogger("storm_vx.engine.shutdown.drainer")

    def register(
        self,
        name: str,
        drain_fn: Callable[[], Awaitable[List[Any]]],
    ) -> None:
        """Register a drainable resource.

        Args:
            name: Resource name (for logging).
            drain_fn: Async callable that returns a list of drained items.
        """
        self._drain_targets[name] = drain_fn

    async def drain_all(self, timeout: float = 10.0) -> Dict[str, int]:
        """Drain all registered resources.

        Args:
            timeout: Maximum total time for draining.

        Returns:
            Dict of resource_name → items_drained.
        """
        results: Dict[str, int] = {}
        per_target_timeout = timeout / max(len(self._drain_targets), 1)

        for name, drain_fn in self._drain_targets.items():
            try:
                items = await asyncio.wait_for(drain_fn(), timeout=per_target_timeout)
                results[name] = len(items)
            except asyncio.TimeoutError:
                self._logger.warning(f"Drain timeout for '{name}'")
                results[name] = -1  # Timeout indicator
            except Exception as exc:
                self._logger.debug(f"Drain error for '{name}': {exc}")
                results[name] = -2  # Error indicator

        return results

    @property
    def count(self) -> int:
        """Number of registered drain targets."""
        return len(self._drain_targets)


# ═══════════════════════════════════════════════════════════════════════════════
# Shutdown Manager — Orchestrates the graceful shutdown process
# ═══════════════════════════════════════════════════════════════════════════════

class ShutdownManager:
    """Orchestrates the graceful shutdown of the STORM VX runtime.

    USAGE:
        manager = ShutdownManager(config, contexts)
        manager.register_cleanup(session.close, name="aiohttp_session")
        manager.register_drain("observability_bus", bus.drain)

        # Start shutdown
        report = await manager.shutdown()

    PHASE TRANSITIONS:
        RUNNING → ORDERED → DRAINING → CANCELLING → FINALIZING → COMPLETE

    Each phase has a configurable timeout. If the timeout expires,
    the manager advances to the next phase automatically.
    """

    def __init__(
        self,
        config: ShutdownConfig,
        contexts: Dict[str, RuntimeContext],
    ) -> None:
        self._config = config
        self._contexts = contexts
        self._phase = ShutdownPhase.RUNNING
        self._logger = logging.getLogger("storm_vx.engine.shutdown")

        # Sub-components
        self._cleanup = CleanupRegistry()
        self._cancellation = CancellationPropagator()
        self._drainer = ResourceDrainer()

        # Report
        self._report = ShutdownReport()
        self._shutdown_start: float = 0.0

    @property
    def phase(self) -> ShutdownPhase:
        """Current shutdown phase."""
        return self._phase

    @property
    def is_shutting_down(self) -> bool:
        """Whether shutdown has been initiated."""
        return self._phase != ShutdownPhase.RUNNING

    @property
    def report(self) -> ShutdownReport:
        """Shutdown report (populated after shutdown completes)."""
        return self._report

    @property
    def cancellation(self) -> CancellationPropagator:
        """Cancellation propagator (for task tracking)."""
        return self._cancellation

    # ── Registration ──

    def register_cleanup(
        self,
        callback: Callable[[], Awaitable[None]],
        name: str = "",
    ) -> None:
        """Register a cleanup callback (called during FINALIZING phase).

        Args:
            callback: Async callable to invoke during cleanup.
            name: Optional name for logging.
        """
        self._cleanup.register(callback, name)

    def register_drain(
        self,
        name: str,
        drain_fn: Callable[[], Awaitable[List[Any]]],
    ) -> None:
        """Register a drainable resource (called during DRAINING phase).

        Args:
            name: Resource name.
            drain_fn: Async callable that returns drained items.
        """
        self._drainer.register(name, drain_fn)

    # ── Shutdown Sequence ──

    async def shutdown(self) -> ShutdownReport:
        """Execute the full shutdown sequence.

        Returns:
            ShutdownReport with timing, task counts, and final metrics.
        """
        self._shutdown_start = time.monotonic()

        try:
            await self._phase_ordered()
            await self._phase_draining()
            await self._phase_cancelling()
            await self._phase_finalizing()
            self._phase = ShutdownPhase.COMPLETE
        except Exception as exc:
            self._report.errors.append(f"Shutdown error: {exc}")
            self._phase = ShutdownPhase.COMPLETE

        self._report.phase_reached = self._phase
        self._report.total_duration = time.monotonic() - self._shutdown_start
        return self._report

    async def _phase_ordered(self) -> None:
        """Phase 1: Signal all targets to stop, wait for natural completion.

        TIMEOUT: config.timeout_seconds (default: 30s)
        """
        self._phase = ShutdownPhase.ORDERED
        phase_start = time.monotonic()
        self._logger.info("Shutdown: ORDERED phase — signaling all targets to stop")

        # Signal all targets to stop
        for target_id, ctx in self._contexts.items():
            ctx.request_stop()

        # Wait for tasks to complete naturally
        try:
            await asyncio.wait_for(
                self._wait_for_contexts(),
                timeout=self._config.timeout_seconds,
            )
        except asyncio.TimeoutError:
            self._logger.warning(
                f"Shutdown: ORDERED phase timed out after {self._config.timeout_seconds}s"
            )

        self._report.ordered_duration = time.monotonic() - phase_start

    async def _wait_for_contexts(self) -> None:
        """Wait for all context stop events to be processed."""
        # Give contexts time to complete their current work
        pending = []
        for ctx in self._contexts.values():
            if not ctx.is_stopping:
                pending.append(ctx)

        # Poll with exponential backoff
        max_wait = 5.0
        waited = 0.0
        interval = 0.1
        while pending and waited < max_wait:
            await asyncio.sleep(interval)
            waited += interval
            interval = min(interval * 1.5, 1.0)
            pending = [ctx for ctx in pending if not ctx.is_stopping]

    async def _phase_draining(self) -> None:
        """Phase 2: Drain bounded queues.

        TIMEOUT: config.drain_timeout_seconds (default: 10s)
        """
        self._phase = ShutdownPhase.DRAINING
        phase_start = time.monotonic()
        self._logger.info("Shutdown: DRAINING phase — flushing queues")

        # Register per-target mailbox drains
        for target_id, ctx in self._contexts.items():
            self._drainer.register(
                f"mailbox:{target_id}",
                ctx.mailbox.drain,
            )

        # Drain all registered resources
        drain_results = await self._drainer.drain_all(
            timeout=self._config.drain_timeout_seconds,
        )

        self._report.draining_duration = time.monotonic() - phase_start
        self._logger.info(
            f"Shutdown: DRAINING complete — {drain_results}"
        )

    async def _phase_cancelling(self) -> None:
        """Phase 3: Cancel remaining tasks.

        TIMEOUT: config.cancel_timeout_seconds (default: 5s)
        """
        self._phase = ShutdownPhase.CANCELLING
        phase_start = time.monotonic()
        self._logger.info("Shutdown: CANCELLING phase — cancelling remaining tasks")

        completed, timed_out = await self._cancellation.cancel_all(
            timeout=self._config.cancel_timeout_seconds,
        )

        self._report.tasks_cancelled = completed
        self._report.tasks_timed_out = timed_out
        self._report.cancelling_duration = time.monotonic() - phase_start

        self._logger.info(
            f"Shutdown: CANCELLING complete — "
            f"{completed} cancelled, {timed_out} timed out"
        )

    async def _phase_finalizing(self) -> None:
        """Phase 4: Close resources, capture final metrics.

        Cleanup callbacks are called in LIFO order (reverse registration).
        Each callback has a per-callback timeout.
        """
        self._phase = ShutdownPhase.FINALIZING
        phase_start = time.monotonic()
        self._logger.info("Shutdown: FINALIZING phase — closing resources")

        # Capture final metrics before closing
        for target_id, ctx in self._contexts.items():
            try:
                self._report.final_metrics[target_id] = ctx.snapshot()
            except Exception:
                pass

        # Run cleanup callbacks
        cleaned = await self._cleanup.run_all(timeout=10.0)
        self._report.resources_cleaned = cleaned
        self._report.finalizing_duration = time.monotonic() - phase_start

        self._logger.info(
            f"Shutdown: FINALIZING complete — {cleaned} resources cleaned"
        )


__all__ = [
    "ShutdownManager",
    "ShutdownPhase",
    "ShutdownReport",
    "CleanupRegistry",
    "CancellationPropagator",
    "ResourceDrainer",
]
