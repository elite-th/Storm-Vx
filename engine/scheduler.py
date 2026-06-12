"""engine.scheduler — Structured concurrency engine with asyncio.TaskGroup.

Redesigned from the ground up for Python 3.12+ with structured concurrency.
Every task belongs to a TaskGroup; there are no orphan tasks, no unbounded
queues, no blocking I/O in the event loop, and no global mutable state.

ARCHITECTURE:
  StormScheduler (top-level orchestrator)
    ├── ScalingController (pure function: health → ScalingCommand)
    ├── BackpressureController (event-loop saturation detection)
    ├── HealthAggregator (per-target health collection)
    └── TickDriver (1Hz scheduling loop)

DESIGN PRINCIPLES:
  - Structured concurrency: all tasks belong to TaskGroups
  - Pure functions: ScalingController.decide() has no side effects
  - O(1) scheduler bookkeeping: no task list scanning in tick path
  - Zero unbounded queues: all channels are bounded
  - No blocking I/O in tick path
  - No asyncio.Lock in tick path
  - Immutable scaling commands (frozen dataclass)

LIFECYCLE:
  1. StormScheduler.start() → creates TaskGroup, starts tick loop
  2. TickDriver.tick() → collect health, decide scaling, apply command
  3. StormScheduler.stop() → cancel tick loop, drain TaskGroup
  4. TaskGroup ensures all child tasks complete before exit
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from engine.atomic_metrics import AtomicMetrics, MetricsSnapshot, PerTargetMetrics
from engine.runtime_context import (
    EngineConfig, RuntimeContext, SchedulerConfig, BackpressureConfig,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Scaling Commands — Immutable decisions
# ═══════════════════════════════════════════════════════════════════════════════

class ScalingAction(Enum):
    """Possible scaling actions."""
    ESCALATE = "escalate"     # Add workers
    HOLD = "hold"             # Maintain current level
    SHRINK = "shrink"         # Remove workers (client connectivity broken)
    PRESSURE = "pressure"     # Server returning 5xx — increase pressure
    PAUSE = "pause"           # Temporarily pause escalation
    RECOVER = "recover"       # Resume from pause/shrink


@dataclass(frozen=True)
class ScalingCommand:
    """Immutable scaling decision produced by ScalingController.

    A pure value object — no side effects, no mutable state.
    The TaskSupervisor applies the command to the actual plugins.
    """
    action: ScalingAction
    delta: int = 0       # Positive = add workers, negative = remove
    target_plugins: tuple[str, ...] = ()  # Which plugins to scale (empty = all)
    reason: str = ""
    timestamp: float = field(default_factory=time.time)


# ═══════════════════════════════════════════════════════════════════════════════
# Scaling State — Mutable per-cycle state (passed to ScalingController)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScalingState:
    """Mutable state for the scaling engine.

    Encapsulates all per-loop-iteration state. Passed as input to
    ScalingController.decide() — the controller is a pure function.
    """
    step_start: float = 0.0
    escalation_paused: bool = False
    escalation_pause_reason: str = ""
    consecutive_shrinks: int = 0
    shrink_cooldown: int = 0
    shrink_hold: bool = False
    prev_health: float = 1.0
    stable_ticks: int = 0
    last_scale_time: float = 0.0
    dynamic_step: int = 50
    healthy_ticks: int = 0
    recovery_ticks: int = 0
    no_active_plugins_logged: bool = False

    # HOLD mode tracking (auto-expiry prevents deadlock)
    hold_start_time: float = 0.0
    hold_recovery_ticks: int = 0

    # Worker bounds (from config)
    min_workers: int = 10
    max_workers: int = 5000
    current_workers: int = 0

    # Configuration
    step: int = 50
    step_duration: int = 5


# ═══════════════════════════════════════════════════════════════════════════════
# ScalingController — Pure function
# ═══════════════════════════════════════════════════════════════════════════════

class ScalingController:
    """Stateless scaling decision engine.

    Pure function: (health_map, metrics, state, config) → ScalingCommand.
    All state is in ScalingState, all thresholds in SchedulerConfig.
    No side effects, no mutable state, easy to test.

    ATTACK-TOOL AWARENESS:
    Server 5xx = attack WORKING. Only CLIENT-SIDE failures (timeouts,
    connection errors) should trigger shrink. Server returning 5xx means
    we should maintain or increase pressure.
    """

    def decide(
        self,
        health_map: Dict[str, float],
        metrics: MetricsSnapshot,
        state: ScalingState,
        config: SchedulerConfig,
    ) -> ScalingCommand:
        """Compute a scaling decision based on current health and metrics.

        Args:
            health_map: Dict of target → health_score (0.0 to 1.0).
            metrics: Point-in-time metrics snapshot.
            state: Current scaling state.
            config: Immutable scheduler configuration.

        Returns:
            Immutable ScalingCommand.
        """
        # Compute aggregate health
        avg_health = (
            sum(health_map.values()) / max(len(health_map), 1)
            if health_map else 1.0
        )

        total = max(metrics.total, 1)
        timeout_rate = metrics.timeout_rate
        non_timeout_fail_rate = metrics.non_timeout_fail_rate
        s5xx_rate = metrics.server_error_rate
        actual_workers = state.current_workers

        # ─── 1. Check for shrink conditions (CLIENT connectivity) ───
        shrink_cmd = self._check_shrink(
            timeout_rate, non_timeout_fail_rate, s5xx_rate,
            actual_workers, state, config,
        )
        if shrink_cmd is not None:
            return shrink_cmd

        # ─── 2. Check for pressure mode (server under load) ───
        if (config.pressure_5xx_min < s5xx_rate < config.pressure_5xx_max
                and timeout_rate < config.pressure_timeout_max
                and not state.escalation_paused
                and not state.shrink_hold):
            step = self._compute_dynamic_step(avg_health, state)
            pressure_step = max(step // 2, 2)
            return ScalingCommand(
                ScalingAction.PRESSURE,
                delta=pressure_step,
                reason=f"server_under_load(5xx={s5xx_rate:.0%})",
            )

        # ─── 3. Check for escalation pause ───
        pause_cmd = self._check_pause(
            timeout_rate, non_timeout_fail_rate, avg_health, state, config,
        )
        if pause_cmd is not None:
            return pause_cmd

        # ─── 4. Normal escalation ───
        if avg_health > 0.5 and not state.escalation_paused and not state.shrink_hold:
            elapsed = time.monotonic() - state.step_start
            if elapsed >= state.step_duration and actual_workers < state.max_workers:
                step = self._compute_dynamic_step(avg_health, state)
                delta = min(step, state.max_workers - actual_workers)
                return ScalingCommand(
                    ScalingAction.ESCALATE,
                    delta=delta,
                    reason=f"healthy_escalation(health={avg_health:.0%})",
                )

        # ─── 5. HOLD recovery ───
        if state.shrink_hold:
            hold_duration = time.monotonic() - state.hold_start_time
            if hold_duration >= config.hold_expiry_seconds:
                recovery_step = min(
                    config.hold_recovery_step,
                    state.max_workers - actual_workers,
                )
                if recovery_step > 0:
                    return ScalingCommand(
                        ScalingAction.RECOVER,
                        delta=recovery_step,
                        reason="hold_expired_recovery",
                    )

        return ScalingCommand(ScalingAction.HOLD, reason="waiting")

    def _check_shrink(
        self,
        timeout_rate: float,
        fail_rate: float,
        s5xx_rate: float,
        actual_workers: int,
        state: ScalingState,
        config: SchedulerConfig,
    ) -> Optional[ScalingCommand]:
        """Check if client connectivity is broken enough to shrink."""
        should_shrink = False
        severity = "moderate"

        if (timeout_rate > config.shrink_extreme_timeout
                and fail_rate > config.shrink_extreme_fail):
            should_shrink = True
            severity = "extreme"
        elif (timeout_rate > config.shrink_high_timeout
              and fail_rate > config.shrink_high_fail):
            should_shrink = True
            severity = "high"
        elif (timeout_rate > config.shrink_moderate_timeout
              and fail_rate > config.shrink_moderate_fail):
            should_shrink = True
            severity = "moderate"

        if not should_shrink:
            return None
        if actual_workers <= state.min_workers:
            return None
        if state.shrink_cooldown > 0:
            return None

        # Compute shrink amount (never more than 1/3 of workers)
        if severity == "extreme":
            to_remove = max(actual_workers // 3, 3)
        elif severity == "high":
            to_remove = max(actual_workers // 4, 2)
        else:
            to_remove = max(actual_workers // 5, 1)

        # Check if we should enter HOLD mode
        if state.consecutive_shrinks + 1 >= config.hold_consecutive_threshold:
            return ScalingCommand(
                ScalingAction.SHRINK,
                delta=-to_remove,
                reason=f"hold_mode_shrink({severity},timeout={timeout_rate:.0%},fail={fail_rate:.0%})",
            )

        return ScalingCommand(
            ScalingAction.SHRINK,
            delta=-to_remove,
            reason=f"client_degraded({severity},timeout={timeout_rate:.0%},fail={fail_rate:.0%})",
        )

    def _check_pause(
        self,
        timeout_rate: float,
        fail_rate: float,
        health: float,
        state: ScalingState,
        config: SchedulerConfig,
    ) -> Optional[ScalingCommand]:
        """Check if escalation should be paused."""
        if timeout_rate > config.pause_timeout_rate:
            if not state.escalation_paused:
                return ScalingCommand(
                    ScalingAction.PAUSE,
                    reason=f"high_timeout_rate({timeout_rate:.0%})",
                )
        elif fail_rate > config.pause_fail_rate:
            if not state.escalation_paused:
                return ScalingCommand(
                    ScalingAction.PAUSE,
                    reason=f"high_fail_rate({fail_rate:.0%})",
                )
        return None

    def _compute_dynamic_step(self, health: float, state: ScalingState) -> int:
        """Compute adaptive step size based on server health."""
        if health > 0.5:
            return state.step
        elif health > 0.3:
            return max(state.step // 2, 3)
        elif health > 0.15:
            return max(state.step // 3, 2)
        else:
            return max(state.step // 5, 1)


# ═══════════════════════════════════════════════════════════════════════════════
# BackpressureController — Event-loop saturation detection
# ═══════════════════════════════════════════════════════════════════════════════

class BackpressureController:
    """Prevents event-loop saturation by monitoring scheduling delay.

    If tasks are taking too long to be scheduled (high lag), the controller
    signals that the event loop is saturated and no new workers should spawn.

    This prevents the death spiral:
    1. Too many workers → event loop saturated → tasks delayed
    2. Delayed tasks → timeouts → scaling engine shrinks
    3. Fewer workers → event loop recovers → scaling engine grows
    4. Back to step 1
    """

    __slots__ = ('_config', '_last_schedule_time', '_lag_samples',
                 '_sample_count', '_saturated_ticks')

    def __init__(self, config: BackpressureConfig) -> None:
        self._config = config
        self._last_schedule_time: float = time.monotonic()
        self._lag_samples: float = 0.0
        self._sample_count: int = 0
        self._saturated_ticks: int = 0

    def record_schedule(self) -> None:
        """Record that a task was scheduled. Measures scheduling lag."""
        now = time.monotonic()
        lag = (now - self._last_schedule_time) * 1000  # ms
        self._lag_samples += lag
        self._sample_count += 1
        self._last_schedule_time = now

    def is_saturated(self) -> bool:
        """Check if the event loop is too busy to add more workers."""
        if self._sample_count < self._config.min_samples:
            return False
        avg_lag = self._lag_samples / self._sample_count
        return avg_lag > self._config.max_lag_ms

    def tick(self) -> bool:
        """Process one tick. Returns True if saturated.

        Resets sample window each tick. Tracks consecutive saturated
        ticks for hysteresis (prevents flapping).
        """
        if self.is_saturated():
            self._saturated_ticks += 1
        else:
            self._saturated_ticks = max(0, self._saturated_ticks - 1)
        self.reset_sample()
        return self._saturated_ticks >= self._config.cooldown_ticks

    def reset_sample(self) -> None:
        """Reset lag samples (called once per scheduler tick)."""
        self._lag_samples = 0.0
        self._sample_count = 0


# ═══════════════════════════════════════════════════════════════════════════════
# HealthAggregator — Per-target health collection
# ═══════════════════════════════════════════════════════════════════════════════

class HealthAggregator:
    """Collects health scores from per-target RuntimeContexts.

    Per-target isolation: WAF blocks on one target don't inflate
    failure rates for other targets. Each RuntimeContext has its own
    AtomicMetrics, so health computation is naturally isolated.
    """

    __slots__ = ('_contexts',)

    def __init__(self, contexts: Dict[str, RuntimeContext]) -> None:
        self._contexts = contexts

    def collect(self) -> Dict[str, float]:
        """Collect health scores for all targets.

        Returns:
            Dict of target_id → health_score (0.0 to 1.0).
        """
        return {
            target_id: ctx.health
            for target_id, ctx in self._contexts.items()
            if not ctx.is_stopping
        }

    @property
    def aggregate_health(self) -> float:
        """Compute aggregate health across all active targets."""
        health_map = self.collect()
        if not health_map:
            return 1.0
        return sum(health_map.values()) / len(health_map)

    def aggregate_metrics(self) -> MetricsSnapshot:
        """Get aggregate metrics across all active targets.

        Creates a snapshot by summing per-target metrics.
        Note: This is a point-in-time snapshot, not a live view.
        """
        aggregate = AtomicMetrics()
        for ctx in self._contexts.values():
            if ctx.is_stopping:
                continue
            snap = ctx.metrics.snapshot()
            # Sum up all counters
            aggregate.total += snap.total
            aggregate.ok += snap.ok
            aggregate.fail += snap.fail
            aggregate.timeout_errors += snap.timeout_errors
            aggregate.server_errors += snap.server_errors
            aggregate.total_rt += snap.total_rt
        aggregate.users = sum(
            ctx.current_workers for ctx in self._contexts.values()
            if not ctx.is_stopping
        )
        return aggregate.snapshot()


# ═══════════════════════════════════════════════════════════════════════════════
# TickDriver — 1Hz scheduling loop
# ═══════════════════════════════════════════════════════════════════════════════

class TickDriver:
    """Central scheduling tick loop.

    Each tick:
    1. Collect health from all targets (via HealthAggregator)
    2. Check backpressure (event-loop saturation)
    3. Compute scaling decision (pure function via ScalingController)
    4. Apply scaling command (via callback)
    5. Sleep for remainder of tick interval

    O(1) bookkeeping: tick does not scan task lists, only reads
    per-target metrics (O(num_targets) which is bounded and small).
    """

    def __init__(
        self,
        scaling: ScalingController,
        backpressure: BackpressureController,
        health: HealthAggregator,
        config: SchedulerConfig,
        apply_command_fn: Optional[Callable[[ScalingCommand], Awaitable[None]]] = None,
        on_tick_fn: Optional[Callable[[ScalingCommand, ScalingState], None]] = None,
    ) -> None:
        self._scaling = scaling
        self._backpressure = backpressure
        self._health = health
        self._config = config
        self._apply_command_fn = apply_command_fn
        self._on_tick_fn = on_tick_fn
        self._state = ScalingState(
            step_start=time.monotonic(),
            min_workers=config.min_workers,
            max_workers=config.max_workers,
            step=50,
            step_duration=config.step_duration,
        )
        self._stop_event = asyncio.Event()
        self._tick_count: int = 0

    @property
    def state(self) -> ScalingState:
        """Read-only access to current scaling state."""
        return self._state

    @property
    def tick_count(self) -> int:
        """Number of ticks since start."""
        return self._tick_count

    def stop(self) -> None:
        """Signal the tick driver to stop."""
        self._stop_event.set()

    def reset(self) -> None:
        """Reset scaling state for a new attack run."""
        self._state = ScalingState(
            step_start=time.monotonic(),
            min_workers=self._config.min_workers,
            max_workers=self._config.max_workers,
            step=50,
            step_duration=self._config.step_duration,
        )
        self._tick_count = 0

    async def run(self) -> None:
        """Main tick loop. Runs until stop() is called or cancelled.

        Uses asyncio.Event.wait() with timeout for clean cancellation.
        No busy-waiting, no blocking I/O.
        """
        while not self._stop_event.is_set():
            tick_start = time.monotonic()
            self._tick_count += 1

            # Record backpressure sample
            self._backpressure.record_schedule()

            # 1. Collect health
            health_map = self._health.collect()
            self._state.prev_health = self._health.aggregate_health

            # 2. Check backpressure (event-loop saturation)
            if self._backpressure.tick():
                # Saturated — skip scaling decision this tick
                await self._sleep_remaining(tick_start)
                continue

            # 3. Compute aggregate metrics for scaling decision
            metrics = self._health.aggregate_metrics()

            # 4. Update worker count from current context states
            self._state.current_workers = metrics.users

            # 5. Compute scaling decision (pure function)
            command = self._scaling.decide(
                health_map, metrics, self._state, self._config,
            )

            # 6. Apply scaling command
            if command.action != ScalingAction.HOLD and self._apply_command_fn:
                try:
                    await self._apply_command_fn(command)
                except asyncio.CancelledError:
                    raise  # Propagate cancellation
                except Exception:
                    pass  # Don't let command application break the tick loop

            # 7. Update state based on command
            self._update_state(command)

            # 8. Notify tick callback (for dashboard, metrics, etc.)
            if self._on_tick_fn:
                try:
                    self._on_tick_fn(command, self._state)
                except Exception:
                    pass

            # 9. Sleep for remainder of tick interval
            await self._sleep_remaining(tick_start)

    def _update_state(self, command: ScalingCommand) -> None:
        """Update scaling state based on the issued command."""
        if command.action == ScalingAction.SHRINK:
            self._state.consecutive_shrinks += 1
            self._state.shrink_cooldown = 10
            self._state.step_start = time.monotonic()
            if self._state.consecutive_shrinks >= self._config.hold_consecutive_threshold:
                self._state.shrink_hold = True
                self._state.hold_start_time = time.monotonic()

        elif command.action == ScalingAction.ESCALATE:
            self._state.consecutive_shrinks = 0
            self._state.step_start = time.monotonic()
            if self._state.shrink_hold:
                self._state.shrink_hold = False
                self._state.hold_recovery_ticks = 0

        elif command.action == ScalingAction.PAUSE:
            self._state.escalation_paused = True
            self._state.escalation_pause_reason = command.reason

        elif command.action == ScalingAction.RECOVER:
            self._state.hold_recovery_ticks += 1
            if self._state.current_workers >= self._state.min_workers * 2:
                self._state.shrink_hold = False
                self._state.consecutive_shrinks = 0

        # Decrement cooldown
        if self._state.shrink_cooldown > 0:
            self._state.shrink_cooldown -= 1

    async def _sleep_remaining(self, tick_start: float) -> None:
        """Sleep for the remainder of the tick interval.

        Uses asyncio.Event.wait() with timeout for clean cancellation
        support. More responsive to stop() than asyncio.sleep().
        """
        elapsed = time.monotonic() - tick_start
        remaining = self._config.tick_interval - elapsed
        if remaining > 0:
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                pass  # Normal: tick interval elapsed
            except asyncio.CancelledError:
                pass  # Clean cancellation


# ═══════════════════════════════════════════════════════════════════════════════
# StormScheduler — Top-level orchestrator with structured concurrency
# ═══════════════════════════════════════════════════════════════════════════════

class StormScheduler:
    """Top-level scheduling orchestrator using asyncio.TaskGroup.

    STRUCTURED CONCURRENCY: The tick driver runs inside a TaskGroup.
    When the TaskGroup exits, all child tasks are guaranteed to complete
    (or be cancelled). No orphan tasks, no task leaks.

    USAGE:
        config = EngineConfig()
        scheduler = StormScheduler(config, contexts)

        # Start the scheduler (creates TaskGroup internally)
        await scheduler.start()

        # ... attack runs ...

        # Graceful shutdown
        await scheduler.stop()
    """

    def __init__(
        self,
        config: EngineConfig,
        contexts: Dict[str, RuntimeContext],
        apply_command_fn: Optional[Callable[[ScalingCommand], Awaitable[None]]] = None,
        on_tick_fn: Optional[Callable[[ScalingCommand, ScalingState], None]] = None,
    ) -> None:
        self._config = config
        self._contexts = contexts
        self._apply_command_fn = apply_command_fn
        self._on_tick_fn = on_tick_fn

        # Sub-components
        self._scaling = ScalingController()
        self._backpressure = BackpressureController(config.backpressure)
        self._health = HealthAggregator(contexts)
        self._tick_driver = TickDriver(
            scaling=self._scaling,
            backpressure=self._backpressure,
            health=self._health,
            config=config.scheduler,
            apply_command_fn=apply_command_fn,
            on_tick_fn=on_tick_fn,
        )

        # Task management
        self._task_group: Optional[asyncio.TaskGroup] = None
        self._tick_task: Optional[asyncio.Task] = None
        self._running: bool = False
        self._stop_event: Optional[asyncio.Event] = None
        self._scheduler_task: Optional[asyncio.Task] = None

    @property
    def is_running(self) -> bool:
        """Whether the scheduler is actively running."""
        return self._running

    @property
    def tick_count(self) -> int:
        """Number of ticks since start."""
        return self._tick_driver.tick_count

    @property
    def scaling_state(self) -> ScalingState:
        """Current scaling state (read-only)."""
        return self._tick_driver.state

    @property
    def health(self) -> Dict[str, float]:
        """Current health map for all targets."""
        return self._health.collect()

    async def start(self) -> None:
        """Start the scheduler with structured concurrency.

        Launches the internal scheduler loop as a managed background task
        that owns the TaskGroup lifecycle via ``async with``. This guarantees
        the TaskGroup is always cleaned up, even if an error occurs after
        ``__aenter__`` succeeds (Bug #1 fix).

        Raises:
            RuntimeError: If the scheduler is already running.
        """
        if self._running:
            raise RuntimeError("StormScheduler is already running")

        self._running = True
        self._stop_event = asyncio.Event()
        self._scheduler_task = asyncio.create_task(
            self._scheduler_loop(), name="storm-vx:scheduler-loop"
        )

    async def _scheduler_loop(self) -> None:
        """Internal loop that owns the TaskGroup lifecycle.

        Using ``async with asyncio.TaskGroup()`` ensures the TaskGroup is
        always cleaned up, even if an exception occurs after ``__aenter__``
        succeeds. The tick driver runs as a child task of the TaskGroup.
        """
        try:
            async with asyncio.TaskGroup() as tg:
                self._task_group = tg
                # Start tick driver as a child task of the TaskGroup
                self._tick_task = tg.create_task(
                    self._tick_driver.run(),
                    name="storm-scheduler:tick-driver",
                )
                # Wait until stop is requested
                await self._stop_event.wait()
                self._tick_driver.stop()
        except ExceptionGroup:
            pass  # Child task exceptions are handled elsewhere

    async def stop(self) -> None:
        """Stop the scheduler gracefully.

        1. Signal the scheduler loop to exit
        2. Wait for the scheduler task to complete
        3. TaskGroup cleanup happens naturally via ``async with`` exit
        """
        if not self._running:
            return

        self._running = False

        # Signal the scheduler loop to exit
        if self._stop_event is not None:
            self._stop_event.set()

        # Wait for the scheduler task to complete (TaskGroup cleanup
        # happens naturally when _scheduler_loop exits the async with block)
        if self._scheduler_task is not None and not self._scheduler_task.done():
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._scheduler_task), timeout=10.0
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._scheduler_task.cancel()
        self._task_group = None
        self._scheduler_task = None

    def reset(self) -> None:
        """Reset scheduler state for a new attack run."""
        self._tick_driver.reset()
        self._backpressure = BackpressureController(self._config.backpressure)


__all__ = [
    "StormScheduler",
    "ScalingController",
    "ScalingCommand",
    "ScalingAction",
    "ScalingState",
    "BackpressureController",
    "HealthAggregator",
    "TickDriver",
]
