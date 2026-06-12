"""Adaptive scaling engine for attack worker management.

Controls dynamic scaling of attack workers based on server health,
WAF detection, and error rates. Extracted from VF_TESTER.py.

Key design: This is an ATTACK tool. Server 5xx = attack WORKING.
Only CLIENT-SIDE failures (timeouts, connection failures) trigger shrink.
HOLD mode auto-expires after 30s (v28 fix for death spiral).
v30 fix: Uses non_timeout_fail_rate to avoid double-counting timeouts.
Phase 4: Circuit breaker state used for scaling decisions + metrics.

Split for Law 14 compliance:
  - vf_adaptive_scaling.py: Core scaling engine (tick, shrink, keyboard, WAF)
  - vf_scaling_effectiveness.py: EffectivenessManager (auto-disable, escalation)
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Tuple

from logging_config import get_logger

logger = get_logger(__name__)

# Re-export for use in engine methods
from tester.vf_plugin_orchestrator import ORIGIN_PLUGINS
from tester.plugin_effectiveness import PluginEffectivenessTracker
from config.defaults import (
    ESCALATION_RESUME_TIMEOUT_FACTOR,
    ORIGIN_AUTO_DISABLE_MIN_REQUESTS,
    ORIGIN_AUTO_DISABLE_ERROR_RATE,
)

# EffectivenessManager handles escalation + effectiveness logic
from tester.vf_scaling_effectiveness import EffectivenessManager

# Phase 4: Metrics + structured logging
from observability.metrics_ext import ext_metrics
from observability.logging_ext import log_with_context

# ─── v28: Attack-Aware Thresholds ─────────────────────────────────────
HOLD_EXPIRY_SECONDS: float = 30.0
HOLD_CONSECUTIVE_SHRINK_THRESHOLD: int = 8
HOLD_RECOVERY_STEP: int = 5
HOLD_RECOVERY_INTERVAL: int = 5

# Shrink triggers (v30: non-timeout fail rate)
SHRINK_EXTREME_TIMEOUT_RATE: float = 0.60
SHRINK_EXTREME_FAIL_RATE: float = 0.30
SHRINK_HIGH_TIMEOUT_RATE: float = 0.45
SHRINK_HIGH_FAIL_RATE: float = 0.20
SHRINK_MODERATE_TIMEOUT_RATE: float = 0.30
SHRINK_MODERATE_FAIL_RATE: float = 0.15


@dataclass
class ScalingState:
    """Mutable state for the adaptive scaling engine."""
    step_start: float = 0.0
    escalation_paused: bool = False
    escalation_pause_reason: str = ""
    consecutive_shrinks: int = 0
    shrink_cooldown: float = 0
    shrink_hold: bool = False
    prev_health: float = 1.0
    stable_ticks: int = 0
    last_scale_time: float = 0.0
    disabled_plugins: list[str] = field(default_factory=list)
    min_workers: int = 10
    dynamic_step: int = 50
    last_shrink_log: float = 0.0
    healthy_ticks: int = 0
    manual_delta: int = 0
    recovery_ticks: int = 0
    no_active_plugins_logged: bool = False
    hold_start_time: float = 0.0
    hold_recovery_ticks: int = 0
    attack_duration: float = 0.0


class AdaptiveScalingEngine:
    """Manages adaptive worker scaling during attack.

    ATTACK tool design: Server 5xx = attack WORKING (keep pressing).
    Client timeouts/failures = reduce workers (can't reach server).
    Phase 4: Circuit breaker state drives scaling decisions; metrics
    track scaling_events, escalation_state, circuit_breaker_state.
    """

    def __init__(
        self,
        orchestrator: Any,
        health_monitor: Any,
        stats: Any,
        keyboard: Any = None,
        evasion: Any = None,
        stop_event: Any = None,
        registry: Any = None,
        waf_getter: Callable[[], str] | None = None,
        waf_setter: Callable[[str], None] | None = None,
        session_getter: Callable[[], Any] | None = None,
        compute_plugin_workers_fn: Callable | None = None,
        build_attack_context_fn: Callable | None = None,
        origin_ips_getter: Callable[[], List[str]] | None = None,
        step: int = 50,
        step_duration: int = 5,
        max_workers: int = 5000,
        initial_workers: int = 5,
        effectiveness_tracker: PluginEffectivenessTracker | None = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._health = health_monitor
        self._stats = stats
        self._keyboard = keyboard
        self._evasion = evasion
        self._stop = stop_event
        self._registry = registry
        self._waf_getter = waf_getter
        self._waf_setter = waf_setter
        self._session_getter = session_getter
        self._compute_plugin_workers_fn = compute_plugin_workers_fn
        self._build_attack_context_fn = build_attack_context_fn
        self._origin_ips_getter = origin_ips_getter
        self._step = step
        self._step_duration = step_duration
        self._max_workers = max_workers
        self._initial_workers = initial_workers
        self._effectiveness_tracker = effectiveness_tracker
        self._state = ScalingState(
            step_start=time.monotonic(),
            min_workers=max(initial_workers, 10),
            dynamic_step=step,
        )
        self._eff_mgr = EffectivenessManager(self)

    @property
    def state(self) -> ScalingState:
        """Read-only access to current scaling state (for dashboards/tests)."""
        return self._state

    def reset(self) -> None:
        """Reset scaling state for a new attack run."""
        self._state = ScalingState(
            step_start=time.monotonic(),
            min_workers=max(self._initial_workers, 10),
            dynamic_step=self._step,
        )

    async def tick(self) -> str | None:
        """Execute one scaling cycle.

        Called once per dashboard loop iteration. Handles keyboard input,
        WAF detection, plugin auto-heal, adaptive step computation,
        auto-shrink, and escalation phase logic.

        Returns:
            Command string if quit requested, else None.
        """
        health = self._health.check(self._stats)
        cmd = self._check_keyboard()
        if cmd == 'q':
            return cmd

        self._state.attack_duration = time.monotonic() - self._stats.t0 if self._stats.t0 > 0 else 0

        snap = self._stats.get_snapshot()
        total = max(snap["total"], 1)
        fail_rate = snap["fail"] / total
        timeout_rate = snap["timeout_errors"] / total
        s5xx_rate = snap["server_errors"] / total
        adjusted_timeout_rate = self._health.adjusted_timeout_rate if hasattr(self._health, 'adjusted_timeout_rate') else timeout_rate
        non_timeout_fail = max(snap["fail"] - snap["timeout_errors"], 0)
        non_timeout_fail_rate = non_timeout_fail / total

        actual_workers = sum(p.worker_count for p in self._orchestrator.active_plugins.values())
        self._orchestrator.total_workers = actual_workers

        # Phase 4: Filter out circuit-OPEN plugins from scaling pool
        available_workers = sum(
            p.worker_count for name, p in self._orchestrator.active_plugins.items()
            if self._eff_mgr.is_plugin_available(name)
        )

        self._check_waf_runtime(health)
        actual_workers = self._eff_mgr.auto_disable_failing_plugins()
        actual_workers = self._eff_mgr.check_effectiveness_auto_disable(actual_workers)
        actual_workers = self._eff_mgr.auto_recover_disabled_plugins(health)

        self._state.dynamic_step = self._compute_dynamic_step(health)

        should_shrink, shrink_hold_active = self._auto_shrink_workers(
            health, non_timeout_fail_rate, s5xx_rate, adjusted_timeout_rate, actual_workers)

        self._eff_mgr.run_escalation_phase(
            self._state.dynamic_step, actual_workers, health, non_timeout_fail_rate,
            s5xx_rate, adjusted_timeout_rate, should_shrink, shrink_hold_active)

        # Phase 4: Update worker metrics per plugin
        for pname, plugin in self._orchestrator.active_plugins.items():
            from observability.metrics import metrics as _metrics
            _metrics.workers_active.labels(plugin=pname).set(plugin.worker_count)

        self._stats.users = self._orchestrator.total_workers
        return None

    # ─── Core Methods ──────────

    def _check_keyboard(self) -> str | None:
        """Handle keyboard input for +/- and quit commands."""
        if self._keyboard is None:
            return None
        cmd = self._keyboard.get_command()
        if cmd == 'q':
            log_with_context(
                logger, logging.WARNING, "Attack stopping — user requested quit",
                component="scaling_engine",
            )
            if self._stop is not None:
                self._stop.set()
            return 'q'
        elif cmd == '+':
            self._state.manual_delta += self._step
        elif cmd == '-':
            self._state.manual_delta -= self._step
        return None

    def _check_waf_runtime(self, health: float) -> None:
        """Check plugin classifiers for runtime WAF detection."""
        detected_waf = self._waf_getter() if self._waf_getter else ""
        if not detected_waf or detected_waf.lower() == "none":
            for pname, plugin in self._orchestrator.active_plugins.items():
                if hasattr(plugin, '_classifier'):
                    detected = plugin._classifier.detected_waf
                    if detected and detected != detected_waf:
                        if self._waf_setter:
                            self._waf_setter(detected)
                        if self._evasion and hasattr(self._evasion, 'set_waf'):
                            self._evasion.set_waf(detected)
                        log_with_context(
                            logger, logging.WARNING,
                            f"Runtime detected WAF: {detected} (from {pname} responses)",
                            component="scaling_engine",
                        )
                        break

    def _compute_dynamic_step(self, health: float) -> int:
        """Compute adaptive step size based on server health.

        F5-09: Previously step was fixed at self._step (usually 50) when
        health > 0.5. Now scales aggressively when the server is healthy:
          - health > 0.8 and timeout < 20%: step × 4 (aggressive scale-up)
          - health > 0.5: step × 1 (normal)
          - health > 0.3: step // 2 (cautious)
          - health > 0.15: step // 3 (conservative)
          - else: step // 5 (minimal)
        """
        if health > 0.8:
            # F5-09: Aggressive scaling when server is very healthy
            # Check if timeout rate is also low
            snap = self._stats.get_snapshot()
            total = max(snap["total"], 1)
            timeout_rate = snap["timeout_errors"] / total
            if timeout_rate < 0.20:
                return self._step * 4
            return self._step * 2
        elif health > 0.5:
            return self._step
        elif health > 0.3:
            return max(self._step // 2, 3)
        elif health > 0.15:
            return max(self._step // 3, 2)
        else:
            return max(self._step // 5, 1)

    def _auto_shrink_workers(self, health: float, fail_rate: float,
                              s5xx_rate: float, timeout_rate: float,
                              actual_workers: int) -> Tuple[bool, bool]:
        """Auto-shrink workers when CLIENT connectivity is broken.

        Phase 4: Shrink events tracked via Prometheus metrics.
        Scaling log messages use structured log_with_context.
        """
        should_shrink = False
        shrink_severity = "moderate"

        if timeout_rate > SHRINK_EXTREME_TIMEOUT_RATE and fail_rate > SHRINK_EXTREME_FAIL_RATE:
            should_shrink = True
            shrink_severity = "extreme"
        elif timeout_rate > SHRINK_HIGH_TIMEOUT_RATE and fail_rate > SHRINK_HIGH_FAIL_RATE:
            should_shrink = True
            shrink_severity = "high"
        elif timeout_rate > SHRINK_MODERATE_TIMEOUT_RATE and fail_rate > SHRINK_MODERATE_FAIL_RATE:
            should_shrink = True
            shrink_severity = "moderate"

        if s5xx_rate > 0.3 and not should_shrink:
            log_with_context(
                logger, logging.INFO,
                f"Server returning {s5xx_rate:.0%} 5xx — attack working, maintaining pressure ({actual_workers} workers)",
                component="scaling_engine",
            )

        if should_shrink and actual_workers > self._state.min_workers:
            if self._state.shrink_cooldown <= 0:
                if shrink_severity == "extreme":
                    to_remove = max(actual_workers // 3, 3)
                elif shrink_severity == "high":
                    to_remove = max(actual_workers // 4, 2)
                else:
                    to_remove = max(actual_workers // 5, 1)

                removed = self._orchestrator.scale_all_plugins(-to_remove)
                self._orchestrator.total_workers = sum(p.worker_count for p in self._orchestrator.active_plugins.values())

                now = time.monotonic()
                if removed > 0:
                    # Phase 4: Track shrink in metrics
                    ext_metrics.scaling_events_total.labels(direction="scale_down").inc(removed)
                    log_with_context(
                        logger, logging.WARNING,
                        f"Client connectivity degraded (timeout={timeout_rate:.0%}, fail={fail_rate:.0%}) → removed {removed} workers (now {self._orchestrator.total_workers})",
                        component="scaling_engine",
                    )
                    self._state.last_shrink_log = now
                elif now - self._state.last_shrink_log > 5:
                    log_with_context(
                        logger, logging.WARNING,
                        f"Client connectivity degraded but minimum workers reached ({self._orchestrator.total_workers})",
                        component="scaling_engine",
                    )
                    self._state.last_shrink_log = now

                self._state.step_start = time.monotonic()
                self._state.shrink_cooldown = 10
                self._state.consecutive_shrinks += 1
            else:
                self._state.shrink_cooldown -= 1

        # HOLD mode with auto-expiry
        shrink_hold_active = False
        if self._state.consecutive_shrinks >= HOLD_CONSECUTIVE_SHRINK_THRESHOLD and actual_workers > self._state.min_workers:
            now = time.monotonic()

            if not self._state.shrink_hold:
                self._state.shrink_hold = True
                self._state.hold_start_time = now
                self._state.hold_recovery_ticks = 0
                log_with_context(
                    logger, logging.WARNING,
                    f"Entered hold mode at {actual_workers} workers (auto-expiry in {HOLD_EXPIRY_SECONDS:.0f}s)",
                    component="scaling_engine",
                )

            hold_duration = now - self._state.hold_start_time

            if hold_duration >= HOLD_EXPIRY_SECONDS:
                self._state.hold_recovery_ticks += 1

                if self._state.hold_recovery_ticks % HOLD_RECOVERY_INTERVAL == 0:
                    recovery_step = min(HOLD_RECOVERY_STEP, self._max_workers - self._orchestrator.total_workers)
                    if recovery_step > 0:
                        added = self._orchestrator.scale_plugins(recovery_step)
                        self._orchestrator.total_workers += added
                        if added > 0:
                            ext_metrics.scaling_events_total.labels(direction="scale_up").inc(added)
                            self._state.step_start = time.monotonic()

                    if self._orchestrator.total_workers >= self._state.min_workers * 2:
                        self._state.shrink_hold = False
                        self._state.consecutive_shrinks = 0
                        self._state.hold_recovery_ticks = 0
                        self._state.escalation_paused = False
                        self._state.escalation_pause_reason = ""
                        self._state.step_start = time.monotonic()
            else:
                if should_shrink:
                    if now - self._state.last_shrink_log > 5:
                        self._state.last_shrink_log = now
                    should_shrink = False
                shrink_hold_active = True

        if self._state.shrink_hold and self._state.consecutive_shrinks < HOLD_CONSECUTIVE_SHRINK_THRESHOLD:
            self._state.shrink_hold = False
            self._state.hold_recovery_ticks = 0

        return should_shrink, shrink_hold_active
