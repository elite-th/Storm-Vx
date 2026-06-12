"""Effectiveness and escalation management for adaptive scaling.

Extracted from vf_adaptive_scaling.py for Law 14 compliance (500-line limit).
Handles: plugin effectiveness auto-disable, circuit breaker, recovery, escalation.
Phase 4: Hard disable/enable toggle replaced with CircuitBreaker pattern.
Phase 5: Auto-disable now covers ALL non-ESSENTIAL plugins (not just ORIGIN).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Dict, List, Tuple

from logging_config import get_logger

logger = get_logger(__name__)

from tester.vf_plugin_orchestrator import ORIGIN_PLUGINS
from tester.plugin_effectiveness import PluginEffectivenessTracker
from config.defaults import (
    ESCALATION_RESUME_TIMEOUT_FACTOR,
    ORIGIN_AUTO_DISABLE_MIN_REQUESTS,
    ORIGIN_AUTO_DISABLE_ERROR_RATE,
    CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    CIRCUIT_BREAKER_HALF_OPEN_TIMEOUT,
    CIRCUIT_BREAKER_SUCCESS_THRESHOLD,
)
from observability.resilience import CircuitBreaker, CircuitState, CircuitOpenError
from observability.metrics_ext import ext_metrics

# ─── Escalation Pause Thresholds ──────────────────────────────────────
# v30: fail_rate is now non-timeout fail rate — adjust thresholds
# BUG-FIX v32: Raised PAUSE_TIMEOUT_RATE from 0.50 to 0.65.
PAUSE_TIMEOUT_RATE: float = 0.65
PAUSE_FAIL_RATE: float = 0.40
PAUSE_COMBO_FAIL: float = 0.20
PAUSE_COMBO_TIMEOUT: float = 0.35


__all__ = ["EffectivenessManager"]


class EffectivenessManager:
    """Manages plugin effectiveness tracking, circuit breaker, and escalation logic.

    Extracted from AdaptiveScalingEngine for Law 14 compliance.
    Receives a reference to the engine to access shared state.

    Phase 4: Per-plugin CircuitBreaker instances replace the hard
    disable/enable toggle. Circuit state drives scaling decisions:
      - OPEN: plugin is failing, skip it for scaling
      - HALF_OPEN: probing, allow limited requests
      - CLOSED: plugin is healthy, normal scaling

    Args:
        engine: AdaptiveScalingEngine instance for accessing shared state.
    """

    def __init__(self, engine: Any) -> None:
        self._engine = engine
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}

    def get_circuit_breaker(self, plugin_name: str) -> CircuitBreaker:
        """Get or create a CircuitBreaker for a plugin.

        Args:
            plugin_name: Name of the plugin.

        Returns:
            CircuitBreaker instance for the plugin.
        """
        if plugin_name not in self._circuit_breakers:
            self._circuit_breakers[plugin_name] = CircuitBreaker(
                name=f"plugin.{plugin_name}",
                failure_threshold=CIRCUIT_BREAKER_FAILURE_THRESHOLD,
                recovery_timeout=CIRCUIT_BREAKER_HALF_OPEN_TIMEOUT,
                success_threshold=CIRCUIT_BREAKER_SUCCESS_THRESHOLD,
            )
        return self._circuit_breakers[plugin_name]

    def is_plugin_available(self, plugin_name: str) -> bool:
        """Check if a plugin's circuit breaker allows requests.

        Returns False only when circuit is OPEN (blocking).
        HALF_OPEN plugins are considered available (probing).

        Args:
            plugin_name: Name of the plugin.

        Returns:
            True if plugin can accept requests, False if circuit is OPEN.
        """
        cb = self._circuit_breakers.get(plugin_name)
        if cb is None:
            return True  # No breaker = no failures = available
        return not cb.is_open

    def update_circuit_metrics(self) -> None:
        """Update Prometheus gauge for all known circuit breaker states."""
        state_map = {CircuitState.CLOSED: 0, CircuitState.HALF_OPEN: 1, CircuitState.OPEN: 2}
        for pname, cb in self._circuit_breakers.items():
            ext_metrics.circuit_breaker_state.labels(plugin=pname).set(
                state_map.get(cb.state, 0)
            )

    # ─── Origin Plugin Auto-Disable ─────────────────────────────────

    def auto_disable_failing_plugins(self) -> int:
        """Auto-disable plugins with high error rate via CircuitBreaker.

        Phase 5 fix: Previously only ORIGIN plugins were auto-disabled.
        Now ALL plugins with error_rate exceeding their tier-specific
        threshold are eligible for auto-disable:
          - ORIGIN plugins: >97% error rate (client-side failures)
          - Non-ORIGIN plugins: >95% error rate (plugin itself is broken,
            e.g. tls_handshake failing on every attempt)
          - ESSENTIAL (Tier 1) plugins are NEVER auto-disabled

        Phase 4: When error rate exceeds threshold, trip the circuit to
        OPEN instead of hard-disabling. The circuit will auto-transition
        to HALF_OPEN after recovery_timeout for probing.
        """
        from config.defaults import PLUGIN_AUTO_DISABLE_ERROR_RATE, PLUGIN_AUTO_DISABLE_MIN_REQUESTS
        from plugin_system import PluginTier
        from config.defaults import PLUGIN_TIER_MAP

        for pname, plugin in list(self._engine._orchestrator.active_plugins.items()):
            ps = plugin.get_stats()
            ptotal = ps.get('total_requests', 0)
            perr = ps.get('error_count', 0)
            if ptotal < 1:
                continue

            error_rate = perr / ptotal
            is_origin = pname in ORIGIN_PLUGINS

            # Tier 1 (ESSENTIAL) plugins are never auto-disabled
            tier_val = PLUGIN_TIER_MAP.get(pname, 2)
            if tier_val == PluginTier.ESSENTIAL:
                continue

            # Determine threshold based on plugin type
            if is_origin:
                threshold = ORIGIN_AUTO_DISABLE_ERROR_RATE
                min_req = ORIGIN_AUTO_DISABLE_MIN_REQUESTS
            else:
                # F5-01: Non-origin plugins also auto-disabled at 95%
                threshold = PLUGIN_AUTO_DISABLE_ERROR_RATE
                min_req = PLUGIN_AUTO_DISABLE_MIN_REQUESTS

            if ptotal >= min_req and error_rate > threshold:
                cb = self.get_circuit_breaker(pname)
                if cb.state != CircuitState.OPEN:
                    cb.force_trip(
                        reason=f"{perr}/{ptotal} errors ({error_rate:.0%})"
                    )
                    logger.warning(
                        f"[CIRCUIT-OPEN] {pname} circuit tripped — "
                        f"{perr}/{ptotal} errors ({error_rate:.0%}), "
                        f"auto-recovery in {CIRCUIT_BREAKER_HALF_OPEN_TIMEOUT:.0f}s"
                    )
                # F5-01 Review: Guard against double-disable race
                if pname in self._engine._orchestrator.active_plugins:
                    plugin = self._engine._orchestrator.active_plugins[pname]
                    freed = plugin.worker_count
                    self._engine._orchestrator.disabled_plugins[pname] = perr
                    plugin.stop()
                    del self._engine._orchestrator.active_plugins[pname]
                    # Redistribute freed workers to remaining active plugins
                    remaining = list(self._engine._orchestrator.active_plugins.keys())
                    if remaining and freed > 0:
                        self._engine._orchestrator.redistribute_workers(
                            from_plugin=pname, to_plugins=remaining, workers=freed
                        )
                actual_workers = sum(
                    p.worker_count for p in self._engine._orchestrator.active_plugins.values()
                )
                self._engine._orchestrator.total_workers = actual_workers
        return sum(p.worker_count for p in self._engine._orchestrator.active_plugins.values())

    # ─── Effectiveness-Based Auto-Disable ────────────────────────────

    def check_effectiveness_auto_disable(self, actual_workers: int) -> int:
        """Phase 4: Auto-disable plugins via CircuitBreaker instead of hard toggle.

        When effectiveness tracker recommends disabling a plugin, the circuit
        is transitioned to OPEN. The plugin is removed from active_plugins
        (backward compat), but the circuit breaker tracks recovery state.
        When circuit transitions to HALF_OPEN, the auto-recovery logic
        will re-enable the plugin for probing.
        """
        if not self._engine._effectiveness_tracker:
            return actual_workers

        for name, plugin in self._engine._orchestrator.active_plugins.items():
            stats = plugin.get_stats()
            total = stats.get("total_requests", 0)
            success = stats.get("success_count", 0)
            errors = stats.get("error_count", 0)
            avg_rtt = stats.get("avg_response_time", 0.0)
            self._engine._effectiveness_tracker.update(
                name, total=total, success=success, errors=errors, avg_rtt_ms=avg_rtt
            )

        elapsed = self._engine._state.attack_duration
        decision = self._engine._effectiveness_tracker.evaluate(
            total_workers=actual_workers, elapsed_seconds=elapsed
        )

        for plugin_name in decision.disabled_plugins:
            if plugin_name in self._engine._orchestrator.active_plugins:
                plugin = self._engine._orchestrator.active_plugins[plugin_name]
                freed_workers = plugin.worker_count
                # Phase 4: Trip circuit to OPEN before disabling
                cb = self.get_circuit_breaker(plugin_name)
                if cb.state != CircuitState.OPEN:
                    cb.force_trip(reason="high_error_rate")
                    logger.warning(
                        f"[CIRCUIT-OPEN] {plugin_name} circuit tripped by effectiveness — "
                        f"auto-recovery in {CIRCUIT_BREAKER_HALF_OPEN_TIMEOUT:.0f}s"
                    )
                if self._engine._orchestrator.auto_disable_plugin(plugin_name, "high_error_rate"):
                    self._engine._state.disabled_plugins.append(plugin_name)
                    if decision.top_plugins:
                        self._engine._orchestrator.redistribute_workers(
                            from_plugin=plugin_name,
                            to_plugins=[
                                p for p in decision.top_plugins
                                if p in self._engine._orchestrator.active_plugins
                            ],
                            workers=freed_workers,
                        )

        # Phase 4: Check circuit breaker states for recovery
        # A plugin in HALF_OPEN state can be re-enabled for probing
        for plugin_name in list(self._engine._state.disabled_plugins):
            cb = self._circuit_breakers.get(plugin_name)
            # Original cooldown-based re-enable (if no circuit breaker)
            if cb is None:
                if self._engine._effectiveness_tracker.can_reenable(plugin_name):
                    if self._engine._effectiveness_tracker.phase != "FOCUS":
                        if plugin_name not in self._engine._orchestrator.active_plugins:
                            self._engine._state.disabled_plugins.remove(plugin_name)
                            if self._engine._effectiveness_tracker:
                                self._engine._effectiveness_tracker.mark_enabled(plugin_name)
                            logger.info(f"[EFFECTIVENESS] Plugin '{plugin_name}' cooldown expired")
            else:
                # Phase 4: Use circuit breaker state for recovery decision
                if cb.state == CircuitState.HALF_OPEN:
                    if plugin_name not in self._engine._orchestrator.active_plugins:
                        # Circuit is probing — allow re-enable
                        if self._engine._effectiveness_tracker.phase != "FOCUS":
                            self._engine._state.disabled_plugins.remove(plugin_name)
                            if self._engine._effectiveness_tracker:
                                self._engine._effectiveness_tracker.mark_enabled(plugin_name)
                            logger.info(
                                f"[CIRCUIT-HALF-OPEN] Plugin '{plugin_name}' "
                                f"probing — allowing re-enable"
                            )
                elif cb.state == CircuitState.CLOSED:
                    # Circuit recovered — definitely re-enable
                    if plugin_name not in self._engine._orchestrator.active_plugins:
                        self._engine._state.disabled_plugins.remove(plugin_name)
                        if self._engine._effectiveness_tracker:
                            self._engine._effectiveness_tracker.mark_enabled(plugin_name)
                        logger.info(
                            f"[CIRCUIT-CLOSED] Plugin '{plugin_name}' recovered"
                        )

        actual_workers = sum(p.worker_count for p in self._engine._orchestrator.active_plugins.values())
        return actual_workers

    # ─── Auto-Recover Disabled Plugins ──────────────────────────────

    def auto_recover_disabled_plugins(self, health: float) -> int:
        """Re-enable disabled plugins when server health improves.

        When the server recovers (health > 0.6 for 5+ ticks) and we have
        disabled plugins, try to re-enable them. Phase 4: Circuit breaker
        state is checked — HALF_OPEN plugins are prioritized for probing.
        """
        if health > 0.6 and self._engine._orchestrator.disabled_plugins:
            _recovery_ticks = self._engine._state.recovery_ticks + 1
            self._engine._state.recovery_ticks = _recovery_ticks

            if _recovery_ticks >= 5:  # 5 consecutive healthy ticks
                recovered = False
                for pname in sorted(self._engine._orchestrator.disabled_plugins.keys(),
                                   key=lambda k: self._engine._orchestrator.disabled_plugins.get(k, 0)):
                    err_count = self._engine._orchestrator.disabled_plugins[pname]

                    # Phase 4: Check circuit breaker before re-enabling
                    cb = self._circuit_breakers.get(pname)
                    if cb and cb.is_open:
                        # Circuit still OPEN — skip recovery, wait for HALF_OPEN
                        continue

                    # F5-07: Only block recovery for err_count > 100 if circuit
                    # is NOT in HALF_OPEN state. HALF_OPEN means the circuit has
                    # already determined the plugin might be healthy again.
                    if err_count > 100:
                        if cb is None or cb.state != CircuitState.HALF_OPEN:
                            continue

                    plugin_cls = self._engine._registry.get_class(pname) if self._engine._registry else None
                    if plugin_cls:
                        try:
                            plugin_instance = plugin_cls()
                        except (TypeError, AttributeError) as e:
                            logger.warning(f"Recovery: plugin '{pname}' instantiation failed: {e}")
                            continue
                    else:
                        plugin_instance = self._engine._registry.get(pname) if self._engine._registry else None
                        if not plugin_instance:
                            continue

                    _session = self._engine._session_getter() if self._engine._session_getter else None
                    if plugin_instance and _session is not None:
                        if self._engine._compute_plugin_workers_fn and self._engine._origin_ips_getter:
                            workers = self._engine._compute_plugin_workers_fn(
                                pname, self._engine._max_workers, self._engine._origin_ips_getter())
                        else:
                            workers = 5
                        if workers > 0:
                            if self._engine._build_attack_context_fn:
                                context = self._engine._build_attack_context_fn(pname, _session, workers)
                            else:
                                continue
                            self._engine._orchestrator.active_plugins[pname] = plugin_instance

                            async def _run_recovered(inst=plugin_instance, ctx=context, name=pname):
                                try:
                                    await inst.run(ctx)
                                except asyncio.CancelledError:
                                    return
                                except (RuntimeError, OSError, ConnectionError, asyncio.TimeoutError) as exc:
                                    logger.warning(f"Recovered plugin {name} error: {exc}")
                                    self._engine._orchestrator.active_plugins.pop(name, None)
                                    self._engine._orchestrator.disabled_plugins[name] = self._engine._orchestrator.disabled_plugins.get(name, 0) + 1
                                    # Phase 4: Trip circuit on recovery failure
                                    recovery_cb = self._circuit_breakers.get(name)
                                    if recovery_cb and recovery_cb.state == CircuitState.HALF_OPEN:
                                        recovery_cb.force_trip(reason="recovery_failed")

                            task = asyncio.create_task(_run_recovered())
                            self._engine._orchestrator.plugin_tasks.append(task)

                            del self._engine._orchestrator.disabled_plugins[pname]
                            # Phase 4: Don't record success at launch time —
                            # let the circuit breaker's normal _record_success()
                            # mechanism handle recovery after the plugin actually
                            # processes requests successfully.
                            logger.info(f"[AUTO-RECOVER] {pname} re-enabled — server health improved ({health:.0%})")
                            recovered = True
                            break

                if not recovered:
                    self._engine._state.recovery_ticks = 0
                else:
                    self._engine._state.recovery_ticks = 0
                    actual_workers = sum(p.worker_count for p in self._engine._orchestrator.active_plugins.values())
                    self._engine._orchestrator.total_workers = actual_workers
        else:
            self._engine._state.recovery_ticks = 0

        return sum(p.worker_count for p in self._engine._orchestrator.active_plugins.values())

    # ─── Escalation Phase ────────────────────────────────────────────

    def run_escalation_phase(self, step: int, actual_workers: int,
                              health: float, fail_rate: float,
                              s5xx_rate: float, timeout_rate: float,
                              should_shrink: bool,
                              shrink_hold_active: bool) -> int:
        """Handle escalation pause/resume and auto-scaling logic.

        v28: Escalation resume checks now run even during HOLD mode.
        Phase 4: Escalation state tracked via Prometheus metrics.
        """
        # Update circuit breaker metrics
        self.update_circuit_metrics()

        # Track escalation state in metrics
        ext_metrics.escalation_state.set(1 if self._engine._state.escalation_paused else 0)

        if timeout_rate > PAUSE_TIMEOUT_RATE:
            if not self._engine._state.escalation_paused:
                self._engine._state.escalation_paused = True
                self._engine._state.escalation_pause_reason = f"timeout={timeout_rate:.0%}"
                self._engine._state.healthy_ticks = 0
                logger.warning(f"[ESCALATION PAUSED] High timeout rate ({timeout_rate:.0%}) — holding workers")
            elif health > 0.5 and timeout_rate < 0.80:
                self._engine._state.healthy_ticks += 1
                if self._engine._state.healthy_ticks >= 5:
                    logger.info(f"[ESCALATION RESUMED] Health stable at {health:.0%} despite timeout rate {timeout_rate:.0%}")
                    self._engine._state.escalation_paused = False
                    self._engine._state.escalation_pause_reason = ""
                    self._engine._state.consecutive_shrinks = 0
                    self._engine._state.step_start = time.monotonic()
                    self._engine._state.shrink_cooldown = 0
                    if self._engine._state.shrink_hold:
                        self._engine._state.shrink_hold = False
                        self._engine._state.hold_recovery_ticks = 0
        elif fail_rate > PAUSE_FAIL_RATE:
            if not self._engine._state.escalation_paused:
                self._engine._state.escalation_paused = True
                self._engine._state.escalation_pause_reason = f"fail={fail_rate:.0%}"
                self._engine._state.healthy_ticks = 0
                logger.warning(f"[ESCALATION PAUSED] High failure rate ({fail_rate:.0%}) — holding workers")
            elif health > 0.5 and fail_rate < 0.60:
                self._engine._state.healthy_ticks += 1
                if self._engine._state.healthy_ticks >= 5:
                    self._engine._state.escalation_paused = False
                    self._engine._state.escalation_pause_reason = ""
                    self._engine._state.consecutive_shrinks = 0
                    self._engine._state.step_start = time.monotonic()
                    self._engine._state.shrink_cooldown = 0
        elif fail_rate > PAUSE_COMBO_FAIL and timeout_rate > PAUSE_COMBO_TIMEOUT:
            if not self._engine._state.escalation_paused:
                self._engine._state.escalation_paused = True
                self._engine._state.escalation_pause_reason = f"fail+timeout={fail_rate:.0%}+{timeout_rate:.0%}"
                self._engine._state.healthy_ticks = 0
                logger.warning(f"[ESCALATION PAUSED] Combined failure+timeout — holding workers")
            elif health > 0.5:
                self._engine._state.healthy_ticks += 1
                if self._engine._state.healthy_ticks >= 5:
                    self._engine._state.escalation_paused = False
                    self._engine._state.escalation_pause_reason = ""
                    self._engine._state.consecutive_shrinks = 0
                    self._engine._state.step_start = time.monotonic()
                    self._engine._state.shrink_cooldown = 0
        else:
            if self._engine._state.escalation_paused and timeout_rate < PAUSE_TIMEOUT_RATE * ESCALATION_RESUME_TIMEOUT_FACTOR:
                self._engine._state.escalation_paused = False
                self._engine._state.escalation_pause_reason = ""
                logger.info(f"[ESCALATION-RESUME] Timeout rate dropped to {timeout_rate:.0%}")

            if health > 0.5:
                self._engine._state.healthy_ticks += 1
            else:
                self._engine._state.healthy_ticks = 0

            if self._engine._state.escalation_paused and self._engine._state.healthy_ticks >= 3:
                self._engine._state.escalation_paused = False
                self._engine._state.escalation_pause_reason = ""
                self._engine._state.consecutive_shrinks = 0
                self._engine._state.step_start = time.monotonic()
                self._engine._state.shrink_cooldown = 0
                if self._engine._state.shrink_hold:
                    self._engine._state.shrink_hold = False
                    self._engine._state.hold_recovery_ticks = 0

        avg_rt = self._engine._stats.avg_response_time
        rt_too_high = avg_rt > 3.0

        # Auto-escalation: scale up every step_duration seconds
        if not self._engine._state.escalation_paused and not rt_too_high and not shrink_hold_active:
            elapsed_step = time.monotonic() - self._engine._state.step_start
            if elapsed_step >= self._engine._step_duration and self._engine._orchestrator.total_workers < self._engine._max_workers:
                delta = min(step, self._engine._max_workers - self._engine._orchestrator.total_workers)
                added = self._engine._orchestrator.scale_plugins(delta)
                self._engine._orchestrator.total_workers += added
                if added > 0:
                    ext_metrics.scaling_events_total.labels(direction="scale_up").inc(added)
                    self._engine._state.step_start = time.monotonic()

        # v28: Pressure scaling
        if (not self._engine._state.escalation_paused and not rt_too_high
                and s5xx_rate > 0.15 and s5xx_rate < 0.5
                and timeout_rate < 0.3 and not shrink_hold_active):
            elapsed_step = time.monotonic() - self._engine._state.step_start
            if elapsed_step >= self._engine._step_duration * 2 and self._engine._orchestrator.total_workers < self._engine._max_workers:
                pressure_step = max(step // 2, 2)
                delta = min(pressure_step, self._engine._max_workers - self._engine._orchestrator.total_workers)
                added = self._engine._orchestrator.scale_plugins(delta)
                self._engine._orchestrator.total_workers += added
                if added > 0:
                    ext_metrics.scaling_events_total.labels(direction="scale_up").inc(added)
                    logger.info(f"[PRESSURE] Server under load (5xx={s5xx_rate:.0%}), adding {added} workers")
                    self._engine._state.step_start = time.monotonic()

        # Apply manual delta
        if self._engine._state.manual_delta != 0:
            if self._engine._state.manual_delta > 0:
                to_add = min(self._engine._state.manual_delta, self._engine._max_workers - self._engine._orchestrator.total_workers)
                added = self._engine._orchestrator.scale_plugins(to_add)
                self._engine._orchestrator.total_workers += added
            else:
                to_remove = min(abs(self._engine._state.manual_delta), self._engine._orchestrator.total_workers)
                removed = self._engine._orchestrator.scale_all_plugins(-to_remove)
                ext_metrics.scaling_events_total.labels(direction="scale_down").inc(removed)
                self._engine._orchestrator.total_workers = sum(p.worker_count for p in self._engine._orchestrator.active_plugins.values())
            self._engine._state.manual_delta = 0

        return self._engine._orchestrator.total_workers