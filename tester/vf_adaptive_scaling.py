"""Adaptive scaling engine for attack worker management.

Controls the dynamic scaling of attack workers based on server health,
WAF detection, and error rates. Extracted from VF_TESTER.py.

Architecture: Phase 3 — AdaptiveScalingEngine Extraction

v30: CRITICAL FIX — Timeout double-counting death spiral.
The old logic used raw fail_rate (which includes timeouts) alongside
timeout_rate in shrink/pause thresholds. This double-counted timeouts:
  timeout_rate > 45% AND fail_rate > 65% meant:
  timeout > 45% AND (timeout + non_timeout) > 65% → timeout counted 1.5x
This caused premature shrinking that created a death spiral the attack
never recovered from.

v30 fix: Use non_timeout_fail_rate (computed from stats.fail - stats.timeout_errors)
instead of raw fail_rate. Thresholds adjusted accordingly.

v28: Previous CRITICAL FIX — Attack auto-stop (death spiral) bug.
The old logic had a HOLD mode deadlock: after 5 consecutive shrinks,
the system entered HOLD which blocked the entire escalation phase.
Since the only way to reset consecutive_shrinks was inside the
escalation phase, this created a circular dependency → permanent stuck.
New logic:
  - HOLD is now a temporary state with auto-expiry (30 seconds)
  - Escalation resume checks run even during HOLD (to detect recovery)
  - Shrink thresholds redesigned for ATTACK tool: server 5xx = attack
    is WORKING, not a reason to shrink. Only shrink when CLIENT can't
    connect (extreme timeouts, connection failures).
  - Gradual recovery: after HOLD expires, slowly add workers back
  - "Pressure mode": when server returns 5xx, maintain or increase
    pressure instead of shrinking
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Tuple

from logging_config import get_logger

logger = get_logger(__name__)

# Re-export for use in engine methods
from tester.vf_plugin_orchestrator import ORIGIN_PLUGINS

# ─── v28: Attack-Aware Thresholds ─────────────────────────────────────
# For an ATTACK tool, server 5xx errors are a POSITIVE signal — the
# attack is working. Only CLIENT-SIDE failures (can't connect, extreme
# timeouts) should trigger shrink.

# How many seconds before HOLD auto-expires and re-escalation is tried
HOLD_EXPIRY_SECONDS: float = 30.0

# How many consecutive shrinks before entering HOLD (raised from 5 to 8)
HOLD_CONSECUTIVE_SHRINK_THRESHOLD: int = 8

# After HOLD expires, how many workers to add per recovery step
HOLD_RECOVERY_STEP: int = 5

# How often (in ticks) to add workers during HOLD recovery
HOLD_RECOVERY_INTERVAL: int = 5

# Shrink trigger: only when CLIENT can't connect at all
# v30: fail_rate is now NON-TIMEOUT fail rate (excludes timeouts).
# Previously, fail_rate included timeouts, causing double-counting:
#   timeout_rate > 45% AND fail_rate > 65% would mean:
#   timeout > 45% AND (timeout + non_timeout) > 65% → timeout counted 1.5x
# Now fail_rate = non-timeout failures only, so thresholds are lower.

# Extreme: connection completely broken (>60% timeouts + >30% non-timeout fail)
SHRINK_EXTREME_TIMEOUT_RATE: float = 0.60
SHRINK_EXTREME_FAIL_RATE: float = 0.30

# High: severe client connectivity issues (>45% timeouts + >20% non-timeout fail)
SHRINK_HIGH_TIMEOUT_RATE: float = 0.45
SHRINK_HIGH_FAIL_RATE: float = 0.20

# Moderate: client struggling (>30% timeouts + >15% non-timeout fail)
SHRINK_MODERATE_TIMEOUT_RATE: float = 0.30
SHRINK_MODERATE_FAIL_RATE: float = 0.15

# Escalation pause: client connectivity is degrading
# v30: fail_rate is now non-timeout fail rate — adjust thresholds
# BUG-FIX v32: Raised PAUSE_TIMEOUT_RATE from 0.50 to 0.65.
# An attack tool should tolerate higher timeout rates — 50% timeouts
# means the server IS struggling under load, which is the ATTACK WORKING.
# The old 0.50 threshold caused escalation to permanently freeze at
# initial workers because the else block (recovery) was unreachable
# when timeout_rate > 50% persisted.
PAUSE_TIMEOUT_RATE: float = 0.65
PAUSE_FAIL_RATE: float = 0.40
PAUSE_COMBO_FAIL: float = 0.20
PAUSE_COMBO_TIMEOUT: float = 0.35


@dataclass
class ScalingState:
    """Mutable state for the adaptive scaling engine.

    Encapsulates all per-loop-iteration state that was previously stored
    as instance attributes on VFTester during the dashboard loop.
    """
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

    # Additional loop state (was instance attrs on VFTester)
    min_workers: int = 10
    dynamic_step: int = 50
    last_shrink_log: float = 0.0
    healthy_ticks: int = 0
    manual_delta: int = 0
    recovery_ticks: int = 0
    no_active_plugins_logged: bool = False

    # v28: HOLD recovery tracking
    hold_start_time: float = 0.0  # When HOLD mode started
    hold_recovery_ticks: int = 0  # Ticks since HOLD recovery began
    attack_duration: float = 0.0  # Total attack duration for context


class AdaptiveScalingEngine:
    """Manages adaptive worker scaling during attack.

    v28: Redesigned to prevent death spiral / auto-stop bug.

    Key design principle: This is an ATTACK tool. Server 5xx errors
    mean the attack is WORKING — the server is struggling under load.
    The old logic treated 5xx as a signal to shrink, which is backwards
    for an attack tool. Now:
      - Server 5xx = keep pressing (or even increase pressure)
      - Client timeouts/connection failures = reduce workers (we can't reach the server)
      - HOLD mode auto-expires after 30 seconds
      - Gradual recovery from HOLD instead of permanent stuck

    Args:
        orchestrator: PluginOrchestrator instance for scaling workers.
        health_monitor: ServerHealthMonitor for health scores.
        stats: Stats instance for request metrics.
        keyboard: KeyboardHandler for runtime commands.
        evasion: Evasion manager for WAF updates.
        stop_event: asyncio.Event to signal attack stop.
        registry: PluginRegistry for plugin instantiation during recovery.
        waf_getter: Callable returning current detected_waf string.
        waf_setter: Callable to set detected_waf string.
        session_getter: Callable returning current aiohttp session or None.
        compute_plugin_workers_fn: Callable(pname, max_workers, origin_ips) -> int.
        build_attack_context_fn: Callable(pname, session, workers) -> AttackContext.
        origin_ips_getter: Callable returning list of origin IPs.
        step: Base step size for worker scaling.
        step_duration: Seconds between auto-escalation steps.
        max_workers: Maximum worker count.
        initial_workers: Initial worker count.
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

        # Config
        self._step = step
        self._step_duration = step_duration
        self._max_workers = max_workers
        self._initial_workers = initial_workers

        # Mutable state
        self._state = ScalingState(
            step_start=time.time(),
            min_workers=max(initial_workers, 10),
            dynamic_step=step,
        )

    @property
    def state(self) -> ScalingState:
        """Read-only access to current scaling state (for dashboards/tests)."""
        return self._state

    def reset(self) -> None:
        """Reset scaling state for a new attack run."""
        self._state = ScalingState(
            step_start=time.time(),
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
        # v20: Health monitor uses raw server-side signals (no disabled_plugin_fails)
        health = self._health.check(self._stats)

        # Check keyboard
        cmd = self._check_keyboard()
        if cmd == 'q':
            return cmd

        # v28: Track attack duration for context-aware decisions
        self._state.attack_duration = time.time() - self._stats.t0 if self._stats.t0 > 0 else 0

        # v18: Compute rates for adaptive decisions
        # BUG-FIX v34: Use get_snapshot() for atomic reads instead of
        # reading stats attributes directly. Direct reads of stats.fail,
        # stats.timeout_errors etc. can be inconsistent between reads
        # (e.g., timeout_errors > fail for a brief moment), causing
        # non_timeout_fail_rate to go negative.
        snap = self._stats.get_snapshot()
        total = max(snap["total"], 1)
        fail_rate = snap["fail"] / total
        timeout_rate = snap["timeout_errors"] / total
        s5xx_rate = snap["server_errors"] / total
        # v30→v31: Compute non-timeout fail rate to avoid double-counting.
        # stats.fail INCLUDES timeout_errors (code=0 with error message),
        # so using both timeout_rate and fail_rate in shrink/pause
        # thresholds counted timeouts 1.5x — triggering premature shrink.
        non_timeout_fail = max(snap["fail"] - snap["timeout_errors"], 0)
        non_timeout_fail_rate = non_timeout_fail / total

        # Actual running workers (from plugins)
        actual_workers = sum(p.worker_count for p in self._orchestrator.active_plugins.values())
        self._orchestrator.total_workers = actual_workers  # v18: sync with reality

        # WAF runtime detection from plugin classifiers
        self._check_waf_runtime(health)

        # Auto-disable failing origin plugins
        actual_workers = self._auto_disable_failing_plugins()

        # Auto-recover disabled plugins when health improves
        actual_workers = self._auto_recover_disabled_plugins(health)

        # Compute adaptive step size
        self._state.dynamic_step = self._compute_dynamic_step(health)

        # v28→v30: Auto-shrink workers — redesigned for ATTACK tool
        # Only shrink when CLIENT connectivity is broken (timeouts/failures),
        # NOT when server returns 5xx (that means attack is working!)
        # v30: Pass non_timeout_fail_rate instead of fail_rate to avoid
        # double-counting timeouts (timeout already checked separately).
        should_shrink, shrink_hold_active = self._auto_shrink_workers(
            health, non_timeout_fail_rate, s5xx_rate, timeout_rate, actual_workers)

        # v28→v30: Escalation pause/resume and auto-scaling
        # Now runs even during HOLD mode (to detect recovery and exit HOLD)
        # v30: Pass non_timeout_fail_rate instead of fail_rate to avoid
        # double-counting timeouts in pause thresholds.
        self._run_escalation_phase(
            self._state.dynamic_step, actual_workers, health, non_timeout_fail_rate,
            s5xx_rate, timeout_rate, should_shrink, shrink_hold_active)

        # Update stats
        self._stats.users = self._orchestrator.total_workers

        return None

    # ─── Extracted Methods ──────────

    def _check_keyboard(self) -> str | None:
        """Handle keyboard input for +/- and quit commands.

        Processes keyboard commands from the user:
        - '+': increases manual delta by step size
        - '-': decreases manual delta by step size
        - 'q': signals attack to stop

        Returns:
            'q' if quit was requested, None otherwise.
        """
        if self._keyboard is None:
            return None
        cmd = self._keyboard.get_command()
        if cmd == 'q':
            logger.warning(f"\n  [QUIT] Stopping attack...")
            if self._stop is not None:
                self._stop.set()
            return 'q'
        elif cmd == '+':
            self._state.manual_delta += self._step
        elif cmd == '-':
            self._state.manual_delta -= self._step
        return None

    def _check_waf_runtime(self, health: float) -> None:
        """Check plugin classifiers for runtime WAF detection.

        Plugins classify responses and may detect WAFs that FINDER missed.
        If any plugin detected a WAF, feed it to the evasion manager.
        """
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
                        logger.warning(f"[WAF-DETECT] Runtime detected WAF: {detected} (from {pname} responses)")
                        break

    def _auto_disable_failing_plugins(self) -> int:
        """Auto-disable origin plugins with >97% error rate.

        HTTP target plugins' failures indicate server health — disabling
        them would hide the fact that the server is down. Only disable
        ORIGIN plugins (their failures are client-side, e.g. unreachable
        origin IPs, not the server's fault).
        """
        for pname, plugin in list(self._orchestrator.active_plugins.items()):
            if pname not in ORIGIN_PLUGINS:
                continue  # v20: Don't auto-disable HTTP target plugins
            ps = plugin.get_stats()
            ptotal = ps.get('total_requests', 0)
            perr = ps.get('error_count', 0)
            if ptotal >= 50 and perr / ptotal > 0.97:
                self._orchestrator.disabled_plugins[pname] = perr
                plugin.stop()
                del self._orchestrator.active_plugins[pname]
                logger.warning(f"[AUTO-DISABLE] {pname} disabled — {perr}/{ptotal} errors ({perr/ptotal:.0%})")
                actual_workers = sum(p.worker_count for p in self._orchestrator.active_plugins.values())
                self._orchestrator.total_workers = actual_workers
        return sum(p.worker_count for p in self._orchestrator.active_plugins.values())

    def _auto_recover_disabled_plugins(self, health: float) -> int:
        """Re-enable disabled plugins when server health improves.

        When the server recovers (health > 0.6 for 5+ ticks) and we have
        disabled plugins, try to re-enable them.
        """
        if health > 0.6 and self._orchestrator.disabled_plugins:
            _recovery_ticks = self._state.recovery_ticks + 1
            self._state.recovery_ticks = _recovery_ticks

            if _recovery_ticks >= 5:  # 5 consecutive healthy ticks
                recovered = False
                for pname in sorted(self._orchestrator.disabled_plugins.keys(),
                                   key=lambda k: self._orchestrator.disabled_plugins.get(k, 0)):
                    err_count = self._orchestrator.disabled_plugins[pname]
                    if err_count > 100:
                        continue

                    plugin_cls = self._registry.get_class(pname) if self._registry else None
                    if plugin_cls:
                        try:
                            plugin_instance = plugin_cls()
                        except (TypeError, AttributeError) as e:
                            logger.warning(f"Recovery: plugin '{pname}' instantiation failed: {e}")
                            continue
                    else:
                        plugin_instance = self._registry.get(pname) if self._registry else None
                        if not plugin_instance:
                            continue

                    _session = self._session_getter() if self._session_getter else None
                    if plugin_instance and _session is not None:
                        if self._compute_plugin_workers_fn and self._origin_ips_getter:
                            workers = self._compute_plugin_workers_fn(
                                pname, self._max_workers, self._origin_ips_getter())
                        else:
                            workers = 5
                        if workers > 0:
                            if self._build_attack_context_fn:
                                context = self._build_attack_context_fn(pname, _session, workers)
                            else:
                                continue
                            self._orchestrator.active_plugins[pname] = plugin_instance

                            async def _run_recovered(inst=plugin_instance, ctx=context, name=pname):
                                try:
                                    await inst.run(ctx)
                                except asyncio.CancelledError:
                                    return
                                except (RuntimeError, OSError, ConnectionError, asyncio.TimeoutError) as exc:
                                    logger.warning(f"Recovered plugin {name} error: {exc}")
                                    # v31 FIX: Clean up crashed recovered plugin — same as
                                    # launch_plugins._run_plugin. Without this, a crashed
                                    # recovered plugin stays in active_plugins as a zombie:
                                    # - actual_workers includes its stale worker_count
                                    # - It's never re-disabled, so auto-disable can't catch it
                                    # - The scaling engine thinks it's still running
                                    self._orchestrator.active_plugins.pop(name, None)
                                    self._orchestrator.disabled_plugins[name] = self._orchestrator.disabled_plugins.get(name, 0) + 1

                            task = asyncio.create_task(_run_recovered())
                            self._orchestrator.plugin_tasks.append(task)

                            del self._orchestrator.disabled_plugins[pname]
                            logger.info(f"[AUTO-RECOVER] {pname} re-enabled — server health improved ({health:.0%})")
                            recovered = True
                            break

                if not recovered:
                    self._state.recovery_ticks = 0
                else:
                    self._state.recovery_ticks = 0
                    actual_workers = sum(p.worker_count for p in self._orchestrator.active_plugins.values())
                    self._orchestrator.total_workers = actual_workers
        else:
            self._state.recovery_ticks = 0

        return sum(p.worker_count for p in self._orchestrator.active_plugins.values())

    def _compute_dynamic_step(self, health: float) -> int:
        """Compute adaptive step size based on server health.

        v28: For an attack tool, lower health = server is struggling =
        attack is working. We should still escalate, just more carefully.
        Only when CLIENT connectivity is broken do we use tiny steps.
        """
        if health > 0.5:
            return self._step
        elif health > 0.3:
            return max(self._step // 2, 3)
        elif health > 0.15:
            return max(self._step // 3, 2)
        else:
            return max(self._step // 5, 1)  # Still escalate, just slowly

    def _auto_shrink_workers(self, health: float, fail_rate: float,
                              s5xx_rate: float, timeout_rate: float,
                              actual_workers: int) -> Tuple[bool, bool]:
        """Auto-shrink workers when CLIENT connectivity is broken.

        v30: CRITICAL FIX — fail_rate parameter is now NON-TIMEOUT fail rate.
        The old logic used raw fail_rate (which includes timeouts), causing
        double-counting: timeout_rate was checked AND fail_rate contained
        the same timeouts. This made the shrink trigger fire when timeout=50%
        and non-timeout fail was only 10% — because fail_rate=60% (50%+10%)
        exceeded the 65% threshold. The attack would shrink prematurely,
        creating a death spiral that never recovered.

        Now fail_rate = non_timeout_fail_rate (computed in tick()).
        Thresholds have been adjusted accordingly (lower values since
        we're no longer counting timeouts twice).

        Shrink is triggered when the CLIENT can't connect:
        - Extreme: >60% timeouts + >30% non-timeout fail
        - High: >45% timeouts + >20% non-timeout fail
        - Moderate: >30% timeouts + >15% non-timeout fail

        Server 5xx errors are logged but do NOT trigger shrink.
        Instead, they may trigger a "pressure hold" where we maintain
        current worker count (don't shrink, but don't escalate either)
        until we see if the server recovers or we can push harder.

        The HOLD deadlock is fixed:
        - HOLD now has a 30-second auto-expiry
        - Escalation resume checks run even during HOLD
        - After HOLD expires, gradual re-escalation begins
        """
        # ── v28: New shrink trigger logic ──
        # Only shrink when CLIENT can't connect to the server.
        # Server 5xx = attack is WORKING → do NOT shrink for this.

        # Calculate CLIENT connectivity score (how well WE can reach the server)
        # Timeouts and connection failures = CLIENT problems
        # 5xx responses = SERVER problems (we CAN connect, server is responding)
        # v30: fail_rate is now non_timeout_fail_rate (passed from tick()),
        # so we can use it directly as the secondary connectivity indicator.
        # No need for separate client_fail_rate — fail_rate IS the non-timeout fail rate.

        should_shrink = False
        shrink_severity = "moderate"  # Default severity

        # Extreme: Client connectivity almost completely broken
        if timeout_rate > SHRINK_EXTREME_TIMEOUT_RATE and fail_rate > SHRINK_EXTREME_FAIL_RATE:
            should_shrink = True
            shrink_severity = "extreme"
        # High: Client connectivity severely degraded
        elif timeout_rate > SHRINK_HIGH_TIMEOUT_RATE and fail_rate > SHRINK_HIGH_FAIL_RATE:
            should_shrink = True
            shrink_severity = "high"
        # Moderate: Client connectivity noticeably degraded
        elif timeout_rate > SHRINK_MODERATE_TIMEOUT_RATE and fail_rate > SHRINK_MODERATE_FAIL_RATE:
            should_shrink = True
            shrink_severity = "moderate"

        # v28: Special case — if server is returning 5xx BUT client can still connect,
        # this is actually GOOD for an attack tool. Log it but don't shrink.
        if s5xx_rate > 0.3 and not should_shrink:
            # Server is under heavy load but we can still reach it — PRESS HARDER
            logger.info(f"[PRESSURE] Server returning {s5xx_rate:.0%} 5xx — attack is working, maintaining pressure ({actual_workers} workers)")

        if should_shrink and actual_workers > self._state.min_workers:
            if self._state.shrink_cooldown <= 0:
                # v28: Much gentler shrink — never remove more than 1/3 of workers
                if shrink_severity == "extreme":
                    to_remove = max(actual_workers // 3, 3)
                elif shrink_severity == "high":
                    to_remove = max(actual_workers // 4, 2)
                else:
                    to_remove = max(actual_workers // 5, 1)

                removed = self._orchestrator.scale_all_plugins(-to_remove)
                self._orchestrator.total_workers = sum(p.worker_count for p in self._orchestrator.active_plugins.values())

                now = time.time()
                if removed > 0:
                    logger.warning(f"[AUTO-SHRINK] Client connectivity degraded (timeout={timeout_rate:.0%}, fail={fail_rate:.0%}) → removed {removed} workers (now {self._orchestrator.total_workers})")
                    self._state.last_shrink_log = now
                elif now - self._state.last_shrink_log > 5:
                    logger.warning(f"[AUTO-SHRINK] Client connectivity degraded but minimum workers reached ({self._orchestrator.total_workers})")
                    self._state.last_shrink_log = now

                self._state.step_start = time.time()
                self._state.shrink_cooldown = 10  # v28: Longer cooldown (was 8)
                self._state.consecutive_shrinks += 1
            else:
                self._state.shrink_cooldown -= 1

        # v28: HOLD mode with auto-expiry — prevents permanent stuck state
        shrink_hold_active = False
        if self._state.consecutive_shrinks >= HOLD_CONSECUTIVE_SHRINK_THRESHOLD and actual_workers > self._state.min_workers:
            now = time.time()

            if not self._state.shrink_hold:
                # Enter HOLD mode — record start time
                self._state.shrink_hold = True
                self._state.hold_start_time = now
                self._state.hold_recovery_ticks = 0
                logger.warning(f"[HOLD] Entered hold mode at {actual_workers} workers (auto-expiry in {HOLD_EXPIRY_SECONDS:.0f}s)")

            # Check if HOLD should auto-expire
            hold_duration = now - self._state.hold_start_time

            if hold_duration >= HOLD_EXPIRY_SECONDS:
                # HOLD expired — try gradual recovery
                self._state.hold_recovery_ticks += 1

                if self._state.hold_recovery_ticks % HOLD_RECOVERY_INTERVAL == 0:
                    # Add a small number of workers back
                    recovery_step = min(HOLD_RECOVERY_STEP, self._max_workers - self._orchestrator.total_workers)
                    if recovery_step > 0:
                        added = self._orchestrator.scale_plugins(recovery_step)
                        self._orchestrator.total_workers += added
                        if added > 0:
                            logger.info(f"[HOLD-RECOVERY] Adding {added} workers (hold expired, gradual re-escalation, now {self._orchestrator.total_workers})")
                            self._state.step_start = time.time()

                    # If we've recovered enough workers, exit HOLD
                    if self._orchestrator.total_workers >= self._state.min_workers * 2:
                        logger.info(f"[HOLD-EXIT] Workers recovered to {self._orchestrator.total_workers}, exiting hold mode")
                        self._state.shrink_hold = False
                        self._state.consecutive_shrinks = 0
                        self._state.hold_recovery_ticks = 0
                        self._state.escalation_paused = False
                        self._state.escalation_pause_reason = ""
                        self._state.step_start = time.time()
            else:
                # Still in HOLD — don't shrink but don't escalate either
                if should_shrink:
                    # Only log once per 5 seconds
                    if now - self._state.last_shrink_log > 5:
                        logger.info(f"[HOLD] Holding at {self._orchestrator.total_workers} workers (expiry in {HOLD_EXPIRY_SECONDS - hold_duration:.0f}s)")
                        self._state.last_shrink_log = now
                    should_shrink = False
                shrink_hold_active = True

        # v28: If shrink_hold is active but consecutive_shrinks dropped (via recovery),
        # make sure hold state is cleaned up
        if self._state.shrink_hold and self._state.consecutive_shrinks < HOLD_CONSECUTIVE_SHRINK_THRESHOLD:
            self._state.shrink_hold = False
            self._state.hold_recovery_ticks = 0

        return should_shrink, shrink_hold_active

    def _run_escalation_phase(self, step: int, actual_workers: int,
                               health: float, fail_rate: float,
                               s5xx_rate: float, timeout_rate: float,
                               should_shrink: bool,
                               shrink_hold_active: bool) -> int:
        """Handle escalation pause/resume and auto-scaling logic.

        v28: Escalation resume checks now run even during HOLD mode.
        This fixes the deadlock where HOLD blocked escalation, and
        escalation resume was the only way to exit HOLD.

        The old logic had:
          if not shrink_hold_active:
              # ... pause/resume checks ...
              # Only way to reset consecutive_shrinks was here
          # DEADLOCK: HOLD blocks this block, so consecutive_shrinks never resets

        New logic:
          - Pause/resume checks always run (they're about server health)
          - Only auto-escalation is blocked during HOLD
          - consecutive_shrinks can be reset during HOLD if health recovers
          - This breaks the circular dependency
        """
        # v28: Escalation pause/resume checks run REGARDLESS of hold state
        # This allows recovery from HOLD when conditions improve

        # v28: Pause escalation when CLIENT connectivity is broken
        # (not when server returns 5xx — that's the attack working)
        # BUG-FIX v32: Added recovery path INSIDE the pause conditions.
        # Previously, when timeout_rate > PAUSE_TIMEOUT_RATE, the else
        # block (where healthy_ticks increments) was unreachable, causing
        # permanent pause. Now, healthy_ticks can increment even while
        # paused if health is acceptable and timeout_rate is not critical.
        if timeout_rate > PAUSE_TIMEOUT_RATE:
            if not self._state.escalation_paused:
                self._state.escalation_paused = True
                self._state.escalation_pause_reason = f"timeout={timeout_rate:.0%}"
                self._state.healthy_ticks = 0
                logger.warning(f"[ESCALATION PAUSED] High timeout rate ({timeout_rate:.0%}) — holding workers")
            # BUG-FIX v32: Recovery path inside pause — if health is decent
            # and timeout_rate is not extreme (>0.80), allow gradual recovery
            elif health > 0.5 and timeout_rate < 0.80:
                self._state.healthy_ticks += 1
                if self._state.healthy_ticks >= 5:
                    logger.info(f"[ESCALATION RESUMED] Health stable at {health:.0%} despite timeout rate {timeout_rate:.0%} (ticks={self._state.healthy_ticks})")
                    self._state.escalation_paused = False
                    self._state.escalation_pause_reason = ""
                    self._state.consecutive_shrinks = 0
                    self._state.step_start = time.time()
                    self._state.shrink_cooldown = 0
                    if self._state.shrink_hold:
                        logger.info(f"[HOLD-EXIT] Escalation resumed, exiting hold mode")
                        self._state.shrink_hold = False
                        self._state.hold_recovery_ticks = 0
        elif fail_rate > PAUSE_FAIL_RATE:
            if not self._state.escalation_paused:
                self._state.escalation_paused = True
                self._state.escalation_pause_reason = f"fail={fail_rate:.0%}"
                self._state.healthy_ticks = 0
                logger.warning(f"[ESCALATION PAUSED] High failure rate ({fail_rate:.0%}) — holding workers")
            # BUG-FIX v32: Same recovery path for fail_rate pause
            elif health > 0.5 and fail_rate < 0.60:
                self._state.healthy_ticks += 1
                if self._state.healthy_ticks >= 5:
                    logger.info(f"[ESCALATION RESUMED] Health stable despite fail rate {fail_rate:.0%}")
                    self._state.escalation_paused = False
                    self._state.escalation_pause_reason = ""
                    self._state.consecutive_shrinks = 0
                    self._state.step_start = time.time()
                    self._state.shrink_cooldown = 0
        elif fail_rate > PAUSE_COMBO_FAIL and timeout_rate > PAUSE_COMBO_TIMEOUT:
            if not self._state.escalation_paused:
                self._state.escalation_paused = True
                self._state.escalation_pause_reason = f"fail+timeout={fail_rate:.0%}+{timeout_rate:.0%}"
                self._state.healthy_ticks = 0
                logger.warning(f"[ESCALATION PAUSED] Combined failure+timeout — holding workers")
            # BUG-FIX v32: Same recovery path for combo pause
            elif health > 0.5:
                self._state.healthy_ticks += 1
                if self._state.healthy_ticks >= 5:
                    logger.info(f"[ESCALATION RESUMED] Health stable despite combo {fail_rate:.0%}+{timeout_rate:.0%}")
                    self._state.escalation_paused = False
                    self._state.escalation_pause_reason = ""
                    self._state.consecutive_shrinks = 0
                    self._state.step_start = time.time()
                    self._state.shrink_cooldown = 0
        else:
            # v28: Health recovery — allow resuming even during HOLD
            # This is the key fix: escalation_paused can be cleared
            # even when shrink_hold_active is True, which allows
            # consecutive_shrinks to be reset, breaking the deadlock.
            if health > 0.5:  # v28: Lowered from 0.6 — attack tool should be more aggressive
                self._state.healthy_ticks += 1
            else:
                self._state.healthy_ticks = 0

            if self._state.escalation_paused and self._state.healthy_ticks >= 3:
                logger.info(f"[ESCALATION RESUMED] Health stable for {self._state.healthy_ticks} ticks (fail={fail_rate:.0%}, timeout={timeout_rate:.0%})")
                self._state.escalation_paused = False
                self._state.escalation_pause_reason = ""
                self._state.consecutive_shrinks = 0  # v28: Reset shrink count on resume
                self._state.step_start = time.time()
                self._state.shrink_cooldown = 0
                # v28: Also exit HOLD if we were in it
                if self._state.shrink_hold:
                    logger.info(f"[HOLD-EXIT] Escalation resumed, exiting hold mode")
                    self._state.shrink_hold = False
                    self._state.hold_recovery_ticks = 0

        # v18: Adaptive response-time-based scaling
        avg_rt = self._stats.avg_response_time
        rt_too_high = avg_rt > 3.0

        # Auto-escalation: scale up every step_duration seconds
        # v28: Only blocked by escalation_paused or rt_too_high, NOT by HOLD
        # (HOLD recovery has its own escalation logic in _auto_shrink_workers)
        if not self._state.escalation_paused and not rt_too_high and not shrink_hold_active:
            elapsed_step = time.time() - self._state.step_start
            if elapsed_step >= self._step_duration and self._orchestrator.total_workers < self._max_workers:
                delta = min(step, self._max_workers - self._orchestrator.total_workers)
                added = self._orchestrator.scale_plugins(delta)
                self._orchestrator.total_workers += added
                if added > 0:
                    self._state.step_start = time.time()

        # v28: If server is returning 5xx but we can still connect (client OK),
        # this is a "pressure" situation — maintain or slightly increase workers
        if (not self._state.escalation_paused and not rt_too_high
                and s5xx_rate > 0.15 and s5xx_rate < 0.5
                and timeout_rate < 0.3 and not shrink_hold_active):
            # Server is under load — good! Add small pressure increments
            elapsed_step = time.time() - self._state.step_start
            if elapsed_step >= self._step_duration * 2 and self._orchestrator.total_workers < self._max_workers:
                # Add half the normal step — gentle pressure increase
                pressure_step = max(step // 2, 2)
                delta = min(pressure_step, self._max_workers - self._orchestrator.total_workers)
                added = self._orchestrator.scale_plugins(delta)
                self._orchestrator.total_workers += added
                if added > 0:
                    logger.info(f"[PRESSURE] Server under load (5xx={s5xx_rate:.0%}), adding {added} workers (now {self._orchestrator.total_workers})")
                    self._state.step_start = time.time()

        # Apply manual delta (always allowed, even when paused)
        if self._state.manual_delta != 0:
            if self._state.manual_delta > 0:
                to_add = min(self._state.manual_delta, self._max_workers - self._orchestrator.total_workers)
                added = self._orchestrator.scale_plugins(to_add)
                self._orchestrator.total_workers += added
            else:
                to_remove = min(abs(self._state.manual_delta), self._orchestrator.total_workers)
                removed = self._orchestrator.scale_all_plugins(-to_remove)
                self._orchestrator.total_workers = sum(p.worker_count for p in self._orchestrator.active_plugins.values())
            self._state.manual_delta = 0

        return self._orchestrator.total_workers
