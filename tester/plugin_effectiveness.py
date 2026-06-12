#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugin_effectiveness — Plugin effectiveness tracking and auto-select engine.

Phase 0: Foundation for the 80/20 auto-select system.
Tracks per-plugin success rates and computes effectiveness scores,
enabling automatic focus on the most productive plugins.

Architecture:
  Probe Phase (0-15s):  All plugins run with minimal workers
  Analyze Phase (15-30s): Score plugins, rank by effectiveness
  Focus Phase (30s+):    Only top-K plugins get full workers
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from logging_config import get_logger
from plugin_system import PluginTier, PluginEffectivenessScore

logger = get_logger(__name__)

from config.defaults import (
    PLUGIN_EFFECTIVENESS_PROBE_DURATION,
    PLUGIN_EFFECTIVENESS_PROBE_WORKERS,
    PLUGIN_EFFECTIVENESS_TOP_K,
    PLUGIN_EFFECTIVENESS_MIN_WORKERS,
    PLUGIN_EFFECTIVENESS_REEVAL_INTERVAL,
    PLUGIN_AUTO_DISABLE_COOLDOWN,
)


class EffectivenessPhase:
    """Phases of the auto-select lifecycle."""
    PROBE = "PROBE"
    ANALYZE = "ANALYZE"
    FOCUS = "FOCUS"


@dataclass
class AutoSelectDecision:
    """Result of an effectiveness evaluation cycle."""
    phase: str = EffectivenessPhase.PROBE
    top_plugins: List[str] = field(default_factory=list)
    disabled_plugins: List[str] = field(default_factory=list)
    enabled_plugins: List[str] = field(default_factory=list)
    worker_allocation: Dict[str, int] = field(default_factory=dict)
    reason: str = ""


class PluginEffectivenessTracker:
    """Tracks and evaluates plugin effectiveness during attack.

    Usage:
        tracker = PluginEffectivenessTracker()
        tracker.update("page_flood", total=1000, success=300, errors=700, avg_rtt=250)
        decision = tracker.evaluate(total_workers=455)
    """

    def __init__(self, top_k: int = PLUGIN_EFFECTIVENESS_TOP_K) -> None:
        self._scores: Dict[str, PluginEffectivenessScore] = {}
        self._top_k = top_k
        self._phase: str = EffectivenessPhase.PROBE
        self._start_time: float = time.monotonic()
        self._last_eval_time: float = 0.0
        self._last_decision: AutoSelectDecision = AutoSelectDecision()

    @property
    def phase(self) -> str:
        return self._phase

    @property
    def scores(self) -> Dict[str, PluginEffectivenessScore]:
        return dict(self._scores)

    @property
    def last_decision(self) -> AutoSelectDecision:
        return self._last_decision

    def register_plugin(self, name: str, tier: PluginTier = PluginTier.SITUATIONAL) -> None:
        if name not in self._scores:
            self._scores[name] = PluginEffectivenessScore(
                plugin_name=name, tier=tier, is_active=True,
            )
            logger.debug(f"[EFFECTIVENESS] Registered: {name} (tier={tier.name})")

    def update(self, plugin_name: str, *, total: int, success: int,
               errors: int, avg_rtt_ms: float) -> None:
        if plugin_name not in self._scores:
            self.register_plugin(plugin_name)
        score = self._scores[plugin_name]
        score.update(total, success, errors, avg_rtt_ms)
        score.is_active = True

    def mark_disabled(self, plugin_name: str, reason: str = "") -> None:
        if plugin_name in self._scores:
            self._scores[plugin_name].is_active = False
            self._scores[plugin_name].disabled_at = time.monotonic()
            self._scores[plugin_name].disable_reason = reason

    def mark_enabled(self, plugin_name: str) -> None:
        if plugin_name in self._scores:
            self._scores[plugin_name].is_active = True
            self._scores[plugin_name].disabled_at = 0.0
            self._scores[plugin_name].disable_reason = ""

    def evaluate(self, total_workers: int,
                 elapsed_seconds: float | None = None) -> AutoSelectDecision:
        """Core decision engine — evaluates plugin effectiveness."""
        now = time.monotonic()
        elapsed = elapsed_seconds if elapsed_seconds is not None else (now - self._start_time)

        if elapsed < PLUGIN_EFFECTIVENESS_PROBE_DURATION:
            self._phase = EffectivenessPhase.PROBE
        elif elapsed < PLUGIN_EFFECTIVENESS_PROBE_DURATION * 2:
            self._phase = EffectivenessPhase.ANALYZE
        else:
            self._phase = EffectivenessPhase.FOCUS

        decision = AutoSelectDecision(phase=self._phase)

        if (self._phase != EffectivenessPhase.PROBE and
            now - self._last_eval_time < PLUGIN_EFFECTIVENESS_REEVAL_INTERVAL):
            return self._last_decision

        self._last_eval_time = now

        active_plugins = [(n, s) for n, s in self._scores.items() if s.is_active]
        sorted_plugins = sorted(active_plugins, key=lambda x: x[1].effectiveness_score, reverse=True)

        if self._phase in (EffectivenessPhase.PROBE, EffectivenessPhase.ANALYZE):
            decision.worker_allocation = {}
            for name, score in sorted_plugins:
                # DEPRECATED plugins get minimal probe workers
                if score.tier == PluginTier.DEPRECATED:
                    decision.worker_allocation[name] = max(1, PLUGIN_EFFECTIVENESS_PROBE_WORKERS // 4)
                else:
                    decision.worker_allocation[name] = PLUGIN_EFFECTIVENESS_PROBE_WORKERS
            if self._phase == EffectivenessPhase.ANALYZE:
                decision.top_plugins = [n for n, _ in sorted_plugins[:self._top_k]]
            decision.reason = f"{self._phase} phase — tier-aware workers"
        else:
            # FOCUS: Top-K get full workers, rest get minimum or disabled
            top_plugins = sorted_plugins[:self._top_k]
            bottom_plugins = sorted_plugins[self._top_k:]

            total_score = sum(s.effectiveness_score for _, s in top_plugins)
            if total_score == 0:
                weights = {n: 1.0 / len(top_plugins) for n, _ in top_plugins} if top_plugins else {}
            else:
                weights = {n: s.effectiveness_score / total_score for n, s in top_plugins}

            for name, score in top_plugins:
                workers = max(PLUGIN_EFFECTIVENESS_MIN_WORKERS, int(total_workers * weights[name]))
                # Cap DEPRECATED plugins even if they're in top-K
                if score.tier == PluginTier.DEPRECATED:
                    workers = min(workers, 5)
                decision.worker_allocation[name] = workers

            decision.top_plugins = [n for n, _ in top_plugins]

            for name, score in bottom_plugins:
                # Never auto-disable ESSENTIAL tier
                if score.tier == PluginTier.ESSENTIAL:
                    decision.worker_allocation[name] = PLUGIN_EFFECTIVENESS_MIN_WORKERS
                    continue
                # DEPRECATED plugins get 0 workers in FOCUS unless surprisingly effective
                if score.tier == PluginTier.DEPRECATED:
                    if score.effectiveness_score > 10:  # only if surprisingly effective
                        decision.worker_allocation[name] = 1
                    else:
                        decision.disabled_plugins.append(name)
                        decision.worker_allocation[name] = 0
                    continue
                if score.should_disable:
                    decision.disabled_plugins.append(name)
                    decision.worker_allocation[name] = 0
                else:
                    decision.worker_allocation[name] = min(
                        PLUGIN_EFFECTIVENESS_MIN_WORKERS,
                        PLUGIN_EFFECTIVENESS_PROBE_WORKERS
                    )

            for name, score in top_plugins:
                if score.should_disable and score.tier != PluginTier.ESSENTIAL:
                    decision.disabled_plugins.append(name)
                    decision.worker_allocation[name] = 0

            decision.enabled_plugins = [
                n for n in decision.worker_allocation if decision.worker_allocation.get(n, 0) > 0
            ]
            decision.reason = (
                f"FOCUS — top-{self._top_k}: {', '.join(decision.top_plugins)}, "
                f"disabled: {', '.join(decision.disabled_plugins) or 'none'}"
            )

        if decision.reason:
            logger.info(f"[EFFECTIVENESS] {decision.reason}")

        self._last_decision = decision
        return decision

    def get_plugin_score(self, plugin_name: str) -> PluginEffectivenessScore | None:
        return self._scores.get(plugin_name)

    def get_ranking(self) -> List[Tuple[str, float]]:
        return sorted(
            [(n, s.effectiveness_score) for n, s in self._scores.items()],
            key=lambda x: x[1], reverse=True
        )

    def can_reenable(self, plugin_name: str) -> bool:
        score = self._scores.get(plugin_name)
        if score is None or score.is_active:
            return True
        if score.disabled_at == 0.0:
            return True
        return time.monotonic() - score.disabled_at >= PLUGIN_AUTO_DISABLE_COOLDOWN

    def reset(self) -> None:
        self._scores.clear()
        self._phase = EffectivenessPhase.PROBE
        self._start_time = time.monotonic()
        self._last_eval_time = 0.0
        self._last_decision = AutoSelectDecision()


__all__ = ["EffectivenessPhase", "AutoSelectDecision", "PluginEffectivenessTracker"]
