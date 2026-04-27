#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF Multi-Target Queue — Attack Multiple Targets                      ║
║     Part of the STORM_VX Infrastructure                                 ║
║                                                                           ║
║  Priority queue for attacking multiple targets in sequential or          ║
║  parallel mode with per-target configuration, auto-balancing, and       ║
║  status tracking.                                                        ║
║                                                                           ║
║  Usage:                                                                  ║
║    from infra.vf_multi_target import MultiTargetQueue                    ║
║    queue = MultiTargetQueue()                                            ║
║    queue.add_target("https://target1.com", priority=2)                  ║
║    queue.add_target("https://target2.com", priority=1)                  ║
║    await queue.run_sequential(stop_event)                                ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import os
import asyncio
import json
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum


# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# Target Status
# ═══════════════════════════════════════════════════════════════════════════════

class TargetStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"


# ═══════════════════════════════════════════════════════════════════════════════
# Target Entry
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TargetEntry:
    """Represents a single target in the attack queue."""
    url: str
    priority: int = 0
    profile: Optional[Dict] = None
    status: TargetStatus = TargetStatus.PENDING
    workers: int = 100
    method: str = "auto"
    bypass_level: str = "normal"
    duration_limit: float = 0  # seconds (0 = unlimited)
    added_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    ended_at: Optional[float] = None

    # Live stats
    total_requests: int = 0
    success_rate: float = 0.0
    current_rps: float = 0.0
    peak_rps: float = 0.0

    @property
    def elapsed(self) -> float:
        """Elapsed time since attack started on this target."""
        if self.started_at is None:
            return 0
        end = self.ended_at or time.time()
        return round(end - self.started_at, 2)

    @property
    def is_rate_limited(self) -> bool:
        """Check if target is heavily rate-limited."""
        return self.success_rate < 0.2 and self.total_requests > 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "priority": self.priority,
            "status": self.status.value,
            "workers": self.workers,
            "method": self.method,
            "bypass_level": self.bypass_level,
            "duration_limit": self.duration_limit,
            "added_at": self.added_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "total_requests": self.total_requests,
            "success_rate": self.success_rate,
            "current_rps": self.current_rps,
            "peak_rps": self.peak_rps,
            "elapsed": self.elapsed,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Multi-Target Queue
# ═══════════════════════════════════════════════════════════════════════════════

class MultiTargetQueue:
    """
    Multi-Target Queue for STORM_VX.

    Manages a priority queue of targets for sequential or parallel
    attack execution with per-target configuration, auto-balancing,
    and status tracking.
    """

    QUEUE_FILE = "target_queue.json"

    def __init__(self):
        """Initialize MultiTargetQueue."""
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.targets: List[TargetEntry] = []
        self._attack_func: Optional[Callable] = None
        self._stats_func: Optional[Callable] = None
        self._stop_func: Optional[Callable] = None
        self._lock = asyncio.Lock()
        self._active_tasks: Dict[str, asyncio.Task] = {}

    # ─── Attack Function Registration ──────────────────────────────────────

    def set_attack_function(self, attack_func: Callable,
                            stats_func: Callable = None,
                            stop_func: Callable = None):
        """
        Register the attack function.

        Args:
            attack_func: async function(url, profile, workers, method, bypass_level,
                          stop_event) -> Dict with stats.
            stats_func: async function(url) -> Dict with current stats.
            stop_func: async function(url) -> None to stop attack on specific target.
        """
        self._attack_func = attack_func
        self._stats_func = stats_func
        self._stop_func = stop_func

    # ─── Queue Management ──────────────────────────────────────────────────

    def add_target(self, url: str, profile: Dict = None, priority: int = 0,
                   workers: int = 100, method: str = "auto",
                   bypass_level: str = "normal", duration_limit: float = 0):
        """
        Add a target to the queue.

        Args:
            url: Target URL.
            profile: Optional VF_FINDER profile dict.
            priority: Higher priority = attacked first.
            workers: Number of workers for this target.
            method: Attack method name.
            bypass_level: Bypass level for this target.
            duration_limit: Max attack duration in seconds (0 = unlimited).
        """
        # Check for duplicate
        for t in self.targets:
            if t.url == url and t.status in (TargetStatus.PENDING, TargetStatus.RUNNING):
                print(f"  {C.Y}[MULTI] Target already in queue: {url}{C.RS}")
                return

        entry = TargetEntry(
            url=url,
            priority=priority,
            profile=profile,
            workers=workers,
            method=method,
            bypass_level=bypass_level,
            duration_limit=duration_limit,
        )
        self.targets.append(entry)

        # Sort by priority (highest first)
        self.targets.sort(key=lambda t: t.priority, reverse=True)

        print(f"  {C.G}[MULTI] Added target: {C.W}{url}{C.RS} (priority={priority}, workers={workers})")

    def remove_target(self, url: str):
        """
        Remove a target from the queue.

        Args:
            url: Target URL to remove.
        """
        to_remove = None
        for t in self.targets:
            if t.url == url:
                to_remove = t
                break

        if to_remove:
            # If running, cancel the task
            if to_remove.url in self._active_tasks:
                self._active_tasks[to_remove.url].cancel()
                del self._active_tasks[to_remove.url]

            self.targets.remove(to_remove)
            print(f"  {C.Y}[MULTI] Removed target: {url}{C.RS}")
        else:
            print(f"  {C.R}[MULTI] Target not found: {url}{C.RS}")

    def get_queue_status(self) -> List[Dict]:
        """
        Get the status of all targets in the queue.

        Returns:
            List of target status dictionaries.
        """
        return [t.to_dict() for t in self.targets]

    # ─── Execution: Sequential ─────────────────────────────────────────────

    async def run_sequential(self, stop_event: asyncio.Event):
        """
        Attack targets one by one in priority order.

        Args:
            stop_event: Event to signal stop.
        """
        if not self._attack_func:
            print(f"  {C.R}[MULTI] No attack function registered!{C.RS}")
            return

        print(f"\n  {C.BD}{C.CY}{'='*60}{C.RS}")
        print(f"  {C.BD}{C.CY}  Multi-Target Queue — Sequential Mode{C.RS}")
        print(f"  {C.BD}{C.CY}  Targets: {len(self.targets)}{C.RS}")
        print(f"  {C.BD}{C.CY}{'='*60}{C.RS}\n")

        pending = [t for t in self.targets if t.status == TargetStatus.PENDING]

        for i, target in enumerate(pending):
            if stop_event.is_set():
                print(f"  {C.Y}[MULTI] Stop signal received, halting queue{C.RS}")
                break

            print(f"  {C.CY}[MULTI] [{i+1}/{len(pending)}] Attacking: {C.W}{target.url}{C.RS}")
            target.status = TargetStatus.RUNNING
            target.started_at = time.time()

            # Create per-target stop event
            target_stop = asyncio.Event()

            # Duration limit watchdog
            duration_task = None
            if target.duration_limit > 0:
                async def _duration_watcher(tgt=target, evt=target_stop):
                    await asyncio.sleep(tgt.duration_limit)
                    if not evt.is_set():
                        evt.set()
                        print(f"  {C.Y}[MULTI] Duration limit reached for {tgt.url}{C.RS}")
                duration_task = asyncio.create_task(_duration_watcher())

            # Also stop if global stop event is set
            global_watcher = asyncio.create_task(self._watch_global_stop(stop_event, target_stop))

            try:
                result = await self._attack_func(
                    url=target.url,
                    profile=target.profile,
                    workers=target.workers,
                    method=target.method,
                    bypass_level=target.bypass_level,
                    stop_event=target_stop,
                )

                if result:
                    target.total_requests = result.get("total", 0)
                    target.success_rate = result.get("success_rate", 0)
                    target.current_rps = result.get("rps", 0)
                    target.peak_rps = result.get("peak_rps", 0)

                if target.is_rate_limited:
                    target.status = TargetStatus.RATE_LIMITED
                else:
                    target.status = TargetStatus.COMPLETED

            except asyncio.CancelledError:
                target.status = TargetStatus.PAUSED
                break
            except Exception as e:
                target.status = TargetStatus.FAILED
                print(f"  {C.R}[MULTI] Error attacking {target.url}: {e}{C.RS}")
            finally:
                target.ended_at = time.time()
                target_stop.set()
                global_watcher.cancel()
                try:
                    await global_watcher
                except asyncio.CancelledError:
                    pass
                if duration_task:
                    duration_task.cancel()
                    try:
                        await duration_task
                    except asyncio.CancelledError:
                        pass

            # Print target result
            self._print_target_result(target)

        # Print final summary
        self._print_summary()

    # ─── Execution: Parallel ───────────────────────────────────────────────

    async def run_parallel(self, stop_event: asyncio.Event, max_concurrent: int = 2):
        """
        Attack multiple targets simultaneously.

        Args:
            stop_event: Event to signal stop.
            max_concurrent: Maximum number of concurrent attacks.
        """
        if not self._attack_func:
            print(f"  {C.R}[MULTI] No attack function registered!{C.RS}")
            return

        print(f"\n  {C.BD}{C.CY}{'='*60}{C.RS}")
        print(f"  {C.BD}{C.CY}  Multi-Target Queue — Parallel Mode{C.RS}")
        print(f"  {C.BD}{C.CY}  Targets: {len(self.targets)} | Max Concurrent: {max_concurrent}{C.RS}")
        print(f"  {C.BD}{C.CY}{'='*60}{C.RS}\n")

        pending = [t for t in self.targets if t.status == TargetStatus.PENDING]
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _attack_target(target: TargetEntry):
            async with semaphore:
                if stop_event.is_set():
                    return

                target.status = TargetStatus.RUNNING
                target.started_at = time.time()

                target_stop = asyncio.Event()

                # Duration limit watchdog
                if target.duration_limit > 0:
                    async def _dw(tgt=target, evt=target_stop):
                        await asyncio.sleep(tgt.duration_limit)
                        if not evt.is_set():
                            evt.set()
                    asyncio.create_task(_dw())

                # Global stop watcher
                global_watcher = asyncio.create_task(
                    self._watch_global_stop(stop_event, target_stop)
                )

                try:
                    result = await self._attack_func(
                        url=target.url,
                        profile=target.profile,
                        workers=target.workers,
                        method=target.method,
                        bypass_level=target.bypass_level,
                        stop_event=target_stop,
                    )

                    if result:
                        target.total_requests = result.get("total", 0)
                        target.success_rate = result.get("success_rate", 0)
                        target.current_rps = result.get("rps", 0)
                        target.peak_rps = result.get("peak_rps", 0)

                    if target.is_rate_limited:
                        target.status = TargetStatus.RATE_LIMITED
                    else:
                        target.status = TargetStatus.COMPLETED

                except asyncio.CancelledError:
                    target.status = TargetStatus.PAUSED
                except Exception as e:
                    target.status = TargetStatus.FAILED
                    print(f"  {C.R}[MULTI] Error attacking {target.url}: {e}{C.RS}")
                finally:
                    target.ended_at = time.time()
                    target_stop.set()
                    global_watcher.cancel()
                    try:
                        await global_watcher
                    except asyncio.CancelledError:
                        pass

                self._print_target_result(target)

        # Launch all attacks (semaphore limits concurrency)
        tasks = [asyncio.create_task(_attack_target(t)) for t in pending]
        self._active_tasks = {t.url: task for t, task in zip(pending, tasks)}

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            print(f"  {C.R}[MULTI] Parallel execution error: {e}{C.RS}")

        # Auto-balance: check if we should redistribute workers
        await self._auto_balance()

        # Print final summary
        self._print_summary()

    # ─── Auto-Balance ──────────────────────────────────────────────────────

    async def _auto_balance(self):
        """
        Auto-balance workers across targets.
        If one target is heavily rate-limited, reduce its workers
        and give them to a better-performing target.
        """
        running = [t for t in self.targets if t.status == TargetStatus.RUNNING]
        if len(running) < 2:
            return

        # Find rate-limited targets
        rate_limited = [t for t in running if t.is_rate_limited]
        if not rate_limited:
            return

        # Find best-performing targets
        best = sorted(running, key=lambda t: t.success_rate, reverse=True)
        best_target = best[0]

        for limited in rate_limited:
            # Move 50% of workers from rate-limited to best target
            transfer = limited.workers // 2
            if transfer > 0:
                limited.workers -= transfer
                best_target.workers += transfer
                print(f"  {C.Y}[MULTI] Auto-balance: moved {transfer} workers "
                      f"from {limited.url} -> {best_target.url}{C.RS}")

    # ─── Save / Load ───────────────────────────────────────────────────────

    def save_queue(self, filepath: str = None):
        """
        Save target queue to a JSON file.

        Args:
            filepath: Path to save file. Defaults to project root.
        """
        if not filepath:
            filepath = os.path.join(self.project_root, self.QUEUE_FILE)

        data = {
            "saved_at": datetime.now().isoformat(),
            "targets": [t.to_dict() for t in self.targets],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"  {C.G}[MULTI] Queue saved: {filepath}{C.RS}")

    def load_queue(self, filepath: str = None) -> int:
        """
        Load target queue from a JSON file.

        Args:
            filepath: Path to load file. Defaults to project root.

        Returns:
            Number of targets loaded.
        """
        if not filepath:
            filepath = os.path.join(self.project_root, self.QUEUE_FILE)

        if not os.path.exists(filepath):
            print(f"  {C.R}[MULTI] Queue file not found: {filepath}{C.RS}")
            return 0

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"  {C.R}[MULTI] Error loading queue: {e}{C.RS}")
            return 0

        self.targets.clear()

        for t_data in data.get("targets", []):
            entry = TargetEntry(
                url=t_data["url"],
                priority=t_data.get("priority", 0),
                profile=t_data.get("profile"),
                workers=t_data.get("workers", 100),
                method=t_data.get("method", "auto"),
                bypass_level=t_data.get("bypass_level", "normal"),
                duration_limit=t_data.get("duration_limit", 0),
                status=TargetStatus.PENDING,  # Reset status on load
            )
            self.targets.append(entry)

        # Sort by priority
        self.targets.sort(key=lambda t: t.priority, reverse=True)

        print(f"  {C.G}[MULTI] Loaded {len(self.targets)} targets from queue{C.RS}")
        return len(self.targets)

    # ─── Print ─────────────────────────────────────────────────────────────

    def print_queue(self):
        """Print a formatted view of the target queue."""
        if not self.targets:
            print(f"\n  {C.Y}[MULTI] No targets in queue{C.RS}")
            return

        print(f"\n  {C.BD}{C.CY}{'='*70}{C.RS}")
        print(f"  {C.BD}{C.CY}  Multi-Target Queue{C.RS}")
        print(f"  {C.BD}{C.CY}{'='*70}{C.RS}")

        for i, t in enumerate(self.targets, 1):
            status_colors = {
                TargetStatus.PENDING: C.DM,
                TargetStatus.RUNNING: C.G,
                TargetStatus.COMPLETED: C.CY,
                TargetStatus.FAILED: C.R,
                TargetStatus.PAUSED: C.Y,
                TargetStatus.RATE_LIMITED: C.M,
            }
            sc = status_colors.get(t.status, C.W)

            print(f"  {C.W}{i}.{C.RS} {sc}[{t.status.value.upper():>14}]{C.RS} "
                  f"{C.BD}{t.url}{C.RS}")
            print(f"     {C.DM}Priority: {t.priority} | Workers: {t.workers} | "
                  f"Method: {t.method} | Bypass: {t.bypass_level}{C.RS}")

            if t.status in (TargetStatus.RUNNING, TargetStatus.COMPLETED,
                            TargetStatus.FAILED, TargetStatus.RATE_LIMITED):
                print(f"     {C.DM}Requests: {t.total_requests:,} | "
                      f"Success: {t.success_rate:.1%} | "
                      f"RPS: {t.current_rps:,.0f} (peak: {t.peak_rps:,.0f}) | "
                      f"Elapsed: {t.elapsed:.0f}s{C.RS}")

        print(f"  {C.BD}{C.CY}{'='*70}{C.RS}\n")

    def _print_target_result(self, target: TargetEntry):
        """Print the result of a single target attack."""
        status_colors = {
            TargetStatus.COMPLETED: C.G,
            TargetStatus.FAILED: C.R,
            TargetStatus.RATE_LIMITED: C.M,
            TargetStatus.PAUSED: C.Y,
        }
        sc = status_colors.get(target.status, C.W)

        print(f"\n  {sc}[MULTI] Target {target.status.value}: {C.W}{target.url}{C.RS}")
        print(f"  {C.DM}  Requests: {target.total_requests:,} | "
              f"Success: {target.success_rate:.1%} | "
              f"Peak RPS: {target.peak_rps:,.0f} | "
              f"Duration: {target.elapsed:.0f}s{C.RS}\n")

    def _print_summary(self):
        """Print the final queue summary."""
        completed = sum(1 for t in self.targets if t.status == TargetStatus.COMPLETED)
        failed = sum(1 for t in self.targets if t.status == TargetStatus.FAILED)
        rate_limited = sum(1 for t in self.targets if t.status == TargetStatus.RATE_LIMITED)
        total_reqs = sum(t.total_requests for t in self.targets)

        print(f"\n  {C.BD}{C.CY}{'='*70}{C.RS}")
        print(f"  {C.BD}{C.CY}  Multi-Target Queue — Summary{C.RS}")
        print(f"  {C.BD}{C.CY}{'='*70}{C.RS}")
        print(f"  {C.G}  Completed:     {completed}{C.RS}")
        print(f"  {C.R}  Failed:        {failed}{C.RS}")
        print(f"  {C.M}  Rate Limited:  {rate_limited}{C.RS}")
        print(f"  {C.W}  Total Requests: {total_reqs:,}{C.RS}")
        print(f"  {C.BD}{C.CY}{'='*70}{C.RS}\n")

    # ─── Internal Helpers ──────────────────────────────────────────────────

    async def _watch_global_stop(self, global_stop: asyncio.Event,
                                  target_stop: asyncio.Event):
        """Watch the global stop event and signal the target stop."""
        try:
            while not global_stop.is_set() and not target_stop.is_set():
                await asyncio.sleep(0.5)
            if global_stop.is_set() and not target_stop.is_set():
                target_stop.set()
        except asyncio.CancelledError:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VF Multi-Target Queue — Attack Multiple Targets")
    parser.add_argument("--add", help="Add target URL to queue")
    parser.add_argument("--priority", type=int, default=0, help="Target priority")
    parser.add_argument("--workers", type=int, default=100, help="Worker count")
    parser.add_argument("--method", default="auto", help="Attack method")
    parser.add_argument("--list", action="store_true", help="List queue")
    parser.add_argument("--save", action="store_true", help="Save queue to file")
    parser.add_argument("--load", action="store_true", help="Load queue from file")
    parser.add_argument("--remove", help="Remove target URL from queue")

    args = parser.parse_args()
    queue = MultiTargetQueue()

    if args.load:
        queue.load_queue()

    if args.add:
        queue.add_target(args.add, priority=args.priority,
                         workers=args.workers, method=args.method)

    if args.remove:
        queue.remove_target(args.remove)

    if args.save:
        queue.save_queue()

    if args.list or not any([args.add, args.remove, args.save, args.load]):
        queue.print_queue()
