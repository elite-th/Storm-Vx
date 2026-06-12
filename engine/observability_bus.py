"""engine.observability_bus — Async event bus for metrics, logs, and traces.

Replaces direct stats_callback/health_callback/live_log_callback invocations
in the hot path with bounded async channels. Plugins emit events through
the bus; dedicated consumer tasks drain them asynchronously.

BENEFITS over direct callbacks:
1. No callback in the hot path — just a channel.send_nowait() (~100ns)
2. Bounded: if consumers can't keep up, oldest events are dropped
3. Consumers can be started/stopped independently
4. Zero coupling between producers and consumers
5. Batch processing: consumers drain N events at once (reduces I/O syscalls)

PERFORMANCE TARGET:
- Emit: <100ns (asyncio.Queue.put_nowait)
- Drain: <10ms for 1024 events (batch processing)
- Memory: O(channel_size) bounded, no growth
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from engine.atomic_counters import AtomicCounters


# ═══════════════════════════════════════════════════════════════════════════════
# Event Types
# ═══════════════════════════════════════════════════════════════════════════════

class EventType(Enum):
    """Observability event types."""
    HIT = "hit"                     # Request hit result
    WORKER_CRASH = "worker_crash"   # Worker crashed
    PLUGIN_CRASH = "plugin_crash"   # Plugin crashed
    WAF_DETECTED = "waf_detected"   # WAF detection
    SCALING = "scaling"             # Scaling decision
    HEALTH = "health"               # Health update
    METRIC = "metric"               # Custom metric


@dataclass
class ObservabilityEvent:
    """Single observability event.

    Lightweight value object — no methods, just data.
    Pre-allocated fields avoid dict overhead in the hot path.
    """
    type: EventType
    timestamp: float = 0.0
    plugin: str = ""
    target: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()  # wall-clock


# ═══════════════════════════════════════════════════════════════════════════════
# ObservabilityBus — Channel-based event bus
# ═══════════════════════════════════════════════════════════════════════════════

class ObservabilityBus:
    """Async event bus for metrics, logs, and traces.

    CHANNEL-BASED: Producers emit events through the bus.
    Consumers drain events asynchronously in batches.

    BOUNDED: If consumers can't keep up, oldest events are dropped.
    This ensures the bus never blocks the hot path.

    DROPPED EVENT TRACKING: A counter tracks how many events were
    dropped due to full channels. This is exposed via metrics for
    monitoring and alerting.
    """

    def __init__(self, channel_size: int = 4096) -> None:
        self._channel: asyncio.Queue[ObservabilityEvent] = asyncio.Queue(channel_size)
        self._dropped: int = 0
        self._total_emitted: int = 0

    def emit(self, event: ObservabilityEvent) -> bool:
        """Emit an event. Non-blocking; drops oldest if channel full.

        HOT PATH: Called on every request (10k+ times/sec).
        Must be as fast as possible: no allocations beyond the event.

        Returns:
            True if event was accepted, False if dropped.
        """
        self._total_emitted += 1
        try:
            self._channel.put_nowait(event)
            return True
        except asyncio.QueueFull:
            # Drop oldest to make room
            try:
                self._channel.get_nowait()
                self._dropped += 1
                self._channel.put_nowait(event)
                return True
            except (asyncio.QueueFull, asyncio.QueueEmpty):
                self._dropped += 1
                return False

    def emit_hit(self, plugin: str, target: str,
                  ok: bool, code: int, rt: float,
                  mode: str = "", err: str = "") -> bool:
        """Convenience method for emitting hit events.

        Avoids creating a dict in the hot path — uses pre-allocated fields.
        """
        return self.emit(ObservabilityEvent(
            type=EventType.HIT,
            plugin=plugin,
            target=target,
            data={
                "ok": ok,
                "code": code,
                "rt": rt,
                "mode": mode,
                "err": err,
            },
        ))

    async def drain(self, batch_size: int = 1024) -> List[ObservabilityEvent]:
        """Drain up to batch_size events from the channel.

        Called by consumer tasks at ~10Hz (every 100ms).
        Batch processing reduces I/O syscalls: 1024 events → 1 write.

        Args:
            batch_size: Maximum number of events to drain.

        Returns:
            List of events.
        """
        events: List[ObservabilityEvent] = []
        for _ in range(batch_size):
            try:
                events.append(self._channel.get_nowait())
            except asyncio.QueueEmpty:
                break
        return events

    @property
    def dropped_count(self) -> int:
        """Number of events dropped due to full channel."""
        return self._dropped

    @property
    def total_emitted(self) -> int:
        """Total events emitted since startup."""
        return self._total_emitted

    @property
    def pending_count(self) -> int:
        """Number of events waiting in the channel."""
        return self._channel.qsize()

    @property
    def stats(self) -> Dict[str, Any]:
        """Bus statistics for monitoring."""
        return {
            "total_emitted": self._total_emitted,
            "dropped": self._dropped,
            "pending": self.pending_count,
            "drop_rate": self._dropped / max(self._total_emitted, 1),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Event Consumers
# ═══════════════════════════════════════════════════════════════════════════════

class MetricsSink:
    """Async consumer that routes events to Prometheus metrics.

    Drains events from the ObservabilityBus in batches and updates
    Prometheus counters/histograms. Runs as a background task.
    """

    def __init__(self, bus: ObservabilityBus,
                 drain_interval: float = 0.1) -> None:
        self._bus = bus
        self._drain_interval = drain_interval
        self._stop = asyncio.Event()

    async def run(self) -> None:
        """Main consumer loop."""
        while not self._stop.is_set():
            events = await self._bus.drain(batch_size=1024)
            if events:
                self._process_batch(events)
            try:
                await asyncio.wait_for(
                    asyncio.create_task(self._stop.wait()),
                    timeout=self._drain_interval,
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

    def _process_batch(self, events: List[ObservabilityEvent]) -> None:
        """Process a batch of events and update metrics."""
        try:
            from observability.metrics import metrics
            for event in events:
                if event.type == EventType.HIT:
                    data = event.data
                    metrics.http_requests_total.labels(
                        method=data.get("mode", "GET"),
                        status_code=str(data.get("code", 0)),
                        target=event.target,
                    ).inc()
                    rt = data.get("rt", 0)
                    if rt > 0:
                        metrics.http_request_duration_seconds.labels(
                            method=data.get("mode", "GET"),
                        ).observe(rt)
        except ImportError:
            pass  # Prometheus not installed — no-op

    def stop(self) -> None:
        """Signal the consumer to stop."""
        self._stop.set()


class LogSink:
    """Async consumer that routes events to the logging subsystem.

    Drains events from the ObservabilityBus and formats them for
    the structured logging system. Batch processing reduces the
    number of log formatting calls.
    """

    def __init__(self, bus: ObservabilityBus,
                 drain_interval: float = 0.1,
                 batch_log: bool = True) -> None:
        self._bus = bus
        self._drain_interval = drain_interval
        self._batch_log = batch_log
        self._stop = asyncio.Event()
        self._logger = logging.getLogger("storm_vx.engine.events")

    async def run(self) -> None:
        """Main consumer loop."""
        while not self._stop.is_set():
            events = await self._bus.drain(batch_size=1024)
            if events:
                self._process_batch(events)
            try:
                await asyncio.wait_for(
                    asyncio.create_task(self._stop.wait()),
                    timeout=self._drain_interval,
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

    def _process_batch(self, events: List[ObservabilityEvent]) -> None:
        """Process a batch of events and write to log."""
        if self._batch_log:
            # Batch mode: summarize instead of logging each event
            hits = [e for e in events if e.type == EventType.HIT]
            crashes = [e for e in events if e.type in (EventType.WORKER_CRASH, EventType.PLUGIN_CRASH)]
            wafs = [e for e in events if e.type == EventType.WAF_DETECTED]

            if hits:
                ok_count = sum(1 for h in hits if h.data.get("ok"))
                fail_count = len(hits) - ok_count
                avg_rt = sum(h.data.get("rt", 0) for h in hits) / max(len(hits), 1)
                self._logger.debug(
                    f"[BATCH] {len(hits)} hits: {ok_count} ok, {fail_count} fail, "
                    f"avg_rt={avg_rt:.3f}s"
                )
            if crashes:
                for c in crashes:
                    self._logger.warning(
                        f"[CRASH] {c.plugin}: {c.data.get('error', 'unknown')}"
                    )
            if wafs:
                for w in wafs:
                    self._logger.warning(
                        f"[WAF] {w.plugin}: {w.data.get('waf_name', 'unknown')} detected"
                    )
        else:
            # Individual mode: log each event
            for event in events:
                self._log_event(event)

    def _log_event(self, event: ObservabilityEvent) -> None:
        """Log a single event."""
        if event.type == EventType.HIT:
            data = event.data
            if data.get("ok"):
                self._logger.debug(
                    f"[HIT] {event.plugin} → {event.target} "
                    f"code={data.get('code')} rt={data.get('rt', 0):.3f}s"
                )
            else:
                self._logger.warning(
                    f"[FAIL] {event.plugin} → {event.target} "
                    f"code={data.get('code')} err={data.get('err', '')}"
                )
        elif event.type in (EventType.WORKER_CRASH, EventType.PLUGIN_CRASH):
            self._logger.error(
                f"[{event.type.value}] {event.plugin}: {event.data.get('error', 'unknown')}"
            )

    def stop(self) -> None:
        """Signal the consumer to stop."""
        self._stop.set()


__all__ = [
    "ObservabilityBus",
    "ObservabilityEvent",
    "EventType",
    "MetricsSink",
    "LogSink",
]
