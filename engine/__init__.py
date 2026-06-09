"""STORM VX Redesigned Engine — Production-grade async-first architecture.

This package contains the redesigned core modules that address the 10 critical
defects identified in the architectural audit AND implement the new structured
concurrency engine for Python 3.12+.

CORE MODULES (v2 — Structured Concurrency Engine):
- atomic_metrics:   Lock-free hot-path counters with histogram + benchmark instrumentation
- runtime_context:  Typed immutable config + per-target isolated runtime state
- scheduler:        Structured concurrency engine with asyncio.TaskGroup
- shutdown_manager: Graceful shutdown + cancellation propagation
- task_supervisor:  Plugin-safe task isolation + supervision

LEGACY MODULES (v1 — Kept for backward compatibility):
- atomic_counters:  Lock-free counters (superseded by atomic_metrics)
- connection_manager: Connection pool with pre-warming
- observability_bus: Async event bus for metrics, logs, and traces
- plugin_sandbox:  Isolated plugin execution (superseded by task_supervisor)

DESIGN PRINCIPLES:
1. Structured concurrency — every task belongs to a TaskGroup
2. Lock-free hot path — GIL-atomic counters, no asyncio.Lock in request path
3. Immutable config — frozen dataclasses, zero global mutable state
4. Per-target isolation — separate metrics, WAF state, failure tracking
5. Bounded queues — no unbounded growth, backpressure-aware
6. Graceful shutdown — phased with cancellation propagation
7. No blocking I/O in event loop
8. O(1) scheduler bookkeeping
9. Benchmark-ready instrumentation on every hot path
10. Plugin crash isolation — one-for-one supervision strategy
"""

# v2 — New structured concurrency engine (primary imports)
from engine.atomic_metrics import (
    AtomicMetrics,
    MetricsSnapshot,
    PerTargetMetrics,
    MetricsRegistry,
    RollingWindow,
    LatencyHistogram,
)
from engine.runtime_context import (
    EngineConfig,
    ConnectionConfig,
    WorkerConfig,
    SchedulerConfig,
    BackpressureConfig,
    ObservabilityConfig,
    SecurityConfig,
    CrashRecoveryConfig,
    ShutdownConfig,
    TargetIdentity,
    RuntimeContext,
    WAFState,
    FailureTracker,
    BoundedMailbox,
)
from engine.scheduler import (
    StormScheduler,
    ScalingController,
    ScalingCommand,
    ScalingAction,
    ScalingState,
    BackpressureController,
    HealthAggregator,
    TickDriver,
)
from engine.shutdown_manager import (
    ShutdownManager,
    ShutdownPhase,
    ShutdownReport,
    CleanupRegistry,
    CancellationPropagator,
    ResourceDrainer,
)
from engine.task_supervisor import (
    TaskSupervisor,
    PluginScope,
    PluginState,
    CrashRecovery,
    ScalingApplier,
)

__all__ = [
    # atomic_metrics
    "AtomicMetrics", "MetricsSnapshot", "PerTargetMetrics", "MetricsRegistry",
    "RollingWindow", "LatencyHistogram",
    # runtime_context
    "EngineConfig", "ConnectionConfig", "WorkerConfig", "SchedulerConfig",
    "BackpressureConfig", "ObservabilityConfig", "SecurityConfig",
    "CrashRecoveryConfig", "ShutdownConfig",
    "TargetIdentity", "RuntimeContext", "WAFState", "FailureTracker",
    "BoundedMailbox",
    # scheduler
    "StormScheduler", "ScalingController", "ScalingCommand", "ScalingAction",
    "ScalingState", "BackpressureController", "HealthAggregator", "TickDriver",
    # shutdown_manager
    "ShutdownManager", "ShutdownPhase", "ShutdownReport",
    "CleanupRegistry", "CancellationPropagator", "ResourceDrainer",
    # task_supervisor
    "TaskSupervisor", "PluginScope", "PluginState", "CrashRecovery",
    "ScalingApplier",
]
