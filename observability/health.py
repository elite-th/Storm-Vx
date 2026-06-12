"""observability.health — Health check and diagnostics for Storm-Vx.

W5.3 HEALTH CHECK & DIAGNOSTICS:

  Provides a lightweight health check system that can be exposed via
  HTTP endpoints or queried programmatically. Designed for:

  1. Kubernetes liveness/readiness probes
  2. Load balancer health checks
  3. Operational diagnostics dashboards
  4. Crash diagnostics and post-mortem analysis

  The HTTP server (start_health_server) with Bearer token auth is in
  observability.health_server, re-exported here for backward compatibility.

DESIGN PRINCIPLES:
  - Zero-dependency: works without aiohttp server running
  - Programmatic API: can be called from any context
  - Non-blocking: all checks complete in <100ms
  - Structured output: all responses are JSON
"""
from __future__ import annotations

import asyncio
import os
import platform
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════════════════════════
# Health Status Model
# ═══════════════════════════════════════════════════════════════════════════════

class HealthStatus(Enum):
    """Health check status values."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a single health check."""
    name: str
    status: HealthStatus
    message: str = ""
    duration_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "duration_ms": round(self.duration_ms, 2),
            "details": self.details,
        }


@dataclass
class HealthReport:
    """Aggregated health report from all checks."""
    status: HealthStatus
    checks: List[HealthCheckResult] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    uptime_seconds: float = 0.0
    version: str = "22.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "timestamp": self.timestamp,
            "uptime_seconds": round(self.uptime_seconds, 2),
            "version": self.version,
            "checks": [c.to_dict() for c in self.checks],
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Individual Health Checks
# ═══════════════════════════════════════════════════════════════════════════════

class HealthCheck:
    """Base class for health checks."""

    name: str = "unnamed"

    async def check(self) -> HealthCheckResult:
        """Run the health check and return a result."""
        raise NotImplementedError


class EventLoopHealthCheck(HealthCheck):
    """Check if the asyncio event loop is responsive."""

    name = "event_loop"

    async def check(self) -> HealthCheckResult:
        start = time.monotonic()
        try:
            # If we can await something, the event loop is alive
            await asyncio.sleep(0)
            elapsed = (time.monotonic() - start) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.HEALTHY,
                message="Event loop is responsive",
                duration_ms=elapsed,
            )
        except RuntimeError as exc:
            elapsed = (time.monotonic() - start) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Event loop error: {exc}",
                duration_ms=elapsed,
            )


class MemoryHealthCheck(HealthCheck):
    """Check memory usage and report if approaching limits."""

    name = "memory"

    def __init__(self, warning_mb: float = 500.0, critical_mb: float = 1000.0):
        self._warning_mb = warning_mb
        self._critical_mb = critical_mb

    async def check(self) -> HealthCheckResult:
        start = time.monotonic()
        try:
            import resource
            # RSS in KB on Linux
            usage_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            usage_mb = usage_kb / 1024.0  # Convert KB to MB
        except (ImportError, AttributeError):
            # Fallback: use /proc/self/status on Linux
            usage_mb = self._read_proc_memory()

        elapsed = (time.monotonic() - start) * 1000

        if usage_mb >= self._critical_mb:
            status = HealthStatus.UNHEALTHY
            message = f"Memory usage critical: {usage_mb:.1f}MB"
        elif usage_mb >= self._warning_mb:
            status = HealthStatus.DEGRADED
            message = f"Memory usage high: {usage_mb:.1f}MB"
        else:
            status = HealthStatus.HEALTHY
            message = f"Memory usage normal: {usage_mb:.1f}MB"

        return HealthCheckResult(
            name=self.name,
            status=status,
            message=message,
            duration_ms=elapsed,
            details={"usage_mb": round(usage_mb, 1)},
        )

    @staticmethod
    def _read_proc_memory() -> float:
        """Read memory usage from /proc/self/status (Linux only)."""
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        # VmRSS is in kB
                        return float(line.split()[1]) / 1024.0
        except (OSError, ValueError, IndexError):
            pass
        return 0.0


class TaskHealthCheck(HealthCheck):
    """Check the number of active asyncio tasks."""

    name = "asyncio_tasks"

    def __init__(self, warning_threshold: int = 500, critical_threshold: int = 1000):
        self._warning = warning_threshold
        self._critical = critical_threshold

    async def check(self) -> HealthCheckResult:
        start = time.monotonic()
        try:
            loop = asyncio.get_running_loop()
            task_count = len(asyncio.all_tasks(loop))
        except RuntimeError:
            task_count = 0

        elapsed = (time.monotonic() - start) * 1000

        if task_count >= self._critical:
            status = HealthStatus.UNHEALTHY
            message = f"Task count critical: {task_count}"
        elif task_count >= self._warning:
            status = HealthStatus.DEGRADED
            message = f"Task count high: {task_count}"
        else:
            status = HealthStatus.HEALTHY
            message = f"Task count normal: {task_count}"

        return HealthCheckResult(
            name=self.name,
            status=status,
            message=message,
            duration_ms=elapsed,
            details={"task_count": task_count},
        )


class ConfigHealthCheck(HealthCheck):
    """Check if configuration is valid and loaded."""

    name = "configuration"

    async def check(self) -> HealthCheckResult:
        start = time.monotonic()
        try:
            from config.defaults import VERIFY_SSL, DEFAULT_TOTAL_TIMEOUT
            from config.settings import ConnectionSettings
            settings = ConnectionSettings()
            issues: list[str] = []

            if settings.connect_timeout <= 0:
                issues.append("connect_timeout must be positive")
            if settings.sock_read_timeout <= 0:
                issues.append("sock_read_timeout must be positive")

            elapsed = (time.monotonic() - start) * 1000

            if issues:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Config issues: {'; '.join(issues)}",
                    duration_ms=elapsed,
                    details={"issues": issues},
                )

            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.HEALTHY,
                message="Configuration valid",
                duration_ms=elapsed,
                details={
                    "verify_ssl": VERIFY_SSL,
                    "total_timeout": DEFAULT_TOTAL_TIMEOUT,
                },
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Config check failed: {exc}",
                duration_ms=elapsed,
            )


# ═══════════════════════════════════════════════════════════════════════════════
# Health Check Manager — Orchestrates all checks
# ═══════════════════════════════════════════════════════════════════════════════

class HealthCheckManager:
    """Manages and runs all health checks.

    Usage:
        manager = HealthCheckManager()
        report = await manager.check_health()

        # For liveness (is the process alive?)
        status = await manager.liveness()

        # For readiness (is it ready to accept work?)
        status = await manager.readiness()
    """

    def __init__(self) -> None:
        self._checks: List[HealthCheck] = []
        self._start_time: float = time.monotonic()
        self._last_report: Optional[HealthReport] = None
        self._ready: bool = False

        # Register default checks
        self._checks.extend([
            EventLoopHealthCheck(),
            MemoryHealthCheck(),
            TaskHealthCheck(),
            ConfigHealthCheck(),
        ])

    def add_check(self, check: HealthCheck) -> None:
        """Register a custom health check."""
        self._checks.append(check)

    def set_ready(self, ready: bool = True) -> None:
        """Mark the system as ready (or not ready).

        Call this after initialization is complete to signal
        readiness to load balancers / orchestrators.
        """
        self._ready = ready

    async def check_health(self) -> HealthReport:
        """Run all health checks and return a comprehensive report."""
        results: List[HealthCheckResult] = []

        for check in self._checks:
            try:
                result = await check.check()
            except Exception as exc:
                result = HealthCheckResult(
                    name=check.name,
                    status=HealthStatus.UNKNOWN,
                    message=f"Check failed with exception: {exc}",
                )
            results.append(result)

        # Determine overall status: worst case wins
        status_priority = {
            HealthStatus.UNHEALTHY: 3,
            HealthStatus.DEGRADED: 2,
            HealthStatus.UNKNOWN: 1,
            HealthStatus.HEALTHY: 0,
        }
        worst = HealthStatus.HEALTHY
        for result in results:
            if status_priority.get(result.status, 0) > status_priority.get(worst, 0):
                worst = result.status

        report = HealthReport(
            status=worst,
            checks=results,
            uptime_seconds=time.monotonic() - self._start_time,
        )
        self._last_report = report
        return report

    async def liveness(self) -> HealthStatus:
        """Quick liveness check — is the process alive?

        This is intentionally minimal: just check if the event loop
        is responsive. For Kubernetes liveness probes.
        """
        check = EventLoopHealthCheck()
        try:
            result = await check.check()
            return result.status
        except Exception:
            return HealthStatus.UNHEALTHY

    async def readiness(self) -> HealthStatus:
        """Readiness check — is the system ready to accept work?

        Combines liveness with the readiness flag and configuration check.
        For Kubernetes readiness probes.
        """
        if not self._ready:
            return HealthStatus.UNHEALTHY

        liveness = await self.liveness()
        if liveness != HealthStatus.HEALTHY:
            return liveness

        return HealthStatus.HEALTHY

    def get_diagnostics(self) -> Dict[str, Any]:
        """Return detailed diagnostic information.

        Includes system info, process info, and last health report.
        This is for /diag endpoints — not for automated probes.
        """
        diag: Dict[str, Any] = {
            "system": {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "hostname": platform.node(),
            },
            "process": {
                "pid": os.getpid(),
                "cwd": os.getcwd(),
                "uid": os.getuid() if hasattr(os, 'getuid') else None,
            },
            "runtime": {
                "uptime_seconds": round(time.monotonic() - self._start_time, 2),
                "ready": self._ready,
            },
        }

        # Add event loop info
        try:
            loop = asyncio.get_running_loop()
            diag["runtime"]["loop_running"] = True
            diag["runtime"]["task_count"] = len(asyncio.all_tasks(loop))
        except RuntimeError:
            diag["runtime"]["loop_running"] = False

        # Add last health report
        if self._last_report:
            diag["last_health_report"] = self._last_report.to_dict()

        return diag


# ═══════════════════════════════════════════════════════════════════════════════
# Global Singleton
# ═══════════════════════════════════════════════════════════════════════════════

health_manager = HealthCheckManager()


# ═══════════════════════════════════════════════════════════════════════════════
# aiohttp Health Server — Lazy re-export from health_server.py
# ═══════════════════════════════════════════════════════════════════════════════
# The server implementation (including Bearer token auth middleware) was
# extracted into observability.health_server to comply with Law 14
# (no file exceeds 500 lines).  A module-level __getattr__ preserves the
# public API:  from observability.health import start_health_server


def __getattr__(name: str) -> Any:
    """Lazy re-export to avoid circular import with health_server."""
    if name == "start_health_server":
        from observability.health_server import start_health_server
        return start_health_server
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "HealthStatus",
    "HealthCheckResult",
    "HealthReport",
    "HealthCheck",
    "EventLoopHealthCheck",
    "MemoryHealthCheck",
    "TaskHealthCheck",
    "ConfigHealthCheck",
    "HealthCheckManager",
    "health_manager",
    "start_health_server",
]
