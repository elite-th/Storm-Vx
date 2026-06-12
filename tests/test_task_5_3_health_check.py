"""Tests for Task 5.3: Health Check & Diagnostics.

Validates:
  - HealthStatus enum values
  - HealthCheckResult serialization
  - HealthReport serialization
  - EventLoopHealthCheck works
  - MemoryHealthCheck works
  - TaskHealthCheck works
  - ConfigHealthCheck works
  - HealthCheckManager orchestrates checks
  - Liveness and readiness probes
  - Diagnostics output
  - start_health_server function
"""
from __future__ import annotations

import asyncio
import json
import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# Health Status Model Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestHealthStatus:
    """Test HealthStatus enum."""

    def test_status_values(self):
        from observability.health import HealthStatus
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"
        assert HealthStatus.UNKNOWN.value == "unknown"

    def test_all_statuses_exist(self):
        from observability.health import HealthStatus
        statuses = list(HealthStatus)
        assert len(statuses) == 4


class TestHealthCheckResult:
    """Test HealthCheckResult dataclass."""

    def test_result_creation(self):
        from observability.health import HealthCheckResult, HealthStatus
        result = HealthCheckResult(
            name="test_check",
            status=HealthStatus.HEALTHY,
            message="All good",
            duration_ms=1.5,
        )
        assert result.name == "test_check"
        assert result.status == HealthStatus.HEALTHY
        assert result.message == "All good"
        assert result.duration_ms == 1.5

    def test_result_to_dict(self):
        from observability.health import HealthCheckResult, HealthStatus
        result = HealthCheckResult(
            name="memory",
            status=HealthStatus.DEGRADED,
            message="High memory",
            duration_ms=2.0,
            details={"usage_mb": 450.0},
        )
        d = result.to_dict()
        assert d["name"] == "memory"
        assert d["status"] == "degraded"
        assert d["message"] == "High memory"
        assert d["details"]["usage_mb"] == 450.0

    def test_result_default_details(self):
        from observability.health import HealthCheckResult, HealthStatus
        result = HealthCheckResult(
            name="test",
            status=HealthStatus.HEALTHY,
        )
        assert result.details == {}
        d = result.to_dict()
        assert d["details"] == {}


class TestHealthReport:
    """Test HealthReport dataclass."""

    def test_report_creation(self):
        from observability.health import HealthReport, HealthStatus
        report = HealthReport(status=HealthStatus.HEALTHY)
        assert report.status == HealthStatus.HEALTHY
        assert report.checks == []

    def test_report_to_dict(self):
        from observability.health import (
            HealthReport, HealthStatus, HealthCheckResult,
        )
        report = HealthReport(
            status=HealthStatus.DEGRADED,
            checks=[
                HealthCheckResult(name="a", status=HealthStatus.HEALTHY),
                HealthCheckResult(name="b", status=HealthStatus.DEGRADED),
            ],
            uptime_seconds=100.0,
            version="22.0.0",
        )
        d = report.to_dict()
        assert d["status"] == "degraded"
        assert len(d["checks"]) == 2
        assert d["uptime_seconds"] == 100.0
        assert d["version"] == "22.0.0"

    def test_report_json_serializable(self):
        from observability.health import HealthReport, HealthStatus, HealthCheckResult
        report = HealthReport(
            status=HealthStatus.HEALTHY,
            checks=[
                HealthCheckResult(name="test", status=HealthStatus.HEALTHY),
            ],
        )
        json_str = json.dumps(report.to_dict())
        assert "healthy" in json_str


# ═══════════════════════════════════════════════════════════════════════════════
# Individual Health Check Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestEventLoopHealthCheck:
    """Test EventLoopHealthCheck."""

    @pytest.mark.asyncio
    async def test_event_loop_healthy(self):
        from observability.health import EventLoopHealthCheck, HealthStatus
        check = EventLoopHealthCheck()
        result = await check.check()
        assert result.name == "event_loop"
        assert result.status == HealthStatus.HEALTHY
        assert result.duration_ms >= 0


class TestMemoryHealthCheck:
    """Test MemoryHealthCheck."""

    @pytest.mark.asyncio
    async def test_memory_check_runs(self):
        from observability.health import MemoryHealthCheck, HealthStatus
        check = MemoryHealthCheck()
        result = await check.check()
        assert result.name == "memory"
        assert result.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED, HealthStatus.UNHEALTHY)
        assert result.duration_ms >= 0
        assert "usage_mb" in result.details

    @pytest.mark.asyncio
    async def test_memory_check_with_low_thresholds(self):
        from observability.health import MemoryHealthCheck, HealthStatus
        # Set very low thresholds to trigger degraded/unhealthy
        check = MemoryHealthCheck(warning_mb=0.001, critical_mb=0.002)
        result = await check.check()
        # Should be at least degraded with such low thresholds
        assert result.status in (HealthStatus.DEGRADED, HealthStatus.UNHEALTHY)


class TestTaskHealthCheck:
    """Test TaskHealthCheck."""

    @pytest.mark.asyncio
    async def test_task_check_runs(self):
        from observability.health import TaskHealthCheck, HealthStatus
        check = TaskHealthCheck()
        result = await check.check()
        assert result.name == "asyncio_tasks"
        assert result.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)
        assert "task_count" in result.details
        assert result.details["task_count"] >= 1  # At least this test task


class TestConfigHealthCheck:
    """Test ConfigHealthCheck."""

    @pytest.mark.asyncio
    async def test_config_check_runs(self):
        from observability.health import ConfigHealthCheck, HealthStatus
        check = ConfigHealthCheck()
        result = await check.check()
        assert result.name == "configuration"
        # Should be healthy with valid config
        assert result.status in (HealthStatus.HEALTHY, HealthStatus.UNHEALTHY)


# ═══════════════════════════════════════════════════════════════════════════════
# Health Check Manager Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestHealthCheckManager:
    """Test HealthCheckManager orchestration."""

    def test_manager_has_default_checks(self):
        from observability.health import HealthCheckManager
        manager = HealthCheckManager()
        assert len(manager._checks) >= 4

    def test_add_custom_check(self):
        from observability.health import HealthCheckManager, HealthCheck, HealthCheckResult, HealthStatus
        manager = HealthCheckManager()

        class CustomCheck(HealthCheck):
            name = "custom"
            async def check(self) -> HealthCheckResult:
                return HealthCheckResult(name=self.name, status=HealthStatus.HEALTHY)

        initial_count = len(manager._checks)
        manager.add_check(CustomCheck())
        assert len(manager._checks) == initial_count + 1

    @pytest.mark.asyncio
    async def test_check_health_runs_all(self):
        from observability.health import HealthCheckManager, HealthStatus
        manager = HealthCheckManager()
        report = await manager.check_health()
        assert report.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED, HealthStatus.UNHEALTHY)
        assert len(report.checks) >= 4
        assert report.uptime_seconds > 0

    @pytest.mark.asyncio
    async def test_check_health_aggregates_worst(self):
        from observability.health import (
            HealthCheckManager, HealthCheck, HealthCheckResult, HealthStatus,
        )

        class AlwaysUnhealthy(HealthCheck):
            name = "always_unhealthy"
            async def check(self) -> HealthCheckResult:
                return HealthCheckResult(name=self.name, status=HealthStatus.UNHEALTHY)

        manager = HealthCheckManager()
        manager.add_check(AlwaysUnhealthy())
        report = await manager.check_health()
        assert report.status == HealthStatus.UNHEALTHY

    @pytest.mark.asyncio
    async def test_liveness_check(self):
        from observability.health import HealthCheckManager, HealthStatus
        manager = HealthCheckManager()
        status = await manager.liveness()
        assert status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_readiness_not_ready(self):
        from observability.health import HealthCheckManager, HealthStatus
        manager = HealthCheckManager()
        # Not marked as ready yet
        status = await manager.readiness()
        assert status == HealthStatus.UNHEALTHY

    @pytest.mark.asyncio
    async def test_readiness_after_set_ready(self):
        from observability.health import HealthCheckManager, HealthStatus
        manager = HealthCheckManager()
        manager.set_ready(True)
        status = await manager.readiness()
        assert status == HealthStatus.HEALTHY

    def test_get_diagnostics(self):
        from observability.health import HealthCheckManager
        manager = HealthCheckManager()
        diag = manager.get_diagnostics()
        assert "system" in diag
        assert "process" in diag
        assert "runtime" in diag
        assert diag["runtime"]["ready"] is False

    @pytest.mark.asyncio
    async def test_check_caches_last_report(self):
        from observability.health import HealthCheckManager
        manager = HealthCheckManager()
        report = await manager.check_health()
        assert manager._last_report is report
        diag = manager.get_diagnostics()
        assert "last_health_report" in diag


# ═══════════════════════════════════════════════════════════════════════════════
# Global Singleton Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestGlobalSingleton:
    """Test the global health_manager singleton."""

    def test_singleton_exists(self):
        from observability.health import health_manager
        assert health_manager is not None

    def test_singleton_is_manager(self):
        from observability.health import health_manager, HealthCheckManager
        assert isinstance(health_manager, HealthCheckManager)


# ═══════════════════════════════════════════════════════════════════════════════
# Health Server Tests (without actually starting server)
# ═══════════════════════════════════════════════════════════════════════════════

class TestHealthServer:
    """Test health server function."""

    def test_start_health_server_importable(self):
        from observability.health import start_health_server
        assert callable(start_health_server)


# ═══════════════════════════════════════════════════════════════════════════════
# Exception in Health Check Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestHealthCheckExceptions:
    """Test that health checks handle exceptions gracefully."""

    @pytest.mark.asyncio
    async def test_check_that_raises(self):
        from observability.health import (
            HealthCheckManager, HealthCheck, HealthCheckResult, HealthStatus,
        )

        class BrokenCheck(HealthCheck):
            name = "broken"
            async def check(self) -> HealthCheckResult:
                raise RuntimeError("Intentional error")

        manager = HealthCheckManager()
        manager.add_check(BrokenCheck())
        report = await manager.check_health()
        # The broken check should be caught and reported as UNKNOWN
        broken_result = next(c for c in report.checks if c.name == "broken")
        assert broken_result.status == HealthStatus.UNKNOWN
        assert "Intentional error" in broken_result.message
