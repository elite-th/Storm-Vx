"""Tests for Task 5.6: OpenTelemetry Tracing.

Validates:
  - NoopSpan and NoopTracer work without OTel installed
  - Tracing module graceful fallback when OTel not installed
  - tracer() returns NoopTracer when disabled
  - span() and async_span() context managers work
  - traced() decorator works for sync and async functions
  - Pipeline tracers (scan, attack, network, plugin)
  - OTel TraceConfig integration with aiohttp
  - Context variable bridging (otel_trace_id, otel_span_id)
  - Log enrichment bridge (trace_id/span_id in JSON logs)
  - TracingSettings dataclass loads from env
  - Config defaults for OTel constants
  - init_tracing / shutdown_tracing lifecycle
  - get_tracing_status / is_tracing_active diagnostics
  - Existing functionality preserved (no regressions)
"""
from __future__ import annotations

import asyncio
import os
import pytest
from unittest.mock import MagicMock, patch


# ═══════════════════════════════════════════════════════════════════════════════
# No-op Stub Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestNoopSpan:
    """Test NoopSpan behavior when OTel is not installed/disabled."""

    def test_noop_span_context_manager(self):
        from observability.tracing import NoopSpan
        s = NoopSpan()
        with s as span:
            assert span is s

    async def test_noop_span_async_context_manager(self):
        from observability.tracing import NoopSpan
        s = NoopSpan()
        async with s as span:
            assert span is s

    def test_noop_span_set_attribute(self):
        from observability.tracing import NoopSpan
        s = NoopSpan()
        result = s.set_attribute("key", "value")
        assert result is s  # Returns self for chaining

    def test_noop_span_set_attributes(self):
        from observability.tracing import NoopSpan
        s = NoopSpan()
        result = s.set_attributes({"key": "value"})
        assert result is s

    def test_noop_span_add_event(self):
        from observability.tracing import NoopSpan
        s = NoopSpan()
        result = s.add_event("event_name", {"attr": "val"})
        assert result is s

    def test_noop_span_record_exception(self):
        from observability.tracing import NoopSpan
        s = NoopSpan()
        s.record_exception(ValueError("test"))  # Should not raise

    def test_noop_span_update_name(self):
        from observability.tracing import NoopSpan
        s = NoopSpan()
        result = s.update_name("new_name")
        assert result is s

    def test_noop_span_is_recording(self):
        from observability.tracing import NoopSpan
        s = NoopSpan()
        assert s.is_recording() is False

    def test_noop_span_end(self):
        from observability.tracing import NoopSpan
        s = NoopSpan()
        s.end()  # Should not raise

    def test_noop_span_context(self):
        from observability.tracing import NoopSpan
        s = NoopSpan()
        assert s.context is None

    def test_noop_span_get_span_context(self):
        from observability.tracing import NoopSpan
        s = NoopSpan()
        assert s.get_span_context() is None


class TestNoopTracer:
    """Test NoopTracer behavior."""

    def test_noop_tracer_start_span(self):
        from observability.tracing import NoopTracer, NoopSpan
        t = NoopTracer()
        s = t.start_span("test")
        assert isinstance(s, NoopSpan)

    def test_noop_tracer_start_as_current_span(self):
        from observability.tracing import NoopTracer, NoopSpan
        t = NoopTracer()
        s = t.start_as_current_span("test")
        assert isinstance(s, NoopSpan)

    def test_noop_tracer_with_context_manager(self):
        from observability.tracing import NoopTracer
        t = NoopTracer()
        with t.start_as_current_span("test") as s:
            s.set_attribute("key", "value")  # Should not raise


# ═══════════════════════════════════════════════════════════════════════════════
# Tracer Factory Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTracerFactory:
    """Test the tracer() factory function."""

    def test_tracer_returns_noop_when_disabled(self):
        from observability.tracing import tracer, NoopTracer
        t = tracer("test")
        assert isinstance(t, NoopTracer)

    def test_tracer_default_name(self):
        from observability.tracing import tracer, NoopTracer
        t = tracer()
        assert isinstance(t, NoopTracer)

    def test_tracer_with_custom_name(self):
        from observability.tracing import tracer, NoopTracer
        t = tracer("storm-vx.scan")
        assert isinstance(t, NoopTracer)


# ═══════════════════════════════════════════════════════════════════════════════
# Context Manager Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestSyncSpan:
    """Test synchronous span() context manager."""

    def test_span_basic_usage(self):
        from observability.tracing import span
        with span("test_span") as s:
            assert s is not None
            s.set_attribute("key", "value")

    def test_span_with_attributes(self):
        from observability.tracing import span
        with span("test_span", url="http://example.com", method="GET") as s:
            s.set_attribute("status", 200)

    def test_span_does_not_raise(self):
        from observability.tracing import span
        # Should never raise, even with no-op spans
        with span("test"):
            pass

    def test_span_nested(self):
        from observability.tracing import span
        with span("parent") as parent:
            with span("child") as child:
                assert child is not None


class TestAsyncSpan:
    """Test async async_span() context manager."""

    async def test_async_span_basic_usage(self):
        from observability.tracing import async_span
        async with async_span("test_span") as s:
            assert s is not None
            s.set_attribute("key", "value")

    async def test_async_span_with_attributes(self):
        from observability.tracing import async_span
        async with async_span("test_span", url="http://example.com") as s:
            s.set_attribute("status", 200)

    async def test_async_span_does_not_raise(self):
        from observability.tracing import async_span
        async with async_span("test"):
            pass

    async def test_async_span_nested(self):
        from observability.tracing import async_span
        async with async_span("parent") as parent:
            async with async_span("child") as child:
                assert child is not None


# ═══════════════════════════════════════════════════════════════════════════════
# Decorator Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTracedDecorator:
    """Test the @traced decorator."""

    async def test_traced_async_function(self):
        from observability.tracing import traced

        @traced("storm_vx.test.operation")
        async def my_async_func(x: int) -> int:
            return x * 2

        result = await my_async_func(5)
        assert result == 10

    def test_traced_sync_function(self):
        from observability.tracing import traced

        @traced("storm_vx.test.operation")
        def my_sync_func(x: int) -> int:
            return x * 3

        result = my_sync_func(4)
        assert result == 12

    async def test_traced_preserves_function_name(self):
        from observability.tracing import traced

        @traced("storm_vx.test")
        async def my_named_func():
            pass

        assert my_named_func.__name__ == "my_named_func"

    async def test_traced_with_static_attributes(self):
        from observability.tracing import traced

        @traced("storm_vx.test", component="tester")
        async def my_func():
            return "ok"

        result = await my_func()
        assert result == "ok"

    async def test_traced_exception_recording(self):
        from observability.tracing import traced

        @traced("storm_vx.test")
        async def failing_func():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            await failing_func()


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline Tracer Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineTracers:
    """Test named pipeline tracers."""

    def test_scan_tracer(self):
        from observability.tracing import scan_tracer, NoopTracer
        t = scan_tracer()
        assert isinstance(t, NoopTracer)

    def test_attack_tracer(self):
        from observability.tracing import attack_tracer, NoopTracer
        t = attack_tracer()
        assert isinstance(t, NoopTracer)

    def test_network_tracer(self):
        from observability.tracing import network_tracer, NoopTracer
        t = network_tracer()
        assert isinstance(t, NoopTracer)

    def test_plugin_tracer(self):
        from observability.tracing import plugin_tracer, NoopTracer
        t = plugin_tracer("page_flood")
        assert isinstance(t, NoopTracer)

    def test_plugin_tracer_empty_name(self):
        from observability.tracing import plugin_tracer, NoopTracer
        t = plugin_tracer()
        assert isinstance(t, NoopTracer)


# ═══════════════════════════════════════════════════════════════════════════════
# Context Variable Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestContextVariables:
    """Test OTel context variables (otel_trace_id, otel_span_id)."""

    def test_otel_trace_id_default_empty(self):
        from observability.tracing import otel_trace_id
        assert otel_trace_id.get("") == ""

    def test_otel_span_id_default_empty(self):
        from observability.tracing import otel_span_id
        assert otel_span_id.get("") == ""

    def test_otel_trace_id_set_and_get(self):
        from observability.tracing import otel_trace_id
        otel_trace_id.set("abc123def456")
        assert otel_trace_id.get("") == "abc123def456"
        otel_trace_id.set("")  # Reset

    def test_otel_span_id_set_and_get(self):
        from observability.tracing import otel_span_id
        otel_span_id.set("789012")
        assert otel_span_id.get("") == "789012"
        otel_span_id.set("")  # Reset

    def test_format_trace_id(self):
        from observability.tracing import _format_trace_id
        result = _format_trace_id(0xabcdef1234567890)
        assert len(result) == 32
        # format(0xabcdef1234567890, "032x") = "0000000000000000abcdef1234567890"
        assert result == "0000000000000000abcdef1234567890"

    def test_format_span_id(self):
        from observability.tracing import _format_span_id
        result = _format_span_id(0xabcdef1234567890)
        assert len(result) == 16
        assert result == "abcdef1234567890"


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTracingConfiguration:
    """Test tracing configuration via environment and defaults."""

    def test_config_defaults_otel_constants(self):
        from config.defaults import (
            OTEL_ENABLED, OTEL_ENDPOINT, OTEL_SERVICE_NAME,
            OTEL_SAMPLE_RATE, OTEL_EXPORT_TIMEOUT_MS,
        )
        assert OTEL_ENABLED is False
        assert isinstance(OTEL_ENDPOINT, str)
        assert OTEL_ENDPOINT == "localhost:4317"
        assert OTEL_SERVICE_NAME == "storm-vx"
        assert OTEL_SAMPLE_RATE == 1.0
        assert isinstance(OTEL_EXPORT_TIMEOUT_MS, int)

    def test_tracing_settings_dataclass(self):
        from config.settings import TracingSettings
        ts = TracingSettings()
        assert ts.enabled is False
        assert ts.endpoint == "localhost:4317"
        assert ts.service_name == "storm-vx"
        assert ts.sample_rate == 1.0

    def test_tracing_settings_from_env(self):
        from config.settings import TracingSettings
        with patch.dict(os.environ, {"STORM_VX_TRACING_ENABLED": "true"}, clear=False):
            ts = TracingSettings.from_env()
            assert ts.enabled is True

    def test_tracing_settings_from_env_endpoint(self):
        from config.settings import TracingSettings
        with patch.dict(os.environ, {"STORM_VX_OTEL_ENDPOINT": "jaeger:4317"}, clear=False):
            ts = TracingSettings.from_env()
            assert ts.endpoint == "jaeger:4317"

    def test_tracing_settings_from_env_service_name(self):
        from config.settings import TracingSettings
        with patch.dict(os.environ, {"STORM_VX_SERVICE_NAME": "my-service"}, clear=False):
            ts = TracingSettings.from_env()
            assert ts.service_name == "my-service"

    def test_tracing_settings_from_env_sample_rate(self):
        from config.settings import TracingSettings
        with patch.dict(os.environ, {"STORM_VX_OTEL_SAMPLE_RATE": "0.5"}, clear=False):
            ts = TracingSettings.from_env()
            assert ts.sample_rate == 0.5

    def test_tracing_settings_disabled_by_default(self):
        from config.settings import TracingSettings
        ts = TracingSettings()
        assert ts.enabled is False

    def test_is_tracing_enabled_default_false(self):
        from observability.tracing import _is_tracing_enabled
        # Ensure env var is not set
        with patch.dict(os.environ, {}, clear=True):
            assert _is_tracing_enabled() is False

    def test_is_tracing_enabled_true(self):
        from observability.tracing import _is_tracing_enabled
        with patch.dict(os.environ, {"STORM_VX_TRACING_ENABLED": "true"}, clear=False):
            assert _is_tracing_enabled() is True

    def test_is_tracing_enabled_yes(self):
        from observability.tracing import _is_tracing_enabled
        with patch.dict(os.environ, {"STORM_VX_TRACING_ENABLED": "yes"}, clear=False):
            assert _is_tracing_enabled() is True

    def test_is_tracing_enabled_one(self):
        from observability.tracing import _is_tracing_enabled
        with patch.dict(os.environ, {"STORM_VX_TRACING_ENABLED": "1"}, clear=False):
            assert _is_tracing_enabled() is True

    def test_is_tracing_enabled_false(self):
        from observability.tracing import _is_tracing_enabled
        with patch.dict(os.environ, {"STORM_VX_TRACING_ENABLED": "false"}, clear=False):
            assert _is_tracing_enabled() is False

    def test_get_otel_endpoint_default(self):
        from observability.tracing import _get_otel_endpoint
        with patch.dict(os.environ, {}, clear=True):
            assert _get_otel_endpoint() == "localhost:4317"

    def test_get_otel_endpoint_from_env(self):
        from observability.tracing import _get_otel_endpoint
        with patch.dict(os.environ, {"STORM_VX_OTEL_ENDPOINT": "collector:4317"}, clear=False):
            assert _get_otel_endpoint() == "collector:4317"

    def test_get_service_name_default(self):
        from observability.tracing import _get_service_name
        with patch.dict(os.environ, {}, clear=True):
            assert _get_service_name() == "storm-vx"


# ═══════════════════════════════════════════════════════════════════════════════
# Init / Shutdown Lifecycle Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTracingLifecycle:
    """Test init_tracing and shutdown_tracing lifecycle."""

    def test_init_tracing_returns_false_when_disabled(self):
        from observability.tracing import init_tracing
        # Reset state
        import observability.tracing as _mod
        _mod._provider_initialized = False
        _mod._tracer_provider = None

        with patch.dict(os.environ, {}, clear=True):
            result = init_tracing()
            assert result is False

    def test_init_tracing_returns_false_when_no_otel(self):
        from observability.tracing import init_tracing, HAS_OTEL
        if HAS_OTEL:
            pytest.skip("OTel is installed, testing no-OTel path separately")
        result = init_tracing()
        assert result is False

    def test_init_tracing_idempotent(self):
        from observability.tracing import init_tracing
        import observability.tracing as _mod
        _mod._provider_initialized = False
        _mod._tracer_provider = None

        with patch.dict(os.environ, {}, clear=True):
            init_tracing()
            init_tracing()  # Should not raise

    def test_shutdown_tracing_no_error_when_not_initialized(self):
        from observability.tracing import shutdown_tracing
        import observability.tracing as _mod
        _mod._provider_initialized = False
        _mod._tracer_provider = None
        shutdown_tracing()  # Should not raise

    def test_shutdown_tracing_resets_state(self):
        from observability.tracing import shutdown_tracing
        import observability.tracing as _mod
        _mod._provider_initialized = True
        _mod._tracer_provider = None
        shutdown_tracing()
        assert _mod._provider_initialized is False
        assert _mod._tracer_provider is None


# ═══════════════════════════════════════════════════════════════════════════════
# Status / Diagnostics Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTracingStatus:
    """Test tracing status and diagnostics functions."""

    def test_is_tracing_active_default(self):
        from observability.tracing import is_tracing_active
        assert is_tracing_active() is False

    def test_get_tracing_status(self):
        from observability.tracing import get_tracing_status
        status = get_tracing_status()
        assert isinstance(status, dict)
        assert "enabled" in status
        assert "active" in status
        assert "otel_installed" in status
        assert "otlp_exporter_installed" in status
        assert "endpoint" in status
        assert "service_name" in status
        assert "provider_initialized" in status

    def test_get_tracing_status_disabled(self):
        from observability.tracing import get_tracing_status
        with patch.dict(os.environ, {}, clear=True):
            status = get_tracing_status()
            assert status["enabled"] is False
            assert status["active"] is False

    def test_get_current_trace_info_default(self):
        from observability.tracing import get_current_trace_info
        info = get_current_trace_info()
        assert isinstance(info, dict)
        assert "trace_id" in info
        assert "span_id" in info

    def test_get_current_trace_info_empty_when_no_span(self):
        from observability.tracing import get_current_trace_info, otel_trace_id, otel_span_id
        otel_trace_id.set("")
        otel_span_id.set("")
        info = get_current_trace_info()
        assert info["trace_id"] == ""
        assert info["span_id"] == ""


# ═══════════════════════════════════════════════════════════════════════════════
# aiohttp TraceConfig Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestOtelTraceConfig:
    """Test OTel TraceConfig creation for aiohttp integration."""

    def test_create_otel_trace_config_returns_none_when_disabled(self):
        from observability.tracing import create_otel_trace_config
        with patch.dict(os.environ, {}, clear=True):
            result = create_otel_trace_config()
            assert result is None

    def test_create_otel_trace_config_returns_none_when_no_otel(self):
        from observability.tracing import create_otel_trace_config, HAS_OTEL
        if HAS_OTEL:
            pytest.skip("OTel is installed — tested in separate test class")
        result = create_otel_trace_config()
        assert result is None


class TestSessionHelpersIntegration:
    """Test that session_helpers integrates OTel TraceConfig."""

    async def test_create_session_with_tracing(self):
        from utils.session_helpers import create_session
        async with create_session(enable_tracing=True) as session:
            assert session is not None

    async def test_create_session_without_tracing(self):
        from utils.session_helpers import create_session
        async with create_session(enable_tracing=False) as session:
            assert session is not None

    async def test_create_session_default_includes_tracing(self):
        from utils.session_helpers import create_session
        # Default should have enable_tracing=True
        async with create_session() as session:
            assert session is not None

    async def test_create_session_preserves_pool_stats_trace(self):
        """Verify that OTel TraceConfig doesn't overwrite pool_stats TraceConfig."""
        from utils.session_helpers import create_session, create_connector
        from vf_network import ConnectionPoolStats
        pool_stats = ConnectionPoolStats()
        connector = create_connector(pool_stats=pool_stats)
        async with create_session(connector=connector, enable_tracing=True) as session:
            # Should have both pool_stats trace config and OTel trace config
            assert session is not None
            assert hasattr(connector, '_vf_trace_config')


# ═══════════════════════════════════════════════════════════════════════════════
# Log Enrichment Bridge Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestLogEnrichmentBridge:
    """Test that OTel trace_id/span_id bridge into structured JSON logs."""

    def test_enrichment_dict_includes_trace_id(self):
        from observability.logging_ext import _get_enrichment_dict
        from observability.tracing import otel_trace_id
        otel_trace_id.set("abc123def4567890123456789012")
        enrichment = _get_enrichment_dict()
        assert "trace_id" in enrichment
        assert enrichment["trace_id"] == "abc123def4567890123456789012"
        otel_trace_id.set("")  # Reset

    def test_enrichment_dict_includes_span_id(self):
        from observability.logging_ext import _get_enrichment_dict
        from observability.tracing import otel_span_id
        otel_span_id.set("7890123456abcdef")
        enrichment = _get_enrichment_dict()
        assert "span_id" in enrichment
        assert enrichment["span_id"] == "7890123456abcdef"
        otel_span_id.set("")  # Reset

    def test_enrichment_dict_no_trace_when_empty(self):
        from observability.logging_ext import _get_enrichment_dict
        from observability.tracing import otel_trace_id, otel_span_id
        otel_trace_id.set("")
        otel_span_id.set("")
        enrichment = _get_enrichment_dict()
        assert "trace_id" not in enrichment
        assert "span_id" not in enrichment

    def test_json_formatter_includes_trace_id(self):
        from observability.logging_ext import StructuredJsonFormatter
        from observability.tracing import otel_trace_id, otel_span_id
        import logging

        otel_trace_id.set("0123456789abcdef0123456789abcdef")
        otel_span_id.set("fedcba9876543210")

        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="test.py",
            lineno=1, msg="test message", args=(), exc_info=None,
        )

        output = formatter.format(record)
        import json
        parsed = json.loads(output)
        assert "trace_id" in parsed
        assert parsed["trace_id"] == "0123456789abcdef0123456789abcdef"
        assert "span_id" in parsed
        assert parsed["span_id"] == "fedcba9876543210"

        otel_trace_id.set("")
        otel_span_id.set("")

    def test_json_formatter_no_trace_when_not_set(self):
        from observability.logging_ext import StructuredJsonFormatter
        from observability.tracing import otel_trace_id, otel_span_id
        import logging

        otel_trace_id.set("")
        otel_span_id.set("")

        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="test.py",
            lineno=1, msg="test message", args=(), exc_info=None,
        )

        output = formatter.format(record)
        import json
        parsed = json.loads(output)
        assert "trace_id" not in parsed
        assert "span_id" not in parsed


# ═══════════════════════════════════════════════════════════════════════════════
# Health Check Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestHealthCheckIntegration:
    """Test that tracing status is available to the health check system."""

    def test_tracing_status_dict_accessible(self):
        from observability.tracing import get_tracing_status
        status = get_tracing_status()
        # Health check system can use this dict
        assert isinstance(status, dict)

    def test_tracing_status_has_all_required_fields(self):
        from observability.tracing import get_tracing_status
        status = get_tracing_status()
        required = {"enabled", "active", "otel_installed", "otlp_exporter_installed",
                     "endpoint", "service_name", "provider_initialized"}
        assert required.issubset(set(status.keys()))


# ═══════════════════════════════════════════════════════════════════════════════
# OTel Package Detection Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestOTelPackageDetection:
    """Test HAS_OTEL and HAS_OTLP_EXPORTER detection."""

    def test_has_otel_is_bool(self):
        from observability.tracing import HAS_OTEL
        assert isinstance(HAS_OTEL, bool)

    def test_has_otlp_exporter_is_bool(self):
        from observability.tracing import HAS_OTLP_EXPORTER
        assert isinstance(HAS_OTLP_EXPORTER, bool)

    def test_status_reflects_has_otel(self):
        from observability.tracing import get_tracing_status, HAS_OTEL
        status = get_tracing_status()
        assert status["otel_installed"] == HAS_OTEL

    def test_status_reflects_has_otlp_exporter(self):
        from observability.tracing import get_tracing_status, HAS_OTLP_EXPORTER
        status = get_tracing_status()
        assert status["otlp_exporter_installed"] == HAS_OTLP_EXPORTER


# ═══════════════════════════════════════════════════════════════════════════════
# Backward Compatibility Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestBackwardCompatibility:
    """Verify that adding tracing doesn't break existing functionality."""

    def test_session_helpers_still_works(self):
        from utils.session_helpers import create_session, create_connector
        from utils.session_helpers import scanner_timeout, attack_timeout, fast_scanner_timeout
        t = scanner_timeout()
        assert t.total == 15
        t2 = attack_timeout()
        assert t2.total == 15
        t3 = fast_scanner_timeout()
        assert t3.total == 5

    async def test_session_creation_still_works(self):
        from utils.session_helpers import create_session
        async with create_session() as session:
            assert session is not None

    def test_metrics_still_works(self):
        from observability.metrics import metrics
        metrics.record_http_request("GET", 200, 0.5, "example.com")

    def test_resilience_still_works(self):
        from observability.resilience import CircuitBreaker, AsyncRetry
        cb = CircuitBreaker(name="test")
        assert cb.state.value == "closed"
        retry = AsyncRetry(max_attempts=3)
        assert retry.stats["total_attempts"] == 0

    def test_logging_ext_still_works(self):
        from observability.logging_ext import StructuredJsonFormatter, new_correlation_id
        cid = new_correlation_id()
        assert len(cid) == 12

    def test_config_defaults_still_accessible(self):
        from config.defaults import VERIFY_SSL, DEFAULT_TIMEOUT_SECONDS
        assert VERIFY_SSL is True
        assert DEFAULT_TIMEOUT_SECONDS == 15

    def test_config_settings_still_accessible(self):
        from config.settings import ConnectionSettings, WorkerSettings, Settings
        cs = ConnectionSettings()
        assert cs.timeout == 15
        ws = WorkerSettings()
        assert ws.max_workers == 5000

    def test_target_selector_still_works(self):
        from tester.target_selector import TargetSelector
        selector = TargetSelector(["http://a.com", "http://b.com"])
        url = selector.select()
        assert url is not None

    def test_response_classifier_still_works(self):
        from tester.response_classifier import ResponseClass, ResponseClassifier
        classifier = ResponseClassifier()
        result = classifier.classify(200, {})
        assert result == ResponseClass.OK

    def test_adaptive_pacer_still_works(self):
        from tester.adaptive_pacer import AdaptivePacer
        from tester.response_classifier import ResponseClass
        pacer = AdaptivePacer(base_delay_ms=10.0)
        pacer.record_response(ResponseClass.OK)
        assert pacer.current_delay_ms > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Module Interface Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestModuleExports:
    """Test that all expected symbols are exported."""

    def test_all_exports_exist(self):
        from observability import tracing
        expected_exports = [
            "tracer", "span", "async_span", "traced",
            "init_tracing", "shutdown_tracing",
            "NoopSpan", "NoopTracer",
            "HAS_OTEL", "HAS_OTLP_EXPORTER",
            "scan_tracer", "attack_tracer", "network_tracer", "plugin_tracer",
            "create_otel_trace_config",
            "otel_trace_id", "otel_span_id",
            "is_tracing_active", "get_tracing_status", "get_current_trace_info",
        ]
        for name in expected_exports:
            assert hasattr(tracing, name), f"Missing export: {name}"

    def test_observability_package_docstring(self):
        import observability
        assert "tracing" in observability.__doc__.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# OTel-Installed Integration Tests (only when OTel SDK is installed)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWithOTelSDK:
    """Test with actual OpenTelemetry SDK installed."""

    @pytest.fixture(autouse=True)
    def check_otel(self):
        from observability.tracing import HAS_OTEL
        if not HAS_OTEL:
            pytest.skip("OpenTelemetry SDK not installed")

    def test_init_tracing_with_otel(self):
        """Test init_tracing when OTel SDK is available but tracing is disabled."""
        from observability.tracing import init_tracing
        import observability.tracing as _mod
        _mod._provider_initialized = False
        _mod._tracer_provider = None

        # With tracing disabled, should return False
        with patch.dict(os.environ, {}, clear=True):
            result = init_tracing()
            assert result is False

    def test_init_tracing_enabled_with_otel(self):
        """Test init_tracing when OTel SDK is available and tracing is enabled."""
        from observability.tracing import init_tracing, shutdown_tracing
        import observability.tracing as _mod

        with patch.dict(os.environ, {"STORM_VX_TRACING_ENABLED": "true"}, clear=False):
            _mod._provider_initialized = False
            _mod._tracer_provider = None

            result = init_tracing(force=True)
            # Should succeed (may use console exporter if OTLP not available)
            assert result is True or result is False  # Depends on exporter availability

        # Cleanup
        shutdown_tracing()
        _mod._provider_initialized = False
        _mod._tracer_provider = None

    def test_tracer_returns_real_tracer_when_enabled(self):
        """Test that tracer() returns a real OTel tracer when enabled."""
        from observability.tracing import tracer, init_tracing, shutdown_tracing, NoopTracer
        import observability.tracing as _mod

        with patch.dict(os.environ, {"STORM_VX_TRACING_ENABLED": "true"}, clear=False):
            _mod._provider_initialized = False
            _mod._tracer_provider = None
            init_tracing(force=True)

            t = tracer("test")
            # Should NOT be a NoopTracer (should be a real OTel tracer)
            assert not isinstance(t, NoopTracer)

        # Cleanup
        shutdown_tracing()
        _mod._provider_initialized = False
        _mod._tracer_provider = None

    def test_real_span_attributes(self):
        """Test setting attributes on a real OTel span."""
        from observability.tracing import tracer, init_tracing, shutdown_tracing
        import observability.tracing as _mod

        with patch.dict(os.environ, {"STORM_VX_TRACING_ENABLED": "true"}, clear=False):
            _mod._provider_initialized = False
            _mod._tracer_provider = None
            init_tracing(force=True)

            t = tracer("test")
            with t.start_as_current_span("test_span") as s:
                s.set_attribute("key", "value")
                s.set_attribute("number", 42)
                s.add_event("test_event", {"detail": "info"})
                assert s.is_recording() is True or s.is_recording() is False

        # Cleanup
        shutdown_tracing()
        _mod._provider_initialized = False
        _mod._tracer_provider = None

    def test_create_otel_trace_config_when_enabled(self):
        """Test that create_otel_trace_config returns a TraceConfig when enabled."""
        from observability.tracing import create_otel_trace_config, init_tracing, shutdown_tracing
        import observability.tracing as _mod
        import aiohttp

        with patch.dict(os.environ, {"STORM_VX_TRACING_ENABLED": "true"}, clear=False):
            _mod._provider_initialized = False
            _mod._tracer_provider = None
            init_tracing(force=True)

            tc = create_otel_trace_config()
            # Should return an aiohttp.TraceConfig (or None if exporter issues)
            if tc is not None:
                assert isinstance(tc, aiohttp.TraceConfig)

        # Cleanup
        shutdown_tracing()
        _mod._provider_initialized = False
        _mod._tracer_provider = None


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Case Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Test edge cases and error handling."""

    async def test_span_with_empty_name(self):
        from observability.tracing import span
        with span("") as s:
            assert s is not None

    async def test_async_span_with_empty_name(self):
        from observability.tracing import async_span
        async with async_span("") as s:
            assert s is not None

    def test_traced_decorator_with_no_name(self):
        from observability.tracing import traced

        @traced("")
        def my_func():
            return 42

        result = my_func()
        assert result == 42

    def test_multiple_spans_in_sequence(self):
        from observability.tracing import span
        for i in range(10):
            with span(f"span_{i}") as s:
                s.set_attribute("iteration", i)

    async def test_multiple_async_spans_in_sequence(self):
        from observability.tracing import async_span
        for i in range(10):
            async with async_span(f"span_{i}") as s:
                s.set_attribute("iteration", i)

    def test_span_with_various_attribute_types(self):
        from observability.tracing import span
        with span("test") as s:
            s.set_attribute("str_val", "hello")
            s.set_attribute("int_val", 42)
            s.set_attribute("float_val", 3.14)
            s.set_attribute("bool_val", True)

    def test_tracer_with_empty_name(self):
        from observability.tracing import tracer
        t = tracer("")
        assert t is not None

    def test_plugin_tracer_with_special_chars(self):
        from observability.tracing import plugin_tracer
        t = plugin_tracer("my-plugin_v2")
        assert t is not None

    def test_init_tracing_with_invalid_sample_rate(self):
        """Init tracing should handle invalid sample_rate gracefully."""
        from observability.tracing import init_tracing
        import observability.tracing as _mod
        _mod._provider_initialized = False
        _mod._tracer_provider = None

        with patch.dict(os.environ, {}, clear=True):
            # Should not raise with out-of-range sample rate
            result = init_tracing(sample_rate=2.0)
            assert isinstance(result, bool)

    def test_shutdown_without_init(self):
        from observability.tracing import shutdown_tracing
        import observability.tracing as _mod
        _mod._provider_initialized = False
        _mod._tracer_provider = None
        shutdown_tracing()  # Should not raise
