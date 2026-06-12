"""Tests for Task 5.1: Structured Logging System.

Validates:
  - ErrorCode taxonomy and string representation
  - Context variable enrichment (correlation_id, component, target, worker)
  - StructuredJsonFormatter produces valid JSON with expected fields
  - EnrichedTextFormatter adds context prefixes
  - get_structured_logger returns working logger
  - log_error / log_warning helpers add error_code to extra
  - Backward compatibility with logging_config.get_logger()
  - Environment variable detection (STORM_VX_LOG_FORMAT)
  - Unhandled exception handler installation
  - Async exception handler installation
"""
from __future__ import annotations

import json
import logging
import os
import io
import sys
import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# ErrorCode Taxonomy Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestErrorCode:
    """Test ErrorCode dataclass and ErrorCategory enum."""

    def test_error_code_str_format(self):
        from observability.logging_ext import ErrorCode, ErrorCategory
        code = ErrorCode(ErrorCategory.NETWORK, 101)
        assert str(code) == "NET-101"

    def test_error_code_str_format_high_number(self):
        from observability.logging_ext import ErrorCode, ErrorCategory
        code = ErrorCode(ErrorCategory.WAF, 204)
        assert str(code) == "WAF-204"

    def test_error_code_metric_label(self):
        from observability.logging_ext import ErrorCode, ErrorCategory
        code = ErrorCode(ErrorCategory.NETWORK, 101)
        assert code.metric_label == "network_101"

    def test_error_code_immutable(self):
        from observability.logging_ext import ErrorCode, ErrorCategory
        code = ErrorCode(ErrorCategory.CONFIG, 301)
        with pytest.raises(AttributeError):
            code.category = ErrorCategory.NETWORK  # type: ignore

    def test_error_category_values(self):
        from observability.logging_ext import ErrorCategory
        assert ErrorCategory.NETWORK.value == "NET"
        assert ErrorCategory.WAF.value == "WAF"
        assert ErrorCategory.CONFIG.value == "CFG"
        assert ErrorCategory.PLUGIN.value == "PLG"
        assert ErrorCategory.RESOURCE.value == "RES"
        assert ErrorCategory.SECURITY.value == "SEC"
        assert ErrorCategory.INTERNAL.value == "INT"

    def test_predefined_error_codes_exist(self):
        from observability.logging_ext import (
            ERR_CONNECTION_REFUSED, ERR_CONNECTION_TIMEOUT,
            ERR_DNS_FAILURE, ERR_SSL_ERROR,
            ERR_WAF_BLOCKED, ERR_WAF_CHALLENGE,
            ERR_CONFIG_INVALID, ERR_PLUGIN_CRASH,
            ERR_MEMORY_LIMIT, ERR_UNHANDLED_EXCEPTION,
        )
        assert str(ERR_CONNECTION_REFUSED) == "NET-101"
        assert str(ERR_CONNECTION_TIMEOUT) == "NET-102"
        assert str(ERR_DNS_FAILURE) == "NET-103"
        assert str(ERR_SSL_ERROR) == "NET-104"
        assert str(ERR_WAF_BLOCKED) == "WAF-201"
        assert str(ERR_WAF_CHALLENGE) == "WAF-202"
        assert str(ERR_CONFIG_INVALID) == "CFG-301"
        assert str(ERR_PLUGIN_CRASH) == "PLG-402"
        assert str(ERR_MEMORY_LIMIT) == "RES-501"
        assert str(ERR_UNHANDLED_EXCEPTION) == "INT-701"

    def test_all_predefined_codes_unique(self):
        from observability.logging_ext import (
            ERR_CONNECTION_REFUSED, ERR_CONNECTION_TIMEOUT,
            ERR_DNS_FAILURE, ERR_SSL_ERROR, ERR_CONNECTION_RESET,
            ERR_POOL_EXHAUSTED,
            ERR_WAF_BLOCKED, ERR_WAF_CHALLENGE,
            ERR_WAF_RATE_LIMITED, ERR_WAF_BYPASS_FAILED,
            ERR_CONFIG_INVALID, ERR_CONFIG_MISSING, ERR_CONFIG_CONFLICT,
            ERR_PLUGIN_LOAD, ERR_PLUGIN_CRASH,
            ERR_PLUGIN_TIMEOUT, ERR_PLUGIN_MISCONFIG,
            ERR_MEMORY_LIMIT, ERR_FILE_LIMIT,
            ERR_TASK_LIMIT, ERR_RESPONSE_TOO_LARGE,
            ERR_SSL_VERIFICATION, ERR_PATH_TRAVERSAL,
            ERR_INPUT_VALIDATION,
            ERR_UNHANDLED_EXCEPTION, ERR_ASYNC_CANCELLED,
            ERR_STATE_CORRUPTION,
        )
        all_codes = [
            ERR_CONNECTION_REFUSED, ERR_CONNECTION_TIMEOUT,
            ERR_DNS_FAILURE, ERR_SSL_ERROR, ERR_CONNECTION_RESET,
            ERR_POOL_EXHAUSTED,
            ERR_WAF_BLOCKED, ERR_WAF_CHALLENGE,
            ERR_WAF_RATE_LIMITED, ERR_WAF_BYPASS_FAILED,
            ERR_CONFIG_INVALID, ERR_CONFIG_MISSING, ERR_CONFIG_CONFLICT,
            ERR_PLUGIN_LOAD, ERR_PLUGIN_CRASH,
            ERR_PLUGIN_TIMEOUT, ERR_PLUGIN_MISCONFIG,
            ERR_MEMORY_LIMIT, ERR_FILE_LIMIT,
            ERR_TASK_LIMIT, ERR_RESPONSE_TOO_LARGE,
            ERR_SSL_VERIFICATION, ERR_PATH_TRAVERSAL,
            ERR_INPUT_VALIDATION,
            ERR_UNHANDLED_EXCEPTION, ERR_ASYNC_CANCELLED,
            ERR_STATE_CORRUPTION,
        ]
        str_codes = [str(c) for c in all_codes]
        assert len(str_codes) == len(set(str_codes)), f"Duplicate codes found: {str_codes}"


# ═══════════════════════════════════════════════════════════════════════════════
# Context Variable Enrichment Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestContextEnrichment:
    """Test log context variable enrichment."""

    def test_correlation_id_generation(self):
        from observability.logging_ext import new_correlation_id, correlation_id
        cid = new_correlation_id()
        assert len(cid) == 12
        assert cid.isalnum()
        assert correlation_id.get("") == cid

    def test_set_log_context(self):
        from observability.logging_ext import (
            set_log_context, clear_log_context,
            correlation_id, component_name, target_host, worker_id_ctx,
        )
        set_log_context(
            correlation_id_val="test123",
            component="api_flood",
            target="example.com",
            worker=3,
        )
        assert correlation_id.get("") == "test123"
        assert component_name.get("") == "api_flood"
        assert target_host.get("") == "example.com"
        assert worker_id_ctx.get(-1) == 3

        clear_log_context()
        assert correlation_id.get("") == ""
        assert component_name.get("") == ""
        assert target_host.get("") == ""
        assert worker_id_ctx.get(-1) == -1

    def test_enrichment_dict_empty(self):
        from observability.logging_ext import _get_enrichment_dict, clear_log_context
        clear_log_context()
        result = _get_enrichment_dict()
        assert result == {}

    def test_enrichment_dict_populated(self):
        from observability.logging_ext import (
            set_log_context, clear_log_context, _get_enrichment_dict,
        )
        set_log_context(
            correlation_id_val="abc456",
            component="scanner",
            target="test.local",
            worker=1,
        )
        result = _get_enrichment_dict()
        assert result["correlation_id"] == "abc456"
        assert result["component"] == "scanner"
        assert result["target"] == "test.local"
        assert result["worker_id"] == 1

        clear_log_context()

    def test_enrichment_dict_skips_defaults(self):
        from observability.logging_ext import (
            set_log_context, clear_log_context, _get_enrichment_dict,
        )
        # Only set correlation_id, leave others as defaults
        set_log_context(correlation_id_val="only_cid")
        result = _get_enrichment_dict()
        assert "correlation_id" in result
        assert "component" not in result
        assert "target" not in result
        assert "worker_id" not in result

        clear_log_context()


# ═══════════════════════════════════════════════════════════════════════════════
# StructuredJsonFormatter Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestStructuredJsonFormatter:
    """Test JSON log formatter output."""

    def test_basic_json_output(self):
        from observability.logging_ext import StructuredJsonFormatter, clear_log_context
        clear_log_context()
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test.module",
            level=logging.ERROR,
            pathname="test.py",
            lineno=42,
            msg="Connection refused",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "ERROR"
        assert data["logger"] == "test.module"
        assert data["message"] == "Connection refused"
        assert "timestamp" in data

    def test_json_with_error_code(self):
        from observability.logging_ext import StructuredJsonFormatter, ERR_CONNECTION_REFUSED, clear_log_context
        clear_log_context()
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Connection failed",
            args=(),
            exc_info=None,
        )
        record.error_code = ERR_CONNECTION_REFUSED
        output = formatter.format(record)
        data = json.loads(output)
        assert data["error_code"] == "NET-101"

    def test_json_with_context_enrichment(self):
        from observability.logging_ext import (
            StructuredJsonFormatter, set_log_context,
            clear_log_context,
        )
        set_log_context(
            correlation_id_val="ctx123",
            component="api_flood",
            target="test.local",
            worker=5,
        )
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Request completed",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["correlation_id"] == "ctx123"
        assert data["component"] == "api_flood"
        assert data["target"] == "test.local"
        assert data["worker_id"] == 5

        clear_log_context()

    def test_json_with_exception(self):
        from observability.logging_ext import StructuredJsonFormatter, clear_log_context
        clear_log_context()
        formatter = StructuredJsonFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys as _sys
            exc_info = _sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert data["exception"]["type"] == "ValueError"
        assert data["exception"]["message"] == "test error"

    def test_json_no_empty_enrichment(self):
        from observability.logging_ext import StructuredJsonFormatter, clear_log_context
        clear_log_context()
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Simple message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        # No context enrichment fields when empty
        assert "correlation_id" not in data
        assert "component" not in data
        assert "target" not in data
        assert "worker_id" not in data

    def test_json_timestamp_format(self):
        from observability.logging_ext import StructuredJsonFormatter, clear_log_context
        clear_log_context()
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        ts = data["timestamp"]
        assert ts.endswith("Z")
        assert "T" in ts
        # Should have milliseconds
        assert "." in ts.split("T")[1]


# ═══════════════════════════════════════════════════════════════════════════════
# EnrichedTextFormatter Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnrichedTextFormatter:
    """Test enriched text formatter with context prefixes."""

    def test_basic_text_output(self):
        from observability.logging_ext import EnrichedTextFormatter, clear_log_context
        clear_log_context()
        formatter = EnrichedTextFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Hello world",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "Hello world" in output
        assert "✓" in output

    def test_text_with_correlation_id(self):
        from observability.logging_ext import (
            EnrichedTextFormatter, set_log_context, clear_log_context,
        )
        set_log_context(correlation_id_val="abc123")
        formatter = EnrichedTextFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "abc123" in output
        assert "[" in output

        clear_log_context()

    def test_text_with_error_code(self):
        from observability.logging_ext import EnrichedTextFormatter, ERR_WAF_BLOCKED, clear_log_context
        clear_log_context()
        formatter = EnrichedTextFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="WAF blocked request",
            args=(),
            exc_info=None,
        )
        record.error_code = ERR_WAF_BLOCKED
        output = formatter.format(record)
        assert "WAF-201" in output

    def test_text_error_icon(self):
        from observability.logging_ext import EnrichedTextFormatter, clear_log_context
        clear_log_context()
        formatter = EnrichedTextFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "✗" in output

    def test_text_warning_icon(self):
        from observability.logging_ext import EnrichedTextFormatter, clear_log_context
        clear_log_context()
        formatter = EnrichedTextFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="Warning",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        assert "⚠" in output


# ═══════════════════════════════════════════════════════════════════════════════
# Logger Factory Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoggerFactory:
    """Test get_structured_logger and configure_root_logger."""

    def test_get_structured_logger_returns_logger(self):
        from observability.logging_ext import get_structured_logger
        log = get_structured_logger("test.factory")
        assert isinstance(log, logging.Logger)
        assert log.name == "test.factory"

    def test_configure_root_logger_text_format(self):
        from observability.logging_ext import configure_root_logger, _root_configured
        import observability.logging_ext as ext
        # Reset state
        ext._root_configured = False
        root = configure_root_logger(log_format="text", level=logging.DEBUG)
        assert root.name == "storm_vx"
        assert root.level == logging.DEBUG
        # Has at least one handler
        assert len(root.handlers) >= 1
        # Handler should use EnrichedTextFormatter
        handler = root.handlers[0]
        assert isinstance(handler.formatter, ext.EnrichedTextFormatter)

    def test_configure_root_logger_json_format(self):
        from observability.logging_ext import configure_root_logger
        import observability.logging_ext as ext
        ext._root_configured = False
        root = configure_root_logger(log_format="json", level=logging.INFO)
        assert root.name == "storm_vx"
        # Handler should use StructuredJsonFormatter
        handler = root.handlers[0]
        assert isinstance(handler.formatter, ext.StructuredJsonFormatter)

    def test_configure_root_logger_with_file(self, tmp_path):
        from observability.logging_ext import configure_root_logger
        import observability.logging_ext as ext
        ext._root_configured = False
        log_file = str(tmp_path / "test.log")
        root = configure_root_logger(
            log_format="text",
            level=logging.INFO,
            log_file=log_file,
        )
        # Should have 2 handlers: console + file
        assert len(root.handlers) == 2
        # File handler should use JSON formatter
        file_handler = root.handlers[1]
        assert isinstance(file_handler, logging.FileHandler)
        assert isinstance(file_handler.formatter, ext.StructuredJsonFormatter)

    def test_logger_produces_json_output(self):
        from observability.logging_ext import configure_root_logger, clear_log_context
        import observability.logging_ext as ext
        ext._root_configured = False
        root = configure_root_logger(log_format="json", level=logging.DEBUG)

        # Capture output
        stream = io.StringIO()
        root.handlers[0].stream = stream

        clear_log_context()
        root.info("Test JSON message")

        output = stream.getvalue().strip()
        data = json.loads(output)
        assert data["message"] == "Test JSON message"
        assert data["level"] == "INFO"


# ═══════════════════════════════════════════════════════════════════════════════
# Logging Helper Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoggingHelpers:
    """Test log_error, log_warning, log_with_context helpers."""

    def _make_capture_logger(self) -> tuple[logging.Logger, io.StringIO]:
        """Create a logger that captures output to a StringIO."""
        import observability.logging_ext as ext
        ext._root_configured = False
        ext.configure_root_logger(log_format="json", level=logging.DEBUG)
        root = logging.getLogger("storm_vx")
        stream = io.StringIO()
        root.handlers[0].stream = stream
        test_logger = logging.getLogger("storm_vx.test_helpers")
        return test_logger, stream

    def test_log_error_adds_error_code(self):
        from observability.logging_ext import log_error, ERR_CONNECTION_REFUSED, clear_log_context
        clear_log_context()
        test_logger, stream = self._make_capture_logger()

        log_error(test_logger, "Connection refused", ERR_CONNECTION_REFUSED)

        output = stream.getvalue().strip()
        data = json.loads(output)
        assert data["error_code"] == "NET-101"
        assert data["message"] == "Connection refused"
        assert data["level"] == "ERROR"

    def test_log_warning_with_error_code(self):
        from observability.logging_ext import log_warning, ERR_WAF_RATE_LIMITED, clear_log_context
        clear_log_context()
        test_logger, stream = self._make_capture_logger()

        log_warning(test_logger, "Rate limited", ERR_WAF_RATE_LIMITED)

        output = stream.getvalue().strip()
        data = json.loads(output)
        assert data["error_code"] == "WAF-203"
        assert data["level"] == "WARNING"

    def test_log_warning_without_error_code(self):
        from observability.logging_ext import log_warning, clear_log_context
        clear_log_context()
        test_logger, stream = self._make_capture_logger()

        log_warning(test_logger, "Something seems off")

        output = stream.getvalue().strip()
        data = json.loads(output)
        assert "error_code" not in data
        assert data["message"] == "Something seems off"

    def test_log_with_context_overrides(self):
        from observability.logging_ext import log_with_context, clear_log_context
        clear_log_context()
        test_logger, stream = self._make_capture_logger()

        log_with_context(
            test_logger,
            logging.INFO,
            "Contextual message",
            correlation_id_val="override_cid",
            component="test_comp",
            target="test.local",
            worker=7,
        )

        output = stream.getvalue().strip()
        data = json.loads(output)
        assert data["correlation_id"] == "override_cid"
        assert data["component"] == "test_comp"
        assert data["target"] == "test.local"
        assert data["worker_id"] == 7


# ═══════════════════════════════════════════════════════════════════════════════
# Backward Compatibility Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestBackwardCompatibility:
    """Test that existing logging_config.get_logger() still works."""

    def test_get_logger_returns_logger(self):
        from logging_config import get_logger
        log = get_logger("test.backward_compat")
        assert isinstance(log, logging.Logger)
        assert log.name == "test.backward_compat"

    def test_get_logger_text_mode_default(self):
        """When no env var is set, get_logger returns a standard logger."""
        from logging_config import get_logger
        # Ensure STORM_VX_LOG_FORMAT is not set
        old = os.environ.pop("STORM_VX_LOG_FORMAT", None)
        try:
            log = get_logger("test.default_mode")
            assert isinstance(log, logging.Logger)
        finally:
            if old is not None:
                os.environ["STORM_VX_LOG_FORMAT"] = old

    def test_logging_config_setup_logger_works(self):
        from logging_config import setup_logger
        log = setup_logger("test.setup_logger_compat")
        assert isinstance(log, logging.Logger)

    def test_ensure_utf8_console_no_crash(self):
        """ensure_utf8_console should not crash on any platform."""
        from logging_config import ensure_utf8_console
        # Should be a no-op on Linux
        ensure_utf8_console()


# ═══════════════════════════════════════════════════════════════════════════════
# Exception Handler Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestExceptionHandlers:
    """Test unhandled exception handler installation."""

    def test_install_exception_handler(self):
        from observability.logging_ext import install_exception_handler
        original = sys.excepthook
        try:
            install_exception_handler()
            # Should have changed sys.excepthook
            assert sys.excepthook is not original
        finally:
            sys.excepthook = original

    def test_install_async_exception_handler_no_loop(self):
        """Should not crash when no event loop is running."""
        from observability.logging_ext import install_async_exception_handler
        # This should gracefully handle the case where no loop is running
        try:
            install_async_exception_handler()
        except RuntimeError:
            pass  # Expected if no loop running


# ═══════════════════════════════════════════════════════════════════════════════
# Environment Variable Detection Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnvironmentDetection:
    """Test environment variable-based configuration."""

    def test_detect_log_format_default(self):
        from observability.logging_ext import _detect_log_format
        old = os.environ.pop("STORM_VX_LOG_FORMAT", None)
        try:
            assert _detect_log_format() == "text"
        finally:
            if old is not None:
                os.environ["STORM_VX_LOG_FORMAT"] = old

    def test_detect_log_format_json(self):
        from observability.logging_ext import _detect_log_format
        old = os.environ.get("STORM_VX_LOG_FORMAT")
        try:
            os.environ["STORM_VX_LOG_FORMAT"] = "json"
            assert _detect_log_format() == "json"
        finally:
            if old is not None:
                os.environ["STORM_VX_LOG_FORMAT"] = old
            else:
                os.environ.pop("STORM_VX_LOG_FORMAT", None)

    def test_detect_log_level(self):
        from observability.logging_ext import _detect_log_level
        old = os.environ.get("STORM_VX_LOG_LEVEL")
        try:
            os.environ["STORM_VX_LOG_LEVEL"] = "DEBUG"
            assert _detect_log_level() == logging.DEBUG

            os.environ["STORM_VX_LOG_LEVEL"] = "WARNING"
            assert _detect_log_level() == logging.WARNING

            os.environ.pop("STORM_VX_LOG_LEVEL", None)
            assert _detect_log_level() == logging.INFO  # Default
        finally:
            if old is not None:
                os.environ["STORM_VX_LOG_LEVEL"] = old
            else:
                os.environ.pop("STORM_VX_LOG_LEVEL", None)

    def test_detect_log_file(self):
        from observability.logging_ext import _detect_log_file
        old = os.environ.get("STORM_VX_LOG_FILE")
        try:
            os.environ["STORM_VX_LOG_FILE"] = "/tmp/storm.log"
            assert _detect_log_file() == "/tmp/storm.log"

            os.environ.pop("STORM_VX_LOG_FILE", None)
            assert _detect_log_file() is None
        finally:
            if old is not None:
                os.environ["STORM_VX_LOG_FILE"] = old
            else:
                os.environ.pop("STORM_VX_LOG_FILE", None)
