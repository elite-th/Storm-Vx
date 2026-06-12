"""observability.logging_ext — Structured logging, enrichment, error codes.

W5.1 PRODUCTION LOGGING UPGRADE:

  1. JSON formatter — machine-parseable log output for log aggregation
  2. Log enrichment — automatic context injection (correlation_id, module, component)
  3. Error code taxonomy — machine-readable error categorisation
  4. Backward-compatible — existing get_logger() calls keep working; new
     features are opt-in via environment variables or explicit calls

DESIGN PRINCIPLES:
  - Zero-breakage: existing logging calls produce the same output by default
  - Opt-in structured: set STORM_VX_LOG_FORMAT=json to enable JSON output
  - Low overhead: JSON formatting only when enabled; context dict is lazy
  - No coupling: no dependency on prometheus, opentelemetry, or external services

ENVIRONMENT VARIABLES:
  - STORM_VX_LOG_FORMAT  : "text" (default) or "json"
  - STORM_VX_LOG_LEVEL   : "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
  - STORM_VX_LOG_FILE    : path to log file (optional)
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


# OPT-4: Module-level optional imports for redaction.
# Avoids try/except ImportError overhead on every formatter.format() call.
# In the logging hot path (5k+ log lines/sec), the repeated try/except
# adds ~100ns per call. A boolean check is ~10ns.
try:
    from security.secrets_guard import redact_secrets_inplace as _redact_secrets_inplace
    from security.secrets_guard import redact_log_message as _redact_log_message
    _HAS_REDACTION = True
except ImportError:
    _HAS_REDACTION = False


# ═══════════════════════════════════════════════════════════════════════════════
# Error Code Taxonomy — Machine-readable error categorisation
# ═══════════════════════════════════════════════════════════════════════════════

class ErrorCategory(Enum):
    """High-level error category for metrics and alerting.

    Each category maps to a prefix in error codes:
      NETWORK  → NET-xxx
      WAF      → WAF-xxx
      CONFIG   → CFG-xxx
      PLUGIN   → PLG-xxx
      RESOURCE → RES-xxx
      SECURITY → SEC-xxx
      INTERNAL → INT-xxx
    """
    NETWORK = "NET"
    WAF = "WAF"
    CONFIG = "CFG"
    PLUGIN = "PLG"
    RESOURCE = "RES"
    SECURITY = "SEC"
    INTERNAL = "INT"


@dataclass(frozen=True)
class ErrorCode:
    """Structured error code with category and numeric identifier.

    Usage:
        code = ErrorCode(ErrorCategory.NETWORK, 101)
        logger.error("Connection refused", extra={"error_code": code})
    """
    category: ErrorCategory
    number: int

    def __str__(self) -> str:
        return f"{self.category.value}-{self.number:03d}"

    @property
    def metric_label(self) -> str:
        """Label suitable for Prometheus metrics (lowercase, underscored)."""
        return f"{self.category.name.lower()}_{self.number:03d}"


# ─── Predefined Error Codes ────────────────────────────────────────────────
# Network errors (NET-1xx)
ERR_CONNECTION_REFUSED = ErrorCode(ErrorCategory.NETWORK, 101)
ERR_CONNECTION_TIMEOUT = ErrorCode(ErrorCategory.NETWORK, 102)
ERR_DNS_FAILURE = ErrorCode(ErrorCategory.NETWORK, 103)
ERR_SSL_ERROR = ErrorCode(ErrorCategory.NETWORK, 104)
ERR_CONNECTION_RESET = ErrorCode(ErrorCategory.NETWORK, 105)
ERR_POOL_EXHAUSTED = ErrorCode(ErrorCategory.NETWORK, 106)

# WAF errors (WAF-2xx)
ERR_WAF_BLOCKED = ErrorCode(ErrorCategory.WAF, 201)
ERR_WAF_CHALLENGE = ErrorCode(ErrorCategory.WAF, 202)
ERR_WAF_RATE_LIMITED = ErrorCode(ErrorCategory.WAF, 203)
ERR_WAF_BYPASS_FAILED = ErrorCode(ErrorCategory.WAF, 204)

# Config errors (CFG-3xx)
ERR_CONFIG_INVALID = ErrorCode(ErrorCategory.CONFIG, 301)
ERR_CONFIG_MISSING = ErrorCode(ErrorCategory.CONFIG, 302)
ERR_CONFIG_CONFLICT = ErrorCode(ErrorCategory.CONFIG, 303)

# Plugin errors (PLG-4xx)
ERR_PLUGIN_LOAD = ErrorCode(ErrorCategory.PLUGIN, 401)
ERR_PLUGIN_CRASH = ErrorCode(ErrorCategory.PLUGIN, 402)
ERR_PLUGIN_TIMEOUT = ErrorCode(ErrorCategory.PLUGIN, 403)
ERR_PLUGIN_MISCONFIG = ErrorCode(ErrorCategory.PLUGIN, 404)

# Resource errors (RES-5xx)
ERR_MEMORY_LIMIT = ErrorCode(ErrorCategory.RESOURCE, 501)
ERR_FILE_LIMIT = ErrorCode(ErrorCategory.RESOURCE, 502)
ERR_TASK_LIMIT = ErrorCode(ErrorCategory.RESOURCE, 503)
ERR_RESPONSE_TOO_LARGE = ErrorCode(ErrorCategory.RESOURCE, 504)

# Security errors (SEC-6xx)
ERR_SSL_VERIFICATION = ErrorCode(ErrorCategory.SECURITY, 601)
ERR_PATH_TRAVERSAL = ErrorCode(ErrorCategory.SECURITY, 602)
ERR_INPUT_VALIDATION = ErrorCode(ErrorCategory.SECURITY, 603)

# Internal errors (INT-7xx)
ERR_UNHANDLED_EXCEPTION = ErrorCode(ErrorCategory.INTERNAL, 701)
ERR_ASYNC_CANCELLED = ErrorCode(ErrorCategory.INTERNAL, 702)
ERR_STATE_CORRUPTION = ErrorCode(ErrorCategory.INTERNAL, 703)


# ═══════════════════════════════════════════════════════════════════════════════
# Context Variables — Request-scoped enrichment
# ═══════════════════════════════════════════════════════════════════════════════

correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
component_name: ContextVar[str] = ContextVar("component_name", default="")
target_host: ContextVar[str] = ContextVar("target_host", default="")
worker_id_ctx: ContextVar[int] = ContextVar("worker_id_ctx", default=-1)


def new_correlation_id() -> str:
    """Generate a new correlation ID and set it in the context."""
    cid = uuid.uuid4().hex[:12]
    correlation_id.set(cid)
    return cid


def set_log_context(
    *,
    correlation_id_val: str = "",
    component: str = "",
    target: str = "",
    worker: int = -1,
) -> None:
    """Set multiple context variables at once for log enrichment."""
    if correlation_id_val:
        correlation_id.set(correlation_id_val)
    if component:
        component_name.set(component)
    if target:
        target_host.set(target)
    if worker >= 0:
        worker_id_ctx.set(worker)


def clear_log_context() -> None:
    """Reset all log context variables."""
    correlation_id.set("")
    component_name.set("")
    target_host.set("")
    worker_id_ctx.set(-1)


def _get_enrichment_dict() -> Dict[str, Any]:
    """Build the enrichment dict from current context variables.

    W5.6: Now includes otel_trace_id and otel_span_id when available,
    bridging OpenTelemetry trace context into structured log entries.
    """
    result: Dict[str, Any] = {}
    cid = correlation_id.get("")
    if cid:
        result["correlation_id"] = cid
    comp = component_name.get("")
    if comp:
        result["component"] = comp
    host = target_host.get("")
    if host:
        result["target"] = host
    wid = worker_id_ctx.get(-1)
    if wid >= 0:
        result["worker_id"] = wid
    # W5.6: Bridge OTel trace context into log entries
    try:
        from observability.tracing import otel_trace_id, otel_span_id
        tid = otel_trace_id.get("")
        if tid:
            result["trace_id"] = tid
        sid = otel_span_id.get("")
        if sid:
            result["span_id"] = sid
    except ImportError:
        pass
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# JSON Log Formatter
# ═══════════════════════════════════════════════════════════════════════════════

class StructuredJsonFormatter(logging.Formatter):
    """JSON log formatter for production log aggregation.

    Output format:
    {
        "timestamp": "2025-03-05T14:30:00.123Z",
        "level": "ERROR",
        "logger": "tester.vf_basic_api_flood",
        "message": "Connection refused",
        "error_code": "NET-101",
        "correlation_id": "abc123def456",
        "component": "basic_api_flood",
        "target": "example.com",
        "worker_id": 3,
        "extra": { ... }
    }

    Fields are only included if they have values (no empty strings, no -1 worker IDs).
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": self._format_timestamp(record.created),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add enrichment from context variables
        enrichment = _get_enrichment_dict()
        log_entry.update(enrichment)

        # Add error_code from extra if present
        error_code = getattr(record, "error_code", None)
        if error_code is not None:
            log_entry["error_code"] = str(error_code)

        # Extract extra fields — promote known context fields to top level
        extra_fields = self._extract_extra(record)
        # Promote context fields from extra to top level (log_with_context)
        context_keys = {"correlation_id", "component", "target", "worker_id", "error_code"}
        promoted: Dict[str, Any] = {}
        remaining: Dict[str, Any] = {}
        for key, value in extra_fields.items():
            if key in context_keys:
                promoted[key] = value
            else:
                remaining[key] = value
        # Promoted fields override context-var enrichment (explicit > implicit)
        log_entry.update(promoted)
        if remaining:
            log_entry["extra"] = remaining

        # Add exception info
        if record.exc_info and record.exc_info[1] is not None:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else "Unknown",
                "message": str(record.exc_info[1]),
                "module": record.module,
                "lineno": record.lineno,
            }

        # W5.7: Redact secrets from log entry before serialization
        # OPT-3: Use inplace redaction — we own this dict (just constructed it)
        # and will immediately serialize it. No other references exist.
        # OPT-4: Use module-level import instead of try/except per call.
        if _HAS_REDACTION:
            _redact_secrets_inplace(log_entry)

        return json.dumps(log_entry, default=str, ensure_ascii=False)

    @staticmethod
    def _format_timestamp(created: float) -> str:
        """Format timestamp as ISO 8601 with milliseconds."""
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(created)) + f".{int(created * 1000) % 1000:03d}Z"

    @staticmethod
    def _extract_extra(record: logging.LogRecord) -> Dict[str, Any]:
        """Extract extra fields that were added to the log record."""
        # Standard LogRecord attributes to skip
        standard = {
            'name', 'msg', 'args', 'created', 'relativeCreated', 'thread',
            'threadName', 'msecs', 'filename', 'funcName', 'levelno',
            'lineno', 'exc_info', 'exc_text', 'stack_info', 'levelname',
            'module', 'process', 'processName', 'message', 'pathname',
            'taskName',  # Python 3.12+
            # Our custom fields (added at top level, not in extra)
            'error_code',
        }
        extra: Dict[str, Any] = {}
        for key, value in record.__dict__.items():
            if key not in standard and not key.startswith('_'):
                extra[key] = value
        return extra


class EnrichedTextFormatter(logging.Formatter):
    """Text formatter that adds context enrichment to standard output.

    Adds [correlation_id] and [component] prefixes when available,
    while keeping the familiar ANSI-colored terminal output.

    Example output:
        ✓ [abc123] [basic_api_flood] Request completed in 120ms
    """

    # ANSI color codes
    COLORS = {
        logging.DEBUG: '\033[2m',       # Dim
        logging.INFO: '\033[92m',       # Green
        logging.WARNING: '\033[93m',    # Yellow
        logging.ERROR: '\033[91m',      # Red
        logging.CRITICAL: '\033[1m\033[91m',  # Bold Red
    }
    RESET = '\033[0m'

    ICONS = {
        logging.DEBUG: '  ○',
        logging.INFO: '  ✓',
        logging.WARNING: '  ⚠',
        logging.ERROR: '  ✗',
        logging.CRITICAL: '  ‼',
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.RESET)
        icon = self.ICONS.get(record.levelno, '  •')

        # Build context prefix
        parts: list[str] = []
        cid = correlation_id.get("")
        if cid:
            parts.append(cid)
        comp = component_name.get("")
        if comp:
            parts.append(comp)
        error_code = getattr(record, "error_code", None)
        if error_code is not None:
            parts.append(str(error_code))

        prefix = f"[{'|'.join(parts)}] " if parts else ""

        message = record.getMessage()

        # W5.7: Redact secrets from text log message
        # OPT-4: Use module-level import instead of try/except per call.
        if _HAS_REDACTION:
            message = _redact_log_message(message)

        # Add exception info
        if record.exc_info and record.exc_info[1] is not None:
            message += f" — {record.exc_info[1]}"

        return f"{color}{icon}{self.RESET} {prefix}{message}"


# ═══════════════════════════════════════════════════════════════════════════════
# Logger Factory — Backward-compatible with logging_config.get_logger()
# ═══════════════════════════════════════════════════════════════════════════════

_LOG_FORMAT_ENV = "STORM_VX_LOG_FORMAT"
_LOG_LEVEL_ENV = "STORM_VX_LOG_LEVEL"
_LOG_FILE_ENV = "STORM_VX_LOG_FILE"

# Track whether the root logger has been configured
_root_configured: bool = False


def _detect_log_format() -> str:
    """Detect log format from environment variable."""
    return os.environ.get(_LOG_FORMAT_ENV, "text").lower()


def _detect_log_level() -> int:
    """Detect log level from environment variable."""
    level_str = os.environ.get(_LOG_LEVEL_ENV, "").upper()
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "WARN": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    return level_map.get(level_str, logging.INFO)


def _detect_log_file() -> Optional[str]:
    """Detect log file path from environment variable."""
    return os.environ.get(_LOG_FILE_ENV) or None


def configure_root_logger(
    *,
    log_format: str = "",
    level: int = -1,
    log_file: Optional[str] = "",
) -> logging.Logger:
    """Configure the root storm_vx logger with the appropriate formatter.

    This is called once at application startup. Subsequent calls are no-ops
    unless force=True.

    Args:
        log_format: "text" or "json". Auto-detected from STORM_VX_LOG_FORMAT if empty.
        level: Logging level. Auto-detected from STORM_VX_LOG_LEVEL if -1.
        log_file: Path to log file. Auto-detected from STORM_VX_LOG_FILE if "".

    Returns:
        The configured root logger.
    """
    global _root_configured
    if _root_configured:
        return logging.getLogger("storm_vx")

    # Resolve settings
    fmt = log_format or _detect_log_format()
    lvl = level if level >= 0 else _detect_log_level()
    lf = log_file if log_file is not None else _detect_log_file()

    root_logger = logging.getLogger("storm_vx")
    root_logger.setLevel(lvl)

    # Remove existing handlers (from logging_config.py setup)
    root_logger.handlers.clear()

    # Console handler with appropriate formatter
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(lvl)

    if fmt == "json":
        console_handler.setFormatter(StructuredJsonFormatter())
    else:
        console_handler.setFormatter(EnrichedTextFormatter())

    root_logger.addHandler(console_handler)

    # Optional file handler
    if lf:
        file_handler = logging.FileHandler(lf, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        # File always gets JSON format for machine parseability
        file_handler.setFormatter(StructuredJsonFormatter())
        root_logger.addHandler(file_handler)

    _root_configured = True
    return root_logger


def get_structured_logger(name: str = "storm_vx") -> logging.Logger:
    """Get a named logger with structured logging support.

    Drop-in replacement for logging_config.get_logger(). Returns a
    standard logging.Logger — the formatting is determined by the
    handler configuration, not the logger itself.

    If the root logger hasn't been configured yet, this auto-configures
    it with the detected format (text by default).

    Args:
        name: Logger name (usually module __name__).

    Returns:
        Logger instance with structured logging support.
    """
    if not _root_configured:
        configure_root_logger()
    return logging.getLogger(name)


# ═══════════════════════════════════════════════════════════════════════════════
# Logging Helpers — Convenient structured logging functions
# ═══════════════════════════════════════════════════════════════════════════════

def log_error(
    logger: logging.Logger,
    message: str,
    error_code: ErrorCode,
    *,
    exc: Optional[BaseException] = None,
    **kwargs: Any,
) -> None:
    """Log an error with structured error code and optional exception.

    Args:
        logger: The logger instance.
        message: Human-readable error message.
        error_code: Structured error code from the taxonomy.
        exc: Optional exception to attach (for stack trace).
        **kwargs: Additional structured fields to include.
    """
    extra: Dict[str, Any] = {"error_code": error_code}
    extra.update(kwargs)
    logger.error(message, extra=extra, exc_info=exc is not None)


def log_warning(
    logger: logging.Logger,
    message: str,
    error_code: Optional[ErrorCode] = None,
    **kwargs: Any,
) -> None:
    """Log a warning, optionally with an error code."""
    extra: Dict[str, Any] = {}
    if error_code:
        extra["error_code"] = error_code
    extra.update(kwargs)
    logger.warning(message, extra=extra)


def log_with_context(
    logger: logging.Logger,
    level: int,
    message: str,
    *,
    correlation_id_val: str = "",
    component: str = "",
    target: str = "",
    worker: int = -1,
    error_code: Optional[ErrorCode] = None,
    **kwargs: Any,
) -> None:
    """Log with explicit context overrides (does NOT persist in ContextVar).

    Use this when you want to add context for a single log entry without
    affecting the global context.

    Args:
        logger: Logger instance.
        level: Logging level (e.g., logging.INFO).
        message: Log message.
        correlation_id_val: Override correlation ID for this entry only.
        component: Override component name for this entry only.
        target: Override target for this entry only.
        worker: Override worker ID for this entry only.
        error_code: Optional error code.
        **kwargs: Additional extra fields.
    """
    extra: Dict[str, Any] = {}
    if correlation_id_val:
        extra["correlation_id"] = correlation_id_val
    if component:
        extra["component"] = component
    if target:
        extra["target"] = target
    if worker >= 0:
        extra["worker_id"] = worker
    if error_code:
        extra["error_code"] = error_code
    extra.update(kwargs)
    logger.log(level, message, extra=extra)


# ═══════════════════════════════════════════════════════════════════════════════
# Unhandled Exception Handler — Last-resort crash logging
# ═══════════════════════════════════════════════════════════════════════════════

def install_exception_handler(logger: Optional[logging.Logger] = None) -> None:
    """Install a sys.excepthook that logs unhandled exceptions.

    This ensures that unhandled exceptions in the main thread are
    captured by the logging system with structured error codes,
    rather than only printed to stderr.

    Args:
        logger: Logger to use. Defaults to root storm_vx logger.
    """
    _logger = logger or logging.getLogger("storm_vx")
    _original_hook = sys.excepthook

    def _structured_excepthook(
        exc_type: type, exc_value: BaseException, exc_tb: Any,
    ) -> None:
        # Log with structured error code
        _logger.critical(
            f"Unhandled exception: {exc_type.__name__}: {exc_value}",
            extra={"error_code": ERR_UNHANDLED_EXCEPTION},
            exc_info=(exc_type, exc_value, exc_tb),
        )
        # Also call original hook for stderr output
        _original_hook(exc_type, exc_value, exc_tb)

    sys.excepthook = _structured_excepthook


def install_async_exception_handler(logger: Optional[logging.Logger] = None) -> None:
    """Install an asyncio exception handler for the running event loop.

    Logs unhandled exceptions from async tasks that would otherwise
    be silently printed to stderr by asyncio's default handler.

    Call this after the event loop is running (e.g., in an async startup function).

    Args:
        logger: Logger to use. Defaults to root storm_vx logger.
    """
    import asyncio

    _logger = logger or logging.getLogger("storm_vx")

    def _async_exception_handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
        exception = context.get("exception")
        message = context.get("message", "Unknown async error")

        if exception:
            _logger.critical(
                f"Unhandled async exception: {type(exception).__name__}: {exception} — {message}",
                extra={
                    "error_code": ERR_UNHANDLED_EXCEPTION,
                    "async_message": message,
                },
                exc_info=(type(exception), exception, exception.__traceback__),
            )
        else:
            _logger.error(
                f"Async error (no exception): {message}",
                extra={
                    "error_code": ERR_ASYNC_CANCELLED,
                    "async_message": message,
                },
            )

    try:
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(_async_exception_handler)
    except RuntimeError:
        # No running event loop — will be installed when loop starts
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# Module Exports
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = [
    # Error taxonomy
    "ErrorCategory",
    "ErrorCode",
    # Predefined error codes
    "ERR_CONNECTION_REFUSED",
    "ERR_CONNECTION_TIMEOUT",
    "ERR_DNS_FAILURE",
    "ERR_SSL_ERROR",
    "ERR_CONNECTION_RESET",
    "ERR_POOL_EXHAUSTED",
    "ERR_WAF_BLOCKED",
    "ERR_WAF_CHALLENGE",
    "ERR_WAF_RATE_LIMITED",
    "ERR_WAF_BYPASS_FAILED",
    "ERR_CONFIG_INVALID",
    "ERR_CONFIG_MISSING",
    "ERR_CONFIG_CONFLICT",
    "ERR_PLUGIN_LOAD",
    "ERR_PLUGIN_CRASH",
    "ERR_PLUGIN_TIMEOUT",
    "ERR_PLUGIN_MISCONFIG",
    "ERR_MEMORY_LIMIT",
    "ERR_FILE_LIMIT",
    "ERR_TASK_LIMIT",
    "ERR_RESPONSE_TOO_LARGE",
    "ERR_SSL_VERIFICATION",
    "ERR_PATH_TRAVERSAL",
    "ERR_INPUT_VALIDATION",
    "ERR_UNHANDLED_EXCEPTION",
    "ERR_ASYNC_CANCELLED",
    "ERR_STATE_CORRUPTION",
    # Context variables
    "correlation_id",
    "component_name",
    "target_host",
    "worker_id_ctx",
    "new_correlation_id",
    "set_log_context",
    "clear_log_context",
    # Formatters
    "StructuredJsonFormatter",
    "EnrichedTextFormatter",
    # Logger factory
    "configure_root_logger",
    "get_structured_logger",
    # Helpers
    "log_error",
    "log_warning",
    "log_with_context",
    # Exception handlers
    "install_exception_handler",
    "install_async_exception_handler",
]
