#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security.audit — Security audit logging and event tracking.

W5.7 SECURITY HARDENING:

  1. security_log() — Structured logging for security events with
     severity levels (INFO, WARNING, CRITICAL).
  2. Audit event types — Enumerated security event categories for
     consistent classification.
  3. Audit trail — Optional buffer of recent security events for
     diagnostics and incident response.
  4. Security event counters — Counters for tracking security events
     by category (useful for metrics integration).

DESIGN PRINCIPLES:
  - Audit events use a dedicated logger (security.audit) separate from
    application logs — ensures security events are never accidentally
    filtered by log level changes.
  - Every security-relevant action (validation failure, SSRF block,
    path traversal attempt, etc.) should be logged via this module.
  - Events include structured context (source_ip, user_agent, module, etc.)
  - Audit trail is bounded (max 1000 events) — prevents memory exhaustion
  - Counters are monotonic — safe for concurrent reads under GIL

USAGE:
    from security.audit import security_log, AuditEvent

    # Log a security event
    security_log(
        AuditEvent.SSRF_BLOCKED,
        severity="WARNING",
        url="http://192.168.1.1/admin",
        module="basic_api_flood",
    )

    # Get security stats
    stats = get_audit_stats()
    # {"ssrf_blocked": 3, "path_traversal_blocked": 1, ...}

    # Get recent events
    events = get_recent_events(limit=10)
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

from logging_config import get_logger

# Dedicated audit logger — separate from application loggers so security
# events are never accidentally filtered by log level changes.
_audit_logger = logging.getLogger("storm_vx.security.audit")

# OPT-4: Module-level optional import for redact_secrets.
# Avoids try/except ImportError overhead on every security_log() call.
try:
    from security.secrets_guard import redact_secrets as _redact_secrets
    _HAS_REDACT = True
except ImportError:
    _HAS_REDACT = False


# ═══════════════════════════════════════════════════════════════════════════════
# Audit Event Types
# ═══════════════════════════════════════════════════════════════════════════════

class AuditEvent(str, Enum):
    """Security event categories for consistent classification.

    Each event maps to a counter key in the audit stats.
    """
    # Input validation
    URL_VALIDATION_FAILED = "url_validation_failed"
    HOSTNAME_BLOCKED = "hostname_blocked"
    HEADER_INJECTION_BLOCKED = "header_injection_blocked"

    # SSRF
    SSRF_BLOCKED = "ssrf_blocked"
    SSRF_PRIVATE_IP = "ssrf_private_ip"
    SSRF_INTERNAL_HOSTNAME = "ssrf_internal_hostname"

    # Path traversal
    PATH_TRAVERSAL_BLOCKED = "path_traversal_blocked"
    PATH_ESCAPE_BLOCKED = "path_escape_blocked"

    # JSON / file
    JSON_BOMB_BLOCKED = "json_bomb_blocked"
    FILE_SIZE_EXCEEDED = "file_size_exceeded"
    FILE_EXTENSION_BLOCKED = "file_extension_blocked"

    # Plugin security
    PLUGIN_LOAD_BLOCKED = "plugin_load_blocked"
    PLUGIN_VALIDATION_FAILED = "plugin_validation_failed"

    # Secrets
    SECRET_REDACTED = "secret_redacted"
    CREDENTIALS_IN_URL = "credentials_in_url"

    # Config
    CONFIG_VALIDATION_FAILED = "config_validation_failed"
    INSECURE_DEFAULT_CHANGED = "insecure_default_changed"

    # General
    SECURITY_MODE_CHANGED = "security_mode_changed"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


# ═══════════════════════════════════════════════════════════════════════════════
# Audit Trail — Bounded buffer of recent events
# ═══════════════════════════════════════════════════════════════════════════════

_MAX_AUDIT_TRAIL_SIZE = 1000


@dataclass(slots=True)
class AuditEntry:
    """A single audit trail entry.

    μOPT-5: Uses slots=True to reduce per-entry memory by ~40%
    (no __dict__ per instance) and faster attribute access.
    """
    timestamp: float
    event: AuditEvent
    severity: str
    message: str
    context: Dict[str, Any] = field(default_factory=dict)


# Bounded deque for audit trail (prevents memory exhaustion)
_audit_trail: deque[AuditEntry] = deque(maxlen=_MAX_AUDIT_TRAIL_SIZE)

# Monotonic counters per event type
_audit_counters: Dict[str, int] = {}

# OPT-5: Lock for thread-safe counter increments.
# Under CPython's GIL, individual dict operations (.get, __setitem__) are
# atomic, but the compound read-modify-write pattern is NOT:
#   _audit_counters[key] = _audit_counters.get(key, 0) + 1
# Between the .get() and __setitem__, another thread can interleave,
# causing lost increments (silent counter corruption under concurrency).
# A lightweight threading.Lock ensures atomicity with negligible overhead
# since security events are infrequent (not 10k/sec like logging).
_counter_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════════
# Security Logging
# ═══════════════════════════════════════════════════════════════════════════════

def security_log(
    event: AuditEvent,
    *,
    severity: str = "WARNING",
    message: str = "",
    **context: Any,
) -> None:
    """Log a security event to the dedicated audit logger.

    The event is:
      1. Written to the security.audit logger at the specified severity
      2. Added to the in-memory audit trail (bounded)
      3. Counted in the per-event-type counters

    Args:
        event: Audit event type (from AuditEvent enum).
        severity: Log severity ("INFO", "WARNING", "ERROR", "CRITICAL").
        message: Human-readable description. If empty, uses event value.
        **context: Additional structured context (url, module, ip, etc.).
    """
    msg = message or event.value

    # Increment counter (thread-safe)
    with _counter_lock:
        _audit_counters[event.value] = _audit_counters.get(event.value, 0) + 1

    # Add to audit trail
    entry = AuditEntry(
        timestamp=time.time(),  # wall-clock
        event=event,
        severity=severity,
        message=msg,
        context=context,
    )
    _audit_trail.append(entry)

    # Log to dedicated audit logger
    # Also redact any secrets in context before logging
    # OPT-4: Use module-level import instead of try/except per call
    if _HAS_REDACT:
        safe_context = _redact_secrets(context)
    else:
        safe_context = context

    context_str = " ".join(f"{k}={v}" for k, v in safe_context.items()) if safe_context else ""
    log_msg = f"[SEC-AUDIT] {event.value}: {msg}"
    if context_str:
        log_msg += f" | {context_str}"

    level = getattr(logging, severity.upper(), logging.WARNING)
    _audit_logger.log(level, log_msg)

    # OPT-7: Removed duplicate app_logger.log() call.
    # Previously this also logged to the application logger, causing
    # 2× formatting overhead per security event. The audit logger
    # already captures the event. If app-level visibility is needed,
    # configure the audit logger's handlers to also write to the
    # app log destination, rather than emitting the message twice.


# ═══════════════════════════════════════════════════════════════════════════════
# Audit Stats & Trail Query
# ═══════════════════════════════════════════════════════════════════════════════

def get_audit_stats() -> Dict[str, int]:
    """Get security event counters.

    Returns:
        Dict of event_type -> count for all events with count > 0.
    """
    return dict(_audit_counters)


def get_recent_events(limit: int = 100) -> List[Dict[str, Any]]:
    """Get recent audit trail entries.

    Args:
        limit: Maximum number of entries to return.

    Returns:
        List of audit entry dicts, most recent first.
    """
    entries = list(_audit_trail)[-limit:]
    return [
        {
            "timestamp": entry.timestamp,
            "event": entry.event.value,
            "severity": entry.severity,
            "message": entry.message,
            "context": entry.context,
        }
        for entry in reversed(entries)
    ]


def reset_audit_stats() -> None:
    """Reset all audit counters and trail. Useful in tests."""
    _audit_counters.clear()
    _audit_trail.clear()


def get_audit_status() -> Dict[str, Any]:
    """Get comprehensive audit status for health checks.

    Returns:
        Dict with audit configuration, counters, and trail size.
    """
    total_events = sum(_audit_counters.values())
    return {
        "total_events": total_events,
        "event_types": len(_audit_counters),
        "trail_size": len(_audit_trail),
        "trail_max_size": _MAX_AUDIT_TRAIL_SIZE,
        "counters": dict(_audit_counters),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Module Exports
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = [
    # Core
    "security_log",
    "AuditEvent",
    "AuditEntry",
    # Stats
    "get_audit_stats",
    "get_recent_events",
    "get_audit_status",
    "reset_audit_stats",
]
