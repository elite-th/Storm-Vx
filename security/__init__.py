"""security — Production security hardening for Storm-Vx.

W5.7 SECURITY HARDENING:

  1. input_validation  — URL validation, SSRF prevention, path traversal guard,
                         header sanitization, JSON bomb protection
  2. secrets_guard     — Sensitive data redaction in logs, secrets detection
  3. audit             — Security event logging and audit trail

DESIGN PRINCIPLES:
  - Zero-breakage: existing code works identically when security module
    is not explicitly enabled — validators return safe defaults, not errors
  - Opt-in strictness: set STORM_VX_SECURITY_STRICT=true to enforce strict
    validation (reject instead of warn)
  - Low overhead: redaction patterns are compiled once, validation is O(1)
  - No coupling: independent of observability, metrics, and tracing
  - Audit-first: all security events are logged via structured audit logger

ENVIRONMENT VARIABLES:
  - STORM_VX_SECURITY_STRICT : "true" to reject invalid input (default: warn)
  - STORM_VX_SSRF_PROTECTION : "true" to block private IPs (default: warn)
  - STORM_VX_REDACT_SECRETS  : "true" to redact secrets in logs (default: true)
"""
from __future__ import annotations

# Convenience re-exports for common operations
from security.input_validation import (
    SecurityValidationError,
    SSRFError,
    PathTraversalError,
    HeaderInjectionError,
    JSONBombError,
    validate_url,
    validate_hostname,
    sanitize_path,
    validate_file_path,
    sanitize_header_value,
    sanitize_headers,
    safe_json_loads,
    safe_json_load,
    sanitize_url_for_log,
    is_private_ip,
    is_internal_hostname,
    _refresh_config,
)

from security.secrets_guard import (
    redact_secrets,
    redact_string,
    redact_url,
    should_redact,
    redact_log_message,
    redact_log_extra,
)

from security.audit import (
    security_log,
    AuditEvent,
    AuditEntry,
    get_audit_stats,
    get_recent_events,
    get_audit_status,
    reset_audit_stats,
)

__all__ = [
    # Input validation exceptions
    "SecurityValidationError",
    "SSRFError",
    "PathTraversalError",
    "HeaderInjectionError",
    "JSONBombError",
    # URL validation
    "validate_url",
    "validate_hostname",
    "sanitize_url_for_log",
    # SSRF detection
    "is_private_ip",
    "is_internal_hostname",
    # Path protection
    "sanitize_path",
    "validate_file_path",
    # Header sanitization
    "sanitize_header_value",
    "sanitize_headers",
    # JSON protection
    "safe_json_loads",
    "safe_json_load",
    # Secrets guard
    "redact_secrets",
    "redact_string",
    "redact_url",
    "should_redact",
    "redact_log_message",
    "redact_log_extra",
    # Audit
    "security_log",
    "AuditEvent",
    "AuditEntry",
    "get_audit_stats",
    "get_recent_events",
    "get_audit_status",
    "reset_audit_stats",
]
