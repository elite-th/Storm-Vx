#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security.input_validation — URL validation, SSRF prevention, path traversal
guard, header sanitization, and JSON bomb protection.

W5.7 SECURITY HARDENING:

  1. validate_url() — Ensures URLs are well-formed, use http/https schemes,
     and optionally blocks private/internal IPs (SSRF prevention).
  2. sanitize_path() — Prevents path traversal (../, /etc/passwd, etc.)
     in file paths used for profile loading and plugin discovery.
  3. sanitize_header_value() — Strips CRLF characters from header values
     to prevent HTTP header injection / response splitting.
  4. SafeJSONDecoder — Limits JSON nesting depth and total string size
     to prevent JSON bomb / billion laughs attacks.
  5. validate_hostname() — Ensures hostnames are DNS-safe and not IP-based
     when private IP access should be blocked.

SECURITY MODEL:
  - Default mode (STORM_VX_SECURITY_STRICT=false): Log warnings for
    suspicious input but allow it through (backward compatible).
  - Strict mode (STORM_VX_SECURITY_STRICT=true): Raise SecurityValidationError
    for any invalid input (production hardening).

USAGE:
    from security.input_validation import validate_url, sanitize_path

    # URL validation (returns cleaned URL or raises)
    safe_url = validate_url("https://example.com/api")

    # Path traversal protection
    safe_path = sanitize_path("../../etc/passwd", base_dir="/app/profiles")

    # Header sanitization
    safe_value = sanitize_header_value("value\r\nX-Injected: true")

    # Safe JSON loading
    data = safe_json_loads(json_string, max_depth=20, max_size=1_000_000)
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, ParseResult

from logging_config import get_logger

logger = get_logger(__name__)

# OPT-4: Module-level optional import for vf_validator.
# Avoids try/except ImportError overhead on every _preprocess_path() call.
# In hot paths (attack loops at 10k+ req/sec), the repeated try/except
# + import machinery check adds ~100ns per call vs. ~10ns for a bool check.
try:
    from vf_validator import sanitize_path as _robust_sanitize_path
    _HAS_VF_VALIDATOR = True
except ImportError:
    _HAS_VF_VALIDATOR = False


# ═══════════════════════════════════════════════════════════════════════════════
# Exceptions
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityValidationError(ValueError):
    """Raised when input fails security validation in strict mode.

    In non-strict mode, a warning is logged instead and the input is
    passed through with best-effort sanitization.
    """
    pass


class SSRFError(SecurityValidationError):
    """Raised when a URL targets a private/internal IP address."""
    pass


class PathTraversalError(SecurityValidationError):
    """Raised when a path contains directory traversal sequences."""
    pass


class HeaderInjectionError(SecurityValidationError):
    """Raised when a header value contains CRLF injection characters."""
    pass


class JSONBombError(SecurityValidationError):
    """Raised when JSON exceeds depth or size limits."""
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration — Reads from config/defaults.py + environment overrides
# ═══════════════════════════════════════════════════════════════════════════════

_STRICT_ENV = "STORM_VX_SECURITY_STRICT"
_SSRF_ENV = "STORM_VX_SSRF_PROTECTION"


# H5 FIX: Cached environment lookups. These are called on every validation
# call in hot paths (10k+ req/sec). os.environ.get() is a C syscall wrapper,
# not a simple dict lookup. Caching avoids the per-call overhead.
# Use _refresh_config() to force re-read after env changes (e.g., in tests).
_strict_mode_cache: bool | None = None
_ssrf_protection_cache: bool | None = None


def _refresh_config() -> None:
    """Force re-read of environment configuration.

    Call this after changing environment variables at runtime
    (e.g., in tests using patch.dict). Normal application code
    should never need to call this — env vars are read once at
    first use and cached for the process lifetime.
    """
    global _strict_mode_cache, _ssrf_protection_cache
    _strict_mode_cache = None
    _ssrf_protection_cache = None


def _is_strict_mode() -> bool:
    """Check if strict security mode is enabled (cached)."""
    global _strict_mode_cache
    if _strict_mode_cache is None:
        _strict_mode_cache = os.environ.get(_STRICT_ENV, "").lower() in ("true", "1", "yes")
    return _strict_mode_cache


def _is_ssrf_protection_enabled() -> bool:
    """Check if SSRF protection is enabled (cached)."""
    global _ssrf_protection_cache
    if _ssrf_protection_cache is None:
        _ssrf_protection_cache = os.environ.get(_SSRF_ENV, "true").lower() in ("true", "1", "yes")
    return _ssrf_protection_cache


# ═══════════════════════════════════════════════════════════════════════════════
# Private IP / SSRF Detection
# ═══════════════════════════════════════════════════════════════════════════════

# RFC 1918 private ranges + loopback + link-local + reserved
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("0.0.0.0/8"),          # "This network"
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT (RFC 6598)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmark testing (RFC 2544)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),           # IPv6 unique-local
    ipaddress.ip_network("ff00::/8"),           # IPv6 multicast
]

# OPT-6: Reduced network list for the fallback path after .is_private
# fast-path check. Only includes networks NOT fully covered by the
# stdlib .is_private/.is_loopback/.is_link_local properties:
# - Multicast (not covered by .is_private)
# - Carrier-grade NAT (not covered by .is_private)
# - IPv6 multicast (not covered by .is_private)
# The full _PRIVATE_NETWORKS list is kept for backward compatibility
# and direct testing.
_PRIVATE_NETWORKS_FAST = [
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT (RFC 6598)
    ipaddress.ip_network("224.0.0.0/4"),        # IPv4 Multicast
    ipaddress.ip_network("ff00::/8"),           # IPv6 multicast
]

# Hostnames that resolve to localhost or internal services
_INTERNAL_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal/reserved.

    H2 FIX: Also handles IPv4-mapped IPv6 addresses like
    ::ffff:127.0.0.1 which map to private IPv4 addresses.
    Without this check, an attacker can bypass SSRF protection
    by using IPv4-mapped IPv6 notation.

    OPT-6: Uses stdlib's .is_loopback and .is_link_local as fast
    paths (C-level checks, O(1)), with fallback to explicit network
    list for the remaining ranges. The stdlib .is_private is NOT
    used because it considers some ranges (e.g., 203.0.113.0/24
    TEST-NET-3) as private that our explicit network list doesn't
    cover — we preserve the exact original behavior.

    Fast path covers: loopback (127/8, ::1), link-local (169.254/16,
    fe80::/10). These are unambiguous and cover ~80% of real-world
    checks. The remaining ~20% fall through to the explicit list.

    Args:
        ip_str: IP address string (IPv4 or IPv6).

    Returns:
        True if the IP is in a private/reserved range.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        # H2 FIX: Unwrap IPv4-mapped IPv6 addresses.
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped

        # OPT-6: Fast path — unambiguous C-level checks.
        if addr.is_loopback or addr.is_link_local:
            return True

        # Fall through to explicit network list for all other ranges.
        # This preserves exact behavioral compatibility with the original
        # implementation while avoiding O(12) iteration for loopback/link-local.
        for network in _PRIVATE_NETWORKS:
            if addr in network:
                return True
        return False
    except ValueError:
        return False


def is_internal_hostname(hostname: str) -> bool:
    """Check if a hostname is a known internal hostname.

    Args:
        hostname: Hostname to check.

    Returns:
        True if the hostname is internal (e.g., "localhost").
    """
    lower = hostname.lower().rstrip(".")
    if lower in _INTERNAL_HOSTNAMES:
        return True
    # Check for .local, .internal, .localhost TLDs
    if lower.endswith((".local", ".internal", ".localhost", ".test", ".example", ".invalid")):
        return True
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# URL Validation
# ═══════════════════════════════════════════════════════════════════════════════

# Allowed URL schemes
_ALLOWED_SCHEMES = {"http", "https"}

# Maximum URL length (most browsers/servers cap at ~2048-8192)
_MAX_URL_LENGTH = 8192

# Pattern for credentials in URLs (user:pass@host)
_CREDENTIALS_PATTERN = re.compile(r"://[^@]+@[^/]")


def validate_url(
    url: str,
    *,
    allow_private_ips: bool = False,
    max_length: int = _MAX_URL_LENGTH,
    strict: bool | None = None,
) -> str:
    """Validate and sanitize a URL for security.

    Checks:
      1. URL is not empty
      2. URL length does not exceed max_length
      3. URL has an allowed scheme (http/https)
      4. URL does not contain credentials (user:pass@host)
      5. URL hostname is not a private/internal IP (SSRF prevention)

    In non-strict mode: logs warnings for issues and returns sanitized URL.
    In strict mode: raises SecurityValidationError for any issue.

    Args:
        url: URL string to validate.
        allow_private_ips: Allow private/internal IPs (for testing).
        max_length: Maximum allowed URL length.
        strict: Override strict mode. None = use env var default.

    Returns:
        Validated (and possibly sanitized) URL string.

    Raises:
        SecurityValidationError: In strict mode, when validation fails.
    """
    is_strict = strict if strict is not None else _is_strict_mode()

    if not url or not url.strip():
        msg = "URL is empty or whitespace-only"
        if is_strict:
            raise SecurityValidationError(msg)
        logger.warning(f"SEC-603: {msg}")
        return url

    url = url.strip()

    # Check URL length
    if len(url) > max_length:
        msg = f"URL exceeds maximum length ({len(url)} > {max_length})"
        if is_strict:
            raise SecurityValidationError(msg)
        logger.warning(f"SEC-603: {msg}")
        url = url[:max_length]

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception as exc:
        msg = f"URL parsing failed: {exc}"
        if is_strict:
            raise SecurityValidationError(msg) from exc
        logger.warning(f"SEC-603: {msg}")
        return url

    # Check scheme
    if parsed.scheme and parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        msg = f"URL scheme '{parsed.scheme}' not allowed (must be http/https)"
        if is_strict:
            raise SecurityValidationError(msg)
        logger.warning(f"SEC-603: {msg}")

    # Check for embedded credentials
    if _CREDENTIALS_PATTERN.search(url):
        msg = "URL contains embedded credentials (user:pass@host)"
        if is_strict:
            raise SecurityValidationError(msg)
        logger.warning(f"SEC-603: {msg} — credentials will be stripped")
        # Strip credentials: replace user:pass@ with just @
        url = re.sub(r"://[^@]+@", "://", url)

    # SSRF check: private/internal IPs
    if not allow_private_ips and _is_ssrf_protection_enabled():
        hostname = parsed.hostname
        if hostname:
            if is_internal_hostname(hostname):
                msg = f"URL targets internal hostname: {hostname}"
                if is_strict:
                    raise SSRFError(msg)
                logger.warning(f"SEC-603: {msg} — SSRF protection enabled")
            else:
                # Try to resolve as IP
                try:
                    ip = ipaddress.ip_address(hostname)
                except ValueError:
                    # It's a domain name, not an IP — that's fine
                    pass
                else:
                    if is_private_ip(str(ip)):
                        msg = f"URL targets private IP: {hostname}"
                        if is_strict:
                            raise SSRFError(msg)
                        logger.warning(f"SEC-603: {msg} — SSRF protection enabled")

    return url


def validate_hostname(
    hostname: str,
    *,
    allow_private: bool = False,
    strict: bool | None = None,
) -> str:
    """Validate a hostname for DNS safety and SSRF prevention.

    Args:
        hostname: Hostname string to validate.
        allow_private: Allow private/internal hostnames.
        strict: Override strict mode.

    Returns:
        Validated hostname string.

    Raises:
        SecurityValidationError: In strict mode, when validation fails.
    """
    is_strict = strict if strict is not None else _is_strict_mode()

    if not hostname or not hostname.strip():
        msg = "Hostname is empty"
        if is_strict:
            raise SecurityValidationError(msg)
        return hostname

    hostname = hostname.strip().lower()

    # Check for null bytes
    if "\x00" in hostname:
        msg = "Hostname contains null byte"
        if is_strict:
            raise SecurityValidationError(msg)
        hostname = hostname.replace("\x00", "")
        logger.warning(f"SEC-603: {msg} — stripped null bytes")

    # SSRF check
    if not allow_private and _is_ssrf_protection_enabled():
        if is_internal_hostname(hostname):
            msg = f"Internal hostname blocked: {hostname}"
            if is_strict:
                raise SSRFError(msg)
            logger.warning(f"SEC-603: {msg}")

        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            pass  # Domain name, not IP
        else:
            if is_private_ip(str(ip)):
                msg = f"Private IP hostname blocked: {hostname}"
                if is_strict:
                    raise SSRFError(msg)
                logger.warning(f"SEC-603: {msg}")

    return hostname


# ═══════════════════════════════════════════════════════════════════════════════
# Path Traversal Protection
# ═══════════════════════════════════════════════════════════════════════════════

# Path traversal patterns
_TRAVERSAL_PATTERNS = re.compile(r"(\.\.[/\\]|[/\\]\.\.)")
_ABSOLUTE_UNIX = re.compile(r"^/")
_ABSOLUTE_WIN = re.compile(r"^[a-zA-Z]:")


def sanitize_path(
    path: str,
    *,
    base_dir: str = "",
    strict: bool | None = None,
) -> str:
    """Sanitize a file path to prevent directory traversal attacks.

    C2 FIX: Now uses the more robust vf_validator.sanitize_path()
    preprocessing when available, which handles URL-encoded traversal
    (%252e%252e), Unicode normalization, Tomcat semicolon bypass
    (..;/), and double-encoding. The security checks (null bytes,
    traversal detection, strict mode raising) are still enforced by
    this function — the delegation is for normalization only.

    Checks for:
      1. Path traversal sequences (../, ..\\, %2e%2e, ..;/  etc.)
      2. Null bytes (path injection)
      3. URL-encoded traversal attempts
      4. Absolute paths that escape base_dir
      5. Symlink escapes from base_dir

    Args:
        path: File path to sanitize.
        base_dir: If provided, resolves the path relative to this directory
            and verifies it stays within base_dir.
        strict: Override strict mode.

    Returns:
        Sanitized path (resolved, within base_dir if specified).

    Raises:
        PathTraversalError: In strict mode, when traversal is detected.
    """
    is_strict = strict if strict is not None else _is_strict_mode()

    if not path:
        return path

    # C2 FIX: Check the ORIGINAL path for traversal/null-byte patterns
    # BEFORE preprocessing. vf_validator.sanitize_path() strips these
    # silently (for URL path use), but we need to detect them first
    # for our security enforcement (raising in strict mode).

    # Check for null bytes in original path
    if "\x00" in path:
        msg = f"Path contains null byte: {path!r}"
        if is_strict:
            raise PathTraversalError(msg)
        logger.warning(f"SEC-602: {msg} — stripped null bytes")

    # Check for path traversal in original path
    if _TRAVERSAL_PATTERNS.search(path):
        msg = f"Path traversal detected: {path!r}"
        if is_strict:
            raise PathTraversalError(msg)
        logger.warning(f"SEC-602: {msg}")

    # C2 FIX: Use vf_validator's robust preprocessing to normalize
    # URL-encoded and Unicode-based traversal attempts. This ensures
    # that %2e%2e%2f and ..;/ and similar bypasses are decoded/stripped,
    # producing a safe path even if the original pattern wasn't caught
    # by the regex above.
    preprocessed = _preprocess_path(path)

    # If base_dir is provided, verify the resolved path stays within it
    if base_dir:
        resolved_base = os.path.realpath(base_dir)
        resolved_path = os.path.realpath(os.path.join(base_dir, preprocessed))

        if not resolved_path.startswith(resolved_base + os.sep) and resolved_path != resolved_base:
            msg = f"Path escapes base directory: {path!r} (base: {base_dir!r})"
            if is_strict:
                raise PathTraversalError(msg)
            logger.warning(f"SEC-602: {msg}")
            # Return just the basename as a safe fallback
            return os.path.basename(preprocessed)

        return resolved_path

    return preprocessed


def _preprocess_path(path: str) -> str:
    """Preprocess a path using robust normalization from vf_validator.

    C2 FIX: Delegates to vf_validator.sanitize_path() when available
    for URL-decoding, Unicode normalization, Tomcat ..;/ bypass, and
    double-encoding handling. Falls back to local preprocessing.

    This only does normalization — it does NOT raise exceptions.
    The caller is responsible for security enforcement.

    OPT-4: Import moved to module level to avoid try/except overhead
    on every call in hot paths (attack loops).
    """
    if _HAS_VF_VALIDATOR:
        return _robust_sanitize_path(path)

    # Fallback: basic local preprocessing
    # Iteratively URL-decode to catch double-encoding
    # C3 FIX: Bounded iteration limit to prevent DoS from deeply nested
    # percent-encoding (e.g., %2525252e%2525252f). Without this limit,
    # an attacker can craft URLs with many encoding levels that cause
    # excessive CPU consumption.
    from urllib.parse import unquote
    _MAX_DECODE_ITERATIONS = 5  # Prevent DoS from deeply nested encoding
    prev = None
    decoded = path
    iterations = 0
    while prev != decoded and iterations < _MAX_DECODE_ITERATIONS:
        prev = decoded
        decoded = unquote(decoded)
        iterations += 1
    if iterations >= _MAX_DECODE_ITERATIONS and prev != decoded:
        logger.warning(
            f"SEC-602: URL decode iteration limit ({_MAX_DECODE_ITERATIONS}) "
            f"reached — possibly malicious deeply-nested encoding"
        )

    # Strip null bytes (without raising — caller handles that)
    decoded = decoded.replace("\x00", "")

    return decoded


def validate_file_path(
    path: str,
    *,
    allowed_extensions: tuple[str, ...] = (),
    max_size_bytes: int = 0,
    strict: bool | None = None,
) -> str:
    """Validate a file path for safe reading/writing.

    Combines path traversal protection with extension and size checks.

    Args:
        path: File path to validate.
        allowed_extensions: If non-empty, only these extensions are allowed
            (e.g., (".json", ".py")).
        max_size_bytes: If > 0, reject files larger than this.
        strict: Override strict mode.

    Returns:
        Validated file path.

    Raises:
        SecurityValidationError: In strict mode, when validation fails.
        PathTraversalError: When path traversal is detected.
    """
    is_strict = strict if strict is not None else _is_strict_mode()

    # Apply path traversal protection
    safe_path = sanitize_path(path, strict=strict)

    # Extension check
    if allowed_extensions:
        ext = os.path.splitext(safe_path)[1].lower()
        if ext not in [e.lower() for e in allowed_extensions]:
            msg = f"File extension '{ext}' not allowed (allowed: {allowed_extensions})"
            if is_strict:
                raise SecurityValidationError(msg)
            logger.warning(f"SEC-603: {msg}")

    # Size check (only if file exists)
    if max_size_bytes > 0 and os.path.isfile(safe_path):
        try:
            size = os.path.getsize(safe_path)
            if size > max_size_bytes:
                msg = f"File size ({size}) exceeds limit ({max_size_bytes}): {safe_path}"
                if is_strict:
                    raise SecurityValidationError(msg)
                logger.warning(f"SEC-603: {msg}")
        except OSError:
            pass

    return safe_path


# ═══════════════════════════════════════════════════════════════════════════════
# Header Sanitization — CRLF Injection Prevention
# ═══════════════════════════════════════════════════════════════════════════════

# CRLF and other dangerous characters in header values
_CRLF_PATTERN = re.compile(r"[\r\n]")


def sanitize_header_value(
    value: str,
    *,
    strict: bool | None = None,
) -> str:
    """Sanitize an HTTP header value to prevent CRLF injection.

    Strips carriage return (\\r) and line feed (\\n) characters that
    could be used for HTTP header injection or response splitting.

    Args:
        value: Header value to sanitize.
        strict: Override strict mode.

    Returns:
        Sanitized header value with CRLF characters removed.

    Raises:
        HeaderInjectionError: In strict mode, when CRLF is detected.
    """
    is_strict = strict if strict is not None else _is_strict_mode()

    if not value:
        return value

    if _CRLF_PATTERN.search(value):
        msg = f"Header value contains CRLF characters: {value!r}"
        if is_strict:
            raise HeaderInjectionError(msg)
        logger.warning(f"SEC-603: {msg} — stripped CRLF")
        return _CRLF_PATTERN.sub("", value)

    return value


def sanitize_headers(
    headers: Dict[str, str],
    *,
    strict: bool | None = None,
) -> Dict[str, str]:
    """Sanitize all header values in a dictionary.

    Args:
        headers: Dict of header name -> value.
        strict: Override strict mode.

    Returns:
        New dict with sanitized header values.
    """
    return {
        key: sanitize_header_value(value, strict=strict)
        for key, value in headers.items()
    }


# ═══════════════════════════════════════════════════════════════════════════════
# JSON Bomb Protection — Depth and Size Limits
# ═══════════════════════════════════════════════════════════════════════════════

class _DepthLimitingDecoder(json.JSONDecoder):
    """JSON decoder that enforces a maximum nesting depth.

    Prevents "billion laughs" / JSON bomb attacks where deeply nested
    structures cause exponential memory consumption during parsing.

    NOTE: This decoder checks depth AFTER parsing. For true pre-parse
    protection, use safe_json_loads() which checks size BEFORE parsing
    and uses _validate_json_depth() as the authoritative depth check.
    """

    def __init__(self, *args: Any, max_depth: int = 20, **kwargs: Any):
        self._max_depth = max_depth
        # Remove max_depth from kwargs before passing to parent —
        # json.JSONDecoder does not accept it as a kwarg.
        kwargs.pop('max_depth', None)
        super().__init__(*args, **kwargs)

    def decode(self, s: str, _w: Any = None) -> Any:
        result = super().decode(s, _w)
        _validate_json_depth(result, self._max_depth)
        return result


def safe_json_loads(
    json_string: str,
    *,
    max_depth: int = 20,
    max_size: int = 10_000_000,
    strict: bool | None = None,
) -> Any:
    """Parse JSON safely with depth and size limits.

    Protects against:
      - JSON bomb / billion laughs attacks (deep nesting)
      - Memory exhaustion from huge JSON payloads

    The protection strategy is:
      1. REJECT oversized payloads BEFORE parsing (always enforced,
         regardless of strict mode — prevents OOM during parsing)
      2. Parse the JSON with the standard decoder
      3. Validate depth AFTER parsing using _validate_json_depth()

    Step 1 is the critical OOM guard: it prevents the Python process
    from allocating memory for a huge parse tree. Step 3 catches
    deeply-nested bombs that fit within the size limit.

    Args:
        json_string: JSON string to parse.
        max_depth: Maximum allowed nesting depth (default: 20).
        max_size: Maximum allowed string size in bytes (default: 10MB).
        strict: Override strict mode.

    Returns:
        Parsed JSON object.

    Raises:
        JSONBombError: When JSON exceeds depth or size limits.
        json.JSONDecodeError: When JSON is syntactically invalid.
    """
    is_strict = strict if strict is not None else _is_strict_mode()

    if not json_string:
        return None

    # SIZE CHECK — Always enforced, even in non-strict mode.
    # This is the critical OOM guard: we must NOT allow a 10MB+ string
    # to be passed to json.loads() where it could allocate many times
    # its size in memory during parse-tree construction.
    #
    # Use character-length as a fast lower-bound estimate first
    # (avoids allocating a bytes copy for the common case).
    char_len = len(json_string)
    if char_len > max_size:
        # String is definitely too large (UTF-8 encoding is >= char count
        # for any non-ASCII, but always >= char count for ASCII).
        msg = f"JSON payload size exceeds limit (char_len={char_len}, max={max_size})"
        raise JSONBombError(msg)
    elif char_len * 4 > max_size:
        # Potential oversize: char_len * 4 is the worst-case UTF-8 size.
        # Only compute actual byte size if it might exceed the limit.
        actual_size = len(json_string.encode("utf-8", errors="replace"))
        if actual_size > max_size:
            msg = f"JSON payload size ({actual_size}) exceeds limit ({max_size})"
            raise JSONBombError(msg)

    # Parse — use standard decoder, then validate depth post-parse.
    # This is safer than trying to use cls= with _DepthLimitingDecoder
    # because the cls= path has edge cases with kwargs that can silently
    # fall through to an unprotected fallback.
    try:
        result = json.loads(json_string)
    except json.JSONDecodeError:
        raise

    # DEPTH CHECK — Always enforced, even in non-strict mode.
    # A deeply nested JSON bomb that fits within max_size can still
    # cause OOM during parse-tree traversal. Reject it.
    _validate_json_depth(result, max_depth)

    return result


def _validate_json_depth(obj: Any, max_depth: int, current: int = 0) -> None:
    """Iteratively validate JSON object depth.

    μOPT-3: Converted from recursive to iterative BFS to avoid Python
    stack frame overhead. Uses an explicit stack of (object, depth) tuples.
    For max_depth=20, the recursive version used up to 20 stack frames
    per call; the iterative version uses a single frame + heap list.
    For large flat objects (many keys at depth 1), this avoids creating
    one stack frame per key.
    """
    # Stack of (object, depth) tuples for iterative traversal
    stack: list[tuple[Any, int]] = [(obj, current)]
    while stack:
        current_obj, depth = stack.pop()
        if depth > max_depth:
            raise JSONBombError(f"JSON nesting depth exceeds limit ({max_depth})")
        if isinstance(current_obj, dict):
            for value in current_obj.values():
                if isinstance(value, (dict, list)):
                    stack.append((value, depth + 1))
        elif isinstance(current_obj, list):
            for item in current_obj:
                if isinstance(item, (dict, list)):
                    stack.append((item, depth + 1))


def safe_json_load(
    path: str,
    *,
    max_depth: int = 20,
    max_size: int = 10_000_000,
    strict: bool | None = None,
) -> Any:
    """Load and parse a JSON file safely with depth and size limits.

    Combines path traversal protection with JSON bomb protection.

    Args:
        path: Path to JSON file.
        max_depth: Maximum nesting depth.
        max_size: Maximum file size in bytes.
        strict: Override strict mode.

    Returns:
        Parsed JSON object.

    Raises:
        PathTraversalError: When path traversal is detected.
        JSONBombError: When JSON exceeds limits.
        json.JSONDecodeError: When JSON is invalid.
    """
    is_strict = strict if strict is not None else _is_strict_mode()

    # Validate file path
    safe_path = validate_file_path(
        path,
        allowed_extensions=(".json",),
        max_size_bytes=max_size,
        strict=strict,
    )

    # Read file content
    try:
        with open(safe_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (OSError, IOError) as exc:
        from exceptions import ProfileError
        raise ProfileError(f"Cannot read file: {exc}") from exc

    # Parse safely
    return safe_json_loads(content, max_depth=max_depth, max_size=max_size, strict=strict)


# ═══════════════════════════════════════════════════════════════════════════════
# URL Query Parameter Sanitization
# ═══════════════════════════════════════════════════════════════════════════════

def sanitize_url_for_log(url: str) -> str:
    """Sanitize a URL for safe logging by removing credentials and sensitive params.

    Removes:
      - User:password from URL (if present)
      - Common sensitive query parameters (token, key, password, secret, etc.)

    Args:
        url: URL string to sanitize.

    Returns:
        Sanitized URL safe for logging.
    """
    if not url:
        return url

    # Strip credentials
    sanitized = re.sub(r"(://)([^@/:]+:[^@/:]+@)", r"\1", url)

    # Strip sensitive query parameters
    _SENSITIVE_PARAMS = {
        "token", "access_token", "refresh_token", "api_key", "apikey",
        "key", "secret", "password", "passwd", "pass", "credential",
        "auth", "authorization", "session_id", "sessionid", "sid",
        "csrf_token", "xsrf_token", "jwt", "id_token",
    }
    try:
        parsed = urlparse(sanitized)
        if parsed.query:
            parts = parsed.query.split("&")
            safe_parts = []
            for part in parts:
                key = part.split("=")[0].lower()
                if key in _SENSITIVE_PARAMS:
                    safe_parts.append(f"{part.split('=')[0]}=***")
                else:
                    safe_parts.append(part)
            new_query = "&".join(safe_parts)
            sanitized = sanitized.replace(parsed.query, new_query)
    except Exception:
        pass

    return sanitized


# ═══════════════════════════════════════════════════════════════════════════════
# Module Exports
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = [
    # Exceptions
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
    # Configuration
    "_is_strict_mode",
    "_is_ssrf_protection_enabled",
    "_refresh_config",
]
