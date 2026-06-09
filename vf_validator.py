"""Storm-Vx Input Validation & URL Sanitization.

Provides validation functions for URLs, IP addresses, and other inputs
to prevent injection attacks and ensure safe operation.
"""
from __future__ import annotations

import re
import unicodedata
import ipaddress
from typing import List, Tuple
from urllib.parse import urlparse, unquote

from exceptions import ValidationError


# Private/reserved IP ranges that should not be targeted
RESERVED_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),  # Carrier-grade NAT
    # SEC-05: IPv6 reserved ranges
    ipaddress.ip_network('::1/128'),     # IPv6 loopback
    ipaddress.ip_network('fe80::/10'),    # IPv6 link-local
    ipaddress.ip_network('fc00::/7'),     # IPv6 unique-local
    ipaddress.ip_network('ff00::/8'),     # IPv6 multicast
    ipaddress.ip_network('::/128'),       # IPv6 unspecified
]

# Dangerous paths that should never be scanned/attacked
BLOCKED_PATHS = [
    '/admin', '/wp-admin', '/phpmyadmin',
    '/.env', '/.git', '/.ssh',
    '/etc/passwd', '/proc/self',
]


def validate_target_url(url: str) -> Tuple[str, List[str]]:
    """Validate and sanitize a target URL.
    
    Args:
        url: URL string to validate.
        
    Returns:
        Tuple of (sanitized_url, list_of_warnings)
        
    Raises:
        ValidationError: If the URL is invalid or points to a reserved address.
    """
    warnings = []
    
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string")
    
    url = url.strip()
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    parsed = urlparse(url)
    
    # Validate scheme
    if parsed.scheme not in ('http', 'https'):
        raise ValidationError(f"Invalid URL scheme: {parsed.scheme}. Only http and https are allowed.")
    
    # Validate hostname
    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("URL must have a valid hostname")
    
    # Check for reserved/local IPs
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None  # Not an IP address, it's a domain name - that's fine
    
    if ip is not None:
        for reserved in RESERVED_IP_RANGES:
            if ip in reserved:
                raise ValidationError(
                    f"Target {hostname} is a reserved/local IP address. "
                    f"Only authorized public targets are allowed."
                )
    
    # BUG-24 FIX: Sanitize the path component against path traversal attacks.
    # Previously sanitize_path() existed but was never called here, leaving
    # the attack pipeline vulnerable to traversal sequences in profile URLs.
    raw_path = parsed.path or '/'
    safe_path = sanitize_path(raw_path)
    if safe_path != raw_path:
        warnings.append(f"Path was sanitized: removed traversal sequences from '{raw_path}'")
        # Reconstruct URL with sanitized path
        url = parsed._replace(path=safe_path).geturl()
    
    # Check for blocked paths (using sanitized path)
    for blocked in BLOCKED_PATHS:
        if safe_path.lower().startswith(blocked.lower()):
            warnings.append(f"Path contains potentially sensitive area: {blocked}")
    
    # Validate port if specified
    if parsed.port and not (1 <= parsed.port <= 65535):
        raise ValidationError(f"Invalid port number: {parsed.port}")
    
    # Check for suspicious characters
    if re.search(r'[<>"{}|\\^`]', url):
        raise ValidationError("URL contains invalid characters")
    
    return url, warnings


def validate_ip_address(ip_str: str) -> str:
    """Validate an IP address string.
    
    Args:
        ip_str: IP address string to validate.
        
    Returns:
        Validated IP address string.
        
    Raises:
        ValidationError: If the IP is invalid or reserved.
    """
    if not ip_str:
        raise ValidationError("IP address cannot be empty")
    
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        raise ValidationError(f"Invalid IP address: {ip_str}")
    
    # Block reserved IPs
    for reserved in RESERVED_IP_RANGES:
        if ip in reserved:
            raise ValidationError(f"IP {ip_str} is a reserved/local address")
    
    return str(ip)


def validate_worker_count(workers: int, max_allowed: int = 50000) -> int:
    """Validate worker count is within safe bounds.
    
    Args:
        workers: Requested worker count.
        max_allowed: Maximum allowed workers.
        
    Returns:
        Validated worker count.
        
    Raises:
        ValidationError: If workers is out of range.
    """
    if not isinstance(workers, int):
        raise ValidationError("Worker count must be an integer")
    if workers < 1:
        raise ValidationError("Worker count must be at least 1")
    if workers > max_allowed:
        raise ValidationError(f"Worker count cannot exceed {max_allowed}")
    return workers


def sanitize_path(path: str) -> str:
    """Sanitize a URL path to prevent path traversal attacks.
    
    Args:
        path: URL path to sanitize.
        
    Returns:
        Sanitized path.
    """
    # Unicode normalization to prevent bypass via look-alike characters
    path = unicodedata.normalize('NFC', path)
    
    # Remove null bytes
    path = path.replace('\x00', '')
    
    # Decode URL-encoded traversal attempts iteratively
    # (handles double-encoding like %252e%252e%252f)
    prev = None
    while prev != path:
        prev = path
        path = unquote(path)
    
    # Re-normalize after decoding
    path = unicodedata.normalize('NFC', path)
    
    # Remove null bytes again (may appear after decoding)
    path = path.replace('\x00', '')
    
    # Handle semicolon-based traversal BEFORE ../ removal (Tomcat/path parameter bypass)
    # This ordering ensures ..; → .. conversion is caught by the ../ loop below.
    # e.g., /foo/..;/bar → /foo/../bar → /foo/bar ✓
    # e.g., /foo/..; → /foo/.. → /foo/ ✓ (caught by second pass)
    while '..;/' in path or '..;\\' in path:
        path = path.replace('..;/', '').replace('..;\\', '')

    while '..;' in path:
        path = path.replace('..;', '..')

    # Remove path traversal attempts (forward and backslash variants)
    while '../' in path or '..\\' in path:
        path = path.replace('../', '').replace('..\\', '')

    # Remove double slashes
    while '//' in path:
        path = path.replace('//', '/')
    
    # Remove backslash-to-forwardslash conversion for consistency
    path = path.replace('\\', '/')
    
    # Clean up any remaining double slashes from backslash conversion
    while '//' in path:
        path = path.replace('//', '/')
    
    return path


def validate_cookie(key: str, value: str) -> bool:
    """Validate a cookie key-value pair for safety and protocol compliance.

    Checks:
    - Key length <= 128, value length <= 4096
    - No null bytes in key or value
    - No control characters in key (chars with ord < 32)
    - No control characters in value except space (ord 32)
    - Key must not start with whitespace or '$' (reserved in some protocols)

    Args:
        key: Cookie name/key string.
        value: Cookie value string.

    Returns:
        True if the cookie is valid, False otherwise.
    """
    # Empty key check
    if not key:
        return False

    # Length checks
    if len(key) > 128 or len(value) > 4096:
        return False

    # Null byte check
    if '\x00' in key or '\x00' in value:
        return False

    # Key: no control characters at all (ord < 32)
    if any(ord(ch) < 32 for ch in key):
        return False

    # Value: no control characters except space (ord 32)
    if any(ord(ch) < 32 and ord(ch) != 32 for ch in value):
        return False

    # Key must not start with whitespace or $
    if key and (key[0].isspace() or key[0] == '$'):
        return False

    return True
