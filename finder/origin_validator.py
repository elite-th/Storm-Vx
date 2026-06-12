"""Origin IP validation helpers.

Extracted from vf_origin_discovery.py for Law 14 compliance (500-line limit).
Provides:
  - verify_origin_ip(): Validate that an IP actually serves the target domain
  - _cert_matches_domain(): TLS certificate CN/SAN matching
  - _hostname_matches(): Wildcard hostname pattern matching

F5-05: Strengthened validation to reduce false positives from CDN IPs.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

from logging_config import get_logger

logger = get_logger(__name__)


# F5-05: CDN detection keywords split into header-only and body+header.
# HEADER signatures are only checked against HTTP headers (before \r\n\r\n).
# These are strong CDN indicators that never appear in origin responses.
CDN_HEADER_SIGNATURES = [
    'cf-ray', 'cf-cache-status', 'x-amz-cf-id',
    'x-sucuri-id', 'x-cdn', 'x-fastly-request-id',
    'x-vercel-id', 'x-netlify-request-id',
]

# BODY signatures are checked against the full response. These are
# CDN brand names that appear in CDN error pages and headers.
# Generic words like "denied", "forbidden", "blocked" are NOT included
# here because they commonly appear in legitimate web page content.
CDN_BODY_SIGNATURES = [
    'cloudflare', 'arvan', 'akamai', 'incapsula',
    'sucuri', 'stackpath', 'fastly', 'sotoon',
    'imperva',
]

# Error page signatures — checked first. These are specific CDN error
# patterns that clearly indicate a CDN interception, not an origin response.
CDN_ERROR_SIGNATURES = [
    'error 1005', 'error 1020',  # Cloudflare
    'ray id',                     # Cloudflare Ray ID in error pages
    'your ip has been blocked',
    'ddos protection by',
    'server not found',           # CDN can't reach origin
    'access denied by security',  # CDN-specific access denial
    'request rejected',           # CDN-specific request rejection
]


async def verify_origin_ip(
    ip: str,
    domain: str,
    verify_ssl: bool = True,
    *,
    create_ssl_context: Any = None,
    dns_probe_timeout: float = 8.0,
) -> str | None:
    """Verify that *ip* actually serves *domain* by connecting and
    inspecting the HTTP response.

    F5-05 fix: Strengthened validation to reduce false positives:
      - Expanded CDN keyword detection (CF-Ray, x-amz-cf-id, etc.)
      - Domain-in-response check now requires domain in HTML title or
        body content, not just anywhere (CDN error pages mention domain)
      - Certificate CN/SAN validation for HTTPS connections
      - Reject responses that are clearly CDN error pages

    Args:
        ip: IP address to validate.
        domain: Expected domain name.
        verify_ssl: Whether to verify SSL certificates.
        create_ssl_context: Factory function for SSL context (injected).
        dns_probe_timeout: Timeout for DNS/probe connections.

    Returns:
        The IP string if valid, None otherwise.
    """
    if create_ssl_context is None:
        from utils.ssl_helpers import create_ssl_context as _create_ssl_ctx
        create_ssl_context = _create_ssl_ctx

    for port in [80, 443]:
        try:
            if port == 443:
                ssl_ctx = create_ssl_context(verify_ssl)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        ip, port, ssl=ssl_ctx, server_hostname=domain
                    ),
                    timeout=dns_probe_timeout,
                )
                # F5-05: Validate TLS certificate CN/SAN matches domain
                ssl_obj = writer.get_extra_info('ssl_object')
                if ssl_obj:
                    cert = ssl_obj.getpeercert()
                    if cert and not cert_matches_domain(cert, domain):
                        _close_writer(writer)
                        continue
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=dns_probe_timeout,
                )
            req = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            try:
                data = await asyncio.wait_for(
                    reader.read(4096), timeout=dns_probe_timeout
                )
                response = data.decode('utf-8', errors='ignore')
                if _is_valid_origin_response(response, domain):
                    _close_writer(writer)
                    return ip
            except (OSError, asyncio.TimeoutError):
                pass
            _close_writer(writer)
        except (OSError, ssl.SSLError, ConnectionError, asyncio.TimeoutError):
            continue
    return None


def _is_valid_origin_response(response: str, domain: str) -> bool:
    """Check if an HTTP response indicates the IP serves the domain.

    F5-05 (review): Multi-layered validation with header/body separation:
      1. Reject CDN error pages (full response)
      2. Reject if CDN header signatures in HTTP headers section
      3. Reject if CDN brand names in body
      4. Accept if domain appears in HTML <title>
      5. Accept if domain appears in body (not just headers)
      6. Accept HTTP 200/301/302 with no CDN indicators
    """
    response_lower = response.lower()

    # Split headers from body
    parts = response.split('\r\n\r\n', 1)
    headers_part = parts[0].lower()
    body_part = parts[1] if len(parts) > 1 else ''

    # 1. Reject obvious CDN error pages (full response)
    if any(sig in response_lower for sig in CDN_ERROR_SIGNATURES):
        return False

    # 2. Reject if CDN header signatures in HTTP headers section only
    if any(sig in headers_part for sig in CDN_HEADER_SIGNATURES):
        return False

    # 3. Reject if CDN brand names in body
    if any(sig in response_lower for sig in CDN_BODY_SIGNATURES):
        return False

    # 4. Domain in HTML title = strong signal
    if '<title>' in response_lower and domain in response:
        return True

    # 5. Domain in body (not just headers)
    if domain in body_part:
        return True

    # 6. HTTP success/redirect with no CDN indicators
    if any(x in response for x in ['200 OK', '301 Moved', '302 Found', '302 Moved']):
        return True  # Already checked CDN indicators above

    return False


def cert_matches_domain(cert: dict, domain: str) -> bool:
    """Check if a TLS certificate's CN or SAN matches the domain.

    F5-05: Prevents false positive origin validation when a CDN's
    wildcard certificate (e.g. *.cloudflare.com) is returned.
    """
    # Check Common Name
    for rdn in cert.get('subject', ()):
        for attr_type, attr_value in rdn:
            if attr_type == 'commonName':
                if hostname_matches(attr_value, domain):
                    return True

    # Check Subject Alternative Names
    for san_type, san_value in cert.get('subjectAltName', ()):
        if san_type == 'DNS':
            if hostname_matches(san_value, domain):
                return True

    return False


def hostname_matches(pattern: str, hostname: str) -> bool:
    """Check if a hostname matches a certificate pattern (supports wildcards)."""
    pattern = pattern.lower()
    hostname = hostname.lower()
    if pattern.startswith('*.'):
        # Wildcard: *.example.com matches sub.example.com
        suffix = pattern[2:]
        return hostname.endswith(suffix) and '.' not in hostname[:-len(suffix)]
    return pattern == hostname


def _close_writer(writer: Any) -> None:
    """Safely close an asyncio StreamWriter (sync portion only)."""
    try:
        writer.close()
    except (OSError, RuntimeError):
        pass


__all__ = [
    "verify_origin_ip",
    "cert_matches_domain",
    "hostname_matches",
    "CDN_RESPONSE_KEYWORDS",
    "CDN_ERROR_SIGNATURES",
]
