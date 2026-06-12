#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""utils.response_helpers — Safe response body reading with size limits.

W1.10 FIX: Prevents memory exhaustion from unbounded response body downloads.

Previously, all `await resp.text()` calls loaded the ENTIRE response body
into memory with no size cap. A malicious or misconfigured server returning
a 100MB+ response would exhaust RAM, especially with multiple concurrent
requests.

This module provides safe_read_text() and safe_read_bytes() that enforce
a configurable maximum body size. When the limit is exceeded, the response
is truncated and a warning is logged.

Usage:
    from utils.response_helpers import safe_read_text
    async with session.get(url) as resp:
        body = await safe_read_text(resp)  # max 1MB by default
        # For JS bundles that can be larger:
        body = await safe_read_text(resp, max_bytes=5_242_880)
"""
from __future__ import annotations

import aiohttp
from config.defaults import MAX_RESPONSE_BODY_BYTES, MAX_JS_BODY_BYTES
from logging_config import get_logger

logger = get_logger(__name__)


class ResponseTooLargeError(Exception):
    """Raised when a response body exceeds the configured size limit.

    Callers can catch this to implement custom handling (e.g., skip analysis,
    use partial data, etc.).
    """
    def __init__(self, url: str, content_length: int | None, max_bytes: int):
        self.url = url
        self.content_length = content_length
        self.max_bytes = max_bytes
        super().__init__(
            f"Response body too large: {url} "
            f"(Content-Length: {content_length}, limit: {max_bytes})"
        )


# F5-08: Safe encoding detection — wraps aiohttp's get_encoding()
# which can raise RuntimeError("Cannot compute fallback encoding of a
# not yet read body") when the response has no Content-Type header and
# the body is empty or too small for charset detection.
def _safe_get_encoding(resp: aiohttp.ClientResponse) -> str:
    """Safely detect response encoding with fallback to UTF-8.

    Args:
        resp: The aiohttp ClientResponse to detect encoding from.

    Returns:
        Encoding string (e.g. 'utf-8', 'iso-8859-1').
    """
    try:
        return resp.get_encoding()
    except (RuntimeError, LookupError, ValueError):
        # Fallback: try declared charset, then UTF-8
        content_type = resp.headers.get('Content-Type', '')
        if 'charset=' in content_type:
            charset = content_type.split('charset=')[-1].split(';')[0].strip().strip('"\'')
            if charset:
                return charset
        return 'utf-8'


# ═══════════════════════════════════════════════════════════════════════════════
# WAF Block Detection (BUG-032 fix)
# ═══════════════════════════════════════════════════════════════════════════════

def _is_waf_block(status: int, headers: dict | None = None) -> bool:
    """Check if HTTP status indicates WAF blocking.

    BUG-032 FIX: Previously, status 500 was always classified as a WAF block
    alongside 403/429/503. However, a generic 500 Internal Server Error is
    NOT necessarily a WAF block — it may be a legitimate server error.
    Only treat 500 as WAF block when WAF-specific headers are present
    (e.g., ArvanCloud Server header, X-WAF-Event header).

    Args:
        status: HTTP status code.
        headers: Response headers dict (optional). If None, 500 is NOT
                 treated as WAF block (conservative — avoids false positives).

    Returns:
        True if the status indicates WAF blocking, False otherwise.
    """
    # These status codes ALWAYS indicate WAF block
    if status in (403, 429, 503):
        return True
    # 500 is WAF block ONLY if WAF-specific headers are present
    if status == 500 and headers:
        server = headers.get('Server', '').lower()
        if 'arvan' in server or headers.get('X-WAF-Event'):
            return True
    return False


async def safe_read_text(
    resp: aiohttp.ClientResponse,
    max_bytes: int = MAX_RESPONSE_BODY_BYTES,
    *,
    truncate: bool = True,
) -> str:
    """Read response body as text with a size limit.

    W1.10 FIX: Prevents loading unbounded response bodies into memory.

    Strategy:
        1. Check Content-Length header for early detection of oversized
           responses (avoids downloading the body at all).
        2. Read up to max_bytes + 1 from the body stream.
        3. If more data is available than max_bytes:
           - If truncate=True (default): log a warning and return truncated text.
           - If truncate=False: raise ResponseTooLargeError.

    Args:
        resp: The aiohttp ClientResponse to read from.
        max_bytes: Maximum bytes to read (default: 1 MiB from config/defaults.py).
        truncate: If True, silently truncate oversized responses.
                  If False, raise ResponseTooLargeError.

    Returns:
        Decoded text of the response body (possibly truncated).

    Raises:
        ResponseTooLargeError: When body exceeds max_bytes and truncate=False.
        UnicodeDecodeError: When the body cannot be decoded (replaced with 'replace').
    """
    # Step 1: Early check via Content-Length header
    content_length = resp.content_length
    url = str(resp.url) if resp.url else "<unknown>"

    if content_length is not None and content_length > max_bytes:
        if truncate:
            logger.warning(
                f"W1.10: Response body too large ({content_length} bytes > "
                f"{max_bytes} limit) for {url}. Truncating."
            )
            data = await resp.content.read(max_bytes)
            encoding = _safe_get_encoding(resp)
            return data.decode(encoding, errors='replace')
        else:
            raise ResponseTooLargeError(url, content_length, max_bytes)

    # Step 2: Read up to max_bytes + 1 to detect truncation
    data = await resp.content.read(max_bytes + 1)

    if len(data) > max_bytes:
        # Body was larger than our limit
        if truncate:
            logger.warning(
                f"W1.10: Response body exceeded {max_bytes} bytes for {url}. "
                f"Truncating (no Content-Length header or it was inaccurate)."
            )
            data = data[:max_bytes]
        else:
            raise ResponseTooLargeError(url, None, max_bytes)

    encoding = _safe_get_encoding(resp)
    return data.decode(encoding, errors='replace')


async def safe_read_bytes(
    resp: aiohttp.ClientResponse,
    max_bytes: int = MAX_RESPONSE_BODY_BYTES,
    *,
    truncate: bool = True,
) -> bytes:
    """Read response body as raw bytes with a size limit.

    Same as safe_read_text() but returns bytes instead of decoded text.
    Useful when you need the raw response (e.g., binary content, hash
    computation) without charset decoding.

    Args:
        resp: The aiohttp ClientResponse to read from.
        max_bytes: Maximum bytes to read (default: 1 MiB).
        truncate: If True, silently truncate oversized responses.
                  If False, raise ResponseTooLargeError.

    Returns:
        Raw bytes of the response body (possibly truncated).

    Raises:
        ResponseTooLargeError: When body exceeds max_bytes and truncate=False.
    """
    content_length = resp.content_length
    url = str(resp.url) if resp.url else "<unknown>"

    if content_length is not None and content_length > max_bytes:
        if truncate:
            logger.warning(
                f"W1.10: Response body too large ({content_length} bytes > "
                f"{max_bytes} limit) for {url}. Truncating."
            )
            return await resp.content.read(max_bytes)
        else:
            raise ResponseTooLargeError(url, content_length, max_bytes)

    data = await resp.content.read(max_bytes + 1)

    if len(data) > max_bytes:
        if truncate:
            logger.warning(
                f"W1.10: Response body exceeded {max_bytes} bytes for {url}. "
                f"Truncating (no Content-Length header or it was inaccurate)."
            )
            return data[:max_bytes]
        else:
            raise ResponseTooLargeError(url, None, max_bytes)

    return data


# Convenience aliases for common use cases
async def safe_read_js(resp: aiohttp.ClientResponse) -> str:
    """Read a JavaScript bundle response (5 MiB limit instead of 1 MiB)."""
    return await safe_read_text(resp, max_bytes=MAX_JS_BODY_BYTES)
