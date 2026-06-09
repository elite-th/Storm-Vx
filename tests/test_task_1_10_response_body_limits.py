#!/usr/bin/env python3
"""Tests for Task 1.10 — Add Response Body Size Limits (W1.10).

Verifies that:
1. safe_read_text() reads normal responses correctly
2. safe_read_text() truncates oversized responses (truncate=True)
3. safe_read_text() raises ResponseTooLargeError when truncate=False
4. safe_read_text() detects oversized responses via Content-Length header
5. safe_read_bytes() works for binary responses
6. safe_read_js() uses the larger JS-specific limit
7. Constants are defined in config/defaults.py
8. All finder/evasion modules use safe_read_text instead of bare resp.text()
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ── Import the module under test ──

from utils.response_helpers import (
    safe_read_text,
    safe_read_bytes,
    safe_read_js,
    ResponseTooLargeError,
)
from config.defaults import MAX_RESPONSE_BODY_BYTES, MAX_JS_BODY_BYTES


# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: Normal response is read correctly
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_safe_read_text_normal():
    """W1.10: Normal-sized response is read without truncation."""
    resp = MagicMock()
    resp.url = "https://example.com/page"
    resp.content_length = 100  # Well under limit
    resp.get_encoding.return_value = "utf-8"
    resp.content = AsyncMock()
    resp.content.read.return_value = b"Hello, World!"

    result = await safe_read_text(resp, max_bytes=1024)
    assert result == "Hello, World!"
    resp.content.read.assert_called_once_with(1025)  # max_bytes + 1


# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: Truncation when response exceeds limit (truncate=True)
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_safe_read_text_truncate_oversized():
    """W1.10: Oversized response is truncated when truncate=True."""
    max_bytes = 10
    resp = MagicMock()
    resp.url = "https://example.com/huge"
    resp.content_length = None  # No Content-Length header
    resp.get_encoding.return_value = "utf-8"
    resp.content = AsyncMock()
    # Return more bytes than the limit
    resp.content.read.return_value = b"A" * 15  # 15 > max_bytes + 1 = 11

    result = await safe_read_text(resp, max_bytes=max_bytes, truncate=True)
    assert len(result) == max_bytes
    assert result == "A" * max_bytes


# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: ResponseTooLargeError when truncate=False
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_safe_read_text_raises_on_oversized():
    """W1.10: Oversized response raises ResponseTooLargeError when truncate=False."""
    max_bytes = 10
    resp = MagicMock()
    resp.url = "https://example.com/huge"
    resp.content_length = None
    resp.get_encoding.return_value = "utf-8"
    resp.content = AsyncMock()
    resp.content.read.return_value = b"A" * 15

    with pytest.raises(ResponseTooLargeError) as exc_info:
        await safe_read_text(resp, max_bytes=max_bytes, truncate=False)

    assert exc_info.value.max_bytes == max_bytes
    assert exc_info.value.url == "https://example.com/huge"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: Early detection via Content-Length header
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_content_length_early_detection():
    """W1.10: Content-Length > max_bytes triggers early truncation."""
    max_bytes = 100
    resp = MagicMock()
    resp.url = "https://example.com/big"
    resp.content_length = 1_000_000  # Way over limit
    resp.get_encoding.return_value = "utf-8"
    resp.content = AsyncMock()
    resp.content.read.return_value = b"X" * max_bytes

    # truncate=True should truncate without downloading full body
    result = await safe_read_text(resp, max_bytes=max_bytes, truncate=True)
    assert len(result) == max_bytes
    # Should read only max_bytes, not max_bytes + 1
    resp.content.read.assert_called_once_with(max_bytes)


@pytest.mark.asyncio
async def test_content_length_raises():
    """W1.10: Content-Length > max_bytes raises when truncate=False."""
    max_bytes = 100
    resp = MagicMock()
    resp.url = "https://example.com/big"
    resp.content_length = 1_000_000
    resp.get_encoding.return_value = "utf-8"
    resp.content = AsyncMock()

    with pytest.raises(ResponseTooLargeError) as exc_info:
        await safe_read_text(resp, max_bytes=max_bytes, truncate=False)

    assert exc_info.value.content_length == 1_000_000


# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: safe_read_bytes works for binary responses
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_safe_read_bytes_normal():
    """W1.10: Normal binary response is read correctly."""
    resp = MagicMock()
    resp.url = "https://example.com/data.bin"
    resp.content_length = 50
    resp.content = AsyncMock()
    resp.content.read.return_value = b"\x00\x01\x02\x03"

    result = await safe_read_bytes(resp, max_bytes=1024)
    assert result == b"\x00\x01\x02\x03"


@pytest.mark.asyncio
async def test_safe_read_bytes_truncates():
    """W1.10: Oversized binary response is truncated."""
    max_bytes = 5
    resp = MagicMock()
    resp.url = "https://example.com/big.bin"
    resp.content_length = None
    resp.content = AsyncMock()
    resp.content.read.return_value = b"\x00" * 10

    result = await safe_read_bytes(resp, max_bytes=max_bytes, truncate=True)
    assert len(result) == max_bytes


# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: safe_read_js uses larger limit
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_safe_read_js_larger_limit():
    """W1.10: JS reader uses MAX_JS_BODY_BYTES (5 MiB) limit."""
    resp = MagicMock()
    resp.url = "https://example.com/app.js"
    resp.content_length = 2_000_000  # 2MB — fine for JS, too big for default
    resp.get_encoding.return_value = "utf-8"
    resp.content = AsyncMock()
    resp.content.read.return_value = b"var x = 1;"

    result = await safe_read_js(resp)
    assert result == "var x = 1;"
    # Should have been called with MAX_JS_BODY_BYTES + 1
    resp.content.read.assert_called_once_with(MAX_JS_BODY_BYTES + 1)


# ═══════════════════════════════════════════════════════════════════════════════
# Test 7: Constants are defined correctly
# ═══════════════════════════════════════════════════════════════════════════════

def test_max_response_body_bytes_constant():
    """W1.10: MAX_RESPONSE_BODY_BYTES is 1 MiB."""
    assert MAX_RESPONSE_BODY_BYTES == 1_048_576


def test_max_js_body_bytes_constant():
    """W1.10: MAX_JS_BODY_BYTES is 5 MiB."""
    assert MAX_JS_BODY_BYTES == 5_242_880


def test_js_limit_larger_than_default():
    """W1.10: JS limit is larger than default HTML limit."""
    assert MAX_JS_BODY_BYTES > MAX_RESPONSE_BODY_BYTES


# ═══════════════════════════════════════════════════════════════════════════════
# Test 8: Source code verification — modules use safe_read_text
# ═══════════════════════════════════════════════════════════════════════════════

def test_finder_modules_use_safe_read():
    """W1.10: All finder modules should import and use safe_read_text."""
    import importlib
    modules_to_check = [
        ("finder.vf_cache_analyzer", "safe_read_text"),
        ("finder.deep_scanner", "safe_read_text"),
        ("finder.vf_waf_probe", "safe_read_text"),
        ("finder.vf_rate_probe", "safe_read_text"),
        ("finder.http_fingerprint", "safe_read_text"),
        ("finder.vf_origin_discovery", "safe_read_text"),
        ("finder.vf_dir_fuzzer", "safe_read_text"),
        ("finder.vf_js_scanner", "safe_read_js"),
        ("evasion.vf_session_harvest", "safe_read_text"),
    ]
    for module_name, func_name in modules_to_check:
        with open(
            f"/home/z/my-project/upload/storm-vx-extracted/{module_name.replace('.', '/')}.py",
            "r"
        ) as f:
            source = f.read()
        assert func_name in source, f"{module_name} should use {func_name}"
        assert "utils.response_helpers" in source, f"{module_name} should import from utils.response_helpers"


def test_no_bare_resp_text_in_finder():
    """W1.10: No bare 'await resp.text()' should remain in finder/evasion modules."""
    import os
    import glob

    # Check all .py files in finder/ and evasion/ directories
    check_dirs = [
        "/home/z/my-project/upload/storm-vx-extracted/finder/",
        "/home/z/my-project/upload/storm-vx-extracted/evasion/",
    ]

    for check_dir in check_dirs:
        for filepath in glob.glob(os.path.join(check_dir, "*.py")):
            with open(filepath, "r") as f:
                source = f.read()
            assert "await resp.text()" not in source, \
                f"{filepath} still contains bare 'await resp.text()' — use safe_read_text() instead"


# ═══════════════════════════════════════════════════════════════════════════════
# Test 9: ResponseTooLargeError attributes
# ═══════════════════════════════════════════════════════════════════════════════

def test_response_too_large_error_attributes():
    """W1.10: ResponseTooLargeError has useful attributes."""
    err = ResponseTooLargeError("https://example.com", 5_000_000, 1_048_576)
    assert err.url == "https://example.com"
    assert err.content_length == 5_000_000
    assert err.max_bytes == 1_048_576
    assert "5_000_000" in str(err) or "5000000" in str(err)


# ═══════════════════════════════════════════════════════════════════════════════
# Test 10: Unicode handling with truncated responses
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_unicode_decode_errors_replaced():
    """W1.10: Truncated UTF-8 sequences are replaced, not crashed."""
    max_bytes = 5
    resp = MagicMock()
    resp.url = "https://example.com/unicode"
    resp.content_length = None
    resp.get_encoding.return_value = "utf-8"
    resp.content = AsyncMock()
    # Return bytes that could form invalid UTF-8 when truncated
    resp.content.read.return_value = b"abcde\xf0\x9f" + b"X" * 10  # Truncated emoji

    result = await safe_read_text(resp, max_bytes=max_bytes, truncate=True)
    # Should not raise UnicodeDecodeError; uses errors='replace'
    assert isinstance(result, str)
    assert len(result) > 0
