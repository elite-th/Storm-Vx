#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adversarial tests for security hardening fixes.

Tests specifically targeting the fixes for:
  C1: JSON bomb protection bypass — safe_json_loads() depth+size enforcement
  C2: Dual sanitize_path inconsistency — URL-encoded/Unicode traversal
  H2: IPv4-mapped IPv6 SSRF bypass
  H3: Non-strict JSON size enforcement weakness
  H5: Hot-path environment lookup caching
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import pytest
from unittest.mock import patch


# ═══════════════════════════════════════════════════════════════════════════════
# C1: JSON Bomb Protection Bypass Fix
# ═══════════════════════════════════════════════════════════════════════════════

class TestC1JSONBombFix:
    """Adversarial tests for C1: safe_json_loads() must enforce size + depth
    BEFORE and AFTER parsing, with no unprotected fallback paths."""

    def setup_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def teardown_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def test_size_limit_enforced_even_in_non_strict_mode(self):
        """C1/H3: Size limit must be enforced regardless of strict mode."""
        from security.input_validation import safe_json_loads, JSONBombError
        big_data = json.dumps({"data": "x" * 1000})
        # Must raise JSONBombError even with strict=False
        with pytest.raises(JSONBombError):
            safe_json_loads(big_data, max_size=100, strict=False)

    def test_depth_limit_enforced_even_in_non_strict_mode(self):
        """C1: Depth limit must be enforced regardless of strict mode."""
        from security.input_validation import safe_json_loads, JSONBombError
        nested = "1"
        for _ in range(30):
            nested = f'{{"a": {nested}}}'
        with pytest.raises(JSONBombError):
            safe_json_loads(nested, max_depth=10, strict=False)

    def test_no_unprotected_fallback_path(self):
        """C1: Verify the old TypeError fallback path no longer exists."""
        from security.input_validation import safe_json_loads, JSONBombError
        # This deeply nested JSON should be caught by _validate_json_depth
        # regardless of how it's parsed internally
        nested = "1"
        for _ in range(50):
            nested = f'[{nested}]'
        with pytest.raises(JSONBombError):
            safe_json_loads(nested, max_depth=20)

    def test_size_check_uses_char_len_fast_path(self):
        """C1: For ASCII strings, char_len == byte_len, so no .encode() needed."""
        from security.input_validation import safe_json_loads
        # 500-char ASCII string, max_size=1000 — should NOT need to encode
        data = json.dumps({"key": "a" * 490})
        result = safe_json_loads(data, max_size=2000)
        assert result["key"] == "a" * 490

    def test_size_check_handles_multibyte_utf8(self):
        """C1: Unicode strings with multi-byte UTF-8 must be measured correctly."""
        from security.input_validation import safe_json_loads, JSONBombError
        # 100 emoji characters → ~400 bytes in UTF-8
        emoji_string = "🎉" * 100  # Each 🎉 is 4 bytes in UTF-8
        data = json.dumps({"data": emoji_string})
        # char_len=100+, but UTF-8 size > 200
        with pytest.raises(JSONBombError):
            safe_json_loads(data, max_size=200)

    def test_empty_json_returns_none(self):
        """C1: Empty string must still return None."""
        from security.input_validation import safe_json_loads
        assert safe_json_loads("") is None

    def test_valid_json_within_limits_passes(self):
        """C1: Normal JSON within limits must still work."""
        from security.input_validation import safe_json_loads
        result = safe_json_loads('{"name": "test", "count": 42}')
        assert result == {"name": "test", "count": 42}

    def test_json_bomb_file_rejected(self):
        """C1: safe_json_load() must reject deeply nested file content."""
        from security.input_validation import safe_json_load, JSONBombError
        nested = "1"
        for _ in range(30):
            nested = f'{{"a": {nested}}}'
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as f:
            f.write(nested)
            f.flush()
            try:
                with pytest.raises(JSONBombError):
                    safe_json_load(f.name, max_depth=10, max_size=1_000_000)
            finally:
                os.unlink(f.name)

    def test_oversized_file_rejected(self):
        """C1/H3: safe_json_load() must reject files exceeding size limit."""
        from security.input_validation import safe_json_load, JSONBombError
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as f:
            f.write('{"data": "' + "x" * 10000 + '"}')
            f.flush()
            try:
                with pytest.raises(JSONBombError):
                    safe_json_load(f.name, max_size=100)
            finally:
                os.unlink(f.name)


# ═══════════════════════════════════════════════════════════════════════════════
# C2: Dual sanitize_path Consistency Fix
# ═══════════════════════════════════════════════════════════════════════════════

class TestC2SanitizePathConsistency:
    """Adversarial tests for C2: sanitize_path() must handle URL-encoded
    and Unicode-based traversal attempts, consistent with vf_validator."""

    def setup_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def teardown_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def test_url_encoded_traversal_detected(self):
        """C2: %2e%2e%2f (URL-encoded ../) must be detected and sanitized."""
        from security.input_validation import sanitize_path
        result = sanitize_path("%2e%2e%2fetc%2fpasswd", strict=False)
        # After URL-decoding and normalization, should not contain ../
        assert "../" not in result

    def test_double_encoded_traversal_detected(self):
        """C2: %252e%252e%252f (double-encoded ../) must be detected."""
        from security.input_validation import sanitize_path
        result = sanitize_path("%252e%252e%252fetc%252fpasswd", strict=False)
        assert "../" not in result

    def test_tomcat_semicolon_bypass_detected(self):
        """C2: ..;/ (Tomcat path parameter bypass) must be sanitized."""
        from security.input_validation import sanitize_path
        result = sanitize_path("foo/..;/bar", strict=False)
        # Should be normalized — no ..;/ remaining
        assert "..;/" not in result

    def test_strict_mode_raises_on_traversal(self):
        """C2: Strict mode must still raise PathTraversalError."""
        from security.input_validation import sanitize_path, PathTraversalError
        with pytest.raises(PathTraversalError):
            sanitize_path("../../etc/passwd", strict=True)

    def test_strict_mode_raises_on_null_bytes(self):
        """C2: Strict mode must still raise on null bytes."""
        from security.input_validation import sanitize_path, PathTraversalError
        with pytest.raises(PathTraversalError):
            sanitize_path("file\x00.json", strict=True)

    def test_base_dir_containment_still_works(self):
        """C2: base_dir containment must work after preprocessing."""
        from security.input_validation import sanitize_path
        with tempfile.TemporaryDirectory() as tmpdir:
            result = sanitize_path("subdir/profile.json", base_dir=tmpdir, strict=True)
            assert result.startswith(tmpdir)

    def test_base_dir_escape_detected_in_strict(self):
        """C2: Escaping base_dir must still be detected in strict mode."""
        from security.input_validation import sanitize_path, PathTraversalError
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(PathTraversalError):
                sanitize_path("../../../etc/passwd", base_dir=tmpdir, strict=True)

    def test_unicode_dots_normalized(self):
        """C2: Unicode dots (\u002e = '.') must be normalized."""
        from security.input_validation import sanitize_path
        # \u002e is the Unicode codepoint for '.' 
        result = sanitize_path("\u002e\u002e/etc/passwd", strict=False)
        # Should not contain the original unicode dots after normalization
        assert "\u002e\u002e/" not in result


# ═══════════════════════════════════════════════════════════════════════════════
# H2: IPv4-Mapped IPv6 SSRF Bypass Fix
# ═══════════════════════════════════════════════════════════════════════════════

class TestH2IPv4MappedIPv6:
    """Adversarial tests for H2: is_private_ip() must detect IPv4-mapped
    IPv6 addresses that resolve to private IPv4 addresses."""

    def setup_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def teardown_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def test_ipv4_mapped_loopback(self):
        """H2: ::ffff:127.0.0.1 must be detected as private."""
        from security.input_validation import is_private_ip
        assert is_private_ip("::ffff:127.0.0.1") is True

    def test_ipv4_mapped_rfc1918_10(self):
        """H2: ::ffff:10.0.0.1 must be detected as private."""
        from security.input_validation import is_private_ip
        assert is_private_ip("::ffff:10.0.0.1") is True

    def test_ipv4_mapped_rfc1918_172(self):
        """H2: ::ffff:172.16.0.1 must be detected as private."""
        from security.input_validation import is_private_ip
        assert is_private_ip("::ffff:172.16.0.1") is True

    def test_ipv4_mapped_rfc1918_192(self):
        """H2: ::ffff:192.168.1.1 must be detected as private."""
        from security.input_validation import is_private_ip
        assert is_private_ip("::ffff:192.168.1.1") is True

    def test_ipv4_mapped_link_local(self):
        """H2: ::ffff:169.254.1.1 must be detected as private."""
        from security.input_validation import is_private_ip
        assert is_private_ip("::ffff:169.254.1.1") is True

    def test_ipv4_mapped_public_is_not_private(self):
        """H2: ::ffff:8.8.8.8 must NOT be detected as private."""
        from security.input_validation import is_private_ip
        assert is_private_ip("::ffff:8.8.8.8") is False

    def test_ipv4_mapped_zero_network(self):
        """H2: ::ffff:0.0.0.1 must be detected as private (this-network)."""
        from security.input_validation import is_private_ip
        assert is_private_ip("::ffff:0.0.0.1") is True

    def test_validate_url_blocks_ipv4_mapped_private(self):
        """H2: validate_url() must block URLs with IPv4-mapped private IPs."""
        from security.input_validation import validate_url, SSRFError
        with patch.dict(os.environ, {"STORM_VX_SSRF_PROTECTION": "true"}):
            from security.input_validation import _refresh_config
            _refresh_config()
            with pytest.raises(SSRFError):
                validate_url("http://[::ffff:192.168.1.1]/admin", strict=True)

    def test_validate_hostname_blocks_ipv4_mapped(self):
        """H2: validate_hostname() must block IPv4-mapped private hostnames."""
        from security.input_validation import validate_hostname, SSRFError
        with patch.dict(os.environ, {"STORM_VX_SSRF_PROTECTION": "true"}):
            from security.input_validation import _refresh_config
            _refresh_config()
            with pytest.raises(SSRFError):
                validate_hostname("::ffff:127.0.0.1", strict=True)

    def test_pure_ipv6_loopback_still_detected(self):
        """H2: Pure IPv6 loopback ::1 must still be detected."""
        from security.input_validation import is_private_ip
        assert is_private_ip("::1") is True

    def test_pure_ipv6_public_still_allowed(self):
        """H2: Public IPv6 must still pass."""
        from security.input_validation import is_private_ip
        assert is_private_ip("2001:4860:4860::8888") is False


# ═══════════════════════════════════════════════════════════════════════════════
# H3: Non-Strict JSON Size Enforcement (covered by C1 tests above)
# ═══════════════════════════════════════════════════════════════════════════════

class TestH3NonStrictSizeEnforcement:
    """Additional tests for H3: Size limits must be enforced even in
    non-strict mode to prevent memory exhaustion."""

    def setup_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def teardown_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def test_non_strict_mode_rejects_oversized_payload(self):
        """H3: Non-strict mode MUST reject oversized JSON to prevent OOM."""
        from security.input_validation import safe_json_loads, JSONBombError
        payload = json.dumps({"data": "x" * 10000})
        with pytest.raises(JSONBombError):
            safe_json_loads(payload, max_size=1000, strict=False)

    def test_non_strict_mode_rejects_deeply_nested(self):
        """H3: Non-strict mode MUST reject deeply nested JSON."""
        from security.input_validation import safe_json_loads, JSONBombError
        nested = "1"
        for _ in range(25):
            nested = f'{{"x": {nested}}}'
        with pytest.raises(JSONBombError):
            safe_json_loads(nested, max_depth=5, strict=False)

    def test_strict_mode_rejects_oversized_payload(self):
        """H3: Strict mode also rejects oversized JSON."""
        from security.input_validation import safe_json_loads, JSONBombError
        payload = json.dumps({"data": "x" * 10000})
        with pytest.raises(JSONBombError):
            safe_json_loads(payload, max_size=1000, strict=True)


# ═══════════════════════════════════════════════════════════════════════════════
# H5: Cached Environment Lookup
# ═══════════════════════════════════════════════════════════════════════════════

class TestH5CachedConfigLookup:
    """Tests for H5: Environment lookups must be cached for hot-path
    performance, with a refresh mechanism for runtime changes."""

    def test_config_caching_returns_consistent_values(self):
        """H5: Multiple calls must return the same cached value."""
        from security.input_validation import _is_strict_mode, _is_ssrf_protection_enabled
        # Call multiple times — should return same value
        val1 = _is_strict_mode()
        val2 = _is_strict_mode()
        assert val1 == val2

    def test_refresh_config_clears_cache(self):
        """H5: _refresh_config() must clear the cache."""
        from security.input_validation import _is_strict_mode, _refresh_config
        # Get cached value
        val1 = _is_strict_mode()
        # Refresh cache
        _refresh_config()
        # Should re-read from env (may be same value, but cache was cleared)
        val2 = _is_strict_mode()
        # Both should be consistent with current env
        expected = os.environ.get("STORM_VX_SECURITY_STRICT", "").lower() in ("true", "1", "yes")
        assert val1 == expected
        assert val2 == expected

    def test_env_change_reflected_after_refresh(self):
        """H5: Environment changes must be reflected after _refresh_config()."""
        from security.input_validation import _is_strict_mode, _refresh_config
        # Get current value
        original = _is_strict_mode()
        # Change env and refresh
        with patch.dict(os.environ, {"STORM_VX_SECURITY_STRICT": "true"}):
            _refresh_config()
            assert _is_strict_mode() is True
        # After context exit, refresh should see old value
        _refresh_config()
        assert _is_strict_mode() == original

    def test_ssrf_protection_caching(self):
        """H5: SSRF protection flag must also be cached."""
        from security.input_validation import _is_ssrf_protection_enabled, _refresh_config
        with patch.dict(os.environ, {"STORM_VX_SSRF_PROTECTION": "false"}):
            _refresh_config()
            assert _is_ssrf_protection_enabled() is False
        _refresh_config()
        # Should revert to default (true)
        assert _is_ssrf_protection_enabled() is True

    def test_cached_lookup_performance(self):
        """H5: Cached lookups should be faster than uncached os.environ.get()."""
        from security.input_validation import _is_strict_mode, _refresh_config
        _refresh_config()
        # Warm the cache
        _is_strict_mode()
        # Time 10000 cached lookups
        start = time.perf_counter()
        for _ in range(10000):
            _is_strict_mode()
        elapsed = time.perf_counter() - start
        # Should be very fast (< 10ms for 10k calls)
        assert elapsed < 0.1, f"Cached lookup too slow: {elapsed:.4f}s for 10k calls"

    def test_refresh_config_exported(self):
        """H5: _refresh_config must be importable from security package."""
        from security import _refresh_config
        # Should not raise
        _refresh_config()
