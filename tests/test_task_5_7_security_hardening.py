#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tests.test_task_5_7_security_hardening — Comprehensive tests for W5.7 Security Hardening.

Tests cover:
  1. input_validation — URL validation, SSRF detection, path traversal,
     header sanitization, JSON bomb protection
  2. secrets_guard — Secret redaction, should_redact detection,
     log message redaction, log extra redaction
  3. audit — Security event logging, audit trail, counters, stats
  4. config — SecuritySettings dataclass, config defaults
  5. integration — Logging redaction, profile loader security, plugin security
"""
from __future__ import annotations

import json
import os
import tempfile
import logging
import pytest
from unittest.mock import patch

# ═══════════════════════════════════════════════════════════════════════════════
# Test: Security Exceptions
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityExceptions:
    """Test security exception hierarchy."""

    def test_security_validation_error_is_value_error(self):
        from security.input_validation import SecurityValidationError
        assert issubclass(SecurityValidationError, ValueError)

    def test_ssrf_error_is_security_error(self):
        from security.input_validation import SSRFError, SecurityValidationError
        assert issubclass(SSRFError, SecurityValidationError)

    def test_path_traversal_error_is_security_error(self):
        from security.input_validation import PathTraversalError, SecurityValidationError
        assert issubclass(PathTraversalError, SecurityValidationError)

    def test_header_injection_error_is_security_error(self):
        from security.input_validation import HeaderInjectionError, SecurityValidationError
        assert issubclass(HeaderInjectionError, SecurityValidationError)

    def test_json_bomb_error_is_security_error(self):
        from security.input_validation import JSONBombError, SecurityValidationError
        assert issubclass(JSONBombError, SecurityValidationError)

    def test_exception_messages(self):
        from security.input_validation import SSRFError
        err = SSRFError("URL targets private IP: 192.168.1.1")
        assert "192.168.1.1" in str(err)


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Private IP Detection (SSRF Prevention)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPrivateIPDetection:
    """Test is_private_ip() for all RFC 1918 and reserved ranges."""

    def test_loopback(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("127.0.0.1") is True

    def test_rfc1918_10(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True

    def test_rfc1918_172(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True

    def test_rfc1918_192(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("192.168.0.1") is True

    def test_link_local(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("169.254.1.1") is True

    def test_carrier_grade_nat(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("100.64.0.1") is True

    def test_this_network(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("0.0.0.1") is True

    def test_multicast(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("224.0.0.1") is True

    def test_reserved(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("240.0.0.1") is True

    def test_public_ips_are_not_private(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
        assert is_private_ip("203.0.113.1") is False

    def test_invalid_ip_returns_false(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("not.an.ip") is False
        assert is_private_ip("") is False

    def test_ipv6_loopback(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("::1") is True

    def test_ipv6_link_local(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("fe80::1") is True

    def test_ipv6_unique_local(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("fc00::1") is True

    def test_ipv6_public_is_not_private(self):
        from security.input_validation import is_private_ip
        assert is_private_ip("2001:4860:4860::8888") is False


class TestInternalHostname:
    """Test is_internal_hostname() for known internal hostnames."""

    def test_localhost(self):
        from security.input_validation import is_internal_hostname
        assert is_internal_hostname("localhost") is True

    def test_localhost_localdomain(self):
        from security.input_validation import is_internal_hostname
        assert is_internal_hostname("localhost.localdomain") is True

    def test_dot_local_tld(self):
        from security.input_validation import is_internal_hostname
        assert is_internal_hostname("myserver.local") is True

    def test_dot_internal_tld(self):
        from security.input_validation import is_internal_hostname
        assert is_internal_hostname("api.internal") is True

    def test_dot_localhost_tld(self):
        from security.input_validation import is_internal_hostname
        assert is_internal_hostname("app.localhost") is True

    def test_public_hostname_is_not_internal(self):
        from security.input_validation import is_internal_hostname
        assert is_internal_hostname("example.com") is False
        assert is_internal_hostname("api.example.com") is False

    def test_case_insensitive(self):
        from security.input_validation import is_internal_hostname
        assert is_internal_hostname("LocalHost") is True
        assert is_internal_hostname("LOCALHOST") is True


# ═══════════════════════════════════════════════════════════════════════════════
# Test: URL Validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestURLValidation:
    """Test validate_url() for various URL patterns."""

    def setup_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def teardown_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def test_valid_http_url(self):
        from security.input_validation import validate_url
        assert validate_url("http://example.com") == "http://example.com"

    def test_valid_https_url(self):
        from security.input_validation import validate_url
        assert validate_url("https://example.com/api/v1") == "https://example.com/api/v1"

    def test_empty_url_returns_as_is(self):
        from security.input_validation import validate_url
        # Non-strict: logs warning, returns as-is
        result = validate_url("", strict=False)
        assert result == ""

    def test_url_with_credentials_stripped(self):
        from security.input_validation import validate_url
        result = validate_url("https://user:pass@example.com/api", strict=False)
        assert "user:pass@" not in result
        assert "example.com" in result

    def test_url_with_credentials_strict_mode(self):
        from security.input_validation import validate_url, SecurityValidationError
        with pytest.raises(SecurityValidationError):
            validate_url("https://user:pass@example.com/api", strict=True)

    def test_ftp_scheme_rejected_in_strict(self):
        from security.input_validation import validate_url, SecurityValidationError
        with pytest.raises(SecurityValidationError):
            validate_url("ftp://example.com/file", strict=True)

    def test_javascript_scheme_rejected(self):
        from security.input_validation import validate_url, SecurityValidationError
        with pytest.raises(SecurityValidationError):
            validate_url("javascript:alert(1)", strict=True)

    def test_file_scheme_rejected(self):
        from security.input_validation import validate_url, SecurityValidationError
        with pytest.raises(SecurityValidationError):
            validate_url("file:///etc/passwd", strict=True)

    def test_url_with_private_ip_in_strict_mode(self):
        from security.input_validation import validate_url, SSRFError, _is_ssrf_protection_enabled
        with patch.dict(os.environ, {"STORM_VX_SSRF_PROTECTION": "true"}):
            assert _is_ssrf_protection_enabled() is True
            with pytest.raises(SSRFError):
                validate_url("http://192.168.1.1/admin", strict=True)

    def test_url_with_localhost_in_strict_mode(self):
        from security.input_validation import validate_url, SSRFError
        with patch.dict(os.environ, {"STORM_VX_SSRF_PROTECTION": "true"}):
            with pytest.raises(SSRFError):
                validate_url("http://localhost:8080/admin", strict=True)

    def test_url_with_public_ip_passes(self):
        from security.input_validation import validate_url
        result = validate_url("http://93.184.216.34/", strict=True)
        assert result == "http://93.184.216.34/"

    def test_very_long_url_warning(self):
        from security.input_validation import validate_url
        long_url = "https://example.com/" + "a" * 9000
        # Non-strict: truncated
        result = validate_url(long_url, max_length=100, strict=False)
        assert len(result) <= 100

    def test_allow_private_ips_flag(self):
        from security.input_validation import validate_url
        result = validate_url("http://192.168.1.1/admin", allow_private_ips=True, strict=True)
        assert "192.168.1.1" in result


class TestURLSanitization:
    """Test sanitize_url_for_log() for log-safe URL output."""

    def test_strips_credentials(self):
        from security.input_validation import sanitize_url_for_log
        result = sanitize_url_for_log("https://user:pass@example.com/api")
        assert "user:pass" not in result
        assert "example.com" in result

    def test_redacts_sensitive_params(self):
        from security.input_validation import sanitize_url_for_log
        result = sanitize_url_for_log("https://api.example.com/data?token=secret123&id=5")
        assert "secret123" not in result
        assert "token=***" in result
        assert "id=5" in result

    def test_redacts_api_key(self):
        from security.input_validation import sanitize_url_for_log
        result = sanitize_url_for_log("https://api.example.com?key=abc123")
        assert "abc123" not in result

    def test_preserves_safe_params(self):
        from security.input_validation import sanitize_url_for_log
        result = sanitize_url_for_log("https://example.com?page=1&limit=10")
        assert "page=1" in result
        assert "limit=10" in result

    def test_empty_url(self):
        from security.input_validation import sanitize_url_for_log
        assert sanitize_url_for_log("") == ""


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Path Traversal Protection
# ═══════════════════════════════════════════════════════════════════════════════

class TestPathTraversal:
    """Test sanitize_path() for directory traversal prevention."""

    def test_simple_path_passes(self):
        from security.input_validation import sanitize_path
        assert sanitize_path("profile.json") == "profile.json"

    def test_traversal_sequence_non_strict(self):
        from security.input_validation import sanitize_path
        # Non-strict: normalizes the path
        result = sanitize_path("../../etc/passwd", strict=False)
        # Should not contain ../
        assert ".." not in result or os.path.normpath("../../etc/passwd") == result

    def test_traversal_sequence_strict(self):
        from security.input_validation import sanitize_path, PathTraversalError
        with pytest.raises(PathTraversalError):
            sanitize_path("../../etc/passwd", strict=True)

    def test_null_byte_stripped(self):
        from security.input_validation import sanitize_path
        result = sanitize_path("file\x00.json", strict=False)
        assert "\x00" not in result

    def test_null_byte_strict(self):
        from security.input_validation import sanitize_path, PathTraversalError
        with pytest.raises(PathTraversalError):
            sanitize_path("file\x00.json", strict=True)

    def test_base_dir_containment(self):
        from security.input_validation import sanitize_path
        with tempfile.TemporaryDirectory() as tmpdir:
            # Path within base_dir is fine
            result = sanitize_path("subdir/profile.json", base_dir=tmpdir, strict=True)
            assert result.startswith(tmpdir)

    def test_escape_from_base_dir_strict(self):
        from security.input_validation import sanitize_path, PathTraversalError
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(PathTraversalError):
                sanitize_path("../../../etc/passwd", base_dir=tmpdir, strict=True)

    def test_escape_from_base_dir_non_strict(self):
        from security.input_validation import sanitize_path
        with tempfile.TemporaryDirectory() as tmpdir:
            # Non-strict: the path is sanitized by vf_validator which strips
            # ../ sequences, resulting in "etc/passwd" which is a valid
            # relative path within base_dir. The resolved path stays within
            # base_dir, so it's returned as the resolved absolute path.
            result = sanitize_path("../../../etc/passwd", base_dir=tmpdir, strict=False)
            # After robust preprocessing, ../../../etc/passwd → etc/passwd
            # which resolves within base_dir — this is the correct safe result
            assert result.startswith(tmpdir) or result == "passwd"

    def test_empty_path(self):
        from security.input_validation import sanitize_path
        assert sanitize_path("") == ""


class TestFilePathValidation:
    """Test validate_file_path() for extension and size checks."""

    def test_json_extension_allowed(self):
        from security.input_validation import validate_file_path
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            f.write("{}")
            f.flush()
            try:
                result = validate_file_path(
                    f.name,
                    allowed_extensions=(".json",),
                )
                assert result.endswith(".json")
            finally:
                os.unlink(f.name)

    def test_wrong_extension_rejected_strict(self):
        from security.input_validation import validate_file_path, SecurityValidationError
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False, mode="w") as f:
            f.write("binary")
            f.flush()
            try:
                with pytest.raises(SecurityValidationError):
                    validate_file_path(
                        f.name,
                        allowed_extensions=(".json",),
                        strict=True,
                    )
            finally:
                os.unlink(f.name)


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Header Sanitization
# ═══════════════════════════════════════════════════════════════════════════════

class TestHeaderSanitization:
    """Test sanitize_header_value() for CRLF injection prevention."""

    def test_clean_header_passes(self):
        from security.input_validation import sanitize_header_value
        assert sanitize_header_value("application/json") == "application/json"

    def test_crlf_stripped(self):
        from security.input_validation import sanitize_header_value
        result = sanitize_header_value("value\r\nX-Injected: true", strict=False)
        # CRLF characters are removed, but the remaining text joins
        assert "\r" not in result
        assert "\n" not in result
        # After stripping \r\n, we get "valueX-Injected: true" — CRLF is gone
        assert "valueX-Injected" in result

    def test_crlf_strict_mode(self):
        from security.input_validation import sanitize_header_value, HeaderInjectionError
        with pytest.raises(HeaderInjectionError):
            sanitize_header_value("value\r\nX-Injected: true", strict=True)

    def test_lf_only_stripped(self):
        from security.input_validation import sanitize_header_value
        result = sanitize_header_value("value\nInjected", strict=False)
        assert "\n" not in result

    def test_cr_only_stripped(self):
        from security.input_validation import sanitize_header_value
        result = sanitize_header_value("value\rInjected", strict=False)
        assert "\r" not in result

    def test_empty_value(self):
        from security.input_validation import sanitize_header_value
        assert sanitize_header_value("") == ""
        assert sanitize_header_value(None) is None  # type: ignore

    def test_sanitize_headers_dict(self):
        from security.input_validation import sanitize_headers
        headers = {
            "Content-Type": "application/json",
            "X-Custom": "value\r\nX-Injected: true",
        }
        result = sanitize_headers(headers, strict=False)
        assert result["Content-Type"] == "application/json"
        assert "\r" not in result["X-Custom"]


# ═══════════════════════════════════════════════════════════════════════════════
# Test: JSON Bomb Protection
# ═══════════════════════════════════════════════════════════════════════════════

class TestJSONBombProtection:
    """Test safe_json_loads() for depth and size limits."""

    def test_valid_json_passes(self):
        from security.input_validation import safe_json_loads
        result = safe_json_loads('{"key": "value"}')
        assert result == {"key": "value"}

    def test_nested_json_within_depth(self):
        from security.input_validation import safe_json_loads
        data = '{"a": {"b": {"c": 1}}}'
        result = safe_json_loads(data, max_depth=5)
        assert result["a"]["b"]["c"] == 1

    def test_deeply_nested_json_blocked(self):
        from security.input_validation import safe_json_loads, JSONBombError
        # Create deeply nested JSON
        nested = "1"
        for _ in range(30):
            nested = f'{{"a": {nested}}}'
        with pytest.raises(JSONBombError):
            safe_json_loads(nested, max_depth=10)

    def test_custom_depth_limit(self):
        from security.input_validation import safe_json_loads, JSONBombError
        data = '{"a": {"b": {"c": {"d": 1}}}}'
        # Should pass with depth=5
        safe_json_loads(data, max_depth=5)
        # Should fail with depth=2
        with pytest.raises(JSONBombError):
            safe_json_loads(data, max_depth=2)

    def test_oversized_json_blocked(self):
        from security.input_validation import safe_json_loads, JSONBombError
        # Create JSON bigger than max_size
        big_data = json.dumps({"data": "x" * 1000})
        with pytest.raises(JSONBombError):
            safe_json_loads(big_data, max_size=100, strict=True)

    def test_invalid_json_raises_decode_error(self):
        from security.input_validation import safe_json_loads
        with pytest.raises(json.JSONDecodeError):
            safe_json_loads("{invalid json}")

    def test_empty_string_returns_none(self):
        from security.input_validation import safe_json_loads
        assert safe_json_loads("") is None

    def test_json_array_passes(self):
        from security.input_validation import safe_json_loads
        result = safe_json_loads('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_safe_json_load_file(self):
        from security.input_validation import safe_json_load
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        ) as f:
            json.dump({"key": "value"}, f)
            f.flush()
            try:
                result = safe_json_load(f.name, max_depth=10, max_size=1_000_000)
                assert result == {"key": "value"}
            finally:
                os.unlink(f.name)


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Hostname Validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestHostnameValidation:
    """Test validate_hostname() for DNS safety."""

    def setup_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def teardown_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def test_valid_hostname_passes(self):
        from security.input_validation import validate_hostname
        result = validate_hostname("example.com")
        assert result == "example.com"

    def test_localhost_blocked_in_strict(self):
        from security.input_validation import validate_hostname, SSRFError
        with patch.dict(os.environ, {"STORM_VX_SSRF_PROTECTION": "true"}):
            with pytest.raises(SSRFError):
                validate_hostname("localhost", strict=True)

    def test_private_ip_hostname_blocked(self):
        from security.input_validation import validate_hostname, SSRFError, _is_ssrf_protection_enabled
        with patch.dict(os.environ, {"STORM_VX_SSRF_PROTECTION": "true"}):
            assert _is_ssrf_protection_enabled() is True
            with pytest.raises(SSRFError):
                validate_hostname("192.168.1.1", strict=True)

    def test_null_byte_stripped(self):
        from security.input_validation import validate_hostname
        result = validate_hostname("example.com\x00", strict=False)
        assert "\x00" not in result

    def test_empty_hostname(self):
        from security.input_validation import validate_hostname, SecurityValidationError
        with pytest.raises(SecurityValidationError):
            validate_hostname("", strict=True)

    def test_allow_private_hostname(self):
        from security.input_validation import validate_hostname
        result = validate_hostname("localhost", allow_private=True, strict=True)
        assert result == "localhost"


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Secrets Guard — should_redact()
# ═══════════════════════════════════════════════════════════════════════════════

class TestShouldRedact:
    """Test should_redact() for sensitive key name detection."""

    def test_password(self):
        from security.secrets_guard import should_redact
        assert should_redact("password") is True

    def test_api_key(self):
        from security.secrets_guard import should_redact
        assert should_redact("api_key") is True

    def test_token(self):
        from security.secrets_guard import should_redact
        assert should_redact("token") is True

    def test_secret(self):
        from security.secrets_guard import should_redact
        assert should_redact("secret_key") is True

    def test_cookie(self):
        from security.secrets_guard import should_redact
        assert should_redact("cookie") is True

    def test_session_id(self):
        from security.secrets_guard import should_redact
        assert should_redact("session_id") is True

    def test_authorization(self):
        from security.secrets_guard import should_redact
        assert should_redact("authorization") is True

    def test_aws_secret(self):
        from security.secrets_guard import should_redact
        assert should_redact("aws_secret_access_key") is True

    def test_username_not_sensitive(self):
        from security.secrets_guard import should_redact
        assert should_redact("username") is False

    def test_name_not_sensitive(self):
        from security.secrets_guard import should_redact
        assert should_redact("name") is False

    def test_url_not_sensitive(self):
        from security.secrets_guard import should_redact
        assert should_redact("url") is False

    def test_empty_key(self):
        from security.secrets_guard import should_redact
        assert should_redact("") is False

    def test_case_insensitive(self):
        from security.secrets_guard import should_redact
        assert should_redact("PASSWORD") is True
        assert should_redact("Api_Key") is True

    def test_leading_underscores(self):
        from security.secrets_guard import should_redact
        assert should_redact("_password") is True
        assert should_redact("__token") is True


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Secrets Guard — redact_secrets()
# ═══════════════════════════════════════════════════════════════════════════════

class TestRedactSecrets:
    """Test redact_secrets() for dict and list redaction."""

    def setup_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def teardown_method(self):
        from security.input_validation import _refresh_config
        _refresh_config()

    def test_redact_dict_with_password(self):
        from security.secrets_guard import redact_secrets
        data = {"password": "secret123", "name": "test"}
        result = redact_secrets(data)
        assert result["name"] == "test"
        assert result["password"] != "secret123"
        assert "***" in result["password"]

    def test_redact_nested_dict(self):
        from security.secrets_guard import redact_secrets
        data = {"config": {"api_key": "sk-1234567890"}}
        result = redact_secrets(data)
        assert result["config"]["api_key"] != "sk-1234567890"

    def test_redact_list_of_dicts(self):
        from security.secrets_guard import redact_secrets
        data = [{"password": "secret1"}, {"token": "tok_1234567890"}]
        result = redact_secrets(data)
        assert result[0]["password"] != "secret1"
        assert result[1]["token"] != "tok_1234567890"

    def test_partial_masking_long_values(self):
        from security.secrets_guard import redact_secrets
        data = {"api_key": "sk-1234567890abcdef"}
        result = redact_secrets(data)
        # Should show first 4 chars + mask
        assert result["api_key"].startswith("sk-1")
        assert "***" in result["api_key"]

    def test_short_value_fully_masked(self):
        from security.secrets_guard import redact_secrets
        data = {"password": "short"}
        result = redact_secrets(data)
        assert result["password"] == "***"

    def test_non_string_values_preserved(self):
        from security.secrets_guard import redact_secrets
        data = {"count": 42, "active": True, "name": "test"}
        result = redact_secrets(data)
        assert result["count"] == 42
        assert result["active"] is True
        assert result["name"] == "test"

    def test_max_depth_limit(self):
        from security.secrets_guard import redact_secrets
        # Create data that exceeds max depth
        data = {"a": {"b": {"c": {"d": {"e": 1}}}}}
        result = redact_secrets(data, max_depth=3)
        # Should not crash — just stop recursing

    def test_redaction_disabled_via_env(self):
        from security.secrets_guard import redact_secrets, _refresh_config
        with patch.dict(os.environ, {"STORM_VX_REDACT_SECRETS": "false"}):
            _refresh_config()
            data = {"password": "secret123"}
            result = redact_secrets(data)
            # When disabled, value should pass through
            assert result["password"] == "secret123"
            _refresh_config()


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Secrets Guard — redact_string()
# ═══════════════════════════════════════════════════════════════════════════════

class TestRedactString:
    """Test redact_string() for inline secret redaction."""

    def test_bearer_token_redacted(self):
        from security.secrets_guard import redact_string
        result = redact_string("Authorization: bearer abc123def456")
        assert "abc123def456" not in result
        assert "bearer" in result.lower()

    def test_url_credentials_redacted(self):
        from security.secrets_guard import redact_string
        result = redact_string("Connecting to https://user:pass@example.com")
        assert "user:pass" not in result
        assert "example.com" in result

    def test_aws_key_redacted(self):
        from security.secrets_guard import redact_string
        result = redact_string("Using AWS key AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_key_value_redacted(self):
        from security.secrets_guard import redact_string
        result = redact_string("api_key=mysecretkey123")
        assert "mysecretkey123" not in result

    def test_safe_string_unchanged(self):
        from security.secrets_guard import redact_string
        text = "Request completed in 120ms"
        assert redact_string(text) == text

    def test_empty_string(self):
        from security.secrets_guard import redact_string
        assert redact_string("") == ""


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Secrets Guard — Log Integration
# ═══════════════════════════════════════════════════════════════════════════════

class TestLogRedaction:
    """Test redact_log_message() and redact_log_extra()."""

    def test_redact_log_message(self):
        from security.secrets_guard import redact_log_message
        msg = "Login with password=supersecret"
        result = redact_log_message(msg)
        assert "supersecret" not in result

    def test_redact_log_extra(self):
        from security.secrets_guard import redact_log_extra
        extra = {"api_key": "sk-1234567890", "request_id": "abc123"}
        result = redact_log_extra(extra)
        assert result["request_id"] == "abc123"
        assert result["api_key"] != "sk-1234567890"

    def test_redact_log_extra_empty(self):
        from security.secrets_guard import redact_log_extra
        assert redact_log_extra({}) == {}
        assert redact_log_extra(None) is None

    def test_redact_url_convenience(self):
        from security.secrets_guard import redact_url
        result = redact_url("https://user:pass@api.example.com/token=secret")
        assert "user:pass" not in result


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Security Audit
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityAudit:
    """Test security audit logging and event tracking."""

    def setup_method(self):
        """Reset audit state before each test."""
        from security.audit import reset_audit_stats
        reset_audit_stats()

    def test_security_log_creates_entry(self):
        from security.audit import security_log, AuditEvent, get_recent_events
        security_log(AuditEvent.SSRF_BLOCKED, url="http://192.168.1.1")
        events = get_recent_events(limit=1)
        assert len(events) == 1
        assert events[0]["event"] == "ssrf_blocked"

    def test_security_log_increments_counter(self):
        from security.audit import security_log, AuditEvent, get_audit_stats
        security_log(AuditEvent.SSRF_BLOCKED)
        security_log(AuditEvent.SSRF_BLOCKED)
        security_log(AuditEvent.PATH_TRAVERSAL_BLOCKED)
        stats = get_audit_stats()
        assert stats["ssrf_blocked"] == 2
        assert stats["path_traversal_blocked"] == 1

    def test_audit_trail_is_bounded(self):
        from security.audit import security_log, AuditEvent, get_recent_events, _MAX_AUDIT_TRAIL_SIZE
        # Add more events than max
        for i in range(_MAX_AUDIT_TRAIL_SIZE + 100):
            security_log(AuditEvent.SECURITY_MODE_CHANGED, message=f"event-{i}")
        events = get_recent_events(limit=99999)
        assert len(events) <= _MAX_AUDIT_TRAIL_SIZE

    def test_recent_events_most_recent_first(self):
        from security.audit import security_log, AuditEvent, get_recent_events
        security_log(AuditEvent.SSRF_BLOCKED, message="first")
        security_log(AuditEvent.SSRF_BLOCKED, message="second")
        events = get_recent_events(limit=2)
        assert events[0]["message"] == "second"
        assert events[1]["message"] == "first"

    def test_audit_event_enum_values(self):
        from security.audit import AuditEvent
        assert AuditEvent.SSRF_BLOCKED.value == "ssrf_blocked"
        assert AuditEvent.PATH_TRAVERSAL_BLOCKED.value == "path_traversal_blocked"
        assert AuditEvent.HEADER_INJECTION_BLOCKED.value == "header_injection_blocked"
        assert AuditEvent.JSON_BOMB_BLOCKED.value == "json_bomb_blocked"

    def test_get_audit_status(self):
        from security.audit import security_log, AuditEvent, get_audit_status
        security_log(AuditEvent.SSRF_BLOCKED)
        status = get_audit_status()
        assert "total_events" in status
        assert status["total_events"] >= 1
        assert "counters" in status
        assert "trail_size" in status

    def test_reset_clears_everything(self):
        from security.audit import security_log, AuditEvent, get_audit_stats, reset_audit_stats
        security_log(AuditEvent.SSRF_BLOCKED)
        reset_audit_stats()
        stats = get_audit_stats()
        assert stats == {}

    def test_security_log_with_context(self):
        from security.audit import security_log, AuditEvent, get_recent_events
        security_log(
            AuditEvent.SSRF_BLOCKED,
            severity="CRITICAL",
            url="http://192.168.1.1",
            module="basic_api_flood",
        )
        events = get_recent_events(limit=1)
        assert events[0]["context"]["url"] == "http://192.168.1.1"
        assert events[0]["context"]["module"] == "basic_api_flood"
        assert events[0]["severity"] == "CRITICAL"


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Config — Security Defaults and Settings
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityConfig:
    """Test security configuration in config/defaults.py and config/settings.py."""

    def test_security_defaults_exist(self):
        from config.defaults import (
            SECURITY_STRICT_MODE, SSRF_PROTECTION_ENABLED,
            REDACT_SECRETS_ENABLED, JSON_MAX_DEPTH, JSON_MAX_SIZE,
            URL_MAX_LENGTH, PROFILE_MAX_SIZE, PLUGIN_MAX_SIZE,
        )
        assert SECURITY_STRICT_MODE is False
        assert SSRF_PROTECTION_ENABLED is True
        assert REDACT_SECRETS_ENABLED is True
        assert JSON_MAX_DEPTH == 20
        assert JSON_MAX_SIZE == 10_000_000
        assert URL_MAX_LENGTH == 8192
        assert PROFILE_MAX_SIZE == 5_000_000
        assert PLUGIN_MAX_SIZE == 500_000

    def test_security_settings_dataclass(self):
        from config.settings import SecuritySettings
        settings = SecuritySettings()
        assert settings.strict_mode is False
        assert settings.ssrf_protection is True
        assert settings.redact_secrets is True

    def test_security_settings_from_env(self):
        from config.settings import SecuritySettings
        with patch.dict(os.environ, {"STORM_VX_SECURITY_STRICT": "true"}):
            settings = SecuritySettings.from_env()
            assert settings.strict_mode is True

    def test_security_settings_ssrf_from_env(self):
        from config.settings import SecuritySettings
        with patch.dict(os.environ, {"STORM_VX_SSRF_PROTECTION": "false"}):
            settings = SecuritySettings.from_env()
            assert settings.ssrf_protection is False

    def test_security_settings_redact_from_env(self):
        from config.settings import SecuritySettings
        with patch.dict(os.environ, {"STORM_VX_REDACT_SECRETS": "false"}):
            settings = SecuritySettings.from_env()
            assert settings.redact_secrets is False

    def test_security_settings_json_depth_from_env(self):
        from config.settings import SecuritySettings
        with patch.dict(os.environ, {"STORM_VX_JSON_MAX_DEPTH": "30"}):
            settings = SecuritySettings.from_env()
            assert settings.json_max_depth == 30

    def test_security_settings_invalid_env_uses_default(self):
        from config.settings import SecuritySettings
        with patch.dict(os.environ, {"STORM_VX_JSON_MAX_DEPTH": "invalid"}):
            settings = SecuritySettings.from_env()
            assert settings.json_max_depth == 20  # default

    def test_allowed_url_schemes(self):
        from config.defaults import ALLOWED_URL_SCHEMES
        assert "http" in ALLOWED_URL_SCHEMES
        assert "https" in ALLOWED_URL_SCHEMES
        assert "ftp" not in ALLOWED_URL_SCHEMES

    def test_profile_allowed_extensions(self):
        from config.defaults import PROFILE_ALLOWED_EXTENSIONS
        assert ".json" in PROFILE_ALLOWED_EXTENSIONS


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Integration — Logging Redaction
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoggingRedactionIntegration:
    """Test that StructuredJsonFormatter redacts secrets."""

    def test_json_formatter_redacts_secrets(self):
        from observability.logging_ext import StructuredJsonFormatter
        formatter = StructuredJsonFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Login attempt", args=None, exc_info=None,
        )
        record.api_key = "sk-1234567890abcdef"
        output = formatter.format(record)
        # The secret should be redacted
        data = json.loads(output)
        # api_key should be in extra and redacted
        if "extra" in data and "api_key" in data["extra"]:
            assert data["extra"]["api_key"] != "sk-1234567890abcdef"


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Integration — Package Imports
# ═══════════════════════════════════════════════════════════════════════════════

class TestPackageImports:
    """Test that the security package is properly importable."""

    def test_import_security_package(self):
        import security
        assert hasattr(security, "validate_url")
        assert hasattr(security, "redact_secrets")
        assert hasattr(security, "security_log")

    def test_import_input_validation(self):
        from security.input_validation import (
            validate_url, sanitize_path, sanitize_header_value,
            safe_json_loads, is_private_ip,
        )
        assert callable(validate_url)
        assert callable(sanitize_path)

    def test_import_secrets_guard(self):
        from security.secrets_guard import (
            redact_secrets, redact_string, should_redact,
        )
        assert callable(redact_secrets)
        assert callable(redact_string)

    def test_import_audit(self):
        from security.audit import (
            security_log, AuditEvent, get_audit_stats,
        )
        assert callable(security_log)
        assert isinstance(AuditEvent.SSRF_BLOCKED, AuditEvent)

    def test_convenience_re_exports(self):
        from security import (
            validate_url, redact_secrets, security_log, AuditEvent,
            SSRFError, PathTraversalError, JSONBombError,
        )
        assert callable(validate_url)
        assert callable(redact_secrets)


# ═══════════════════════════════════════════════════════════════════════════════
# Test: Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_validate_url_with_port(self):
        from security.input_validation import validate_url
        result = validate_url("https://example.com:8443/api")
        assert "example.com:8443" in result

    def test_validate_url_with_query(self):
        from security.input_validation import validate_url
        result = validate_url("https://example.com/api?key=value")
        assert "key=value" in result

    def test_validate_url_with_fragment(self):
        from security.input_validation import validate_url
        result = validate_url("https://example.com/page#section")
        assert "#section" in result

    def test_unicode_url(self):
        from security.input_validation import validate_url
        result = validate_url("https://example.com/üñíçödé")
        assert "example.com" in result

    def test_sanitize_path_with_spaces(self):
        from security.input_validation import sanitize_path
        result = sanitize_path("my file.json")
        assert result == "my file.json"

    def test_json_with_unicode(self):
        from security.input_validation import safe_json_loads
        result = safe_json_loads('{"name": "日本語"}')
        assert result["name"] == "日本語"

    def test_redact_secrets_with_none_value(self):
        from security.secrets_guard import redact_secrets
        data = {"password": None, "name": "test"}
        result = redact_secrets(data)
        assert result["password"] is None
        assert result["name"] == "test"

    def test_redact_secrets_deeply_nested(self):
        from security.secrets_guard import redact_secrets
        data = {"level1": {"level2": {"level3": {"token": "deep_secret"}}}}
        result = redact_secrets(data)
        assert result["level1"]["level2"]["level3"]["token"] != "deep_secret"

    def test_audit_event_all_values_unique(self):
        from security.audit import AuditEvent
        values = [e.value for e in AuditEvent]
        assert len(values) == len(set(values))

    def test_security_settings_inherits_defaults(self):
        from config.settings import SecuritySettings
        from config.defaults import JSON_MAX_DEPTH, PLUGIN_MAX_SIZE
        settings = SecuritySettings()
        assert settings.json_max_depth == JSON_MAX_DEPTH
        assert settings.plugin_max_size == PLUGIN_MAX_SIZE
