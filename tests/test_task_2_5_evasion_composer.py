"""Tests for Task 2.5 Step 1 — Create EvasionComposer.

Verifies:
  - EvasionComposer implements EvasionProtocol
  - Consistent browser identity (no contradictory signals)
  - All EvasionProtocol methods work
  - ReferrerChainSpoofer delegation
  - WAF bypass headers
  - Path obfuscation and cache busting
  - Composition with existing evasion modules
"""
from __future__ import annotations

import pytest


class TestEvasionProtocolConformance:
    """EvasionComposer implements EvasionProtocol."""

    def test_satisfies_protocol(self):
        from evasion.composer import EvasionComposer, EvasionProtocol
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=True, enable_ua_rotation=True
        )
        assert isinstance(composer, EvasionProtocol)

    def test_has_all_protocol_methods(self):
        from evasion.composer import EvasionComposer
        required = ['request_headers', 'base_headers', 'update_cookies',
                     'get_cookies', 'set_waf', 'obfuscate_url', 'get_cache_busted_url']
        for method in required:
            assert hasattr(EvasionComposer, method), f"Missing method: {method}"


class TestConsistentBrowserIdentity:
    """W4.5 KEY IMPROVEMENT: All signals from the SAME profile."""

    def test_ua_matches_sec_ch_ua(self):
        """If UA is Chrome, Sec-CH-UA must be Chrome's. If Firefox, no Sec-CH-UA."""
        from evasion.composer import EvasionComposer, UNIFIED_BROWSER_PROFILES
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=False, enable_ua_rotation=False
        )
        headers = composer.request_headers("document")
        ua = headers.get("User-Agent", "")
        sec_ch_ua = headers.get("Sec-CH-UA")

        if "Firefox" in ua:
            assert sec_ch_ua is None, "Firefox should NOT have Sec-CH-UA"
        elif "Chrome" in ua or "Edg" in ua:
            assert sec_ch_ua is not None, "Chrome/Edge should have Sec-CH-UA"

    def test_accept_matches_ua(self):
        """Accept header should be consistent with the browser type."""
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=False, enable_ua_rotation=False
        )
        doc_headers = composer.request_headers("document")
        api_headers = composer.request_headers("api")
        # Document should have HTML accept, API should have JSON accept
        assert "text/html" in doc_headers.get("Accept", "")
        assert "application/json" in api_headers.get("Accept", "")

    def test_sec_fetch_consistent_with_request_type(self):
        """Sec-Fetch-Dest should match the request type."""
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=False, enable_ua_rotation=False
        )
        doc_headers = composer.request_headers("document")
        api_headers = composer.request_headers("api")
        res_headers = composer.request_headers("resource")

        assert doc_headers.get("Sec-Fetch-Dest") == "document"
        assert api_headers.get("Sec-Fetch-Dest") == "empty"
        assert res_headers.get("Sec-Fetch-Dest") in ("image", "style", "script")


class TestEvasionComposerMethods:
    """All EvasionProtocol methods work correctly."""

    def test_base_headers(self):
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=True, enable_ua_rotation=True
        )
        headers = composer.base_headers()
        assert "User-Agent" in headers
        assert "Accept" in headers
        assert "Sec-Fetch-Dest" in headers

    def test_request_headers_document(self):
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=True, enable_ua_rotation=True
        )
        headers = composer.request_headers("document")
        assert "User-Agent" in headers
        assert "Accept" in headers

    def test_request_headers_api(self):
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=True, enable_ua_rotation=True
        )
        headers = composer.request_headers("api")
        assert "Origin" in headers

    def test_request_headers_login(self):
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=True, enable_ua_rotation=True
        )
        headers = composer.request_headers("login")
        assert "Content-Type" in headers
        assert headers["Content-Type"] == "application/x-www-form-urlencoded"

    def test_update_and_get_cookies(self):
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=False, enable_ua_rotation=False
        )
        composer.update_cookies({"session": "abc123"})
        cookies = composer.get_cookies()
        assert cookies["session"] == "abc123"

    def test_set_waf(self):
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=True, enable_ua_rotation=True
        )
        composer.set_waf("cloudflare")
        # WAF bypass headers should now include Cloudflare-specific ones
        headers = composer.request_headers("document")
        # At least one of CF-Connecting-IP, X-Real-IP, CF-RAY should appear
        waf_keys = {"CF-Connecting-IP", "X-Real-IP", "CF-RAY"}
        assert bool(set(headers.keys()) & waf_keys)

    def test_obfuscate_url(self):
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=False, enable_ua_rotation=False
        )
        # Should return a valid URL (may or may not be obfuscated — 30% chance)
        result = composer.obfuscate_url("https://example.com/admin")
        assert result.startswith("https://")

    def test_cache_busted_url(self):
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=False, enable_ua_rotation=False
        )
        result = composer.get_cache_busted_url("https://example.com/page")
        assert "?" in result  # Should have added a query param

    def test_get_stats(self):
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=True, enable_ua_rotation=True
        )
        stats = composer.get_stats()
        assert "active" in stats
        assert "waf_name" in stats
        assert "current_profile" in stats


class TestUnifiedBrowserProfiles:
    """The unified profile database has no contradictory signals."""

    def test_all_profiles_have_ua(self):
        from evasion.composer import UNIFIED_BROWSER_PROFILES
        for profile in UNIFIED_BROWSER_PROFILES:
            assert "ua" in profile
            assert profile["ua"].startswith("Mozilla/5.0")

    def test_all_profiles_have_accept_headers(self):
        from evasion.composer import UNIFIED_BROWSER_PROFILES
        for profile in UNIFIED_BROWSER_PROFILES:
            assert "accept_html" in profile
            assert "accept_json" in profile
            assert "accept_img" in profile

    def test_chromium_profiles_have_sec_ch_ua(self):
        from evasion.composer import UNIFIED_BROWSER_PROFILES
        for profile in UNIFIED_BROWSER_PROFILES:
            ua = profile["ua"]
            if "Chrome" in ua or "Edg" in ua:
                assert profile.get("sec_ch_ua") is not None, \
                    f"Chromium profile {profile['name']} missing Sec-CH-UA"
            elif "Firefox" in ua or "Safari" in ua:
                assert profile.get("sec_ch_ua") is None, \
                    f"Non-Chromium profile {profile['name']} should not have Sec-CH-UA"

    def test_all_profiles_have_tls_hints(self):
        from evasion.composer import UNIFIED_BROWSER_PROFILES
        for profile in UNIFIED_BROWSER_PROFILES:
            assert "tls_version" in profile
            assert "alpn" in profile


class TestDeterministicComposition:
    """Same profile selection → same complete identity."""

    def test_same_profile_same_headers(self):
        from evasion.composer import EvasionComposer
        composer = EvasionComposer(
            domain="example.com", url="https://example.com",
            page_targets=[], resource_targets=[],
            enable_header_random=False, enable_ua_rotation=False
        )
        # With rotation disabled, profile[0] is always used
        h1 = composer.request_headers("document")
        h2 = composer.request_headers("document")
        assert h1["User-Agent"] == h2["User-Agent"]
        # Accept should also be the same
        assert h1["Accept"] == h2["Accept"]
