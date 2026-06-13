#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tester.response_classifier — HTTP response classification engine.

W4.2 EXTRACTION: Extracted from vf_attack_base.py for single responsibility.
All existing `from vf_attack_base import ResponseClass, ResponseClassifier` continues
to work via re-export facade. New code should import directly:
`from tester.response_classifier import ResponseClass, ResponseClassifier`.
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, Any


class ResponseClass(Enum):
    """Classification of an HTTP response for attack intelligence.

    This classification drives auto-tuning decisions:
    - WAF_BLOCKED → switch evasion strategy, add WAF bypass headers
    - NOT_FOUND → stop hitting this URL, probe others
    - AUTH_REQUIRED → good target (server processed the request)
    - RATE_LIMITED → back off, rotate fingerprint faster
    - SERVER_ERROR → server under stress, may be close to failing
    - OK → keep going, this endpoint is working
    - REDIRECT → follow or note the redirect target
    - CHALLENGE → WAF challenge page (Cloudflare JS challenge, etc.)
    """
    OK = "ok"
    REDIRECT = "redirect"
    NOT_FOUND = "not_found"
    AUTH_REQUIRED = "auth_required"
    RATE_LIMITED = "rate_limited"
    WAF_BLOCKED = "waf_blocked"
    CHALLENGE = "challenge"
    SERVER_ERROR = "server_error"
    CONNECTION_ERROR = "connection_error"


class ResponseClassifier:
    """v25 P1: Classifies HTTP responses for attack intelligence.

    Analyzes status codes, response headers, and body signatures
    to classify responses. This classification is used to:
    1. Auto-tune targeting (stop hitting 404s, focus on 200/302/401)
    2. Detect WAF blocking patterns and switch strategies
    3. Detect WAF challenge pages and extract cookies
    4. Feed back to evasion manager for adaptive bypass

    WAF Detection Signatures:
    - Cloudflare: CF-Ray header, __cfduid/cf_clearance cookies, 1020 status
    - ArvanCloud: ArvanCloud header, 403 with specific body
    - Sucuri: Sucuri/Cloudproxy header
    - ModSecurity: 403 with "ModSecurity" in body
    - Generic WAF: 403/503 with no server header + specific body patterns
    """

    # WAF signature patterns in response headers (header KEYS, not cookie names)
    WAF_HEADER_SIGNATURES = {
        "cloudflare": ["cf-ray", "cf-cache-status"],
        "arvancloud": ["arvancloud", "x-arvan"],
        "sucuri": ["sucuri", "cloudproxy", "x-sucuri-id"],
        "imperva": ["x-iinfo", "x-cdn"],
        "akamai": ["akamai", "x-akamai", "x-cache-akamai"],
        "fastly": ["fastly", "x-fastly"],
        "wordfence": ["x-wordfence"],
        "modsecurity": ["x-modsecurity"],  # "server" removed — too many false positives
    }

    # WAF cookie name signatures (checked against Set-Cookie header values)
    WAF_COOKIE_SIGNATURES = {
        "cloudflare": ["__cfduid", "cf_clearance", "cf_chl_rc"],
        "imperva": ["incap_ses", "visid_incap", "nlbi_"],
        "akamai": ["akamai_session"],
    }

    # WAF challenge page body signatures
    WAF_BODY_SIGNATURES = {
        "cloudflare": [
            "cf-browser-verification", "checking your browser",
            "cf-challenge", "ray id",
            "please wait while we check your browser",
        ],
        "arvancloud": [
            "arvancloud", "security check",
        ],
        "generic": [
            "access denied", "forbidden", "blocked",
            "security check", "please verify you are a human",
            "enable javascript", "checking your browser",
        ],
    }

    def __init__(self):
        self._detected_waf: str | None = None
        self._waf_confidence: int = 0  # Number of WAF signatures matched
        self._classification_counts: Dict[ResponseClass, int] = {}

    @property
    def detected_waf(self) -> str | None:
        """WAF name detected from responses (None if not detected)."""
        return self._detected_waf

    def classify(self, status_code: int, headers: Dict[str, str],
                 body_snippet: str = "") -> ResponseClass:
        """Classify an HTTP response.

        Args:
            status_code: HTTP status code
            headers: Response headers (lowercase keys preferred)
            body_snippet: First ~500 chars of response body for signature matching

        Returns:
            ResponseClass enum value
        """
        # Null-byte fix: strip \x00 from body_snippet to prevent
        # crashes on Windows when downstream code prints/logs this string.
        body_snippet = body_snippet.replace('\x00', '')

        # Normalize header keys to lowercase for matching
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # Detect WAF from headers (even if we already know the WAF)
        self._detect_waf_from_headers(lower_headers)

        # Classify by status code + WAF context
        if status_code == 0:
            result = ResponseClass.CONNECTION_ERROR
        elif status_code < 300:
            result = ResponseClass.OK
        elif status_code < 400:
            result = ResponseClass.REDIRECT
        elif status_code == 401 or status_code == 407:
            result = ResponseClass.AUTH_REQUIRED
        elif status_code == 403:
            # 403 could be WAF block or real auth denied
            # Check for WAF signatures
            if self._is_waf_block(lower_headers, body_snippet):
                result = ResponseClass.WAF_BLOCKED
            else:
                result = ResponseClass.AUTH_REQUIRED
        elif status_code == 404:
            result = ResponseClass.NOT_FOUND
        elif status_code == 429:
            result = ResponseClass.RATE_LIMITED
        elif status_code == 503:
            # 503 is often WAF challenge page
            if self._is_waf_challenge(lower_headers, body_snippet):
                result = ResponseClass.CHALLENGE
            else:
                result = ResponseClass.SERVER_ERROR
        elif status_code >= 500:
            result = ResponseClass.SERVER_ERROR
        elif status_code >= 400:
            # Other 4xx (400, 405, 406, 408, 409, 410, 411, 413, 415, etc.)
            # BUG-FIX v32: 405 Method Not Allowed means the endpoint EXISTS
            # but the HTTP method is not supported. Classifying it as NOT_FOUND
            # causes valid targets to be deprioritized by the TargetSelector.
            if status_code == 405:
                result = ResponseClass.AUTH_REQUIRED  # Endpoint exists, just wrong method
            else:
                result = ResponseClass.NOT_FOUND
        else:
            result = ResponseClass.OK

        # Track classification counts
        self._classification_counts[result] = self._classification_counts.get(result, 0) + 1

        return result

    def _detect_waf_from_headers(self, lower_headers: Dict[str, str]) -> None:
        """Detect WAF type from response headers and cookies.

        Called on every response to build WAF intelligence over time.
        Once a WAF is detected with high confidence, it's stored.

        v25 P1 fix: Also checks Set-Cookie header for WAF cookie signatures
        (e.g., __cfduid, cf_clearance, incap_ses are cookies, not headers).
        """
        # Check header key signatures — BUG-FIX: use substring match against all header keys
        # (e.g., "x-akamai" should match "x-akamai-session-info")
        for waf_name, signatures in self.WAF_HEADER_SIGNATURES.items():
            matches = sum(
                1 for sig in signatures
                if any(sig in key for key in lower_headers)
            )
            # v26 P2: Allow same-confidence overrides (allows WAF detection correction)
            if matches > 0 and matches > self._waf_confidence:
                self._detected_waf = waf_name
                self._waf_confidence = matches

        # Check Set-Cookie header values for WAF cookie name signatures
        set_cookie_val = lower_headers.get("set-cookie", "")
        if set_cookie_val:
            set_cookie_lower = set_cookie_val.lower()
            for waf_name, cookie_sigs in self.WAF_COOKIE_SIGNATURES.items():
                matches = sum(1 for sig in cookie_sigs if sig in set_cookie_lower)
                # Combine with existing confidence (headers + cookies)
                total_matches = matches + sum(
                    1 for sig in self.WAF_HEADER_SIGNATURES.get(waf_name, [])
                    if any(sig in key for key in lower_headers)
                )
                # v26 P2: Allow same-confidence overrides
                # Fix: require at least 1 match (0 >= 0 would falsely detect WAF)
                if total_matches > 0 and total_matches > self._waf_confidence:
                    self._detected_waf = waf_name
                    self._waf_confidence = total_matches

    def _is_waf_block(self, lower_headers: Dict[str, str],
                      body_snippet: str) -> bool:
        """Check if a 403 response is a WAF block (not real auth denial)."""
        # v26 P2: Check www-authenticate FIRST — it's the strongest signal for real auth.
        # A 403 with www-authenticate is always a real auth challenge, NOT a WAF block.
        if "www-authenticate" in lower_headers:
            return False
        # Cloudflare-specific 403
        if "cf-ray" in lower_headers:
            return True
        # ArvanCloud-specific 403
        if "arvancloud" in lower_headers or "x-arvan" in lower_headers:
            return True
        # Check for WAF-specific cookie signatures in Set-Cookie
        set_cookie_val = lower_headers.get("set-cookie", "")
        if set_cookie_val:
            set_cookie_lower = set_cookie_val.lower()
            for waf_name, cookie_sigs in self.WAF_COOKIE_SIGNATURES.items():
                if any(sig in set_cookie_lower for sig in cookie_sigs):
                    return True
        # Check body for WAF-specific signatures (NOT generic — "forbidden" is too common)
        body_lower = body_snippet.lower()[:500]
        for waf_name, sigs in self.WAF_BODY_SIGNATURES.items():
            if waf_name == "generic":
                continue  # Skip generic — too many false positives on normal 403s
            if any(sig in body_lower for sig in sigs):
                return True
        # No WAF-specific evidence found — assume real auth denied, not WAF
        return False

    def _is_waf_challenge(self, lower_headers: Dict[str, str],
                          body_snippet: str) -> bool:
        """Check if a 503 response is a WAF challenge page."""
        body_lower = body_snippet.lower()[:500]
        # Cloudflare challenge
        if "cf-ray" in lower_headers:
            return True
        if "checking your browser" in body_lower:
            return True
        if "cf-challenge" in body_lower or "cf-browser" in body_lower:
            return True
        # ArvanCloud challenge
        if "arvancloud" in lower_headers or "arvancloud" in body_lower:
            return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Return classification statistics."""
        return {
            "detected_waf": self._detected_waf,
            "waf_confidence": self._waf_confidence,
            "classifications": {cls.value: count for cls, count in self._classification_counts.items()},
        }


__all__ = ["ResponseClass", "ResponseClassifier"]
