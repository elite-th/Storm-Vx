"""Tests for Task 2.2 Step 1 — Extract ResponseClass + ResponseClassifier.

Verifies:
  - Re-export identity (same objects from both import paths)
  - Functional correctness of ResponseClassifier
  - Backward compatibility (9 plugins still import from vf_attack_base)
  - No circular imports
  - vf_attack_base line reduction
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestReExportIdentity:
    """Re-exported symbols are the same objects as canonical source."""

    def test_response_class_identity(self):
        from tester.vf_attack_base import ResponseClass
        from tester.response_classifier import ResponseClass as RC2
        assert ResponseClass is RC2

    def test_response_classifier_identity(self):
        from tester.vf_attack_base import ResponseClassifier
        from tester.response_classifier import ResponseClassifier as RCl2
        assert ResponseClassifier is RCl2


class TestResponseClassifierFunctional:
    """ResponseClassifier works correctly from new location."""

    def test_classify_ok(self):
        from tester.response_classifier import ResponseClass, ResponseClassifier
        clf = ResponseClassifier()
        assert clf.classify(200, {}) == ResponseClass.OK

    def test_classify_redirect(self):
        from tester.response_classifier import ResponseClass, ResponseClassifier
        clf = ResponseClassifier()
        assert clf.classify(301, {}) == ResponseClass.REDIRECT

    def test_classify_not_found(self):
        from tester.response_classifier import ResponseClass, ResponseClassifier
        clf = ResponseClassifier()
        assert clf.classify(404, {}) == ResponseClass.NOT_FOUND

    def test_classify_auth_required(self):
        from tester.response_classifier import ResponseClass, ResponseClassifier
        clf = ResponseClassifier()
        assert clf.classify(401, {}) == ResponseClass.AUTH_REQUIRED

    def test_classify_rate_limited(self):
        from tester.response_classifier import ResponseClass, ResponseClassifier
        clf = ResponseClassifier()
        assert clf.classify(429, {}) == ResponseClass.RATE_LIMITED

    def test_classify_waf_blocked_cloudflare(self):
        from tester.response_classifier import ResponseClass, ResponseClassifier
        clf = ResponseClassifier()
        result = clf.classify(403, {"cf-ray": "abc123"})
        assert result == ResponseClass.WAF_BLOCKED

    def test_classify_waf_challenge(self):
        from tester.response_classifier import ResponseClass, ResponseClassifier
        clf = ResponseClassifier()
        result = clf.classify(503, {"cf-ray": "abc"}, "checking your browser")
        assert result == ResponseClass.CHALLENGE

    def test_classify_connection_error(self):
        from tester.response_classifier import ResponseClass, ResponseClassifier
        clf = ResponseClassifier()
        assert clf.classify(0, {}) == ResponseClass.CONNECTION_ERROR

    def test_classify_server_error(self):
        from tester.response_classifier import ResponseClass, ResponseClassifier
        clf = ResponseClassifier()
        assert clf.classify(500, {}) == ResponseClass.SERVER_ERROR

    def test_classify_405_is_auth_required(self):
        """BUG-FIX v32: 405 should be AUTH_REQUIRED, not NOT_FOUND."""
        from tester.response_classifier import ResponseClass, ResponseClassifier
        clf = ResponseClassifier()
        assert clf.classify(405, {}) == ResponseClass.AUTH_REQUIRED

    def test_classify_403_with_www_authenticate_not_waf(self):
        """403 with www-authenticate is real auth, not WAF block."""
        from tester.response_classifier import ResponseClass, ResponseClassifier
        clf = ResponseClassifier()
        result = clf.classify(403, {"www-authenticate": "Basic realm=test"})
        assert result == ResponseClass.AUTH_REQUIRED

    def test_waf_detection_from_headers(self):
        from tester.response_classifier import ResponseClassifier
        clf = ResponseClassifier()
        clf.classify(200, {"cf-ray": "abc123"})
        assert clf.detected_waf == "cloudflare"

    def test_get_stats(self):
        from tester.response_classifier import ResponseClassifier
        clf = ResponseClassifier()
        clf.classify(200, {})
        stats = clf.get_stats()
        assert "detected_waf" in stats
        assert "classifications" in stats


class TestBackwardCompatibility:
    """Existing imports from vf_attack_base still work."""

    def test_import_response_class_from_vf_attack_base(self):
        from tester.vf_attack_base import ResponseClass
        assert ResponseClass.OK.value == "ok"

    def test_import_response_classifier_from_vf_attack_base(self):
        from tester.vf_attack_base import ResponseClassifier
        clf = ResponseClassifier()
        assert clf.classify(200, {}) is not None

    def test_attack_plugin_still_works(self):
        """AttackPlugin still creates ResponseClassifier internally."""
        from tester.vf_attack_base import AttackPlugin, ResponseClass
        # AttackPlugin is abstract, but we can check it's importable
        assert hasattr(AttackPlugin, '_worker_loop')


class TestNoCircularImports:
    """No circular import chains."""

    def test_response_classifier_no_vf_attack_base_import(self):
        """response_classifier.py should NOT import from vf_attack_base."""
        source = (PROJECT_ROOT / "tester" / "response_classifier.py").read_text()
        tree = ast.parse(source)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module != "vf_attack_base", \
                    "response_classifier.py should not import from vf_attack_base (circular!)"
                assert node.module != "tester.vf_attack_base", \
                    "response_classifier.py should not import from tester.vf_attack_base (circular!)"


class TestExtractionMetrics:
    """Verify the extraction metrics."""

    def test_response_classifier_file_exists(self):
        assert (PROJECT_ROOT / "tester" / "response_classifier.py").exists()

    def test_vf_attack_base_reduced(self):
        """vf_attack_base.py should be significantly smaller after extraction."""
        source = (PROJECT_ROOT / "tester" / "vf_attack_base.py").read_text()
        lines = len(source.splitlines())
        # Original was 1313 lines. After extracting ~240 lines of ResponseClassifier
        # it should be around 1070-1090.
        assert lines < 1200, f"vf_attack_base.py is {lines} lines — should be under 1200 after extraction"

    def test_response_class_enum_complete(self):
        """All 9 ResponseClass values are preserved."""
        from tester.response_classifier import ResponseClass
        values = {rc.value for rc in ResponseClass}
        expected = {"ok", "redirect", "not_found", "auth_required", "rate_limited",
                    "waf_blocked", "challenge", "server_error", "connection_error"}
        assert values == expected
