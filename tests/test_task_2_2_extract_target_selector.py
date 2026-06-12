"""Tests for Task 2.2 Step 2 — Extract TargetSelector.

Verifies:
  - Re-export identity
  - Functional correctness of TargetSelector
  - Backward compatibility
  - No circular imports
  - Correct dependency on ResponseClass
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestReExportIdentity:
    def test_target_selector_identity(self):
        from tester.vf_attack_base import TargetSelector
        from tester.target_selector import TargetSelector as TS2
        assert TargetSelector is TS2


class TestTargetSelectorFunctional:
    def test_select_from_urls(self):
        from tester.target_selector import TargetSelector
        ts = TargetSelector(["http://a.com/p1", "http://a.com/p2"])
        url = ts.select()
        assert url in ["http://a.com/p1", "http://a.com/p2"]

    def test_dead_url_excluded(self):
        from tester.target_selector import TargetSelector
        from tester.response_classifier import ResponseClass
        ts = TargetSelector(["http://a.com/p1"])
        for _ in range(5):
            ts.record_result("http://a.com/p1", False, ResponseClass.NOT_FOUND)
        assert ts.dead_count == 1

    def test_emergency_revive(self):
        from tester.target_selector import TargetSelector
        from tester.response_classifier import ResponseClass
        ts = TargetSelector(["http://a.com/p1"])
        # Kill the URL
        for _ in range(5):
            ts.record_result("http://a.com/p1", False, ResponseClass.NOT_FOUND)
        assert ts.dead_count == 1
        # select() should trigger emergency revive
        url = ts.select()
        assert url is not None

    def test_discover_url(self):
        from tester.target_selector import TargetSelector
        ts = TargetSelector(["http://a.com/p1"])
        ts.discover_url("http://a.com/new")
        url = ts.select()
        assert url in ["http://a.com/p1", "http://a.com/new"]

    def test_success_increases_weight(self):
        from tester.target_selector import TargetSelector
        from tester.response_classifier import ResponseClass
        ts = TargetSelector(["http://a.com/p1"])
        initial_weight = ts._weights["http://a.com/p1"]
        ts.record_result("http://a.com/p1", True, ResponseClass.OK)
        assert ts._weights["http://a.com/p1"] > initial_weight

    def test_waf_block_decreases_weight(self):
        from tester.target_selector import TargetSelector
        from tester.response_classifier import ResponseClass
        ts = TargetSelector(["http://a.com/p1"])
        initial_weight = ts._weights["http://a.com/p1"]
        ts.record_result("http://a.com/p1", False, ResponseClass.WAF_BLOCKED)
        assert ts._weights["http://a.com/p1"] < initial_weight

    def test_get_stats(self):
        from tester.target_selector import TargetSelector
        ts = TargetSelector(["http://a.com/p1"])
        stats = ts.get_stats()
        assert "total_urls" in stats
        assert "alive_urls" in stats
        assert "dead_urls" in stats

    def test_empty_urls_returns_none(self):
        from tester.target_selector import TargetSelector
        ts = TargetSelector([])
        url = ts.select()
        assert url is None

    def test_deduplication(self):
        from tester.target_selector import TargetSelector
        ts = TargetSelector(["http://a.com/p1", "http://a.com/p1", "http://a.com/p2"])
        assert ts.get_stats()["total_urls"] == 2


class TestNoCircularImports:
    def test_target_selector_no_vf_attack_base_import(self):
        source = (PROJECT_ROOT / "tester" / "target_selector.py").read_text()
        tree = ast.parse(source)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module != "vf_attack_base"
                assert node.module != "tester.vf_attack_base"

    def test_target_selector_imports_response_classifier(self):
        """target_selector.py should import from tester.response_classifier."""
        source = (PROJECT_ROOT / "tester" / "target_selector.py").read_text()
        assert "from tester.response_classifier import" in source


class TestExtractionMetrics:
    def test_file_exists(self):
        assert (PROJECT_ROOT / "tester" / "target_selector.py").exists()

    def test_vf_attack_base_further_reduced(self):
        source = (PROJECT_ROOT / "tester" / "vf_attack_base.py").read_text()
        lines = len(source.splitlines())
        # Was ~1074 after Step 1. After extracting ~200 lines of TargetSelector,
        # should be around 870-890.
        assert lines < 950, f"vf_attack_base.py is {lines} lines — should be under 950"
