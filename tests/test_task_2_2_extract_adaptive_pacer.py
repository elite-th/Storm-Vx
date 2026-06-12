"""Tests for Task 2.2 Step 3 — Extract AdaptivePacer.

Verifies re-export identity, functional correctness, backward compat, no circular imports.
"""
from __future__ import annotations

import ast
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestReExportIdentity:
    def test_adaptive_pacer_identity(self):
        from tester.vf_attack_base import AdaptivePacer
        from tester.adaptive_pacer import AdaptivePacer as AP2
        assert AdaptivePacer is AP2


class TestAdaptivePacerFunctional:
    def test_base_delay(self):
        from tester.adaptive_pacer import AdaptivePacer
        pacer = AdaptivePacer(base_delay_ms=20.0)
        assert pacer.current_delay_ms >= 20.0

    def test_ok_response_no_slowdown(self):
        from tester.adaptive_pacer import AdaptivePacer
        from tester.response_classifier import ResponseClass
        pacer = AdaptivePacer(base_delay_ms=10.0)
        for _ in range(20):
            pacer.record_response(ResponseClass.OK)
        # Multiplier should be at or near 1.0 (no slowdown)
        assert pacer.get_stats()["current_multiplier"] <= 1.1

    def test_waf_block_increases_multiplier(self):
        from tester.adaptive_pacer import AdaptivePacer
        from tester.response_classifier import ResponseClass
        pacer = AdaptivePacer(base_delay_ms=10.0)
        for _ in range(20):
            pacer.record_response(ResponseClass.WAF_BLOCKED)
        # Multiplier should increase
        assert pacer.get_stats()["current_multiplier"] > 1.0

    def test_challenge_triggers_cooldown(self):
        from tester.adaptive_pacer import AdaptivePacer
        from tester.response_classifier import ResponseClass
        pacer = AdaptivePacer(base_delay_ms=10.0)
        pacer.record_response(ResponseClass.CHALLENGE)
        # Should be in challenge cooldown
        assert pacer.get_stats()["in_challenge_cooldown"] is True

    def test_rate_limited_response(self):
        from tester.adaptive_pacer import AdaptivePacer
        from tester.response_classifier import ResponseClass
        pacer = AdaptivePacer(base_delay_ms=10.0)
        for _ in range(20):
            pacer.record_response(ResponseClass.RATE_LIMITED)
        assert pacer.get_stats()["current_multiplier"] > 1.0

    def test_get_stats_keys(self):
        from tester.adaptive_pacer import AdaptivePacer
        pacer = AdaptivePacer()
        stats = pacer.get_stats()
        assert "base_delay_ms" in stats
        assert "current_multiplier" in stats
        assert "effective_delay_ms" in stats
        assert "in_challenge_cooldown" in stats

    def test_challenge_cooldown_expires(self):
        """Challenge cooldown should eventually expire."""
        from tester.adaptive_pacer import AdaptivePacer
        from tester.response_classifier import ResponseClass
        pacer = AdaptivePacer(base_delay_ms=10.0)
        pacer.record_response(ResponseClass.CHALLENGE)
        # Manually expire the cooldown
        pacer._waf_challenge_until = time.monotonic() - 1.0
        assert pacer.get_stats()["in_challenge_cooldown"] is False


class TestNoCircularImports:
    def test_adaptive_pacer_no_vf_attack_base_import(self):
        source = (PROJECT_ROOT / "tester" / "adaptive_pacer.py").read_text()
        tree = ast.parse(source)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module != "vf_attack_base"
                assert node.module != "tester.vf_attack_base"

    def test_adaptive_pacer_imports_response_classifier(self):
        source = (PROJECT_ROOT / "tester" / "adaptive_pacer.py").read_text()
        assert "from tester.response_classifier import" in source


class TestExtractionMetrics:
    def test_file_exists(self):
        assert (PROJECT_ROOT / "tester" / "adaptive_pacer.py").exists()

    def test_vf_attack_base_final_size(self):
        """vf_attack_base.py should now be much smaller after all 3 extractions."""
        source = (PROJECT_ROOT / "tester" / "vf_attack_base.py").read_text()
        lines = len(source.splitlines())
        # Original: 1313. After 3 extractions (~640 lines total removed),
        # should be around 670-700
        assert lines < 750, f"vf_attack_base.py is {lines} lines — should be under 750"

    def test_vf_attack_base_still_has_attack_plugin(self):
        """AttackPlugin class must still be defined in vf_attack_base.py."""
        source = (PROJECT_ROOT / "tester" / "vf_attack_base.py").read_text()
        assert "class AttackPlugin" in source
