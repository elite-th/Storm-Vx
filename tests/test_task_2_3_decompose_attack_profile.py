"""Tests for Task 2.3 — Decompose vf_attack_profile.py.

Verifies:
  - All builder modules exist and are importable
  - AttackProfileGenerator still works as orchestrator
  - Builder functions are pure (no self)
  - No circular imports
  - Backward compatibility with engine.py
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestBuilderModulesExist:
    """All builder modules should exist and be importable."""

    def test_strategy_module(self):
        from finder.profile_builders.strategy import determine_strategy, determine_strategy_reason

    def test_vectors_module(self):
        from finder.profile_builders.vectors import determine_vectors, determine_surgical_vectors, determine_all_vectors

    def test_config_module(self):
        from finder.profile_builders.config import determine_waf_strategy, determine_worker_config

    def test_targets_module(self):
        from finder.profile_builders.targets import determine_page_targets, determine_resource_targets

    def test_platform_configs_module(self):
        from finder.profile_builders.platform_configs import determine_wordpress_config

    def test_risk_module(self):
        from finder.profile_builders.risk import determine_risk_notes


class TestBuilderFunctionsArePure:
    """Builder functions should be standalone (no self dependency)."""

    def test_strategy_is_function(self):
        from finder.profile_builders.strategy import determine_strategy
        assert callable(determine_strategy)
        # Check it's not a method (no self parameter)
        import inspect
        sig = inspect.signature(determine_strategy)
        assert 'self' not in sig.parameters

    def test_vectors_is_function(self):
        from finder.profile_builders.vectors import determine_vectors
        assert callable(determine_vectors)
        import inspect
        sig = inspect.signature(determine_vectors)
        assert 'self' not in sig.parameters

    def test_surgical_vectors_returns_tuple(self):
        """determine_surgical_vectors should return (vectors, surgical_targets) tuple."""
        from finder.profile_builders.vectors import determine_surgical_vectors
        from finder.site_profile import SiteProfile
        p = SiteProfile('https://example.com')
        result = determine_surgical_vectors(p, '')
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], list)

    def test_config_functions_are_pure(self):
        import inspect
        from finder.profile_builders.config import (
            determine_waf_strategy, determine_worker_config,
            determine_surgical_worker_config, determine_all_worker_config,
            determine_request_config, determine_timing_config,
            determine_evasion_config,
        )
        for fn in [determine_waf_strategy, determine_worker_config,
                    determine_surgical_worker_config, determine_all_worker_config,
                    determine_request_config, determine_timing_config,
                    determine_evasion_config]:
            sig = inspect.signature(fn)
            assert 'self' not in sig.parameters, f"{fn.__name__} should not have self"

    def test_platform_config_functions_are_pure(self):
        import inspect
        from finder.profile_builders.platform_configs import (
            determine_aspnet_config, determine_php_config,
            determine_wordpress_config, determine_api_config,
            determine_edu_config, determine_spa_config,
        )
        for fn in [determine_aspnet_config, determine_php_config,
                    determine_wordpress_config, determine_api_config,
                    determine_edu_config, determine_spa_config]:
            sig = inspect.signature(fn)
            assert 'self' not in sig.parameters, f"{fn.__name__} should not have self"

    def test_targets_functions_are_pure(self):
        import inspect
        from finder.profile_builders.targets import determine_page_targets, determine_resource_targets
        for fn in [determine_page_targets, determine_resource_targets]:
            sig = inspect.signature(fn)
            assert 'self' not in sig.parameters, f"{fn.__name__} should not have self"

    def test_risk_function_is_pure(self):
        import inspect
        from finder.profile_builders.risk import determine_risk_notes
        sig = inspect.signature(determine_risk_notes)
        assert 'self' not in sig.parameters


class TestBackwardCompatibility:
    """AttackProfileGenerator still works as before."""

    def test_generator_importable(self):
        from finder.vf_attack_profile import AttackProfileGenerator
        assert AttackProfileGenerator is not None

    def test_generator_has_generate(self):
        from finder.vf_attack_profile import AttackProfileGenerator
        assert hasattr(AttackProfileGenerator, 'generate')

    def test_generator_has_surgical_analysis_attr(self):
        """engine.py reads generator._surgical_analysis via getattr."""
        from finder.vf_attack_profile import AttackProfileGenerator
        gen = AttackProfileGenerator.__new__(AttackProfileGenerator)
        # _surgical_analysis should be set during generate()
        # Just verify the attribute can be accessed via getattr
        result = getattr(gen, '_surgical_analysis', [])
        assert isinstance(result, list)

    def test_generate_returns_dict_with_expected_keys(self):
        from finder.vf_attack_profile import AttackProfileGenerator
        from finder.site_profile import SiteProfile
        p = SiteProfile('https://example.com')
        gen = AttackProfileGenerator(p, '', True)
        result = gen.generate()
        expected_keys = [
            "target_url", "recommended_strategy", "strategy_reason",
            "attack_vectors", "surgical_vectors", "surgical_analysis",
            "all_vectors", "waf_strategy", "worker_config",
            "surgical_worker_config", "all_worker_config", "request_config",
            "login_config", "page_targets", "resource_targets",
            "timing_config", "evasion_config", "asp_net_config",
            "php_config", "wordpress_config", "api_config",
            "spa_config", "edu_config", "risk_notes",
        ]
        for key in expected_keys:
            assert key in result, f"Missing key: {key}"

    def test_surgical_analysis_populated(self):
        """After generate(), _surgical_analysis should be set for engine.py."""
        from finder.vf_attack_profile import AttackProfileGenerator
        from finder.site_profile import SiteProfile
        p = SiteProfile('https://example.com')
        gen = AttackProfileGenerator(p, '', True)
        gen.generate()
        assert isinstance(gen._surgical_analysis, list)
        assert len(gen._surgical_analysis) > 0

    def test_surgical_analysis_matches_dict(self):
        """_surgical_analysis attr should match surgical_analysis in dict."""
        from finder.vf_attack_profile import AttackProfileGenerator
        from finder.site_profile import SiteProfile
        p = SiteProfile('https://example.com')
        gen = AttackProfileGenerator(p, '', True)
        result = gen.generate()
        assert gen._surgical_analysis == result["surgical_analysis"]

    def test_engine_compatible_getattr(self):
        """engine.py pattern: getattr(generator, '_surgical_analysis', [])."""
        from finder.vf_attack_profile import AttackProfileGenerator
        from finder.site_profile import SiteProfile
        p = SiteProfile('https://example.com')
        gen = AttackProfileGenerator(p, '', True)
        gen.generate()
        # Exact pattern used in engine.py
        surgical_analysis = getattr(gen, '_surgical_analysis', [])
        assert isinstance(surgical_analysis, list)


class TestNoCircularImports:
    """Builder modules should not import from vf_attack_profile."""

    def test_builders_no_circular_import(self):
        builders_dir = PROJECT_ROOT / "finder" / "profile_builders"
        for py_file in builders_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue
            source = py_file.read_text()
            tree = ast.parse(source)
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, ast.ImportFrom):
                    assert node.module != "finder.vf_attack_profile", \
                        f"{py_file.name} imports from vf_attack_profile — circular!"
                    assert node.module != "vf_attack_profile", \
                        f"{py_file.name} imports from vf_attack_profile — circular!"

    def test_vf_attack_profile_imports_builders(self):
        """vf_attack_profile.py should import from profile_builders."""
        source = (PROJECT_ROOT / "finder" / "vf_attack_profile.py").read_text()
        assert "finder.profile_builders" in source


class TestDecompositionMetrics:
    def test_vf_attack_profile_reduced(self):
        """vf_attack_profile.py should be significantly smaller."""
        source = (PROJECT_ROOT / "finder" / "vf_attack_profile.py").read_text()
        lines = len(source.splitlines())
        # Original: 913. After decomposition, should be mostly orchestration.
        assert lines < 500, f"vf_attack_profile.py is {lines} lines — should be under 500"

    def test_builder_directory_exists(self):
        assert (PROJECT_ROOT / "finder" / "profile_builders").is_dir()

    def test_builder_files_count(self):
        builders_dir = PROJECT_ROOT / "finder" / "profile_builders"
        py_files = list(builders_dir.glob("*.py"))
        # __init__.py + 6 builder modules = 7
        assert len(py_files) >= 7


class TestBuilderFunctionalCorrectness:
    """Verify builder functions produce correct output."""

    @pytest.fixture
    def profile(self):
        from finder.site_profile import SiteProfile
        p = SiteProfile('https://example.com')
        return p

    def test_determine_strategy_generic(self, profile):
        from finder.profile_builders.strategy import determine_strategy
        result = determine_strategy(profile)
        assert result == "GENERIC_FLOOD"

    def test_determine_strategy_waf(self, profile):
        from finder.profile_builders.strategy import determine_strategy
        profile.waf = "Cloudflare"
        result = determine_strategy(profile)
        assert result == "WAF_BYPASS_FOCUSED"

    def test_determine_strategy_edu(self, profile):
        from finder.profile_builders.strategy import determine_strategy
        profile.site_category = 'educational'
        result = determine_strategy(profile)
        assert result == "EDU_FOCUSED"

    def test_determine_strategy_edu_waf(self, profile):
        from finder.profile_builders.strategy import determine_strategy
        profile.site_category = 'educational'
        profile.waf = "Arvan"
        result = determine_strategy(profile)
        assert result == "EDU_WAF_HYBRID"

    def test_determine_waf_strategy_no_waf(self, profile):
        from finder.profile_builders.config import determine_waf_strategy
        result = determine_waf_strategy(profile)
        assert result == {"detected": False}

    def test_determine_waf_strategy_cloudflare(self, profile):
        from finder.profile_builders.config import determine_waf_strategy
        profile.waf = "Cloudflare"
        profile.waf_confidence = 0.95
        result = determine_waf_strategy(profile)
        assert result["detected"] is True
        assert "CFB_CHALLENGE_SOLVE" in result["bypass_methods"]

    def test_determine_risk_notes(self, profile):
        from finder.profile_builders.risk import determine_risk_notes
        result = determine_risk_notes(profile)
        assert isinstance(result, list)

    def test_determine_wordpress_config_not_wp(self, profile):
        from finder.profile_builders.platform_configs import determine_wordpress_config
        result = determine_wordpress_config(profile)
        assert result == {"enabled": False}

    def test_determine_wordpress_config_is_wp(self, profile):
        from finder.profile_builders.platform_configs import determine_wordpress_config
        profile.cms = "WordPress"
        result = determine_wordpress_config(profile)
        assert result["enabled"] is True
        assert "xmlrpc.php" in result["xmlrpc_url"]

    def test_determine_edu_config_not_edu(self, profile):
        from finder.profile_builders.platform_configs import determine_edu_config
        result = determine_edu_config(profile)
        assert result == {"enabled": False}

    def test_determine_edu_config_is_edu(self, profile):
        from finder.profile_builders.platform_configs import determine_edu_config
        profile.site_category = 'educational'
        result = determine_edu_config(profile)
        assert result["enabled"] is True
        assert "edu_endpoints" in result

    def test_determine_aspnet_config_no_viewstate(self, profile):
        from finder.profile_builders.platform_configs import determine_aspnet_config
        result = determine_aspnet_config(profile)
        assert result == {"enabled": False}

    def test_determine_spa_config_no_spa(self, profile):
        from finder.profile_builders.platform_configs import determine_spa_config
        result = determine_spa_config(profile)
        assert result == {"enabled": False}

    def test_determine_api_config_no_endpoints(self, profile):
        from finder.profile_builders.platform_configs import determine_api_config
        result = determine_api_config(profile)
        assert result == {"enabled": False}

    def test_determine_api_config_with_endpoints(self, profile):
        from finder.profile_builders.platform_configs import determine_api_config
        profile.api_endpoints = ["/api/v1/users"]
        result = determine_api_config(profile)
        assert result["enabled"] is True
        assert result["endpoints"] == ["/api/v1/users"]

    def test_determine_worker_config_defaults(self, profile):
        from finder.profile_builders.config import determine_worker_config
        profile.baseline_rt = 0.5  # Normal baseline so default config applies
        result = determine_worker_config(profile)
        assert result["initial_workers"] == 50
        assert result["max_workers"] == 10000
        assert result["ramp_strategy"] == "GRADUAL"

    def test_determine_worker_config_with_waf(self, profile):
        from finder.profile_builders.config import determine_worker_config
        profile.waf = "Cloudflare"
        profile.baseline_rt = 0.5  # Normal baseline so WAF-specific config applies
        result = determine_worker_config(profile)
        assert result["initial_workers"] == 10  # Cloudflare specific
        assert result["ramp_strategy"] == "SLOW_STEALTHY"

    def test_determine_surgical_worker_config(self, profile):
        from finder.profile_builders.config import determine_surgical_worker_config
        result = determine_surgical_worker_config(profile)
        assert result["ramp_strategy"] == "SURGICAL_PRECISE"

    def test_determine_all_worker_config(self, profile):
        from finder.profile_builders.config import determine_all_worker_config
        result = determine_all_worker_config(profile)
        assert result["ramp_strategy"] == "ALL_MAXIMUM"
        assert result["initial_workers"] == 200

    def test_determine_request_config(self, profile):
        from finder.profile_builders.config import determine_request_config
        result = determine_request_config(profile, verify_ssl=True)
        assert result["verify_ssl"] is True
        assert result["timeout"] == 20

    def test_determine_request_config_with_waf(self, profile):
        from finder.profile_builders.config import determine_request_config
        profile.waf = "Cloudflare"
        result = determine_request_config(profile)
        assert result["delay_between_requests_ms"] == 50

    def test_determine_evasion_config_no_waf(self, profile):
        from finder.profile_builders.config import determine_evasion_config
        result = determine_evasion_config(profile)
        assert result["proxy_rotation"] is False
        assert result["header_randomization"] is False

    def test_determine_evasion_config_cloudflare(self, profile):
        from finder.profile_builders.config import determine_evasion_config
        profile.waf = "Cloudflare"
        result = determine_evasion_config(profile)
        assert result["proxy_rotation"] is True
        assert result["header_randomization"] is True

    def test_determine_vectors_generic(self, profile):
        from finder.profile_builders.vectors import determine_vectors
        result = determine_vectors(profile, "GENERIC_FLOOD")
        assert "PAGE_FLOOD" in result
        assert "SLOWLORIS" in result

    def test_determine_all_vectors_unique(self, profile):
        from finder.profile_builders.vectors import determine_all_vectors
        result = determine_all_vectors(profile)
        assert len(result) == len(set(result)), "All vectors should be unique"

    def test_determine_page_targets_generic(self, profile):
        from finder.profile_builders.targets import determine_page_targets
        result = determine_page_targets(profile)
        assert isinstance(result, list)
        assert len(result) <= 50

    def test_determine_resource_targets_generic(self, profile):
        from finder.profile_builders.targets import determine_resource_targets
        result = determine_resource_targets(profile)
        assert isinstance(result, list)
        assert len(result) <= 30

    def test_determine_strategy_reason(self, profile):
        from finder.profile_builders.strategy import determine_strategy_reason
        result = determine_strategy_reason(profile)
        assert isinstance(result, str)
        assert len(result) > 0
