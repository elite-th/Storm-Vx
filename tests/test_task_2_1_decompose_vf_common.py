#!/usr/bin/env python3
"""Tests for Task 2.1 Step 1 — Decompose vf_common.py: Extract random_helpers.

Validates:
  1. utils/random_helpers.py — canonical source works correctly
  2. vf_common.py — backward-compatible re-exports still work
  3. No circular imports
  4. Same behavior as original code
  5. Unused stdlib imports removed from vf_common
"""
from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Direct import from canonical source
# ═══════════════════════════════════════════════════════════════════════════════

class TestRandomHelpersDirect:
    """Verify utils/random_helpers.py works as standalone module."""

    def test_rand_str_default_length(self):
        from utils.random_helpers import rand_str
        result = rand_str()
        assert len(result) == 8

    def test_rand_str_custom_length(self):
        from utils.random_helpers import rand_str
        result = rand_str(16)
        assert len(result) == 16

    def test_rand_str_alphanumeric(self):
        from utils.random_helpers import rand_str
        result = rand_str(100)
        assert result.isalnum()

    def test_rand_str_lowercase(self):
        from utils.random_helpers import rand_str
        result = rand_str(100)
        assert result == result.lower()

    def test_rand_user_format(self):
        from utils.random_helpers import rand_user
        result = rand_user()
        assert '_' in result
        prefix, suffix = result.split('_', 1)
        assert prefix in ['user', 'admin', 'guest', 'test', 'member', 'demo', 'info', 'support']
        assert len(suffix) == 6

    def test_rand_pass_length_range(self):
        from utils.random_helpers import rand_pass
        for _ in range(50):
            result = rand_pass()
            assert 8 <= len(result) <= 16

    def test_rand_pass_has_special_chars(self):
        from utils.random_helpers import rand_pass
        # With 50 samples, very high probability of hitting special chars
        results = ''.join(rand_pass() for _ in range(50))
        has_special = any(c in '!@#$%' for c in results)
        assert has_special

    def test_rand_cache_bust_format(self):
        from utils.random_helpers import rand_cache_bust
        result = rand_cache_bust()
        assert result.startswith('_=')
        assert '&t=' in result
        # Timestamp should be reasonable (ms since epoch)
        ts_part = result.split('&t=')[1]
        ts = int(ts_part)
        assert ts > 1_000_000_000_000  # After 2001

    def test_secure_token_hex_string(self):
        from utils.random_helpers import secure_token
        result = secure_token()
        assert len(result) == 32  # 16 bytes = 32 hex chars
        assert all(c in '0123456789abcdef' for c in result)

    def test_secure_token_custom_length(self):
        from utils.random_helpers import secure_token
        result = secure_token(8)
        assert len(result) == 16  # 8 bytes = 16 hex chars

    def test_random_ua_returns_string(self):
        from utils.random_helpers import random_ua
        result = random_ua()
        assert isinstance(result, str)
        assert 'Mozilla' in result

    def test_random_ua_in_user_agents(self):
        from utils.random_helpers import random_ua, USER_AGENTS
        result = random_ua()
        assert result in USER_AGENTS

    def test_user_agents_count(self):
        from utils.random_helpers import USER_AGENTS
        assert len(USER_AGENTS) == 26

    def test_user_agents_all_strings(self):
        from utils.random_helpers import USER_AGENTS
        for ua in USER_AGENTS:
            assert isinstance(ua, str)
            assert len(ua) > 50


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Backward compatibility — vf_common re-exports
# ═══════════════════════════════════════════════════════════════════════════════

class TestVfCommonReExports:
    """Verify vf_common.py re-exports maintain backward compatibility."""

    def test_rand_str_via_vf_common(self):
        from vf_common import rand_str
        result = rand_str()
        assert len(result) == 8
        assert result.isalnum()

    def test_rand_user_via_vf_common(self):
        from vf_common import rand_user
        result = rand_user()
        assert '_' in result

    def test_rand_pass_via_vf_common(self):
        from vf_common import rand_pass
        result = rand_pass()
        assert 8 <= len(result) <= 16

    def test_rand_cache_bust_via_vf_common(self):
        from vf_common import rand_cache_bust
        result = rand_cache_bust()
        assert result.startswith('_=')

    def test_secure_token_via_vf_common(self):
        from vf_common import secure_token
        result = secure_token()
        assert len(result) == 32

    def test_random_ua_via_vf_common(self):
        from vf_common import random_ua
        result = random_ua()
        assert 'Mozilla' in result

    def test_user_agents_via_vf_common(self):
        from vf_common import USER_AGENTS
        assert len(USER_AGENTS) == 26

    def test_other_vf_common_imports_unaffected(self):
        """C, ssl_param, T, set_theme still work after extraction."""
        from vf_common import C, ssl_param, T, set_theme
        assert C.R  # ANSI code exists
        assert ssl_param(True) is None or ssl_param(True) is False
        assert isinstance(T("primary"), str)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. No circular imports
# ═══════════════════════════════════════════════════════════════════════════════

class TestNoCircularImports:
    """Verify no circular import chains were introduced."""

    def test_random_helpers_no_vf_common_import(self):
        """utils/random_helpers must NOT import from vf_common (code, not docs)."""
        source = (PROJECT_ROOT / "utils" / "random_helpers.py").read_text()
        # Parse AST and check imports only (not docstrings/comments)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert 'vf_common' not in alias.name, \
                        f"Circular import: random_helpers imports {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                assert 'vf_common' not in (node.module or ''), \
                    f"Circular import: random_helpers imports from {node.module}"

    def test_random_helpers_no_c_import(self):
        """utils/random_helpers must NOT import C or theme stuff."""
        source = (PROJECT_ROOT / "utils" / "random_helpers.py").read_text()
        assert "from vf_common import C" not in source
        assert "_Colors" not in source

    def test_random_helpers_deps_are_stdlib_only(self):
        """random_helpers should only depend on stdlib + logging_config."""
        source = (PROJECT_ROOT / "utils" / "random_helpers.py").read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name in ('random', 'secrets', 'string', 'time'), \
                        f"Unexpected import: {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                assert node.module in ('__future__', 'logging_config'), \
                    f"Unexpected from-import: {node.module}"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. vf_common.py cleanup — unused imports removed
# ═══════════════════════════════════════════════════════════════════════════════

class TestVfCommonCleanup:
    """Verify vf_common.py had unused imports removed after extraction."""

    def test_no_random_import(self):
        """random module should no longer be imported in vf_common."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        # Check the import section (first 30 lines)
        import_section = '\n'.join(source.split('\n')[:30])
        assert 'import random' not in import_section

    def test_no_secrets_import(self):
        """secrets module should no longer be imported in vf_common."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        import_section = '\n'.join(source.split('\n')[:30])
        assert 'import secrets' not in import_section

    def test_no_string_import(self):
        """string module should no longer be imported in vf_common."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        import_section = '\n'.join(source.split('\n')[:30])
        assert 'import string' not in import_section

    def test_time_not_used_in_vf_common(self):
        """time module should no longer be imported in vf_common."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        import_section = '\n'.join(source.split('\n')[:30])
        assert 'import time' not in import_section

    def test_re_export_present(self):
        """vf_common must have re-export from utils.random_helpers."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        assert "from utils.random_helpers import" in source
        assert "rand_str" in source  # At least one re-export

    def test_original_code_removed(self):
        """Original USER_AGENTS list and function definitions must be gone."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        # The original UA list had these exact strings
        assert 'Chrome/133.0.0.0 Safari/537.36",' not in source
        # The original function definitions should be gone
        # (re-exports use `from X import`, not `def`)
        lines = source.split('\n')
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('def rand_str') or stripped.startswith('def rand_pass'):
                if 'noqa' not in stripped:
                    pytest.fail(f"Original function definition still present: {stripped}")


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Behavioral equivalence — same output patterns
# ═══════════════════════════════════════════════════════════════════════════════

class TestBehavioralEquivalence:
    """Verify the extraction preserves exact behavior."""

    def test_rand_str_same_from_both_sources(self):
        """Both import paths should produce same-format output."""
        from utils.random_helpers import rand_str as direct
        from vf_common import rand_str as compat
        # Both should be 8-char alphanumeric lowercase
        d, c = direct(), compat()
        assert len(d) == len(c) == 8
        assert d.isalnum() and c.isalnum()

    def test_user_agents_same_object(self):
        """Both import paths should reference the same USER_AGENTS list."""
        from utils.random_helpers import USER_AGENTS as direct
        from vf_common import USER_AGENTS as compat
        assert direct is compat  # Same object due to re-export

    def test_rand_str_is_same_function(self):
        """Both import paths should reference the same function."""
        from utils.random_helpers import rand_str as direct
        from vf_common import rand_str as compat
        assert direct is compat  # Same function object due to re-export

    def test_rand_cache_bust_uniqueness(self):
        """Each call should produce a different cache-bust value."""
        from utils.random_helpers import rand_cache_bust
        results = {rand_cache_bust() for _ in range(10)}
        assert len(results) == 10  # All unique

    def test_secure_token_uniqueness(self):
        """Each secure_token call should produce different output."""
        from utils.random_helpers import secure_token
        results = {secure_token() for _ in range(10)}
        assert len(results) == 10
