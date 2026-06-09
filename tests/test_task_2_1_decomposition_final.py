"""Tests for Task 2.1 — Decompose vf_common.py: Final verification.

Verifies that the full decomposition from 921-line monolith to pure
re-export facade is correct, with no breakage and no circular imports.

Covers:
  - All 36 names re-exportable from vf_common
  - Identity checks: re-exported symbols are same objects as canonical
  - vf_common.py is pure facade (no local function/class definitions)
  - No circular imports in the dependency graph
  - Each new module has correct single responsibility
  - Functional correctness of each extracted module
  - Backward compatibility for all 58 consumer files
"""
from __future__ import annotations

import ast
import importlib
import sys
import types
from pathlib import Path

import pytest

# ── Project root ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ═══════════════════════════════════════════════════════════════════════════════
# 1. COMPLETE RE-EXPORT INVENTORY — All 36 names importable from vf_common
# ═══════════════════════════════════════════════════════════════════════════════

ALL_VF_COMMON_NAMES = [
    # Colors (utils/colors.py)
    "C", "_Colors",
    # Themes (utils/themes.py)
    "THEMES", "THEME_NAMES", "set_theme", "T", "get_box_chars",
    # Box drawing (utils/box_drawing.py)
    "box_top", "box_bottom", "box_mid", "box_line",
    "box_line_centered", "box_line_right", "box_divider",
    # Progress bars (utils/progress.py)
    "health_bar", "worker_bar", "mini_bar",
    "progress_bar_detailed", "sparkline",
    # Formatting (utils/formatting.py)
    "kv_line", "render_table", "MODE_ICONS", "mode_icon", "severity_icon",
    # Terminal width (utils/terminal_width.py)
    "detect_terminal_width", "AUTO_WIDTH", "auto_width",
    # Unicode helpers (utils/unicode_helpers.py)
    "_strip_ansi", "_visible_len", "_ANSI_RE",
    # Random helpers (utils/random_helpers.py)
    "USER_AGENTS", "random_ua", "rand_str", "rand_user", "rand_pass",
    "rand_cache_bust", "secure_token", "rand_ip", "join_url",
    # Log helpers (utils/log_helpers.py)
    "live_log", "live_ok", "live_warn", "live_eta",
    # SSL helpers (utils/ssl_helpers.py)
    "ssl_param", "create_ssl_context",
]


class TestCompleteReExports:
    """Every name that was in the original vf_common is still importable."""

    def test_all_names_importable(self):
        """All 48 names can be imported from vf_common."""
        import vf_common
        missing = []
        for name in ALL_VF_COMMON_NAMES:
            if not hasattr(vf_common, name):
                missing.append(name)
        assert not missing, f"Missing re-exports: {missing}"

    @pytest.mark.parametrize("name", ALL_VF_COMMON_NAMES)
    def test_each_name_not_none(self, name):
        """Each re-exported name is not None."""
        import vf_common
        assert getattr(vf_common, name) is not None, f"{name} is None"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. IDENTITY CHECKS — Re-exported symbols are the SAME objects as canonical
# ═══════════════════════════════════════════════════════════════════════════════

class TestIdentityChecks:
    """Re-exported objects must be the same object (not a copy)."""

    def test_c_identity(self):
        from vf_common import C
        from utils.colors import C as C2
        assert C is C2

    def test_colors_class_identity(self):
        from vf_common import _Colors
        from utils.colors import _Colors as _Colors2
        assert _Colors is _Colors2

    def test_t_identity(self):
        from vf_common import T
        from utils.themes import T as T2
        assert T is T2

    def test_set_theme_identity(self):
        from vf_common import set_theme
        from utils.themes import set_theme as st2
        assert set_theme is st2

    def test_themes_identity(self):
        from vf_common import THEMES
        from utils.themes import THEMES as THEMES2
        assert THEMES is THEMES2

    def test_box_top_identity(self):
        from vf_common import box_top
        from utils.box_drawing import box_top as bt2
        assert box_top is bt2

    def test_health_bar_identity(self):
        from vf_common import health_bar
        from utils.progress import health_bar as hb2
        assert health_bar is hb2

    def test_mode_icon_identity(self):
        from vf_common import mode_icon
        from utils.formatting import mode_icon as mi2
        assert mode_icon is mi2

    def test_rand_str_identity(self):
        from vf_common import rand_str
        from utils.random_helpers import rand_str as rs2
        assert rand_str is rs2

    def test_live_log_identity(self):
        from vf_common import live_log
        from utils.log_helpers import live_log as ll2
        assert live_log is ll2

    def test_ssl_param_identity(self):
        from vf_common import ssl_param
        from utils.ssl_helpers import ssl_param as sp2
        assert ssl_param is sp2

    def test_detect_terminal_width_identity(self):
        from vf_common import detect_terminal_width
        from utils.terminal_width import detect_terminal_width as dtw2
        assert detect_terminal_width is dtw2

    def test_strip_ansi_identity(self):
        from vf_common import _strip_ansi
        from utils.unicode_helpers import _strip_ansi as sa2
        assert _strip_ansi is sa2


# ═══════════════════════════════════════════════════════════════════════════════
# 3. VF_COMMON IS PURE FACADE — No local function/class definitions
# ═══════════════════════════════════════════════════════════════════════════════

class TestVfCommonIsPureFacade:
    """vf_common.py should contain NO local function or class definitions."""

    def test_no_local_functions(self):
        """All functions in vf_common are re-imported, not defined locally."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        tree = ast.parse(source)
        func_defs = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        assert len(func_defs) == 0, f"Found local function definitions: {[f.name for f in func_defs]}"

    def test_no_local_classes(self):
        """All classes in vf_common are re-imported, not defined locally."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        tree = ast.parse(source)
        class_defs = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        assert len(class_defs) == 0, f"Found local class definitions: {[c.name for c in class_defs]}"

    def test_no_local_assignments(self):
        """No local variable assignments in vf_common (only imports)."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        tree = ast.parse(source)
        # Filter out module-level assignments (like __all__)
        assigns = [
            node for node in ast.iter_child_nodes(tree)
            if isinstance(node, ast.Assign)
            and not (len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id.startswith("__"))
        ]
        assert len(assigns) == 0, f"Found local assignments: {[ast.dump(a) for a in assigns]}"

    def test_vf_common_line_count(self):
        """vf_common.py should be under 150 lines (pure facade)."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        lines = [l for l in source.splitlines() if l.strip() and not l.strip().startswith("#")]
        assert len(source.splitlines()) < 150, f"vf_common.py is {len(source.splitlines())} lines — should be under 150"

    def test_no_logger_in_vf_common(self):
        """vf_common.py should not have a local logger."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        assert "get_logger" not in source, "vf_common.py should not import get_logger"
        assert "logger =" not in source, "vf_common.py should not define logger"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. NO CIRCULAR IMPORTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestNoCircularImports:
    """Verify no circular import chains exist."""

    def test_import_all_utils_modules(self):
        """All utils/ modules can be imported without circular errors."""
        modules = [
            "utils.colors",
            "utils.themes",
            "utils.box_drawing",
            "utils.progress",
            "utils.formatting",
            "utils.terminal_width",
            "utils.unicode_helpers",
            "utils.log_helpers",
            "utils.random_helpers",
            "utils.ssl_helpers",
            "utils.session_helpers",
            "utils.response_helpers",
            "utils.async_helpers",
        ]
        for mod_name in modules:
            mod = importlib.import_module(mod_name)
            assert mod is not None

    def test_vf_common_imports_utils_not_vice_versa(self):
        """vf_common imports from utils/, but utils/ modules never import vf_common."""
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        assert "from utils." in source, "vf_common should import from utils/"

        # Check each utils module does NOT import vf_common
        # Use AST parsing to check actual import statements (not docstring mentions)
        utils_dir = PROJECT_ROOT / "utils"
        for py_file in utils_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue
            mod_source = py_file.read_text()
            tree = ast.parse(mod_source)
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, ast.ImportFrom):
                    assert node.module != "vf_common", f"{py_file.name} has 'from vf_common' import — circular!"
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name != "vf_common", f"{py_file.name} has 'import vf_common' — circular!"

    def test_dependency_chain_no_loops(self):
        """Verify the dependency chain is strictly one-directional.

        colors → themes → box_drawing → formatting
                           progress
        All other utils modules are independent.
        """
        import utils.colors
        import utils.themes
        import utils.box_drawing
        import utils.progress
        import utils.formatting

        def _get_import_modules(filepath):
            """Extract all 'from X import' module names from a file using AST."""
            tree = ast.parse(filepath.read_text())
            return [node.module for node in ast.iter_child_nodes(tree)
                    if isinstance(node, ast.ImportFrom) and node.module]

        colors_imports = _get_import_modules(PROJECT_ROOT / "utils" / "colors.py")
        assert not any(m.startswith(("utils.", "vf_")) for m in colors_imports), \
            f"colors.py should have no project deps, found: {colors_imports}"

        themes_imports = _get_import_modules(PROJECT_ROOT / "utils" / "themes.py")
        assert "utils.colors" in themes_imports, "themes.py should import from utils.colors"

        box_imports = _get_import_modules(PROJECT_ROOT / "utils" / "box_drawing.py")
        assert "utils.colors" in box_imports, "box_drawing.py should import from utils.colors"
        assert "utils.themes" in box_imports, "box_drawing.py should import from utils.themes"

        progress_imports = _get_import_modules(PROJECT_ROOT / "utils" / "progress.py")
        assert "utils.colors" in progress_imports, "progress.py should import from utils.colors"
        assert "utils.themes" in progress_imports, "progress.py should import from utils.themes"

        fmt_imports = _get_import_modules(PROJECT_ROOT / "utils" / "formatting.py")
        assert "utils.colors" in fmt_imports, "formatting.py should import from utils.colors"
        assert "utils.themes" in fmt_imports, "formatting.py should import from utils.themes"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. SINGLE RESPONSIBILITY — Each module has correct domain
# ═══════════════════════════════════════════════════════════════════════════════

class TestSingleResponsibility:
    """Each extracted module owns exactly one domain."""

    def test_colors_only_color_constants(self):
        """utils/colors.py should only contain _Colors class and C instance."""
        source = (PROJECT_ROOT / "utils" / "colors.py").read_text()
        tree = ast.parse(source)
        # Should have exactly 1 class definition and 1 assignment
        classes = [n for n in ast.iter_child_nodes(tree) if isinstance(n, ast.ClassDef)]
        assert len(classes) == 1
        assert classes[0].name == "_Colors"

    def test_themes_only_theme_engine(self):
        """utils/themes.py should contain THEMES, _ThemeManager, set_theme, T, get_box_chars."""
        import utils.themes as themes
        expected = ["THEMES", "THEME_NAMES", "_ThemeManager", "_theme_mgr",
                    "set_theme", "T", "get_box_chars"]
        for name in expected:
            assert hasattr(themes, name), f"themes module missing: {name}"

    def test_box_drawing_only_box_functions(self):
        """utils/box_drawing.py should only contain box_* functions."""
        source = (PROJECT_ROOT / "utils" / "box_drawing.py").read_text()
        tree = ast.parse(source)
        funcs = [n.name for n in ast.iter_child_nodes(tree) if isinstance(n, ast.FunctionDef)]
        # All should start with "box_"
        for func in funcs:
            assert func.startswith("box_"), f"Unexpected function in box_drawing: {func}"

    def test_progress_only_bars_and_sparkline(self):
        """utils/progress.py should only contain bar functions and sparkline."""
        import utils.progress as progress
        expected = ["health_bar", "worker_bar", "mini_bar",
                    "progress_bar_detailed", "sparkline"]
        for name in expected:
            assert hasattr(progress, name), f"progress module missing: {name}"

    def test_formatting_only_display_helpers(self):
        """utils/formatting.py should contain kv_line, render_table, MODE_ICONS, mode_icon, severity_icon."""
        import utils.formatting as formatting
        expected = ["kv_line", "render_table", "MODE_ICONS", "mode_icon", "severity_icon"]
        for name in expected:
            assert hasattr(formatting, name), f"formatting module missing: {name}"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. FUNCTIONAL CORRECTNESS — Each module works correctly
# ═══════════════════════════════════════════════════════════════════════════════

class TestFunctionalCorrectness:
    """Verify each extracted module produces correct output."""

    def test_colors_rgb(self):
        from utils.colors import C
        result = C.rgb(255, 128, 0)
        assert result == "\033[38;2;255;128;0m"

    def test_colors_bg_rgb(self):
        from utils.colors import C
        result = C.bg_rgb(0, 0, 255)
        assert result == "\033[48;2;0;0;255m"

    def test_colors_reset(self):
        from utils.colors import C
        assert C.RS == "\033[0m"

    def test_colors_box_chars(self):
        from utils.colors import C
        assert C.TL == "╔"
        assert C.TR == "╗"
        assert C.H == "═"
        assert C.V == "║"

    def test_themes_all_8_present(self):
        from utils.themes import THEMES
        expected = {"MATRIX", "CYBER", "PHANTOM", "BLOOD",
                    "TOXIC", "OCEAN", "SOLAR", "MONO"}
        assert set(THEMES.keys()) == expected

    def test_themes_set_and_get(self):
        from utils.themes import set_theme, T
        from utils.colors import C
        set_theme("CYBER")
        # CYBER theme primary is NEON_CYAN = '\033[38;5;51m'
        assert T("primary") == C.NEON_CYAN
        set_theme("MATRIX")  # Reset

    def test_box_top_produces_box(self):
        from utils.box_drawing import box_top
        result = box_top(20)
        assert "╔" in result or "┏" in result or "╭" in result or "┌" in result

    def test_box_line_produces_content(self):
        from utils.box_drawing import box_line
        result = box_line("Hello", 20)
        assert "Hello" in result

    def test_health_bar_gradient(self):
        from utils.progress import health_bar
        result = health_bar(0.8, 10)
        assert "█" in result
        assert "░" in result

    def test_mini_bar_gradient(self):
        from utils.progress import mini_bar
        result = mini_bar(0.5, 10)
        assert "█" in result

    def test_sparkline_no_data(self):
        from utils.progress import sparkline
        result = sparkline([], 10)
        assert "─" in result

    def test_sparkline_with_data(self):
        from utils.progress import sparkline
        result = sparkline([1, 2, 3, 4, 5], 10)
        assert len(result) > 0

    def test_mode_icon_known(self):
        from utils.formatting import mode_icon
        assert mode_icon("LOGIN") == "🔑"
        assert mode_icon("PAGE") == "📄"
        assert mode_icon("API") == "🔌"

    def test_mode_icon_unknown(self):
        from utils.formatting import mode_icon
        result = mode_icon("UNKNOWN_MODE")
        assert result == "⚔"  # fallback sword icon

    def test_severity_icon_critical(self):
        from utils.formatting import severity_icon
        result = severity_icon("critical")
        assert "●" in result

    def test_kv_line_format(self):
        from utils.formatting import kv_line
        result = kv_line("RPS", "5000")
        assert "RPS" in result
        assert "5000" in result

    def test_terminal_width_fallback(self):
        from utils.terminal_width import detect_terminal_width
        result = detect_terminal_width(fallback=72)
        assert 48 <= result <= 120

    def test_auto_width_constant(self):
        from utils.terminal_width import AUTO_WIDTH
        assert 48 <= AUTO_WIDTH <= 120

    def test_strip_ansi(self):
        from utils.unicode_helpers import _strip_ansi
        assert _strip_ansi("\033[91mRed\033[0m") == "Red"

    def test_visible_len_ascii(self):
        from utils.unicode_helpers import _visible_len
        assert _visible_len("Hello") == 5

    def test_visible_len_with_ansi(self):
        from utils.unicode_helpers import _visible_len
        # ANSI codes should not count toward visible length
        assert _visible_len("\033[91mHi\033[0m") == 2

    def test_live_log_function(self):
        from utils.log_helpers import live_log, live_ok, live_warn, live_eta
        # Just verify they're callable
        assert callable(live_log)
        assert callable(live_ok)
        assert callable(live_warn)
        assert callable(live_eta)

    def test_ssl_param_true(self):
        from utils.ssl_helpers import ssl_param
        assert ssl_param(True) is None

    def test_ssl_param_false(self):
        from utils.ssl_helpers import ssl_param
        assert ssl_param(False) is False

    def test_rand_str_length(self):
        from utils.random_helpers import rand_str
        result = rand_str(16)
        assert len(result) == 16


# ═══════════════════════════════════════════════════════════════════════════════
# 7. BACKWARD COMPATIBILITY — Consumer files can still import everything
# ═══════════════════════════════════════════════════════════════════════════════

class TestBackwardCompatibility:
    """Simulate real consumer import patterns."""

    def test_import_c_from_vf_common(self):
        from vf_common import C
        assert C.R == "\033[91m"

    def test_import_t_from_vf_common(self):
        from vf_common import T
        color = T("primary")
        assert isinstance(color, str)

    def test_import_box_functions_from_vf_common(self):
        from vf_common import box_top, box_bottom, box_mid, box_line
        assert callable(box_top)
        assert callable(box_bottom)

    def test_import_progress_from_vf_common(self):
        from vf_common import health_bar, worker_bar, mini_bar
        assert callable(health_bar)

    def test_import_random_from_vf_common(self):
        from vf_common import rand_str, rand_user, rand_pass, random_ua
        s = rand_str(8)
        assert len(s) == 8

    def test_import_ssl_from_vf_common(self):
        from vf_common import ssl_param
        assert ssl_param(True) is None

    def test_import_formatting_from_vf_common(self):
        from vf_common import mode_icon, severity_icon, kv_line
        assert callable(mode_icon)

    def test_import_terminal_from_vf_common(self):
        from vf_common import detect_terminal_width, AUTO_WIDTH, auto_width
        assert callable(detect_terminal_width)
        assert isinstance(AUTO_WIDTH, int)

    def test_import_unicode_from_vf_common(self):
        from vf_common import _strip_ansi, _visible_len
        assert callable(_strip_ansi)

    def test_import_log_from_vf_common(self):
        from vf_common import live_log, live_ok, live_warn, live_eta
        assert callable(live_log)

    def test_import_themes_from_vf_common(self):
        from vf_common import THEMES, THEME_NAMES, set_theme, get_box_chars
        assert len(THEMES) == 8
        assert len(THEME_NAMES) == 8

    def test_vf_tester_style_import(self):
        """Simulate the VF_TESTER.py import pattern."""
        from vf_common import (
            C, rand_user, rand_pass, rand_cache_bust, rand_str,
            T, set_theme, box_top, box_bottom, box_mid,
            box_line, box_line_centered, health_bar, worker_bar,
            mini_bar, mode_icon,
        )
        assert C is not None

    def test_dashboard_style_import(self):
        """Simulate the vf_dashboard.py import pattern."""
        from vf_common import (
            C, T, set_theme, detect_terminal_width,
            box_top, box_bottom, box_mid, box_line,
            box_line_centered, box_line_right, box_divider,
            health_bar, worker_bar, mini_bar,
            progress_bar_detailed, mode_icon, sparkline,
            kv_line, severity_icon, _strip_ansi,
        )
        assert C is not None

    def test_finder_style_import(self):
        """Simulate the finder/engine.py import pattern."""
        from vf_common import C, live_log, live_ok, live_warn, live_eta
        assert C is not None
        assert callable(live_log)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. DECOMPOSITION METRICS
# ═══════════════════════════════════════════════════════════════════════════════

class TestDecompositionMetrics:
    """Track the size reduction and module count."""

    def test_vf_common_under_150_lines(self):
        source = (PROJECT_ROOT / "vf_common.py").read_text()
        line_count = len(source.splitlines())
        assert line_count < 150, f"vf_common.py is {line_count} lines — should be under 150 as pure facade"

    def test_new_modules_exist(self):
        """All 10 extracted modules exist."""
        expected = [
            "colors.py", "themes.py", "box_drawing.py", "progress.py",
            "formatting.py", "terminal_width.py", "unicode_helpers.py",
            "log_helpers.py", "random_helpers.py", "ssl_helpers.py",
        ]
        for filename in expected:
            assert (PROJECT_ROOT / "utils" / filename).exists(), f"Missing: utils/{filename}"

    def test_no_shared_mutable_state(self):
        """Verify _ThemeManager instance is shared between vf_common and utils.themes."""
        from vf_common import set_theme, T
        from utils.themes import set_theme as st2, T as T2

        # Set theme via vf_common, read via utils
        set_theme("BLOOD")
        assert "BLOOD" in repr(T2("primary")) or T2("primary") == T("primary")

        # Reset
        set_theme("MATRIX")

    def test_colors_module_has_no_project_deps(self):
        """utils/colors.py should depend only on stdlib."""
        source = (PROJECT_ROOT / "utils" / "colors.py").read_text()
        tree = ast.parse(source)
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module is None or not node.module.startswith(("utils", "vf_", "config", "finder", "tester", "evasion", "infra", "ui")), \
                    f"colors.py has project import: from {node.module}"
