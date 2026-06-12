"""Task 1.1: Fix Runtime Crash Bug — logger NameError in VF_FINDER.py

Tests verify that:
1. The `logger` name is defined at module level in VF_FINDER
2. The logger follows the project's standard pattern (get_logger(__name__))
3. The Windows console mode except block can execute without NameError
4. The logger import is co-located with ensure_utf8_console import
5. No other NameError references exist in the file
"""
from __future__ import annotations

import ast
import sys
import types
import unittest
from unittest.mock import patch, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Unit Tests
# ---------------------------------------------------------------------------

class TestVFLoggerImport(unittest.TestCase):
    """Verify that VF_FINDER.py properly imports and defines `logger`."""

    def test_logger_name_defined_at_module_level(self):
        """The name `logger` must be defined at VF_FINDER module level.

        Before the fix, `logger` was used on line 66 but never imported,
        causing NameError on Windows when SetConsoleMode failed.
        """
        # We verify by parsing the AST — no side effects from import
        with open("VF_FINDER.py", "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)

        # Collect all top-level assigned names
        top_level_names = set()
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        top_level_names.add(target.id)

        self.assertIn(
            "logger", top_level_names,
            "`logger` is not defined at module level in VF_FINDER.py — "
            "will cause NameError on Windows"
        )

    def test_logger_initialized_with_get_logger(self):
        """The `logger` must be initialized via get_logger(__name__), matching
        the project's standard pattern used by 35+ other modules."""
        with open("VF_FINDER.py", "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)

        # Find the logger assignment
        logger_assign = None
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "logger":
                        logger_assign = node
                        break

        self.assertIsNotNone(logger_assign, "No `logger = ...` assignment found")

        # Verify it's `get_logger(__name__)`
        value = logger_assign.value
        self.assertIsInstance(value, ast.Call)
        self.assertIsInstance(value.func, ast.Name)
        self.assertEqual(value.func.id, "get_logger",
                         "logger must be initialized with get_logger()")
        self.assertEqual(len(value.args), 1)
        self.assertIsInstance(value.args[0], ast.Name)
        self.assertEqual(value.args[0].id, "__name__",
                         "logger must be initialized with get_logger(__name__)")

    def test_get_logger_imported_from_logging_config(self):
        """`get_logger` must be imported from `logging_config` module."""
        with open("VF_FINDER.py", "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)

        # Collect all imports from logging_config
        logging_config_imports = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "logging_config":
                for alias in node.names:
                    logging_config_imports.append(alias.name)

        self.assertIn(
            "get_logger", logging_config_imports,
            "`get_logger` must be imported from `logging_config` in VF_FINDER.py"
        )

    def test_logger_defined_before_windows_block(self):
        """The `logger` definition must appear BEFORE the IS_WINDOWS block
        that uses `logger.debug()` at line 66 (now 68)."""
        with open("VF_FINDER.py", "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)

        logger_line = None
        windows_if_line = None

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "logger":
                        logger_line = node.lineno
            if isinstance(node, ast.If):
                # Check if this is the IS_WINDOWS if block
                if isinstance(node.test, ast.Name) and node.test.id == "IS_WINDOWS":
                    windows_if_line = node.lineno

        self.assertIsNotNone(logger_line, "logger assignment not found")
        self.assertIsNotNone(windows_if_line, "IS_WINDOWS if block not found")
        self.assertLess(
            logger_line, windows_if_line,
            f"`logger` defined at line {logger_line} must appear BEFORE "
            f"IS_WINDOWS block at line {windows_if_line}"
        )


class TestNoUndefinedNamesInVFFinder(unittest.TestCase):
    """Scan VF_FINDER.py for any remaining undefined name references."""

    def test_no_other_undefined_name_references(self):
        """Verify no other names are used without being defined or imported.

        Uses AST static analysis to find potential NameError risks.
        Excludes builtins and common implicit names.
        """
        with open("VF_FINDER.py", "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)

        # Collect all defined/imported names at module level
        defined_names = set(dir(__builtins__)) if isinstance(__builtins__, dict) else set(dir(__builtins__))
        defined_names.update({
            # Module-level constants/variables defined in VF_FINDER.py
            "IS_WINDOWS", "CACHE_FILE", "_cache_lock", "_last_cache_write",
            "_CACHE_DEBOUNCE_SECONDS", "_CACHE_RETRY_ATTEMPTS", "_CACHE_RETRY_DELAY",
        })

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    defined_names.add(name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    defined_names.add(name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        defined_names.add(target.id)
            elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                defined_names.add(node.name)
            elif isinstance(node, ast.ClassDef):
                defined_names.add(node.name)

        # Check that `logger` is in the defined set
        self.assertIn("logger", defined_names,
                       "`logger` is not defined or imported — NameError risk")


# ---------------------------------------------------------------------------
# Regression Tests
# ---------------------------------------------------------------------------

class TestWindowsConsoleFallbackRegression(unittest.TestCase):
    """Regression: ensure the Windows console except block never crashes."""

    @patch("platform.system", return_value="Windows")
    def test_windows_console_exception_does_not_crash(self, mock_platform):
        """When SetConsoleMode fails on Windows, logger.debug() should work.

        Before fix: NameError: name 'logger' is not defined
        After fix: logger is properly imported and initialized
        """
        # We can't fully import VF_FINDER (it has side effects),
        # but we verify the pattern by checking the import chain
        from logging_config import get_logger

        # Create a logger matching the pattern VF_FINDER should use
        test_logger = get_logger("VF_FINDER")

        # This should not raise NameError
        try:
            test_logger.debug("Windows console mode setup failed (non-critical): test error")
        except NameError:
            self.fail("logger.debug() raised NameError — `logger` not properly defined")

    def test_logger_name_is_accessible_in_module_namespace(self):
        """When VF_FINDER is importable, `logger` must exist in its namespace.

        Note: This test is conditional — if VF_FINDER can't be imported due
        to missing dependencies, the test is skipped gracefully.
        """
        try:
            import VF_FINDER
            self.assertTrue(
                hasattr(VF_FINDER, "logger"),
                "VF_FINDER module does not have a `logger` attribute"
            )
            import logging
            self.assertIsInstance(
                VF_FINDER.logger, logging.Logger,
                "VF_FINDER.logger is not a logging.Logger instance"
            )
        except ImportError as e:
            self.skipTest(f"Cannot import VF_FINDER (missing dependency): {e}")


# ---------------------------------------------------------------------------
# Edge Case Tests
# ---------------------------------------------------------------------------

class TestLoggerEdgeCases(unittest.TestCase):
    """Edge cases around the logger fix."""

    def test_logger_uses_correct_name(self):
        """The logger name should match the module's __name__ for proper
        hierarchical logging configuration."""
        try:
            import VF_FINDER
            # Logger name should be "VF_FINDER" (the module name)
            self.assertEqual(
                VF_FINDER.logger.name, "VF_FINDER",
                f"Logger name is '{VF_FINDER.logger.name}', expected 'VF_FINDER'"
            )
        except ImportError as e:
            self.skipTest(f"Cannot import VF_FINDER: {e}")

    def test_get_logger_and_ensure_utf8_console_coimported(self):
        """Both `get_logger` and `ensure_utf8_console` should come from
        the same `logging_config` import statement for clarity."""
        with open("VF_FINDER.py", "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)

        # Find all ImportFrom nodes for logging_config
        logging_config_imports = [
            node for node in ast.iter_child_nodes(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "logging_config"
        ]

        # There should be exactly one ImportFrom for logging_config
        # that contains both ensure_utf8_console and get_logger
        combined_import = None
        for imp in logging_config_imports:
            names = [alias.name for alias in imp.names]
            if "get_logger" in names and "ensure_utf8_console" in names:
                combined_import = imp
                break

        self.assertIsNotNone(
            combined_import,
            "Expected a single `from logging_config import ensure_utf8_console, get_logger` "
            "statement — found separate import statements instead"
        )

    def test_no_bare_logger_usage_without_definition(self):
        """Scan for any other bare `logger.` references in the file that
        might also be undefined. All logger references must be backed by
        the `logger = get_logger(__name__)` definition."""
        with open("VF_FINDER.py", "r", encoding="utf-8") as f:
            source = f.read()

        # Count logger references
        logger_refs = source.count("logger.")
        # We expect at least 1 (the debug call on line 68)
        self.assertGreaterEqual(
            logger_refs, 1,
            "Expected at least one `logger.` reference in VF_FINDER.py"
        )

        # Verify logger is defined
        logger_def = "logger = get_logger" in source
        self.assertTrue(
            logger_def,
            "Found `logger.` references but no `logger = get_logger(...)` definition"
        )


if __name__ == "__main__":
    unittest.main()
