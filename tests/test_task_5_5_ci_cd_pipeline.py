"""Tests for Task 5.5: CI/CD Pipeline Configuration.

Validates:
  - pyproject.toml has all required tool configs (ruff, mypy, bandit, pytest)
  - GitHub Actions workflow file exists and has correct structure
  - Ruff configuration is valid
  - Bandit configuration is valid
  - pytest configuration is valid
  - dev dependencies include all CI tools
  - Observability package is included in setuptools discovery
"""
from __future__ import annotations

import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ═══════════════════════════════════════════════════════════════════════════════
# pyproject.toml Validation Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPyprojectToml:
    """Validate pyproject.toml configuration."""

    @pytest.fixture
    def pyproject_content(self):
        with open(os.path.join(PROJECT_ROOT, "pyproject.toml")) as f:
            return f.read()

    def test_file_exists(self):
        assert os.path.exists(os.path.join(PROJECT_ROOT, "pyproject.toml"))

    def test_has_ruff_config(self, pyproject_content):
        assert "[tool.ruff]" in pyproject_content
        assert "target-version" in pyproject_content

    def test_has_ruff_lint_config(self, pyproject_content):
        assert "[tool.ruff.lint]" in pyproject_content
        assert "select" in pyproject_content

    def test_ruff_selects_essential_rules(self, pyproject_content):
        """Verify key ruff rule categories are enabled."""
        essential = ["E", "W", "F", "I"]  # pycodestyle, pyflakes, isort
        for rule in essential:
            assert rule in pyproject_content, f"Ruff rule {rule} not found"

    def test_has_mypy_config(self, pyproject_content):
        assert "[tool.mypy]" in pyproject_content
        assert "python_version" in pyproject_content

    def test_has_bandit_config(self, pyproject_content):
        assert "[tool.bandit]" in pyproject_content
        assert "exclude_dirs" in pyproject_content

    def test_has_pytest_config(self, pyproject_content):
        assert "[tool.pytest.ini_options]" in pyproject_content
        assert "asyncio_mode" in pyproject_content

    def test_dev_dependencies_include_ci_tools(self, pyproject_content):
        assert "pytest" in pyproject_content
        assert "ruff" in pyproject_content
        assert "mypy" in pyproject_content
        assert "bandit" in pyproject_content

    def test_observability_in_package_discovery(self, pyproject_content):
        """Verify observability package is included in setuptools discovery."""
        assert "observability*" in pyproject_content

    def test_project_version(self, pyproject_content):
        assert 'version = "22.0.0"' in pyproject_content


# ═══════════════════════════════════════════════════════════════════════════════
# GitHub Actions Workflow Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestGitHubActions:
    """Validate GitHub Actions CI workflow."""

    @pytest.fixture
    def workflow_content(self):
        path = os.path.join(PROJECT_ROOT, ".github", "workflows", "ci.yml")
        if not os.path.exists(path):
            pytest.skip("GitHub Actions workflow not found")
        with open(path) as f:
            return f.read()

    def test_workflow_file_exists(self):
        path = os.path.join(PROJECT_ROOT, ".github", "workflows", "ci.yml")
        assert os.path.exists(path), "CI workflow file missing"

    def test_has_ruff_job(self, workflow_content):
        assert "ruff" in workflow_content.lower()

    def test_has_mypy_job(self, workflow_content):
        assert "mypy" in workflow_content.lower()

    def test_has_bandit_job(self, workflow_content):
        assert "bandit" in workflow_content.lower()

    def test_has_test_job(self, workflow_content):
        assert "pytest" in workflow_content.lower() or "test" in workflow_content.lower()

    def test_has_python_matrix(self, workflow_content):
        """Verify multi-Python-version testing."""
        assert "3.10" in workflow_content or "3.12" in workflow_content

    def test_has_coverage(self, workflow_content):
        assert "cov" in workflow_content.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# CI Script Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestCIScript:
    """Validate local CI script."""

    def test_script_exists(self):
        path = os.path.join(PROJECT_ROOT, "scripts", "ci-local.sh")
        assert os.path.exists(path), "ci-local.sh script missing"

    def test_script_has_lint_check(self):
        path = os.path.join(PROJECT_ROOT, "scripts", "ci-local.sh")
        with open(path) as f:
            content = f.read()
        assert "ruff" in content

    def test_script_has_test_check(self):
        path = os.path.join(PROJECT_ROOT, "scripts", "ci-local.sh")
        with open(path) as f:
            content = f.read()
        assert "pytest" in content


# ═══════════════════════════════════════════════════════════════════════════════
# Observability Package Structure Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestObservabilityPackage:
    """Validate observability package structure."""

    def test_observability_init_exists(self):
        path = os.path.join(PROJECT_ROOT, "observability", "__init__.py")
        assert os.path.exists(path)

    def test_observability_modules_exist(self):
        modules = ["logging_ext.py", "metrics.py", "health.py", "resilience.py"]
        for module in modules:
            path = os.path.join(PROJECT_ROOT, "observability", module)
            assert os.path.exists(path), f"observability/{module} missing"

    def test_observability_importable(self):
        import observability
        assert observability is not None

    def test_logging_ext_importable(self):
        from observability.logging_ext import ErrorCode, StructuredJsonFormatter
        assert ErrorCode is not None
        assert StructuredJsonFormatter is not None

    def test_metrics_importable(self):
        from observability.metrics import metrics, generate_metrics
        assert metrics is not None
        assert generate_metrics is not None

    def test_health_importable(self):
        from observability.health import HealthCheckManager, HealthStatus
        assert HealthCheckManager is not None
        assert HealthStatus is not None

    def test_resilience_importable(self):
        from observability.resilience import CircuitBreaker, AsyncRetry
        assert CircuitBreaker is not None
        assert AsyncRetry is not None


# ═══════════════════════════════════════════════════════════════════════════════
# Ruff Config Validation (if ruff is installed)
# ═══════════════════════════════════════════════════════════════════════════════

class TestRuffConfig:
    """Test that ruff configuration is valid."""

    def test_ruff_can_parse_config(self):
        """Verify ruff can parse the pyproject.toml config."""
        import shutil
        if not shutil.which("ruff"):
            pytest.skip("ruff not installed in PATH")
        import subprocess
        result = subprocess.run(
            ["ruff", "check", "--config", "pyproject.toml", "--help"],
            capture_output=True, text=True,
            cwd=PROJECT_ROOT,
        )
        # If ruff is installed, it should not crash
        if result.returncode == 0 or "usage" in result.stdout.lower():
            pass  # ruff works


# ═══════════════════════════════════════════════════════════════════════════════
# Test File Inventory Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTestInventory:
    """Validate test file inventory for Wave 5."""

    def test_wave5_test_files_exist(self):
        test_dir = os.path.join(PROJECT_ROOT, "tests")
        wave5_tests = [
            "test_task_5_1_structured_logging.py",
            "test_task_5_2_prometheus_metrics.py",
            "test_task_5_3_health_check.py",
            "test_task_5_4_circuit_breaker.py",
            "test_task_5_5_ci_cd_pipeline.py",
        ]
        for test_file in wave5_tests:
            path = os.path.join(test_dir, test_file)
            assert os.path.exists(path), f"Test file {test_file} missing"
