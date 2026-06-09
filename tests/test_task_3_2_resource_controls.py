#!/usr/bin/env python3
"""Tests for Task 3.2 — Add Response Body Size & Resource Controls.

Validates:
  1. utils/session_helpers.py — session/connector factory functions
  2. config/settings.py — ConnectionSettings aligned with defaults
  3. Finder modules — 3-way timeouts enforced
  4. vf_api_flood.py — attack_timeout usage
  5. No total-only ClientTimeout in scanner session creation
"""
from __future__ import annotations

import ast
import asyncio
import inspect
import textwrap
from pathlib import Path

import aiohttp
import pytest

# ═══════════════════════════════════════════════════════════════════════════════
# Project root for source file access
# ═══════════════════════════════════════════════════════════════════════════════

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ═══════════════════════════════════════════════════════════════════════════════
# 1. scanner_timeout() — 3-way timeout factory
# ═══════════════════════════════════════════════════════════════════════════════

class TestScannerTimeout:
    """Verify scanner_timeout() creates proper 3-way timeouts."""

    def test_default_timeout_has_three_phases(self):
        """Default scanner_timeout must have total, connect, sock_read."""
        from utils.session_helpers import scanner_timeout
        t = scanner_timeout()
        assert t.total == 15
        assert t.connect == 3
        assert t.sock_read == 10

    def test_custom_total_preserves_connect_sock_read(self):
        """Custom total should not override connect/sock_read defaults."""
        from utils.session_helpers import scanner_timeout
        t = scanner_timeout(total=8)
        assert t.total == 8
        assert t.connect == 3
        assert t.sock_read == 10

    def test_all_custom_values(self):
        """All three timeout phases should be customizable."""
        from utils.session_helpers import scanner_timeout
        t = scanner_timeout(total=20, connect=5, sock_read=15)
        assert t.total == 20
        assert t.connect == 5
        assert t.sock_read == 15

    def test_returns_client_timeout_instance(self):
        """Must return aiohttp.ClientTimeout."""
        from utils.session_helpers import scanner_timeout
        t = scanner_timeout()
        assert isinstance(t, aiohttp.ClientTimeout)

    def test_defaults_match_config(self):
        """Timeout defaults must match config/defaults.py constants."""
        from utils.session_helpers import scanner_timeout
        from config.defaults import (
            DEFAULT_TIMEOUT_SECONDS,
            DEFAULT_CONNECT_TIMEOUT_SECONDS,
            DEFAULT_READ_TIMEOUT_SECONDS,
        )
        t = scanner_timeout()
        assert t.total == DEFAULT_TIMEOUT_SECONDS
        assert t.connect == DEFAULT_CONNECT_TIMEOUT_SECONDS
        assert t.sock_read == DEFAULT_READ_TIMEOUT_SECONDS


# ═══════════════════════════════════════════════════════════════════════════════
# 2. fast_scanner_timeout()
# ═══════════════════════════════════════════════════════════════════════════════

class TestFastScannerTimeout:
    """Verify fast_scanner_timeout() for quick probes."""

    def test_fast_scanner_timeout_values(self):
        """Fast scanner should use aggressive short timeouts."""
        from utils.session_helpers import fast_scanner_timeout
        t = fast_scanner_timeout()
        assert t.total == 5
        assert t.connect == 3
        assert t.sock_read == 3

    def test_fast_scanner_is_3_way(self):
        """Must have connect and sock_read, not just total."""
        from utils.session_helpers import fast_scanner_timeout
        t = fast_scanner_timeout()
        assert t.connect is not None
        assert t.sock_read is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 3. attack_timeout()
# ═══════════════════════════════════════════════════════════════════════════════

class TestAttackTimeout:
    """Verify attack_timeout() for attack modules."""

    def test_default_attack_timeout(self):
        """Default attack timeout must match scanner timeout defaults."""
        from utils.session_helpers import attack_timeout
        t = attack_timeout()
        assert t.total == 15
        assert t.connect == 3
        assert t.sock_read == 10

    def test_custom_attack_timeout(self):
        """Attack timeout with custom values (e.g., vf_api_flood)."""
        from utils.session_helpers import attack_timeout
        t = attack_timeout(total=10, connect=5, sock_read=8)
        assert t.total == 10
        assert t.connect == 5
        assert t.sock_read == 8

    def test_attack_timeout_returns_client_timeout(self):
        """Must return aiohttp.ClientTimeout."""
        from utils.session_helpers import attack_timeout
        t = attack_timeout()
        assert isinstance(t, aiohttp.ClientTimeout)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. create_connector() — async tests (aiohttp needs event loop)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateConnector:
    """Verify create_connector() enforces resource limits."""

    @pytest.mark.asyncio
    async def test_default_connector_limits(self):
        """Default connector must use config limits."""
        from utils.session_helpers import create_connector
        from config.defaults import DEFAULT_CONNECTION_LIMIT
        conn = create_connector()
        try:
            assert conn.limit == min(DEFAULT_CONNECTION_LIMIT, 10_000)
        finally:
            await conn.close()

    @pytest.mark.asyncio
    async def test_custom_max_connections(self):
        """Custom max_connections must be respected (capped at 10000)."""
        from utils.session_helpers import create_connector
        conn = create_connector(max_connections=500)
        try:
            assert conn.limit == 500
        finally:
            await conn.close()

    @pytest.mark.asyncio
    async def test_max_connections_cap(self):
        """max_connections must be capped at 10000."""
        from utils.session_helpers import create_connector
        conn = create_connector(max_connections=50_000)
        try:
            assert conn.limit == 10_000
        finally:
            await conn.close()

    @pytest.mark.asyncio
    async def test_default_per_host_limit(self):
        """Default per_host_limit must be 0 (unlimited) for single-target."""
        from utils.session_helpers import create_connector
        conn = create_connector()
        try:
            assert conn.limit_per_host == 0
        finally:
            await conn.close()

    @pytest.mark.asyncio
    async def test_custom_per_host_limit(self):
        """Custom per_host_limit must be respected."""
        from utils.session_helpers import create_connector
        conn = create_connector(per_host_limit=100)
        try:
            assert conn.limit_per_host == 100
        finally:
            await conn.close()

    @pytest.mark.asyncio
    async def test_connector_is_tcp_connector(self):
        """Must return aiohttp.TCPConnector."""
        from utils.session_helpers import create_connector
        conn = create_connector()
        try:
            assert isinstance(conn, aiohttp.TCPConnector)
        finally:
            await conn.close()

    @pytest.mark.asyncio
    async def test_connector_dns_cache_enabled(self):
        """DNS cache must be enabled."""
        from utils.session_helpers import create_connector
        conn = create_connector()
        try:
            assert conn.use_dns_cache is True
        finally:
            await conn.close()

    @pytest.mark.asyncio
    async def test_connector_limits_match_config(self):
        """Connector limits must reference DEFAULT_* constants."""
        from utils.session_helpers import create_connector
        from config.defaults import (
            DEFAULT_CONNECTION_LIMIT,
            DEFAULT_PER_HOST_LIMIT,
        )
        conn = create_connector()
        try:
            assert conn.limit == min(DEFAULT_CONNECTION_LIMIT, 10_000)
            assert conn.limit_per_host == DEFAULT_PER_HOST_LIMIT
        finally:
            await conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# 5. create_session() — async tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateSession:
    """Verify create_session() creates properly configured sessions."""

    @pytest.mark.asyncio
    async def test_default_session_has_3_way_timeout(self):
        """Default session must have total, connect, sock_read timeouts."""
        from utils.session_helpers import create_session
        session = create_session()
        try:
            t = session.timeout
            assert t.total == 15
            assert t.connect == 3
            assert t.sock_read == 10
        finally:
            await session.close()

    @pytest.mark.asyncio
    async def test_custom_timeout_session(self):
        """Session with custom timeout must preserve 3-way config."""
        from utils.session_helpers import create_session, scanner_timeout
        session = create_session(timeout=scanner_timeout(total=8))
        try:
            t = session.timeout
            assert t.total == 8
            assert t.connect == 3
            assert t.sock_read == 10
        finally:
            await session.close()

    @pytest.mark.asyncio
    async def test_session_is_client_session(self):
        """Must return aiohttp.ClientSession."""
        from utils.session_helpers import create_session
        session = create_session()
        try:
            assert isinstance(session, aiohttp.ClientSession)
        finally:
            await session.close()

    @pytest.mark.asyncio
    async def test_session_with_unsafe_cookie_jar(self):
        """unsafe_cookie_jar=True must create CookieJar(unsafe=True)."""
        from utils.session_helpers import create_session
        session = create_session(unsafe_cookie_jar=True)
        try:
            assert isinstance(session.cookie_jar, aiohttp.CookieJar)
        finally:
            await session.close()

    @pytest.mark.asyncio
    async def test_session_connector_limits(self):
        """Auto-created connector must have proper limits."""
        from utils.session_helpers import create_session
        session = create_session(max_connections=500, per_host_limit=50)
        try:
            conn = session.connector
            assert conn.limit == 500
            assert conn.limit_per_host == 50
        finally:
            await session.close()

    @pytest.mark.asyncio
    async def test_connector_cap_is_10000(self):
        """Connector factory must cap at 10000 connections."""
        from utils.session_helpers import create_connector
        conn = create_connector(max_connections=999_999)
        try:
            assert conn.limit == 10_000
        finally:
            await conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# 6. config/settings.py — ConnectionSettings aligned with defaults
# ═══════════════════════════════════════════════════════════════════════════════

class TestConnectionSettingsFixed:
    """Verify ConnectionSettings now references defaults constants."""

    def test_connect_timeout_matches_defaults(self):
        """connect_timeout must be DEFAULT_CONNECT_TIMEOUT_SECONDS (3), not 5."""
        from config.settings import ConnectionSettings
        from config.defaults import DEFAULT_CONNECT_TIMEOUT_SECONDS
        cs = ConnectionSettings()
        assert cs.connect_timeout == DEFAULT_CONNECT_TIMEOUT_SECONDS
        assert cs.connect_timeout == 3  # Was incorrectly hardcoded to 5

    def test_read_timeout_matches_defaults(self):
        """read_timeout must be DEFAULT_READ_TIMEOUT_SECONDS (10), not 8."""
        from config.settings import ConnectionSettings
        from config.defaults import DEFAULT_READ_TIMEOUT_SECONDS
        cs = ConnectionSettings()
        assert cs.read_timeout == DEFAULT_READ_TIMEOUT_SECONDS
        assert cs.read_timeout == 10  # Was incorrectly hardcoded to 8

    def test_verify_ssl_matches_defaults(self):
        """verify_ssl must reference VERIFY_SSL constant, not hardcoded True."""
        from config.settings import ConnectionSettings
        from config.defaults import VERIFY_SSL
        cs = ConnectionSettings()
        assert cs.verify_ssl == VERIFY_SSL
        assert cs.verify_ssl is True

    def test_per_host_limit_exists(self):
        """per_host_limit field must exist and match DEFAULT_PER_HOST_LIMIT."""
        from config.settings import ConnectionSettings
        from config.defaults import DEFAULT_PER_HOST_LIMIT
        cs = ConnectionSettings()
        assert cs.per_host_limit == DEFAULT_PER_HOST_LIMIT
        assert cs.per_host_limit == 0  # Unlimited for single-target

    def test_connection_limit_matches_defaults(self):
        """connection_limit must reference DEFAULT_CONNECTION_LIMIT."""
        from config.settings import ConnectionSettings
        from config.defaults import DEFAULT_CONNECTION_LIMIT
        cs = ConnectionSettings()
        assert cs.connection_limit == DEFAULT_CONNECTION_LIMIT

    def test_timeout_matches_defaults(self):
        """timeout must reference DEFAULT_TIMEOUT_SECONDS."""
        from config.settings import ConnectionSettings
        from config.defaults import DEFAULT_TIMEOUT_SECONDS
        cs = ConnectionSettings()
        assert cs.timeout == DEFAULT_TIMEOUT_SECONDS


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Source code verification — no total-only ClientTimeout in scanner files
# ═══════════════════════════════════════════════════════════════════════════════

class TestSourceCodeThreeWayTimeouts:
    """Verify finder modules use scanner_timeout() instead of bare ClientTimeout(total=N)."""

    SCANNER_FILES = [
        "finder/deep_scanner.py",
        "finder/http_fingerprint.py",
        "finder/vf_waf_probe.py",
        "finder/vf_rate_probe.py",
        "finder/vf_js_scanner.py",
        "finder/vf_dir_fuzzer.py",
        "finder/vf_cache_analyzer.py",
    ]

    def _safe_read_source(self, filepath: str) -> str:
        """Read source code, stripping null bytes if present."""
        data = (PROJECT_ROOT / filepath).read_bytes()
        return data.replace(b"\x00", b"").decode("utf-8", errors="replace")

    def test_scanner_files_import_session_helpers(self):
        """All scanner files must import scanner_timeout from session_helpers."""
        for filepath in self.SCANNER_FILES:
            source = self._safe_read_source(filepath)
            assert "from utils.session_helpers import scanner_timeout" in source, \
                f"{filepath} missing import of scanner_timeout"

    def test_scanner_files_use_scanner_timeout(self):
        """All scanner files must use scanner_timeout() instead of bare ClientTimeout(total=...)."""
        for filepath in self.SCANNER_FILES:
            source = self._safe_read_source(filepath)
            try:
                tree = ast.parse(source)
            except SyntaxError:
                # If we can't parse, fall back to string search
                assert "scanner_timeout(" in source, \
                    f"{filepath} does not use scanner_timeout()"
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if (isinstance(node.func, ast.Attribute) and
                            node.func.attr == "ClientTimeout"):
                        kw_names = {kw.arg for kw in node.keywords}
                        has_connect = "connect" in kw_names
                        has_sock_read = "sock_read" in kw_names
                        if not has_connect and not has_sock_read:
                            pytest.fail(
                                f"{filepath} has total-only ClientTimeout at line {node.lineno}. "
                                f"Use scanner_timeout() instead."
                            )

    def test_api_flood_uses_attack_timeout(self):
        """vf_api_flood.py must use attack_timeout instead of bare ClientTimeout."""
        filepath = "tester/vf_api_flood.py"
        source = self._safe_read_source(filepath)
        assert "from utils.session_helpers import attack_timeout" in source, \
            "vf_api_flood.py missing import of attack_timeout"

    def test_api_flood_session_creation_uses_attack_timeout(self):
        """vf_api_flood.py session creation must use attack_timeout()."""
        filepath = "tester/vf_api_flood.py"
        source = self._safe_read_source(filepath)
        assert "attack_timeout(" in source, \
            "vf_api_flood.py must use attack_timeout() for session timeout"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Integration: session_helpers + ssl_helpers + config/defaults consistency
# ═══════════════════════════════════════════════════════════════════════════════

class TestResourceControlIntegration:
    """End-to-end consistency checks across resource control modules."""

    def test_defaults_per_host_limit_is_zero(self):
        """DEFAULT_PER_HOST_LIMIT must be 0 for single-target attack tool."""
        from config.defaults import DEFAULT_PER_HOST_LIMIT
        assert DEFAULT_PER_HOST_LIMIT == 0

    def test_defaults_verify_ssl_is_true(self):
        """VERIFY_SSL must be True by default for security."""
        from config.defaults import VERIFY_SSL
        assert VERIFY_SSL is True

    def test_connection_limit_is_reasonable(self):
        """DEFAULT_CONNECTION_LIMIT must be reasonable (100-10000)."""
        from config.defaults import DEFAULT_CONNECTION_LIMIT
        assert 100 <= DEFAULT_CONNECTION_LIMIT <= 10_000

    def test_all_timeout_constants_positive(self):
        """All timeout constants must be positive integers."""
        from config.defaults import (
            DEFAULT_TIMEOUT_SECONDS,
            DEFAULT_CONNECT_TIMEOUT_SECONDS,
            DEFAULT_READ_TIMEOUT_SECONDS,
            DEFAULT_KEEPALIVE_TIMEOUT,
        )
        assert DEFAULT_TIMEOUT_SECONDS > 0
        assert DEFAULT_CONNECT_TIMEOUT_SECONDS > 0
        assert DEFAULT_READ_TIMEOUT_SECONDS > 0
        assert DEFAULT_KEEPALIVE_TIMEOUT > 0

    def test_connect_less_than_total(self):
        """connect_timeout must be less than total timeout."""
        from config.defaults import (
            DEFAULT_TIMEOUT_SECONDS,
            DEFAULT_CONNECT_TIMEOUT_SECONDS,
        )
        assert DEFAULT_CONNECT_TIMEOUT_SECONDS < DEFAULT_TIMEOUT_SECONDS

    def test_read_less_than_total(self):
        """read_timeout must be less than total timeout."""
        from config.defaults import (
            DEFAULT_TIMEOUT_SECONDS,
            DEFAULT_READ_TIMEOUT_SECONDS,
        )
        assert DEFAULT_READ_TIMEOUT_SECONDS < DEFAULT_TIMEOUT_SECONDS

    def test_response_body_limits_exist(self):
        """Response body size limits must be defined and positive."""
        from config.defaults import MAX_RESPONSE_BODY_BYTES, MAX_JS_BODY_BYTES
        assert MAX_RESPONSE_BODY_BYTES > 0
        assert MAX_JS_BODY_BYTES > 0
        assert MAX_JS_BODY_BYTES > MAX_RESPONSE_BODY_BYTES  # JS bundles can be larger

    def test_session_helpers_module_exports(self):
        """session_helpers must export all key functions."""
        import utils.session_helpers as sh
        assert hasattr(sh, 'scanner_timeout')
        assert hasattr(sh, 'fast_scanner_timeout')
        assert hasattr(sh, 'attack_timeout')
        assert hasattr(sh, 'create_connector')
        assert hasattr(sh, 'create_session')

    def test_connection_settings_references_defaults_not_hardcodes(self):
        """ConnectionSettings must import from config.defaults, not hardcode."""
        import config.settings as settings_mod
        source = inspect.getsource(settings_mod)
        # The old hardcoded values should NOT appear in the dataclass
        # Check that connect_timeout is not hardcoded to 5
        lines = source.split('\n')
        for line in lines:
            if 'connect_timeout' in line and '=' in line and 'DEFAULT_' not in line:
                stripped = line.strip()
                # Allow comments but not actual assignments with hardcoded values
                if stripped.startswith('#') or stripped.startswith('"""'):
                    continue
                if 'connect_timeout: int = 5' in stripped:
                    pytest.fail(
                        "ConnectionSettings.connect_timeout is still hardcoded to 5 "
                        "instead of referencing DEFAULT_CONNECT_TIMEOUT_SECONDS"
                    )
            if 'read_timeout' in line and '=' in line and 'DEFAULT_' not in line:
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('"""'):
                    continue
                if 'read_timeout: int = 8' in stripped:
                    pytest.fail(
                        "ConnectionSettings.read_timeout is still hardcoded to 8 "
                        "instead of referencing DEFAULT_READ_TIMEOUT_SECONDS"
                    )
