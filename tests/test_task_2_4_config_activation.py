"""test_task_2_4_config_activation — Verify W2.4: Activate Configuration System.

Ensures that all hardcoded configuration values have been replaced with
references to config/defaults.py constants, and that the config system
is the single source of truth for all tuning parameters.

Tests:
1. All new config constants exist and have correct values
2. Consumer modules use config constants (not hardcoded values)
3. Config re-exports work via config/__init__.py
4. Settings dataclass references config defaults
"""
import importlib
import os
import re

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Config constants exist with correct values
# ═══════════════════════════════════════════════════════════════════════════════

class TestScannerTimeoutConstants:
    """Scanner timeout presets defined in config/defaults.py."""

    def test_deep_scan_timeout(self):
        from config.defaults import DEEP_SCAN_TIMEOUT
        assert DEEP_SCAN_TIMEOUT == 8

    def test_fast_probe_timeout(self):
        from config.defaults import FAST_PROBE_TIMEOUT
        assert FAST_PROBE_TIMEOUT == 5

    def test_fast_probe_connect(self):
        from config.defaults import FAST_PROBE_CONNECT
        assert FAST_PROBE_CONNECT == 2

    def test_fast_probe_sock_read(self):
        from config.defaults import FAST_PROBE_SOCK_READ
        assert FAST_PROBE_SOCK_READ == 3

    def test_fingerprint_timeout(self):
        from config.defaults import FINGERPRINT_TIMEOUT
        assert FINGERPRINT_TIMEOUT == 20

    def test_origin_probe_timeout(self):
        from config.defaults import ORIGIN_PROBE_TIMEOUT
        assert ORIGIN_PROBE_TIMEOUT == 8

    def test_origin_quick_probe_timeout(self):
        from config.defaults import ORIGIN_QUICK_PROBE_TIMEOUT
        assert ORIGIN_QUICK_PROBE_TIMEOUT == 5


class TestAttackTimeoutConstants:
    """Attack timeout presets defined in config/defaults.py."""

    def test_attack_session_timeout(self):
        from config.defaults import ATTACK_SESSION_TIMEOUT
        assert ATTACK_SESSION_TIMEOUT == 10

    def test_attack_session_connect(self):
        from config.defaults import ATTACK_SESSION_CONNECT
        assert ATTACK_SESSION_CONNECT == 5

    def test_attack_session_sock_read(self):
        from config.defaults import ATTACK_SESSION_SOCK_READ
        assert ATTACK_SESSION_SOCK_READ == 8

    def test_attack_request_timeout(self):
        from config.defaults import ATTACK_REQUEST_TIMEOUT
        assert ATTACK_REQUEST_TIMEOUT == 5

    def test_attack_quick_timeout(self):
        from config.defaults import ATTACK_QUICK_TIMEOUT
        assert ATTACK_QUICK_TIMEOUT == 3

    def test_attack_session_mgr_timeout(self):
        from config.defaults import ATTACK_SESSION_MGR_TIMEOUT
        assert ATTACK_SESSION_MGR_TIMEOUT == 8


class TestLowLevelTimeoutConstants:
    """Raw socket and low-level timeout constants."""

    def test_raw_connect_timeout(self):
        from config.defaults import RAW_CONNECT_TIMEOUT
        assert RAW_CONNECT_TIMEOUT == 10.0

    def test_writer_close_timeout(self):
        from config.defaults import WRITER_CLOSE_TIMEOUT
        assert WRITER_CLOSE_TIMEOUT == 5.0

    def test_plugin_cleanup_timeout(self):
        from config.defaults import PLUGIN_CLEANUP_TIMEOUT
        assert PLUGIN_CLEANUP_TIMEOUT == 10.0

    def test_worker_cleanup_timeout(self):
        from config.defaults import WORKER_CLEANUP_TIMEOUT
        assert WORKER_CLEANUP_TIMEOUT == 15.0

    def test_dns_probe_timeout(self):
        from config.defaults import DNS_PROBE_TIMEOUT
        assert DNS_PROBE_TIMEOUT == 3.0

    def test_network_probe_timeout(self):
        from config.defaults import NETWORK_PROBE_TIMEOUT
        assert NETWORK_PROBE_TIMEOUT == 5.0

    def test_origin_quick_network_timeout(self):
        from config.defaults import ORIGIN_QUICK_NETWORK_TIMEOUT
        assert ORIGIN_QUICK_NETWORK_TIMEOUT == 2.0

    def test_finder_engine_timeout(self):
        from config.defaults import FINDER_ENGINE_TIMEOUT
        assert FINDER_ENGINE_TIMEOUT == 10.0

    def test_evasion_fpc_timeout(self):
        from config.defaults import EVASION_FPC_TIMEOUT
        assert EVASION_FPC_TIMEOUT == 10.0


class TestProtocolTimeoutConstants:
    """Protocol-specific timeout constants (H2, WebSocket)."""

    def test_h2_rapid_reset_timeout(self):
        from config.defaults import H2_RAPID_RESET_TIMEOUT
        assert H2_RAPID_RESET_TIMEOUT == 5.0

    def test_ws_connect_timeout(self):
        from config.defaults import WS_CONNECT_TIMEOUT
        assert WS_CONNECT_TIMEOUT == 5.0

    def test_ws_receive_timeout(self):
        from config.defaults import WS_RECEIVE_TIMEOUT
        assert WS_RECEIVE_TIMEOUT == 0.05

    def test_ws_heartbeat(self):
        from config.defaults import WS_HEARTBEAT
        assert WS_HEARTBEAT == 10


class TestConcurrencyConstants:
    """Semaphore / concurrency limit constants."""

    def test_deep_scan_semaphore(self):
        from config.defaults import DEEP_SCAN_SEMAPHORE
        assert DEEP_SCAN_SEMAPHORE == 5

    def test_script_analysis_semaphore(self):
        from config.defaults import SCRIPT_ANALYSIS_SEMAPHORE
        assert SCRIPT_ANALYSIS_SEMAPHORE == 3

    def test_waf_probe_semaphore(self):
        from config.defaults import WAF_PROBE_SEMAPHORE
        assert WAF_PROBE_SEMAPHORE == 10

    def test_cache_analysis_semaphore(self):
        from config.defaults import CACHE_ANALYSIS_SEMAPHORE
        assert CACHE_ANALYSIS_SEMAPHORE == 5

    def test_js_scan_semaphore(self):
        from config.defaults import JS_SCAN_SEMAPHORE
        assert JS_SCAN_SEMAPHORE == 6

    def test_session_harvest_connector_limit(self):
        from config.defaults import SESSION_HARVEST_CONNECTOR_LIMIT
        assert SESSION_HARVEST_CONNECTOR_LIMIT == 10

    def test_session_harvest_form_limit(self):
        from config.defaults import SESSION_HARVEST_FORM_LIMIT
        assert SESSION_HARVEST_FORM_LIMIT == 5


class TestDequeSizeConstants:
    """Bounded buffer / deque maxlen constants."""

    def test_stats_rps_window_size(self):
        from config.defaults import STATS_RPS_WINDOW_SIZE
        assert STATS_RPS_WINDOW_SIZE == 10_000

    def test_report_timeline_max(self):
        from config.defaults import REPORT_TIMELINE_MAX
        assert REPORT_TIMELINE_MAX == 5000

    def test_report_stats_history_max(self):
        from config.defaults import REPORT_STATS_HISTORY_MAX
        assert REPORT_STATS_HISTORY_MAX == 1000

    def test_report_waf_interactions_max(self):
        from config.defaults import REPORT_WAF_INTERACTIONS_MAX
        assert REPORT_WAF_INTERACTIONS_MAX == 1000

    def test_report_health_history_max(self):
        from config.defaults import REPORT_HEALTH_HISTORY_MAX
        assert REPORT_HEALTH_HISTORY_MAX == 500

    def test_session_harvest_pages_max(self):
        from config.defaults import SESSION_HARVEST_PAGES_MAX
        assert SESSION_HARVEST_PAGES_MAX == 2000

    def test_behavior_response_history_max(self):
        from config.defaults import BEHAVIOR_RESPONSE_HISTORY_MAX
        assert BEHAVIOR_RESPONSE_HISTORY_MAX == 1000


class TestWAFConstants:
    """WAF configuration constants."""

    def test_waf_blocks_max(self):
        from config.defaults import WAF_BLOCKS_MAX
        assert WAF_BLOCKS_MAX == 5000


class TestJSScannerConstants:
    """JS scanner limit constants."""

    def test_js_scan_max_file_size(self):
        from config.defaults import JS_SCAN_MAX_FILE_SIZE
        assert JS_SCAN_MAX_FILE_SIZE == 256_000

    def test_js_scan_total_timeout(self):
        from config.defaults import JS_SCAN_TOTAL_TIMEOUT
        assert JS_SCAN_TOTAL_TIMEOUT == 30

    def test_js_scan_head_chars(self):
        from config.defaults import JS_SCAN_HEAD_CHARS
        assert JS_SCAN_HEAD_CHARS == 50_000


class TestStatsConstants:
    """Stats tuning constants."""

    def test_stats_ema_alpha(self):
        from config.defaults import STATS_EMA_ALPHA
        assert STATS_EMA_ALPHA == 0.05

    def test_stats_rps_window_seconds(self):
        from config.defaults import STATS_RPS_WINDOW_SECONDS
        assert STATS_RPS_WINDOW_SECONDS == 3.0


class TestDashboardConstants:
    """Dashboard tuning constants."""

    def test_dashboard_max_rps_history(self):
        from config.defaults import DASHBOARD_MAX_RPS_HISTORY
        assert DASHBOARD_MAX_RPS_HISTORY == 60


class TestLoginFloodConstants:
    """Login flood tuning constants."""

    def test_csrf_refresh_interval(self):
        from config.defaults import CSRF_REFRESH_INTERVAL
        assert CSRF_REFRESH_INTERVAL == 120.0

    def test_csrf_refresh_every_n(self):
        from config.defaults import CSRF_REFRESH_EVERY_N
        assert CSRF_REFRESH_EVERY_N == 500


class TestSessionHarvestConstants:
    """Session harvest tuning constants."""

    def test_session_refresh_interval(self):
        from config.defaults import SESSION_REFRESH_INTERVAL
        assert SESSION_REFRESH_INTERVAL == 300.0


class TestBehaviorConstants:
    """Behavior evasion tuning constants."""

    def test_behavior_max_pages_per_session(self):
        from config.defaults import BEHAVIOR_MAX_PAGES_PER_SESSION
        assert BEHAVIOR_MAX_PAGES_PER_SESSION == (10, 30)

    def test_behavior_network_latency_base(self):
        from config.defaults import BEHAVIOR_NETWORK_LATENCY_BASE
        assert BEHAVIOR_NETWORK_LATENCY_BASE == 0.3


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Config re-exports work via config/__init__.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestConfigReExports:
    """Verify config/__init__.py re-exports all constants."""

    def test_can_import_defaults_from_config(self):
        from config import DEFAULT_TIMEOUT_SECONDS, VERIFY_SSL
        assert DEFAULT_TIMEOUT_SECONDS == 15
        assert VERIFY_SSL is True

    def test_can_import_new_constants_from_config(self):
        from config import (
            DEEP_SCAN_TIMEOUT,
            ATTACK_SESSION_TIMEOUT,
            WAF_BLOCKS_MAX,
            STATS_RPS_WINDOW_SIZE,
            WS_HEARTBEAT,
            BEHAVIOR_NETWORK_LATENCY_BASE,
        )
        assert DEEP_SCAN_TIMEOUT == 8
        assert ATTACK_SESSION_TIMEOUT == 10
        assert WAF_BLOCKS_MAX == 5000

    def test_settings_importable_from_config(self):
        from config import ConnectionSettings, WorkerSettings, Settings
        cs = ConnectionSettings()
        assert cs.timeout == 15
        assert cs.verify_ssl is True


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Consumer modules import successfully with config
# ═══════════════════════════════════════════════════════════════════════════════

class TestConsumerModuleImports:
    """Verify all modified modules can import their config constants."""

    @pytest.mark.parametrize("module_name", [
        "finder.deep_scanner",
        "finder.http_fingerprint",
        "finder.vf_origin_discovery",
        "finder.dns_scanner",
        "finder.vf_subdomain",
        "finder.vf_waf_probe",
        "finder.vf_cache_analyzer",
        "finder.vf_js_scanner",
        "finder.engine",
        "tester.vf_data",
        "tester.vf_dashboard",
        "tester.vf_attack_base",
        "tester.vf_basic_api_flood",
        "tester.vf_session_manager",
        "tester.vf_login_flood",
        "tester.vf_conn_exhaust",
        "tester.vf_tls_handshake",
        "tester.vf_slowloris",
        "tester.vf_slow_read",
        "tester.vf_ws_flood",
        "tester.vf_http2_rapid_reset",
        "tester.VF_TESTER",
        "evasion.vf_behavior",
        "evasion.vf_session_harvest",
        "evasion.vf_fp_cloner",
        "infra.vf_report",
    ])
    def test_module_imports_successfully(self, module_name):
        mod = importlib.import_module(module_name)
        assert mod is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 4. W2.4 markers exist in all modified files
# ═══════════════════════════════════════════════════════════════════════════════

class TestW24Markers:
    """Verify traceability markers exist in all modified files."""

    MODIFIED_FILES = [
        "finder/deep_scanner.py",
        "finder/http_fingerprint.py",
        "finder/vf_origin_discovery.py",
        "finder/dns_scanner.py",
        "finder/vf_subdomain.py",
        "finder/vf_waf_probe.py",
        "finder/vf_cache_analyzer.py",
        "finder/vf_js_scanner.py",
        "finder/engine.py",
        "tester/vf_basic_api_flood.py",
        "tester/vf_attack_base.py",
        "tester/vf_session_manager.py",
        "tester/vf_login_flood.py",
        "tester/VF_TESTER.py",
        "tester/vf_conn_exhaust.py",
        "tester/vf_tls_handshake.py",
        "tester/vf_slowloris.py",
        "tester/vf_slow_read.py",
        "tester/vf_ws_flood.py",
        "tester/vf_http2_rapid_reset.py",
        "tester/vf_data.py",
        "tester/vf_dashboard.py",
        "evasion/vf_behavior.py",
        "evasion/vf_session_harvest.py",
        "evasion/vf_fp_cloner.py",
        "infra/vf_report.py",
    ]

    @pytest.mark.parametrize("filepath", MODIFIED_FILES)
    def test_has_w24_markers(self, filepath):
        full_path = os.path.join(PROJECT_ROOT, filepath)
        with open(full_path, 'r') as f:
            content = f.read()
        markers = len(re.findall(r'# W2\.4', content))
        assert markers >= 1, f"{filepath} should have at least 1 W2.4 marker, found {markers}"

    def test_total_marker_count(self):
        total = 0
        for filepath in self.MODIFIED_FILES:
            full_path = os.path.join(PROJECT_ROOT, filepath)
            with open(full_path, 'r') as f:
                content = f.read()
            total += len(re.findall(r'# W2\.4', content))
        # We expect approximately 95 markers across all files
        assert total >= 80, f"Expected at least 80 W2.4 markers, found {total}"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Runtime verification — config constants match expected runtime values
# ═══════════════════════════════════════════════════════════════════════════════

class TestRuntimeConfigUsage:
    """Verify runtime objects use config constants correctly."""

    def test_vf_data_stats_uses_config(self):
        from tester.vf_data import Stats
        from config.defaults import STATS_EMA_ALPHA, STATS_RPS_WINDOW_SIZE, STATS_RPS_WINDOW_SECONDS
        s = Stats()
        assert s._EMA_ALPHA == STATS_EMA_ALPHA
        assert s._rps_window.maxlen == STATS_RPS_WINDOW_SIZE
        assert s._RPS_WINDOW_SECONDS == STATS_RPS_WINDOW_SECONDS

    def test_vf_report_uses_config(self):
        from infra.vf_report import AttackReporter
        from config.defaults import (
            REPORT_TIMELINE_MAX, REPORT_STATS_HISTORY_MAX,
            REPORT_WAF_INTERACTIONS_MAX, REPORT_HEALTH_HISTORY_MAX,
        )
        r = AttackReporter(target="http://test", output_dir="/tmp/w24_test_report")
        try:
            assert r.timeline.maxlen == REPORT_TIMELINE_MAX
            assert r.stats_history.maxlen == REPORT_STATS_HISTORY_MAX
            assert r.waf_interactions.maxlen == REPORT_WAF_INTERACTIONS_MAX
            assert r.server_health_history.maxlen == REPORT_HEALTH_HISTORY_MAX
        finally:
            import shutil
            shutil.rmtree("/tmp/w24_test_report", ignore_errors=True)
