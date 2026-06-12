"""Storm-Vx Default Configuration.

All magic numbers, default values, and tuning parameters in one place.
Change these values to tune behavior without modifying code.

W2.4 ACTIVATION: Every hardcoded value in the codebase now references
a constant defined here. No magic numbers remain in consumer modules.
"""
from __future__ import annotations
from typing import Dict, Any, Tuple


# ═══════════════════════════════════════════════════════════════════════════════
# UI Theme — v21
# ═══════════════════════════════════════════════════════════════════════════════

# Available themes: MATRIX, CYBER, PHANTOM, BLOOD, TOXIC, OCEAN, SOLAR, MONO
UI_THEME: str = "MATRIX"
DASHBOARD_WIDTH: int = 72  # v22: Wider default for sparklines & tables
DASHBOARD_AUTO_WIDTH: bool = True  # v22: Auto-detect terminal width


# ═══════════════════════════════════════════════════════════════════════════════
# Connection & Network Defaults
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT_SECONDS: int = 15
DEFAULT_CONNECT_TIMEOUT_SECONDS: int = 3
DEFAULT_READ_TIMEOUT_SECONDS: int = 5
DEFAULT_KEEPALIVE_TIMEOUT: int = 30  # v35: longer keepalive for better connection reuse
DEFAULT_DNS_CACHE_TTL: int = 120

# Phase 0: Default False — SSL verification causes massive false failures in attack mode. Use --verify-ssl CLI flag to enable.
VERIFY_SSL: bool = False

# Worker concurrency limits by strategy
# NOTE v35: These limits are now SOFT GUIDES only. The connection pool scales
# with max_workers (see VF_TESTER.py). These values are kept for documentation
# and potential future use as advisory caps.
STRATEGY_CONCURRENCY_LIMITS: Dict[str, int] = {
    "ALL": 500,
    "SURGICAL": 100,
    "STANDARD": 300,
    "WAF_BYPASS_FOCUSED": 300,
    "ASP_NET_FOCUSED": 300,
    "CONFERENCE_FOCUSED": 300,
}

# Connection pool defaults
DEFAULT_CONNECTION_LIMIT: int = 2000
DEFAULT_PER_HOST_LIMIT: int = 0  # 0 = unlimited

# Connection pool lifecycle (Phase 0) — see bottom of file for values
# NOTE: These were originally defined here with conservative values (100/300/600/60)
# but were redefined with attack-optimized values at the bottom of this file.
# Python uses the last definition, so the values at EOF are effective.


# ═══════════════════════════════════════════════════════════════════════════════
# Worker Defaults
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_INITIAL_WORKERS: int = 5
DEFAULT_MAX_WORKERS: int = 5000
DEFAULT_STEP: int = 50
DEFAULT_STEP_DURATION: int = 5
DEFAULT_REQUEST_DELAY_MS: int = 10

# Backoff configuration
BACKOFF_BASE_SECONDS: float = 0.01
BACKOFF_MAX_DELAY_SECONDS: float = 2.0
BACKOFF_MAX_FAILS: int = 5


# ═══════════════════════════════════════════════════════════════════════════════
# Scanner Defaults
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_SCAN_TIMEOUT_SECONDS: int = 20
DEFAULT_BASELINE_SAMPLE_COUNT: int = 5
DEFAULT_DEEP_SCAN_CONCURRENCY: int = 20
DEFAULT_RATE_PROBE_REQUESTS: int = 100
DEFAULT_JS_BUNDLE_TIMEOUT: int = 10

# Response body size limits (W1.10 — prevent memory exhaustion from large responses)
# 1MB default: large enough for any legitimate HTML/API response,
# small enough to prevent OOM from multi-GB responses.
MAX_RESPONSE_BODY_BYTES: int = 1_048_576  # 1 MiB
MAX_JS_BODY_BYTES: int = 5_242_880  # 5 MiB (JS bundles can be larger)


# ═══════════════════════════════════════════════════════════════════════════════
# Stats Defaults
# ═══════════════════════════════════════════════════════════════════════════════

STATS_MAX_RESPONSE_TIMES: int = 50000
STATS_MAX_RECENT_HITS: int = 5000
STATS_REALTIME_WINDOW_SECONDS: int = 5
DASHBOARD_MAX_LOG_LINES: int = 8


# ═══════════════════════════════════════════════════════════════════════════════
# Health Monitor Defaults
# ═══════════════════════════════════════════════════════════════════════════════

HEALTH_CHECK_INTERVAL: int = 3
HEALTH_WINDOW_SECONDS: int = 30
CRASH_MODE_5XX_THRESHOLD: float = 0.5
CRASH_MODE_TIMEOUT_THRESHOLD: float = 0.7


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Profile Defaults
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_MINIMAL_PROFILE: Dict[str, Any] = {
    "version": 1,
    "url": "",
    "waf": None,
    "cms": None,
    "site_category": "generic",
    "viewstate_present": False,
    "technologies": [],
}

DEFAULT_MINIMAL_ATTACK: Dict[str, Any] = {
    "recommended_strategy": "GENERIC_FLOOD",
    "attack_vectors": ["LOGIN_FLOOD", "PAGE_FLOOD", "RESOURCE_FLOOD"],
    "worker_config": {
        "initial_workers": 10,
        "max_workers": 10000,
        "step": 50,
        "step_duration": 5,
        "ramp_strategy": "GRADUAL",
    },
    "page_targets": [],
    "resource_targets": [],
    "waf_strategy": {"detected": False},
    "request_config": {"delay_between_requests_ms": 50},
    "evasion_config": {"rotate_user_agent": True, "cache_bust": True},
    "edu_config": {"enabled": False},
}

# Technology detection confidence thresholds
TECH_DETECTION_HEADER_WEIGHT: float = 0.4
TECH_DETECTION_HTML_WEIGHT: float = 0.25
TECH_DETECTION_COOKIE_WEIGHT: float = 0.3
TECH_DETECTION_META_WEIGHT: float = 0.5
TECH_DETECTION_SCRIPT_WEIGHT: float = 0.3
TECH_DETECTION_MIN_CONFIDENCE: float = 0.2


# ═══════════════════════════════════════════════════════════════════════════════
# C6: Dashboard Loop Thresholds
# ═══════════════════════════════════════════════════════════════════════════════

# Health thresholds for dynamic step sizing
DASHBOARD_HEALTH_FULL: float = 0.7       # health > this → full step
DASHBOARD_HEALTH_WARNING: float = 0.4    # health > this → step // 3
DASHBOARD_HEALTH_CRITICAL: float = 0.2   # health > this → step // 5

# Auto-shrink thresholds (v28: Redesigned for attack tool)
# OLD: Triggered on server 5xx = WRONG (5xx = attack working)
# NEW: Only trigger on CLIENT connectivity failure (timeouts)
AUTOSHRINK_FAIL_RATE: float = 0.80        # fail_rate > this + high timeout → shrink
AUTOSHRINK_TIMEOUT_RATE: float = 0.60     # timeout_rate > this + high fail → shrink (v28)
AUTOSHRINK_EXTREME_TIMEOUT: float = 0.60  # timeout_rate > this → remove 1/3 workers (v28)
AUTOSHRINK_EXTREME_FAIL: float = 0.80     # fail_rate > this + high timeout → shrink
AUTOSHRINK_HIGH_TIMEOUT: float = 0.45     # timeout_rate > this → remove 1/4 workers (v28)
AUTOSHRINK_HIGH_FAIL: float = 0.65        # fail_rate > this → remove 1/4 workers
AUTOSHRINK_MODERATE_TIMEOUT: float = 0.30 # timeout_rate > this → remove 1/5 workers (v28)
AUTOSHRINK_MODERATE_FAIL: float = 0.50    # fail_rate > this → remove 1/5 workers

# NOTE: ESCALATION_PAUSE_* constants moved to config/defaults_effectiveness.py
# and re-exported here via `from config.defaults_effectiveness import *` at EOF.

# Recovery threshold (v28: Lowered — attack tool should be more aggressive)
RECOVERY_HEALTH_THRESHOLD: float = 0.5    # health > this for recovery/resume (v28)

# HOLD mode (v28: Auto-expiry to prevent permanent stuck)
HOLD_CONSECUTIVE_SHRINK_THRESHOLD: int = 8  # Consecutive shrinks before HOLD (v28, was 5)
HOLD_EXPIRY_SECONDS: float = 30.0           # HOLD auto-expires after this (v28)
HOLD_RECOVERY_STEP: int = 5                 # Workers added per recovery step (v28)
HOLD_RECOVERY_INTERVAL: int = 5             # Ticks between recovery steps (v28)

# Health status display thresholds
HEALTH_DISPLAY_HEALTHY: float = 0.7
HEALTH_DISPLAY_WARNING: float = 0.4


# ═══════════════════════════════════════════════════════════════════════════════
# C6: Target Selector Weight Multipliers
# ═══════════════════════════════════════════════════════════════════════════════

TARGET_WEIGHT_SUCCESS_MULTIPLIER: float = 1.1   # weight * 1.1 + 0.1 on success
TARGET_WEIGHT_SUCCESS_BONUS: float = 0.1         # +0.1 bonus on success
TARGET_WEIGHT_CAP: float = 3.0                   # max weight per URL
TARGET_WEIGHT_WAF_BLOCK_MULTIPLIER: float = 0.3  # weight * 0.3 on WAF block
TARGET_WEIGHT_CHALLENGE_MULTIPLIER: float = 0.4  # weight * 0.4 on challenge
TARGET_WEIGHT_NOT_FOUND_MULTIPLIER: float = 0.5  # weight * 0.5 on 404
TARGET_WEIGHT_RATE_LIMITED_MULTIPLIER: float = 0.8  # weight * 0.8 on 429
TARGET_WEIGHT_SERVER_ERROR_MULTIPLIER: float = 0.7   # weight * 0.7 on 5xx
TARGET_WEIGHT_OTHER_FAIL_MULTIPLIER: float = 0.6     # weight * 0.6 on other fail
TARGET_WEIGHT_FLOOR: float = 0.05                   # min weight (unless dead)
TARGET_WEIGHT_DISCOVERED_INITIAL: float = 1.5       # initial weight for discovered URLs
TARGET_WEIGHT_REVIVED: float = 0.5                  # weight after emergency revive
TARGET_DEAD_THRESHOLD: int = 5                       # consecutive fails → dead


# ═══════════════════════════════════════════════════════════════════════════════
# C6: Plugin Worker Allocation — _compute_plugin_workers thresholds
# ═══════════════════════════════════════════════════════════════════════════════

# Each entry: (max_workers, min_workers, divisor)
# Workers = min(max_workers, max(min_workers, total_max // divisor))

PLUGIN_WORKER_SLOWLORIS: Dict[str, int] = {"max": 50, "min": 10, "divisor": 200}
PLUGIN_WORKER_CONN_EXHAUST: Dict[str, int] = {"max": 40, "min": 8, "divisor": 250}
PLUGIN_WORKER_TLS_HANDSHAKE: Dict[str, int] = {"max": 30, "min": 5, "divisor": 300}
PLUGIN_WORKER_ORIGIN_HTTP: Dict[str, int] = {"max": 40, "min": 8, "divisor": 250}
PLUGIN_WORKER_SLOW_READ: Dict[str, int] = {"max": 30, "min": 5, "divisor": 300}
PLUGIN_WORKER_GENERIC_ORIGIN: Dict[str, int] = {"max": 20, "min": 5, "divisor": 500}

# Memory-heavy plugins (large payloads)
PLUGIN_WORKER_MEMORY_HEAVY: Dict[str, int] = {"max": 20, "min": 5, "divisor": 500}

# WebSocket flood (persistent connections)
PLUGIN_WORKER_WS_FLOOD: Dict[str, int] = {"max": 50, "min": 10, "divisor": 200}

# WordPress amplification (high amplification per request)
PLUGIN_WORKER_WP_AMPLIFY: Dict[str, int] = {"max": 30, "min": 5, "divisor": 300}

# WordPress-specific plugins (v34: new high-amplification WP endpoints)
PLUGIN_WORKER_WP_CRON: Dict[str, int] = {"max": 40, "min": 10, "divisor": 200}  # wp-cron = CPU burn
PLUGIN_WORKER_WP_AJAX: Dict[str, int] = {"max": 40, "min": 10, "divisor": 200}  # admin-ajax = CPU + DB
PLUGIN_WORKER_WP_REST: Dict[str, int] = {"max": 30, "min": 8, "divisor": 300}   # REST API = DB-heavy
PLUGIN_WORKER_WP_SEARCH: Dict[str, int] = {"max": 30, "min": 8, "divisor": 300} # Search = LIKE scan
PLUGIN_WORKER_WP_WOOCOMMERCE: Dict[str, int] = {"max": 25, "min": 5, "divisor": 400}  # WooCommerce = DB write

# ASP.NET CPU-heavy
PLUGIN_WORKER_ASPNET: Dict[str, int] = {"max": 25, "min": 5, "divisor": 400}

# CPU-heavy (HTTP/2 rapid reset, GraphQL)
PLUGIN_WORKER_CPU_HEAVY: Dict[str, int] = {"max": 30, "min": 5, "divisor": 300}

# Cache poisoning
PLUGIN_WORKER_CACHE_POISON: Dict[str, int] = {"max": 25, "min": 5, "divisor": 400}

# HTTP plugins (default)
PLUGIN_WORKER_HTTP_MIN: int = 10

# ═══════════════════════════════════════════════════════════════════════════════
# Scanner Timeout Presets — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

# Deep scan timeout (path discovery — shorter than full scan)
DEEP_SCAN_TIMEOUT: int = 8

# Fast probe timeout (subdomain check, DNS scan, origin discovery)
FAST_PROBE_TIMEOUT: int = 5
FAST_PROBE_CONNECT: int = 2
FAST_PROBE_SOCK_READ: int = 3

# Fingerprint scan timeout (HTTP fingerprinting — needs more time)
FINGERPRINT_TIMEOUT: int = 20

# Origin discovery specific timeouts
ORIGIN_PROBE_TIMEOUT: int = 8
ORIGIN_QUICK_PROBE_TIMEOUT: int = 5


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Timeout Presets — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

# API flood session timeout (faster than default — attack pacing)
ATTACK_SESSION_TIMEOUT: int = 15
ATTACK_SESSION_CONNECT: int = 5
ATTACK_SESSION_SOCK_READ: int = 5

# Per-request attack timeouts (varies by plugin)
ATTACK_REQUEST_TIMEOUT: int = 5       # Standard per-request attack timeout
ATTACK_QUICK_TIMEOUT: int = 3         # Quick attack timeout (basic_api_flood, login_flood step)
ATTACK_SESSION_MGR_TIMEOUT: int = 8   # Session manager total timeout


# ═══════════════════════════════════════════════════════════════════════════════
# Low-Level / Raw Socket Timeouts — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

# asyncio.open_connection / raw TCP timeouts
RAW_CONNECT_TIMEOUT: float = 5.0     # For open_connection() in conn_exhaust, slowloris, etc.
WRITER_CLOSE_TIMEOUT: float = 5.0     # For writer.close() with timeout

# Plugin cleanup timeout
PLUGIN_CLEANUP_TIMEOUT: float = 10.0  # For VF_TESTER plugin shutdown

# Attack base worker cleanup
WORKER_CLEANUP_TIMEOUT: float = 15.0  # For vf_attack_base.run() task gather

# DNS/network probe timeouts
DNS_PROBE_TIMEOUT: float = 3.0        # For DNS queries in origin_discovery, dns_scanner
NETWORK_PROBE_TIMEOUT: float = 5.0    # For network-level probes
ORIGIN_QUICK_NETWORK_TIMEOUT: float = 2.0  # Quick origin network probe

# Finder engine timeout
FINDER_ENGINE_TIMEOUT: float = 10.0

# Evasion timeout
EVASION_FPC_TIMEOUT: float = 10.0


# ═══════════════════════════════════════════════════════════════════════════════
# Protocol-Specific Timeouts — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

# HTTP/2 rapid reset
H2_RAPID_RESET_TIMEOUT: float = 5.0

# WebSocket
WS_CONNECT_TIMEOUT: float = 5.0       # ws_connect() timeout
WS_RECEIVE_TIMEOUT: float = 0.05      # ws.receive() timeout (non-blocking check)
WS_HEARTBEAT: int = 10                # WebSocket heartbeat interval


# ═══════════════════════════════════════════════════════════════════════════════
# Scanner Concurrency / Semaphore Limits — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

DEEP_SCAN_SEMAPHORE: int = 5          # deep_scanner path check concurrency
SCRIPT_ANALYSIS_SEMAPHORE: int = 3    # deep_scanner script analysis concurrency
WAF_PROBE_SEMAPHORE: int = 10         # vf_waf_probe concurrency
CACHE_ANALYSIS_SEMAPHORE: int = 5     # vf_cache_analyzer concurrency
JS_SCAN_SEMAPHORE: int = 6            # vf_js_scanner concurrency
SESSION_HARVEST_CONNECTOR_LIMIT: int = 10  # Session harvesting connector limit
SESSION_HARVEST_FORM_LIMIT: int = 5   # Session harvesting form concurrency


# ═══════════════════════════════════════════════════════════════════════════════
# Deque / Bounded Buffer Sizes — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

STATS_RPS_WINDOW_SIZE: int = 10_000     # vf_data.py RPS rolling window
REPORT_TIMELINE_MAX: int = 5000         # vf_report.py timeline events
REPORT_STATS_HISTORY_MAX: int = 1000    # vf_report.py stats snapshots
REPORT_WAF_INTERACTIONS_MAX: int = 1000 # vf_report.py WAF interactions
REPORT_HEALTH_HISTORY_MAX: int = 500    # vf_report.py server health
SESSION_HARVEST_PAGES_MAX: int = 2000   # vf_session_harvest.py pages visited
BEHAVIOR_RESPONSE_HISTORY_MAX: int = 1000  # vf_behavior.py response history


# ═══════════════════════════════════════════════════════════════════════════════
# WAF Defaults — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

WAF_BLOCKS_MAX: int = 5000  # Cap _url_waf_blocks dict size in vf_attack_base


# ═══════════════════════════════════════════════════════════════════════════════
# JS Scanner Limits — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

JS_SCAN_MAX_FILE_SIZE: int = 256_000    # 256 KB — skip larger files
JS_SCAN_TOTAL_TIMEOUT: int = 30         # 30s — abort entire scan after this
JS_SCAN_HEAD_CHARS: int = 50_000        # Scan only first 50 KB of content


# ═══════════════════════════════════════════════════════════════════════════════
# Stats Tuning — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

STATS_EMA_ALPHA: float = 0.05           # EMA smoothing factor for response time
STATS_RPS_WINDOW_SECONDS: float = 3.0   # Rolling window duration for RPS


# ═══════════════════════════════════════════════════════════════════════════════
# Dashboard Tuning — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

DASHBOARD_MAX_RPS_HISTORY: int = 60     # RPS history buffer for sparkline (~1 min)


# ═══════════════════════════════════════════════════════════════════════════════
# Login Flood Tuning — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

CSRF_REFRESH_INTERVAL: float = 120.0    # Seconds between CSRF token refreshes
CSRF_REFRESH_EVERY_N: int = 500         # Refresh CSRF every N requests


# ═══════════════════════════════════════════════════════════════════════════════
# Session Harvest Tuning — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

SESSION_REFRESH_INTERVAL: float = 300.0  # Seconds between session refreshes


# ═══════════════════════════════════════════════════════════════════════════════
# Behavior Evasion Tuning — W2.4
# ═══════════════════════════════════════════════════════════════════════════════

BEHAVIOR_MAX_PAGES_PER_SESSION: Tuple[int, int] = (10, 30)  # Random range for pages
BEHAVIOR_NETWORK_LATENCY_BASE: float = 0.3  # Base latency (Iran internet)


# ═══════════════════════════════════════════════════════════════════════════════
# M1: Profile Schema Version
# ═══════════════════════════════════════════════════════════════════════════════

PROFILE_SCHEMA_VERSION: int = 1


# ═══════════════════════════════════════════════════════════════════════════════
# W5.6: OpenTelemetry Tracing Defaults
# ═══════════════════════════════════════════════════════════════════════════════

# Tracing is disabled by default. Enable with STORM_VX_TRACING_ENABLED=true
OTEL_ENABLED: bool = False
OTEL_ENDPOINT: str = "localhost:4317"      # OTLP gRPC endpoint
OTEL_SERVICE_NAME: str = "storm-vx"        # Service name in traces
OTEL_SAMPLE_RATE: float = 1.0              # 1.0 = sample all traces, 0.1 = sample 10%
OTEL_EXPORT_TIMEOUT_MS: int = 30000        # Batch export timeout in milliseconds


# ═══════════════════════════════════════════════════════════════════════════════
# W5.7: Security Hardening Defaults
# ═══════════════════════════════════════════════════════════════════════════════

# Strict mode: reject invalid input instead of warning.
# Default false for backward compatibility — set STORM_VX_SECURITY_STRICT=true to enable.
SECURITY_STRICT_MODE: bool = False

# SSRF protection: block URLs targeting private/internal IPs.
# Default true — can be disabled for testing with STORM_VX_SSRF_PROTECTION=false.
SSRF_PROTECTION_ENABLED: bool = True

# Secret redaction in logs: automatically mask API keys, tokens, passwords.
# Default true — rarely needs to be disabled.
REDACT_SECRETS_ENABLED: bool = True

# Maximum JSON nesting depth (prevents JSON bomb / billion laughs attacks).
JSON_MAX_DEPTH: int = 20

# Maximum JSON file/payload size in bytes (prevents memory exhaustion from huge JSON).
JSON_MAX_SIZE: int = 10_000_000  # 10 MB

# Maximum URL length (prevents buffer-based attacks).
URL_MAX_LENGTH: int = 8192

# Allowed URL schemes (others are rejected/blocked).
ALLOWED_URL_SCHEMES: Tuple[str, ...] = ("http", "https")

# Allowed file extensions for profile loading.
PROFILE_ALLOWED_EXTENSIONS: Tuple[str, ...] = (".json",)

# Maximum profile file size in bytes.
PROFILE_MAX_SIZE: int = 5_000_000  # 5 MB

# Maximum plugin file size in bytes (existing SEC-012 limit).
PLUGIN_MAX_SIZE: int = 500_000  # 500 KB


# ═══════════════════════════════════════════════════════════════════════════════
# SiteProfile List Limits — BUG-043 fix
# ═══════════════════════════════════════════════════════════════════════════════

# Prevent unbounded memory growth from large pages with many links/scripts/images.
# After reaching these limits, further items are silently dropped with a warning.
MAX_DISCOVERED_LINKS: int = 200
MAX_DISCOVERED_SCRIPTS: int = 100
MAX_DISCOVERED_IMAGES: int = 50
MAX_DISCOVERED_ENDPOINTS: int = 50


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 0+2 constants moved to config/defaults_effectiveness.py
# ═══════════════════════════════════════════════════════════════════════════════
# The following constants are now defined in config/defaults_effectiveness.py
# and re-exported here for backward compatibility:
#   PLUGIN_TIER_1, PLUGIN_TIER_2, PLUGIN_TIER_3, PLUGIN_TIER_MAP
#   PLUGIN_AUTO_DISABLE_ERROR_RATE, PLUGIN_AUTO_DISABLE_MIN_REQUESTS,
#   PLUGIN_AUTO_DISABLE_COOLDOWN
#   PLUGIN_EFFECTIVENESS_PROBE_DURATION, PLUGIN_EFFECTIVENESS_PROBE_WORKERS,
#   PLUGIN_EFFECTIVENESS_TOP_K, PLUGIN_EFFECTIVENESS_MIN_WORKERS,
#   PLUGIN_EFFECTIVENESS_REEVAL_INTERVAL
#   ESCALATION_PAUSE_TIMEOUT, ESCALATION_PAUSE_FAIL,
#   ESCALATION_PAUSE_TIMEOUT_COMBO_FAIL, ESCALATION_PAUSE_TIMEOUT_COMBO_TIMEOUT,
#   ESCALATION_RESUME_TIMEOUT_FACTOR
#   ORIGIN_AUTO_DISABLE_MIN_REQUESTS, ORIGIN_AUTO_DISABLE_ERROR_RATE
#   SMART_TIMEOUT_ENABLED, SMART_TIMEOUT_RTT_MULTIPLIER_CONNECT,
#   SMART_TIMEOUT_RTT_MULTIPLIER_READ, SMART_TIMEOUT_MIN_CONNECT,
#   SMART_TIMEOUT_MIN_READ, SMART_TIMEOUT_MAX_CONNECT, SMART_TIMEOUT_MAX_READ
#   DEFAULT_POOL_MAX_SIZE, DEFAULT_POOL_RECYCLE_INTERVAL,
#   DEFAULT_POOL_RECYCLE_MAX_AGE, DEFAULT_POOL_DEAD_CLEANUP_INTERVAL

from config.defaults_effectiveness import *  # noqa: F401,F403 — re-export all effectiveness constants
