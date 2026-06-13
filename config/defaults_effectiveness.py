"""Storm-Vx Effectiveness & Smart Timeout Defaults.

Phase 0+2 configuration constants for:
- Plugin tier classification and effectiveness scoring
- Auto-disable thresholds for plugins and origin plugins
- Smart timeout tuning
- Connection pool lifecycle
- Escalation control

Extracted from config/defaults.py for Law 14 compliance (500-line limit).
All constants are re-exported by config/defaults.py for backward compatibility:
    from config.defaults import SMART_TIMEOUT_ENABLED  # still works
"""
from __future__ import annotations
from typing import Dict


# ═══════════════════════════════════════════════════════════════════════════════
# Escalation Pause Thresholds (v28: Based on CLIENT connectivity)
# ═══════════════════════════════════════════════════════════════════════════════

ESCALATION_PAUSE_TIMEOUT: float = 0.50    # timeout_rate > this → pause escalation (v28)
ESCALATION_PAUSE_FAIL: float = 0.80       # fail_rate > this → pause escalation (v28)
ESCALATION_PAUSE_TIMEOUT_COMBO_FAIL: float = 0.55  # fail + timeout combo (v28)
ESCALATION_PAUSE_TIMEOUT_COMBO_TIMEOUT: float = 0.35  # combo timeout (v28)

# Escalation resume
ESCALATION_RESUME_TIMEOUT_FACTOR: float = 0.75  # Resume when timeout_rate < PAUSE_TIMEOUT_RATE * this factor


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 0: Plugin Effectiveness & Auto-Select Defaults
# ═══════════════════════════════════════════════════════════════════════════════

# Plugin tier classification (80/20 rule)
PLUGIN_TIER_1: int = 1  # Essential
PLUGIN_TIER_2: int = 2  # Situational
PLUGIN_TIER_3: int = 3  # Deprecated

PLUGIN_TIER_MAP: Dict[str, int] = {
    # Tier 1 — Essential
    "page_flood": 1,
    "basic_api_flood": 1,
    "slowloris": 1,
    "http2_rapid_reset": 1,
    "cache_poison": 1,
    "login_flood": 1,
    # Tier 2 — Situational
    "header_bomb": 2,
    "multipart_upload": 2,
    "json_bomb": 2,
    "ws_flood": 2,
    "wp_xmlrpc_bomb": 2,
    "wp_pingback_amplify": 2,
    "wp_cron_bomb": 2,
    "wp_ajax_flood": 2,
    "wp_rest_flood": 2,
    "wp_search_bomb": 2,
    "wp_woocommerce_flood": 2,
    "graphql_introspection": 2,
    "viewstate_burn": 2,
    "aspnet_session_flood": 2,
    # Tier 3 — Deprecated
    "origin_http": 3,
    "conn_exhaust": 3,
    "tls_handshake": 3,
    "slow_read": 3,
    "resource_flood": 3,
}

# Auto-disable thresholds
PLUGIN_AUTO_DISABLE_ERROR_RATE: float = 0.95
PLUGIN_AUTO_DISABLE_MIN_REQUESTS: int = 50
PLUGIN_AUTO_DISABLE_COOLDOWN: int = 60

# Effectiveness scoring
PLUGIN_EFFECTIVENESS_PROBE_DURATION: int = 15
PLUGIN_EFFECTIVENESS_PROBE_WORKERS: int = 20
PLUGIN_EFFECTIVENESS_TOP_K: int = 3
PLUGIN_EFFECTIVENESS_MIN_WORKERS: int = 30
PLUGIN_EFFECTIVENESS_REEVAL_INTERVAL: int = 30

# Auto-disable thresholds (origin plugins)
ORIGIN_AUTO_DISABLE_MIN_REQUESTS: int = 50
ORIGIN_AUTO_DISABLE_ERROR_RATE: float = 0.97

# ESSENTIAL plugin auto-disable thresholds (much stricter than non-ESSENTIAL)
# Even ESSENTIAL plugins should be disabled when they have 99%+ error rate —
# they're wasting workers that should go to productive plugins.
ESSENTIAL_AUTO_DISABLE_ERROR_RATE: float = 0.99
ESSENTIAL_AUTO_DISABLE_MIN_REQUESTS: int = 100

# Smart timeout
SMART_TIMEOUT_ENABLED: bool = True
SMART_TIMEOUT_RTT_MULTIPLIER_CONNECT: float = 3.0
SMART_TIMEOUT_RTT_MULTIPLIER_READ: float = 5.0
SMART_TIMEOUT_MIN_CONNECT: float = 2.0
SMART_TIMEOUT_MIN_READ: float = 3.0
SMART_TIMEOUT_MAX_CONNECT: float = 10.0
SMART_TIMEOUT_MAX_READ: float = 15.0

# Connection pool lifecycle (Phase 0 — attack-optimized values)
DEFAULT_POOL_MAX_SIZE: int = 500
DEFAULT_POOL_RECYCLE_INTERVAL: int = 30
DEFAULT_POOL_RECYCLE_MAX_AGE: int = 60
DEFAULT_POOL_DEAD_CLEANUP_INTERVAL: int = 10

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 4: Circuit Breaker Defaults (replaces hard disable/enable toggle)
# ═══════════════════════════════════════════════════════════════════════════════
# When a plugin's error rate exceeds threshold, the circuit transitions
# CLOSED → OPEN (blocking). After half_open_timeout seconds, it transitions
# to HALF_OPEN (probing). After success_threshold consecutive successes,
# it transitions back to CLOSED (recovered).
CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = 5      # Consecutive failures before OPEN
CIRCUIT_BREAKER_HALF_OPEN_TIMEOUT: float = 30.0  # Seconds before probing
CIRCUIT_BREAKER_SUCCESS_THRESHOLD: int = 2       # Successes in HALF_OPEN to CLOSE


__all__ = [
    # Escalation pause
    "ESCALATION_PAUSE_TIMEOUT", "ESCALATION_PAUSE_FAIL",
    "ESCALATION_PAUSE_TIMEOUT_COMBO_FAIL", "ESCALATION_PAUSE_TIMEOUT_COMBO_TIMEOUT",
    "ESCALATION_RESUME_TIMEOUT_FACTOR",
    # Plugin tier
    "PLUGIN_TIER_1", "PLUGIN_TIER_2", "PLUGIN_TIER_3", "PLUGIN_TIER_MAP",
    # Auto-disable
    "PLUGIN_AUTO_DISABLE_ERROR_RATE", "PLUGIN_AUTO_DISABLE_MIN_REQUESTS",
    "PLUGIN_AUTO_DISABLE_COOLDOWN",
    # Effectiveness scoring
    "PLUGIN_EFFECTIVENESS_PROBE_DURATION", "PLUGIN_EFFECTIVENESS_PROBE_WORKERS",
    "PLUGIN_EFFECTIVENESS_TOP_K", "PLUGIN_EFFECTIVENESS_MIN_WORKERS",
    "PLUGIN_EFFECTIVENESS_REEVAL_INTERVAL",
    # Origin auto-disable
    "ORIGIN_AUTO_DISABLE_MIN_REQUESTS", "ORIGIN_AUTO_DISABLE_ERROR_RATE",
    # ESSENTIAL auto-disable (much stricter than non-ESSENTIAL)
    "ESSENTIAL_AUTO_DISABLE_ERROR_RATE", "ESSENTIAL_AUTO_DISABLE_MIN_REQUESTS",
    # Smart timeout
    "SMART_TIMEOUT_ENABLED", "SMART_TIMEOUT_RTT_MULTIPLIER_CONNECT",
    "SMART_TIMEOUT_RTT_MULTIPLIER_READ", "SMART_TIMEOUT_MIN_CONNECT",
    "SMART_TIMEOUT_MIN_READ", "SMART_TIMEOUT_MAX_CONNECT", "SMART_TIMEOUT_MAX_READ",
    # Connection pool lifecycle
    "DEFAULT_POOL_MAX_SIZE", "DEFAULT_POOL_RECYCLE_INTERVAL",
    "DEFAULT_POOL_RECYCLE_MAX_AGE", "DEFAULT_POOL_DEAD_CLEANUP_INTERVAL",
    # Circuit breaker
    "CIRCUIT_BREAKER_FAILURE_THRESHOLD", "CIRCUIT_BREAKER_HALF_OPEN_TIMEOUT",
    "CIRCUIT_BREAKER_SUCCESS_THRESHOLD",
]
