"""Configuration determination builder.

Extracted from AttackProfileGenerator._determine_waf_strategy(),
_determine_worker_config(), _determine_surgical_worker_config(),
_determine_all_worker_config(), _determine_request_config(),
_determine_login_config(), _determine_timing_config(),
_determine_evasion_config() (Task 2.3).

Pure functions — take profile + needed params, return a value.
"""

from __future__ import annotations

from typing import Any, Dict

from finder.site_profile import SiteProfile


def determine_waf_strategy(profile: SiteProfile) -> Dict[str, Any]:
    """Determine WAF bypass strategy.

    Args:
        profile: The site profile with discovered information.

    Returns:
        Dictionary with WAF detection info and bypass methods.
    """
    p = profile
    if not p.waf:
        return {"detected": False}

    strategy: Dict[str, Any] = {
        "detected": True,
        "waf_name": p.waf,
        "confidence": p.waf_confidence,
        "bypass_methods": [],
    }

    waf_lower = p.waf.lower()

    if "cloudflare" in waf_lower:
        strategy["bypass_methods"] = [
            "CFB_CHALLENGE_SOLVE", "ROTATE_USER_AGENT", "SLOW_REQUEST_RATE",
            "USE_CF_CLEARANCE_COOKIE", "ORIGIN_IP_DIRECT",
        ]
    elif "arvan" in waf_lower:
        strategy["bypass_methods"] = [
            "ROTATE_USER_AGENT", "SLOW_RAMP_UP", "CACHE_BUST_PARAMS",
            "HEADER_MANIPULATION", "DISTRIBUTED_SOURCES", "SLOW_POST_READ",
            "HTTP2_MULTIPLEXING", "CACHE_DECEPTION_BYPASS", "ORIGIN_IP_DIRECT",
        ]
    elif "modsecurity" in waf_lower:
        strategy["bypass_methods"] = [
            "PAYLOAD_ENCODING", "HEADER_MANIPULATION", "PATH_OBFUSCATION",
            "CHUNKED_ENCODING",
        ]
    elif "imperva" in waf_lower or "incapsula" in waf_lower:
        strategy["bypass_methods"] = [
            "ROTATE_COOKIES", "SLOW_REQUEST_RATE", "HEADER_MANIPULATION",
        ]
    elif "akamai" in waf_lower:
        strategy["bypass_methods"] = [
            "CACHE_BUST_PARAMS", "ROTATE_USER_AGENT", "SLOW_RAMP_UP",
        ]
    elif "sotoon" in waf_lower:
        strategy["bypass_methods"] = [
            "ROTATE_USER_AGENT", "SLOW_RAMP_UP", "CACHE_BUST_PARAMS",
            "HEADER_MANIPULATION", "ORIGIN_IP_DIRECT", "SLOW_POST_READ",
            "CACHE_DECEPTION_BYPASS",
        ]
    else:
        strategy["bypass_methods"] = [
            "ROTATE_USER_AGENT", "CACHE_BUST_PARAMS", "SLOW_RAMP_UP",
            "HEADER_MANIPULATION",
        ]

    return strategy


def determine_worker_config(profile: SiteProfile, strategy: str = "") -> Dict[str, Any]:
    """Determine optimal worker configuration.

    Args:
        profile: The site profile with discovered information.
        strategy: The selected attack strategy name (reserved for future use).

    Returns:
        Dictionary with worker configuration parameters.
    """
    p = profile
    config: Dict[str, Any] = {
        "initial_workers": 50, "max_workers": 10000,
        "step": 100, "step_duration": 3, "ramp_strategy": "GRADUAL",
    }
    if p.waf:
        config["initial_workers"] = 20
        config["step"] = 50
        config["step_duration"] = 5
        config["ramp_strategy"] = "STEALTHY"
        if "cloudflare" in (p.waf or "").lower():
            config["initial_workers"] = 10
            config["step"] = 30
            config["step_duration"] = 8
            config["ramp_strategy"] = "SLOW_STEALTHY"
    if p.baseline_rt > 2.0:
        config["initial_workers"] = max(10, config["initial_workers"] // 2)
        config["max_workers"] = 5000
    elif p.baseline_rt < 0.3:
        config["max_workers"] = 15000
        config["step"] = 150
    if p.rate_limit_detected and p.rate_limit_threshold:
        if p.rate_limit_threshold < 20:
            config["initial_workers"] = 5
            config["step"] = 10
            config["step_duration"] = 15
            config["ramp_strategy"] = "VERY_SLOW"
    return config


def determine_surgical_worker_config(profile: SiteProfile) -> Dict[str, Any]:
    """SURGICAL mode worker config.

    Args:
        profile: The site profile with discovered information.

    Returns:
        Dictionary with surgical worker configuration parameters.
    """
    p = profile
    config: Dict[str, Any] = {
        "initial_workers": 10, "max_workers": 2000,
        "step": 20, "step_duration": 5, "ramp_strategy": "SURGICAL_PRECISE",
    }
    if p.waf:
        config["initial_workers"] = 5
        config["step"] = 10
        config["step_duration"] = 8
        config["ramp_strategy"] = "SURGICAL_STEALTHY"
    if p.rate_limit_detected:
        config["initial_workers"] = 3
        config["step"] = 5
        config["step_duration"] = 10
    if p.baseline_rt < 0.3:
        config["max_workers"] = 3000
        config["step"] = 30
    return config


def determine_all_worker_config(profile: SiteProfile) -> Dict[str, Any]:
    """ALL mode worker config.

    Args:
        profile: The site profile with discovered information.

    Returns:
        Dictionary with all-out worker configuration parameters.
    """
    p = profile
    config: Dict[str, Any] = {
        "initial_workers": 200, "max_workers": 15000,
        "step": 200, "step_duration": 2, "ramp_strategy": "ALL_MAXIMUM",
    }
    if p.waf:
        config["initial_workers"] = 100
        config["step"] = 150
        config["step_duration"] = 3
    if p.baseline_rt > 2.0:
        config["max_workers"] = 8000
        config["initial_workers"] = 100
    elif p.baseline_rt < 0.3:
        config["max_workers"] = 20000
        config["step"] = 300
    if p.rate_limit_detected:
        config["initial_workers"] = max(config["initial_workers"], 300)
        config["max_workers"] = max(config["max_workers"], 15000)
    return config


def determine_request_config(profile: SiteProfile,
                             verify_ssl: bool = True) -> Dict[str, Any]:
    """Determine request configuration.

    Args:
        profile: The site profile with discovered information.
        verify_ssl: Whether SSL verification is enabled.

    Returns:
        Dictionary with request configuration parameters.
    """
    p = profile
    config: Dict[str, Any] = {
        "timeout": 20, "follow_redirects": True, "verify_ssl": verify_ssl,
        "keepalive": True, "cache_bust": True, "user_agent_rotation": True,
        "delay_between_requests_ms": 10,
    }
    if p.waf:
        config["delay_between_requests_ms"] = 50
        config["cache_bust"] = True
    if p.rate_limit_detected:
        config["delay_between_requests_ms"] = 100
    return config


def determine_login_config(profile: SiteProfile) -> Dict[str, Any]:
    """Determine login attack configuration.

    Args:
        profile: The site profile with discovered information.

    Returns:
        Dictionary with login attack configuration parameters.
    """
    p = profile
    config: Dict[str, Any] = {
        "enabled": bool(p.forms and p.login_fields),
        "username_field": p.login_fields.get("username", "username"),
        "password_field": p.login_fields.get("password", "password"),
        "login_url": p.url, "method": "POST",
        "include_hidden_fields": True, "weight": 0.45,
    }
    if p.viewstate_present:
        config["weight"] = 0.50
        config["refresh_viewstate"] = True
        config["viewstate_ttl"] = 30
    return config


def determine_timing_config(profile: SiteProfile) -> Dict[str, Any]:
    """Determine timing configuration.

    Args:
        profile: The site profile with discovered information.

    Returns:
        Dictionary with timing configuration parameters.
    """
    p = profile
    config: Dict[str, Any] = {
        "crash_mode": True, "crash_sensitivity": "MEDIUM",
        "health_check_interval": 5, "auto_scale": True,
    }
    if p.waf:
        config["crash_sensitivity"] = "LOW"
        config["health_check_interval"] = 3
    if p.baseline_rt > 2.0:
        config["crash_sensitivity"] = "HIGH"
    return config


def determine_evasion_config(profile: SiteProfile) -> Dict[str, Any]:
    """Determine evasion techniques.

    Args:
        profile: The site profile with discovered information.

    Returns:
        Dictionary with evasion configuration parameters.
    """
    p = profile
    config: Dict[str, Any] = {
        "rotate_user_agent": True, "cache_bust": True,
        "random_delays": True, "header_randomization": False,
        "proxy_rotation": False,
    }
    if p.waf:
        config["header_randomization"] = True
        config["random_delays"] = True
        waf_lower = p.waf.lower()
        if "cloudflare" in waf_lower:
            config["proxy_rotation"] = True
        if "arvan" in waf_lower:
            config["header_randomization"] = True
    return config
