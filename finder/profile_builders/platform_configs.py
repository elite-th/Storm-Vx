"""Platform-specific configuration builder.

Extracted from AttackProfileGenerator._determine_aspnet_config(),
_determine_php_config(), _determine_wordpress_config(),
_determine_api_config(), _determine_edu_config(),
_determine_spa_config() (Task 2.3).

Pure functions — take profile + needed params, return a value.
"""

from __future__ import annotations

from typing import Any, Dict, List

from finder.site_profile import SiteProfile
from finder.vf_tech_helpers import (
    is_spa, is_nextjs, has_graphql,
    detect_spa_framework, find_graphql_endpoint,
    extract_spa_routes, extract_next_data_routes,
)


def determine_aspnet_config(profile: SiteProfile) -> Dict[str, Any]:
    """ASP.NET specific configuration.

    Args:
        profile: The site profile with discovered information.

    Returns:
        Dictionary with ASP.NET configuration parameters.
    """
    p = profile
    if not p.viewstate_present:
        return {"enabled": False}
    return {
        "enabled": True, "viewstate_cache_ttl": 30,
        "eventvalidation_required": p.eventvalidation_present,
        "target_login_url": p.url, "hidden_fields": p.hidden_fields,
        "session_cookie": "ASP.NET_SessionId",
    }


def determine_php_config(profile: SiteProfile) -> Dict[str, Any]:
    """PHP specific configuration.

    Args:
        profile: The site profile with discovered information.

    Returns:
        Dictionary with PHP configuration parameters.
    """
    p = profile
    php_detected = p.backend_lang and "PHP" in (p.backend_lang or "")
    if not php_detected and not any("PHP" in t["name"] for t in p.technologies):
        return {"enabled": False}
    return {
        "enabled": True, "session_cookie": "PHPSESSID",
        "common_paths": ["/login.php", "/index.php", "/admin/login.php"],
    }


def determine_wordpress_config(profile: SiteProfile) -> Dict[str, Any]:
    """WordPress specific configuration.

    Args:
        profile: The site profile with discovered information.

    Returns:
        Dictionary with WordPress configuration parameters.
    """
    p = profile
    if not p.cms or "WordPress" not in p.cms:
        return {"enabled": False}
    domain = p.domain
    return {
        "enabled": True,
        "xmlrpc_url": f"{p.scheme}://{domain}/xmlrpc.php",
        "login_url": f"{p.scheme}://{domain}/wp-login.php",
        "rest_api": f"{p.scheme}://{domain}/wp-json/wp/v2/posts",
        "admin_url": f"{p.scheme}://{domain}/wp-admin/",
        "wp_content": f"{p.scheme}://{domain}/wp-content/",
    }


def determine_api_config(profile: SiteProfile) -> Dict[str, Any]:
    """API endpoint configuration.

    Args:
        profile: The site profile with discovered information.

    Returns:
        Dictionary with API configuration parameters.
    """
    p = profile
    if not p.api_endpoints:
        return {"enabled": False}
    return {
        "enabled": True, "endpoints": p.api_endpoints,
        "methods": ["GET", "POST"],
        "content_types": ["application/json", "application/x-www-form-urlencoded"],
    }


def determine_edu_config(profile: SiteProfile) -> Dict[str, Any]:
    """v18: Educational site specific configuration.

    Args:
        profile: The site profile with discovered information.

    Returns:
        Dictionary with educational site configuration parameters.
    """
    p = profile
    if p.site_category != 'educational':
        return {"enabled": False}

    edu_api_endpoints: List[str] = []
    domain = p.domain
    scheme = p.scheme

    edu_api_endpoints.extend([
        f"{scheme}://{domain}/api/students",
        f"{scheme}://{domain}/api/grades",
        f"{scheme}://{domain}/api/courses",
        f"{scheme}://{domain}/api/attendance",
        f"{scheme}://{domain}/api/exam/results",
        f"{scheme}://{domain}/api/search",
        f"{scheme}://{domain}/api/transcript",
        f"{scheme}://{domain}/api/report/card",
        f"{scheme}://{domain}/api/dashboard",
        f"{scheme}://{domain}/api/v1/students",
        f"{scheme}://{domain}/api/v1/grades",
        f"{scheme}://{domain}/api/v1/courses",
        f"{scheme}://{domain}/student/grades",
        f"{scheme}://{domain}/student/attendance",
        f"{scheme}://{domain}/student/courses",
        f"{scheme}://{domain}/parent/grades",
        f"{scheme}://{domain}/teacher/classes",
        f"{scheme}://{domain}/admin/students",
        f"{scheme}://{domain}/admin/grades",
        f"{scheme}://{domain}/report/card",
        f"{scheme}://{domain}/export/grades/pdf",
        f"{scheme}://{domain}/export/transcript",
        f"{scheme}://{domain}/login",
        f"{scheme}://{domain}/auth/login",
        f"{scheme}://{domain}/dashboard",
    ])

    for ep in p.edu_endpoints:
        if ep.startswith('/'):
            full_url = f"{scheme}://{domain}{ep}"
        else:
            full_url = ep
        if full_url not in edu_api_endpoints:
            edu_api_endpoints.append(full_url)

    phase_weights = {
        "slowloris": 0.40, "api_flood": 0.25,
        "cookie_poison": 0.15, "chunked_bomb": 0.10,
        "login_flood": 0.10,
    }

    return {
        "enabled": True, "site_category": "educational",
        "confidence_indicators": p.edu_indicators[:5],
        "edu_endpoints": edu_api_endpoints,
        "phase_weights": phase_weights,
        "worker_distribution": {
            "slowloris_workers": 0.40, "api_flood_workers": 0.25,
            "cookie_poison_workers": 0.15, "chunked_bomb_workers": 0.10,
            "login_flood_workers": 0.10,
        },
        "aggressive_start": not bool(p.waf),
        "login_endpoints": [
            f"{scheme}://{domain}/login",
            f"{scheme}://{domain}/auth/login",
            f"{scheme}://{domain}/student/login",
            f"{scheme}://{domain}/parent/login",
            f"{scheme}://{domain}/api/auth/login",
            f"{scheme}://{domain}/api/login",
        ],
        "session_cookies": [
            "PHPSESSID", "sessionid", "laravel_session",
            "django_sessionid", "JSESSIONID",
            "ASP.NET_SessionId", "connect.sid",
        ],
    }


def determine_spa_config(profile: SiteProfile,
                         html: str = "") -> Dict[str, Any]:
    """SPA/React specific attack configuration.

    Args:
        profile: The site profile with discovered information.
        html: Optional raw HTML content for SPA detection.

    Returns:
        Dictionary with SPA configuration parameters.
    """
    p = profile
    if not is_spa(p, html):
        return {"enabled": False}

    return {
        "enabled": True,
        "framework": detect_spa_framework(p) or "Unknown SPA",
        "is_nextjs": is_nextjs(p, html),
        "has_graphql": has_graphql(p, html),
        "api_endpoints": p.api_endpoints,
        "graphql_endpoint": find_graphql_endpoint(p, html),
        "spa_routes": extract_spa_routes(p),
        "next_data_routes": extract_next_data_routes(p, html),
        "worker_weights": {
            "api_pct": 0.40,
            "graphql_pct": 0.20 if has_graphql(p, html) else 0,
            "spa_route_pct": 0.15,
            "ssr_render_pct": 0.10 if is_nextjs(p, html) else 0,
            "login_pct": 0.05 if p.forms else 0,
            "slowloris_pct": 0.05,
            "resource_pct": 0.05,
        },
    }
