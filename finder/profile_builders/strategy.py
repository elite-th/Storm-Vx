"""Strategy determination builder.

Extracted from AttackProfileGenerator._determine_strategy() and
_determine_strategy_reason() (Task 2.3).

Pure functions — take profile + needed params, return a value.
"""

from __future__ import annotations

from typing import List

from finder.site_profile import SiteProfile
from finder.vf_tech_helpers import is_spa, has_graphql


def determine_strategy(profile: SiteProfile) -> str:
    """Determine the overall attack strategy (composite).

    Args:
        profile: The site profile with discovered information.

    Returns:
        Strategy name string.
    """
    p = profile
    has_waf = bool(p.waf)
    _is_spa = is_spa(p)
    has_cms = bool(p.cms)
    has_aspnet = bool(p.viewstate_present)
    has_php = bool(p.backend_lang and "PHP" in (p.backend_lang or ""))
    has_api = bool(p.api_endpoints)
    is_edu = p.site_category == 'educational'

    if is_edu and has_waf:
        return "EDU_WAF_HYBRID"
    elif is_edu:
        return "EDU_FOCUSED"
    elif has_waf and _is_spa:
        return "WAF_SPA_HYBRID"
    elif has_waf and has_api:
        return "WAF_API_HYBRID"
    elif has_waf:
        return "WAF_BYPASS_FOCUSED"
    elif _is_spa:
        return "SPA_FOCUSED"
    elif has_cms:
        return "CMS_EXPLOIT_FOCUSED"
    elif has_aspnet:
        return "ASP_NET_FOCUSED"
    elif has_php:
        return "PHP_FOCUSED"
    elif has_api:
        return "API_FOCUSED"
    else:
        return "GENERIC_FLOOD"


def determine_strategy_reason(profile: SiteProfile, html: str = "") -> str:
    """Explain WHY a strategy was chosen.

    Args:
        profile: The site profile with discovered information.
        html: Optional raw HTML content for pattern matching.

    Returns:
        Human-readable strategy reason string.
    """
    p = profile
    reasons: List[str] = []

    if p.waf:
        reasons.append(f"WAF detected: {p.waf} -> WAF bypass methods prioritized")
    if p.cdn:
        reasons.append(f"CDN detected: {p.cdn} -> Origin IP bypass attempted")
    if is_spa(p, html):
        spa_fws = [t['name'] for t in p.technologies
                   if t['name'] in ['React', 'Vue.js', 'Angular', 'Next.js', 'Nuxt.js', 'Svelte']
                   and t.get('confidence', 0) > 0.2]
        reasons.append(f"SPA detected ({', '.join(spa_fws)}) -> API backend is the real target")
    if p.cms:
        reasons.append(f"CMS detected: {p.cms} -> CMS-specific attack vectors enabled")
    if p.viewstate_present:
        reasons.append("ASP.NET ViewState detected -> ViewState flood enabled")
    if p.backend_lang and "PHP" in (p.backend_lang or ""):
        reasons.append("PHP backend detected -> PHP-specific attack vectors enabled")
    if p.api_endpoints:
        reasons.append(f"API endpoints found ({len(p.api_endpoints)}) -> API flood enabled")

    missing_headers = []
    if not p.security_headers.get("Content-Security-Policy", {}).get("present"):
        missing_headers.append("CSP")
    if not p.security_headers.get("X-Frame-Options", {}).get("present"):
        missing_headers.append("X-Frame-Options")
    if not p.security_headers.get("X-Content-Type-Options", {}).get("present"):
        missing_headers.append("X-Content-Type-Options")
    if missing_headers:
        reasons.append(f"Missing security headers: {', '.join(missing_headers)} -> easier to exploit")

    if not p.rate_limit_detected:
        reasons.append("No rate limiting detected -> flood attacks viable")
    else:
        reasons.append(f"Rate limiting detected ({p.rate_limit_threshold}/s) -> evasion required")

    if p.origin_ips:
        reasons.append(f"Origin IPs found ({len(p.origin_ips)}): {', '.join(p.origin_ips[:3])} -> CDN bypass possible")
    else:
        if p.cdn or p.waf:
            reasons.append("No origin IPs found -> CDN bypass NOT possible, attacking through CDN")

    if p.ssl_enabled and p.headers.get('Strict-Transport-Security'):
        reasons.append("HSTS enabled -> SSL required, no HTTP downgrade")

    return "\n".join(f"  • {r}" for r in reasons) if reasons else "  • Default strategy based on general analysis"
