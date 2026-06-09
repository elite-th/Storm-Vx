"""Risk notes determination builder.

Extracted from AttackProfileGenerator._determine_risk_notes() (Task 2.3).

Pure functions — take profile + needed params, return a value.
"""

from __future__ import annotations

from typing import List

from finder.site_profile import SiteProfile


def determine_risk_notes(profile: SiteProfile) -> List[str]:
    """Generate risk notes and warnings.

    Args:
        profile: The site profile with discovered information.

    Returns:
        List of risk note strings.
    """
    p = profile
    notes: List[str] = []

    if p.waf:
        notes.append(f"WAF detected: {p.waf} (confidence: {p.waf_confidence:.0%}). "
                    "Expect request blocking and potential IP bans.")
    if p.rate_limit_detected:
        notes.append(f"Rate limiting detected at ~{p.rate_limit_threshold} requests. "
                    "Slow ramp-up recommended.")
    if p.security_headers.get("Strict-Transport-Security", {}).get("present"):
        notes.append("HSTS is enabled. SSL bypass may not work.")
    if not p.security_headers.get("Content-Security-Policy", {}).get("present"):
        notes.append("No CSP header. Injection attacks may be easier.")
    if p.sensitive_files:
        notes.append(f"Sensitive files exposed: {', '.join(p.sensitive_files)}. "
                    "Information disclosure risk.")
    if p.viewstate_present:
        notes.append("ASP.NET ViewState detected. ViewState flooding is highly effective.")
    if p.baseline_rt > 3.0:
        notes.append(f"Slow baseline RT ({p.baseline_rt*1000:.0f}ms). "
                    "Server may already be under load or poorly configured.")
    if p.ssl_enabled and p.ssl_info.get("protocol") in ("TLSv1", "TLSv1.1"):
        notes.append("Outdated TLS version detected. May be vulnerable to downgrade attacks.")
    if not notes:
        notes.append("No specific risks identified. Standard attack strategy recommended.")
    return notes
