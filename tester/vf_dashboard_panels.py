#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tester.vf_dashboard_panels — Extracted panel rendering functions.

W4.3 EXTRACTION: Extracted from vf_dashboard.py for Law 14 compliance.
Contains standalone functions for rendering specific dashboard panels.
The DashboardRenderer imports and delegates to these functions.

Each function takes explicit parameters (no self dependency) for
clean separation and testability.
"""
from __future__ import annotations

from typing import Dict, List, Any

from logging_config import get_logger
logger = get_logger(__name__)

from vf_common import (
    C, T,
    box_top, box_bottom, box_mid,
    box_line, box_line_centered, box_divider,
    mini_bar, sparkline, severity_icon,
)
from finder.site_profile import SiteProfile


__all__ = [
    "render_effectiveness_panel",
    "render_scan_summary",
    "render_strategy_box",
    "render_final_report",
]


def render_effectiveness_panel(tracker: Any, W: int) -> str:
    """Render the auto-select effectiveness tracking panel.

    Shows current phase, top-K plugin ranking, disabled plugins,
    and worker allocation summary.

    Args:
        tracker: PluginEffectivenessTracker instance.
        W: Dashboard width.

    Returns:
        Formatted panel string, or empty string if tracker is None.
    """
    if tracker is None:
        return ""

    lines: list[str] = []

    # Divider header
    lines.append(box_divider(f"{C.ICON_TARGET} AUTO-SELECT", W))

    # Phase indicator
    phase = tracker.phase
    phase_colors = {"PROBE": C.Y, "ANALYZE": C.CY, "FOCUS": C.G}
    phase_color = phase_colors.get(phase, C.W)
    lines.append(box_line(
        f" {C.ICON_BOLT} {T('info')}PHASE{C.RS}   {phase_color}{phase}{C.RS}", W))

    # Plugin ranking (top 5)
    ranking = tracker.get_ranking()
    if not ranking:
        lines.append(box_line(f" {C.DM}Waiting for data...{C.RS}", W))
    else:
        scores = tracker.scores
        for i, (name, score) in enumerate(ranking[:5]):
            bar = mini_bar(score / 100, width=12)
            score_obj = scores.get(name)
            if score_obj:
                tier = score_obj.tier.name
                active = f"{C.G}✓{C.RS}" if score_obj.is_active else f"{C.R}✗{C.RS}"
            else:
                tier = "?"
                active = f"{C.DM}?{C.RS}"
            rank_color = T('accent') if i < 3 else T('dim')
            lines.append(box_line(
                f" {rank_color}{i+1}.{C.RS} {name:<16} {bar} {score:>5.1f} {active} {C.DM}{tier}{C.RS}", W))

    # Disabled plugins summary
    disabled = [n for n, s in tracker.scores.items() if not s.is_active]
    if disabled:
        lines.append(box_line(
            f" {C.R}✗{C.RS} {T('danger')}DISABLED{C.RS} {C.DM}{', '.join(disabled[:4])}{C.RS}", W))

    # Worker allocation (if FOCUS phase)
    decision = tracker.last_decision
    if decision.worker_allocation and phase == "FOCUS":
        alloc_items = sorted(decision.worker_allocation.items(), key=lambda x: -x[1])[:5]
        alloc_str = " ".join(f"{n[:8]}:{w}" for n, w in alloc_items)
        lines.append(box_line(
            f" {C.ICON_CHART} {T('info')}ALLOC{C.RS}   {C.DM}{alloc_str}{C.RS}", W))

    return "\n".join(lines)


def render_scan_summary(profile: SiteProfile | Dict[str, Any],
                        attack: Dict[str, Any],
                        detected_waf: str | None,
                        detected_cms: str | None,
                        W: int) -> None:
    """Print the RECONNAISSANCE SUMMARY box.

    Args:
        profile: SiteProfile or dict with scan results.
        attack: Attack configuration dict with waf_strategy and risk_notes.
        detected_waf: Detected WAF name.
        detected_cms: Detected CMS name.
        W: Dashboard width.
    """
    waf_strategy = attack.get("waf_strategy", {})
    risk_notes = attack.get("risk_notes", [])

    print()
    print(box_top(W))
    print(box_line_centered(f"{T('accent')}{C.ICON_EYE}  RECONNAISSANCE SUMMARY  {C.ICON_EYE}{C.RS}", W))

    # Technology stack
    tech_list = profile.get("technologies", []) if isinstance(profile, dict) else getattr(profile, 'technologies', [])
    if tech_list:
        print(box_divider("TECH STACK", W))
        tech_names = [t.get("name", "") if isinstance(t, dict) else str(t) for t in tech_list[:8]]
        print(box_line(f"  {C.W}{', '.join(tech_names)}{C.RS}", W))

    # WAF info
    if detected_waf:
        print(box_divider("WAF", W))
        bypass_methods = waf_strategy.get("bypass_methods", [])
        bypass_str = ', '.join(bypass_methods[:4]) if bypass_methods else 'none'
        print(box_line(f"  {T('danger')}{detected_waf} {C.ICON_SHLD}{C.RS}  {T('dim')}bypass: {bypass_str}{C.RS}", W))

    # CMS
    if detected_cms:
        print(box_line(f"  {T('warning')}CMS{C.RS}     {T('warning')}{detected_cms}{C.RS}", W))

    # Backend language
    backend = profile.get("backend_lang") if isinstance(profile, dict) else getattr(profile, 'backend_lang', None)
    if backend:
        print(box_line(f"  {T('info')}BACKEND{C.RS} {backend}", W))

    # API endpoints
    api_eps = profile.get("api_endpoints", []) if isinstance(profile, dict) else getattr(profile, 'api_endpoints', [])
    if api_eps:
        print(box_line(f"  {T('success')}API{C.RS}     {len(api_eps)} endpoints found", W))

    # Origin IPs
    origin_ips = profile.get("origin_ips", []) if isinstance(profile, dict) else getattr(profile, 'origin_ips', [])
    if origin_ips:
        print(box_line(f"  {T('success')}ORIGIN{C.RS}  {len(origin_ips)} IPs (CDN bypass)", W))

    # Rate limit
    rl_detected = profile.get("rate_limit_detected", False) if isinstance(profile, dict) else getattr(profile, 'rate_limit_detected', False)
    if rl_detected:
        rl_threshold = profile.get("rate_limit_threshold") if isinstance(profile, dict) else getattr(profile, 'rate_limit_threshold', None)
        print(box_line(f"  {T('warning')}RATE-LIM{C.RS} Detected ({rl_threshold}/s)", W))
    else:
        print(box_line(f"  {T('success')}RATE-LIM{C.RS} Not detected", W))

    # Security headers
    sec_headers = profile.get("security_headers", {}) if isinstance(profile, dict) else getattr(profile, 'security_headers', {})
    missing = []
    if not sec_headers.get("content_security_policy"): missing.append("CSP")
    if not sec_headers.get("x_frame_options"): missing.append("X-Frame")
    if not sec_headers.get("x_content_type_options"): missing.append("X-Content-Type")
    if missing:
        print(box_line(f"  {T('warning')}MISSING{C.RS}  {', '.join(missing)}", W))

    # Risk notes
    if risk_notes:
        notes_str = ' | '.join(risk_notes[:3])
        print(box_line(f"  {severity_icon('high')} {T('danger')}{notes_str}{C.RS}", W))

    print(box_bottom(W))


def render_strategy_box(strategy: str, vectors: List[str],
                        strategy_reason: str = "",
                        surgical_analysis: List[str] | None = None,
                        W: int = 80) -> None:
    """Print the strategy selection box with vectors and reasons.

    Args:
        strategy: Selected strategy name.
        vectors: List of attack vectors.
        strategy_reason: Reason for strategy selection.
        surgical_analysis: List of surgical target hints.
        W: Dashboard width.
    """
    print()
    print(box_top(W))
    print(box_line_centered(f"{T('primary')}{C.ICON_TARGET}  {strategy}  {C.ICON_TARGET}{C.RS}", W))

    # Vector icons mapping
    vec_icons = {
        "LOGIN_FLOOD": "🔑", "PAGE_FLOOD": "📄", "RESOURCE_FLOOD": "📦",
        "SLOWLORIS": "🐢", "SLOW_POST_READ": "🐌", "API_FLOOD": "🔌",
        "SPA_ROUTE_FLOOD": "⚛", "SSR_RENDER_FLOOD": "🖥", "GRAPHQL_FLOOD": "◈",
        "VIEWSTATE_FLOOD": "🔷", "WP_XMLRPC": "📰", "WP_LOGIN": "🔐",
        "CACHE_DECEPTION_BYPASS": "🎭", "HTTP2_MULTIPLEX": "⚡",
        "ORIGIN_IP_DIRECT": "🎯", "EDU_API_FLOOD": "🎓", "COOKIE_POISON": "🍪",
        "CHUNKED_BOMB": "💣", "SLOW_READ": "📖",
    }

    # Show vectors in a compact grid (3 per line)
    print(box_divider("VECTORS", W))
    vec_lines = []
    current_line = []
    for v in vectors:
        icon = vec_icons.get(v, "▸")
        current_line.append(f"{icon}{C.CY}{v}{C.RS}")
        if len(current_line) >= 3:
            vec_lines.append("  ".join(current_line))
            current_line = []
    if current_line:
        vec_lines.append("  ".join(current_line))

    for vl in vec_lines:
        print(box_line(f"  {vl}", W))

    # Strategy reason with severity coloring
    if strategy_reason:
        reason_lines = [l.strip() for l in strategy_reason.strip().split('\n') if l.strip()][:4]
        print(box_divider("REASON", W))
        for line in reason_lines:
            r = line
            if 'WAF' in r or 'waf' in r.lower():
                r = f'{severity_icon("critical")} {C.R}{r}{C.RS}'
            elif 'CDN' in r or 'cdn' in r.lower():
                r = f'{severity_icon("medium")} {C.Y}{r}{C.RS}'
            elif 'Origin' in r or 'origin' in r.lower():
                r = f'{severity_icon("low")} {C.G}{r}{C.RS}'
            elif 'rate' in r.lower() or 'limit' in r.lower():
                r = f'{severity_icon("high")} {C.M}{r}{C.RS}'
            else:
                r = f'{severity_icon("info")} {T("dim")}{r}{C.RS}'
            print(box_line(f"  {r}", W))

    print(box_bottom(W))

    # Surgical hints (if available)
    if surgical_analysis:
        print()
        print(box_top(W))
        print(box_line_centered(f"{T('success')}{C.ICON_GEM}  SURGICAL TARGETS  {C.ICON_GEM}{C.RS}", W))
        print(box_mid(W))
        for note in surgical_analysis[:5]:
            print(box_line(f"  {T('success')}▸{C.RS} {note}", W))
        print(box_bottom(W))

    print()


def render_final_report(stats: Any, active_plugins: Dict[str, Any],
                        rps_history: list, W: int) -> None:
    """Print the final attack report.

    Args:
        stats: Stats object with request statistics.
        active_plugins: Dict of active plugin instances.
        rps_history: RPS history list for sparkline.
        W: Dashboard width.
    """
    s = stats

    print()
    print(box_top(W))
    print(box_line_centered(f"{T('danger')}{C.ICON_SWORD}  VF_TESTER — ATTACK REPORT  {C.ICON_SWORD}{C.RS}", W))

    # Overview
    print(box_divider("OVERVIEW", W))
    print(box_line(f"  {T('info')}DURATION{C.RS}   {s.duration:.1f}s", W))
    print(box_line(f"  {T('info')}TOTAL{C.RS}      {s.total:,}", W))
    print(box_line(f"  {T('info')}AVG RPS{C.RS}    {T('accent')}{s.requests_per_second:.1f}{C.RS}  {T('dim')}(rolling: {getattr(s, 'rps_rolling', 0):.1f}){C.RS}", W))
    print(box_line(f"  {T('info')}AVG RT{C.RS}     {T('warning')}{s.avg_response_time*1000:.0f}ms{C.RS}", W))

    # RPS trend sparkline
    if len(rps_history) >= 5:
        chart = sparkline(list(rps_history), width=min(36, W - 20))
        print(box_line(f"  {T('info')}RPS TREND{C.RS} {chart}", W))

    # Results
    print(box_divider("RESULTS", W))
    ok_pct = s.ok / max(s.total, 1) * 100
    fail_pct = s.fail / max(s.total, 1) * 100
    print(box_line(f"  {T('success')}{C.ICON_OK}{C.RS} {T('success')}SUCCESSFUL{C.RS}  {s.ok:>7,}  ({ok_pct:.0f}%)  {mini_bar(ok_pct/100, width=12)}", W))
    print(box_line(f"  {T('danger')}{C.ICON_FAIL}{C.RS} {T('danger')}FAILED{C.RS}      {s.fail:>7,}  ({fail_pct:.0f}%)  {mini_bar(fail_pct/100, width=12)}", W))
    print(box_line(f"  {T('warning')}{C.ICON_BOLT}{C.RS} {T('warning')}RATE LIMIT{C.RS} {s.rate_limited:>7,}", W))

    # Errors
    print(box_divider("ERRORS", W))
    print(box_line(f"  {severity_icon('high')} {T('danger')}5xx SERVER{C.RS}  {s.server_errors:>7,}  {mini_bar(s.server_errors / max(s.total, 1), width=10)}", W))
    print(box_line(f"  {severity_icon('medium')} {T('danger')}TIMEOUT{C.RS}     {s.timeout_errors:>7,}  {mini_bar(s.timeout_errors / max(s.total, 1), width=10)}", W))

    # Plugin stats
    if active_plugins:
        print(box_divider("PLUGIN STATISTICS", W))
        for name, plugin in active_plugins.items():
            try:
                ps = plugin.get_stats()
                pt = ps.get('total_requests', 0)
                po = ps.get('success_count', 0)
                pe = ps.get('error_count', 0)
                p_bar = mini_bar(po / max(pt, 1), width=10)
                print(box_line(
                    f"  {T('accent')}{name:<16}{C.RS} t:{pt:>5,}  "
                    f"{T('success')}ok:{po:,}{C.RS}  "
                    f"{T('danger')}err:{pe:,}{C.RS}  {p_bar}", W))
            except (AttributeError, TypeError, KeyError):
                print(box_line(f"  {C.DM}{name}: stats unavailable{C.RS}", W))

    print(box_bottom(W))
    print()
