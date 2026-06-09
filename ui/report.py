#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ui.report — Scan report renderer for Storm-Vx.

v22: Redesigned with:
  - Labeled dividers for clear section separation
  - Severity indicators for security findings
  - Technology list with gradient confidence bars
  - Compact security headers with status badges
  - Better visual hierarchy with themed icons
  - Attack profile summary with aligned key-values

Renders the reconnaissance scan report to the terminal using themed
box-drawing characters. Moved from VF_FINDER.py's render_report()
function for UI/logging separation.
"""
from __future__ import annotations


from vf_common import (
    C, T, set_theme, detect_terminal_width,
    box_top, box_bottom, box_mid,
    box_line, box_line_centered, box_divider,
    mini_bar, severity_icon, kv_line, sparkline,
)
from ui.terminal import TerminalUI


class ScanReporter:
    """Renders the reconnaissance scan report.

    v22: Redesigned with severity indicators, labeled dividers,
    and improved visual hierarchy.

    Usage::

        ui = TerminalUI("MATRIX", width=72)
        reporter = ScanReporter(ui)
        reporter.render(profile)
    """

    def __init__(self, ui: TerminalUI):
        """Initialize ScanReporter.

        Args:
            ui: TerminalUI instance for themed output.
        """
        self.ui = ui

    def render(self, profile) -> None:
        """Render a beautiful hacker-style scan report to the terminal.

        v22: Uses labeled dividers, severity indicators, and gradient bars.

        Args:
            profile: SiteProfile object from finder.engine.
        """
        from config.defaults import UI_THEME, DASHBOARD_WIDTH
        set_theme(UI_THEME)
        W = DASHBOARD_WIDTH

        p = profile

        # ── ASCII Art Banner ──
        print()
        print(box_top(W))
        print(box_line_centered(f"{T('primary')}\u2588\u2588\u2502   \u2588\u2588\u2502\u2588\u2588\u2502   \u2588\u2588\u2502\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2502\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2502\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2502{C.RS}", W))
        print(box_line_centered(f"{T('primary')}\u2588\u2588\u2502   \u2588\u2588\u2502\u2588\u2588\u2502   \u2588\u2588\u2502\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2502\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2502\u255a\u2550\u2550\u2550\u2588\u2588\u2554\u2550\u2550\u2502{C.RS}", W))
        print(box_line_centered(f"{T('primary')}\u2588\u2588\u2502   \u2588\u2588\u2502\u2588\u2588\u2502   \u2588\u2588\u2502\u2588\u2588\u2588\u2588\u2588\u2588\u2502  \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2502   \u2588\u2588\u2502{C.RS}   ", W))
        print(box_line_centered(f"{T('primary')}\u255a\u2588\u2588\u2502 \u2588\u2588\u2550\u2588\u2588\u2502   \u2588\u2588\u2502\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u2502  \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2588\u2588\u2502   \u2588\u2588\u2502{C.RS}   ", W))
        print(box_line_centered(f"{T('primary')} \u255a\u2588\u2588\u2588\u2588\u2550\u2588\u2502 \u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2550\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2502\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2502   \u2588\u2588\u2502{C.RS}   ", W))
        print(box_line_centered(f"{T('primary')}  \u255a\u2550\u2550\u2550\u2550\u2550\u2502 \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2502 \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2502\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2502   \u255a\u2550\u2550\u2502{C.RS}   ", W))
        print(box_mid(W))
        print(box_line_centered(f"{T('accent')}{C.ICON_EYE}  RECONNAISSANCE ENGINE v3.0  {C.ICON_EYE}{C.RS}", W))
        print(box_bottom(W))

        # ═══ TARGET ═══
        print(box_top(W))
        print(box_line_centered(f"{T('info')}{C.ICON_TARGET}  TARGET  {C.ICON_TARGET}{C.RS}", W))
        print(box_line(f"  {T('info')}URL{C.RS}       {C.W}{p.url}{C.RS}", W))
        print(box_line(f"  {T('info')}HOST{C.RS}      {p.host}:{p.port}", W))
        print(box_line(f"  {T('info')}IPS{C.RS}       {', '.join(p.ip_addresses) if p.ip_addresses else 'Unknown'}", W))
        if p.hosting_provider:
            print(box_line(f"  {T('info')}HOSTING{C.RS}   {p.hosting_provider}", W))
        # BUG-031: ssl_enabled can be None (cannot determine) — handle explicitly
        if p.ssl_enabled is True:
            ssl_display = f"  {T('info')}SSL{C.RS}       {T('success')}Yes{C.RS}"
        elif p.ssl_enabled is False:
            ssl_display = f"  {T('info')}SSL{C.RS}       {T('danger')}No{C.RS}"
        else:
            ssl_display = f"  {T('info')}SSL{C.RS}       {T('warning')}Unknown{C.RS}"
        print(box_line(ssl_display, W))

        # ═══ SERVER ═══
        print(box_divider("SERVER", W))
        print(box_line(f"  {T('info')}SOFTWARE{C.RS}  {T('warning')}{p.server or 'Unknown'}{C.RS}", W))
        if p.server_version:
            print(box_line(f"  {T('info')}VERSION{C.RS}   {p.server_version}", W))
        if p.os_guess:
            print(box_line(f"  {T('info')}OS{C.RS}       {p.os_guess}", W))

        # ═══ TECHNOLOGIES ═══
        if p.technologies:
            print(box_divider(f"TECHNOLOGIES ({len(p.technologies)})", W))
            for tech in p.technologies:
                conf_bar = mini_bar(tech["confidence"], width=10)
                print(box_line(
                    f"  {T('primary')}{tech['name']:<22}{C.RS} {conf_bar} {tech['confidence']:.0%} {C.DM}{tech['category']}{C.RS}", W))

        # ═══ WAF ═══
        if p.waf:
            print(box_divider("WAF DETECTED", W))
            print(box_line(f"  {severity_icon('critical')} {T('danger')}{p.waf}{C.RS} ({p.waf_confidence:.0%})", W))
            bypass = p.attack_profile.get("waf_strategy", {}).get("bypass_methods", [])
            if bypass:
                print(box_line(f"  {T('info')}BYPASS{C.RS}   {', '.join(bypass)}", W))

        # ═══ CMS ═══
        if p.cms:
            print(box_divider("CMS", W))
            print(box_line(f"  {T('warning')}{p.cms}{C.RS}", W))

        # ═══ PERFORMANCE ═══
        print(box_divider("PERFORMANCE", W))
        print(box_line(f"  {T('info')}STATUS{C.RS}    {p.status_code}", W))
        print(box_line(f"  {T('info')}SIZE{C.RS}      {p.page_size:,}B ({_human_size(p.page_size)})", W))
        print(box_line(f"  {T('info')}BASELINE{C.RS}  {p.baseline_rt*1000:.0f}ms", W))
        if p.rate_limit_detected:
            print(box_line(f"  {severity_icon('high')} {T('danger')}DETECTED at ~{p.rate_limit_threshold} req/s{C.RS}", W))
        else:
            print(box_line(f"  {severity_icon('low')} {T('success')}Not detected{C.RS}", W))

        # ═══ CONTENT ═══
        print(box_divider("CONTENT", W))
        # Compact content stats in a row
        content_items = [
            f"{T('info')}FORMS{C.RS} {len(p.forms)}",
            f"{T('info')}HIDDEN{C.RS} {len(p.hidden_fields)}",
            f"{T('info')}SCRIPTS{C.RS} {len(p.scripts)}",
        ]
        print(box_line(f"  {'  │  '.join(content_items)}", W))
        content_items2 = [
            f"{T('info')}LINKS{C.RS} {len(p.links)}",
            f"{T('info')}APIS{C.RS} {len(p.api_endpoints)}",
        ]
        if p.viewstate_present:
            content_items2.append(f"{T('warning')}VIEWSTATE{C.RS} {T('warning')}PRESENT{C.RS}")
        print(box_line(f"  {'  │  '.join(content_items2)}", W))

        if p.login_fields:
            print(box_line(f"  {T('info')}LOGIN{C.RS}     user={p.login_fields.get('username','?')} pass={p.login_fields.get('password','?')}", W))

        # ═══ SECURITY HEADERS ═══
        print(box_divider("SECURITY HEADERS", W))
        for header, info in p.security_headers.items():
            if info["present"]:
                print(box_line(f"  {severity_icon('low')} {T('success')}{header}{C.RS}: {C.DM}{info['value'][:35]}{C.RS}", W))
            else:
                print(box_line(f"  {severity_icon('high')} {T('danger')}{header}{C.RS}: {T('danger')}MISSING{C.RS}", W))

        # ═══ SENSITIVE FILES ═══
        if p.sensitive_files:
            print(box_divider("SENSITIVE FILES", W))
            for sf in p.sensitive_files:
                print(box_line(f"  {severity_icon('critical')} {T('danger')}{sf}{C.RS}", W))

        # ═══ ATTACK PROFILE ═══
        if p.attack_profile:
            ap = p.attack_profile
            print(box_divider("ATTACK PROFILE", W))
            print(box_line(f"  {T('info')}STRATEGY{C.RS}  {T('accent')}{ap.get('recommended_strategy', 'N/A')}{C.RS}", W))
            vectors = ap.get('attack_vectors', [])
            if vectors:
                print(box_line(f"  {T('info')}VECTORS{C.RS}   {', '.join(vectors)}", W))
            wc = ap.get('worker_config', {})
            print(box_line(
                f"  {T('info')}WORKERS{C.RS}   init={wc.get('initial_workers','?')} "
                f"max={wc.get('max_workers','?')} step={wc.get('step','?')}", W))

        print(box_bottom(W))
        print()


# ─── Helper (local copy to avoid circular imports) ──────────────────────────

def _human_size(size: int) -> str:
    """Convert bytes to human-readable size string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
