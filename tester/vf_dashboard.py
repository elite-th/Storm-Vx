#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DashboardRenderer — Extracted from VFTester God Class.

v22: Redesigned terminal dashboard with:
  - Sparkline RPS trend chart (real-time mini graph)
  - Labeled dividers for visual section separation
  - Gradient progress bars with smooth color transitions
  - Key-value aligned formatting
  - Improved live log with color-coded status badges
  - Phase indicator (RAMP / PEAK / HOLD / SHRINK)
  - Connection pool stats with reuse rate bar
  - Auto terminal width detection
  - Theme-aware box styles (rounded, heavy, double, single)

Handles all dashboard/UI rendering for the VFTester attack engine.
This module is responsible for:
  - Real-time dashboard rendering (workers, health, RPS, live log)
  - Scan summary display (reconnaissance results)
  - Strategy display box (selected strategy + vectors)
  - Surgical hints display
  - ASCII art banner
  - Countdown display
  - Attack started message
  - Final attack report
  - User confirmation dialog
"""

from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Any, Sequence
from collections import deque


from logging_config import get_logger
logger = get_logger(__name__)

from vf_common import (
    C, T, set_theme, detect_terminal_width,
    box_top, box_bottom, box_mid,
    box_line, box_line_centered, box_line_right, box_divider,
    health_bar, worker_bar, mini_bar, progress_bar_detailed,
    mode_icon, sparkline, kv_line, severity_icon, _strip_ansi,
)
from finder.site_profile import SiteProfile
from config.defaults import DASHBOARD_MAX_RPS_HISTORY


class DashboardRenderer:
    """Renders all dashboard/UI elements for the VFTester attack engine.

    v22: Enhanced with sparklines, labeled dividers, phase indicators,
    and gradient bars.

    Usage:
        renderer = DashboardRenderer(stats, health_monitor, live_log, ...)
        renderer.print_banner(url, strategy, ...)
        renderer.print_dashboard(cur, max_w, strategy, health)
        renderer.print_final_report(stats, active_plugins)
    """

    # v22: RPS history buffer for sparkline (keep last 60 data points = ~1 min)
    MAX_RPS_HISTORY = DASHBOARD_MAX_RPS_HISTORY  # W2.4

    def __init__(self, stats, health_monitor, live_log, active_plugins_getter,
                 pool_stats=None):
        """Initialize the dashboard renderer.

        Args:
            stats: Stats object for request statistics.
            health_monitor: ServerHealthMonitor instance.
            live_log: LiveLog instance for recent request log.
            active_plugins_getter: Callable returning Dict[str, PluginInterface]
                                   of currently active plugins.
            pool_stats: ConnectionPoolStats instance (optional).
        """
        self.stats = stats
        self.health_monitor = health_monitor
        self.live_log = live_log
        self._get_active_plugins = active_plugins_getter
        self._pool_stats = pool_stats
        # v22: RPS history for sparkline chart
        self._rps_history: deque = deque(maxlen=self.MAX_RPS_HISTORY)
        # v22: Phase tracking
        self._phase = "RAMP"
        self._phase_since = time.time()

    def _record_rps(self) -> None:
        """Record current RPS for sparkline history.

        v26: Uses rolling RPS (3s window) for more accurate display.
        Falls back to overall average if rolling window has no data yet.
        """
        rps = getattr(self.stats, 'rps_rolling', 0) or self.stats.requests_per_second
        self._rps_history.append(rps)

    def _update_phase(self, health: float, fail_rate: float,
                      s5xx_rate: float, workers: int, max_workers: int) -> str:
        """Determine the current attack phase for display.

        v28: Redesigned for attack tool context.
        - Server 5xx errors = PRESSURE (attack is working), not SHRINK
        - Only show SHRINK when CLIENT connectivity is broken (high timeout)
        - Added PRESSURE phase when server is struggling under attack load
        BUG-FIX v32: Use non_timeout_fail_rate for SHRINK decision to prevent
        phase oscillation. Previously fail_rate included timeouts, so 54%
        timeout rate caused fail_rate > 0.6 → SHRINK, then back → PEAK.
        Now only non-timeout failures trigger SHRINK.
        """
        old_phase = self._phase

        # v28: Compute timeout rate for CLIENT connectivity assessment
        total = max(getattr(self.stats, 'total', 1), 1)
        timeout_rate = getattr(self.stats, 'timeout_errors', 0) / total

        # BUG-FIX v32: Compute non-timeout fail rate for accurate phase.
        # The old fail_rate includes timeouts which makes it misleading —
        # 54% timeout rate means fail_rate=0.54 which triggers SHRINK,
        # but the attack IS working (server is struggling).
        non_timeout_fail_rate = max(fail_rate - timeout_rate, 0)

        if health < 0.15 and timeout_rate > 0.5:
            new_phase = "CRITICAL"  # Client can't reach server at all
        elif timeout_rate > 0.7 and non_timeout_fail_rate > 0.3:
            new_phase = "SHRINK"    # Client connectivity severely degraded
        elif s5xx_rate > 0.2 and timeout_rate < 0.3:
            new_phase = "PRESSURE"  # v28: Server struggling = attack working!
        elif workers >= max_workers * 0.9 and health > 0.5:
            new_phase = "PEAK"      # BUG-FIX v32: Only PEAK if healthy
        elif health > 0.5 and non_timeout_fail_rate < 0.3:
            new_phase = "RAMP"
        else:
            new_phase = "HOLD"

        if new_phase != old_phase:
            self._phase = new_phase
            self._phase_since = time.time()

        return self._phase

    def _phase_badge(self) -> str:
        """Return a colored phase badge string."""
        phase_colors = {
            "RAMP":     T("success"),
            "PEAK":     T("warning"),
            "HOLD":     T("info"),
            "PRESSURE": C.M,          # v28: Magenta — server under pressure
            "SHRINK":   C.ORANGE,
            "CRITICAL": T("danger"),
        }
        color = phase_colors.get(self._phase, T("dim"))
        elapsed = time.time() - self._phase_since
        return f"{color}◆ {self._phase}{C.RS} {C.DM}{elapsed:.0f}s{C.RS}"

    def _get_width(self) -> int:
        """Get dashboard width, auto-detecting terminal size."""
        try:
            from config.defaults import DASHBOARD_WIDTH
            return DASHBOARD_WIDTH
        except ImportError:
            return detect_terminal_width()

    def print_dashboard(self, cur: int, max_w: int, strategy: str, health: float):
        """Print real-time hacker-style dashboard with live request log.

        v22: Sparkline RPS chart, labeled dividers, gradient bars,
        phase indicator, and improved live log.
        """
        W = self._get_width()
        s = self.stats

        # Record RPS for sparkline
        self._record_rps()

        # Compute rates
        total = max(s.total, 1)
        fail_rate = s.fail / total
        s5xx_rate = s.server_errors / total
        timeout_rate = s.timeout_errors / total
        ok_pct = s.ok / total * 100
        fail_pct = s.fail / total * 100

        # Update phase
        phase = self._update_phase(health, fail_rate, s5xx_rate, cur, max_w)

        # ── Header with phase badge ──
        print(box_top(W))
        phase_badge = self._phase_badge()
        dur_str = f"{s.duration:.1f}s"
        print(box_line(
            f"{T('info')}VF_TESTER{C.RS}  {phase_badge}  "
            f"{C.DM}{' ' * max(W - 50, 1)}{C.RS} "
            f"{T('dim')}{C.ICON_CLOCK} {dur_str}{C.RS}", W))

        # ── Workers + HP with gradient bars ──
        w_bar = worker_bar(cur, max_w, width=22)
        w_pct = cur / max(max_w, 1) * 100
        print(box_line(f"{T('info')}WORKERS{C.RS} [{w_bar}] {T('accent')}{cur:,}{C.RS}/{T('dim')}{max_w:,}{C.RS} ({w_pct:.0f}%)", W))

        h_bar = health_bar(health, width=22)
        h_pct = health * 100
        if health > 0.7:
            h_status = f"{T('success')}HEALTHY{C.RS}"
        elif health > 0.4:
            h_status = f"{T('warning')}WARNING{C.RS}"
        else:
            h_status = f"{T('danger')}CRITICAL{C.RS}"
        print(box_line(f"{T('info')}HP     {C.RS}[{h_bar}] {h_pct:.0f}% {h_status}", W))

        # ── RPS sparkline trend ──
        if len(self._rps_history) >= 3:
            chart = sparkline(list(self._rps_history), width=min(30, W - 30))
            print(box_line(f"{T('info')}TREND  {C.RS}{chart}  {T('dim')}last {len(self._rps_history)}s{C.RS}", W))

        # ── Key metrics row ──
        print(box_line(
            f"{T('info')}RPS{C.RS}    {T('accent')}{max(getattr(s, 'rps_rolling', 0), s.requests_per_second):,.0f}{C.RS}  "
            f"{C.VB}  {T('info')}RT{C.RS} {T('warning')}{s.avg_response_time*1000:.0f}ms{C.RS}  "
            f"{C.VB}  {T('info')}STRATEGY{C.RS} {T('primary')}{strategy}{C.RS}", W))

        # ── Stats section with labeled divider ──
        print(box_divider("RESULTS", W))
        print(box_line(
            f" {T('success')}{C.ICON_OK}{C.RS} {T('success')}OK{C.RS}       {s.ok:>7,}  ({ok_pct:.0f}%)  {mini_bar(ok_pct/100, width=12)}", W))
        print(box_line(
            f" {T('danger')}{C.ICON_FAIL}{C.RS} {T('danger')}FAIL{C.RS}     {s.fail:>7,}  ({fail_pct:.0f}%)  {mini_bar(fail_pct/100, width=12)}", W))
        print(box_line(
            f" {T('warning')}{C.ICON_BOLT}{C.RS} {T('warning')}RATELIM{C.RS}  {s.rate_limited:>7,}", W))

        # ── Errors section ──
        print(box_divider("ERRORS", W))
        s5xx_info = f"{T('danger')}{s.server_errors:>7,}{C.RS}" if s.server_errors > 0 else f"{C.DM}      0{C.RS}"
        to_info = f"{T('danger')}{s.timeout_errors:>7,}{C.RS}" if s.timeout_errors > 0 else f"{C.DM}      0{C.RS}"
        print(box_line(f" {T('danger')}{C.ICON_WARN}{C.RS} 5xx{C.RS}      {s5xx_info}      {T('danger')}TIMEOUT{C.RS} {to_info}", W))

        # Active plugins count
        active_plugins = self._get_active_plugins()
        active_with_workers = sum(1 for p in active_plugins.values() if p.worker_count > 0)
        print(box_line(
            f" {T('info')}{C.ICON_EYE}{C.RS} {T('info')}PLUGINS{C.RS}  {T('accent')}{active_with_workers}{C.RS} active", W))

        # Connection pool stats
        if self._pool_stats is not None:
            ps = self._pool_stats.get_stats()
            if ps.get("total", 0) > 0:
                reuse_rate = ps.get("reuse_rate", 0)
                reuse_bar = mini_bar(reuse_rate, width=8)
                print(box_line(
                    f" {T('info')}POOL{C.RS}    {ps['active']} active  {reuse_bar} {reuse_rate:.0%} reuse", W))

        # Target selector stats
        total_alive = 0
        total_dead = 0
        avg_pacer_mult = 0.0
        pacer_count = 0
        for pname, plugin in active_plugins.items():
            try:
                ps = plugin.get_stats()
                total_alive += ps.get("alive_targets", 0)
                total_dead += ps.get("dead_targets", 0)
                if "pacer_multiplier" in ps:
                    avg_pacer_mult += ps["pacer_multiplier"]
                    pacer_count += 1
            except (AttributeError, TypeError, KeyError):
                pass
        if total_alive > 0 or total_dead > 0:
            target_info = f"{T('success')}{total_alive}{C.RS} alive"
            if total_dead > 0:
                target_info += f" {T('danger')}{total_dead}{C.RS} dead"
            print(box_line(f" {T('info')}{C.ICON_TARGET}{C.RS} {T('info')}TARGETS{C.RS} {target_info}", W))
        if pacer_count > 0 and avg_pacer_mult / pacer_count > 1.1:
            pacer_avg = avg_pacer_mult / pacer_count
            print(box_line(f" {T('warning')}{C.ICON_CLOCK}{C.RS} {T('warning')}PACER{C.RS}   {pacer_avg:.1f}x delay (WAF-aware)", W))

        # ── Warning when health is low ──
        if health < 0.4:
            print(box_mid(W))
            print(box_line_centered(f"{T('danger')}{C.ICON_SKULL} SERVER HEALTH CRITICAL! {C.ICON_SKULL}{C.RS}", W))
        elif health < 0.7:
            print(box_mid(W))
            print(box_line_centered(f"{T('warning')}{C.ICON_WARN} Server health degraded {C.ICON_WARN}{C.RS}", W))

        # ── Error summary when fail rate is high ──
        if fail_pct > 70 and s.error_types:
            top_errors = sorted(s.error_types.items(), key=lambda x: x[1], reverse=True)[:3]
            err_str = " | ".join(f"{err[:18]}:{cnt}" for err, cnt in top_errors)
            print(box_mid(W))
            print(box_line(f"{T('dim')}  ERRORS: {err_str}{C.RS}", W))

        # ── Live Log section with labeled divider ──
        log_lines = self.live_log.get_lines()
        if log_lines:
            print(box_divider("LIVE LOG", W))
            shown_modes = set()
            entries = log_lines[-5:]  # v22: show 5 entries instead of 4
            for idx, entry in enumerate(entries):
                mode = entry.get("mode", "")
                err = entry.get("err", "")
                if err and mode in shown_modes:
                    continue
                if err:
                    shown_modes.add(mode)
                is_last = (idx == len(entries) - 1)
                prefix = f"{T('primary')}└{C.RS}" if is_last else f"{T('primary')}├{C.RS}"
                icon = mode_icon(mode)
                code = entry.get("code", 0)
                rt = entry.get("rt", 0)
                url = entry.get("url", "")
                url_short = url[:30] + "…" if len(url) > 30 else url

                # v22: Color-coded status badge
                if err:
                    status_badge = f"{T('danger')}ERR{C.RS}"
                elif code >= 500:
                    status_badge = f"{T('danger')}{code}{C.RS}"
                elif code >= 400:
                    status_badge = f"{T('warning')}{code}{C.RS}"
                elif code >= 300:
                    status_badge = f"{T('info')}{code}{C.RS}"
                else:
                    status_badge = f"{T('success')}{code}{C.RS}"

                if err:
                    err_short = err[:15]
                    log_text = f"{prefix} {icon}{mode:<8} {status_badge} {err_short} {C.DM}{url_short}{C.RS}"
                else:
                    log_text = f"{prefix} {icon}{mode:<8} {status_badge} {rt*1000:>5.0f}ms {C.DM}{url_short}{C.RS}"

                print(box_line(log_text, W))

        print(box_bottom(W))

    def print_scan_summary(self, profile: SiteProfile | Dict[str, Any], attack: Dict[str, Any],
                           detected_waf: str | None, detected_cms: str | None):
        """Print the RECONNAISSANCE SUMMARY box.

        v22: Uses labeled dividers and severity indicators.
        """
        W = self._get_width()

        waf_strategy = attack.get("waf_strategy", {})
        risk_notes = attack.get("risk_notes", [])

        # ─── Scan Summary Box ───
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

    def print_strategy_box(self, strategy: str, vectors: List[str],
                           strategy_reason: str = "",
                           surgical_analysis: List[str] | None = None):
        """Print the strategy selection box with vectors and reasons.

        v22: Enhanced with severity-colored reasons and compact vector grid.
        """
        W = self._get_width()

        # ─── Strategy Box ───
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

        # ─── Surgical hints (if available) ───
        if surgical_analysis:
            print()
            print(box_top(W))
            print(box_line_centered(f"{T('success')}{C.ICON_GEM}  SURGICAL TARGETS  {C.ICON_GEM}{C.RS}", W))
            print(box_mid(W))
            for note in surgical_analysis[:5]:
                print(box_line(f"  {T('success')}▸{C.RS} {note}", W))
            print(box_bottom(W))

        print()

    def confirm_attack(self, domain: str, authorized_only: bool,
                       stop_event) -> bool:
        """Ask user for confirmation before launching the attack.

        v27: Requires domain confirmation if --authorized-only is set.
        """
        if authorized_only:
            print(f"  {C.BD}{T('danger')}[AUTHORIZED-ONLY]{C.RS} {C.W}Type the target domain to confirm: {T('accent')}{domain}{C.RS}")
            try:
                confirmation = input(f"  {C.Y}> {C.RS}").strip()
            except (EOFError, KeyboardInterrupt):
                confirmation = ""
            if confirmation != domain:
                print(f"\n  {C.R}[ABORT] Domain confirmation failed — '{confirmation}' does not match '{domain}'{C.RS}\n")
                stop_event.set()
                return False
            print(f"  {C.G}[AUTHORIZED] Domain confirmed: {domain}{C.RS}")

        print(f"  {C.BD}{T('accent')}[?]{C.RS} {C.W}Do you want to launch the attack? {C.BD}[Y/n]{C.RS} ", end="", flush=True)
        try:
            answer = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer in ("n", "no", "nej", "خیر"):
            print(f"\n  {C.Y}[ABORT] Attack cancelled by user.{C.RS}\n")
            stop_event.set()
            return False
        print()
        return True

    def print_banner(self, url: str, strategy: str,
                     detected_waf: str | None, detected_cms: str | None,
                     is_aspnet: bool, is_wordpress: bool,
                     origin_ips: List[str], vectors: List[str],
                     actual_max: int, initial_workers: int, step: int,
                     page_count: int, resource_count: int,
                     registry_names: List[str], registry_errors: Dict[str, str],
                     selected_plugins: Dict[str, Any]):
        """Print the ASCII art banner + target info box.

        v22: Cleaner layout with labeled dividers and aligned key-values.
        """
        from config.defaults import DASHBOARD_WIDTH, UI_THEME
        W = DASHBOARD_WIDTH
        set_theme(UI_THEME)

        # ── ASCII Art Banner ──
        print()
        print(box_top(W))
        print(box_line_centered(f"{T('primary')}██╗   ██╗██╗   ██╗███████╗███████╗████████╗{C.RS}", W))
        print(box_line_centered(f"{T('primary')}██║   ██║██║   ██║██╔════╝██╔════╝╚══██╔══╝{C.RS}", W))
        print(box_line_centered(f"{T('primary')}██║   ██║██║   ██║█████╗  ███████╗   ██║{C.RS}   ", W))
        print(box_line_centered(f"{T('primary')}╚██╗ ██╔╝██║   ██║██╔══╝  ╚════██║   ██║{C.RS}   ", W))
        print(box_line_centered(f"{T('primary')} ╚████╔╝ ╚██████╔╝███████╗███████║   ██║{C.RS}   ", W))
        print(box_line_centered(f"{T('primary')}  ╚═══╝   ╚═════╝ ╚══════╝╚══════╝   ╚═╝{C.RS}   ", W))
        print(box_mid(W))
        print(box_line_centered(f"{T('accent')}{C.ICON_SWORD}  ADAPTIVE ATTACK ENGINE v3.0  {C.ICON_SWORD}{C.RS}", W))
        print(box_bottom(W))

        # ── Target Info Box ──
        print(box_top(W))
        print(box_line(f"{T('info')}TARGET{C.RS}   {C.W}{url}{C.RS}", W))
        print(box_line(f"{T('info')}STRATEGY{C.RS} {T('accent')}{strategy}{C.RS}", W))
        if detected_waf:  print(box_line(f"{T('info')}WAF{C.RS}      {T('danger')}{detected_waf} {C.ICON_SHLD}{C.RS}", W))
        if detected_cms:  print(box_line(f"{T('info')}CMS{C.RS}      {T('warning')}{detected_cms}{C.RS}", W))
        if is_aspnet:     print(box_line(f"{T('info')}ASP.NET{C.RS}  {C.M}ViewState Attack Enabled{C.RS}", W))
        if is_wordpress:  print(box_line(f"{T('info')}WordPress{C.RS} {C.CY}XMLRPC + WP-Login Enabled{C.RS}", W))
        if origin_ips:    print(box_line(f"{T('info')}ORIGIN{C.RS}   {T('success')}{len(origin_ips)} IPs found (CDN bypass){C.RS}", W))

        print(box_divider("CONFIG", W))
        print(box_line(f"{T('info')}VECTORS{C.RS}  {C.W}{', '.join(vectors)}{C.RS}", W))
        print(box_line(f"{T('info')}WORKERS{C.RS}  {C.BD}{actual_max:,}{C.RS} (initial: {initial_workers}, step: +{step})", W))
        print(box_line(f"{T('info')}TARGETS{C.RS}  {page_count} pages | {resource_count} resources", W))

        # Plugin info
        if registry_names:
            print(box_line(f"{T('info')}PLUGINS{C.RS}  {T('success')}{len(registry_names)} discovered{C.RS} ({', '.join(registry_names)})", W))
        else:
            print(box_line(f"{T('info')}PLUGINS{C.RS}  {T('warning')}None discovered{C.RS}", W))

        if selected_plugins:
            sel_names = ', '.join(selected_plugins.keys())
            print(box_line(f"{T('info')}ACTIVE{C.RS}   {T('success')}{sel_names}{C.RS}", W))
        else:
            print(box_line(f"{T('info')}ACTIVE{C.RS}   {T('danger')}No plugins selected!{C.RS}", W))

        if registry_errors:
            print(box_mid(W))
            for mk, mv in registry_errors.items():
                print(box_line(f"{T('warning')}{C.ICON_WARN} {mk}: {mv}{C.RS}", W))

        print(box_mid(W))
        print(box_line(f"{T('info')}MODE{C.RS}     {T('accent')}AUTO-ESCALATE{C.RS} — gradually increasing pressure", W))
        print(box_line(f"{T('info')}CTRL{C.RS}     {C.BD}[+]{C.RS} Workers  {C.BD}[-]{C.RS} Remove  {C.BD}[q]{C.RS} Quit", W))
        print(box_bottom(W))

    async def print_countdown(self):
        """Print the 3-2-1 countdown before attack starts.

        v22: Sparkline-style progress bar with theme-aware box.
        """
        W = self._get_width()

        for i in [3, 2, 1]:
            pct = i / 3
            bar_filled = int(pct * 24)
            bar_empty = 24 - bar_filled
            print()
            print(box_top(W))
            print(box_line_centered(f"{T('accent')}{C.ICON_SWORD}  LAUNCHING IN  {C.BD}{i}{C.RS}  {C.ICON_SWORD}{C.RS}", W))
            print(box_line_centered(f"{T('danger')}{'▓' * bar_filled}{C.DM}{'░' * bar_empty}{C.RS}", W))
            print(box_bottom(W))
            await asyncio.sleep(1)

    def print_attack_started(self):
        """Print the ATTACK STARTED message."""
        W = self._get_width()

        print()
        print(box_top(W))
        print(box_line_centered(f"{T('danger')}{C.ICON_SKULL}  ATTACK STARTED!  {C.ICON_SKULL}{C.RS}", W))
        print(box_line_centered(f"{T('danger')}{'▓' * 24}{C.RS}", W))
        print(box_bottom(W))
        print(flush=True)

    def print_final_report(self, stats, active_plugins: Dict[str, Any]):
        """Print the final attack report.

        v22: Labeled dividers, gradient bars, severity indicators,
        and sparkline history summary.
        """
        W = self._get_width()
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
        if len(self._rps_history) >= 5:
            chart = sparkline(list(self._rps_history), width=min(36, W - 20))
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
