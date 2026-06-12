#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DashboardRenderer — Terminal dashboard for the VFTester attack engine.

Handles real-time dashboard rendering, ASCII art banner, countdown,
attack started message, and user confirmation. Panel rendering
(effectiveness, scan summary, strategy, final report) is delegated
to vf_dashboard_panels.py for Law 14 compliance.
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
from tester.vf_dashboard_panels import (
    render_effectiveness_panel,
    render_scan_summary,
    render_strategy_box,
    render_final_report,
)


__all__ = ["DashboardRenderer"]


class DashboardRenderer:
    """Renders all dashboard/UI elements for the VFTester attack engine.

    Usage:
        renderer = DashboardRenderer(stats, health_monitor, live_log, ...)
        renderer.print_banner(url, strategy, ...)
        renderer.print_dashboard(cur, max_w, strategy, health)
        renderer.print_final_report(stats, active_plugins)
    """

    MAX_RPS_HISTORY = DASHBOARD_MAX_RPS_HISTORY

    def __init__(self, stats, health_monitor, live_log, active_plugins_getter,
                 pool_stats=None, effectiveness_tracker=None):
        """Initialize the dashboard renderer.

        Args:
            stats: Stats object for request statistics.
            health_monitor: ServerHealthMonitor instance.
            live_log: LiveLog instance for recent request log.
            active_plugins_getter: Callable returning Dict[str, PluginInterface].
            pool_stats: ConnectionPoolStats instance (optional).
            effectiveness_tracker: PluginEffectivenessTracker instance (optional).
        """
        self.stats = stats
        self.health_monitor = health_monitor
        self.live_log = live_log
        self._get_active_plugins = active_plugins_getter
        self._pool_stats = pool_stats
        self._effectiveness_tracker = effectiveness_tracker
        self._rps_history: deque = deque(maxlen=self.MAX_RPS_HISTORY)
        self._phase = "RAMP"
        self._phase_since = time.monotonic()

    def _record_rps(self) -> None:
        """Record current RPS for sparkline history."""
        rps = getattr(self.stats, 'rps_rolling', 0) or self.stats.requests_per_second
        self._rps_history.append(rps)

    def _update_phase(self, health: float, fail_rate: float,
                      s5xx_rate: float, workers: int, max_workers: int) -> str:
        """Determine the current attack phase for display.

        v28: Redesigned for attack tool context. Server 5xx = PRESSURE.
        BUG-FIX v32: Use non_timeout_fail_rate for SHRINK decision.
        """
        old_phase = self._phase

        total = max(getattr(self.stats, 'total', 1), 1)
        timeout_rate = getattr(self.stats, 'timeout_errors', 0) / total
        non_timeout_fail_rate = max(fail_rate - timeout_rate, 0)

        if health < 0.15 and timeout_rate > 0.5:
            new_phase = "CRITICAL"
        elif timeout_rate > 0.7 and non_timeout_fail_rate > 0.3:
            new_phase = "SHRINK"
        elif s5xx_rate > 0.2 and timeout_rate < 0.3:
            new_phase = "PRESSURE"
        elif workers >= max_workers * 0.9 and health > 0.5:
            new_phase = "PEAK"
        elif health > 0.5 and non_timeout_fail_rate < 0.3:
            new_phase = "RAMP"
        else:
            new_phase = "HOLD"

        if new_phase != old_phase:
            self._phase = new_phase
            self._phase_since = time.monotonic()

        return self._phase

    def _phase_badge(self) -> str:
        """Return a colored phase badge string."""
        phase_colors = {
            "RAMP":     T("success"),
            "PEAK":     T("warning"),
            "HOLD":     T("info"),
            "PRESSURE": C.M,
            "SHRINK":   C.ORANGE,
            "CRITICAL": T("danger"),
        }
        color = phase_colors.get(self._phase, T("dim"))
        elapsed = time.monotonic() - self._phase_since
        return f"{color}◆ {self._phase}{C.RS} {C.DM}{elapsed:.0f}s{C.RS}"

    def _get_width(self) -> int:
        """Get dashboard width, auto-detecting terminal size."""
        try:
            from config.defaults import DASHBOARD_WIDTH
            return DASHBOARD_WIDTH
        except ImportError:
            return detect_terminal_width()

    def print_dashboard(self, cur: int, max_w: int, strategy: str, health: float):
        """Print real-time hacker-style dashboard with live request log."""
        W = self._get_width()
        s = self.stats

        self._record_rps()

        # Compute rates
        total = max(s.total, 1)
        fail_rate = s.fail / total
        s5xx_rate = s.server_errors / total
        timeout_rate = s.timeout_errors / total
        ok_pct = s.ok / total * 100
        fail_pct = s.fail / total * 100

        phase = self._update_phase(health, fail_rate, s5xx_rate, cur, max_w)

        # Header with phase badge
        print(box_top(W))
        phase_badge = self._phase_badge()
        dur_str = f"{s.duration:.1f}s"
        print(box_line(
            f"{T('info')}VF_TESTER{C.RS}  {phase_badge}  "
            f"{C.DM}{' ' * max(W - 50, 1)}{C.RS} "
            f"{T('dim')}{C.ICON_CLOCK} {dur_str}{C.RS}", W))

        # Workers + HP with gradient bars
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

        # RPS sparkline trend
        if len(self._rps_history) >= 3:
            chart = sparkline(list(self._rps_history), width=min(30, W - 30))
            print(box_line(f"{T('info')}TREND  {C.RS}{chart}  {T('dim')}last {len(self._rps_history)}s{C.RS}", W))

        # Key metrics row
        print(box_line(
            f"{T('info')}RPS{C.RS}    {T('accent')}{max(getattr(s, 'rps_rolling', 0), s.requests_per_second):,.0f}{C.RS}  "
            f"{C.VB}  {T('info')}RT{C.RS} {T('warning')}{s.avg_response_time*1000:.0f}ms{C.RS}  "
            f"{C.VB}  {T('info')}STRATEGY{C.RS} {T('primary')}{strategy}{C.RS}", W))

        # Stats section
        print(box_divider("RESULTS", W))
        print(box_line(
            f" {T('success')}{C.ICON_OK}{C.RS} {T('success')}OK{C.RS}       {s.ok:>7,}  ({ok_pct:.0f}%)  {mini_bar(ok_pct/100, width=12)}", W))
        print(box_line(
            f" {T('danger')}{C.ICON_FAIL}{C.RS} {T('danger')}FAIL{C.RS}     {s.fail:>7,}  ({fail_pct:.0f}%)  {mini_bar(fail_pct/100, width=12)}", W))
        print(box_line(
            f" {T('warning')}{C.ICON_BOLT}{C.RS} {T('warning')}RATELIM{C.RS}  {s.rate_limited:>7,}", W))

        # Errors section
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

        # Effectiveness panel (delegated)
        eff_panel = render_effectiveness_panel(self._effectiveness_tracker, W)
        if eff_panel:
            print(eff_panel)

        # Target selector + pacer stats
        total_alive, total_dead, avg_pacer_mult, pacer_count = 0, 0, 0.0, 0
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

        # Health warnings
        if health < 0.4:
            print(box_mid(W))
            print(box_line_centered(f"{T('danger')}{C.ICON_SKULL} SERVER HEALTH CRITICAL! {C.ICON_SKULL}{C.RS}", W))
        elif health < 0.7:
            print(box_mid(W))
            print(box_line_centered(f"{T('warning')}{C.ICON_WARN} Server health degraded {C.ICON_WARN}{C.RS}", W))

        # Error summary
        if fail_pct > 70 and s.error_types:
            top_errors = sorted(s.error_types.items(), key=lambda x: x[1], reverse=True)[:3]
            err_str = " | ".join(f"{err[:18]}:{cnt}" for err, cnt in top_errors)
            print(box_mid(W))
            print(box_line(f"{T('dim')}  ERRORS: {err_str}{C.RS}", W))

        # Live Log section
        log_lines = self.live_log.get_lines()
        if log_lines:
            print(box_divider("LIVE LOG", W))
            shown_modes = set()
            entries = log_lines[-5:]
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

    def print_effectiveness_panel(self, W: int) -> str:
        """Render the auto-select effectiveness tracking panel."""
        return render_effectiveness_panel(self._effectiveness_tracker, W)

    def print_scan_summary(self, profile: SiteProfile | Dict[str, Any], attack: Dict[str, Any],
                           detected_waf: str | None, detected_cms: str | None):
        """Print the RECONNAISSANCE SUMMARY box."""
        W = self._get_width()
        render_scan_summary(profile, attack, detected_waf, detected_cms, W)

    def print_strategy_box(self, strategy: str, vectors: List[str],
                           strategy_reason: str = "",
                           surgical_analysis: List[str] | None = None):
        """Print the strategy selection box with vectors and reasons."""
        W = self._get_width()
        render_strategy_box(strategy, vectors, strategy_reason, surgical_analysis, W)

    def confirm_attack(self, domain: str, authorized_only: bool,
                       stop_event) -> bool:
        """Ask user for confirmation before launching the attack."""
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
        """Print the ASCII art banner + target info box."""
        from config.defaults import DASHBOARD_WIDTH, UI_THEME
        W = DASHBOARD_WIDTH
        set_theme(UI_THEME)

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

        # Target Info Box
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
        """Print the 3-2-1 countdown before attack starts."""
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
        """Print the final attack report."""
        W = self._get_width()
        render_final_report(stats, active_plugins, list(self._rps_history), W)
