#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF Report — Post-Attack Report Generator                            ║
║     Part of the STORM_VX Infrastructure                                 ║
║                                                                           ║
║  Collects data during an attack session and generates a detailed         ║
║  HTML report with timeline, statistics, method breakdown, WAF            ║
║  interaction summary, and future recommendations.                        ║
║                                                                           ║
║  Usage:                                                                  ║
║    from infra.vf_report import AttackReporter                            ║
║    reporter = AttackReporter("https://target.com")                       ║
║    reporter.add_event("phase_change", {"phase": "ramp"})                ║
║    reporter.update_stats({"rps": 500, "success_rate": 0.85})            ║
║    path = reporter.generate_html()                                       ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import os
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict


# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Reporter
# ═══════════════════════════════════════════════════════════════════════════════

class AttackReporter:
    """
    Post-Attack Report Generator for STORM_VX.

    Collects attack data in real-time (timeline events, statistics,
    methods, WAF interactions) and generates a professional HTML report
    with dark-theme styling matching STORM_VX branding.
    """

    def __init__(self, target: str, output_dir: str = "reports"):
        """
        Initialize AttackReporter.

        Args:
            target: Target URL of the attack.
            output_dir: Directory to save reports.
        """
        self.target = target
        self.start_time: float = time.time()
        self.end_time: Optional[float] = None

        # Resolve output directory
        if not os.path.isabs(output_dir):
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            output_dir = os.path.join(project_root, output_dir)
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        # Data collection
        self.timeline: List[Dict[str, Any]] = []
        self.stats_history: List[Dict[str, Any]] = []
        self.current_stats: Dict[str, Any] = {}
        self.methods_used: Dict[str, Dict[str, Any]] = {}
        self.waf_interactions: List[Dict[str, Any]] = []
        self.server_health_history: List[Dict[str, Any]] = []

    # ─── Data Collection ───────────────────────────────────────────────────

    def add_event(self, event_type: str, data: Dict):
        """
        Add an event to the attack timeline.

        Args:
            event_type: Type of event (e.g., 'start', 'phase_change',
                        'waf_detected', 'peak_rps', 'crash_mode', 'stop').
            data: Event data dictionary.
        """
        event = {
            "timestamp": time.time(),
            "time_offset": round(time.time() - self.start_time, 2),
            "time_str": datetime.now().strftime("%H:%M:%S"),
            "event_type": event_type,
            "data": data,
        }
        self.timeline.append(event)

        # Auto-track special events
        if event_type == "waf_detected":
            self.waf_interactions.append({
                "time": event["time_str"],
                "waf": data.get("waf_name", "Unknown"),
                "action": data.get("action", "detected"),
                "block_rate": data.get("block_rate", 0),
            })
        elif event_type == "method_result":
            method = data.get("method", "unknown")
            if method not in self.methods_used:
                self.methods_used[method] = {
                    "total": 0, "success": 0, "fail": 0,
                    "rate_limited": 0, "avg_rt": 0, "rt_samples": [],
                }
            m = self.methods_used[method]
            m["total"] += 1
            if data.get("success", False):
                m["success"] += 1
            else:
                m["fail"] += 1
            if data.get("rate_limited", False):
                m["rate_limited"] += 1
            rt = data.get("response_time", 0)
            if rt > 0:
                m["rt_samples"].append(rt)
                m["avg_rt"] = sum(m["rt_samples"]) / len(m["rt_samples"])
        elif event_type == "server_health":
            self.server_health_history.append({
                "time": event["time_str"],
                "time_offset": event["time_offset"],
                "health": data.get("health", 1.0),
                "trend": data.get("trend", "unknown"),
            })

    def update_stats(self, stats: Dict):
        """
        Update current attack statistics.

        Args:
            stats: Dictionary with current stats (rps, success_rate,
                   workers, bypass_level, etc.).
        """
        self.current_stats = dict(stats)
        snapshot = {
            "timestamp": time.time(),
            "time_offset": round(time.time() - self.start_time, 2),
        }
        snapshot.update(stats)
        self.stats_history.append(snapshot)

    def mark_end(self):
        """Mark the attack as ended."""
        self.end_time = time.time()
        self.add_event("stop", {
            "duration": round(self.end_time - self.start_time, 2),
        })

    # ─── Report Generation ─────────────────────────────────────────────────

    def generate_html(self) -> str:
        """
        Generate a detailed HTML report.

        Returns:
            File path of the generated HTML report.
        """
        end = self.end_time or time.time()
        duration = round(end - self.start_time, 2)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{ts}.html"
        filepath = os.path.join(self.output_dir, filename)

        stats = self.current_stats
        total_requests = stats.get("total", 0)
        success_rate = stats.get("success_rate", 0)
        peak_rps = stats.get("peak_rps", 0)
        avg_rps = stats.get("avg_rps", 0)

        # Build timeline HTML rows
        timeline_rows = self._build_timeline_rows()

        # Build method breakdown HTML
        method_rows = self._build_method_rows()

        # Build WAF interaction HTML
        waf_rows = self._build_waf_rows()

        # Build RPS chart (inline SVG)
        rps_chart = self._build_rps_chart()

        # Build health chart
        health_chart = self._build_health_chart()

        # Recommendations
        recommendations = self._generate_recommendations()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>STORM_VX Attack Report — {self._esc(self.target)}</title>
<style>
  :root {{
    --bg-primary: #0a0a0f;
    --bg-secondary: #12121a;
    --bg-card: #1a1a2e;
    --bg-card-hover: #22223a;
    --border: #2a2a40;
    --text-primary: #e0e0e8;
    --text-secondary: #8888a0;
    --accent-red: #ff4466;
    --accent-green: #44ff88;
    --accent-blue: #4488ff;
    --accent-yellow: #ffaa22;
    --accent-purple: #aa44ff;
    --accent-cyan: #44ddff;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: var(--bg-primary);
    color: var(--text-primary);
    font-family: 'Segoe UI', 'Consolas', 'Courier New', monospace;
    line-height: 1.6;
    padding: 20px;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{
    text-align: center;
    padding: 40px 20px;
    border-bottom: 2px solid var(--accent-red);
    margin-bottom: 30px;
  }}
  .header h1 {{
    font-size: 28px;
    color: var(--accent-red);
    letter-spacing: 3px;
    margin-bottom: 10px;
  }}
  .header .subtitle {{
    color: var(--text-secondary);
    font-size: 14px;
  }}
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-bottom: 30px;
  }}
  .stat-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    text-align: center;
  }}
  .stat-card .label {{
    color: var(--text-secondary);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
  }}
  .stat-card .value {{
    font-size: 28px;
    font-weight: bold;
  }}
  .stat-card .value.red {{ color: var(--accent-red); }}
  .stat-card .value.green {{ color: var(--accent-green); }}
  .stat-card .value.blue {{ color: var(--accent-blue); }}
  .stat-card .value.yellow {{ color: var(--accent-yellow); }}
  .stat-card .value.purple {{ color: var(--accent-purple); }}
  .section {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 25px;
    margin-bottom: 25px;
  }}
  .section h2 {{
    color: var(--accent-cyan);
    font-size: 18px;
    margin-bottom: 15px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
  }}
  th {{
    text-align: left;
    padding: 10px 12px;
    background: var(--bg-secondary);
    color: var(--accent-cyan);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    color: var(--text-primary);
    font-size: 13px;
  }}
  tr:hover {{ background: var(--bg-card-hover); }}
  .tag {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: bold;
  }}
  .tag-red {{ background: rgba(255,68,102,0.2); color: var(--accent-red); }}
  .tag-green {{ background: rgba(68,255,136,0.2); color: var(--accent-green); }}
  .tag-yellow {{ background: rgba(255,170,34,0.2); color: var(--accent-yellow); }}
  .tag-blue {{ background: rgba(68,136,255,0.2); color: var(--accent-blue); }}
  .chart-container {{
    background: var(--bg-secondary);
    border-radius: 8px;
    padding: 15px;
    margin: 10px 0;
    overflow-x: auto;
  }}
  .recommendations li {{
    padding: 8px 0;
    border-bottom: 1px solid var(--border);
    color: var(--text-primary);
  }}
  .recommendations li:last-child {{ border-bottom: none; }}
  .footer {{
    text-align: center;
    padding: 20px;
    color: var(--text-secondary);
    font-size: 12px;
    border-top: 1px solid var(--border);
    margin-top: 30px;
  }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>STORM_VX</h1>
    <div class="subtitle">Post-Attack Report — {self._esc(self.target)}</div>
    <div class="subtitle">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
  </div>

  <!-- Summary Cards -->
  <div class="summary-grid">
    <div class="stat-card">
      <div class="label">Target</div>
      <div class="value blue" style="font-size:16px;word-break:break-all;">{self._esc(self.target)}</div>
    </div>
    <div class="stat-card">
      <div class="label">Duration</div>
      <div class="value yellow">{self._fmt_duration(duration)}</div>
    </div>
    <div class="stat-card">
      <div class="label">Total Requests</div>
      <div class="value red">{total_requests:,}</div>
    </div>
    <div class="stat-card">
      <div class="label">Success Rate</div>
      <div class="value {'green' if success_rate > 0.7 else 'yellow' if success_rate > 0.4 else 'red'}">{success_rate:.1%}</div>
    </div>
    <div class="stat-card">
      <div class="label">Peak RPS</div>
      <div class="value purple">{peak_rps:,}</div>
    </div>
    <div class="stat-card">
      <div class="label">Avg RPS</div>
      <div class="value blue">{avg_rps:,}</div>
    </div>
  </div>

  <!-- RPS Over Time -->
  <div class="section">
    <h2>RPS Over Time</h2>
    <div class="chart-container">
      {rps_chart}
    </div>
  </div>

  <!-- Server Health -->
  <div class="section">
    <h2>Server Health Over Time</h2>
    <div class="chart-container">
      {health_chart}
    </div>
  </div>

  <!-- Timeline -->
  <div class="section">
    <h2>Event Timeline</h2>
    <table>
      <thead>
        <tr><th>Time</th><th>Offset</th><th>Type</th><th>Details</th></tr>
      </thead>
      <tbody>
        {timeline_rows}
      </tbody>
    </table>
  </div>

  <!-- Method Breakdown -->
  <div class="section">
    <h2>Attack Method Breakdown</h2>
    <table>
      <thead>
        <tr><th>Method</th><th>Total</th><th>Success</th><th>Failed</th><th>Rate Limited</th><th>Success %</th><th>Avg RT</th></tr>
      </thead>
      <tbody>
        {method_rows}
      </tbody>
    </table>
  </div>

  <!-- WAF Interactions -->
  <div class="section">
    <h2>WAF Interaction Summary</h2>
    <table>
      <thead>
        <tr><th>Time</th><th>WAF</th><th>Action</th><th>Block Rate</th></tr>
      </thead>
      <tbody>
        {waf_rows}
      </tbody>
    </table>
  </div>

  <!-- Recommendations -->
  <div class="section">
    <h2>Recommendations for Future Attacks</h2>
    <ul class="recommendations">
      {recommendations}
    </ul>
  </div>

  <div class="footer">
    STORM_VX Attack Report — {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} — FOR AUTHORIZED TESTING ONLY
  </div>

</div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  {C.G}[REPORT] HTML report generated{C.RS}")
        print(f"  {C.DM}  Path: {filepath}{C.RS}")

        return filepath

    def generate_summary(self) -> str:
        """
        Generate a plain-text summary of the attack.

        Returns:
            Text summary string.
        """
        end = self.end_time or time.time()
        duration = round(end - self.start_time, 2)
        stats = self.current_stats

        total = stats.get("total", 0)
        success_rate = stats.get("success_rate", 0)
        peak_rps = stats.get("peak_rps", 0)
        bypass_level = stats.get("bypass_level", "N/A")
        waf = stats.get("waf", "None")

        lines = [
            "=" * 50,
            "STORM_VX Attack Summary",
            "=" * 50,
            f"Target:       {self.target}",
            f"Duration:     {self._fmt_duration(duration)}",
            f"Total Req:    {total:,}",
            f"Success Rate: {success_rate:.1%}",
            f"Peak RPS:     {peak_rps:,}",
            f"Avg RPS:      {stats.get('avg_rps', 0):,}",
            f"WAF:          {waf}",
            f"Bypass Level: {bypass_level}",
            "",
        ]

        if self.methods_used:
            lines.append("Methods Used:")
            for method, mstats in self.methods_used.items():
                sr = mstats["success"] / max(mstats["total"], 1)
                lines.append(f"  {method}: {mstats['total']} req, {sr:.0%} success, "
                             f"avg RT {mstats['avg_rt']*1000:.0f}ms")

        if self.waf_interactions:
            lines.append(f"\nWAF Interactions: {len(self.waf_interactions)}")

        lines.append("")
        lines.append("=" * 50)

        summary = "\n".join(lines)

        print(f"  {C.G}[REPORT] Text summary generated{C.RS}")

        return summary

    # ─── HTML Builder Helpers ──────────────────────────────────────────────

    def _build_timeline_rows(self) -> str:
        """Build HTML table rows for the timeline."""
        if not self.timeline:
            return '<tr><td colspan="4" style="color:var(--text-secondary);">No events recorded</td></tr>'

        rows = []
        for event in self.timeline:
            etype = event["event_type"]
            tag_class = {
                "start": "tag-green", "stop": "tag-red",
                "waf_detected": "tag-yellow", "phase_change": "tag-blue",
                "crash_mode": "tag-red", "peak_rps": "tag-green",
            }.get(etype, "tag-blue")

            details = self._esc(json.dumps(event["data"], default=str))[:200]
            rows.append(
                f'<tr>'
                f'<td>{event["time_str"]}</td>'
                f'<td>{event["time_offset"]:.1f}s</td>'
                f'<td><span class="tag {tag_class}">{self._esc(etype)}</span></td>'
                f'<td style="font-size:11px;color:var(--text-secondary);">{details}</td>'
                f'</tr>'
            )
        return "\n".join(rows)

    def _build_method_rows(self) -> str:
        """Build HTML table rows for method breakdown."""
        if not self.methods_used:
            return '<tr><td colspan="7" style="color:var(--text-secondary);">No method data</td></tr>'

        rows = []
        for method, m in self.methods_used.items():
            sr = m["success"] / max(m["total"], 1)
            sr_class = "green" if sr > 0.7 else "yellow" if sr > 0.4 else "red"
            rows.append(
                f'<tr>'
                f'<td><span class="tag tag-blue">{self._esc(method)}</span></td>'
                f'<td>{m["total"]:,}</td>'
                f'<td style="color:var(--accent-green);">{m["success"]:,}</td>'
                f'<td style="color:var(--accent-red);">{m["fail"]:,}</td>'
                f'<td style="color:var(--accent-yellow);">{m["rate_limited"]:,}</td>'
                f'<td class="{sr_class}">{sr:.1%}</td>'
                f'<td>{m["avg_rt"]*1000:.0f}ms</td>'
                f'</tr>'
            )
        return "\n".join(rows)

    def _build_waf_rows(self) -> str:
        """Build HTML table rows for WAF interactions."""
        if not self.waf_interactions:
            return '<tr><td colspan="4" style="color:var(--text-secondary);">No WAF interactions</td></tr>'

        rows = []
        for w in self.waf_interactions:
            br = w.get("block_rate", 0)
            br_class = "red" if br > 0.6 else "yellow" if br > 0.3 else "green"
            rows.append(
                f'<tr>'
                f'<td>{w["time"]}</td>'
                f'<td>{self._esc(w["waf"])}</td>'
                f'<td>{self._esc(w["action"])}</td>'
                f'<td class="{br_class}">{br:.0%}</td>'
                f'</tr>'
            )
        return "\n".join(rows)

    def _build_rps_chart(self) -> str:
        """Build an inline SVG chart for RPS over time."""
        if len(self.stats_history) < 2:
            return '<p style="color:var(--text-secondary);text-align:center;">Not enough data for chart</p>'

        width = 800
        height = 200
        padding = 40
        chart_w = width - 2 * padding
        chart_h = height - 2 * padding

        rps_values = [s.get("rps", s.get("rrps", 0)) for s in self.stats_history]
        max_rps = max(rps_values) if rps_values else 1
        if max_rps == 0:
            max_rps = 1

        points = []
        n = len(rps_values)
        for i, rps in enumerate(rps_values):
            x = padding + (i / max(n - 1, 1)) * chart_w
            y = padding + chart_h - (rps / max_rps) * chart_h
            points.append(f"{x:.1f},{y:.1f}")

        polyline = " ".join(points)

        svg = (
            f'<svg width="{width}" height="{height}" '
            f'style="background:var(--bg-secondary);">'
            f'<text x="{padding}" y="{padding-10}" fill="var(--text-secondary)" font-size="11">'
            f'RPS (max: {max_rps:,.0f})</text>'
            f'<line x1="{padding}" y1="{padding}" x2="{padding}" y2="{padding+chart_h}" '
            f'stroke="var(--border)" stroke-width="1"/>'
            f'<line x1="{padding}" y1="{padding+chart_h}" x2="{padding+chart_w}" y2="{padding+chart_h}" '
            f'stroke="var(--border)" stroke-width="1"/>'
            f'<polyline points="{polyline}" fill="none" stroke="var(--accent-green)" '
            f'stroke-width="2" stroke-linejoin="round"/>'
            f'</svg>'
        )
        return svg

    def _build_health_chart(self) -> str:
        """Build an inline SVG chart for server health over time."""
        if len(self.server_health_history) < 2:
            return '<p style="color:var(--text-secondary);text-align:center;">Not enough health data for chart</p>'

        width = 800
        height = 200
        padding = 40
        chart_w = width - 2 * padding
        chart_h = height - 2 * padding

        health_values = [h["health"] for h in self.server_health_history]
        points = []
        n = len(health_values)
        for i, health in enumerate(health_values):
            x = padding + (i / max(n - 1, 1)) * chart_w
            y = padding + chart_h - (health) * chart_h
            points.append(f"{x:.1f},{y:.1f}")

        polyline = " ".join(points)

        svg = (
            f'<svg width="{width}" height="{height}" '
            f'style="background:var(--bg-secondary);">'
            f'<text x="{padding}" y="{padding-10}" fill="var(--text-secondary)" font-size="11">'
            f'Server Health (0.0-1.0)</text>'
            f'<line x1="{padding}" y1="{padding}" x2="{padding}" y2="{padding+chart_h}" '
            f'stroke="var(--border)" stroke-width="1"/>'
            f'<line x1="{padding}" y1="{padding+chart_h}" x2="{padding+chart_w}" y2="{padding+chart_h}" '
            f'stroke="var(--border)" stroke-width="1"/>'
            f'<polyline points="{polyline}" fill="none" stroke="var(--accent-yellow)" '
            f'stroke-width="2" stroke-linejoin="round"/>'
            f'</svg>'
        )
        return svg

    def _generate_recommendations(self) -> str:
        """Generate HTML recommendations for future attacks."""
        recs = []
        stats = self.current_stats
        success_rate = stats.get("success_rate", 0)
        waf = stats.get("waf", "None")

        if success_rate < 0.3:
            recs.append(
                "Low success rate detected. Consider increasing bypass level, "
                "rotating proxies more aggressively, or switching attack vectors."
            )
        if waf and waf != "None":
            recs.append(
                f"WAF ({waf}) was active. Try different bypass strategies: "
                "header rotation, TLS fingerprint rotation, or CDN edge rotation."
            )
        if self.methods_used:
            best_method = max(
                self.methods_used.items(),
                key=lambda x: x[1]["success"] / max(x[1]["total"], 1)
            )
            recs.append(
                f"Most effective method: <strong>{best_method[0]}</strong> "
                f"({best_method[1]['success']/max(best_method[1]['total'],1):.0%} success rate). "
                "Prioritize this method in future attacks."
            )
        if self.server_health_history:
            last_health = self.server_health_history[-1]["health"]
            if last_health < 0.4:
                recs.append(
                    "Server health was critically low at end of attack. "
                    "Crash mode may be effective — increase workers to finish the job."
                )
            elif last_health > 0.8:
                recs.append(
                    "Server health remained high. The target has significant capacity. "
                    "Consider increasing worker count or using multiple attack vectors simultaneously."
                )

        if not recs:
            recs.append("Attack completed successfully. No specific recommendations at this time.")

        items = "\n".join(f"<li>{r}</li>" for r in recs)
        return items

    # ─── Utility ───────────────────────────────────────────────────────────

    @staticmethod
    def _esc(text: str) -> str:
        """Escape HTML special characters."""
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        """Format duration in human-readable form."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            m = int(seconds // 60)
            s = int(seconds % 60)
            return f"{m}m {s}s"
        else:
            h = int(seconds // 3600)
            m = int((seconds % 3600) // 60)
            return f"{h}h {m}m"


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VF Report — Post-Attack Report Generator")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--input", help="JSON file with attack data")
    parser.add_argument("--output-dir", default="reports", help="Output directory")

    args = parser.parse_args()
    reporter = AttackReporter(args.target, output_dir=args.output_dir)

    if args.input:
        try:
            with open(args.input, "r", encoding="utf-8") as f:
                data = json.load(f)
            for event in data.get("timeline", []):
                reporter.add_event(event.get("event_type", "unknown"), event.get("data", {}))
            if data.get("stats"):
                reporter.update_stats(data["stats"])
            reporter.mark_end()
        except Exception as e:
            print(f"  {C.R}[REPORT] Error loading input: {e}{C.RS}")
            exit(1)
    else:
        reporter.add_event("start", {"target": args.target})
        reporter.mark_end()

    path = reporter.generate_html()
    print(f"  {C.G}[REPORT] Report saved to: {path}{C.RS}")
