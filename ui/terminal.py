#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ui.terminal — Centralized terminal UI output for Storm-Vx.

v22: Redesigned with rich formatting capabilities:
  - Spinner animation support (dots, arrows, pulse)
  - Sparkline mini-charts
  - Key-value pair formatting with alignment
  - Table rendering
  - Labeled dividers
  - Gradient text support
  - Severity-colored status lines
  - Theme-aware box styles (rounded, heavy, double, single)
  - Auto terminal width detection
"""
from __future__ import annotations

import sys
import time
from typing import Any, Dict, List, Sequence

from vf_common import (
    THEMES, THEME_NAMES, set_theme, C, T, get_box_chars,
    box_top, box_bottom, box_mid, box_line, box_line_centered,
    box_line_right, box_divider, _strip_ansi, _visible_len,
    sparkline, kv_line, render_table, severity_icon,
    health_bar, worker_bar, mini_bar, progress_bar_detailed,
    detect_terminal_width,
)


class TerminalUI:
    """Centralized terminal UI output for Storm-Vx.

    v22: Rich formatting with theme-aware box styles, sparklines,
    spinners, tables, and key-value alignment.

    Usage::

        ui = TerminalUI("MATRIX", width=72)
        ui.box("Title", ["Line 1", "Line 2"])
        ui.info("Something happened")
        ui.success("It worked!")
        ui.warning("Be careful")
        ui.error("Something broke")
        ui.spinner(3, "Loading")
        ui.sparkline(data, "RPS")
        ui.table(["Name", "Status"], [["Plugin1", "OK"]])
        ui.kv("WORKERS", "500/5000")
        ui.divider("PHASE 2")
        ui.severity("critical", "Server down!")
    """

    def __init__(self, theme_name: str = "MATRIX", width: int = 0):
        """Initialize TerminalUI with a theme and box width.

        Args:
            theme_name: Color theme name (MATRIX, CYBER, PHANTOM, BLOOD,
                        TOXIC, OCEAN, SOLAR, MONO).
            width: Default width for box-drawing. 0 = auto-detect.
        """
        self.theme_name = theme_name
        self.width = width if width > 0 else detect_terminal_width()
        set_theme(theme_name)
        self._C = C
        self._T = T
        self._spinner_idx = 0

    # ─── Box Drawing ────────────────────────────────────────────────────────

    def box(self, title: str, lines: List[str], color: str = "") -> None:
        """Print a framed box with title and content lines.

        Args:
            title: Box title (centered in the top border).
            lines: Content lines to display inside the box.
            color: Optional ANSI color override for the frame.
        """
        c = color or T("primary")
        W = self.width

        print(box_top(W, c))
        print(box_line_centered(f"{T('accent')}{title}{C.RS}", W, c))
        print(box_mid(W, c))
        for line in lines:
            print(box_line(line, W, c))
        print(box_bottom(W, c))

    def box_raw(self, lines: List[str]) -> None:
        """Print pre-formatted box lines without any wrapping.

        Useful when the caller has already constructed lines using
        box_top/box_mid/box_line/box_bottom helpers.

        Args:
            lines: Pre-formatted lines to print.
        """
        for line in lines:
            print(line)

    def divider(self, label: str, color: str = "") -> None:
        """Print a labeled divider line inside a box.

        v22: Embeds the label text into the horizontal rule.
        Like: ╠══ METRICS ══╣

        Args:
            label: Text to embed in the divider.
            color: Optional color override.
        """
        print(box_divider(label, self.width, color))

    # ─── Themed Message Methods ─────────────────────────────────────────────

    def info(self, msg: str) -> None:
        """Print an info message with theme styling."""
        print(f"  {T('info')}{C.ICON_OK}{C.RS} {msg}", flush=True)

    def success(self, msg: str) -> None:
        """Print a success message with theme styling."""
        print(f"  {T('success')}{C.ICON_OK}{C.RS} {msg}", flush=True)

    def warning(self, msg: str) -> None:
        """Print a warning message with theme styling."""
        print(f"  {T('warning')}{C.ICON_WARN}{C.RS} {msg}", flush=True)

    def error(self, msg: str) -> None:
        """Print an error message with theme styling."""
        print(f"  {T('danger')}{C.ICON_FAIL}{C.RS} {msg}", flush=True)

    def log(self, msg: str) -> None:
        """Print a general log message with theme styling."""
        print(f"  {T('info')}\u25cf{C.RS} {msg}", flush=True)

    # ─── v22: Severity-colored status ──────────────────────────────────────

    def severity(self, level: str, msg: str) -> None:
        """Print a severity-colored status message.

        Args:
            level: One of 'critical', 'high', 'medium', 'low', 'info'.
            msg: Message text.
        """
        icon = severity_icon(level)
        print(f"  {icon} {msg}", flush=True)

    # ─── v22: Spinner ──────────────────────────────────────────────────────

    def spinner_frame(self, frames: List[str] | None = None) -> str:
        """Get the next spinner frame character.

        Args:
            frames: Optional custom spinner frames. Defaults to braille dots.

        Returns:
            Current spinner character with theme coloring.
        """
        if frames is None:
            frames = C.SPINNER_DOTS
        frame = frames[self._spinner_idx % len(frames)]
        self._spinner_idx += 1
        return f"{T('accent')}{frame}{C.RS}"

    def spinner(self, count: int = 1, label: str = "",
                frames: List[str] | None = None) -> None:
        """Print animated spinner frames inline.

        Args:
            count: Number of spinner frames to print.
            label: Optional label after the spinner.
            frames: Optional custom spinner frames.
        """
        for _ in range(count):
            frame = self.spinner_frame(frames)
            if label:
                print(f"\r  {frame} {T('dim')}{label}{C.RS}", end="", flush=True)
            else:
                print(f"\r  {frame}", end="", flush=True)
            time.sleep(0.08)

    # ─── v22: Sparkline ────────────────────────────────────────────────────

    def sparkline(self, data: Sequence[float], label: str = "",
                  width: int = 24, color: str = "") -> None:
        """Print a sparkline mini-chart.

        Args:
            data: Sequence of numeric values.
            label: Optional label before the sparkline.
            width: Character width of the sparkline.
            color: Optional color override.
        """
        chart = sparkline(data, width, color)
        if label:
            print(f"  {T('info')}{label}{C.RS} {chart}")
        else:
            print(f"  {chart}")

    def sparkline_box(self, data: Sequence[float], label: str = "",
                      width: int = 24, color: str = "") -> None:
        """Print a sparkline inside a box frame.

        Args:
            data: Sequence of numeric values.
            label: Title for the box.
            width: Character width of the sparkline.
            color: Optional color override.
        """
        W = self.width
        chart = sparkline(data, width, color)
        if label:
            print(box_line(f"{T('info')}{label}{C.RS} {chart}", W))
        else:
            print(box_line(f"  {chart}", W))

    # ─── v22: Key-Value Pair ───────────────────────────────────────────────

    def kv(self, key: str, value: str, key_width: int = 10,
           key_color: str = "", val_color: str = "") -> None:
        """Print a key-value pair with aligned columns.

        Args:
            key: Label text (left-aligned).
            value: Value text.
            key_width: Width allocated for the key column.
            key_color: Optional color for the key.
            val_color: Optional color for the value.
        """
        print(f"  {kv_line(key, value, key_width, key_color, val_color)}")

    def kv_box(self, pairs: List[tuple], key_width: int = 10,
               color: str = "") -> None:
        """Print multiple key-value pairs inside a box.

        Args:
            pairs: List of (key, value) tuples.
            key_width: Width for key column alignment.
            color: Optional frame color override.
        """
        W = self.width
        for key, value in pairs:
            line = kv_line(key, value, key_width)
            print(box_line(f"  {line}", W, color))

    # ─── v22: Table ────────────────────────────────────────────────────────

    def table(self, headers: List[str], rows: List[List[str]],
              col_widths: List[int] | None = None,
              title: str = "") -> None:
        """Print a formatted table inside a box.

        Args:
            headers: Column header texts.
            rows: List of rows, each row is a list of cell strings.
            col_widths: Optional explicit column widths.
            title: Optional table title.
        """
        W = self.width
        if title:
            print(box_top(W))
            print(box_line_centered(f"{T('accent')}{title}{C.RS}", W))
            print(box_mid(W))
        else:
            print(box_top(W))

        lines = render_table(headers, rows, col_widths, W)
        for line in lines:
            print(line)
        print(box_bottom(W))

    # ─── v22: Progress Bar ─────────────────────────────────────────────────

    def progress(self, current: int, total: int, width: int = 30,
                 label: str = "") -> None:
        """Print a detailed progress bar.

        Args:
            current: Current progress value.
            total: Total value.
            width: Bar width in characters.
            label: Optional label prefix.
        """
        bar = progress_bar_detailed(current, total, width, label)
        print(f"  {bar}")

    # ─── Direct Access to Theme Colors ──────────────────────────────────────

    @property
    def C(self):
        """Access to the _Colors singleton."""
        return self._C

    @property
    def theme_color(self) -> Any:
        """Get a color from the active theme by key.

        Usage::

            ui.theme_color("primary")  # Returns the primary theme color ANSI code
        """
        return T

    def set_width(self, width: int) -> None:
        """Change the default box width.

        Args:
            width: New box width.
        """
        self.width = width

    def set_theme(self, theme_name: str) -> None:
        """Change the active color theme.

        Args:
            theme_name: Theme name (MATRIX, CYBER, PHANTOM, BLOOD,
                        TOXIC, OCEAN, SOLAR, MONO).
        """
        self.theme_name = theme_name
        set_theme(theme_name)

    def auto_width(self) -> None:
        """Auto-detect terminal width and update self.width."""
        self.width = detect_terminal_width()

    # ─── v22: Theme Preview ────────────────────────────────────────────────

    @staticmethod
    def list_themes() -> None:
        """Print a preview of all available themes."""
        print()
        print(f"  {C.BD}Available Themes:{C.RS}")
        for name in THEME_NAMES:
            theme = THEMES[name]
            box_style = theme.get("box_style", "double")
            # Show a mini sample of the theme
            sample = (
                f"{theme['primary']}██{C.RS} "
                f"{theme['accent']}██{C.RS} "
                f"{theme['danger']}██{C.RS} "
                f"{theme['warning']}██{C.RS} "
                f"{theme['success']}██{C.RS} "
                f"{theme['info']}██{C.RS}"
            )
            print(f"  {C.BD}{name:<10}{C.RS} [{box_style:<8}] {sample}")
        print()
