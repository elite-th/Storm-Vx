"""utils.formatting — Display formatting utilities for terminal UI.

CANONICAL SOURCE for kv_line, render_table, mode_icon, MODE_ICONS, severity_icon.
W2.1-C extraction from vf_common.py.
All existing `from vf_common import kv_line` continues to work via re-export facade.
"""
from __future__ import annotations

from typing import List

from utils.colors import C  # W2.1-C
from utils.themes import T  # W2.1-C
from utils.unicode_helpers import _visible_len, _strip_ansi  # W2.1-C
from utils.box_drawing import box_line, box_mid  # W2.1-C


# ═══════════════════════════════════════════════════════════════════════════════
# Mode Icons — v22: Expanded
# ═══════════════════════════════════════════════════════════════════════════════

MODE_ICONS = {
    "LOGIN":     "🔑",
    "PAGE":      "📄",
    "RES":       "📦",
    "API":       "🔌",
    "WP-XMLRPC": "📝",
    "ORIGIN":    "🎯",
    "SLOW":      "🐌",
    "TLS":       "🔒",
    "WS":        "🔌",
    "GRAPHQL":   "◈",
    "HEADER":    "💣",
    "MULTI":     "📤",
    "SLOWR":     "🐌",
    "CACHE":     "🎭",
    "JSON":      "📦",
    "VIEWST":    "⚙",
    "SESSION":   "🍪",
    "PINGBACK":  "📡",
    "HTTP2":     "⚡",
    "CONN":      "🔗",
}


def mode_icon(mode: str) -> str:
    """Get icon for attack mode, fallback to '⚔'."""
    for key, icon in MODE_ICONS.items():
        if key in mode.upper():
            return icon
    return C.ICON_SWORD


# ═══════════════════════════════════════════════════════════════════════════════
# Severity Indicators — v22
# ═══════════════════════════════════════════════════════════════════════════════

def severity_icon(level: str) -> str:
    """Get a colored severity indicator.

    Args:
        level: One of 'critical', 'high', 'medium', 'low', 'info'.

    Returns:
        Colored icon string like '🔴' or '🟢'.
    """
    mapping = {
        "critical": f"{T('danger')}●{C.RS}",
        "high":     f"{C.ORANGE}●{C.RS}",
        "medium":   f"{T('warning')}●{C.RS}",
        "low":      f"{T('info')}●{C.RS}",
        "info":     f"{T('dim')}●{C.RS}",
    }
    return mapping.get(level.lower(), f"{C.DM}●{C.RS}")


# ═══════════════════════════════════════════════════════════════════════════════
# Key-Value Pair Formatting — v22
# ═══════════════════════════════════════════════════════════════════════════════

def kv_line(key: str, value: str, key_width: int = 10,
            key_color: str = "", val_color: str = "") -> str:
    """Format a key-value pair with aligned columns.

    Example: WORKERS  ████░░░ 500/5000

    Args:
        key: Label text (left-aligned).
        value: Value text (follows the key).
        key_width: Width allocated for the key column.
        key_color: Optional color for the key.
        val_color: Optional color for the value.
    """
    kc = key_color or T("info")
    vc = val_color or C.W
    return f"{kc}{key:<{key_width}}{C.RS} {vc}{value}{C.RS}"


# ═══════════════════════════════════════════════════════════════════════════════
# Table Rendering — v22
# ═══════════════════════════════════════════════════════════════════════════════

def render_table(headers: List[str], rows: List[List[str]],
                 col_widths: List[int] | None = None,
                 width: int = 64,
                 cell_color: str = "") -> List[str]:
    """Render a formatted table inside a box.

    v22: Auto-calculates column widths if not provided.

    Args:
        headers: Column header texts.
        rows: List of rows, each row is a list of cell strings.
        col_widths: Optional explicit column widths. Auto-calculated if None.
        width: Total box width.
        cell_color: Optional theme key (e.g. 'info', 'success') to color all cells.

    Returns:
        List of box-formatted lines (ready for box_raw).
    """
    lines = []

    # Calculate column widths
    num_cols = len(headers)
    if col_widths is None:
        # Auto-calculate: find max width per column
        col_widths = [0] * num_cols
        for i, h in enumerate(headers):
            col_widths[i] = max(col_widths[i], _visible_len(h))
        for row in rows:
            for i, cell in enumerate(row):
                if i < num_cols:
                    col_widths[i] = max(col_widths[i], _visible_len(cell))
        # Clamp total width
        available = width - 4 - (num_cols - 1) * 2  # borders + separators
        total = sum(col_widths)
        if total > available:
            scale = available / total
            col_widths = [max(4, int(w * scale)) for w in col_widths]

    # Header
    header_parts = []
    for i, h in enumerate(headers):
        w = col_widths[i] if i < len(col_widths) else 8
        header_parts.append(f"{T('accent')}{_strip_ansi(h):<{w}}{C.RS}")
    lines.append(box_line("  ".join(header_parts), width))
    lines.append(box_mid(width))

    # Rows
    _cc = T(cell_color) if cell_color else ""
    for row in rows:
        row_parts = []
        for i in range(num_cols):
            cell = row[i] if i < len(row) else ""
            w = col_widths[i] if i < len(col_widths) else 8
            if _cc:
                cell = f"{_cc}{cell}{C.RS}"
            visible = _strip_ansi(cell)
            vlen = _visible_len(cell)
            if vlen > w:
                visible = visible[:w-1] + "…"
                vlen = _visible_len(visible)
            row_parts.append(f"{cell}{C.RS}{' ' * max(0, w - vlen)}")
        lines.append(box_line("  ".join(row_parts), width))

    return lines
