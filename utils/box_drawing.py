"""utils.box_drawing — Box-drawing helpers for terminal UI.

CANONICAL SOURCE for box_* functions. W2.1-C extraction from vf_common.py.
All existing `from vf_common import box_top` continues to work via re-export facade.
"""
from __future__ import annotations

from utils.colors import C  # W2.1-C
from utils.themes import T, get_box_chars  # W2.1-C
from utils.unicode_helpers import _visible_len, _strip_ansi  # W2.1-C


def box_top(width: int, color: str = "") -> str:
    """Draw top border using current theme's box style."""
    c = color or T("primary")
    bx = get_box_chars()
    inner = bx["H"] * (width - 2)
    return f"{c}{bx['TL']}{inner}{bx['TR']}{C.RS}"


def box_bottom(width: int, color: str = "") -> str:
    """Draw bottom border using current theme's box style."""
    c = color or T("primary")
    bx = get_box_chars()
    inner = bx["H"] * (width - 2)
    return f"{c}{bx['BL']}{inner}{bx['BR']}{C.RS}"


def box_mid(width: int, color: str = "") -> str:
    """Draw middle divider using current theme's box style."""
    c = color or T("primary")
    bx = get_box_chars()
    inner = bx["H"] * (width - 2)
    return f"{c}{bx['LT']}{inner}{bx['RT']}{C.RS}"


def box_line(text: str, width: int, color: str = "", text_color: str = "") -> str:
    """Draw a content line: ║ text ║ (padded to width)"""
    c = color or T("primary")
    tc = text_color  # Apply text_color if provided
    bx = get_box_chars()
    visible_len = _visible_len(text)
    pad = max(width - 4 - visible_len, 0)
    inner = f"{tc}{text}{C.RS}" if tc else f"{text}{C.RS}"
    return f"{c}{bx['V']}{C.RS} {inner}{' ' * pad} {c}{bx['V']}{C.RS}"


def box_line_centered(text: str, width: int, color: str = "", text_color: str = "") -> str:
    """Draw a centered content line: ║   text   ║"""
    c = color or T("primary")
    tc = text_color  # Apply text_color if provided
    bx = get_box_chars()
    visible_len = _visible_len(text)
    total_pad = max(width - 4 - visible_len, 0)
    left = total_pad // 2
    right = total_pad - left
    inner = f"{tc}{text}{C.RS}" if tc else f"{text}{C.RS}"
    return f"{c}{bx['V']}{C.RS}{' ' * left}{inner}{' ' * right} {c}{bx['V']}{C.RS}"


def box_line_right(text: str, width: int, color: str = "") -> str:
    """Draw a right-aligned content line: ║       text ║"""
    c = color or T("primary")
    bx = get_box_chars()
    visible_len = _visible_len(text)
    pad = max(width - 4 - visible_len, 0)
    return f"{c}{bx['V']}{C.RS}{' ' * pad}{text}{C.RS} {c}{bx['V']}{C.RS}"


def box_divider(label: str, width: int, color: str = "") -> str:
    """Draw a labeled divider: ╠══ LABEL ══╣

    v22: The label is embedded in the horizontal line with padding.
    """
    c = color or T("primary")
    bx = get_box_chars()
    label_text = f" {label} "
    inner_width = width - 2
    label_len = len(label_text)
    if label_len + 4 > inner_width:
        # Label too long, just use regular mid
        inner = bx["H"] * inner_width
        return f"{c}{bx['LT']}{inner}{bx['RT']}{C.RS}"
    side = (inner_width - label_len) // 2
    left_fill = bx["H"] * side
    right_fill = bx["H"] * (inner_width - label_len - side)
    return f"{c}{bx['LT']}{left_fill}{C.RS}{T('accent')}{label_text}{C.RS}{c}{right_fill}{bx['RT']}{C.RS}"
