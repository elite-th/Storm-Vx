#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""terminal_width — Terminal width detection utilities extracted from vf_common.py.

W2.1 EXTRACTION: Canonical source for detect_terminal_width, AUTO_WIDTH, auto_width.
These functions have ZERO dependencies on C (Colors), T (themes), or any other
vf_common domain — only on os and sys stdlib modules.

BUG-038 FIX: AUTO_WIDTH is now a function that re-detects the terminal width
on each call, instead of a constant computed once at import time. Use
AUTO_WIDTH() to get the current width. This fixes the bug where terminal
resize was not reflected during long-running sessions.

Backward compatibility: vf_common.py re-exports these symbols so existing
`from vf_common import AUTO_WIDTH` continues to work. Note that AUTO_WIDTH
is now a callable — code that previously used `AUTO_WIDTH` as an int
should use `AUTO_WIDTH()` instead.
"""
from __future__ import annotations

import os
import sys


def detect_terminal_width(fallback: int = 72) -> int:
    """Detect terminal width, clamped to [48, 120]."""
    try:
        cols = os.get_terminal_size(sys.stdout.fileno()).columns
        return max(48, min(120, cols))
    except (OSError, ValueError, AttributeError):
        return fallback


def auto_width() -> int:
    """Get current terminal width (recomputed each call)."""
    return detect_terminal_width()


# BUG-038: AUTO_WIDTH was a constant computed once at import time, never
# updated when the terminal was resized. Now it's a function alias for
# auto_width(), so each call re-detects the current width.
# Use: AUTO_WIDTH() — note the parentheses.
AUTO_WIDTH = auto_width
