#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""terminal_width — Terminal width detection utilities extracted from vf_common.py.

W2.1 EXTRACTION: Canonical source for detect_terminal_width, AUTO_WIDTH, auto_width.
These functions have ZERO dependencies on C (Colors), T (themes), or any other
vf_common domain — only on os and sys stdlib modules.

Backward compatibility: vf_common.py re-exports these symbols so existing
`from vf_common import AUTO_WIDTH` continues to work.
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


AUTO_WIDTH = detect_terminal_width()  # Backward-compat constant (snapshot)


def auto_width() -> int:
    """Get current terminal width (recomputed each call)."""
    return detect_terminal_width()
