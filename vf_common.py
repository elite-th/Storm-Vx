#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vf_common — Backward-compatibility re-export facade.

W2.1 DECOMPOSITION: This module is now a pure re-export facade.
All functionality has been decomposed into focused single-responsibility
modules under utils/:

  - utils/colors:       ANSI color constants, box-drawing chars, RGB helpers
  - utils/themes:       Theme engine (8 themes, per-instance theming)
  - utils/box_drawing:  Box-drawing helpers (box_top, box_line, etc.)
  - utils/progress:     Progress bars, sparklines
  - utils/formatting:   Display formatting (kv_line, render_table, mode_icon)
  - utils/terminal_width: Terminal width detection
  - utils/unicode_helpers: Unicode-aware string helpers
  - utils/log_helpers:  Live logging utilities
  - utils/random_helpers: Random generators (UA, strings, tokens)
  - utils/ssl_helpers:  SSL parameter helpers

All existing `from vf_common import C, T, rand_str, box_top, ...` calls
continue to work unchanged. New code should import directly from utils/.
"""
from __future__ import annotations


# ═══════════════════════════════════════════════════════════════════════════════
# Terminal Width — CANONICAL SOURCE: utils.terminal_width
# ═══════════════════════════════════════════════════════════════════════════════
# W2.1 EXTRACTION: Moved to utils/terminal_width.py for single responsibility.
# These re-exports preserve backward compatibility — existing
# `from vf_common import AUTO_WIDTH` continues to work.
# New code should import directly: `from utils.terminal_width import AUTO_WIDTH`.
from utils.terminal_width import detect_terminal_width, AUTO_WIDTH, auto_width  # noqa: F401 — re-export for backward compat


# ═══════════════════════════════════════════════════════════════════════════════
# ANSI Color Codes — CANONICAL SOURCE: utils.colors
# ═══════════════════════════════════════════════════════════════════════════════
# W2.1-B EXTRACTION: Moved to utils/colors.py for single responsibility.
# This re-export preserves backward compatibility — existing `from vf_common import C`
# continues to work. New code should import directly: `from utils.colors import C`.
from utils.colors import C, _Colors  # noqa: F401 — re-export for backward compat


# ═══════════════════════════════════════════════════════════════════════════════
# Theme Engine — CANONICAL SOURCE: utils.themes
# ═══════════════════════════════════════════════════════════════════════════════
# W2.1-B EXTRACTION: Moved to utils/themes.py for single responsibility.
# This re-export preserves backward compatibility — existing `from vf_common import T, set_theme`
# continues to work. New code should import directly: `from utils.themes import T, set_theme`.
from utils.themes import THEMES, THEME_NAMES, set_theme, T, get_box_chars  # noqa: F401 — re-export for backward compat


# ═══════════════════════════════════════════════════════════════════════════════
# Unicode Helpers — CANONICAL SOURCE: utils.unicode_helpers
# ═══════════════════════════════════════════════════════════════════════════════
# W2.1 EXTRACTION: Moved to utils/unicode_helpers.py for single responsibility.
# These re-exports preserve backward compatibility — existing
# `from vf_common import _strip_ansi` continues to work.
# New code should import directly: `from utils.unicode_helpers import _strip_ansi`.
from utils.unicode_helpers import _strip_ansi, _visible_len, _ANSI_RE, _strip_null_bytes, sanitize_output  # noqa: F401 — re-export for backward compat


# ═══════════════════════════════════════════════════════════════════════════════
# Box-drawing Helpers — CANONICAL SOURCE: utils.box_drawing
# ═══════════════════════════════════════════════════════════════════════════════
# W2.1-C EXTRACTION: Moved to utils/box_drawing.py for single responsibility.
# This re-export preserves backward compatibility — existing `from vf_common import box_top`
# continues to work. New code should import directly: `from utils.box_drawing import box_top`.
from utils.box_drawing import (  # noqa: F401 — re-export for backward compat
    box_top, box_bottom, box_mid, box_line,
    box_line_centered, box_line_right, box_divider,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Progress Bar & Sparkline — CANONICAL SOURCE: utils.progress
# ═══════════════════════════════════════════════════════════════════════════════
# W2.1-C EXTRACTION: Moved to utils/progress.py for single responsibility.
# This re-export preserves backward compatibility — existing `from vf_common import health_bar`
# continues to work. New code should import directly: `from utils.progress import health_bar`.
from utils.progress import (  # noqa: F401 — re-export for backward compat
    health_bar, worker_bar, mini_bar,
    progress_bar_detailed, sparkline,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Display Formatting — CANONICAL SOURCE: utils.formatting
# ═══════════════════════════════════════════════════════════════════════════════
# W2.1-C EXTRACTION: Moved to utils/formatting.py for single responsibility.
# This re-export preserves backward compatibility — existing `from vf_common import kv_line`
# continues to work. New code should import directly: `from utils.formatting import kv_line`.
from utils.formatting import (  # noqa: F401 — re-export for backward compat
    kv_line, render_table,
    MODE_ICONS, mode_icon, severity_icon,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Random Generators — CANONICAL SOURCE: utils.random_helpers
# ═══════════════════════════════════════════════════════════════════════════════
# W2.1 EXTRACTION: Moved to utils/random_helpers.py for single responsibility.
# These re-exports preserve backward compatibility — existing
# `from vf_common import rand_str` continues to work.
# New code should import directly: `from utils.random_helpers import rand_str`.
from utils.random_helpers import (  # noqa: F401 — re-exports for backward compat
    USER_AGENTS,
    random_ua,
    rand_str,
    rand_user,
    rand_pass,
    rand_cache_bust,
    secure_token,
    rand_ip,
    join_url,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Live Logging Utilities — CANONICAL SOURCE: utils.log_helpers
# ═══════════════════════════════════════════════════════════════════════════════
# W2.1 EXTRACTION: Moved to utils/log_helpers.py for single responsibility.
# These re-exports preserve backward compatibility — existing
# `from vf_common import live_log` continues to work.
# New code should import directly: `from utils.log_helpers import live_log`.
from utils.log_helpers import live_log, live_ok, live_warn, live_eta  # noqa: F401 — re-export for backward compat


# ═══════════════════════════════════════════════════════════════════════════════
# SSL Parameter Helper — ARCH-5
# ═══════════════════════════════════════════════════════════════════════════════
# CANONICAL SOURCE: utils.ssl_helpers.ssl_param
# This re-export preserves backward compatibility — existing `from vf_common import ssl_param`
# continues to work. New code should import directly from utils.ssl_helpers.
from utils.ssl_helpers import ssl_param, create_ssl_context  # noqa: F401 — re-export for backward compat
