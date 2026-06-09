"""utils.progress — Progress bar and sparkline rendering.

CANONICAL SOURCE for health_bar, worker_bar, mini_bar, progress_bar_detailed, sparkline.
W2.1-C extraction from vf_common.py.
All existing `from vf_common import health_bar` continues to work via re-export facade.
"""
from __future__ import annotations

from typing import Sequence

from utils.colors import C  # W2.1-C
from utils.themes import T  # W2.1-C


_SPARKLINE_CHARS = ' ▁▂▃▄▅▆▇█'


def health_bar(health: float, width: int = 20) -> str:
    """HP bar with gradient color using truecolor RGB: green→yellow→orange→red.

    v22: Smooth gradient via RGB interpolation instead of discrete steps.
    BUG-FIX v32: Clamped health to [0.0, 1.0] to prevent overflow.
    """
    health = min(max(health, 0.0), 1.0)  # Clamp to valid range
    filled = min(int(health * width), width)
    empty = width - filled

    # Gradient: green(0,255,0) → yellow(255,255,0) → red(255,0,0)
    if health > 0.5:
        # green → yellow
        t = (1.0 - health) * 2  # 0 → 1 as health goes 1.0 → 0.5
        r = int(255 * t)
        g = 255
    else:
        # yellow → red
        t = health * 2  # 1 → 0 as health goes 0.5 → 0
        r = 255
        g = int(255 * t)

    bar_color = C.rgb(r, g, 0)
    return f"{bar_color}{'█' * filled}{C.DM}{'░' * empty}{C.RS}"


def worker_bar(cur: int, max_w: int, width: int = 20) -> str:
    """Worker progress bar with gradient: green → cyan → magenta → red.

    BUG-FIX v32: Clamped pct to [0.0, 1.0] to prevent negative RGB values
    when cur > max_w (workers exceed max_workers). Also clamps filled/empty
    to prevent rendering issues.
    """
    pct = min(cur / max(max_w, 1), 1.0)  # Clamp to prevent overflow
    filled = min(int(pct * width), width)
    empty = width - filled

    # Gradient: green(0,255,100) → cyan(0,255,255) → magenta(255,0,255) → red(255,50,50)
    if pct < 0.33:
        t = pct / 0.33
        r, g, b = 0, 255, int(100 + 155 * t)
    elif pct < 0.66:
        t = (pct - 0.33) / 0.33
        r, g, b = int(255 * t), int(255 * (1 - t)), 255
    else:
        t = min((pct - 0.66) / 0.34, 1.0)  # Clamp t to prevent negative colors
        r, g, b = 255, int(50 * (1 - t)), int(255 * (1 - t))

    bar_color = C.rgb(r, g, b)
    return f"{bar_color}{'█' * filled}{C.DM}{'░' * empty}{C.RS}"


def mini_bar(pct: float, width: int = 16) -> str:
    """Small percentage bar for stats with gradient color.

    BUG-FIX v32: Clamped pct to [0.0, 1.0] to prevent overflow.
    """
    pct = min(max(pct, 0.0), 1.0)  # Clamp to valid range
    filled = min(int(pct * width), width)
    empty = width - filled

    # Gradient: red → yellow → green
    if pct > 0.5:
        t = (pct - 0.5) * 2
        r, g = int(255 * (1 - t)), 255
    else:
        t = pct * 2
        r, g = 255, int(255 * t)

    bar_color = C.rgb(r, g, 50)
    return f"{bar_color}{'█' * filled}{C.DM}{'░' * empty}{C.RS}"


def progress_bar_detailed(current: int, total: int, width: int = 30,
                          label: str = "") -> str:
    """Detailed progress bar with percentage text inside.

    v22: Shows a bar like [████████░░░░░░░░] 53% with optional label.
    """
    if total <= 0:
        pct = 0.0
    else:
        pct = current / total
    filled = int(pct * width)
    empty = width - filled
    pct_str = f"{pct:.0%}"

    # Color gradient
    if pct > 0.7:
        color = T("success")
    elif pct > 0.4:
        color = T("warning")
    else:
        color = T("danger")

    bar = f"{color}{'█' * filled}{C.DM}{'░' * empty}{C.RS}"
    label_str = f"{T('info')}{label}{C.RS} " if label else ""
    return f"{label_str}[{bar}] {T('accent')}{pct_str}{C.RS}"


def sparkline(data: Sequence[float], width: int = 24, color: str = "") -> str:
    """Render a sparkline mini-chart from numeric data.

    v22: Unicode block characters create a compact inline chart.

    Args:
        data: Sequence of numeric values (RPS, health, etc.).
        width: Maximum number of characters for the sparkline.
        color: Optional color override. Defaults to theme accent.

    Returns:
        Styled sparkline string like ' ▃▅▇█▆▄▃▂▃▅'
    """
    if not data:
        return f"{C.DM}{'─' * width}{C.RS}"

    c = color or T("accent")

    # Sample or pad data to fit width
    if len(data) > width:
        # Downsample: pick evenly spaced values
        step = len(data) / width
        sampled = [data[int(i * step)] for i in range(width)]
    else:
        sampled = list(data)

    # Normalize to [0, 1]
    min_val = min(sampled)
    max_val = max(sampled)
    rng = max_val - min_val if max_val != min_val else 1.0

    chars = []
    for val in sampled:
        normalized = (val - min_val) / rng
        idx = int(normalized * (len(_SPARKLINE_CHARS) - 1))
        idx = max(0, min(idx, len(_SPARKLINE_CHARS) - 1))
        chars.append(_SPARKLINE_CHARS[idx])

    return f"{c}{''.join(chars)}{C.RS}"
