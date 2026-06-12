"""utils.themes — Theme engine for terminal UI styling.

CANONICAL SOURCE for THEMES, T(), set_theme(), get_box_chars(). W2.1-B extraction from vf_common.py.
All existing `from vf_common import T, set_theme, THEMES` continues to work via re-export facade.
"""
from __future__ import annotations

import weakref

from utils.colors import C  # W2.1-B: import from canonical source


# Box style presets: "double", "single", "rounded", "heavy"
THEMES = {
    "MATRIX": {
        "primary":  C.NEON_GREEN,
        "accent":   C.NEON_CYAN,
        "danger":   C.NEON_RED,
        "warning":  C.NEON_YELLOW,
        "info":     C.NEON_CYAN,
        "dim":      C.DARK_GREEN,
        "success":  C.NEON_GREEN,
        "box_style": "double",
        "name":     "MATRIX",
    },
    "CYBER": {
        "primary":  C.NEON_CYAN,
        "accent":   C.NEON_MAGENTA,
        "danger":   C.NEON_RED,
        "warning":  C.ORANGE,
        "info":     C.ICE_BLUE,
        "dim":      C.DARK_CYAN,
        "success":  C.LIME,
        "box_style": "rounded",
        "name":     "CYBER",
    },
    "PHANTOM": {
        "primary":  C.ICE_BLUE,
        "accent":   C.PINK,
        "danger":   C.ORANGE,
        "warning":  C.GOLD,
        "info":     C.VIOLET,
        "dim":      C.STEEL,
        "success":  C.LIME,
        "box_style": "single",
        "name":     "PHANTOM",
    },
    "BLOOD": {
        "primary":  C.NEON_RED,
        "accent":   C.ORANGE,
        "danger":   C.SALMON,
        "warning":  C.NEON_YELLOW,
        "info":     C.GOLD,
        "dim":      C.DARK_RED,
        "success":  C.LIME,
        "box_style": "heavy",
        "name":     "BLOOD",
    },
    # ── v22: New themes ──
    "TOXIC": {
        "primary":  C.TOXIC_GREEN,
        "accent":   C.AMBER,
        "danger":   C.SUNSET,
        "warning":  C.NEON_YELLOW,
        "info":     C.LIME,
        "dim":      C.DARK_GREEN,
        "success":  C.NEON_GREEN,
        "box_style": "double",
        "name":     "TOXIC",
    },
    "OCEAN": {
        "primary":  C.DEEP_BLUE,
        "accent":   C.AQUA,
        "danger":   C.CORAL,
        "warning":  C.GOLD,
        "info":     C.SEA_GREEN,
        "dim":      C.SLATE,
        "success":  C.SEA_GREEN,
        "box_style": "rounded",
        "name":     "OCEAN",
    },
    "SOLAR": {
        "primary":  C.GOLD,
        "accent":   C.AMBER,
        "danger":   C.SUNSET,
        "warning":  C.NEON_YELLOW,
        "info":     C.ORANGE,
        "dim":      C.STEEL,
        "success":  C.LIME,
        "box_style": "heavy",
        "name":     "SOLAR",
    },
    "MONO": {
        "primary":  C.BRIGHT_WHITE,
        "accent":   C.STEEL,
        "danger":   C.R,
        "warning":  C.Y,
        "info":     C.W,
        "dim":      C.DM,
        "success":  C.G,
        "box_style": "single",
        "name":     "MONO",
    },
}

# v22: Ordered theme names for display
THEME_NAMES = list(THEMES.keys())


class _ThemeManager:
    """Thread-safe theme manager supporting both global and per-instance themes.

    ARCH-4 fix: Replaces module-level ACTIVE_THEME global to support
    multiple VFTester instances with different themes simultaneously.

    BUG-23 FIX: Uses weakref.WeakKeyDictionary instead of Dict[int, dict]
    to automatically clean up entries when key objects are garbage collected.
    """
    def __init__(self):
        import threading
        self._lock = threading.Lock()
        self._global_theme = THEMES["MATRIX"]
        self._instances: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()

    def set_global(self, name: str) -> None:
        """Set the global default theme."""
        with self._lock:
            if name.upper() in THEMES:
                self._global_theme = THEMES[name.upper()]

    def register(self, obj: object, theme_name: str) -> None:
        """Register a theme for a specific object instance."""
        with self._lock:
            if theme_name.upper() in THEMES:
                self._instances[obj] = THEMES[theme_name.upper()]

    def unregister(self, obj: object) -> None:
        """Remove theme registration for an object."""
        with self._lock:
            self._instances.pop(obj, None)

    def get(self, obj: object = None) -> dict:
        """Get theme for an object, falling back to global theme."""
        with self._lock:
            if obj is not None:
                instance_theme = self._instances.get(obj)
                if instance_theme is not None:
                    return instance_theme
            return self._global_theme


_theme_mgr = _ThemeManager()


def set_theme(name: str, obj: object = None):
    """Set the active color theme.

    Args:
        name: Theme name (MATRIX, CYBER, PHANTOM, BLOOD, TOXIC, OCEAN, SOLAR, MONO)
        obj: Optional object instance for per-instance theming.
    """
    if obj is not None:
        _theme_mgr.register(obj, name)
    else:
        _theme_mgr.set_global(name)


def T(key: str, obj: object = None) -> str:
    """Get a color from the active theme. Shorthand for theme.get(obj)[key]."""
    return _theme_mgr.get(obj).get(key, C.W)


def get_box_chars(obj: object = None) -> dict:
    """Get box-drawing characters for the current theme's box_style.

    Returns a dict with keys: TL, TR, BL, BR, H, V, LT, RT
    """
    style = _theme_mgr.get(obj).get("box_style", "double")
    if style == "rounded":
        return {"TL": C.RTL, "TR": C.RTR, "BL": C.RBL, "BR": C.RBR,
                "H": C.HB, "V": C.VB, "LT": C.LTB, "RT": C.RTB}
    elif style == "single":
        return {"TL": '┌', "TR": '┐', "BL": '└', "BR": '┘',
                "H": C.HB, "V": C.VB, "LT": C.LTB, "RT": C.RTB}
    elif style == "heavy":
        return {"TL": C.HTL, "TR": C.HTR, "BL": C.HBL, "BR": C.HBR,
                "H": C.HH, "V": C.HV, "LT": '┣', "RT": '┫'}
    else:  # double (default)
        return {"TL": C.TL, "TR": C.TR, "BL": C.BL, "BR": C.BR,
                "H": C.H, "V": C.V, "LT": C.LT, "RT": C.RT}
