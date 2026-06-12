"""utils.colors — ANSI color constants, box-drawing chars, and RGB helpers.

CANONICAL SOURCE for C (_Colors instance). W2.1-B extraction from vf_common.py.
All existing `from vf_common import C` continues to work via re-export facade.
"""
from __future__ import annotations


class _Colors:
    """ANSI color constants for terminal output.

    v22: Extended neon palette + truecolor gradient helpers.
    """

    # Reset
    RS = '\033[0m'

    # Styles
    BD = '\033[1m'      # Bold
    DM = '\033[2m'      # Dim
    IT = '\033[3m'      # Italic
    UL = '\033[4m'      # Underline
    FL = '\033[5m'      # Flash/Blink
    RV = '\033[7m'      # Reverse video

    # ── Standard Foreground colors ──
    R = '\033[91m'      # Red
    G = '\033[92m'      # Green
    Y = '\033[93m'      # Yellow
    B = '\033[94m'      # Blue
    M = '\033[95m'      # Magenta
    CY = '\033[96m'     # Cyan
    W = '\033[97m'      # White

    # ── 256-color Neon Palette (hacker-style) ──
    NEON_GREEN   = '\033[38;5;46m'    # Matrix green
    NEON_CYAN    = '\033[38;5;51m'    # Cyber cyan
    NEON_RED     = '\033[38;5;196m'   # Hot red
    NEON_YELLOW  = '\033[38;5;226m'   # Bright yellow
    NEON_MAGENTA = '\033[38;5;201m'   # Electric magenta
    DARK_GREEN   = '\033[38;5;22m'    # Deep green
    DARK_RED     = '\033[38;5;88m'    # Deep red
    DARK_CYAN    = '\033[38;5;23m'    # Teal
    ORANGE       = '\033[38;5;208m'   # Warning orange
    PINK         = '\033[38;5;213m'   # Soft pink
    LIME         = '\033[38;5;118m'   # Lime green
    ICE_BLUE     = '\033[38;5;75m'    # Ice blue
    VIOLET       = '\033[38;5;141m'   # Soft violet
    SALMON       = '\033[38;5;210m'   # Salmon
    GOLD         = '\033[38;5;220m'   # Gold
    STEEL        = '\033[38;5;245m'   # Steel grey

    # ── v22: Additional 256-color entries ──
    TOXIC_GREEN  = '\033[38;5;76m'    # Bright toxic green
    DEEP_BLUE    = '\033[38;5;27m'    # Deep ocean blue
    AMBER        = '\033[38;5;214m'   # Warm amber
    HOT_PINK     = '\033[38;5;199m'   # Hot pink
    SEA_GREEN    = '\033[38;5;72m'    # Sea green
    SLATE        = '\033[38;5;102m'   # Slate grey
    BRIGHT_WHITE = '\033[38;5;231m'   # Pure white
    SUNSET       = '\033[38;5;202m'   # Sunset orange-red
    CORAL        = '\033[38;5;204m'   # Coral
    AQUA         = '\033[38;5;87m'    # Aqua

    # ── Background colors ──
    BG_R = '\033[41m'
    BG_G = '\033[42m'
    BG_Y = '\033[43m'
    BG_B = '\033[44m'
    BG_M = '\033[45m'
    BG_CY = '\033[46m'

    # ── 256-color backgrounds ──
    BG_DARK   = '\033[48;5;234m'    # Dark grey background
    BG_DARKER = '\033[48;5;232m'    # Near-black background

    # ── Box-drawing characters (double-line) ──
    TL = '╔'   # Top-left corner
    TR = '╗'   # Top-right corner
    BL = '╚'   # Bottom-left corner
    BR = '╝'   # Bottom-right corner
    H  = '═'   # Horizontal double
    V  = '║'   # Vertical double
    LT = '╠'   # Left tee
    RT = '╣'   # Right tee

    # ── Box-drawing characters (single-line) ──
    HB = '─'   # Horizontal single
    VB = '│'   # Vertical single
    LTB = '├'  # Left tee single
    RTB = '┤'  # Right tee single
    TTB = '┬'  # Top tee single
    BTB = '┴'  # Bottom tee single
    CROSS = '┼'  # Cross

    # ── v22: Rounded box-drawing characters ──
    RTL = '╭'  # Rounded top-left
    RTR = '╮'  # Rounded top-right
    RBL = '╰'  # Rounded bottom-left
    RBR = '╯'  # Rounded bottom-right

    # ── v22: Heavy box-drawing characters ──
    HTL = '┏'  # Heavy top-left
    HTR = '┐'  # Heavy top-right (using standard)
    HBL = '┗'  # Heavy bottom-left
    HBR = '┛'  # Heavy bottom-right
    HH  = '━'  # Heavy horizontal
    HV  = '┃'  # Heavy vertical

    # ── Icons ──
    ICON_OK    = '✓'
    ICON_FAIL  = '✗'
    ICON_WARN  = '⚠'
    ICON_BOLT  = '⚡'
    ICON_FIRE  = '🔥'
    ICON_SKULL = '💀'
    ICON_SWORD = '⚔'
    ICON_SHLD  = '🛡'
    ICON_EYE   = '👁'
    ICON_TARGET= '🎯'
    ICON_GEM   = '💎'
    ICON_ROCKET= '🚀'
    ICON_CLOCK = '⏱'
    ICON_CHART = '📊'

    # ── v22: Spinner frames ──
    SPINNER_DOTS   = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    SPINNER_ARROWS  = ['←','↖','↑','↗','→','↘','↓','↙']
    SPINNER_BLOCKS  = ['▏','▎','▍','▌','▋','▊','▉','█']
    SPINNER_PULSE   = ['○','◔','◑','◕','●','◕','◑','◔']

    # ── Truecolor RGB helper ──
    @staticmethod
    def rgb(r: int, g: int, b: int) -> str:
        """Return ANSI truecolor escape for RGB values."""
        return f'\033[38;2;{r};{g};{b}m'

    @staticmethod
    def bg_rgb(r: int, g: int, b: int) -> str:
        """Return ANSI truecolor background escape for RGB values."""
        return f'\033[48;2;{r};{g};{b}m'


C = _Colors()
