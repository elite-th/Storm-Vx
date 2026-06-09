"""ui — Storm-Vx terminal UI package.

v22: Redesigned with rich formatting capabilities.

Exports:
    TerminalUI       — Centralized terminal output (box-drawing, themed messages,
                       sparklines, spinners, tables, key-value pairs)
    DashboardRenderer — Real-time attack dashboard rendering (sparklines,
                       phase indicators, gradient bars, labeled dividers)
    ScanReporter     — Reconnaissance scan report rendering (severity indicators,
                       labeled sections, compact content stats)
"""

__all__ = ["TerminalUI", "DashboardRenderer", "ScanReporter"]


def __getattr__(name):
    if name == 'TerminalUI':
        from ui.terminal import TerminalUI
        return TerminalUI
    elif name == 'DashboardRenderer':
        from ui.dashboard import DashboardRenderer
        return DashboardRenderer
    elif name == 'ScanReporter':
        from ui.report import ScanReporter
        return ScanReporter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
