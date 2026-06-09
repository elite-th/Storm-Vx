#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vf_live_log — Circular buffer for live log display.

v21: Now uses themed colors and mode icons for hacker-style display.
"""
from __future__ import annotations

from collections import deque
from typing import Dict, List, Any


from vf_common import C, T, mode_icon


class LiveLog:
    """Circular buffer for recent log lines."""

    def __init__(self, max_lines: int = 8):
        self._max = max_lines
        self._lines: deque = deque(maxlen=max_lines)

    def add(self, entry: Dict[str, Any]):
        """Add a log entry."""
        self._lines.append(entry)

    def get_lines(self) -> List[Dict]:
        """Get all log lines."""
        return list(self._lines)

    def format_line(self, entry: Dict) -> str:
        """Format a log entry for display.

        v21: Uses themed colors and mode icons.
        """
        mode = entry.get("mode", "?")
        code = entry.get("code", 0)
        rt = entry.get("rt", 0)
        hint = entry.get("hint", "")
        err = entry.get("err", "")
        url = entry.get("url", "")

        # Truncate URL for display
        url_short = url[:50] + "…" if len(url) > 50 else url
        icon = mode_icon(mode)

        if err:
            return f"    {T('danger')}{C.ICON_FAIL}{C.RS} {icon}{T('danger')}{mode:<14}{C.RS} {code} {err[:30]} {C.DM}{url_short}{C.RS}"
        elif code >= 500:
            return f"    {T('danger')}{C.ICON_FAIL}{C.RS} {icon}{T('danger')}{mode:<14}{C.RS} {code} {rt*1000:.0f}ms {C.DM}{url_short}{C.RS}"
        elif code >= 400:
            return f"    {T('warning')}{C.ICON_WARN}{C.RS} {icon}{T('warning')}{mode:<14}{C.RS} {code} {rt*1000:.0f}ms {C.DM}{url_short}{C.RS}"
        else:
            return f"    {T('success')}{C.ICON_OK}{C.RS} {icon}{T('success')}{mode:<14}{C.RS} {code} {rt*1000:.0f}ms {C.DM}{url_short}{C.RS}"


__all__ = ['LiveLog']
