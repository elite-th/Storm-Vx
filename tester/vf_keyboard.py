#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vf_keyboard — Keyboard input handler for runtime controls.

Provides the KeyboardHandler class that allows non-blocking keyboard
input during an attack session (+/- workers, q to quit).
"""
from __future__ import annotations

import sys
import os


class KeyboardHandler:
    """Handles keyboard input during attack (non-blocking)."""

    _KEY_MAP: dict[str, str] = {
        '+': '+',
        '=': '+',  # + key without shift
        '-': '-',
        '_': '-',  # - key without shift on some layouts
        'q': 'q',
    }

    def __init__(self):
        self._running = False

    async def start(self):
        """Start keyboard listener (no-op on most platforms)."""
        self._running = True

    async def stop(self):
        """Stop keyboard listener."""
        self._running = False

    def get_command(self) -> str | None:
        """Check for keyboard input without blocking.

        Uses select() on Unix or msvcrt on Windows to detect keypresses
        without blocking the async event loop. Returns '+', '-', 'q', or None.
        """
        try:
            if os.name == 'nt':
                import msvcrt
                if msvcrt.kbhit():
                    key = msvcrt.getch().decode('utf-8', errors='ignore').lower()
                    return self._KEY_MAP.get(key)
            else:
                import select
                if select.select([sys.stdin], [], [], 0)[0]:
                    key = sys.stdin.readline().strip().lower()
                    return self._KEY_MAP.get(key)
        except Exception:
            pass
        return None


__all__ = ['KeyboardHandler']
