#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""unicode_helpers — Unicode-aware string helpers extracted from vf_common.py.

W2.1 EXTRACTION: Canonical source for _ANSI_RE, _strip_ansi, _visible_len.
These utilities have ZERO dependencies on C (Colors), T (themes), or any other
vf_common domain — only on re and unicodedata stdlib modules.

Backward compatibility: vf_common.py re-exports these symbols so existing
`from vf_common import _strip_ansi` continues to work.
"""
from __future__ import annotations

import re
import unicodedata


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

# Control chars to strip in sanitize_output (all C0 + DEL except \t \n \r)
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text for length calculation."""
    return _ANSI_RE.sub('', text)


def _strip_null_bytes(s: str | None) -> str:
    """Strip null bytes (\\x00) from a string.

    Fast variant that only removes \\x00 — the minimum needed to
    prevent ``ValueError: embedded null character`` on Windows
    when writing to stdout/stderr or logging.

    None-safe: returns ``""`` if *s* is ``None`` instead of crashing.

    Use this instead of ``.replace('\\x00', '')`` when you need
    the canonical utility (centralised, testable, grep-friendly).
    """
    if not s:
        return ''
    return s.replace('\x00', '')


def sanitize_output(s: str | None) -> str:
    """Sanitize a string for safe terminal output on all platforms.

    Strips:
    - All null bytes (\\x00) — crashes Windows ``print()`` / ``logging``
    - Other C0 control characters except \\t, \\n, \\r
    - DEL (\\x7f)

    None-safe: returns ``""`` if *s* is ``None`` instead of crashing.

    Does NOT strip ANSI escape codes (those are handled by ``_strip_ansi``).

    Args:
        s: Input string that may contain unsafe control characters.

    Returns:
        Sanitized string safe for ``print()`` / ``logging`` on Windows.
    """
    if not s:
        return ''
    return _CONTROL_CHARS_RE.sub('', s)


def _visible_len(text: str) -> int:
    """Return the visible display width, accounting for CJK double-width characters."""
    stripped = _strip_ansi(text)
    width = 0
    for ch in stripped:
        eaw = unicodedata.east_asian_width(ch)
        if eaw in ('F', 'W'):
            width += 2
        else:
            width += 1
    return width
