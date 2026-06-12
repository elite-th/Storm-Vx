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


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text for length calculation."""
    return _ANSI_RE.sub('', text)


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
