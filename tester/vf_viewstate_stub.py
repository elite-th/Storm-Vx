#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vf_viewstate_stub — Minimal ViewState manager stub for ASP.NET targets.

Provides the ViewStateManagerStub class as a lightweight replacement
for the full vf_viewstate module. Returns None on refresh (no actual
ViewState parsing).
"""
from __future__ import annotations


class ViewStateManagerStub:
    """Minimal ViewState manager for ASP.NET targets."""

    def __init__(self, url: str, headers_fn):
        self.url = url
        self._headers_fn = headers_fn
        self.invalid_count: int = 0
        self.viewstate_ts: float = 0.0

    async def refresh(self, session) -> str | None:
        """Attempt to fetch and parse ViewState (stub — returns None)."""
        return None


__all__ = ['ViewStateManagerStub']
