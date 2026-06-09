#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""utils.ssl_helpers — Centralized SSL parameter computation and context creation.

Extracted from vf_common.py as part of the god-module decomposition (Task 2.1).

ARCH-5 fix: Replaces scattered `ssl=False` hardcoding across finder/infra/evasion
modules with a single source of truth for SSL parameter computation.

Task 2.7: Added create_ssl_context() to replace the identical 4-line
"create_default_context + disable verification" block that was copy-pasted
in 7 different files (VF_TESTER, vf_session_manager, vf_attack_base,
vf_origin_discovery, vf_fp_cloner).

This module has ZERO dependencies on vf_common.py internals (no colors, themes, etc.)
making it safe to import from any subsystem without circular import risk.
"""
from __future__ import annotations

import ssl
from typing import Any


def ssl_param(verify_ssl: bool = True, ssl_ctx: Any = None) -> Any:
    """Compute the correct ssl parameter for aiohttp/httpx requests.

    Security-first: SSL verification enabled by default.

    Args:
        verify_ssl: Whether to verify SSL certificates (default True).
        ssl_ctx: Pre-built SSL context (takes precedence).

    Returns:
        ssl_ctx if provided, otherwise None (verify) or False (no verify).

    Examples:
        >>> ssl_param(verify_ssl=True)
        None
        >>> ssl_param(verify_ssl=False)
        False
        >>> import ssl; ctx = ssl.create_default_context()
        >>> ssl_param(verify_ssl=False, ssl_ctx=ctx) is ctx
        True
    """
    if ssl_ctx is not None:
        return ssl_ctx
    return None if verify_ssl else False


def create_ssl_context(verify_ssl: bool = True) -> ssl.SSLContext:
    """Create an SSL context with optional verification disabling.

    W2.7 FIX: Replaces the identical 4-line block copy-pasted in 7 files:
        ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    Now there's a single source of truth for SSL context creation.
    Use this for raw asyncio.open_connection() calls that need an
    actual ssl.SSLContext object (not just the ssl= param for aiohttp).

    For aiohttp sessions, use ssl_param() instead — it returns None/False.

    Args:
        verify_ssl: Whether to verify SSL certificates (default True).

    Returns:
        Configured ssl.SSLContext.

    Examples:
        >>> ctx = create_ssl_context(verify_ssl=True)
        >>> ctx.verify_mode.name
        'CERT_REQUIRED'
        >>> ctx = create_ssl_context(verify_ssl=False)
        >>> ctx.verify_mode.name
        'CERT_NONE'
    """
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx
