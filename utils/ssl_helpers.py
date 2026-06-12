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

BUG-021 fix (FR-P3-012): Added create_no_verify_ssl_context() with caching
to avoid creating a new SSLContext on every call when verification is disabled.
Updated create_ssl_context() to use the cached context when verify_ssl=False.

This module has ZERO dependencies on vf_common.py internals (no colors, themes, etc.)
making it safe to import from any subsystem without circular import risk.
"""
from __future__ import annotations

import ssl
from typing import Any


# ═══════════════════════════════════════════════════════════════════════════════
# BUG-021: Cached no-verify SSL context (singleton)
# ═══════════════════════════════════════════════════════════════════════════════
_no_verify_ctx: ssl.SSLContext | None = None


def create_no_verify_ssl_context() -> ssl.SSLContext:
    """Return a cached SSL context with verification disabled.

    BUG-021 fix: The no-verify context is immutable after creation
    (check_hostname=False, verify_mode=CERT_NONE), so it is safe to
    reuse across all callers.  Caching avoids the overhead of creating
    a new SSLContext on every call.

    Returns:
        A cached ssl.SSLContext with hostname checking and certificate
        verification disabled.
    """
    global _no_verify_ctx
    if _no_verify_ctx is None:
        _no_verify_ctx = ssl.create_default_context()
        _no_verify_ctx.check_hostname = False
        _no_verify_ctx.verify_mode = ssl.CERT_NONE
    return _no_verify_ctx


def ssl_param(verify_ssl: bool = False, ssl_ctx: Any = None) -> Any:
    """Compute the correct ssl parameter for aiohttp/httpx requests.

    Phase 0: Default False for attack mode.

    Args:
        verify_ssl: Whether to verify SSL certificates (default False).
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


def create_ssl_context(verify_ssl: bool = False) -> ssl.SSLContext:
    """Create an SSL context with optional verification disabling.

    Phase 0: Default False for attack mode.

    W2.7 FIX: Replaces the identical 4-line block copy-pasted in 7 files:
        ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    BUG-021 fix: When verify_ssl=False, returns a cached singleton context
    via create_no_verify_ssl_context() instead of creating a new one each time.

    Use this for raw asyncio.open_connection() calls that need an
    actual ssl.SSLContext object (not just the ssl= param for aiohttp).

    For aiohttp sessions, use ssl_param() instead — it returns None/False.

    Args:
        verify_ssl: Whether to verify SSL certificates (default False).

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
    if not verify_ssl:
        return create_no_verify_ssl_context()
    return ssl.create_default_context()
