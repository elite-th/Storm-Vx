"""HTTP fingerprinting module.

Performs the initial HTTP request to gather server headers, status codes,
cookies, and redirect chains.
"""
from __future__ import annotations
import asyncio
import re
import time
from typing import Dict, Tuple, Any

import aiohttp


from vf_common import C, ssl_param
from utils.response_helpers import safe_read_text
from utils.session_helpers import scanner_timeout
from config.defaults import FINGERPRINT_TIMEOUT
from logging_config import get_logger
logger = get_logger(__name__)
from finder.site_profile import SiteProfile


async def http_fingerprint(url: str, profile: SiteProfile, verify_ssl: bool = True) -> Tuple[str | None, SiteProfile]:
    """Fetch the page and extract HTTP-level information.

    Args:
        url: Target URL to fingerprint.
        profile: SiteProfile to populate with results.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        Tuple of (html_content, updated_profile).
    """
    timeout = scanner_timeout(total=FINGERPRINT_TIMEOUT)  # W2.4
    html: str | None = None
    _ssl = ssl_param(verify_ssl)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Main page request
            t0 = time.monotonic()
            async with session.get(url, ssl=_ssl, allow_redirects=True) as resp:
                html = await safe_read_text(resp)  # W1.10: bounded read
                elapsed = time.monotonic() - t0

                profile.status_code = resp.status
                profile.response_time = elapsed
                profile.page_size = len(html or '')
                profile.html_size = len(html or '')

                # Headers
                profile.headers = dict(resp.headers)

                # Cookies
                try:
                    from yarl import URL as YarlURL
                    for cookie in session.cookie_jar.filter_cookies(YarlURL(url)).values():
                        profile.cookies[cookie.key] = cookie.value
                except (ImportError, AttributeError):
                    try:
                        for cookie in session.cookie_jar:
                            profile.cookies[cookie.key] = cookie.value
                    except (AttributeError, TypeError, KeyError):  # Intentional: cookie jar access varies by aiohttp version
                        pass

                # Redirect chain
                if resp.history:
                    profile.redirect_chain = [str(h.url) for h in resp.history]

                # Server detection
                server_header = resp.headers.get('Server', '')
                if server_header:
                    profile.server = server_header
                    # Extract version (support hyphenated names like Microsoft-IIS)
                    match = re.match(r'([\w.-]+)/([\d.]+)', server_header)
                    if match:
                        profile.server = match.group(1)
                        profile.server_version = match.group(2)

                # Powered-By
                powered_by = resp.headers.get('X-Powered-By', '')
                if powered_by:
                    profile.backend_framework = powered_by

                # ASP.NET version
                aspnet_ver = resp.headers.get('X-AspNet-Version', '')
                if aspnet_ver:
                    profile.backend_lang = f"ASP.NET {aspnet_ver}"

                print(f"  {C.G}  Status: {resp.status} | RT: {elapsed*1000:.0f}ms | Size: {profile.page_size:,}B{C.RS}")
                if profile.server:
                    print(f"  {C.G}  Server: {profile.server}{C.RS}")
                if powered_by:
                    print(f"  {C.G}  Powered-By: {powered_by}{C.RS}")

    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.error(f"HTTP fingerprinting error: {e}", exc_info=True)

    return html, profile
