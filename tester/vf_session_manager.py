"""Session management for attack testing.

Handles session warmup, cookie extraction, and origin IP validation.
Extracted from VF_TESTER.py.

Architecture: Phase 4 — SessionManager Extraction
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Any
from urllib.parse import urlparse

from logging_config import get_logger
from utils.ssl_helpers import create_ssl_context
from utils.session_helpers import attack_timeout
from config.defaults import ATTACK_SESSION_MGR_TIMEOUT, ATTACK_REQUEST_TIMEOUT, DEFAULT_CONNECT_TIMEOUT_SECONDS, DNS_PROBE_TIMEOUT

logger = get_logger(__name__)

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    aiohttp = None  # type: ignore[assignment]
    _HAS_AIOHTTP = False


class SessionManager:
    """Manage attack session lifecycle.

    Handles:
    - Session warmup with cookie extraction and WAF detection
    - Origin IP preflight validation via HTTP and TCP

    Args:
        evasion_manager: Evasion manager for headers and cookies.
        verify_ssl: Whether to verify SSL certificates.
    """

    def __init__(self, evasion_manager: Any = None, verify_ssl: bool = True) -> None:
        self._evasion = evasion_manager
        self._verify_ssl = verify_ssl

        # Build reusable SSL context (same pattern as VFTester.__init__)
        self._ssl_ctx = create_ssl_context(self._verify_ssl)

    @property
    def ssl_ctx(self) -> ssl.SSLContext:
        """Current SSL context (settable for CLI override sync)."""
        return self._ssl_ctx

    @ssl_ctx.setter
    def ssl_ctx(self, value: ssl.SSLContext) -> None:
        self._ssl_ctx = value

    # ─── Session Warmup ──────────────────────────────────────────────

    async def warmup_session(
        self,
        session: Any,
        url: str,
        health_callback: Any = None,
    ) -> dict[str, Any]:
        """Warm up session by extracting cookies and detecting WAF.

        v24: Session warmup — visit target URL to establish cookies.
        Many WAFs (Cloudflare, ArvanCloud) set challenge cookies on the
        first visit. Without these cookies, subsequent requests get blocked
        immediately with 403/503. This warmup ensures the session has
        valid cookies before the attack starts.

        Also extracts cookies and feeds them to the evasion manager.

        Args:
            session: aiohttp.ClientSession to warm up.
            url: Target URL.
            health_callback: Optional callback for health updates.

        Returns:
            Dict with 'waf_name', 'cookies', 'status' keys.
        """
        result: dict[str, Any] = {
            'waf_name': None,
            'cookies': {},
            'status': None,
        }

        if not _HAS_AIOHTTP:
            logger.warning("[WARMUP] aiohttp not available — skipping warmup")
            return result

        try:
            headers = self._evasion.base_headers() if self._evasion else {}
            async with session.get(url, headers=headers,
                                   ssl=self._ssl_ctx, allow_redirects=True,
                                   timeout=attack_timeout(total=ATTACK_SESSION_MGR_TIMEOUT)) as resp:  # W2.4
                result['status'] = resp.status

                # Extract cookies from the response
                # v26 P2: Use filter_cookies for safer iteration across aiohttp versions
                from vf_validator import validate_cookie as _validate_cookie
                try:
                    cookies = {}
                    for c in session.cookie_jar:
                        try:
                            key = c.key
                            value = c.value
                            # Use centralized validation from vf_validator
                            if _validate_cookie(key, value):
                                cookies[key] = value
                        except AttributeError:
                            pass  # Skip Morsel objects without .key
                except (AttributeError, TypeError, ValueError):
                    cookies = {}
                if cookies:
                    if self._evasion and hasattr(self._evasion, 'update_cookies'):
                        self._evasion.update_cookies(cookies)
                    cookie_names = list(cookies.keys())[:5]
                    logger.info(f"[WARMUP] Session warmed — {len(cookies)} cookies captured ({', '.join(cookie_names)})")
                else:
                    logger.warning(f"[WARMUP] No cookies set by target")

                result['cookies'] = cookies

                # Check if WAF challenged us
                if resp.status in (403, 503):
                    logger.warning(f"[WARMUP] WAF challenge detected (HTTP {resp.status}) — evasion headers will be critical")
                elif resp.status < 400:
                    logger.info(f"[WARMUP] Target responded normally (HTTP {resp.status})")
                else:
                    logger.warning(f"[WARMUP] Target returned HTTP {resp.status}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"[WARMUP] Failed: {type(e).__name__} — proceeding without warmup")
        except (OSError, IOError) as e:
            logger.warning(f"[WARMUP] Network error: {type(e).__name__} — proceeding without warmup")

        return result

    # ─── Origin IP Preflight Validation ──────────────────────────────

    async def preflight_check_origin_ips(
        self,
        origin_ips: list[str],
        host: str,
        port: int = 443,
        url: str = "",
        verify_ssl: bool = True,
    ) -> list[str]:
        """Validate origin IPs via HTTP and TCP fallback.

        v22: HTTP-based origin IP validation.
        For each origin IP, sends an HTTP request with the target domain's
        Host header. Validates that the IP actually serves the target site.

        Validation criteria:
        - IP responds to HTTP with correct Host header
        - Response status is 200/301/302/403 (not 404/connection error)
        - Domain appears in response body OR response is a redirect to the domain

        Falls back to TCP check if HTTP validation fails.

        Args:
            origin_ips: List of candidate origin IPs.
            host: Target hostname for SNI.
            port: Target port.
            url: Original URL for HTTP validation.
            verify_ssl: Whether to verify SSL certificates.

        Returns:
            List of validated origin IPs.
        """
        if not origin_ips:
            return []

        if not _HAS_AIOHTTP:
            logger.warning("[ORIGIN-VALIDATE] aiohttp not available — returning all IPs unvalidated")
            return list(origin_ips[:5])

        target_is_https = urlparse(url).scheme == 'https' if url else (port == 443)
        validated = []

        # Build SSL context for this check if verify_ssl differs from default
        if verify_ssl != self._verify_ssl:
            ssl_ctx = create_ssl_context(verify_ssl)
        else:
            ssl_ctx = self._ssl_ctx

        timeout_cfg = attack_timeout(total=ATTACK_REQUEST_TIMEOUT, connect=DEFAULT_CONNECT_TIMEOUT_SECONDS)  # W2.4

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            for ip in origin_ips[:5]:
                try:
                    # Build URL pointing to origin IP with target domain's Host header
                    scheme = 'https' if target_is_https else 'http'
                    ip_url = f"{scheme}://{ip}/"
                    headers = {"Host": host, "User-Agent": "Mozilla/5.0"}

                    async with session.get(ip_url, headers=headers, ssl=ssl_ctx, allow_redirects=False) as resp:
                        status = resp.status
                        body = await resp.text(errors='ignore')

                        # Valid if:
                        # 1. Status is not 404/5xx (server recognized the host)
                        # 2. OR domain appears in response body
                        # 3. OR redirect to our domain
                        is_valid = False

                        if status in (200, 301, 302, 307, 308):
                            is_valid = True
                        elif status == 403:
                            # 403 is only valid if domain appears in body AND WAF headers present
                            lower_headers = {k.lower(): v for k, v in resp.headers.items()}
                            waf_headers = ('cf-ray', 'arvancloud', 'x-arvan',
                                           'sucuri', 'x-sucuri-id', 'x-iinfo',
                                           'x-modsecurity')
                            has_waf_header = any(h in lower_headers for h in waf_headers)
                            if has_waf_header and host in body[:2000]:
                                is_valid = True
                            else:
                                is_valid = False
                        elif status < 500 and host in body[:2000]:
                            is_valid = True

                        location = resp.headers.get('Location', '')
                        if host in location:
                            is_valid = True

                        if is_valid:
                            validated.append(ip)
                            logger.info(f"[ORIGIN-VALIDATE] {ip} → HTTP {status} ✓ (valid)")
                        else:
                            logger.warning(f"[ORIGIN-VALIDATE] {ip} → HTTP {status} ✗ (not target)")

                except asyncio.TimeoutError:
                    logger.warning(f"[ORIGIN-VALIDATE] {ip} → Timeout")
                except (aiohttp.ClientError, OSError) as e:
                    logger.debug(f"[ORIGIN-VALIDATE] {ip} → {type(e).__name__}")

        # Fallback: if no IPs passed HTTP validation, try TCP check
        if not validated:
            logger.warning(f"[ORIGIN-VALIDATE] HTTP validation failed, trying TCP fallback...")
            for ip in origin_ips[:5]:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=DNS_PROBE_TIMEOUT  # W2.4
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, IOError):
                        pass
                    validated.append(ip)
                except (OSError, IOError, asyncio.TimeoutError):
                    continue
            if validated:
                logger.warning(f"[ORIGIN-VALIDATE] {len(validated)}/{len(origin_ips)} IPs TCP-reachable (unvalidated)")

        if not validated:
            logger.warning(f"[ORIGIN-VALIDATE] 0/{len(origin_ips)} IPs valid — skipping origin plugins")

        return validated
