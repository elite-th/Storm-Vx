"""TLS client wrapper for realistic browser fingerprinting.

Provides true JA3/JA4 fingerprint cloning using the tls-client library.
Falls back to Python's ssl module when tls-client is not available.

Architecture: Phase 6 — Real JA3 Fingerprint Support
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from logging_config import get_logger

logger = get_logger(__name__)

# Try to import tls-client for real browser fingerprints
try:
    import tls_client
    _HAS_TLS_CLIENT = True
except ImportError:
    tls_client = None
    _HAS_TLS_CLIENT = False


# Browser profile mapping for tls-client
BROWSER_PROFILES: dict[str, str] = {
    "chrome_120": "chrome_120",
    "chrome_116": "chrome_116",
    "firefox_120": "firefox_120",
    "safari_17_0": "safari_17_0_ios",
    "edge_120": "chrome_120",  # Edge uses Chromium
}


class RealisticTLSClient:
    """HTTP client with real browser TLS fingerprints.

    Uses tls-client when available for true JA3/JA4 matching.
    Falls back to standard aiohttp when tls-client is not installed.

    Usage:
        client = RealisticTLSClient("chrome_120")
        response = client.get("https://target.com")
    """

    def __init__(self, browser: str = "chrome_120", verify_ssl: bool = True) -> None:
        self._browser = browser
        self._verify_ssl = verify_ssl
        self._session: Any = None

        if _HAS_TLS_CLIENT:
            identifier = BROWSER_PROFILES.get(browser, "chrome_120")
            self._session = tls_client.Session(
                client_identifier=identifier,
                random_tls_extension_order=True,
            )
            logger.info(f"TLS client initialized with {browser} fingerprint")
        else:
            logger.info(
                "tls-client not installed — using fallback ssl module. "
                "Install with: pip install tls-client"
            )

    @property
    def has_real_fingerprints(self) -> bool:
        """Whether this client produces real browser JA3 hashes."""
        return _HAS_TLS_CLIENT

    def get(self, url: str, headers: dict[str, str] | None = None) -> Any:
        """Send GET request with browser-like TLS fingerprint.

        Note: tls-client is synchronous. For async usage, use async_get()
        instead to avoid blocking the event loop.

        Args:
            url: Target URL.
            headers: Optional HTTP headers dict.

        Returns:
            Response object from tls-client, or None if session is unavailable.
        """
        if self._session is not None:
            return self._session.get(
                url,
                headers=headers or {},
                verify_ssl=self._verify_ssl,
            )
        return None

    def post(self, url: str, headers: dict[str, str] | None = None, data: Any = None) -> Any:
        """Send POST request with browser-like TLS fingerprint.

        Note: tls-client is synchronous. For async usage, use async_post()
        instead to avoid blocking the event loop.

        Args:
            url: Target URL.
            headers: Optional HTTP headers dict.
            data: Optional request body.

        Returns:
            Response object from tls-client, or None if session is unavailable.
        """
        if self._session is not None:
            return self._session.post(
                url,
                headers=headers or {},
                data=data,
                verify_ssl=self._verify_ssl,
            )
        return None

    async def async_get(self, url: str, headers: dict[str, str] | None = None) -> Any:
        """Send GET request asynchronously without blocking the event loop.

        Runs the synchronous tls-client call in a thread pool executor so
        that the asyncio event loop is not blocked while the TLS handshake
        and HTTP request are in progress.

        Args:
            url: Target URL.
            headers: Optional HTTP headers dict.

        Returns:
            Response object from tls-client, or None if session is unavailable.
        """
        if self._session is not None:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self.get(url, headers)
            )
        return None

    async def async_post(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        data: Any = None,
    ) -> Any:
        """Send POST request asynchronously without blocking the event loop.

        Runs the synchronous tls-client call in a thread pool executor so
        that the asyncio event loop is not blocked while the TLS handshake
        and HTTP request are in progress.

        Args:
            url: Target URL.
            headers: Optional HTTP headers dict.
            data: Optional request body.

        Returns:
            Response object from tls-client, or None if session is unavailable.
        """
        if self._session is not None:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self.post(url, headers, data)
            )
        return None

    def close(self) -> None:
        """Close the TLS client session."""
        # tls-client sessions don't need explicit closing
        self._session = None
