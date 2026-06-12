"""SSL/TLS analysis module (async version).

Analyzes target SSL/TLS configuration including certificate details,
cipher suites, and protocol versions.

Architecture: Phase 5 — Async ssl_analyzer Conversion
"""
from __future__ import annotations

import asyncio
import ssl
import logging
from typing import Any

from logging_config import get_logger
from utils.ssl_helpers import create_ssl_context

logger = get_logger(__name__)


async def analyze_ssl(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> dict[str, Any]:
    """Analyze SSL/TLS configuration of a target host.

    Args:
        host: Target hostname.
        port: Target port (default 443).
        timeout: Connection timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        Dict with ssl_enabled (bool | None), cert info, cipher, protocol, etc.
    """
    result: dict[str, Any] = {
        "ssl_enabled": None,
        "cert": {},
        "cipher_name": "",
        "cipher_bits": 0,
        "cipher_protocol": "",
        "ssl_version": "",
        "issuer": {},
        "subject": {},
        "issuer_org": "Unknown",
        "subject_cn": "Unknown",
        "valid_from": "Unknown",
        "expire_date": "",
        "days_remaining": 0,
    }

    reader = writer = None
    try:
        ctx = create_ssl_context(verify_ssl)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout,
        )

        ssl_object = writer.get_extra_info("ssl_object")

        # Extract certificate
        cert = ssl_object.getpeercert()
        if cert:
            result["cert"] = cert

            # Parse issuer
            try:
                issuer_raw = cert.get("issuer", ())
                if isinstance(issuer_raw, (tuple, list)):
                    result["issuer"] = dict(x[0] for x in issuer_raw if isinstance(x, (tuple, list)) and len(x) > 0)
                elif isinstance(issuer_raw, dict):
                    result["issuer"] = issuer_raw
            except (ValueError, TypeError, AttributeError):
                pass

            # Parse subject
            try:
                subject_raw = cert.get("subject", ())
                if isinstance(subject_raw, (tuple, list)):
                    result["subject"] = dict(x[0] for x in subject_raw if isinstance(subject_raw, (tuple, list)) and len(x) > 0)
                elif isinstance(subject_raw, dict):
                    result["subject"] = subject_raw
            except (ValueError, TypeError, AttributeError):
                pass

            # Issuer/subject display names
            result["issuer_org"] = result["issuer"].get("organizationName", "Unknown") if isinstance(result["issuer"], dict) else "Unknown"
            result["subject_cn"] = result["subject"].get("commonName", "Unknown") if isinstance(result["subject"], dict) else "Unknown"

            # Validity dates
            result["valid_from"] = cert.get("notBefore", "Unknown")
            result["expire_date"] = cert.get("notAfter", "")

        # Extract cipher and protocol
        cipher = ssl_object.cipher()
        if cipher:
            result["cipher_name"] = cipher[0]
            result["cipher_protocol"] = cipher[1]
            result["cipher_bits"] = cipher[2] if len(cipher) > 2 else 0

        result["ssl_version"] = ssl_object.version() or ""
        result["ssl_enabled"] = True

    except ssl.SSLError as e:
        result["ssl_enabled"] = False
        logger.debug(f"SSL error for {host}: {e}")
    except asyncio.TimeoutError:
        result["ssl_enabled"] = None
        logger.debug(f"SSL timeout for {host}:{port}")
    except Exception as e:
        result["ssl_enabled"] = None
        logger.debug(f"SSL check failed for {host}: {e}")
    finally:
        # BUG-FIX: Always close the connection to prevent file descriptor leaks
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    return result
