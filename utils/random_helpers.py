#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""utils.random_helpers — Random string, UA, and token generators.

W2.1 EXTRACTION: Pulled from vf_common.py (921 lines) to decompose
the god module. This domain has ZERO dependencies on C, themes, or
any other vf_common domain — making it the safest first extraction.

Previously in vf_common.py, these functions were scattered between
lines 787-871 alongside unrelated UI and theme code. Now they have
a single-responsibility home.

Backward compatibility: vf_common.py re-exports all names, so
existing `from vf_common import rand_str` continues to work.
New code should import directly: `from utils.random_helpers import rand_str`.
"""
from __future__ import annotations

import random
import secrets
import string
import time

from logging_config import get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# User-Agent Strings
# ═══════════════════════════════════════════════════════════════════════════════

USER_AGENTS = [
    # Chrome 130-133 (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome 130-133 (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Chrome 130-133 (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Firefox 132-135 (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Firefox 132-135 (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Firefox 132-135 (Linux)
    "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    # Safari 17.4-17.6 (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Edge 130-133 (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    # Mobile Chrome 130+ (Android)
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    # Mobile Safari 17.4+ (iOS)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


# ═══════════════════════════════════════════════════════════════════════════════
# Random Generators
# ═══════════════════════════════════════════════════════════════════════════════

def random_ua() -> str:
    """Return a random User-Agent string."""
    return random.choice(USER_AGENTS)


def rand_str(length: int = 8) -> str:
    """Generate a random alphanumeric string using cryptographically secure RNG."""
    return ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def rand_user() -> str:
    """Generate a random username.

    NOTE: Uses random.choice (not secrets) for prefix selection — the prefix
    is not security-sensitive, only the suffix (from rand_str) needs to be
    unpredictable. This is intentional: the prefix is purely cosmetic.
    """
    prefixes = ['user', 'admin', 'guest', 'test', 'member', 'demo', 'info', 'support']
    return f"{random.choice(prefixes)}_{rand_str(6)}"


def rand_pass() -> str:
    """Generate a random password using cryptographically secure RNG."""
    chars = string.ascii_letters + string.digits + "!@#$%"
    length = secrets.randbelow(9) + 8  # 8-16, equivalent to random.randint(8, 16)
    return ''.join(secrets.choice(chars) for _ in range(length))


def rand_cache_bust() -> str:
    """Generate a cache-busting query parameter."""
    return f"_={rand_str(12)}&t={int(time.time() * 1000)}"


def secure_token(length: int = 16) -> str:
    """Generate a cryptographically secure session token.

    Uses secrets.token_hex() for maximum entropy.
    Returns a hex string of 2*length characters (length bytes of randomness).
    """
    return secrets.token_hex(length)


# ═══════════════════════════════════════════════════════════════════════════════
# Network Helpers — unified from scattered duplicates (Task 2.7)
# ═══════════════════════════════════════════════════════════════════════════════

# First-octet ranges for realistic-looking random IPs (avoids 0.x, 127.x, 224+)
_SAFE_FIRST_OCTETS = list(range(1, 127)) + list(range(128, 224))


def rand_ip() -> str:
    """Generate a random public-looking IPv4 address.

    W2.7 FIX: Replaces 3 different random IP implementations:
    - vf_evasion_stub._rand_ip() (18-line function with hand-curated list)
    - vf_api_flood inline f"{random.randint(1,255)}..." (6 occurrences)
    - vf_slowloris inline f"{random.randint(1,255)}..." (1 occurrence)

    Generates IPs that look like real public addresses, avoiding:
    - 0.x.x.x (reserved)
    - 127.x.x.x (loopback)
    - 224+.x.x.x (multicast/reserved)

    Not cryptographically secure — IPs are for header spoofing only.
    """
    first = random.choice(_SAFE_FIRST_OCTETS)
    return f"{first}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def join_url(base: str, path: str) -> str:
    """Join a base URL and a path, handling trailing/leading slashes.

    W2.7 FIX: Replaces 15+ scattered ``url.rstrip('/') + '/' + path.lstrip('/')``
    patterns across the codebase (vf_updater, vf_ws_flood, vf_resource_flood,
    vf_cache_poison, vf_wp_xmlrpc_bomb, vf_wp_pingback_amplify,
    vf_cache_analyzer, vf_dir_fuzzer).

    Always produces exactly one ``/`` between base and path, regardless
    of whether base has a trailing slash or path has a leading slash.

    Args:
        base: Base URL (e.g., "https://example.com" or "https://example.com/")
        path: Path to append (e.g., "/api/v1" or "api/v1")

    Returns:
        Joined URL with exactly one slash between base and path.

    Examples:
        >>> join_url("https://example.com", "/api/v1")
        'https://example.com/api/v1'
        >>> join_url("https://example.com/", "api/v1")
        'https://example.com/api/v1'
        >>> join_url("https://example.com/", "/api/v1")
        'https://example.com/api/v1'
    """
    return base.rstrip('/') + '/' + path.lstrip('/')
