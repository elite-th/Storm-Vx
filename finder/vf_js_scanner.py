#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  vf_js_scanner.py — JavaScript Secret Scanner Module                    ║
║  Part of the STORM_VX Toolkit                                           ║
║                                                                          ║
║  Downloads JS files and scans them with regex patterns to find:          ║
║  - API keys (AWS, Google, Stripe, GitHub, etc.)                         ║
║  - Tokens (Bearer, JWT, authorization headers)                          ║
║  - Internal IPs (10.x, 172.16-31.x, 192.168.x)                        ║
║  - Hidden endpoints (/api/, /admin/, /graphql, etc.)                    ║
║  - Secrets (passwords, private keys, credentials)                       ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import re
import time
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin

import aiohttp

from vf_common import C, ssl_param
from utils.response_helpers import safe_read_js
from utils.session_helpers import scanner_timeout
from config.defaults import JS_SCAN_MAX_FILE_SIZE, JS_SCAN_TOTAL_TIMEOUT, JS_SCAN_HEAD_CHARS, JS_SCAN_SEMAPHORE
from finder.signatures import CDN_DOMAIN_SUFFIXES


# ═══════════════════════════════════════════════════════════════════════════════
# Scan Limits
# ═══════════════════════════════════════════════════════════════════════════════

MAX_FILE_SIZE = JS_SCAN_MAX_FILE_SIZE          # W2.4 — 256 KB — skip files larger than this (v23: reduced for speed)
TOTAL_SCAN_TIMEOUT = JS_SCAN_TOTAL_TIMEOUT          # W2.4 — 30 seconds — abort the entire scan after this (v23: was 60, too slow)
HEAD_FIRST = True                # Do a HEAD request before GET to check size
SCAN_HEAD_CHARS = JS_SCAN_HEAD_CHARS         # W2.4 — Scan only first 50 KB of content for large files (v23: was 100K)

# CDN domains to skip — they never contain site-specific secrets
# BUG-033: Moved from local definition to finder.signatures.CDN_DOMAIN_SUFFIXES
_CDN_DOMAINS = CDN_DOMAIN_SUFFIXES

# URL schemes to skip (non-downloadable)
_SKIP_URL_PREFIXES = ('data:', 'javascript:', 'blob:', 'file:', 'about:')

# Content types we accept for scanning
_ACCEPTABLE_CONTENT_TYPES = {
    "javascript", "text/", "application/json", "application/xml",
}

# Content types we reject outright
_REJECT_CONTENT_TYPES = {
    "image/", "video/", "audio/", "font/", "application/octet-stream",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Regex Pattern Database
# ═══════════════════════════════════════════════════════════════════════════════

API_KEY_PATTERNS = [
    ("AWS Access Key", r'AKIA[0-9A-Z]{16}'),
    ("AWS Secret Key", r'(?i)aws(.{0,20})?(?-i)[\'"][0-9a-zA-Z/+]{40}[\'"]'),
    ("Google API Key", r'AIza[0-9A-Za-z\-_]{35}'),
    ("Google OAuth", r'[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com'),
    ("Stripe Publishable", r'pk_(live|test)_[0-9a-zA-Z]{24}'),
    ("Stripe Secret", r'sk_(live|test)_[0-9a-zA-Z]{24}'),
    ("Stripe Restricted", r'rk_(live|test)_[0-9a-zA-Z]{24}'),
    ("GitHub Token", r'ghp_[0-9a-zA-Z]{36}'),
    ("GitHub OAuth", r'gho_[0-9a-zA-Z]{36}'),
    ("GitHub App Token", r'(ghu|ghs)_[0-9a-zA-Z]{36}'),
    ("GitHub Refresh", r'ghr_[0-9a-zA-Z]{36}'),
    ("SendGrid API Key", r'SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}'),
    ("Mailgun API Key", r'key-[0-9a-zA-Z]{32}'),
    ("Slack Bot Token", r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
    ("Slack User Token", r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
    ("Slack App Token", r'xapp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}'),
    ("Slack Webhook", r'https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[a-zA-Z0-9]{24}'),
    ("Twilio API Key", r'SK[0-9a-fA-F]{32}'),
    ("Firebase Key", r'AIza[0-9A-Za-z\-_]{35}'),
    ("Azure Tenant", r'https://login\.microsoftonline\.com/([0-9a-fA-F\-]{36})'),
    ("Azure Client Secret", r'(?i)client[_\-]?secret[\'"\s:=]+[\'"]([a-zA-Z0-9~_.-]{20,40})[\'"]'),
    ("Heroku API Key", r'(?i)heroku(.{0,20})?[\'"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[\'"]'),
    ("Shopify Token", r'shp(at|ca|ss|pa|ma)_[0-9a-fA-F]{32}'),
    ("PayPal Braintree", r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
    ("Square Access Token", r'sq0atp-[0-9A-Za-z\-_]{22}'),
    ("Square OAuth Secret", r'sq0csp-[0-9A-Za-z\-_]{43}'),
    ("Telegram Bot Token", r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}'),
    ("Discord Bot Token", r'[MN][a-zA-Z\d]{23,}\.[\w-]{6}\.[\w-]{27}'),
    ("NPM Token", r'(?i)//registry\.npmjs\.org/:_authToken=[0-9a-f-]{36}'),
    ("Docker Hub", r'(?i)docker(.{0,20})?hub[\'"\s:=]+[\'"][a-zA-Z0-9]{20,}[\'"]'),
    ("Jenkins Token", r'(?i)jenkins(.{0,20})?token[\'"\s:=]+[\'"][a-zA-Z0-9]{20,}[\'"]'),
]

TOKEN_PATTERNS = [
    ("Bearer Token", r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*'),
    ("JWT Token", r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'),
    ("Authorization Header", r'(?i)authorization\s*[:=]\s*[\'"]?[Bb]earer\s+[^\s\'"]+'),
    ("Basic Auth", r'(?i)basic\s+[a-zA-Z0-9+/]+=*'),
    ("OAuth Token", r'(?i)oauth[_\-]?token[\'"\s:=]+[\'"]?[a-zA-Z0-9\-._~+/]+=*'),
    ("Access Token", r'(?i)access[_\-]?token[\'"\s:=]+[\'"]?[a-zA-Z0-9\-._~+/]{20,}'),
    ("Refresh Token", r'(?i)refresh[_\-]?token[\'"\s:=]+[\'"]?[a-zA-Z0-9\-._~+/]{20,}'),
    ("ID Token", r'(?i)id[_\-]?token[\'"\s:=]+[\'"]?[a-zA-Z0-9\-._~+/]{20,}'),
    ("X-Auth-Token", r'(?i)x[\-_]auth[\-_]token[\'"\s:=]+[\'"]?[a-zA-Z0-9\-._~+/]{20,}'),
    ("API Token", r'(?i)api[\-_]?token[\'"\s:=]+[\'"]?[a-zA-Z0-9\-._~+/]{20,}'),
    ("Session Token", r'(?i)session[\-_]?token[\'"\s:=]+[\'"]?[a-zA-Z0-9\-._~+/]{20,}'),
    ("CSRF Token", r'(?i)csrf[\-_]?token[\'"\s:=]+[\'"]?[a-zA-Z0-9\-._~+/]{20,}'),
]

INTERNAL_IP_PATTERNS = [
    ("Private IP 10.x", r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    ("Private IP 172.16-31", r'\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b'),
    ("Private IP 192.168", r'\b192\.168\.\d{1,3}\.\d{1,3}\b'),
    ("Loopback 127.x", r'\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    ("Link-Local 169.254", r'\b169\.254\.\d{1,3}\.\d{1,3}\b'),
    ("Metadata 169.254.169.254", r'\b169\.254\.169\.254\b'),
    ("IPv6 Loopback", r'\[::1\]|\b0:0:0:0:0:0:0:1\b'),
]

HIDDEN_ENDPOINT_PATTERNS = [
    ("API Endpoint", r'["\'](/api/[^"\']+)["\']'),
    ("API v1", r'["\'](/v1/[^"\']+)["\']'),
    ("API v2", r'["\'](/v2/[^"\']+)["\']'),
    ("Admin Panel", r'["\'](/admin/[^"\']*)["\']'),
    ("Internal Route", r'["\'](/internal/[^"\']+)["\']'),
    ("GraphQL", r'["\'](/graphql[^"\']*)["\']'),
    ("Debug Route", r'["\'](/debug/[^"\']+)["\']'),
    ("Swagger UI", r'["\'](/swagger[^"\']*)["\']'),
    ("OpenAPI", r'["\'](/openapi[^"\']*)["\']'),
    ("GraphQL Playground", r'["\'](/graphiql[^"\']*)["\']'),
    ("Actuator", r'["\'](/actuator[^"\']*)["\']'),
    ("Metrics", r'["\'](/metrics[^"\']*)["\']'),
    ("Health Check", r'["\'](/health[^"\']*)["\']'),
    ("WebSocket", r'["\']wss?://[^"\']+["\']'),
    ("Fetch URL", r'fetch\(["\']([^"\']+)["\']'),
    ("Axios URL", r'axios\.\w+\(["\']([^"\']+)["\']'),
    ("XHR URL", r'\.open\(["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([^"\']+)["\']'),
]

SECRET_PATTERNS = [
    ("Password Assignment", r'(?i)password\s*[:=]\s*[\'"][^\'"]{4,}[\'"]'),
    ("Password JSON", r'(?i)["\']password["\']\s*:\s*["\'][^"\']{4,}["\']'),
    ("Secret Key", r'(?i)secret[_\-]?key\s*[:=]\s*[\'"][^\'"]{4,}[\'"]'),
    ("Secret JSON", r'(?i)["\']secret[_\-]?key["\']\s*:\s*["\'][^"\']{4,}["\']'),
    ("Private Key", r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'),
    ("Credentials Object", r'(?i)credentials\s*[:=]\s*\{[^}]{10,}\}'),
    ("DB Connection String", r'(?i)(?:mongodb|mysql|postgres|postgresql|redis|mssql|amqp)://[^\s\'"<>]+'),
    ("JDBC String", r'(?i)jdbc:[a-zA-Z]+://[^\s\'"<>]+'),
    ("S3 Bucket", r'(?i)s3[.\-_]?[a-zA-Z0-9\-]+\.amazonaws\.com'),
    ("AWS Endpoint", r'(?i)https?://[a-z0-9\-]+\.execute-api\.[a-z0-9\-]+\.amazonaws\.com'),
    ("Firebase URL", r'(?i)https?://[a-z0-9\-]+\.firebaseio\.com'),
    ("Encryption Key", r'(?i)(?:encryption|encrypt|aes|rsa)[_\-]?key\s*[:=]\s*[\'"][^\'"]{8,}[\'"]'),
    ("Signing Key", r'(?i)signing[_\-]?key\s*[:=]\s*[\'"][^\'"]{8,}[\'"]'),
    ("Client Secret", r'(?i)client[_\-]?secret\s*[:=]\s*[\'"][^\'"]{8,}[\'"]'),
    ("API Secret", r'(?i)api[_\-]?secret\s*[:=]\s*[\'"][^\'"]{8,}[\'"]'),
]


def _is_acceptable_content_type(content_type: str) -> bool:
    """Check if a Content-Type header is acceptable for JS scanning."""
    ct_lower = content_type.lower()
    # Reject known non-text types first
    for reject in _REJECT_CONTENT_TYPES:
        if reject in ct_lower:
            return False
    # Accept if it matches known text types or is empty
    if not ct_lower:
        return True
    for accept in _ACCEPTABLE_CONTENT_TYPES:
        if accept in ct_lower:
            return True
    # Default: reject unknown content types
    return False


class JSSecretScanner:
    """
    JavaScript secret scanner for STORM_VX.

    Downloads JS files, scans them with comprehensive regex patterns
    for API keys, tokens, internal IPs, hidden endpoints, and secrets.
    """

    def __init__(self, url: str, scripts: List[str], timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize JSSecretScanner.

        Args:
            url: Base URL of the target site
            scripts: List of JS file URLs (relative or absolute)
            timeout: HTTP request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.url = url
        self.scripts = self._filter_scripts(scripts)  # v23: Pre-filter invalid/CDN scripts
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._ssl = ssl_param(self.verify_ssl)
        self._semaphore = asyncio.Semaphore(JS_SCAN_SEMAPHORE)  # W2.4 — Rate limit: 6 concurrent downloads (was 8)
        self._compiled = {}  # Cache compiled regex patterns
        self._downloaded_urls: Set[str] = set()  # v23: Deduplicate downloads

    def _filter_scripts(self, scripts: List[str]) -> List[str]:
        """v23: Pre-filter scripts — remove data:, CDN, duplicates, non-HTTP."""
        filtered = []
        seen = set()
        skipped_cdn = 0
        skipped_scheme = 0
        skipped_dup = 0

        for s in scripts:
            # Skip non-HTTP schemes
            if any(s.startswith(pfx) for pfx in _SKIP_URL_PREFIXES):
                skipped_scheme += 1
                continue

            # Resolve URL to check CDN
            resolved = self._resolve_url(s)
            if not resolved:
                skipped_scheme += 1
                continue

            # Skip CDN-hosted scripts (they never contain site-specific secrets)
            if self._is_cdn_url(resolved):
                skipped_cdn += 1
                continue

            # Deduplicate
            key = resolved.lower().rstrip('/')
            if key in seen:
                skipped_dup += 1
                continue
            seen.add(key)

            filtered.append(s)

        if skipped_cdn or skipped_scheme or skipped_dup:
            print(f"  {C.DM}    JS filter: {len(scripts)} → {len(filtered)} scripts "
                  f"(skipped: {skipped_cdn} CDN, {skipped_scheme} non-HTTP, {skipped_dup} dupes){C.RS}")

        return filtered

    @staticmethod
    def _is_cdn_url(url: str) -> bool:
        """v23: Check if a URL is hosted on a known CDN."""
        url_lower = url.lower()
        for cdn in _CDN_DOMAINS:
            if cdn in url_lower:
                return True
        return False

    async def run(self) -> Dict:
        """
        Run JS secret scanning.

        Returns:
            Dictionary with:
                - api_keys: List of found API keys
                - tokens: List of found tokens
                - internal_ips: List of found internal IPs
                - hidden_endpoints: List of found hidden endpoints
                - secrets: List of found secrets
        """
        if not self.scripts:
            print(f"\n  {C.DM}[*] JS Secret Scanner — No origin scripts to scan{C.RS}")
            return {"api_keys": [], "tokens": [], "internal_ips": [],
                    "hidden_endpoints": [], "secrets": []}

        print(f"\n  {C.BD}{C.CY}[*] JS Secret Scanner — {self.url}{C.RS}")
        print(f"  {C.DM}    Scripts to scan: {len(self.scripts)} | Timeout: {self.timeout}s | Max: {MAX_FILE_SIZE//1024}KB{C.RS}")

        t0 = time.monotonic()

        api_keys: List[Dict] = []
        tokens: List[Dict] = []
        internal_ips: List[Dict] = []
        hidden_endpoints: List[Dict] = []
        secrets: List[Dict] = []
        seen_endpoints: Set[str] = set()

        # Counters for summary
        files_scanned = 0
        files_skipped_size = 0     # skipped because too large or too small
        files_skipped_error = 0    # skipped due to download error
        total_bytes_scanned = 0

        # v15: Download and scan each JS file IN PARALLEL
        timeout_cfg = scanner_timeout(total=self.timeout)

        # Shared flag to signal timeout abort
        scan_timed_out = asyncio.Event()

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            async def _process_script(idx, script_url):
                """Download and scan a single JS file — returns all findings."""
                nonlocal files_scanned, files_skipped_size, files_skipped_error, total_bytes_scanned

                # Check if scan has been aborted due to total timeout
                if scan_timed_out.is_set():
                    return [], [], [], [], []

                full_url = self._resolve_url(script_url)

                # Skip invalid URLs immediately
                if not full_url:
                    files_skipped_error += 1
                    return [], [], [], [], []

                # v23: Deduplicate by resolved URL
                if full_url in self._downloaded_urls:
                    return [], [], [], [], []
                self._downloaded_urls.add(full_url)
                # Cap set size to prevent unbounded memory growth
                if len(self._downloaded_urls) > 2000:
                    # Remove oldest entries by clearing and re-adding recent ones
                    # (Sets are unordered, so this is a simple size cap)
                    excess = len(self._downloaded_urls) - 1500
                    for _ in range(excess):
                        self._downloaded_urls.pop()

                script_api_keys = []
                script_tokens = []
                script_internal_ips = []
                script_endpoints = []
                script_secrets = []

                print(f"  {C.B}  [{idx+1}/{len(self.scripts)}] {C.DM}{full_url[:80]}{C.RS}")

                # HEAD request first to check size (if enabled)
                if HEAD_FIRST:
                    head_size = await self._head_check(session, full_url)
                    if head_size is not None and head_size > MAX_FILE_SIZE:
                        print(f"  {C.Y}    ✗ {head_size:,}B — Skip (>{MAX_FILE_SIZE//1024}KB){C.RS}")
                        files_skipped_size += 1
                        return [], [], [], [], []

                js_content = await self._download_js(session, full_url)
                if not js_content:
                    files_skipped_error += 1
                    return [], [], [], [], []

                content_size = len(js_content)

                # Skip files larger than MAX_FILE_SIZE
                if content_size > MAX_FILE_SIZE:
                    print(f"  {C.Y}    ✗ {content_size:,}B — Skip (>{MAX_FILE_SIZE//1024}KB){C.RS}")
                    files_skipped_size += 1
                    return [], [], [], [], []

                # Skip tiny JS files (likely redirects or error pages)
                if content_size < 500:
                    files_skipped_size += 1
                    return [], [], [], [], []

                # For large files, scan only the first SCAN_HEAD_CHARS characters
                scan_content = js_content[:SCAN_HEAD_CHARS] if content_size > SCAN_HEAD_CHARS else js_content
                total_bytes_scanned += len(scan_content)
                files_scanned += 1

                size_info = f"{content_size:,}B" if content_size < 1024 else f"{content_size//1024}KB"
                print(f"  {C.G}    ↓ {size_info} — scanning...{C.RS}")

                # Scan for API keys
                for name, pattern in API_KEY_PATTERNS:
                    matches = self._find_with_context(scan_content, pattern)
                    for match_text, context in matches:
                        result = {
                            "type": name, "match": match_text, "context": context,
                            "file": script_url, "full_url": full_url,
                        }
                        script_api_keys.append(result)
                        print(f"  {C.R}    [API KEY] {name}: {match_text}{C.RS}")
                        print(f"  {C.DM}             Context: ...{context}...{C.RS}")

                # Scan for tokens
                for name, pattern in TOKEN_PATTERNS:
                    matches = self._find_with_context(scan_content, pattern)
                    for match_text, context in matches:
                        result = {
                            "type": name, "match": match_text, "context": context,
                            "file": script_url, "full_url": full_url,
                        }
                        script_tokens.append(result)
                        print(f"  {C.Y}    [TOKEN] {name}: {match_text[:60]}...{C.RS}")
                        print(f"  {C.DM}             Context: ...{context}...{C.RS}")

                # Scan for internal IPs
                for name, pattern in INTERNAL_IP_PATTERNS:
                    matches = self._find_with_context(scan_content, pattern)
                    for match_text, context in matches:
                        result = {
                            "type": name, "ip": match_text, "context": context,
                            "file": script_url, "full_url": full_url,
                        }
                        script_internal_ips.append(result)
                        print(f"  {C.M}    [INTERNAL IP] {name}: {match_text}{C.RS}")

                # Scan for hidden endpoints
                for name, pattern in HIDDEN_ENDPOINT_PATTERNS:
                    matches = self._find_with_context(scan_content, pattern)
                    for match_text, context in matches:
                        if match_text not in seen_endpoints:
                            seen_endpoints.add(match_text)
                            result = {
                                "type": name, "endpoint": match_text, "context": context,
                                "file": script_url, "full_url": full_url,
                            }
                            script_endpoints.append(result)
                            print(f"  {C.CY}    [ENDPOINT] {name}: {match_text}{C.RS}")

                # Scan for secrets
                for name, pattern in SECRET_PATTERNS:
                    matches = self._find_with_context(scan_content, pattern)
                    for match_text, context in matches:
                        result = {
                            "type": name, "match": match_text, "context": context,
                            "file": script_url, "full_url": full_url,
                        }
                        script_secrets.append(result)
                        print(f"  {C.R}    [SECRET] {name}{C.RS}")
                        print(f"  {C.DM}             Context: ...{context}...{C.RS}")

                return script_api_keys, script_tokens, script_internal_ips, script_endpoints, script_secrets

            # v15: Process all scripts IN PARALLEL with total timeout
            # Collect results incrementally so completed scans survive a timeout
            _completed_results: List[tuple] = []

            async def _run_with_timeout():
                nonlocal _completed_results
                coros = [_process_script(i, s) for i, s in enumerate(self.scripts)]
                # Use asyncio.as_completed to gather results as they finish
                # so partial results survive a timeout
                for coro in asyncio.as_completed(coros):
                    result = await coro
                    _completed_results.append(result)

            try:
                await asyncio.wait_for(
                    _run_with_timeout(), timeout=TOTAL_SCAN_TIMEOUT
                )
            except asyncio.TimeoutError:
                scan_timed_out.set()
                print(f"\n  {C.Y}  ⚠ Total scan timeout ({TOTAL_SCAN_TIMEOUT}s) reached — preserving {len(_completed_results)} completed scans{C.RS}")

            all_results = _completed_results

            # Merge results from all scripts
            for s_api_keys, s_tokens, s_ips, s_endpoints, s_secrets in all_results:
                api_keys.extend(s_api_keys)
                tokens.extend(s_tokens)
                internal_ips.extend(s_ips)
                hidden_endpoints.extend(s_endpoints)
                secrets.extend(s_secrets)

        elapsed = time.monotonic() - t0

        # Print summary
        total_findings = len(api_keys) + len(tokens) + len(internal_ips) + len(hidden_endpoints) + len(secrets)
        total_files = len(self.scripts)
        scanned_mb = total_bytes_scanned / (1024 * 1024)

        print(f"\n  {C.G}  ╔══════════════════════════════════════════════════╗{C.RS}")
        print(f"  {C.G}  ║  JS Secret Scan Results                        ║{C.RS}")
        print(f"  {C.G}  ╠══════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  API Keys:          {C.R}{len(api_keys):<25}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Tokens:            {C.Y}{len(tokens):<25}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Internal IPs:      {C.M}{len(internal_ips):<25}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Hidden Endpoints:  {C.CY}{len(hidden_endpoints):<25}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Secrets:           {C.R}{len(secrets):<25}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Total Findings:    {C.W}{total_findings:<25}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Time:              {C.CY}{elapsed:.1f}s{' ' * (22 - len(f'{elapsed:.1f}s'))}{C.G}║{C.RS}")
        print(f"  {C.G}  ╚══════════════════════════════════════════════════╝{C.RS}")

        # File counter summary
        skipped_total = files_skipped_size + files_skipped_error
        print(f"  {C.DM}  Scanned {files_scanned}/{total_files} files ({scanned_mb:.1f} MB), "
              f"{skipped_total} skipped ({files_skipped_size} size, {files_skipped_error} error), "
              f"{total_findings} findings in {elapsed:.1f}s{C.RS}")

        return {
            "api_keys": api_keys,
            "tokens": tokens,
            "internal_ips": internal_ips,
            "hidden_endpoints": hidden_endpoints,
            "secrets": secrets,
        }

    def _resolve_url(self, script_url: str) -> str:
        """Resolve a script URL to an absolute URL."""
        # Skip data: URIs immediately
        if script_url.startswith('data:'):
            return ""
        if script_url.startswith(('http://', 'https://')):
            return script_url
        if script_url.startswith('//'):
            parsed = self.url
            scheme = parsed.split('://')[0] if '://' in parsed else 'https'
            return f"{scheme}:{script_url}"
        return urljoin(self.url, script_url)

    async def _head_check(self, session: aiohttp.ClientSession, url: str) -> int | None:
        """
        Do a HEAD request to check Content-Length before downloading.

        Args:
            session: aiohttp session
            url: Full URL of the JS file

        Returns:
            Content-Length as int, or None if unavailable
        """
        async with self._semaphore:
            try:
                async with session.head(url, ssl=self._ssl, allow_redirects=True) as resp:
                    if resp.status == 200:
                        content_length = resp.headers.get('Content-Length')
                        if content_length:
                            try:
                                return int(content_length)
                            except (ValueError, TypeError):
                                return None
                    return None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return None

    async def _download_js(self, session: aiohttp.ClientSession, url: str) -> str:
        """
        Download a JS file with rate limiting and content-type filtering.

        Args:
            session: aiohttp session
            url: Full URL of the JS file

        Returns:
            JS content as string, or empty string on failure
        """
        async with self._semaphore:
            try:
                async with session.get(url, ssl=self._ssl, allow_redirects=True) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get('Content-Type', '')

                        # Filter out non-text content types
                        if not _is_acceptable_content_type(content_type):
                            return ""

                        text = await safe_read_js(resp)  # W1.10: bounded read (5MB for JS)
                        return text
                    else:
                        return ""
            except asyncio.TimeoutError:
                return ""
            except (aiohttp.ClientError, UnicodeDecodeError):
                return ""

    def _find_with_context(
        self, content: str, pattern: str, context_chars: int = 50
    ) -> List[Tuple[str, str]]:
        """
        Find all matches of a pattern and extract surrounding context.

        Args:
            content: JS content to search
            pattern: Regex pattern
            context_chars: Number of chars before/after match for context

        Returns:
            List of (matched_text, context_string) tuples
        """
        results = []
        try:
            for m in self._get_compiled(pattern).finditer(content):
                match_text = m.group(0)
                start = max(0, m.start() - context_chars)
                end = min(len(content), m.end() + context_chars)
                context = content[start:end].replace('\n', ' ').replace('\r', ' ')
                # Clean up context for readability
                context = re.sub(r'\s+', ' ', context).strip()
                results.append((match_text, context))
        except re.error:
            pass
        return results

    def _get_compiled(self, pattern: str):
        """Get or create a compiled regex pattern."""
        if pattern not in self._compiled:
            self._compiled[pattern] = re.compile(pattern)
        return self._compiled[pattern]
