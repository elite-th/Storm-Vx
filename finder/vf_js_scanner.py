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


# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


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


class JSSecretScanner:
    """
    JavaScript secret scanner for STORM_VX.

    Downloads JS files, scans them with comprehensive regex patterns
    for API keys, tokens, internal IPs, hidden endpoints, and secrets.
    """

    def __init__(self, url: str, scripts: List[str], timeout: int = 15):
        """
        Initialize JSSecretScanner.

        Args:
            url: Base URL of the target site
            scripts: List of JS file URLs (relative or absolute)
            timeout: HTTP request timeout in seconds
        """
        self.url = url
        self.scripts = scripts
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(2)  # Rate limit: 2 concurrent downloads

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
        print(f"\n  {C.BD}{C.CY}[*] JS Secret Scanner — {self.url}{C.RS}")
        print(f"  {C.DM}    Scripts to scan: {len(self.scripts)} | Timeout: {self.timeout}s{C.RS}")

        t0 = time.time()

        api_keys: List[Dict] = []
        tokens: List[Dict] = []
        internal_ips: List[Dict] = []
        hidden_endpoints: List[Dict] = []
        secrets: List[Dict] = []
        seen_endpoints: Set[str] = set()

        # Download and scan each JS file
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            for idx, script_url in enumerate(self.scripts):
                full_url = self._resolve_url(script_url)
                print(f"  {C.B}  [{idx+1}/{len(self.scripts)}] Downloading: {C.DM}{full_url[:80]}{C.RS}")

                js_content = await self._download_js(session, full_url)
                if not js_content:
                    continue

                print(f"  {C.G}    Size: {len(js_content):,} bytes — Scanning...{C.RS}")

                # Scan for API keys
                for name, pattern in API_KEY_PATTERNS:
                    matches = self._find_with_context(js_content, pattern)
                    for match_text, context in matches:
                        result = {
                            "type": name,
                            "match": match_text,
                            "context": context,
                            "file": script_url,
                            "full_url": full_url,
                        }
                        api_keys.append(result)
                        print(f"  {C.R}    [API KEY] {name}: {match_text}{C.RS}")
                        print(f"  {C.DM}             Context: ...{context}...{C.RS}")

                # Scan for tokens
                for name, pattern in TOKEN_PATTERNS:
                    matches = self._find_with_context(js_content, pattern)
                    for match_text, context in matches:
                        result = {
                            "type": name,
                            "match": match_text,
                            "context": context,
                            "file": script_url,
                            "full_url": full_url,
                        }
                        tokens.append(result)
                        print(f"  {C.Y}    [TOKEN] {name}: {match_text[:60]}...{C.RS}")
                        print(f"  {C.DM}             Context: ...{context}...{C.RS}")

                # Scan for internal IPs
                for name, pattern in INTERNAL_IP_PATTERNS:
                    matches = self._find_with_context(js_content, pattern)
                    for match_text, context in matches:
                        result = {
                            "type": name,
                            "ip": match_text,
                            "context": context,
                            "file": script_url,
                            "full_url": full_url,
                        }
                        internal_ips.append(result)
                        print(f"  {C.M}    [INTERNAL IP] {name}: {match_text}{C.RS}")

                # Scan for hidden endpoints
                for name, pattern in HIDDEN_ENDPOINT_PATTERNS:
                    matches = self._find_with_context(js_content, pattern)
                    for match_text, context in matches:
                        if match_text not in seen_endpoints:
                            seen_endpoints.add(match_text)
                            result = {
                                "type": name,
                                "endpoint": match_text,
                                "context": context,
                                "file": script_url,
                                "full_url": full_url,
                            }
                            hidden_endpoints.append(result)
                            print(f"  {C.CY}    [ENDPOINT] {name}: {match_text}{C.RS}")

                # Scan for secrets
                for name, pattern in SECRET_PATTERNS:
                    matches = self._find_with_context(js_content, pattern)
                    for match_text, context in matches:
                        result = {
                            "type": name,
                            "match": match_text,
                            "context": context,
                            "file": script_url,
                            "full_url": full_url,
                        }
                        secrets.append(result)
                        print(f"  {C.R}    [SECRET] {name}{C.RS}")
                        print(f"  {C.DM}             Context: ...{context}...{C.RS}")

        elapsed = time.time() - t0

        # Print summary
        total_findings = len(api_keys) + len(tokens) + len(internal_ips) + len(hidden_endpoints) + len(secrets)
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

        return {
            "api_keys": api_keys,
            "tokens": tokens,
            "internal_ips": internal_ips,
            "hidden_endpoints": hidden_endpoints,
            "secrets": secrets,
        }

    def _resolve_url(self, script_url: str) -> str:
        """Resolve a script URL to an absolute URL."""
        if script_url.startswith(('http://', 'https://')):
            return script_url
        if script_url.startswith('//'):
            parsed = self.url
            scheme = parsed.split('://')[0] if '://' in parsed else 'https'
            return f"{scheme}:{script_url}"
        return urljoin(self.url, script_url)

    async def _download_js(self, session: aiohttp.ClientSession, url: str) -> str:
        """
        Download a JS file with rate limiting.

        Args:
            session: aiohttp session
            url: Full URL of the JS file

        Returns:
            JS content as string, or empty string on failure
        """
        async with self._semaphore:
            try:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get('Content-Type', '')
                        # Accept JS even if content-type is not perfect
                        text = await resp.text()
                        return text
                    else:
                        print(f"  {C.Y}    HTTP {resp.status} for {url[:60]}{C.RS}")
                        return ""
            except asyncio.TimeoutError:
                print(f"  {C.Y}    Timeout downloading {url[:60]}{C.RS}")
                return ""
            except Exception as e:
                print(f"  {C.Y}    Error downloading {url[:60]}: {type(e).__name__}{C.RS}")
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
            for m in re.finditer(pattern, content):
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
