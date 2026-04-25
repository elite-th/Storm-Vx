#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF_FINDER — Reconnaissance Engine                                   ║
║     Part of the VF (Vector-Finder) Architecture                         ║
║                                                                           ║
║  Scans a target website and builds a complete technology profile:         ║
║  - Server fingerprinting (Apache, Nginx, IIS, LiteSpeed, etc.)           ║
║  - Backend detection (ASP.NET, PHP, Node.js, Python, Java, Ruby, etc.)   ║
║  - WAF identification (Cloudflare, ArvanCloud, ModSecurity, etc.)        ║
║  - CMS detection (WordPress, Drupal, Joomla, DNN, etc.)                  ║
║  - Framework detection (React, Angular, Vue, Laravel, Django, etc.)      ║
║  - SSL/TLS analysis                                                       ║
║  - DNS & subdomain enumeration                                            ║
║  - Content analysis (forms, hidden fields, endpoints)                     ║
║  - Performance baseline (response times, payload sizes, rate limits)      ║
║  - Security headers audit                                                 ║
║                                                                           ║
║  Output: VF_PROFILE.json → Feed to VF_TESTER for adaptive attack         ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage:
  python VF_FINDER.py https://target.com
  python VF_FINDER.py https://target.com --deep
  python VF_FINDER.py https://target.com --output my_profile.json
  python VF_FINDER.py https://target.com --dns --subdomains

Requirements:
  pip install aiohttp httpx beautifulsoup4
  Optional: pip install dnspython (for DNS enumeration)
"""

import asyncio
import argparse
import time
import sys
import json
import re
import os
import platform
import socket
import hashlib
import math
import ssl
from typing import List, Optional, Dict, Set, Tuple, Any
from collections import deque, OrderedDict
from urllib.parse import urlparse, urljoin, urlencode

IS_WINDOWS = platform.system() == 'Windows'

if IS_WINDOWS:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    print("[ERROR] aiohttp is required! pip install aiohttp")

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

if not HAS_AIOHTTP:
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# Technology Fingerprint Database (Wappalyzer-like)
# ═══════════════════════════════════════════════════════════════════════════════

TECH_SIGNATURES = {
    # ─── Web Servers ───
    "Apache": {
        "headers": {"Server": r"Apache(/[\d.]+)?"},
        "category": "Web Server",
    },
    "Nginx": {
        "headers": {"Server": r"nginx(/[\d.]+)?"},
        "category": "Web Server",
    },
    "IIS": {
        "headers": {"Server": r"Microsoft-IIS(/[\d.]+)?"},
        "category": "Web Server",
    },
    "LiteSpeed": {
        "headers": {"Server": r"LiteSpeed"},
        "category": "Web Server",
    },
    "Caddy": {
        "headers": {"Server": r"Caddy"},
        "category": "Web Server",
    },
    "OpenResty": {
        "headers": {"Server": r"OpenResty"},
        "category": "Web Server",
    },
    "ArvanCloud": {
        "headers": {"Server": r"[Aa]rvan"},
        "category": "Web Server / CDN",
    },

    # ─── Backend Languages / Frameworks ───
    "ASP.NET": {
        "headers": {
            "X-AspNet-Version": r".+",
            "X-Powered-By": r"ASP\.NET",
        },
        "html": [
            r'__VIEWSTATE',
            r'__EVENTVALIDATION',
            r'__EVENTTARGET',
            r'aspnetForm',
            r'/WebResource\.axd',
            r'/ScriptResource\.axd',
            r'\.aspx',
        ],
        "cookies": ["ASP.NET_SessionId", "ASPSESSIONID"],
        "category": "Backend Framework",
    },
    "PHP": {
        "headers": {
            "X-Powered-By": r"PHP(/[\d.]+)?",
            "Server": r"PHP",
        },
        "html": [r'\.php', r'PHPSESSID', r'X-Powered-By: PHP'],
        "cookies": ["PHPSESSID", "laravel_session"],
        "category": "Backend Language",
    },
    "Laravel": {
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "html": [r'laravel', r'csrf-token'],
        "headers": {"X-Powered-By": r"Laravel"},
        "category": "Backend Framework",
    },
    "Django": {
        "cookies": ["csrftoken", "sessionid"],
        "html": [r'csrfmiddlewaretoken', r'__django'],
        "headers": {"X-Frame-Options": r"DENY"},
        "category": "Backend Framework",
    },
    "Express.js": {
        "headers": {"X-Powered-By": r"Express"},
        "category": "Backend Framework",
    },
    "Next.js": {
        "html": [
            r'__NEXT_DATA__',
            r'_next/static',
            r'_next/image',
        ],
        "headers": {"X-Powered-By": r"Next\.js"},
        "category": "Backend Framework",
    },
    "Flask": {
        "headers": {"Server": r"Werkzeug"},
        "cookies": ["session"],
        "category": "Backend Framework",
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": r"Phusion Passenger"},
        "cookies": ["_session_id"],
        "html": [r'authenticity_token', r'turbolinks'],
        "category": "Backend Framework",
    },
    "Spring Boot": {
        "headers": {"X-Application-Context": r".+"},
        "cookies": ["JSESSIONID"],
        "category": "Backend Framework",
    },
    "FastAPI": {
        "html": [r'fastapi', r'openapi\.json', r'swagger'],
        "category": "Backend Framework",
    },

    # ─── CMS ───
    "WordPress": {
        "html": [
            r'wp-content',
            r'wp-includes',
            r'wp-admin',
            r'WordPress',
            r'wp-json',
        ],
        "headers": {"Link": r'<[^>]+>; rel="https://api\.w\.org/"'},
        "cookies": ["wordpress_", "wp-settings-"],
        "meta": {"generator": r"WordPress"},
        "category": "CMS",
    },
    "Drupal": {
        "html": [r'Drupal', r'sites/default', r'misc/drupal\.js'],
        "headers": {"X-Generator": r"Drupal"},
        "meta": {"generator": r"Drupal"},
        "category": "CMS",
    },
    "Joomla": {
        "html": [r'/media/jui/', r'Joomla!', r'com_content'],
        "meta": {"generator": r"Joomla!"},
        "category": "CMS",
    },
    "DotNetNuke (DNN)": {
        "html": [r'DNN', r'dotnetnuke', r'/DesktopModules/'],
        "meta": {"generator": r"DotNetNuke"},
        "cookies": ["dnn_IsMobile"],
        "category": "CMS",
    },
    "SharePoint": {
        "headers": {"SharePoint": r".+", "SPRequestGuid": r".+"},
        "html": [r'_layouts/', r'SharePoint'],
        "category": "CMS",
    },

    # ─── Frontend Frameworks ───
    "React": {
        "html": [
            r'react',
            r'_reactRootContainer',
            r'data-reactroot',
            r'reactjs',
        ],
        "scripts": [r'react', r'react-dom'],
        "category": "Frontend Framework",
    },
    "Vue.js": {
        "html": [r'data-v-[a-f0-9]', r'__vue__', r'vue-app'],
        "scripts": [r'vue'],
        "category": "Frontend Framework",
    },
    "Angular": {
        "html": [r'ng-app', r'ng-controller', r'_nghost', r'ng-version'],
        "scripts": [r'angular', r'@angular'],
        "category": "Frontend Framework",
    },
    "jQuery": {
        "scripts": [r'jquery'],
        "html": [r'jquery', r'jQuery'],
        "category": "JavaScript Library",
    },
    "Bootstrap": {
        "html": [r'bootstrap\.min\.css', r'bootstrap\.css', r'btn-primary'],
        "category": "CSS Framework",
    },
    "Tailwind CSS": {
        "html": [r'tailwind', r'flex.*gap-'],
        "category": "CSS Framework",
    },

    # ─── WAF / CDN ───
    "Cloudflare": {
        "headers": {"CF-Ray": r".+", "CF-Cache-Status": r".+", "Server": r"cloudflare"},
        "html": [r'cf-browser-verification', r'Cloudflare', r'cf_chl_opt'],
        "cookies": ["__cf_bm", "cf_clearance"],
        "category": "WAF / CDN",
    },
    "ArvanCloud": {
        "headers": {"Server": r"[Aa]rvan"},
        "html": [r'arvancloud', r'ArvanCloud'],
        "category": "WAF / CDN",
    },
    "ModSecurity": {
        "headers": {"Server": r"Mod_Security", "X-Mod-Security": r".+"},
        "category": "WAF",
    },
    "Sucuri": {
        "headers": {"X-Sucuri-ID": r".+", "Server": r"Sucuri"},
        "category": "WAF / CDN",
    },
    "Imperva (Incapsula)": {
        "headers": {"X-CDN": r"Incapsula", "X-Iinfo": r".+"},
        "cookies": ["visid_incap", "incap_ses"],
        "category": "WAF / CDN",
    },
    "Akamai": {
        "headers": {"X-Akamai-Transformed": r".+", "X-Cache": r"Akamai"},
        "category": "WAF / CDN",
    },
    "AWS WAF / CloudFront": {
        "headers": {"X-Cache": r".*CloudFront.*", "Via": r".*CloudFront.*"},
        "cookies": ["AWSALB", "aws-waf-token"],
        "category": "WAF / CDN",
    },
    "F5 BIG-IP": {
        "headers": {"Server": r"BigIP", "X-WA-Info": r".+"},
        "cookies": ["BIGipServer"],
        "category": "WAF / Load Balancer",
    },
    "Barracuda": {
        "headers": {"Server": r"Barracuda"},
        "category": "WAF",
    },

    # ─── Databases (detected via error messages) ───
    "MySQL": {
        "html": [r'mysql', r'MySQL Error', r'Warning: mysql_'],
        "category": "Database",
    },
    "PostgreSQL": {
        "html": [r'PostgreSQL', r'pg_query'],
        "category": "Database",
    },
    "MSSQL": {
        "html": [r'Microsoft SQL Server', r'SqlException', r'SQL Server error'],
        "category": "Database",
    },
    "MongoDB": {
        "html": [r'mongo', r'MongoError', r'mongod'],
        "category": "Database",
    },

    # ─── Analytics / Tracking ───
    "Google Analytics": {
        "scripts": [r'google-analytics', r'gtag', r'GA-'],
        "category": "Analytics",
    },
    "Google Tag Manager": {
        "scripts": [r'googletagmanager', r'GTM-'],
        "category": "Analytics",
    },
    "Yandex Metrika": {
        "scripts": [r'metrika', r'yaCounter'],
        "category": "Analytics",
    },
}

# Common paths for deep scanning
DEEP_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD",
    "/wp-admin/", "/wp-login.php", "/administrator/",
    "/admin/", "/admin/login", "/api/", "/api/v1/",
    "/swagger.json", "/openapi.json", "/graphql",
    "/.well-known/security.txt", "/favicon.ico",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/elmah.axd", "/trace.axd", "/Web.config",
    "/phpinfo.php", "/info.php", "/server-status",
    "/.htaccess", "/wp-config.php.bak",
    "/login", "/signin", "/auth/login",
    "/forgot-password", "/register", "/signup",
    "/health", "/status", "/ping",
    "/.well-known/openid-configuration",
]


# ═══════════════════════════════════════════════════════════════════════════════
# Site Profile Data Structure
# ═══════════════════════════════════════════════════════════════════════════════

class SiteProfile:
    """Complete technology profile of a target website"""

    def __init__(self, url: str):
        self.url = url
        parsed = urlparse(url)
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.path = parsed.path
        self.domain = parsed.netloc.split(':')[0]

        # Scan results
        self.scan_time: float = 0
        self.technologies: List[Dict[str, Any]] = []
        self.server: Optional[str] = None
        self.server_version: Optional[str] = None
        self.os_guess: Optional[str] = None
        self.backend_lang: Optional[str] = None
        self.backend_framework: Optional[str] = None
        self.frontend_frameworks: List[str] = []
        self.cms: Optional[str] = None
        self.waf: Optional[str] = None
        self.waf_confidence: float = 0.0
        self.cdn: Optional[str] = None

        # HTTP details
        self.status_code: Optional[int] = None
        self.response_time: float = 0
        self.page_size: int = 0
        self.headers: Dict[str, str] = {}
        self.cookies: Dict[str, str] = {}
        self.security_headers: Dict[str, Any] = {}
        self.redirect_chain: List[str] = []

        # SSL/TLS
        self.ssl_info: Dict[str, Any] = {}
        self.ssl_enabled: bool = False

        # Content
        self.html_size: int = 0
        self.forms: List[Dict[str, Any]] = []
        self.hidden_fields: List[str] = []
        self.scripts: List[str] = []
        self.stylesheets: List[str] = []
        self.images: List[str] = []
        self.links: List[str] = []
        self.api_endpoints: List[str] = []
        self.meta_tags: Dict[str, str] = {}

        # ASP.NET specific
        self.viewstate_present: bool = False
        self.eventvalidation_present: bool = False
        self.login_fields: Dict[str, str] = {}

        # Performance baseline
        self.baseline_rt: float = 0
        self.baseline_rts: List[float] = []
        self.rate_limit_detected: bool = False
        self.rate_limit_threshold: Optional[int] = None

        # DNS
        self.dns_records: Dict[str, List[str]] = {}
        self.ip_addresses: List[str] = []
        self.hosting_provider: Optional[str] = None
        self.subdomains: List[str] = []

        # Deep scan
        self.found_paths: List[Dict[str, Any]] = []
        self.sensitive_files: List[str] = []

        # Attack recommendations (generated at end)
        self.attack_profile: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "domain": self.domain,
            "scan_time": round(self.scan_time, 2),
            "technologies": self.technologies,
            "server": self.server,
            "server_version": self.server_version,
            "os_guess": self.os_guess,
            "backend_language": self.backend_lang,
            "backend_framework": self.backend_framework,
            "frontend_frameworks": self.frontend_frameworks,
            "cms": self.cms,
            "waf": self.waf,
            "waf_confidence": self.waf_confidence,
            "cdn": self.cdn,
            "status_code": self.status_code,
            "response_time_ms": round(self.response_time * 1000, 1),
            "page_size_bytes": self.page_size,
            "page_size_human": self._human_size(self.page_size),
            "headers": self.headers,
            "cookies": self.cookies,
            "security_headers": self.security_headers,
            "ssl_enabled": self.ssl_enabled,
            "ssl_info": self.ssl_info,
            "html_size": self.html_size,
            "forms": self.forms,
            "hidden_fields": self.hidden_fields,
            "scripts_count": len(self.scripts),
            "stylesheets_count": len(self.stylesheets),
            "images_count": len(self.images),
            "links_count": len(self.links),
            "api_endpoints": self.api_endpoints,
            "meta_tags": self.meta_tags,
            "viewstate_present": self.viewstate_present,
            "eventvalidation_present": self.eventvalidation_present,
            "login_fields": self.login_fields,
            "baseline_rt_ms": round(self.baseline_rt * 1000, 1),
            "rate_limit_detected": self.rate_limit_detected,
            "rate_limit_threshold": self.rate_limit_threshold,
            "dns_records": self.dns_records,
            "ip_addresses": self.ip_addresses,
            "hosting_provider": self.hosting_provider,
            "subdomains": self.subdomains,
            "found_paths": self.found_paths,
            "sensitive_files": self.sensitive_files,
            "attack_profile": self.attack_profile,
        }

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


# ═══════════════════════════════════════════════════════════════════════════════
# FINDER Engine
# ═══════════════════════════════════════════════════════════════════════════════

class VFFinder:
    """
    VF_FINDER — Reconnaissance Engine

    Performs deep analysis of a target website and builds a complete
    technology profile that can be fed to VF_TESTER for adaptive attacks.
    """

    def __init__(self, url: str, deep: bool = False, dns_scan: bool = False,
                 subdomain_scan: bool = False):
        self.url = url
        self.deep = deep
        self.dns_scan = dns_scan
        self.subdomain_scan = subdomain_scan
        self.profile = SiteProfile(url)
        self._html: Optional[str] = None

    async def scan(self) -> SiteProfile:
        """Run full reconnaissance scan"""
        t0 = time.time()
        print(f"\n{'='*72}")
        print(f"  {C.BD}{C.R}VF_FINDER — Reconnaissance Engine{C.RS}")
        print(f"{'='*72}")
        print(f"  Target: {C.W}{self.url}{C.RS}")
        print(f"  Deep:   {C.Y}{'ON' if self.deep else 'OFF'}{C.RS}")
        print(f"  DNS:    {C.Y}{'ON' if self.dns_scan else 'OFF'}{C.RS}")
        print(f"{'='*72}\n")

        # Phase 1: HTTP Fingerprinting
        print(f"  {C.CY}[1/8] HTTP Fingerprinting...{C.RS}")
        await self._http_fingerprint()

        # Phase 2: Technology Detection
        print(f"  {C.CY}[2/8] Technology Detection...{C.RS}")
        self._detect_technologies()

        # Phase 3: Content Analysis
        print(f"  {C.CY}[3/8] Content Analysis...{C.RS}")
        self._analyze_content()

        # Phase 4: Security Headers Audit
        print(f"  {C.CY}[4/8] Security Headers Audit...{C.RS}")
        self._audit_security_headers()

        # Phase 5: SSL/TLS Analysis
        if self.profile.scheme == 'https':
            print(f"  {C.CY}[5/8] SSL/TLS Analysis...{C.RS}")
            self._analyze_ssl()
        else:
            print(f"  {C.Y}[5/8] SSL: Not HTTPS, skipping{C.RS}")

        # Phase 6: DNS Enumeration
        if self.dns_scan:
            print(f"  {C.CY}[6/8] DNS Enumeration...{C.RS}")
            await self._dns_enumerate()
        else:
            print(f"  {C.DM}[6/8] DNS: Skipped (use --dns to enable){C.RS}")

        # Phase 7: Deep Scan
        if self.deep:
            print(f"  {C.CY}[7/8] Deep Path Scanning...{C.RS}")
            await self._deep_scan()
        else:
            print(f"  {C.DM}[7/8] Deep Scan: Skipped (use --deep to enable){C.RS}")

        # Phase 8: Performance Baseline
        print(f"  {C.CY}[8/8] Performance Baseline...{C.RS}")
        await self._performance_baseline()

        # Generate Attack Profile
        print(f"\n  {C.G}[DONE] Generating attack profile...{C.RS}")
        self._generate_attack_profile()

        self.profile.scan_time = time.time() - t0
        print(f"  {C.G}Scan completed in {self.profile.scan_time:.1f}s{C.RS}")

        return self.profile

    # ─── Phase 1: HTTP Fingerprinting ────────────────────────────────────────

    async def _http_fingerprint(self):
        """Fetch the page and extract HTTP-level information"""
        timeout = aiohttp.ClientTimeout(total=20)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Main page request
                t0 = time.time()
                async with session.get(self.url, ssl=False, allow_redirects=True) as resp:
                    self._html = await resp.text()
                    elapsed = time.time() - t0

                    self.profile.status_code = resp.status
                    self.profile.response_time = elapsed
                    self.profile.page_size = len(self._html or '')
                    self.profile.html_size = len(self._html or '')

                    # Headers
                    self.profile.headers = dict(resp.headers)

                    # Cookies
                    for cookie in session.cookie_jar:
                        self.profile.cookies[cookie.key] = cookie.value

                    # Redirect chain
                    if resp.history:
                        self.profile.redirect_chain = [str(h.url) for h in resp.history]

                    # Server detection
                    server_header = resp.headers.get('Server', '')
                    if server_header:
                        self.profile.server = server_header
                        # Extract version
                        match = re.match(r'(\w+)/([\d.]+)', server_header)
                        if match:
                            self.profile.server = match.group(1)
                            self.profile.server_version = match.group(2)

                    # Powered-By
                    powered_by = resp.headers.get('X-Powered-By', '')
                    if powered_by:
                        self.profile.backend_framework = powered_by

                    # ASP.NET version
                    aspnet_ver = resp.headers.get('X-AspNet-Version', '')
                    if aspnet_ver:
                        self.profile.backend_lang = f"ASP.NET {aspnet_ver}"

                    print(f"  {C.G}  Status: {resp.status} | RT: {elapsed*1000:.0f}ms | Size: {self.profile.page_size:,}B{C.RS}")
                    if self.profile.server:
                        print(f"  {C.G}  Server: {self.profile.server}{C.RS}")
                    if powered_by:
                        print(f"  {C.G}  Powered-By: {powered_by}{C.RS}")

        except Exception as e:
            print(f"  {C.R}  HTTP Error: {e}{C.RS}")

    # ─── Phase 2: Technology Detection ───────────────────────────────────────

    def _detect_technologies(self):
        """Detect technologies based on headers, HTML, cookies, and scripts"""
        detected = {}

        for tech_name, sig in TECH_SIGNATURES.items():
            confidence = 0.0
            evidence = []

            # Check headers
            for header_name, pattern in sig.get("headers", {}).items():
                header_val = self.profile.headers.get(header_name, '')
                if header_val and re.search(pattern, header_val, re.IGNORECASE):
                    confidence += 0.4
                    evidence.append(f"Header: {header_name}={header_val}")

            # Check HTML content
            html = self._html or ''
            for pattern in sig.get("html", []):
                if re.search(pattern, html, re.IGNORECASE):
                    confidence += 0.25
                    evidence.append(f"HTML: {pattern}")

            # Check cookies
            for cookie_pattern in sig.get("cookies", []):
                for cookie_name in self.profile.cookies:
                    if cookie_pattern.lower() in cookie_name.lower():
                        confidence += 0.3
                        evidence.append(f"Cookie: {cookie_name}")

            # Check meta tags
            for meta_name, meta_pattern in sig.get("meta", {}).items():
                meta_content = self.profile.meta_tags.get(meta_name, '')
                if meta_content and re.search(meta_pattern, meta_content, re.IGNORECASE):
                    confidence += 0.5
                    evidence.append(f"Meta: {meta_name}={meta_content}")

            # Check scripts
            for script_pattern in sig.get("scripts", []):
                for script in self.profile.scripts if hasattr(self.profile, '_scripts_raw') else []:
                    if re.search(script_pattern, script, re.IGNORECASE):
                        confidence += 0.3
                        evidence.append(f"Script: {script[:50]}")

            if confidence > 0.2:
                detected[tech_name] = {
                    "name": tech_name,
                    "category": sig.get("category", "Unknown"),
                    "confidence": min(confidence, 1.0),
                    "evidence": evidence,
                }

        # Sort by confidence
        sorted_tech = sorted(detected.values(), key=lambda x: x["confidence"], reverse=True)
        self.profile.technologies = sorted_tech

        # Categorize
        for tech in sorted_tech:
            cat = tech["category"]
            name = tech["name"]
            if cat == "Web Server" and not self.profile.server:
                self.profile.server = name
            elif cat == "Backend Language" and not self.profile.backend_lang:
                self.profile.backend_lang = name
            elif cat == "Backend Framework":
                if not self.profile.backend_framework or tech["confidence"] > 0.5:
                    self.profile.backend_framework = name
            elif cat == "Frontend Framework":
                self.profile.frontend_frameworks.append(name)
            elif cat == "CMS":
                self.profile.cms = name
            elif "WAF" in cat:
                self.profile.waf = name
                self.profile.waf_confidence = tech["confidence"]
            elif "CDN" in cat:
                self.profile.cdn = name

        # Print detected technologies
        for tech in sorted_tech:
            conf_bar = int(tech["confidence"] * 10)
            bar = f"{'|' * conf_bar}{'.' * (10 - conf_bar)}"
            conf_color = C.G if tech["confidence"] > 0.7 else C.Y if tech["confidence"] > 0.4 else C.DM
            print(f"  {conf_color}  {tech['name']:<25} [{bar}] {tech['confidence']:.0%} {C.DM}({tech['category']}){C.RS}")

    # ─── Phase 3: Content Analysis ───────────────────────────────────────────

    def _analyze_content(self):
        """Analyze HTML content: forms, scripts, links, hidden fields"""
        html = self._html or ''
        if not html:
            return

        # Extract meta tags
        for m in re.finditer(r'<meta\s+[^>]*>', html, re.IGNORECASE):
            tag = m.group(0)
            name_match = re.search(r'name=["\']?([^"\'>\s]+)["\']?', tag)
            content_match = re.search(r'content=["\']?([^"\'>]+)["\']?', tag)
            if name_match and content_match:
                self.profile.meta_tags[name_match.group(1)] = content_match.group(1)

        # Also check property= for og: tags
        for m in re.finditer(r'<meta\s+property=["\']?([^"\'>\s]+)["\']?\s+content=["\']?([^"\'>]+)["\']?', html, re.IGNORECASE):
            self.profile.meta_tags[m.group(1)] = m.group(2)

        # Extract forms
        form_pattern = re.finditer(r'<form\s+([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        for i, form_match in enumerate(form_pattern):
            form_attrs = form_match.group(1)
            form_html = form_match.group(2)

            action_match = re.search(r'action=["\']?([^"\'>\s]+)["\']?', form_attrs)
            method_match = re.search(r'method=["\']?([^"\'>\s]+)["\']?', form_attrs, re.IGNORECASE)

            form_info = {
                "index": i,
                "action": action_match.group(1) if action_match else "",
                "method": (method_match.group(1) or "GET").upper() if method_match else "GET",
                "fields": [],
                "hidden_fields": [],
            }

            # Extract input fields
            for inp in re.finditer(r'<input\s+([^>]*)>', form_html, re.IGNORECASE):
                attrs = inp.group(1)
                name_m = re.search(r'name=["\']?([^"\'>\s]+)["\']?', attrs)
                type_m = re.search(r'type=["\']?([^"\'>\s]+)["\']?', attrs, re.IGNORECASE)
                value_m = re.search(r'value=["\']?([^"\'>]*)["\']?', attrs)

                field_name = name_m.group(1) if name_m else ""
                field_type = (type_m.group(1) or "text").lower() if type_m else "text"
                field_value = value_m.group(1) if value_m else ""

                if field_type == "hidden":
                    form_info["hidden_fields"].append({"name": field_name, "value": field_value})
                    if field_name and field_name not in self.profile.hidden_fields:
                        self.profile.hidden_fields.append(field_name)
                else:
                    form_info["fields"].append({
                        "name": field_name,
                        "type": field_type,
                        "value": field_value,
                    })

            self.profile.forms.append(form_info)

        # Check ASP.NET specific
        if '__VIEWSTATE' in html:
            self.profile.viewstate_present = True
        if '__EVENTVALIDATION' in html:
            self.profile.eventvalidation_present = True

        # Detect login fields
        self._detect_login_fields(html)

        # Extract scripts
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            self.profile.scripts.append(m.group(1))

        # Extract stylesheets
        for m in re.finditer(r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']', html, re.IGNORECASE):
            self.profile.stylesheets.append(m.group(1))

        # Extract images
        for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            self.profile.images.append(m.group(1))

        # Extract links
        parsed = urlparse(self.url)
        domain = parsed.netloc
        for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            link = m.group(1)
            if link.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
                continue
            if link.startswith('/'):
                link = f"{self.profile.scheme}://{domain}{link}"
            elif not link.startswith('http'):
                link = urljoin(self.url, link)
            self.profile.links.append(link)

        # Extract API endpoints
        api_patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'\.ajax\({[^}]*url:\s*["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'url:\s*["\'](/api/[^"\']+)["\']',
            r'["\'](/api/[^"\']+)["\']',
        ]
        for pattern in api_patterns:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                endpoint = m.group(1)
                if endpoint not in self.profile.api_endpoints:
                    self.profile.api_endpoints.append(endpoint)

        # Print summary
        print(f"  {C.G}  Forms: {len(self.profile.forms)} | Scripts: {len(self.profile.scripts)} | Links: {len(self.profile.links)}{C.RS}")
        print(f"  {C.G}  Hidden Fields: {len(self.profile.hidden_fields)} | Images: {len(self.profile.images)} | APIs: {len(self.profile.api_endpoints)}{C.RS}")
        if self.profile.viewstate_present:
            print(f"  {C.Y}  ASP.NET ViewState: DETECTED{C.RS}")
        if self.profile.eventvalidation_present:
            print(f"  {C.Y}  ASP.NET EventValidation: DETECTED{C.RS}")
        if self.profile.login_fields:
            print(f"  {C.Y}  Login Fields: {self.profile.login_fields}{C.RS}")

    def _detect_login_fields(self, html: str):
        """Detect login form field names"""
        username_field = "username"
        password_field = "password"

        patterns_user = [
            r'name=["\']?([^"\'>\s]*(?:[Uu]ser|[Ee]mail|[Ll]ogin)[^"\'>\s]*)["\']?',
        ]
        patterns_pass = [
            r'name=["\']?([^"\'>\s]*(?:[Pp]ass|[Pp]wd)[^"\'>\s]*)["\']?',
        ]

        for p in patterns_user:
            m = re.search(p, html)
            if m:
                username_field = m.group(1)
                break

        for p in patterns_pass:
            m = re.search(p, html)
            if m:
                password_field = m.group(1)
                break

        self.profile.login_fields = {
            "username": username_field,
            "password": password_field,
        }

    # ─── Phase 4: Security Headers Audit ─────────────────────────────────────

    def _audit_security_headers(self):
        """Check for presence and correctness of security headers"""
        headers = self.profile.headers
        security = {
            "Strict-Transport-Security": {
                "present": "Strict-Transport-Security" in headers,
                "value": headers.get("Strict-Transport-Security", "MISSING"),
                "importance": "HIGH",
            },
            "Content-Security-Policy": {
                "present": "Content-Security-Policy" in headers,
                "value": headers.get("Content-Security-Policy", "MISSING"),
                "importance": "HIGH",
            },
            "X-Frame-Options": {
                "present": "X-Frame-Options" in headers,
                "value": headers.get("X-Frame-Options", "MISSING"),
                "importance": "MEDIUM",
            },
            "X-Content-Type-Options": {
                "present": "X-Content-Type-Options" in headers,
                "value": headers.get("X-Content-Type-Options", "MISSING"),
                "importance": "MEDIUM",
            },
            "X-XSS-Protection": {
                "present": "X-XSS-Protection" in headers,
                "value": headers.get("X-XSS-Protection", "MISSING"),
                "importance": "LOW",
            },
            "Referrer-Policy": {
                "present": "Referrer-Policy" in headers,
                "value": headers.get("Referrer-Policy", "MISSING"),
                "importance": "MEDIUM",
            },
            "Permissions-Policy": {
                "present": "Permissions-Policy" in headers,
                "value": headers.get("Permissions-Policy", "MISSING"),
                "importance": "LOW",
            },
        }
        self.profile.security_headers = security

        missing = [k for k, v in security.items() if not v["present"]]
        present = [k for k, v in security.items() if v["present"]]

        if present:
            print(f"  {C.G}  Present: {', '.join(present)}{C.RS}")
        if missing:
            print(f"  {C.R}  Missing:  {', '.join(missing)}{C.RS}")

    # ─── Phase 5: SSL/TLS Analysis ───────────────────────────────────────────

    def _analyze_ssl(self):
        """Analyze SSL/TLS configuration"""
        try:
            hostname = self.profile.host
            port = self.profile.port
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(True)
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    # Parse certificate
                    from ssl import DER_cert_to_PEM_cert
                    import ssl as _ssl

                    cert_dict = ssock.getpeercert()
                    issuer = ""
                    subject = ""
                    if cert_dict:
                        issuer = dict(x[0] for x in cert_dict.get('issuer', ()))
                        subject = dict(x[0] for x in cert_dict.get('subject', ()))

                    self.profile.ssl_info = {
                        "protocol": protocol,
                        "cipher": cipher[0] if cipher else "Unknown",
                        "cipher_bits": cipher[2] if cipher else 0,
                        "issuer_org": issuer.get('organizationName', 'Unknown'),
                        "subject_cn": subject.get('commonName', 'Unknown'),
                        "valid_from": cert_dict.get('notBefore', 'Unknown') if cert_dict else 'Unknown',
                        "valid_to": cert_dict.get('notAfter', 'Unknown') if cert_dict else 'Unknown',
                    }
                    self.profile.ssl_enabled = True

                    print(f"  {C.G}  Protocol: {protocol} | Cipher: {cipher[0] if cipher else '?'}{C.RS}")
                    print(f"  {C.G}  Issuer: {issuer.get('organizationName', '?')}{C.RS}")

        except Exception as e:
            print(f"  {C.Y}  SSL check failed: {e}{C.RS}")
            self.profile.ssl_enabled = True  # Assume HTTPS means SSL

    # ─── Phase 6: DNS Enumeration ────────────────────────────────────────────

    async def _dns_enumerate(self):
        """Enumerate DNS records"""
        domain = self.profile.domain

        # Basic DNS resolution
        try:
            ips = socket.getaddrinfo(domain, None)
            ip_list = list(set(addr[4][0] for addr in ips))
            self.profile.ip_addresses = ip_list
            print(f"  {C.G}  IPs: {', '.join(ip_list)}{C.RS}")
        except Exception as e:
            print(f"  {C.R}  DNS resolution failed: {e}{C.RS}")

        # DNS record lookup
        if HAS_DNS:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    records = [str(r) for r in answers]
                    self.profile.dns_records[rtype] = records
                    print(f"  {C.G}  {rtype}: {', '.join(records[:3])}{'...' if len(records) > 3 else ''}{C.RS}")
                except Exception:
                    pass

        # Subdomain enumeration (common subdomains)
        if self.subdomain_scan:
            await self._enumerate_subdomains(domain)

    async def _enumerate_subdomains(self, domain: str):
        """Enumerate common subdomains"""
        common_subs = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap',
            'api', 'admin', 'portal', 'app', 'dev', 'staging',
            'test', 'cdn', 'static', 'assets', 'media',
            'blog', 'shop', 'store', 'forum', 'wiki',
            'vpn', 'remote', 'cloud', 'db', 'mysql',
            'backup', 'git', 'ci', 'jenkins', 'jira',
        ]
        print(f"  {C.CY}  Scanning subdomains...{C.RS}")
        found = []

        async def check_sub(sub: str):
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append(fqdn)
                print(f"  {C.G}    {fqdn} -> {ip}{C.RS}")
            except socket.gaierror:
                pass

        # Run in batches of 10
        for i in range(0, len(common_subs), 10):
            batch = common_subs[i:i+10]
            await asyncio.gather(*[check_sub(sub) for sub in batch])

        self.profile.subdomains = found
        print(f"  {C.G}  Subdomains found: {len(found)}{C.RS}")

    # ─── Phase 7: Deep Scan ──────────────────────────────────────────────────

    async def _deep_scan(self):
        """Scan for common paths and sensitive files"""
        timeout = aiohttp.ClientTimeout(total=8)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            found = []
            sem = asyncio.Semaphore(5)  # Limit concurrency

            async def check_path(path: str):
                url = f"{self.profile.scheme}://{self.profile.host}{path}"
                async with sem:
                    try:
                        async with session.get(url, ssl=False, allow_redirects=False) as resp:
                            if resp.status in (200, 301, 302, 403):
                                size = 0
                                try:
                                    body = await resp.text()
                                    size = len(body)
                                except Exception:
                                    pass
                                info = {
                                    "path": path,
                                    "status": resp.status,
                                    "size": size,
                                }
                                found.append(info)

                                # Check for sensitive files
                                sensitive = ['.env', '.git', 'Web.config', 'wp-config',
                                             'phpinfo', 'server-status', '.htaccess']
                                if any(s in path for s in sensitive):
                                    self.profile.sensitive_files.append(path)

                                status_color = C.G if resp.status == 200 else C.Y
                                print(f"  {status_color}    {resp.status} {path} ({size:,}B){C.RS}")
                    except Exception:
                        pass

            # Scan in batches
            for i in range(0, len(DEEP_PATHS), 10):
                batch = DEEP_PATHS[i:i+10]
                await asyncio.gather(*[check_path(p) for p in batch])

        self.profile.found_paths = found
        print(f"  {C.G}  Paths found: {len(found)} | Sensitive: {len(self.profile.sensitive_files)}{C.RS}")
        if self.profile.sensitive_files:
            for sf in self.profile.sensitive_files:
                print(f"  {C.R}  !! Sensitive: {sf}{C.RS}")

    # ─── Phase 8: Performance Baseline ───────────────────────────────────────

    async def _performance_baseline(self):
        """Measure baseline performance: response times, rate limits"""
        timeout = aiohttp.ClientTimeout(total=15)
        rts = []

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Send 10 rapid requests to measure baseline RT
                for i in range(10):
                    t0 = time.time()
                    try:
                        async with session.get(self.url, ssl=False, allow_redirects=True) as resp:
                            elapsed = time.time() - t0
                            rts.append(elapsed)
                            await asyncio.sleep(0.1)
                    except Exception:
                        pass

                if rts:
                    self.profile.baseline_rt = sum(rts) / len(rts)
                    self.profile.baseline_rts = rts

                # Rate limit detection: send 20 rapid requests
                print(f"  {C.CY}  Testing rate limits (20 rapid requests)...{C.RS}")
                rl_detected = False
                rl_threshold = None
                for i in range(20):
                    t0 = time.time()
                    try:
                        async with session.get(self.url, ssl=False, allow_redirects=True) as resp:
                            if resp.status == 429:
                                rl_detected = True
                                rl_threshold = i + 1
                                print(f"  {C.Y}  Rate limit at request #{i+1} (429){C.RS}")
                                break
                            elif resp.status == 503:
                                # Could be rate limit or WAF challenge
                                body = await resp.text()
                                if any(x in body.lower() for x in ['rate', 'limit', 'too many', 'challenge']):
                                    rl_detected = True
                                    rl_threshold = i + 1
                                    print(f"  {C.Y}  Rate limit at request #{i+1} (503){C.RS}")
                                    break
                    except Exception:
                        pass

                self.profile.rate_limit_detected = rl_detected
                self.profile.rate_limit_threshold = rl_threshold

                if rts:
                    avg_rt = sum(rts) / len(rts)
                    min_rt = min(rts)
                    max_rt = max(rts)
                    print(f"  {C.G}  Baseline RT: avg={avg_rt*1000:.0f}ms min={min_rt*1000:.0f}ms max={max_rt*1000:.0f}ms{C.RS}")

                if rl_detected:
                    print(f"  {C.Y}  Rate Limit: DETECTED at ~{rl_threshold} requests{C.RS}")
                else:
                    print(f"  {C.G}  Rate Limit: Not detected in 20 requests{C.RS}")

        except Exception as e:
            print(f"  {C.Y}  Performance test error: {e}{C.RS}")

    # ─── Attack Profile Generation ───────────────────────────────────────────

    def _generate_attack_profile(self):
        """
        Generate a customized attack profile based on detected technologies.

        This is the key output that VF_TESTER reads to customize its attack.
        """
        p = self.profile
        attack = {
            "target_url": p.url,
            "recommended_strategy": self._determine_strategy(),
            "attack_vectors": self._determine_vectors(),
            "waf_strategy": self._determine_waf_strategy(),
            "worker_config": self._determine_worker_config(),
            "request_config": self._determine_request_config(),
            "login_config": self._determine_login_config(),
            "page_targets": self._determine_page_targets(),
            "resource_targets": self._determine_resource_targets(),
            "timing_config": self._determine_timing_config(),
            "evasion_config": self._determine_evasion_config(),
            "asp_net_config": self._determine_aspnet_config(),
            "php_config": self._determine_php_config(),
            "wordpress_config": self._determine_wordpress_config(),
            "api_config": self._determine_api_config(),
            "risk_notes": self._determine_risk_notes(),
        }
        p.attack_profile = attack

    def _determine_strategy(self) -> str:
        """Determine the overall attack strategy"""
        p = self.profile
        if p.waf:
            return "WAF_BYPASS_FOCUSED"
        if p.cms:
            return "CMS_EXPLOIT_FOCUSED"
        if p.viewstate_present:
            return "ASP_NET_FOCUSED"
        if p.backend_lang and "PHP" in (p.backend_lang or ""):
            return "PHP_FOCUSED"
        if p.api_endpoints:
            return "API_FOCUSED"
        return "GENERIC_FLOOD"

    def _determine_vectors(self) -> List[str]:
        """Determine which attack vectors to use"""
        p = self.profile
        vectors = []

        # Always include login flood if login form found
        if p.login_fields.get("username") != "username" or p.forms:
            vectors.append("LOGIN_FLOOD")

        # Page flood always useful
        vectors.append("PAGE_FLOOD")

        # Resource flood if resources found
        if p.images or p.stylesheets or p.scripts:
            vectors.append("RESOURCE_FLOOD")

        # Slowloris if server supports keep-alive
        if p.headers.get("Connection", "").lower() == "keep-alive" or \
           p.headers.get("Keep-Alive", ""):
            vectors.append("SLOWLORIS")

        # API flood if endpoints detected
        if p.api_endpoints:
            vectors.append("API_FLOOD")

        # ASP.NET specific
        if p.viewstate_present:
            vectors.append("VIEWSTATE_FLOOD")

        # WordPress specific
        if p.cms and "WordPress" in p.cms:
            vectors.append("WP_XMLRPC")
            vectors.append("WP_LOGIN")

        return vectors

    def _determine_waf_strategy(self) -> Dict[str, Any]:
        """Determine WAF bypass strategy"""
        p = self.profile
        if not p.waf:
            return {"detected": False}

        strategy = {
            "detected": True,
            "waf_name": p.waf,
            "confidence": p.waf_confidence,
            "bypass_methods": [],
        }

        waf_lower = p.waf.lower()

        if "cloudflare" in waf_lower:
            strategy["bypass_methods"] = [
                "CFB_CHALLENGE_SOLVE",
                "ROTATE_USER_AGENT",
                "SLOW_REQUEST_RATE",
                "USE_CF_CLEARANCE_COOKIE",
                "ORIGIN_IP_DIRECT",
            ]
        elif "arvan" in waf_lower:
            strategy["bypass_methods"] = [
                "ROTATE_USER_AGENT",
                "SLOW_RAMP_UP",
                "CACHE_BUST_PARAMS",
                "HEADER_MANIPULATION",
                "DISTRIBUTED_SOURCES",
            ]
        elif "modsecurity" in waf_lower:
            strategy["bypass_methods"] = [
                "PAYLOAD_ENCODING",
                "HEADER_MANIPULATION",
                "PATH_OBFUSCATION",
                "CHUNKED_ENCODING",
            ]
        elif "imperva" in waf_lower or "incapsula" in waf_lower:
            strategy["bypass_methods"] = [
                "ROTATE_COOKIES",
                "SLOW_REQUEST_RATE",
                "HEADER_MANIPULATION",
            ]
        elif "akamai" in waf_lower:
            strategy["bypass_methods"] = [
                "CACHE_BUST_PARAMS",
                "ROTATE_USER_AGENT",
                "SLOW_RAMP_UP",
            ]
        else:
            strategy["bypass_methods"] = [
                "ROTATE_USER_AGENT",
                "CACHE_BUST_PARAMS",
                "SLOW_RAMP_UP",
                "HEADER_MANIPULATION",
            ]

        return strategy

    def _determine_worker_config(self) -> Dict[str, Any]:
        """Determine optimal worker configuration"""
        p = self.profile

        # Base config
        config = {
            "initial_workers": 50,
            "max_workers": 2000,
            "step": 100,
            "step_duration": 5,
            "ramp_strategy": "GRADUAL",
        }

        # Adjust based on WAF
        if p.waf:
            config["initial_workers"] = 20
            config["step"] = 50
            config["step_duration"] = 8
            config["ramp_strategy"] = "STEALTHY"
            if "cloudflare" in (p.waf or "").lower():
                config["initial_workers"] = 10
                config["step"] = 30
                config["step_duration"] = 10
                config["ramp_strategy"] = "SLOW_STEALTHY"

        # Adjust based on baseline RT
        if p.baseline_rt > 2.0:
            config["initial_workers"] = max(10, config["initial_workers"] // 2)
            config["max_workers"] = 1000
        elif p.baseline_rt < 0.3:
            config["max_workers"] = 5000

        # Adjust based on rate limiting
        if p.rate_limit_detected and p.rate_limit_threshold:
            if p.rate_limit_threshold < 20:
                config["initial_workers"] = 5
                config["step"] = 20
                config["step_duration"] = 15
                config["ramp_strategy"] = "VERY_SLOW"

        return config

    def _determine_request_config(self) -> Dict[str, Any]:
        """Determine request configuration"""
        p = self.profile
        config = {
            "timeout": 20,
            "follow_redirects": True,
            "verify_ssl": False,
            "keepalive": True,
            "cache_bust": True,
            "user_agent_rotation": True,
            "delay_between_requests_ms": 10,
        }

        if p.waf:
            config["delay_between_requests_ms"] = 50
            config["cache_bust"] = True

        if p.rate_limit_detected:
            config["delay_between_requests_ms"] = 100

        return config

    def _determine_login_config(self) -> Dict[str, Any]:
        """Determine login attack configuration"""
        p = self.profile
        config = {
            "enabled": bool(p.forms and p.login_fields),
            "username_field": p.login_fields.get("username", "username"),
            "password_field": p.login_fields.get("password", "password"),
            "login_url": p.url,
            "method": "POST",
            "include_hidden_fields": True,
            "weight": 0.45,
        }

        # ASP.NET specific
        if p.viewstate_present:
            config["weight"] = 0.50
            config["refresh_viewstate"] = True
            config["viewstate_ttl"] = 30

        return config

    def _determine_page_targets(self) -> List[str]:
        """Determine which pages to target"""
        p = self.profile
        pages = []

        # Add discovered links (same domain)
        domain = p.domain
        for link in p.links:
            link_parsed = urlparse(link)
            if link_parsed.netloc == domain:
                page = link.split('?')[0].split('#')[0]
                if page not in pages and page.startswith('http'):
                    pages.append(page)

        # Add common paths based on technology
        if p.viewstate_present or (p.backend_lang and "ASP.NET" in p.backend_lang):
            pages.extend([
                f"{p.scheme}://{domain}/Default.aspx",
                f"{p.scheme}://{domain}/Login.aspx",
                f"{p.scheme}://{domain}/Home.aspx",
                f"{p.scheme}://{domain}/About.aspx",
                f"{p.scheme}://{domain}/Contact.aspx",
            ])

        if p.cms and "WordPress" in p.cms:
            pages.extend([
                f"{p.scheme}://{domain}/wp-admin/",
                f"{p.scheme}://{domain}/wp-login.php",
                f"{p.scheme}://{domain}/",
                f"{p.scheme}://{domain}/feed/",
                f"{p.scheme}://{domain}/wp-json/wp/v2/posts",
            ])

        if p.api_endpoints:
            pages.extend([f"{p.scheme}://{domain}{ep}" for ep in p.api_endpoints
                         if not ep.startswith('http')])

        # Add found paths from deep scan
        for fp in p.found_paths:
            full_url = f"{p.scheme}://{domain}{fp['path']}"
            if full_url not in pages:
                pages.append(full_url)

        # Deduplicate and limit
        pages = list(dict.fromkeys(pages))[:50]
        return pages

    def _determine_resource_targets(self) -> List[str]:
        """Determine which resources to target"""
        p = self.profile
        resources = list(p.images) + list(p.stylesheets) + list(p.scripts)
        domain = p.domain

        # Add common resources
        if p.cms and "WordPress" in p.cms:
            resources.extend([
                f"{p.scheme}://{domain}/wp-includes/js/jquery/jquery.js",
                f"{p.scheme}://{domain}/wp-includes/css/dist/block-library/style.min.css",
            ])

        if p.viewstate_present:
            resources.extend([
                f"{p.scheme}://{domain}/WebResource.axd?d=test",
                f"{p.scheme}://{domain}/ScriptResource.axd?d=test",
            ])

        # Deduplicate and limit
        resources = list(dict.fromkeys(resources))[:30]
        return resources

    def _determine_timing_config(self) -> Dict[str, Any]:
        """Determine timing configuration for the attack"""
        p = self.profile
        config = {
            "crash_mode": True,
            "crash_sensitivity": "MEDIUM",
            "health_check_interval": 5,
            "auto_scale": True,
        }

        if p.waf:
            config["crash_sensitivity"] = "LOW"  # Be more careful with WAF
            config["health_check_interval"] = 3

        if p.baseline_rt > 2.0:
            config["crash_sensitivity"] = "HIGH"

        return config

    def _determine_evasion_config(self) -> Dict[str, Any]:
        """Determine evasion techniques"""
        p = self.profile
        config = {
            "rotate_user_agent": True,
            "cache_bust": True,
            "random_delays": True,
            "header_randomization": False,
            "proxy_rotation": False,
        }

        if p.waf:
            config["header_randomization"] = True
            config["random_delays"] = True
            waf_lower = p.waf.lower()
            if "cloudflare" in waf_lower:
                config["proxy_rotation"] = True
            if "arvan" in waf_lower:
                config["header_randomization"] = True

        return config

    def _determine_aspnet_config(self) -> Dict[str, Any]:
        """ASP.NET specific configuration"""
        p = self.profile
        if not p.viewstate_present:
            return {"enabled": False}

        return {
            "enabled": True,
            "viewstate_cache_ttl": 30,
            "eventvalidation_required": p.eventvalidation_present,
            "target_login_url": p.url,
            "hidden_fields": p.hidden_fields,
            "session_cookie": "ASP.NET_SessionId",
        }

    def _determine_php_config(self) -> Dict[str, Any]:
        """PHP specific configuration"""
        p = self.profile
        php_detected = p.backend_lang and "PHP" in (p.backend_lang or "")

        if not php_detected and not any("PHP" in t["name"] for t in p.technologies):
            return {"enabled": False}

        return {
            "enabled": True,
            "session_cookie": "PHPSESSID",
            "common_paths": ["/login.php", "/index.php", "/admin/login.php"],
        }

    def _determine_wordpress_config(self) -> Dict[str, Any]:
        """WordPress specific configuration"""
        p = self.profile
        if not p.cms or "WordPress" not in p.cms:
            return {"enabled": False}

        domain = p.domain
        return {
            "enabled": True,
            "xmlrpc_url": f"{p.scheme}://{domain}/xmlrpc.php",
            "login_url": f"{p.scheme}://{domain}/wp-login.php",
            "rest_api": f"{p.scheme}://{domain}/wp-json/wp/v2/posts",
            "admin_url": f"{p.scheme}://{domain}/wp-admin/",
            "wp_content": f"{p.scheme}://{domain}/wp-content/",
        }

    def _determine_api_config(self) -> Dict[str, Any]:
        """API endpoint configuration"""
        p = self.profile
        if not p.api_endpoints:
            return {"enabled": False}

        return {
            "enabled": True,
            "endpoints": p.api_endpoints,
            "methods": ["GET", "POST"],
            "content_types": ["application/json", "application/x-www-form-urlencoded"],
        }

    def _determine_risk_notes(self) -> List[str]:
        """Generate risk notes and warnings"""
        p = self.profile
        notes = []

        if p.waf:
            notes.append(f"WAF detected: {p.waf} (confidence: {p.waf_confidence:.0%}). "
                        "Expect request blocking and potential IP bans.")

        if p.rate_limit_detected:
            notes.append(f"Rate limiting detected at ~{p.rate_limit_threshold} requests. "
                        "Slow ramp-up recommended.")

        if p.security_headers.get("Strict-Transport-Security", {}).get("present"):
            notes.append("HSTS is enabled. SSL bypass may not work.")

        if not p.security_headers.get("Content-Security-Policy", {}).get("present"):
            notes.append("No CSP header. Injection attacks may be easier.")

        if p.sensitive_files:
            notes.append(f"Sensitive files exposed: {', '.join(p.sensitive_files)}. "
                        "Information disclosure risk.")

        if p.viewstate_present:
            notes.append("ASP.NET ViewState detected. ViewState flooding is highly effective.")

        if p.baseline_rt > 3.0:
            notes.append(f"Slow baseline RT ({p.baseline_rt*1000:.0f}ms). "
                        "Server may already be under load or poorly configured.")

        if p.ssl_enabled and p.ssl_info.get("protocol") in ("TLSv1", "TLSv1.1"):
            notes.append("Outdated TLS version detected. May be vulnerable to downgrade attacks.")

        if not notes:
            notes.append("No specific risks identified. Standard attack strategy recommended.")

        return notes


# ═══════════════════════════════════════════════════════════════════════════════
# Report Renderer
# ═══════════════════════════════════════════════════════════════════════════════

def render_report(profile: SiteProfile):
    """Render a beautiful scan report to the terminal"""
    p = profile

    print(f"\n\n{'='*72}")
    print(f"  {C.BD}{C.R}VF_FINDER — Scan Report{C.RS}")
    print(f"{'='*72}")

    # Target
    print(f"\n  {C.BD}Target{C.RS}")
    print(f"  URL:       {C.W}{p.url}{C.RS}")
    print(f"  Host:      {p.host}:{p.port}")
    print(f"  IPs:       {', '.join(p.ip_addresses) if p.ip_addresses else 'Unknown'}")
    if p.hosting_provider:
        print(f"  Hosting:   {p.hosting_provider}")
    print(f"  SSL:       {'Yes' if p.ssl_enabled else 'No'}")

    # Server
    print(f"\n  {C.BD}Server{C.RS}")
    print(f"  Software:  {C.Y}{p.server or 'Unknown'}{C.RS}")
    if p.server_version:
        print(f"  Version:   {p.server_version}")
    if p.os_guess:
        print(f"  OS Guess:  {p.os_guess}")

    # Technologies
    print(f"\n  {C.BD}Technologies ({len(p.technologies)}){C.RS}")
    for tech in p.technologies:
        conf_color = C.G if tech["confidence"] > 0.7 else C.Y if tech["confidence"] > 0.4 else C.DM
        conf_bar = int(tech["confidence"] * 10)
        bar = f"{'|' * conf_bar}{'.' * (10 - conf_bar)}"
        print(f"  {conf_color}{tech['name']:<25}{C.RS} [{bar}] {tech['confidence']:.0%} {C.DM}{tech['category']}{C.RS}")

    # WAF
    if p.waf:
        print(f"\n  {C.BD}{C.R}WAF Detection{C.RS}")
        print(f"  WAF:       {C.R}{p.waf}{C.RS} (confidence: {p.waf_confidence:.0%})")
        bypass = p.attack_profile.get("waf_strategy", {}).get("bypass_methods", [])
        if bypass:
            print(f"  Bypass:    {', '.join(bypass)}")

    # CMS
    if p.cms:
        print(f"\n  {C.BD}CMS{C.RS}")
        print(f"  Platform:  {C.Y}{p.cms}{C.RS}")

    # Performance
    print(f"\n  {C.BD}Performance{C.RS}")
    print(f"  Status:    {p.status_code}")
    print(f"  Page Size: {p.page_size:,}B ({SiteProfile._human_size(p.page_size)})")
    print(f"  Baseline RT: {p.baseline_rt*1000:.0f}ms")
    if p.rate_limit_detected:
        print(f"  Rate Limit: {C.R}DETECTED at ~{p.rate_limit_threshold} requests{C.RS}")
    else:
        print(f"  Rate Limit: {C.G}Not detected{C.RS}")

    # Content
    print(f"\n  {C.BD}Content{C.RS}")
    print(f"  Forms:       {len(p.forms)}")
    print(f"  Hidden Fields: {len(p.hidden_fields)}")
    print(f"  Scripts:     {len(p.scripts)}")
    print(f"  Links:       {len(p.links)}")
    print(f"  API Endpoints: {len(p.api_endpoints)}")
    if p.viewstate_present:
        print(f"  ViewState:   {C.Y}PRESENT{C.RS}")
    if p.login_fields:
        print(f"  Login:       user={p.login_fields.get('username','?')} pass={p.login_fields.get('password','?')}")

    # Security
    print(f"\n  {C.BD}Security Headers{C.RS}")
    for header, info in p.security_headers.items():
        if info["present"]:
            print(f"  {C.G}+ {header}: {info['value'][:50]}{C.RS}")
        else:
            print(f"  {C.R}- {header}: MISSING{C.RS}")

    # Sensitive files
    if p.sensitive_files:
        print(f"\n  {C.BD}{C.R}Sensitive Files{C.RS}")
        for sf in p.sensitive_files:
            print(f"  {C.R}!! {sf}{C.RS}")

    # Attack Profile Summary
    if p.attack_profile:
        ap = p.attack_profile
        print(f"\n  {C.BD}{C.M}Attack Profile (for VF_TESTER){C.RS}")
        print(f"  Strategy:    {C.Y}{ap.get('recommended_strategy', 'N/A')}{C.RS}")
        print(f"  Vectors:     {', '.join(ap.get('attack_vectors', []))}")
        wc = ap.get('worker_config', {})
        print(f"  Workers:     initial={wc.get('initial_workers','?')} max={wc.get('max_workers','?')} step={wc.get('step','?')}")
        print(f"  Ramp:        {wc.get('ramp_strategy', 'N/A')}")

        notes = ap.get('risk_notes', [])
        if notes:
            print(f"\n  {C.BD}Risk Notes{C.RS}")
            for note in notes:
                print(f"  {C.Y}* {note}{C.RS}")

    print(f"\n  Scan Time: {p.scan_time:.1f}s")
    print(f"{'='*72}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="VF_FINDER — Reconnaissance Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Output: VF_PROFILE.json (feed to VF_TESTER)\n")
    p.add_argument("url", help="Target URL to scan")
    p.add_argument("--deep", action="store_true", help="Deep path scanning")
    p.add_argument("--dns", action="store_true", help="DNS enumeration")
    p.add_argument("--subdomains", action="store_true", help="Subdomain enumeration")
    p.add_argument("--output", default="VF_PROFILE.json", help="Output file (default: VF_PROFILE.json)")
    p.add_argument("--no-report", action="store_true", help="Skip terminal report (JSON only)")
    return p.parse_args()


async def main():
    args = parse_args()

    url = args.url
    if not url.startswith("http"):
        url = "https://" + url

    finder = VFFinder(url, deep=args.deep, dns_scan=args.dns,
                      subdomain_scan=args.subdomains)
    profile = await finder.scan()

    # Render report
    if not args.no_report:
        render_report(profile)

    # Save JSON profile
    output_data = profile.to_dict()
    output_path = args.output
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    print(f"  {C.G}Profile saved to: {output_path}{C.RS}")
    print(f"  {C.CY}Feed this file to VF_TESTER: python VF_TESTER.py --profile {output_path}{C.RS}")


if __name__ == "__main__":
    asyncio.run(main())
