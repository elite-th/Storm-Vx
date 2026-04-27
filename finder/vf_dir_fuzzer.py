#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  vf_dir_fuzzer.py — Directory Fuzzer Module                             ║
║  Part of the STORM_VX Toolkit                                           ║
║                                                                          ║
║  Fuzzes common sensitive paths using HEAD requests, detects interesting  ║
║  responses, and identifies paths that exist but are blocked by CDN/WAF.  ║
║  Smart detection: different 403 body = path exists but blocked.          ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import aiohttp


# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# Internal Wordlist — 300+ common sensitive paths
# ═══════════════════════════════════════════════════════════════════════════════

DIR_WORDLIST = [
    # Robots & Sitemap
    "/robots.txt", "/sitemap.xml", "/sitemap.xml.gz",
    "/sitemap_index.xml", "/sitemap.ror",

    # Version control
    "/.git/HEAD", "/.git/config", "/.git/description", "/.git/COMMIT_EDITMSG",
    "/.gitignore", "/.gitmodules",
    "/.svn/entries", "/.svn/wc.db",
    "/.hg/store", "/.hg/hgrc",
    "/.DS_Store", "/.env", "/.env.bak", "/.env.local", "/.env.production",
    "/.env.development", "/.env.staging",

    # Server info
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php",
    "/phpmyadmin/", "/pma/", "/adminer.php",
    "/mysql/", "/mysqladmin/",

    # WordPress
    "/wp-admin/", "/wp-login.php", "/wp-config.php.bak",
    "/wp-content/debug.log", "/wp-content/", "/wp-includes/",
    "/wp-json/", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/wp-cron.php",

    # Admin panels
    "/administrator/", "/admin/", "/admin/login", "/admin/dashboard",
    "/admin/config", "/admin/settings", "/admin/admin",
    "/manager/html", "/console", "/controlpanel", "/cpanel",
    "/plesk", "/webmail", "/mailer/",

    # API endpoints
    "/api/", "/api/v1/", "/api/v2/", "/api/docs", "/api/swagger",
    "/api/openapi.json", "/api/health", "/api/status",
    "/swagger.json", "/swagger-ui/", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml",
    "/graphql", "/graphiql", "/playground",

    # Spring Boot Actuator
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/configprops", "/actuator/beans",
    "/actuator/info", "/actuator/metrics", "/actuator/trace",
    "/actuator/loggers", "/actuator/threaddump", "/actuator/heapdump",

    # Debug endpoints
    "/debug", "/debug/vars", "/debug/pprof", "/debug/pprof/goroutine",
    "/trace", "/metrics", "/health", "/status", "/ping",
    "/info", "/version", "/env", "/configenv",

    # Config files
    "/config", "/config.json", "/config.yml", "/config.yaml",
    "/config.php", "/config.inc.php",
    "/settings", "/settings.py", "/settings.json",
    "/package.json", "/composer.json", "/Gemfile", "/requirements.txt",
    "/Pipfile", "/Makefile", "/Dockerfile", "/.dockerenv",
    "/docker-compose.yml", "/docker-compose.yaml", "/Jenkinsfile",

    # Web servers
    "/nginx.conf", "/httpd.conf", "/web.config", "/app.config",
    "/web.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.htaccess", "/.htpasswd",

    # Well-known
    "/.well-known/security.txt", "/.well-known/assetlinks.json",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
    "/.well-known/change-password", "/.well-known/nodeinfo",

    # OAuth / Auth
    "/oauth/authorize", "/oauth/token", "/oauth/callback",
    "/auth/login", "/auth/register", "/auth/forgot-password",
    "/login", "/signin", "/sign-in", "/register", "/signup", "/sign-up",
    "/forgot-password", "/reset-password",
    "/profile", "/account", "/settings", "/dashboard",

    # Upload & Files
    "/upload", "/uploads/", "/files/", "/download", "/export", "/import",
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/dump.sql", "/database.sql", "/db.sql",
    "/backup/", "/backups/", "/old/", "/temp/", "/tmp/",
    "/cache/", "/log/", "/logs/", "/error/", "/errors/",

    # Static / Assets
    "/static/", "/assets/", "/public/", "/private/",
    "/internal/", "/secret/", "/restricted/", "/secure/",

    # SSL / Certs
    "/ssl/", "/cert/", "/certificate/", "/key/", "/keys/",
    "/ssh/", "/.ssh/authorized_keys", "/.ssh/id_rsa", "/.ssh/id_rsa.pub",
    "/id_rsa",

    # Analytics
    "/webalizer/", "/awstats/",

    # Databases
    "/pgadmin/", "/solr/", "/elastic/", "/kibana/",
    "/grafana/", "/prometheus/",

    # DevOps
    "/jenkins/", "/gitlab/", "/bitbucket/", "/jira/",
    "/confluence/", "/nexus/", "/sonar/", "/sonarqube/",
    "/artifactory/", "/docker/", "/registry/", "/rancher/",
    "/traefik/", "/varnish/", "/haproxy/", "/nginx/",
    "/apache/", "/caddy/",

    # Java / .NET
    "/tomcat/", "/wildfly/", "/jboss/", "/websphere/", "/weblogic/",
    "/iis/", "/dotnet/",
    "/elmah.axd", "/trace.axd", "/web.config", "/Web.config",
    "/Global.asa", "/Global.asax", "/Application.asax",

    # Misc
    "/home", "/index", "/search",
    "/favicon.ico", "/apple-touch-icon.png",
    "/humans.txt", "/CHANGELOG.md", "/CHANGELOG.txt", "/README.md",
    "/readme.html", "/readme.txt", "/LICENSE", "/license.txt",
    "/CONTRIBUTING.md", "/SECURITY.md",
    "/bower.json", "/package-lock.json", "/yarn.lock",
    "/tsconfig.json", "/.eslintrc", "/.prettierrc",
    "/webpack.config.js", "/vite.config.js", "/rollup.config.js",
    "/next.config.js", "/nuxt.config.js", "/vue.config.js",
    "/angular.json", "/gatsby-config.js",
    "/.babelrc", "/.editorconfig", "/.firebaserc",
    "/firebase.json", "/now.json", "/vercel.json",
    "/netlify.toml", "/procfile",
    "/main.py", "/app.py", "/manage.py", "/wsgi.py", "/asgi.py",
    "/server.js", "/index.js", "/app.js",
    "/index.php", "/wp-load.php",
    "/cron.php", "/cron.sh", "/scheduler",
    "/queue", "/worker", "/jobs",
    "/mailer", "/email", "/sms",
    "/notification", "/notify", "/push",
    "/payment", "/payments", "/checkout", "/order", "/orders",
    "/cart", "/shop", "/store", "/catalog", "/product", "/products",
    "/user", "/users", "/profile", "/profiles",
    "/post", "/posts", "/article", "/articles",
    "/comment", "/comments", "/review", "/reviews",
    "/tag", "/tags", "/category", "/categories",
    "/feed", "/rss", "/atom.xml",
    "/sitemap/", "/archive/", "/archives/",
    "/channel", "/channels", "/room", "/rooms",
    "/event", "/events", "/booking", "/bookings",
    "/reservation", "/reservations",
    "/ticket", "/tickets", "/support", "/help", "/faq",
    "/contact", "/about", "/terms", "/privacy", "/legal",
    "/cookie", "/cookies", "/consent",
    "/subscribe", "/unsubscribe", "/newsletter",
    "/survey", "/poll", "/vote",
    "/game", "/games", "/play",
    "/video", "/videos", "/audio", "/music", "/podcast",
    "/photo", "/photos", "/gallery", "/album", "/albums",
    "/map", "/location", "/directions",
    "/weather", "/news", "/blog", "/blogs",
    "/forum", "/forums", "/discussion", "/discussions",
    "/thread", "/threads", "/topic", "/topics",
    "/wiki/", "/docs/", "/documentation/",
    "/api-docs", "/api-docs.json", "/api-reference",
    "/redoc", "/rapidoc",
]


class DirectoryFuzzer:
    """
    Directory fuzzer for STORM_VX.

    Fuzzes common sensitive paths using HEAD requests for speed,
    detects interesting responses, and identifies paths that exist
    but are blocked by CDN/WAF through smart body comparison.
    """

    # Interesting status codes
    INTERESTING_STATUS = {200, 201, 204, 301, 302, 401, 403, 405, 500, 503}

    def __init__(self, url: str, timeout: int = 15, max_concurrent: int = 30):
        """
        Initialize DirectoryFuzzer.

        Args:
            url: Target URL
            timeout: HTTP request timeout in seconds
            max_concurrent: Maximum concurrent requests
        """
        self.url = url
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        parsed = urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._baseline_403_body: str = ""
        self._baseline_404_body: str = ""

    async def run(self) -> Dict:
        """
        Run directory fuzzing.

        Returns:
            Dictionary with:
                - found_paths: List of found paths with details
                - status_codes: Dict of status_code -> count
                - interesting_files: List of particularly interesting findings
        """
        print(f"\n  {C.BD}{C.CY}[*] Directory Fuzzer — {self.url}{C.RS}")
        print(f"  {C.DM}    Paths: {len(DIR_WORDLIST)} | Concurrency: {self.max_concurrent} | Timeout: {self.timeout}s{C.RS}")

        t0 = time.time()

        # Step 1: Get baseline 403/404 body for comparison
        print(f"  {C.B}  [1/3] Establishing baseline responses...{C.RS}")
        await self._get_baselines()

        # Step 2: Fuzz all paths
        print(f"  {C.B}  [2/3] Fuzzing {len(DIR_WORDLIST)} paths...{C.RS}")
        raw_results = await self._fuzz_paths()

        # Step 3: Analyze results
        print(f"  {C.B}  [3/3] Analyzing results...{C.RS}")
        found_paths, status_codes, interesting = self._analyze_results(raw_results)

        elapsed = time.time() - t0

        # Print summary
        self._print_summary(found_paths, status_codes, interesting, elapsed)

        return {
            "found_paths": found_paths,
            "status_codes": status_codes,
            "interesting_files": interesting,
        }

    async def _get_baselines(self):
        """Get baseline 403 and 404 response bodies for comparison."""
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            # Get a likely 404 response
            try:
                url_404 = f"{self.base_url}/this-path-definitely-does-not-exist-xyz123"
                async with session.get(url_404, ssl=False, allow_redirects=False) as resp:
                    self._baseline_404_body = (await resp.text())[:500]
                    print(
                        f"  {C.G}    Baseline 404: HTTP {resp.status} | "
                        f"Size: {len(self._baseline_404_body)}B{C.RS}"
                    )
            except Exception as e:
                print(f"  {C.Y}    Baseline 404 error: {type(e).__name__}{C.RS}")

            # Get a likely 403 response (try admin path)
            try:
                url_403 = f"{self.base_url}/admin"
                async with session.get(url_403, ssl=False, allow_redirects=False) as resp:
                    if resp.status == 403:
                        self._baseline_403_body = (await resp.text())[:500]
                        print(
                            f"  {C.G}    Baseline 403: HTTP {resp.status} | "
                            f"Size: {len(self._baseline_403_body)}B{C.RS}"
                        )
            except Exception:
                pass

    async def _fuzz_paths(self) -> List[Dict]:
        """Fuzz all paths in the wordlist."""
        results = []
        processed = 0
        total = len(DIR_WORDLIST)
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)

        async def check_path(path: str) -> Optional[Dict]:
            nonlocal processed
            async with self._semaphore:
                url = f"{self.base_url}{path}"
                try:
                    async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                        # Try HEAD first (faster)
                        try:
                            async with session.head(
                                url, ssl=False, allow_redirects=False
                            ) as resp:
                                status = resp.status
                                content_length = resp.headers.get("Content-Length", "")
                                location = resp.headers.get("Location", "")
                                server = resp.headers.get("Server", "")

                                # For interesting responses, also GET the body
                                body_snippet = ""
                                if status in self.INTERESTING_STATUS:
                                    try:
                                        async with session.get(
                                            url, ssl=False, allow_redirects=False
                                        ) as resp_get:
                                            body_snippet = (await resp_get.text())[:300]
                                            status = resp_get.status
                                    except Exception:
                                        pass

                                result = {
                                    "path": path,
                                    "url": url,
                                    "status_code": status,
                                    "content_length": content_length,
                                    "redirect_location": location,
                                    "server": server,
                                    "body_snippet": body_snippet,
                                }

                                processed += 1
                                if processed % 50 == 0:
                                    print(
                                        f"  {C.DM}    Progress: {processed}/{total} "
                                        f"({processed*100//total}%) — "
                                        f"Found: {len(results)}{C.RS}"
                                    )

                                return result

                        except asyncio.TimeoutError:
                            processed += 1
                            return None
                        except Exception:
                            # Fallback to GET if HEAD not supported
                            try:
                                async with session.get(
                                    url, ssl=False, allow_redirects=False
                                ) as resp:
                                    body_snippet = (await resp.text())[:300]
                                    result = {
                                        "path": path,
                                        "url": url,
                                        "status_code": resp.status,
                                        "content_length": resp.headers.get("Content-Length", ""),
                                        "redirect_location": resp.headers.get("Location", ""),
                                        "server": resp.headers.get("Server", ""),
                                        "body_snippet": body_snippet,
                                    }
                                    processed += 1
                                    return result
                            except Exception:
                                processed += 1
                                return None

                except Exception:
                    processed += 1
                    return None

        tasks = [check_path(path) for path in DIR_WORDLIST]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in raw_results:
            if isinstance(r, dict) and r is not None:
                results.append(r)

        return results

    def _analyze_results(
        self, raw_results: List[Dict]
    ) -> Tuple[List[Dict], Dict, List[Dict]]:
        """
        Analyze raw fuzzing results.

        Returns:
            Tuple of (found_paths, status_codes, interesting_files)
        """
        found_paths = []
        status_codes: Dict[str, int] = {}
        interesting = []

        for result in raw_results:
            status = result.get("status_code", 0)
            path = result.get("path", "")

            # Count status codes
            status_key = str(status)
            status_codes[status_key] = status_codes.get(status_key, 0) + 1

            # Skip non-interesting responses
            if status not in self.INTERESTING_STATUS:
                continue

            # Smart detection: if 403 but body differs from baseline
            is_smart_403 = False
            if status == 403 and self._baseline_403_body:
                body = result.get("body_snippet", "")
                if body and body != self._baseline_403_body:
                    is_smart_403 = True
                    result["smart_detection"] = "403 body differs from baseline — path likely exists"
                    print(
                        f"  {C.Y}    [SMART-403] {path} → Body differs from baseline 403{C.RS}"
                    )

            # Smart detection: if 403 but body differs from 404 baseline
            if status == 403 and self._baseline_404_body:
                body = result.get("body_snippet", "")
                if body and body == self._baseline_404_body:
                    # 403 with 404 body = generic block, path may not exist
                    result["smart_detection"] = "403 with 404-like body — generic WAF block"
                    continue

            found_paths.append(result)

            # Flag particularly interesting findings
            is_interesting = False
            interest_reason = ""

            if status == 200:
                # Check for sensitive file patterns
                sensitive_patterns = [
                    ".env", ".git", ".svn", ".hg", ".ssh",
                    "phpinfo", "phpmyadmin", "adminer", "wp-config",
                    "backup", "dump.sql", "database.sql", "db.sql",
                    "debug.log", "error.log",
                    "id_rsa", "authorized_keys", ".htpasswd",
                    "swagger", "openapi", "graphql", "graphiql",
                    "actuator", "metrics", "trace",
                    "server-status", "server-info",
                    "Dockerfile", "docker-compose",
                    "Jenkinsfile",
                ]
                for pattern in sensitive_patterns:
                    if pattern in path.lower():
                        is_interesting = True
                        interest_reason = f"Sensitive file: {pattern}"
                        break

            elif status == 401:
                is_interesting = True
                interest_reason = "Authentication required — valid endpoint"

            elif status == 403 and is_smart_403:
                is_interesting = True
                interest_reason = "Path exists but blocked by WAF/CDN"

            elif status in (301, 302):
                location = result.get("redirect_location", "")
                if any(k in location.lower() for k in ["login", "auth", "sso"]):
                    is_interesting = True
                    interest_reason = f"Redirects to auth: {location[:50]}"

            elif status == 500:
                is_interesting = True
                interest_reason = "Server error — may reveal information"

            if is_interesting:
                result["interest_reason"] = interest_reason
                interesting.append(result)

                # Print interesting finding
                if status == 200:
                    color = C.R
                elif status == 401:
                    color = C.Y
                elif status == 403:
                    color = C.M
                elif status == 500:
                    color = C.R
                else:
                    color = C.CY

                print(
                    f"  {color}    [!] {path} → HTTP {status} "
                    f"| {interest_reason}{C.RS}"
                )

        # Also print non-interesting found paths
        for result in found_paths:
            status = result.get("status_code", 0)
            path = result.get("path", "")
            if result not in interesting:
                color = C.G if status == 200 else C.DM
                print(
                    f"  {color}    [+] {path} → HTTP {status}{C.RS}"
                )

        return found_paths, status_codes, interesting

    def _print_summary(
        self,
        found_paths: List[Dict],
        status_codes: Dict,
        interesting: List[Dict],
        elapsed: float
    ):
        """Print formatted summary."""
        print(f"\n  {C.G}  ╔════════════════════════════════════════════════════════╗{C.RS}")
        print(f"  {C.G}  ║  Directory Fuzz Results                               ║{C.RS}")
        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Total Paths Tested:  {C.W}{len(DIR_WORDLIST):<27}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Found Paths:         {C.CY}{len(found_paths):<27}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Interesting Files:   {C.Y}{len(interesting):<27}{C.G}║{C.RS}")
        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")

        # Status code breakdown
        print(f"  {C.G}  ║  Status Code Breakdown:{C.RS}")
        for code in sorted(status_codes.keys()):
            count = status_codes[code]
            if int(code) in self.INTERESTING_STATUS:
                color = C.Y if int(code) >= 400 else C.G
            else:
                color = C.DM
            print(f"  {C.G}  ║{C.RS}    {color}HTTP {code}: {count} responses{C.RS}")

        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")

        # Interesting files
        if interesting:
            print(f"  {C.G}  ║  Interesting Findings:{C.RS}")
            for item in interesting:
                status = item.get("status_code", 0)
                path = item.get("path", "")
                reason = item.get("interest_reason", "")
                if status == 200:
                    color = C.R
                elif status == 401:
                    color = C.Y
                elif status == 403:
                    color = C.M
                else:
                    color = C.CY
                print(f"  {C.G}  ║{C.RS}    {color}{path:<40}{C.RS} HTTP {status} | {reason}")

        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Time: {C.CY}{elapsed:.1f}s{C.RS} ({len(DIR_WORDLIST)/elapsed:.0f} req/s)")
        print(f"  {C.G}  ╚════════════════════════════════════════════════════════╝{C.RS}")
