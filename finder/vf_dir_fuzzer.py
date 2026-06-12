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
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

import aiohttp

from vf_common import C, ssl_param
from utils.response_helpers import safe_read_text
from utils.session_helpers import scanner_timeout


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

    def __init__(self, url: str, timeout: int = 8, max_concurrent: int = 50, verify_ssl: bool = True):
        """
        Initialize DirectoryFuzzer.

        Args:
            url: Target URL
            timeout: HTTP request timeout in seconds
            max_concurrent: Maximum concurrent requests
            verify_ssl: Whether to verify SSL certificates
        """
        self.url = url
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.verify_ssl = verify_ssl
        self._ssl = ssl_param(self.verify_ssl)
        parsed = urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._baseline_403_body: str = ""
        self._baseline_404_body: str = ""
        # v2: Store baseline 404 status code and redirect location for smart 301/302 filtering
        self._baseline_404_status: int = 0
        self._baseline_404_location: str = ""
        self._baseline_404_size: int = 0

    async def run(self) -> Dict:
        """
        Run directory fuzzing.

        Returns:
            Dictionary with:
                - found_paths: List of found paths with details (excludes non-auth 301s)
                - redirect_paths: List of 301 redirects (uncertain, not catch-all)
                - paths: Combined list of paths for TESTER (200, 302, 403 + valid 301s)
                - status_codes: Dict of status_code -> count
                - interesting_files: List of particularly interesting findings
        """
        print(f"\n  {C.BD}{C.CY}[*] Directory Fuzzer — {self.url}{C.RS}")
        print(f"  {C.DM}    Paths: {len(DIR_WORDLIST)} | Concurrency: {self.max_concurrent} | Timeout: {self.timeout}s{C.RS}")

        t0 = time.monotonic()

        # Step 1: Get baseline 403/404 body for comparison
        print(f"  {C.B}  [1/3] Establishing baseline responses...{C.RS}")
        await self._get_baselines()

        # Step 2: Fuzz all paths
        print(f"  {C.B}  [2/3] Fuzzing {len(DIR_WORDLIST)} paths...{C.RS}")
        raw_results = await self._fuzz_paths()

        # Step 3: Analyze results
        print(f"  {C.B}  [3/3] Analyzing results...{C.RS}")
        found_paths, status_codes, interesting, redirect_paths, catchall_301_count = self._analyze_results(raw_results)

        elapsed = time.monotonic() - t0

        # Print summary
        self._print_summary(
            found_paths, status_codes, interesting, elapsed,
            redirect_paths=redirect_paths,
            catchall_301_count=catchall_301_count,
        )

        # FIX-3: Build final paths list for TESTER profile.
        # Only include paths that indicate real/discoverable endpoints:
        #   - HTTP 200 (real endpoints)
        #   - HTTP 302 (auth redirects — indicate real auth pages)
        #   - HTTP 301 that redirect to specific/different URLs (not catch-all)
        #   - HTTP 403 (blocked — indicate real files that are access-controlled)
        _valid_tester_statuses = {200, 302, 403}
        paths_for_tester = [
            p for p in found_paths
            if p.get("status_code", 0) in _valid_tester_statuses
        ] + list(redirect_paths)  # redirect_paths contains only non-catch-all 301s

        return {
            "found_paths": found_paths,
            "redirect_paths": redirect_paths,
            "paths": paths_for_tester,
            "status_codes": status_codes,
            "interesting_files": interesting,
        }

    async def _get_baselines(self):
        """Get baseline 403 and 404 response bodies for comparison.

        v2: Also stores baseline 404 status code and redirect location
        to filter out catch-all 301/302 redirects (false positives).
        """
        timeout_cfg = scanner_timeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            # Get a likely 404 response
            try:
                url_404 = f"{self.base_url}/this-path-definitely-does-not-exist-xyz123"
                async with session.get(url_404, ssl=self._ssl, allow_redirects=False) as resp:
                    # BUG-FIX v33: Read body once, use full length for size.
                    # Previously: body was truncated to 500, then size was set
                    # to truncated length (max 500). This made the Content-Length
                    # comparison at line 497-498 unreliable for large 404 pages.
                    full_body_404 = await safe_read_text(resp)  # W1.10: bounded read
                    self._baseline_404_body = full_body_404[:500]
                    self._baseline_404_status = resp.status
                    self._baseline_404_location = resp.headers.get("Location", "")
                    self._baseline_404_size = len(full_body_404)
                    print(
                        f"  {C.G}    Baseline 404: HTTP {resp.status} | "
                        f"Size: {self._baseline_404_size}B{C.RS}"
                    )
                    # v2: Warn if baseline is a redirect (catch-all server)
                    if resp.status in (301, 302) and self._baseline_404_location:
                        print(
                            f"  {C.Y}    ⚠ Baseline 404 returns HTTP {resp.status} → {self._baseline_404_location[:50]}{C.RS}"
                        )
                        print(
                            f"  {C.DM}    Redirects matching baseline will be filtered as false positives{C.RS}"
                        )
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                print(f"  {C.Y}    Baseline 404 error: {type(e).__name__}{C.RS}")

            # Get a likely 403 response (try admin path)
            try:
                url_403 = f"{self.base_url}/admin"
                async with session.get(url_403, ssl=self._ssl, allow_redirects=False) as resp:
                    if resp.status == 403:
                        self._baseline_403_body = (await safe_read_text(resp))[:500]  # W1.10: bounded read
                        print(
                            f"  {C.G}    Baseline 403: HTTP {resp.status} | "
                            f"Size: {len(self._baseline_403_body)}B{C.RS}"
                        )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

    async def _fuzz_paths(self) -> List[Dict]:
        """Fuzz all paths in the wordlist."""
        results = []
        found_count = 0
        processed = 0
        total = len(DIR_WORDLIST)
        timeout_cfg = scanner_timeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout_cfg) as shared_session:

            async def check_path(session: aiohttp.ClientSession, path: str) -> Dict | None:
                nonlocal processed, found_count
                async with self._semaphore:
                    url = f"{self.base_url}{path}"
                    try:
                        # Try HEAD first (faster)
                        try:
                            async with session.head(
                                url, ssl=self._ssl, allow_redirects=False
                            ) as resp:
                                status = resp.status
                                content_length = resp.headers.get("Content-Length", "")
                                location = resp.headers.get("Location", "")
                                server = resp.headers.get("Server", "")

                                # Only GET for 200 to capture body snippet;
                                # non-200 interesting statuses (403/401/301/302) don't need a follow-up GET
                                body_snippet = ""
                                if status == 200:
                                    try:
                                        async with session.get(
                                            url, ssl=self._ssl, allow_redirects=False
                                        ) as resp_get:
                                            body_snippet = (await safe_read_text(resp_get))[:300]  # W1.10: bounded read
                                            status = resp_get.status
                                    except (aiohttp.ClientError, asyncio.TimeoutError):
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
                                found_count += 1
                                if processed % 100 == 0:
                                    print(
                                        f"  {C.DM}    Progress: {processed}/{total} "
                                        f"({processed*100//total}%) — "
                                        f"Found: {found_count}{C.RS}"
                                    )

                                return result

                        except asyncio.TimeoutError:
                            processed += 1
                            return None
                        except (aiohttp.ClientError, asyncio.TimeoutError):
                            # Fallback to GET if HEAD not supported
                            try:
                                async with session.get(
                                    url, ssl=self._ssl, allow_redirects=False
                                ) as resp:
                                    body_snippet = (await safe_read_text(resp))[:300]  # W1.10: bounded read
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
                                    found_count += 1
                                    return result
                            except (aiohttp.ClientError, asyncio.TimeoutError):
                                processed += 1
                                return None

                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        processed += 1
                        return None

            tasks = [check_path(shared_session, path) for path in DIR_WORDLIST]
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in raw_results:
            if isinstance(r, dict) and r is not None:
                results.append(r)

        return results

    def _analyze_results(
        self, raw_results: List[Dict]
    ) -> Tuple[List[Dict], Dict, List[Dict], List[Dict], int]:
        """
        Analyze raw fuzzing results.

        Returns:
            Tuple of (found_paths, status_codes, interesting_files,
                      redirect_paths, catchall_301_count)
        """
        found_paths = []
        redirect_paths = []  # FIX-3: 301 redirects (uncertain, not confirmed real)
        status_codes: Dict[str, int] = {}
        interesting = []
        catchall_301_count = 0  # FIX-3: Count of filtered catch-all 301s

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
                # BUG-FIX v33: Use prefix comparison instead of full equality.
                # Baseline bodies are truncated to 500 chars but fuzzing
                # snippets to 300 chars. Full equality comparison (`body != baseline`)
                # always triggers when body (300) is shorter than baseline (500),
                # causing false SMART-403 detections on every 403 response.
                compare_len = min(len(body), len(self._baseline_403_body))
                if body and body[:compare_len] != self._baseline_403_body[:compare_len]:
                    is_smart_403 = True
                    result["smart_detection"] = "403 body differs from baseline — path likely exists"
                    print(
                        f"  {C.Y}    [SMART-403] {path} → Body differs from baseline 403{C.RS}"
                    )

            # Smart detection: if 403 but body differs from 404 baseline
            if status == 403 and self._baseline_404_body:
                body = result.get("body_snippet", "")
                # BUG-FIX v33: Same prefix comparison fix as SMART-403 above.
                compare_len = min(len(body), len(self._baseline_404_body))
                if body and body[:compare_len] == self._baseline_404_body[:compare_len]:
                    # 403 with 404 body = generic block, path may not exist
                    result["smart_detection"] = "403 with 404-like body — generic WAF block"
                    continue

            # v2→v4: Smart detection for 301/302 redirects that match baseline 404 redirect
            # If the server returns 301 for nonexistent paths (catch-all redirect),
            # filter out results that match the catch-all pattern.
            # v4: Much more aggressive filtering — when baseline is a 301 catch-all,
            # ONLY show redirects to auth-related paths (login, admin, etc.)
            # Everything else is assumed to be a catch-all redirect false positive.
            # v5: Added WordPress content redirect filter and post-processing
            # catch-all detection for sites that redirect ANY unknown path
            # to content/article pages.
            is_catchall_301 = False  # v5: track if this 301 was filtered
            if status in (301, 302) and self._baseline_404_status in (301, 302):
                location = result.get("redirect_location", "")
                content_length = result.get("content_length", "")

                # v4: Auth-related redirect keywords — these are genuine findings
                _auth_keywords = ["login", "signin", "sign-in", "auth", "sso",
                                  "admin", "dashboard", "portal", "oauth",
                                  "callback", "verify", "confirm", "register",
                                  "signup", "sign-up", "reset", "forgot"]
                location_lower = (location or "").lower()
                is_auth_redirect = any(kw in location_lower for kw in _auth_keywords)

                # If redirect goes to an auth path, it's a genuine finding — keep it
                if is_auth_redirect:
                    pass  # Don't filter, fall through to found_paths
                else:
                    # v4: For non-auth redirects when baseline is a catch-all,
                    # apply aggressive false positive filtering

                    # Filter 1: Same redirect location as baseline
                    if location and location == self._baseline_404_location:
                        is_catchall_301 = True
                        continue

                    # Filter 2: Trailing-slash redirect (e.g., /path → /path/)
                    if location:
                        from urllib.parse import urlparse as _urlparse
                        loc_path = _urlparse(location).path.rstrip('/')
                        req_path = path.rstrip('/')
                        if loc_path == req_path and path != location:
                            is_catchall_301 = True
                            continue

                    # Filter 3: Same response size as baseline (±100 bytes, was ±50)
                    if content_length and self._baseline_404_size and \
                       content_length.isdigit() and abs(int(content_length) - self._baseline_404_size) < 100:
                        is_catchall_301 = True
                        continue

                    # Filter 4 (v4): Redirect to homepage/root = catch-all
                    if location:
                        from urllib.parse import urlparse as _urlparse
                        loc_path = _urlparse(location).path
                        if loc_path in ('', '/'):
                            is_catchall_301 = True
                            continue

                    # Filter 5 (v4): Redirect just adds/removes www or http→https
                    # e.g., http://example.com/path → https://example.com/path
                    if location and self._baseline_404_location:
                        from urllib.parse import urlparse as _urlparse
                        loc_parsed = _urlparse(location)
                        base_parsed = _urlparse(self._baseline_404_location)
                        if (loc_parsed.path == base_parsed.path and
                            loc_parsed.query == base_parsed.query and
                            loc_parsed.params == base_parsed.params):
                            is_catchall_301 = True
                            continue

                    # Filter 6 (v4): Path-rewriting redirect
                    # e.g., /admin → /admin, /test → /test (same path, just canonicalized)
                    if location:
                        from urllib.parse import urlparse as _urlparse
                        loc_path = _urlparse(location).path.rstrip('/')
                        req_path = path.rstrip('/')
                        if loc_path == req_path:
                            is_catchall_301 = True
                            continue

                    # Filter 7 (v5): WordPress-style content redirect patterns
                    # WordPress redirects ANY unknown path to a content page/article.
                    # Patterns: ?p=123, ?page_id=123, ?cat=5, /2024/01/article/
                    # These are NOT real path discoveries — they're catch-all redirects.
                    if location:
                        from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs
                        loc_parsed = _urlparse(location)
                        loc_query = loc_parsed.query.lower()
                        loc_path_lower = loc_parsed.path.lower()

                        # WordPress query param redirects (?p=123, ?page_id=, ?cat=)
                        wp_query_params = ['p=', 'page_id=', 'cat=', 'm=', 'w=',
                                          'attachment_id=', 'post=', 'tag=']
                        if any(loc_query.startswith(qp) or f'&{qp}' in loc_query for qp in wp_query_params):
                            is_catchall_301 = True
                            continue

                        # Date-based permalink redirects (/2024/01/, /2024/01/15/)
                        import re as _re
                        if _re.match(r'/\d{4}/\d{2}', loc_path_lower):
                            is_catchall_301 = True
                            continue

                        # Zero-byte body with redirect = WordPress catch-all style
                        if content_length and content_length.isdigit() and int(content_length) == 0:
                            is_catchall_301 = True
                            continue

            # FIX-3: Track catch-all 301s that were filtered by existing filters
            if is_catchall_301:
                catchall_301_count += 1
                continue

            # FIX-3: Check if 301 redirects to an auth/login page
            # Auth-related 301s are real endpoints and go to found_paths.
            # Non-auth 301s are uncertain and go to redirect_paths.
            _is_auth_301 = False
            if status == 301:
                _auth_keywords_fix3 = [
                    "login", "signin", "sign-in", "auth", "sso",
                    "admin", "wp-admin", "dashboard", "portal",
                    "oauth", "callback", "verify", "confirm",
                    "register", "signup", "sign-up", "reset", "forgot",
                ]
                _redirect_loc = result.get("redirect_location", "")
                _is_auth_301 = any(
                    kw in (_redirect_loc or "").lower()
                    for kw in _auth_keywords_fix3
                )
                # Also check if the path itself is a well-known auth path
                _path_lower = path.lower()
                _auth_path_patterns = [
                    "/login", "/signin", "/sign-in", "/auth",
                    "/admin", "/wp-admin", "/wp-login", "/oauth",
                    "/sso", "/dashboard", "/portal",
                ]
                _is_auth_301 = _is_auth_301 or any(
                    p in _path_lower for p in _auth_path_patterns
                )

            # FIX-3: Non-auth 301 redirects go to redirect_paths (uncertain),
            # not found_paths. 302s (auth redirects) stay in found_paths.
            if status == 301 and not _is_auth_301:
                redirect_paths.append(result)
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

        # Print non-interesting found paths with [+] prefix
        for result in found_paths:
            status = result.get("status_code", 0)
            path = result.get("path", "")
            if result not in interesting:
                color = C.G if status == 200 else C.DM
                print(
                    f"  {color}    [+] {path} → HTTP {status}{C.RS}"
                )

        # FIX-3: Statistical catch-all 301 detection
        # If >70% of redirect_paths go to the same destination URL,
        # they're likely catch-all redirects (not real endpoints).
        if redirect_paths:
            dest_counts: Dict[str, int] = {}
            for rp in redirect_paths:
                dest = rp.get("redirect_location", "")
                dest_path = urlparse(dest).path if dest else ""
                # Normalize: strip trailing slash for comparison
                dest_key = dest_path.rstrip("/") or "/"
                dest_counts[dest_key] = dest_counts.get(dest_key, 0) + 1

            if dest_counts:
                most_common_dest = max(dest_counts, key=dest_counts.get)
                most_common_count = dest_counts[most_common_dest]
                if most_common_count / len(redirect_paths) > 0.7:
                    # >70% go to the same destination = catch-all pattern
                    before_count = len(redirect_paths)
                    redirect_paths = [
                        rp for rp in redirect_paths
                        if (
                            urlparse(rp.get("redirect_location", "")).path.rstrip("/") or "/"
                        ) != most_common_dest
                    ]
                    filtered_count = before_count - len(redirect_paths)
                    catchall_301_count += filtered_count
                    if filtered_count > 0:
                        print(
                            f"  {C.Y}    [FILTER] {filtered_count} catch-all 301 redirects → "
                            f"{most_common_dest} (>70% same destination){C.RS}"
                        )
                        # Also remove from interesting if any were added
                        interesting = [
                            i for i in interesting
                            if (
                                urlparse(i.get("redirect_location", "")).path.rstrip("/") or "/"
                            ) != most_common_dest
                            or i.get("status_code", 0) != 301
                        ]

        # FIX-3: Print redirect_paths with ~ prefix (uncertain 301s)
        for rp in redirect_paths:
            rp_path = rp.get("path", "")
            rp_location = rp.get("redirect_location", "")
            print(
                f"  {C.DM}    ~ {rp_path} → HTTP 301 → {rp_location[:50]}{C.RS}"
            )

        return found_paths, status_codes, interesting, redirect_paths, catchall_301_count

    def _print_summary(
        self,
        found_paths: List[Dict],
        status_codes: Dict,
        interesting: List[Dict],
        elapsed: float,
        redirect_paths: List[Dict] = None,
        catchall_301_count: int = 0,
    ):
        """Print formatted summary."""
        redirect_paths = redirect_paths or []

        # FIX-3: Categorize results for clear breakdown
        real_endpoints = sum(1 for p in found_paths if p.get("status_code") == 200)
        auth_redirects = sum(1 for p in found_paths if p.get("status_code") == 302)
        auth_301s = sum(1 for p in found_paths if p.get("status_code") == 301)
        blocked_paths = sum(1 for p in found_paths if p.get("status_code") == 403)
        uncertain_301s = len(redirect_paths)

        print(f"\n  {C.G}  ╔════════════════════════════════════════════════════════╗{C.RS}")
        print(f"  {C.G}  ║  Directory Fuzz Results                               ║{C.RS}")
        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Total Paths Tested:  {C.W}{len(DIR_WORDLIST):<27}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Found Paths:         {C.CY}{len(found_paths):<27}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Interesting Files:   {C.Y}{len(interesting):<27}{C.G}║{C.RS}")
        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")

        # FIX-3: Categorized summary
        print(f"  {C.G}  ║  Category Breakdown:{C.RS}")
        print(f"  {C.G}  ║{C.RS}    {C.G}Real endpoints (200):      {real_endpoints}{C.RS}")
        print(f"  {C.G}  ║{C.RS}    {C.CY}Auth redirects (302):     {auth_redirects}{C.RS}")
        if auth_301s > 0:
            print(f"  {C.G}  ║{C.RS}    {C.CY}Auth redirects (301):     {auth_301s}{C.RS}")
        if catchall_301_count > 0:
            print(f"  {C.G}  ║{C.RS}    {C.DM}Catch-all redirects (301): {catchall_301_count} (filtered){C.RS}")
        if uncertain_301s > 0:
            print(f"  {C.G}  ║{C.RS}    {C.Y}Uncertain redirects (301): {uncertain_301s}{C.RS}")
        print(f"  {C.G}  ║{C.RS}    {C.M}Blocked (403):            {blocked_paths}{C.RS}")
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
        # BUG-FIX v33: Guard against ZeroDivisionError when elapsed is 0
        req_per_s = len(DIR_WORDLIST) / elapsed if elapsed > 0 else 0
        print(f"  {C.G}  ║  Time: {C.CY}{elapsed:.1f}s{C.RS} ({req_per_s:.0f} req/s)")
        print(f"  {C.G}  ╚════════════════════════════════════════════════════════╝{C.RS}")
