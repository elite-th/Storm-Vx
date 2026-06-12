#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  vf_subdomain.py — Subdomain Bruteforcer Module                         ║
║  Part of the STORM_VX Toolkit                                           ║
║                                                                          ║
║  Bruteforces subdomains via DNS resolution with DoH fallback             ║
║  for Iranian networks (Shecan/Electro). Filters CDN IPs to              ║
║  discover potential origin servers.                                      ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import ipaddress
import socket
import json
import time
from typing import Dict, List, Set, Tuple

import aiohttp

from vf_common import C, ssl_param
from utils.session_helpers import fast_scanner_timeout
from config.defaults import NETWORK_PROBE_TIMEOUT, DNS_PROBE_TIMEOUT


# ═══════════════════════════════════════════════════════════════════════════════
# Internal Wordlist — 500+ common subdomain prefixes
# ═══════════════════════════════════════════════════════════════════════════════

SUBDOMAIN_WORDLIST = [
    # Infrastructure
    "mail", "ftp", "admin", "api", "panel", "staging", "dev", "test",
    "db", "mysql", "postgres", "redis", "mongo", "elastic", "kafka",
    "rabbit", "nginx", "apache", "iis", "cpanel", "plesk", "webmail",
    "smtp", "pop", "imap", "vpn", "ssh", "git", "jenkins", "ci", "cd",
    "jira", "confluence", "bitbucket", "grafana", "prometheus", "kibana",
    "logstash", "sonar", "nexus", "docker", "registry", "harbor",
    "vault", "consul", "etcd", "zookeeper", "minio",
    # Environment
    "backup", "old", "new", "beta", "alpha", "pre", "prod", "production",
    "uat", "sit", "demo", "sandbox",
    # Web
    "portal", "app", "web", "www", "m", "mobile", "static", "cdn",
    "media", "img", "images", "assets", "css", "js", "fonts", "files",
    "download", "uploads", "storage", "s3", "docs", "doc", "wiki",
    "help", "support", "forum", "blog", "shop", "store", "pay", "billing",
    # API
    "api", "rest", "graphql", "ws", "wss", "socket", "rpc", "soap",
    "oauth", "auth", "login", "sso", "id", "identity", "account",
    "user", "users", "profile", "dashboard", "administrator", "mod",
    "moderator", "root", "sys", "system",
    # Internal
    "internal", "intranet", "extranet", "office", "corp", "hr",
    "finance", "sales", "marketing", "crm", "erp", "sap", "oracle",
    # DNS / Mail
    "mx", "ns1", "ns2", "dns", "dns1", "dns2", "primary", "secondary",
    "mx1", "mx2", "mail1", "mail2", "relay", "gw", "gateway",
    # Proxy / Load Balancer
    "proxy", "squid", "haproxy", "lb", "loadbalancer", "varnish", "cache",
    "memcached", "es",
    # Database
    "database", "pg", "mssql", "oracle-db", "rabbitmq",
    # DevOps
    "gitlab", "github", "svn", "alertmanager", "nagios", "zabbix",
    "datadog", "newrelic", "sentry", "sonarqube", "artifactory",
    "k8s", "kubernetes", "rancher", "traefik", "istio", "envoy",
    "coredns", "ceph", "gluster", "nas", "san", "bak",
    # Environment variants
    "rc", "stage", "testing", "qa", "live", "poc", "mvp",
    # Versioned APIs
    "v1", "v2", "v3", "api-v1", "api-v2", "rest-api", "grpc",
    "websocket", "socketio", "push", "notify", "notification",
    "email", "sms", "otp", "captcha", "recaptcha", "turnstile",
    # Monitoring
    "monitor", "health", "status", "ping", "trace", "debug", "info",
    "metrics", "stats", "analytics", "tracking", "pixel", "beacon",
    # Ads / Tracking
    "ads", "ad", "advertising", "affiliate", "partner", "referral",
    "callback", "webhook",
    # Task / Queue
    "cron", "job", "task", "queue", "worker", "scheduler", "celery",
    "sidekiq", "bull", "agenda", "temporal",
    # Big Data
    "airflow", "spark", "hadoop", "hive", "presto", "trino", "dbt",
    "superset", "metabase", "redash", "looker", "tableau", "powerbi",
    # Additional common
    "remote", "cloud", "server", "host", "node", "master", "slave",
    "primary1", "primary2", "secondary1", "secondary2", "web1", "web2",
    "app1", "app2", "api1", "api2", "db1", "db2", "db3", "web3",
    "cache1", "cache2", "search", "elasticsearch", "solr",
    "monitoring", "logging", "log", "error", "errors",
    "dev1", "dev2", "dev3", "stg", "stg1", "stg2", "preprod",
    "dr", "disaster", "failover", "hot", "cold", "warm",
    "service", "services", "microservice", "backend", "frontend",
    "client", "desktop", "ios", "android", "native",
    "stream", "streaming", "video", "audio", "live", "broadcast",
    "chat", "messenger", "notification", "pusher", "socket",
    "payment", "payments", "gateway", "gateway2", "checkout",
    "inventory", "warehouse", "logistics", "shipping", "order",
    "orders", "cart", "catalog", "product", "products", "catalogue",
    "report", "reports", "reporting", "export", "import",
    "migration", "migrate", "sync", "synchronize", "etl",
    "oauth2", "openid", "saml", "cas", "ldap", "ad",
    "firewall", "fw", "ips", "ids", "siem", "soc",
    "pen", "pentest", "security", "sec", "audit",
    "stun", "turn", "webrtc", "janus", "mediasoup",
    "cdn1", "cdn2", "edge", "edge1", "edge2", "origin",
    "mirror", "mirrors", "repo", "repository", "repositories",
    "archive", "snapshot", "snapshots", "dump", "dumps",
    "devops", "sre", "ops", "infra", "infrastructure", "platform",
    "eng", "engineering", "tech", "technology", "rd", "research",
    "ml", "ai", "model", "models", "training", "inference",
    "prediction", "predictions", "feature", "features", "flag",
    "flags", "config", "configuration", "setting", "settings",
    "env", "environment", "variable", "variables", "secret", "secrets",
    "key", "keys", "token", "tokens", "credential", "credentials",
    "cert", "certs", "certificate", "certificates", "ssl", "tls",
    "pki", "ca", "rootca", "intermediate",
]


class SubdomainBruteforcer:
    """
    Subdomain bruteforcer with DNS-over-HTTPS support for Iranian networks.

    Resolves subdomains using system DNS and DoH resolvers (Shecan/Electro),
    filters CDN IPs by comparing against main domain resolution, and
    identifies potential origin IPs.
    """

    # Known CDN IP ranges as proper CIDR networks (v4: replaces string-prefix CDN_RANGES)
    CDN_CIDR_RANGES = [
        # ArvanCloud
        ipaddress.ip_network("185.143.232.0/22"),
        ipaddress.ip_network("185.143.234.0/24"),
        ipaddress.ip_network("185.48.176.0/22"),
        ipaddress.ip_network("94.101.184.0/24"),
        ipaddress.ip_network("5.160.128.0/20"),
        # Cloudflare
        ipaddress.ip_network("103.21.244.0/22"),
        ipaddress.ip_network("103.22.200.0/22"),
        ipaddress.ip_network("103.31.4.0/22"),
        ipaddress.ip_network("104.16.0.0/13"),
        ipaddress.ip_network("108.162.192.0/18"),
        ipaddress.ip_network("131.0.72.0/22"),
        ipaddress.ip_network("141.101.64.0/18"),
        ipaddress.ip_network("162.158.0.0/15"),
        ipaddress.ip_network("172.64.0.0/13"),
        ipaddress.ip_network("173.245.48.0/20"),
        ipaddress.ip_network("188.114.96.0/20"),
        ipaddress.ip_network("190.93.240.0/20"),
        ipaddress.ip_network("197.234.240.0/22"),
        ipaddress.ip_network("198.41.128.0/17"),
    ]

    # DoH resolvers for Iranian networks
    DOH_RESOLVERS = [
        "https://dns.shecan.ir/dns-query",
        "https://dns.electro.ir/dns-query",
    ]

    def __init__(self, domain: str, timeout: int = 3, max_concurrent: int = 100, verify_ssl: bool = True):
        """
        Initialize SubdomainBruteforcer.

        Args:
            domain: Target domain (e.g., 'example.com')
            timeout: DNS/HTTP timeout in seconds (default 3, was 5 — system DNS is fast)
            max_concurrent: Maximum concurrent DNS resolutions (default 100, was 50)
            verify_ssl: Whether to verify SSL certificates
        """
        self.domain = domain.strip().lower()
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.verify_ssl = verify_ssl
        self._ssl = ssl_param(self.verify_ssl)
        self.cdn_ips: Set[str] = set()
        self.main_ips: Set[str] = set()
        self._dns_cache: Dict[str, Set[str]] = {}  # FQDN → resolved IPs cache
        self._cdn_ip_cache: Dict[str, bool] = {}  # IP → is_cdn cache (avoids repeated prefix matching)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        # v5: Wildcard DNS detection
        self._wildcard_detected: bool = False
        self._wildcard_ips: Set[str] = set()

    async def run(self) -> Dict:
        """
        Run subdomain bruteforce enumeration.

        Returns:
            Dictionary with:
                - subdomains: List of discovered subdomains
                - ips: Dict mapping subdomain -> list of IPs
                - new_origin_ips: List of non-CDN IPs (potential origins)
        """
        print(f"\n  {C.BD}{C.CY}[*] Subdomain Bruteforcer — {self.domain}{C.RS}")
        print(f"  {C.DM}    Timeout: {self.timeout}s | Concurrency: {self.max_concurrent}{C.RS}")

        t0 = time.monotonic()

        # Step 1: Resolve main domain to get CDN IPs
        print(f"  {C.B}  [1/4] Resolving main domain for CDN baseline...{C.RS}")
        await self._resolve_main_domain()

        # Step 2: Resolve subdomains using system DNS
        print(f"  {C.B}  [2/4] Bruteforcing subdomains (system DNS)...{C.RS}")
        system_results = await self._bruteforce_system_dns()

        # Step 3: Resolve via DoH for Iranian networks
        print(f"  {C.B}  [3/4] Resolving via DoH (Shecan/Electro)...{C.RS}")
        doh_results = await self._bruteforce_doh()

        # Step 4: Merge results and filter CDN IPs
        print(f"  {C.B}  [4/4] Filtering CDN IPs and identifying origins...{C.RS}")
        merged = self._merge_results(system_results, doh_results)
        subdomains, ips, origin_ips = self._filter_cdn_ips(merged)

        elapsed = time.monotonic() - t0

        # Print summary
        print(f"\n  {C.G}  ╔══════════════════════════════════════════════════╗{C.RS}")
        print(f"  {C.G}  ║  Subdomain Bruteforce Results                   ║{C.RS}")
        print(f"  {C.G}  ╠══════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Total subdomains found: {C.W}{len(subdomains):<23}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Potential origin IPs:   {C.Y}{len(origin_ips):<23}{C.G}║{C.RS}")
        print(f"  {C.G}  ║  Time elapsed:           {C.CY}{elapsed:.1f}s{' ' * (20 - len(f'{elapsed:.1f}s'))}{C.G}║{C.RS}")
        print(f"  {C.G}  ╚══════════════════════════════════════════════════╝{C.RS}")

        if origin_ips:
            print(f"\n  {C.Y}  [!] Non-CDN (Origin) IPs:{C.RS}")
            for ip in sorted(origin_ips):
                print(f"  {C.R}    → {ip}{C.RS}")

        return {
            "subdomains": sorted(subdomains),
            "ips": {k: sorted(v) for k, v in ips.items()},
            "new_origin_ips": sorted(origin_ips),
        }

    async def _resolve_main_domain(self):
        """Resolve the main domain to establish CDN IP baseline.

        v2: Added 5s timeout to prevent indefinite hanging.
        v5: Added wildcard DNS detection before bruteforcing.
        """
        try:
            loop = asyncio.get_running_loop()
            results = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(self.domain, None, socket.AF_INET)
                ),
                timeout=NETWORK_PROBE_TIMEOUT  # W2.4
            )
            for r in results:
                ip = r[4][0]
                self.main_ips.add(ip)
                if self._is_cdn_ip(ip):
                    self.cdn_ips.add(ip)

            print(f"  {C.G}    Main domain IPs: {', '.join(sorted(self.main_ips))}{C.RS}")
            print(f"  {C.G}    CDN IPs identified: {len(self.cdn_ips)}{C.RS}")
        except asyncio.TimeoutError:
            print(f"  {C.Y}    Main domain DNS resolution timed out (5s){C.RS}")
        except (socket.gaierror, OSError) as e:
            print(f"  {C.Y}    Could not resolve main domain: {e}{C.RS}")

        # v5: Wildcard DNS detection — probe a statistically improbable subdomain
        await self._detect_wildcard_dns(loop)

    async def _detect_wildcard_dns(self, loop=None):
        """Detect wildcard DNS by resolving a random improbable subdomain.

        If a random subdomain like 'wildcard-test-a7f3b2.example.com' resolves,
        the domain has a wildcard DNS record. All subdomains resolving to the
        same IP set are likely false positives and should be filtered.
        """
        import random
        import string
        random_tag = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        wildcard_fqdn = f"wildcard-test-{random_tag}.{self.domain}"

        if loop is None:
            loop = asyncio.get_running_loop()

        try:
            results = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(wildcard_fqdn, None, socket.AF_INET)
                ),
                timeout=NETWORK_PROBE_TIMEOUT  # W2.4
            )
            ips = set()
            for r in results:
                ips.add(r[4][0])
            if ips:
                self._wildcard_detected = True
                self._wildcard_ips = ips
                print(f"  {C.Y}    ⚠ Wildcard DNS detected: *.{self.domain} → {', '.join(sorted(ips))}{C.RS}")
                print(f"  {C.DM}    Subdomains resolving to wildcard IPs will be flagged{C.RS}")
            else:
                print(f"  {C.G}    No wildcard DNS detected{C.RS}")
        except (asyncio.TimeoutError, socket.gaierror, OSError):
            # Random subdomain doesn't resolve → no wildcard
            print(f"  {C.G}    No wildcard DNS detected{C.RS}")

    async def _bruteforce_system_dns(self) -> Dict[str, Set[str]]:
        """Bruteforce subdomains using system DNS resolver.

        v2: Added per-query timeout (was unbounded — could hang forever)
        v3: Limited to top-150 prefixes (BUG-3 fix — was bruteforcing all 500+)
        v3: Reduced per-query timeout to 3s (was 5s — system DNS should be fast)
        """
        results: Dict[str, Set[str]] = {}
        found_count = 0
        prefixes = SUBDOMAIN_WORDLIST[:150]  # v3: BUG-3 fix — limit to top-150

        async def resolve_one(subdomain: str):
            nonlocal found_count
            fqdn = f"{subdomain}.{self.domain}"
            # v3: Check cache — skip if already resolved
            if fqdn in self._dns_cache:
                cached = self._dns_cache[fqdn]
                if cached:
                    results[fqdn] = set(cached)
                    found_count += 1
                return
            async with self._semaphore:
                try:
                    loop = asyncio.get_running_loop()
                    # v3: 3s timeout per query — system DNS should be fast
                    addr_results = await asyncio.wait_for(
                        loop.run_in_executor(
                            None,
                            lambda: socket.getaddrinfo(fqdn, None, socket.AF_INET)
                        ),
                        timeout=DNS_PROBE_TIMEOUT  # W2.4
                    )
                    ips = set()
                    for r in addr_results:
                        ips.add(r[4][0])
                    if ips:
                        # v5: Filter wildcard DNS false positives
                        if self._wildcard_detected and ips == self._wildcard_ips:
                            # Same IPs as wildcard → likely false positive
                            self._dns_cache[fqdn] = set(ips)
                            cdn_tag = f" {C.DM}[WILDCARD]{C.RS}"
                            print(f"  {C.DM}    [~]{C.RS} {C.DM}{fqdn:<40}{C.RS} → {', '.join(sorted(ips))}{cdn_tag} (wildcard)")
                            return  # v6: BUG FIX — was 'continue' which is invalid outside a loop (inside async def)
                        results[fqdn] = ips
                        self._dns_cache[fqdn] = set(ips)  # v3: Cache resolved IPs
                        found_count += 1
                        ip_str = ', '.join(sorted(ips))
                        cdn_tag = f" {C.DM}[CDN]{C.RS}" if ips & self.cdn_ips else f" {C.Y}[ORIGIN]{C.RS}"
                        print(f"  {C.G}    [+]{C.RS} {C.W}{fqdn:<40}{C.RS} → {ip_str}{cdn_tag}")
                except asyncio.TimeoutError:
                    pass  # v2: Silent — don't spam for each timeout
                except (socket.gaierror, socket.timeout, OSError):
                    pass
                except (RuntimeError, ValueError, AttributeError):  # Intentional: unknown DNS error types during bruteforce
                    pass

        tasks = [resolve_one(prefix) for prefix in prefixes]
        await asyncio.gather(*tasks)

        print(f"  {C.G}    System DNS: {found_count} subdomains found (top-{len(prefixes)} prefixes){C.RS}")
        return results

    async def _bruteforce_doh(self) -> Dict[str, Set[str]]:
        """Bruteforce subdomains using DNS-over-HTTPS resolvers.

        v2 OPTIMIZED:
        - Single shared aiohttp session (was creating 400+ sessions!)
        - 3s connect timeout + 5s total (was 15s!)
        - Both resolvers run in parallel (was sequential)
        - Batch size 25 with 0.1s delay (was 10 with 0.3s)
        v3 OPTIMIZED:
        - Increased prefix limit to 150 (was 100) — broader coverage
        - Skip prefixes already resolved by system DNS (cache-aware)
        - Both resolvers still get all prefixes for maximum coverage
        """
        results: Dict[str, Set[str]] = {}
        found_count = 0
        # v2: Aggressive timeouts — DoH should be fast, not 15 seconds
        timeout = fast_scanner_timeout()

        all_prefixes = SUBDOMAIN_WORDLIST[:150]  # v3: Increased from 100 to 150
        # v3: Filter out prefixes already resolved by system DNS (cache-aware)
        prefixes_to_try = [p for p in all_prefixes if f"{p}.{self.domain}" not in self._dns_cache]
        skipped = len(all_prefixes) - len(prefixes_to_try)
        if skipped:
            print(f"  {C.DM}    Skipping {skipped} prefixes already resolved by system DNS{C.RS}")

        async def resolve_doh(session: aiohttp.ClientSession, subdomain: str, resolver_url: str) -> Set[str]:
            """Resolve a subdomain via DoH using a SHARED session."""
            fqdn = f"{subdomain}.{self.domain}"
            ips = set()
            try:
                params = {"name": fqdn, "type": "A"}
                headers = {"Accept": "application/dns-json"}
                async with session.get(
                    resolver_url, params=params, headers=headers, ssl=self._ssl
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for answer in data.get("Answer", []):
                            if answer.get("type") == 1:  # A record
                                ips.add(answer.get("data", ""))
            except asyncio.TimeoutError:
                pass  # v2: Silent timeout — no need to spam
            except (aiohttp.ClientError, ValueError):
                pass
            return ips

        # v2: Create ONE shared session for ALL DoH queries (was one per query!)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # v2: Run BOTH resolvers in parallel instead of sequentially
            async def _process_resolver(resolver_url: str) -> Dict[str, Set[str]]:
                resolver_results: Dict[str, Set[str]] = {}
                resolver_name = "Shecan" if "shecan" in resolver_url else "Electro"
                print(f"  {C.DM}    Querying {resolver_name} DoH...{C.RS}")

                # v2: Larger batches, shorter delays
                batch_size = 25
                for i in range(0, len(prefixes_to_try), batch_size):
                    batch = prefixes_to_try[i:i + batch_size]
                    tasks = [resolve_doh(session, prefix, resolver_url) for prefix in batch]
                    responses = await asyncio.gather(*tasks, return_exceptions=True)

                    for prefix, resp_ips in zip(batch, responses):
                        if isinstance(resp_ips, Exception) or not resp_ips:
                            continue
                        fqdn = f"{prefix}.{self.domain}"
                        # v5: Filter wildcard DNS false positives in DoH results
                        if self._wildcard_detected and resp_ips == self._wildcard_ips:
                            self._dns_cache[fqdn] = set(resp_ips)
                            continue
                        if fqdn not in resolver_results:
                            resolver_results[fqdn] = resp_ips
                        else:
                            resolver_results[fqdn].update(resp_ips)

                    # v2: Shorter delay between batches
                    await asyncio.sleep(0.1)

                return resolver_results

            # Run both resolvers simultaneously
            shecan_url = self.DOH_RESOLVERS[0] if len(self.DOH_RESOLVERS) > 0 else None
            electro_url = self.DOH_RESOLVERS[1] if len(self.DOH_RESOLVERS) > 1 else None

            resolver_tasks = []
            if shecan_url:
                resolver_tasks.append(_process_resolver(shecan_url))
            if electro_url:
                resolver_tasks.append(_process_resolver(electro_url))

            all_resolver_results = await asyncio.gather(*resolver_tasks, return_exceptions=True)

        # Merge results from all resolvers
        for resolver_result in all_resolver_results:
            if isinstance(resolver_result, Exception):
                continue
            for fqdn, ips in resolver_result.items():
                # v3: Cache DoH results for future lookups
                if fqdn not in self._dns_cache:
                    self._dns_cache[fqdn] = set(ips)
                else:
                    self._dns_cache[fqdn].update(ips)
                if fqdn not in results:
                    results[fqdn] = ips
                    found_count += 1
                    ip_str = ', '.join(sorted(ips))
                    cdn_tag = f" {C.DM}[CDN]{C.RS}" if ips & self.cdn_ips else f" {C.Y}[ORIGIN]{C.RS}"
                    resolver_name = "DoH"
                    print(f"  {C.G}    [+]{C.RS} {C.W}{fqdn:<40}{C.RS} → {ip_str} {C.M}({resolver_name}){C.RS}{cdn_tag}")
                else:
                    # Merge IPs from another resolver
                    results[fqdn].update(ips)

        print(f"  {C.G}    DoH: {found_count} new subdomains found{C.RS}")
        return results

    def _merge_results(
        self,
        system: Dict[str, Set[str]],
        doh: Dict[str, Set[str]]
    ) -> Dict[str, Set[str]]:
        """Merge results from system DNS and DoH."""
        merged = {}
        for fqdn, ips in system.items():
            merged[fqdn] = set(ips)
        for fqdn, ips in doh.items():
            if fqdn in merged:
                merged[fqdn].update(ips)
            else:
                merged[fqdn] = set(ips)
        return merged

    def _filter_cdn_ips(
        self, merged: Dict[str, Set[str]]
    ) -> Tuple[List[str], Dict[str, List[str]], List[str]]:
        """
        Filter CDN IPs from results to identify origin IPs.

        v5: Also filters wildcard DNS false positives.

        Returns:
            Tuple of (subdomains, ips_dict, origin_ips)
        """
        # v5: Remove wildcard false positives
        if self._wildcard_detected:
            merged = {fqdn: ips for fqdn, ips in merged.items()
                      if ips != self._wildcard_ips}

        subdomains = sorted(merged.keys())
        ips_dict = {k: sorted(v) for k, v in merged.items()}

        origin_ips: Set[str] = set()
        for fqdn, ips in merged.items():
            for ip in ips:
                # v5: main_ips are filtered as "known" but NOT classified as CDN
                if not self._is_cdn_ip(ip) and ip not in self.main_ips:
                    origin_ips.add(ip)

        return subdomains, ips_dict, sorted(origin_ips)

    def _is_cdn_ip(self, ip: str) -> bool:
        """Check if an IP belongs to a known CDN range.

        v4: Uses ipaddress module for correct CIDR matching instead of
        error-prone string prefix matching (e.g. "104.16." matched "104.160.x.x").
        v5: Removed main_ips membership check — the main domain IP is NOT
        necessarily a CDN IP. Only known CDN CIDR ranges are CDN IPs.
        Main domain IPs are filtered separately in _filter_cdn_ips().
        """
        # Check cache first
        if ip in self._cdn_ip_cache:
            return self._cdn_ip_cache[ip]

        result = False
        try:
            addr = ipaddress.ip_address(ip)
            for cdn_range in self.CDN_CIDR_RANGES:
                if addr in cdn_range:
                    result = True
                    break
        except ValueError:
            pass

        # v5: Do NOT treat main_ips as CDN — the main domain IP is likely the origin
        self._cdn_ip_cache[ip] = result
        return result
