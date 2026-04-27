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
import socket
import json
import time
from typing import Dict, List, Set, Tuple, Optional

import aiohttp


# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


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

    # Known CDN IP ranges (common ArvanCloud, Cloudflare, etc.)
    CDN_RANGES = [
        # ArvanCloud
        "185.143.234.", "185.143.235.", "185.55.224.", "185.55.225.",
        "185.55.226.", "185.55.227.", "94.101.184.", "5.160.128.",
        "5.160.129.", "5.160.130.", "5.160.131.",
        # Cloudflare
        "103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.",
        "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
        "104.24.", "104.25.", "104.26.", "104.27.", "108.162.192.",
        "131.0.72.", "141.101.64.", "162.158.", "172.64.", "172.65.",
        "172.66.", "172.67.", "173.245.48.", "188.114.96.", "188.114.97.",
        "188.114.98.", "188.114.99.", "190.93.240.", "197.234.240.",
        "198.41.128.",
    ]

    # DoH resolvers for Iranian networks
    DOH_RESOLVERS = [
        "https://dns.shecan.ir/dns-query",
        "https://dns.electro.ir/dns-query",
    ]

    def __init__(self, domain: str, timeout: int = 15, max_concurrent: int = 50):
        """
        Initialize SubdomainBruteforcer.

        Args:
            domain: Target domain (e.g., 'example.com')
            timeout: DNS/HTTP timeout in seconds
            max_concurrent: Maximum concurrent DNS resolutions
        """
        self.domain = domain.strip().lower()
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.cdn_ips: Set[str] = set()
        self.main_ips: Set[str] = set()
        self._semaphore = asyncio.Semaphore(max_concurrent)

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

        t0 = time.time()

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

        elapsed = time.time() - t0

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
        """Resolve the main domain to establish CDN IP baseline."""
        try:
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(self.domain, None, socket.AF_INET)
            )
            for r in results:
                ip = r[4][0]
                self.main_ips.add(ip)
                if self._is_cdn_ip(ip):
                    self.cdn_ips.add(ip)

            print(f"  {C.G}    Main domain IPs: {', '.join(sorted(self.main_ips))}{C.RS}")
            print(f"  {C.G}    CDN IPs identified: {len(self.cdn_ips)}{C.RS}")
        except Exception as e:
            print(f"  {C.Y}    Could not resolve main domain: {e}{C.RS}")

    async def _bruteforce_system_dns(self) -> Dict[str, Set[str]]:
        """Bruteforce subdomains using system DNS resolver."""
        results: Dict[str, Set[str]] = {}
        found_count = 0

        async def resolve_one(subdomain: str):
            nonlocal found_count
            fqdn = f"{subdomain}.{self.domain}"
            async with self._semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    addr_results = await loop.run_in_executor(
                        None,
                        lambda: socket.getaddrinfo(fqdn, None, socket.AF_INET)
                    )
                    ips = set()
                    for r in addr_results:
                        ips.add(r[4][0])
                    if ips:
                        results[fqdn] = ips
                        found_count += 1
                        ip_str = ', '.join(sorted(ips))
                        cdn_tag = f" {C.DM}[CDN]{C.RS}" if ips & self.cdn_ips else f" {C.Y}[ORIGIN]{C.RS}"
                        print(f"  {C.G}    [+]{C.RS} {C.W}{fqdn:<40}{C.RS} → {ip_str}{cdn_tag}")
                except (socket.gaierror, socket.timeout, OSError):
                    pass
                except Exception:
                    pass

        tasks = [resolve_one(prefix) for prefix in SUBDOMAIN_WORDLIST]
        await asyncio.gather(*tasks)

        print(f"  {C.G}    System DNS: {found_count} subdomains found{C.RS}")
        return results

    async def _bruteforce_doh(self) -> Dict[str, Set[str]]:
        """Bruteforce subdomains using DNS-over-HTTPS resolvers."""
        results: Dict[str, Set[str]] = {}
        found_count = 0
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async def resolve_doh(subdomain: str, resolver_url: str) -> Set[str]:
            """Resolve a subdomain via DoH."""
            fqdn = f"{subdomain}.{self.domain}"
            ips = set()
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    params = {
                        "name": fqdn,
                        "type": "A",
                    }
                    headers = {"Accept": "application/dns-json"}
                    async with session.get(
                        resolver_url, params=params, headers=headers, ssl=False
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            for answer in data.get("Answer", []):
                                if answer.get("type") == 1:  # A record
                                    ips.add(answer.get("data", ""))
            except Exception:
                pass
            return ips

        # Only try subdomains that weren't found by system DNS + a subset
        # to avoid too many requests
        existing = set(results.keys())
        prefixes_to_try = SUBDOMAIN_WORDLIST[:200]  # Limit DoH queries

        for resolver_url in self.DOH_RESOLVERS:
            resolver_name = "Shecan" if "shecan" in resolver_url else "Electro"
            print(f"  {C.DM}    Querying {resolver_name} DoH...{C.RS}")

            # Batch in groups of 10 to avoid overwhelming DoH
            batch_size = 10
            for i in range(0, len(prefixes_to_try), batch_size):
                batch = prefixes_to_try[i:i + batch_size]
                tasks = [resolve_doh(prefix, resolver_url) for prefix in batch]
                responses = await asyncio.gather(*tasks)

                for prefix, ips in zip(batch, responses):
                    fqdn = f"{prefix}.{self.domain}"
                    if ips and fqdn not in existing:
                        results[fqdn] = ips
                        existing.add(fqdn)
                        found_count += 1
                        ip_str = ', '.join(sorted(ips))
                        cdn_tag = f" {C.DM}[CDN]{C.RS}" if ips & self.cdn_ips else f" {C.Y}[ORIGIN]{C.RS}"
                        print(f"  {C.G}    [+]{C.RS} {C.W}{fqdn:<40}{C.RS} → {ip_str} {C.M}(DoH-{resolver_name}){C.RS}{cdn_tag}")
                    elif ips and fqdn in existing:
                        # Merge IPs from DoH
                        if fqdn in results:
                            results[fqdn].update(ips)

                # Small delay between batches for DoH
                await asyncio.sleep(0.3)

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

        Returns:
            Tuple of (subdomains, ips_dict, origin_ips)
        """
        subdomains = sorted(merged.keys())
        ips_dict = {k: sorted(v) for k, v in merged.items()}

        origin_ips: Set[str] = set()
        for fqdn, ips in merged.items():
            for ip in ips:
                if not self._is_cdn_ip(ip) and ip not in self.main_ips:
                    origin_ips.add(ip)

        return subdomains, ips_dict, sorted(origin_ips)

    def _is_cdn_ip(self, ip: str) -> bool:
        """Check if an IP belongs to a known CDN range."""
        for cdn_range in self.CDN_RANGES:
            if ip.startswith(cdn_range):
                return True
        # Also check against main domain IPs (likely CDN)
        if ip in self.main_ips:
            return True
        return False
