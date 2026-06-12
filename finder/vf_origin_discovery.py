"""Origin IP discovery methods — extracted from dns_scanner.py.

Each discovery method is a standalone module-level async function that
takes an ``OriginIPContext`` (shared state) and optionally an
``aiohttp.ClientSession``.  The orchestrator in ``dns_scanner.py``
creates the context and session, then runs all methods in parallel.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

import aiohttp

from vf_common import C
from utils.response_helpers import safe_read_text
from utils.ssl_helpers import create_ssl_context
from utils.session_helpers import scanner_timeout
from config.defaults import (
    FAST_PROBE_TIMEOUT, FAST_PROBE_CONNECT, FAST_PROBE_SOCK_READ,
    ORIGIN_PROBE_TIMEOUT, ORIGIN_QUICK_PROBE_TIMEOUT,
    ORIGIN_QUICK_NETWORK_TIMEOUT, NETWORK_PROBE_TIMEOUT, DNS_PROBE_TIMEOUT,
)
from finder.signatures import CDN_KEYWORDS


# ═══════════════════════════════════════════════════════════════════════
# Bounded concurrency — imported from shared utility (W2.7-2 dedup)
# ═══════════════════════════════════════════════════════════════════════
# W2.6 FIX: All asyncio.gather() calls in this module now go through
# bounded_gather() which enforces a semaphore cap, preventing hundreds
# of concurrent DNS/HTTP tasks from exhausting connection pools or
# triggering DNS throttling.  The default concurrency of 20 matches the
# pattern used in other finder modules (vf_waf_probe, vf_subdomain, etc.)

from utils.async_helpers import bounded_gather

# Optional dns.resolver import
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# ═══════════════════════════════════════════════════════════════════════
# CDN IP ranges — https://www.cloudflare.com/ips-v4/
# ═══════════════════════════════════════════════════════════════════════
CDN_IPV4_RANGES: dict[str, list[ipaddress.IPv4Network]] = {
    "cloudflare": [
        ipaddress.ip_network("173.245.48.0/20"),
        ipaddress.ip_network("103.21.244.0/22"),
        ipaddress.ip_network("103.22.200.0/22"),
        ipaddress.ip_network("103.31.4.0/22"),
        ipaddress.ip_network("141.101.64.0/18"),
        ipaddress.ip_network("108.162.192.0/18"),
        ipaddress.ip_network("190.93.240.0/20"),
        ipaddress.ip_network("188.114.96.0/20"),
        ipaddress.ip_network("197.234.240.0/22"),
        ipaddress.ip_network("198.41.128.0/17"),
        ipaddress.ip_network("162.158.0.0/15"),
        ipaddress.ip_network("104.16.0.0/13"),
        ipaddress.ip_network("104.24.0.0/14"),
        ipaddress.ip_network("172.64.0.0/13"),
        ipaddress.ip_network("131.0.72.0/22"),
    ],
    "arvancloud": [
        ipaddress.ip_network("185.143.232.0/22"),
        ipaddress.ip_network("185.143.234.0/24"),
        ipaddress.ip_network("185.48.176.0/22"),
    ],
}


# ═══════════════════════════════════════════════════════════════════════
# Shared state dataclass
# ═══════════════════════════════════════════════════════════════════════
@dataclass
class OriginIPContext:
    """Shared state for all origin-IP discovery methods."""
    domain: str
    cdn_ips: set[str]
    found_ips: set[str] = field(default_factory=set)
    all_subdomains: set[str] = field(default_factory=set)
    sources: Dict[str, List[str]] = field(default_factory=dict)
    verify_ssl: bool = True
    _ssl: Any = None
    skip_slow: bool = False


# ═══════════════════════════════════════════════════════════════════════
# Helper functions (module-level, pure / testable)
# ═══════════════════════════════════════════════════════════════════════
def is_cdn_ip(ip: str, cdn_ips: set[str]) -> bool:
    """Check whether *ip* belongs to a known CDN range or matches a
    CDN-resolved IP address.

    v24: Correct ipaddress-based CDN check replacing broken hex ranges.
    """
    try:
        addr = ipaddress.ip_address(ip)
        for cdn_name, networks in CDN_IPV4_RANGES.items():
            for network in networks:
                if addr in network:
                    return True
        if ip in cdn_ips:
            return True
    except ValueError:
        pass
    return False


async def is_cdn_ip_async(ip: str, cdn_ips: set[str]) -> bool:
    """v15: Async CDN check with reverse DNS — non-blocking with 2s timeout."""
    if is_cdn_ip(ip, cdn_ips):
        return True
    loop = asyncio.get_running_loop()
    try:
        hostname, _, _ = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)),
            timeout=ORIGIN_QUICK_NETWORK_TIMEOUT,  # W2.4
        )
        hostname_lower = hostname.lower()
        return any(ck in hostname_lower for ck in CDN_KEYWORDS)
    except (OSError, socket.herror, socket.timeout, RuntimeError):
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


async def resolve_subdomains(subdomains: set[str], cdn_ips: set[str]) -> set[str]:
    """Resolve subdomains to IPs — v12: parallel with 3s timeout."""
    resolved: set[str] = set()
    loop = asyncio.get_running_loop()

    async def _resolve_one(sub: str):
        try:
            ip = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, sub),
                timeout=DNS_PROBE_TIMEOUT,  # W2.4
            )
            if ip and not is_private_ip(ip) and not is_cdn_ip(ip, cdn_ips) and ip not in cdn_ips:
                resolved.add(ip)
                return sub, ip
        except (socket.gaierror, OSError, asyncio.TimeoutError):
            pass
        return sub, None

    results = await bounded_gather(*[_resolve_one(sub) for sub in subdomains])
    for sub, ip in results:
        if ip:
            print(f"  {C.G}    {sub} -> {ip} (non-CDN){C.RS}")
    return resolved


# ═══════════════════════════════════════════════════════════════════════
# 9 Discovery Methods
# ═══════════════════════════════════════════════════════════════════════

async def discover_crtsh(ctx: OriginIPContext, session: aiohttp.ClientSession) -> set[str]:
    """Method 1: crt.sh (Certificate Transparency)."""
    if ctx.skip_slow:
        return set()
    print(f"  {C.CY}  [1] crt.sh Certificate Transparency...{C.RS}")
    try:
        crtsh_url = f"https://crt.sh/?q=%.{ctx.domain}&output=json"
        async with session.get(crtsh_url, ssl=ctx._ssl) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                crtsh_subdomains: set[str] = set()
                crtsh_ips: set[str] = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for line in name_value.split('\n'):
                        line = line.strip()
                        if not line:
                            continue
                        ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            if not is_private_ip(ip) and ip not in ctx.cdn_ips:
                                crtsh_ips.add(ip)
                        else:
                            clean = line[2:] if line.startswith('*.') else line
                            if clean and ctx.domain in clean:
                                crtsh_subdomains.add(clean)

                if crtsh_subdomains:
                    resolved = await resolve_subdomains(crtsh_subdomains, ctx.cdn_ips)
                    ctx.all_subdomains.update(crtsh_subdomains)
                    crtsh_ips.update(resolved)

                non_cdn = {ip for ip in crtsh_ips if not is_cdn_ip(ip, ctx.cdn_ips)}
                if non_cdn:
                    print(f"  {C.G}    crt.sh: {len(non_cdn)} non-CDN IPs{C.RS}")
                    return non_cdn
                print(f"  {C.DM}    crt.sh: No non-CDN IPs{C.RS}")
            else:
                print(f"  {C.DM}    crt.sh: HTTP {resp.status}{C.RS}")
    except asyncio.TimeoutError:
        print(f"  {C.Y}    crt.sh: Timeout (5s){C.RS}")
    except (aiohttp.ClientError, ValueError) as e:
        print(f"  {C.Y}    crt.sh: {type(e).__name__}{C.RS}")
    return set()


async def discover_doh(ctx: OriginIPContext, session: aiohttp.ClientSession) -> set[str]:
    """Method 2: DNS-over-HTTPS (Iran-friendly only)."""
    print(f"  {C.CY}  [2] DNS-over-HTTPS (Iranian resolvers)...{C.RS}")
    doh_servers = [
        ("https://dns.shecan.ir/dns-query", "Shecan"),
        ("https://dns.electro.ir/dns-query", "Electro"),
        ("https://dns.radar.oracle.com/dns-query", "Radar"),
        ("https://dns.google/resolve", "Google"),
        ("https://cloudflare-dns.com/dns-query", "Cloudflare"),
    ]
    doh_ips: set[str] = set()
    headers = {"Accept": "application/dns-json"}

    async def _query_doh(doh_url: str, doh_name: str, _ssl: Any) -> set[str]:
        try:
            params = {"name": ctx.domain, "type": "A"}
            query_timeout = scanner_timeout(total=FAST_PROBE_TIMEOUT, connect=FAST_PROBE_CONNECT, sock_read=FAST_PROBE_SOCK_READ)  # W2.4
            async with session.get(doh_url, params=params, headers=headers,
                                   ssl=_ssl, timeout=query_timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ips: set[str] = set()
                    for answer in data.get('Answer', []):
                        ip = answer.get('data', '')
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                            if not is_private_ip(ip) and ip not in ctx.cdn_ips and not is_cdn_ip(ip, ctx.cdn_ips):
                                ips.add(ip)
                    if ips:
                        print(f"  {C.G}    {doh_name}: {len(ips)} IPs{C.RS}")
                    else:
                        print(f"  {C.DM}    {doh_name}: CDN only{C.RS}")
                    return ips
                else:
                    print(f"  {C.DM}    {doh_name}: status {resp.status}{C.RS}")
        except asyncio.TimeoutError:
            print(f"  {C.DM}    {doh_name}: timeout{C.RS}")
        except (aiohttp.ClientError, ValueError) as e:
            print(f"  {C.DM}    {doh_name}: {type(e).__name__}{C.RS}")
        return set()

    results = await asyncio.gather(*[_query_doh(url, name, ctx._ssl) for url, name in doh_servers])
    for ips in results:
        doh_ips.update(ips)
    return doh_ips


async def discover_subdomain(ctx: OriginIPContext) -> set[str]:
    """Method 3: Subdomain brute-force (mail, ftp, etc.)."""
    print(f"  {C.CY}  [3] Subdomain brute-force (mail, ftp, etc.)...{C.RS}")
    subdomain_candidates = [
        f'mail.{ctx.domain}', f'ftp.{ctx.domain}', f'imap.{ctx.domain}',
        f'smtp.{ctx.domain}', f'pop.{ctx.domain}', f'direct.{ctx.domain}',
        f'origin.{ctx.domain}', f'server.{ctx.domain}', f'webmail.{ctx.domain}',
        f'cpanel.{ctx.domain}', f'ns1.{ctx.domain}', f'ns2.{ctx.domain}',
        f'admin.{ctx.domain}', f'portal.{ctx.domain}', f'api.{ctx.domain}',
        f'dev.{ctx.domain}', f'staging.{ctx.domain}', f'test.{ctx.domain}',
        f'backup.{ctx.domain}', f'db.{ctx.domain}', f'mysql.{ctx.domain}',
        f'panel.{ctx.domain}', f'old.{ctx.domain}', f'new.{ctx.domain}',
        f'remote.{ctx.domain}', f'vpn.{ctx.domain}', f'ssh.{ctx.domain}',
        f'cdn-origin.{ctx.domain}', f'backend.{ctx.domain}', f'app.{ctx.domain}',
    ]
    sub_ips: set[str] = set()
    loop = asyncio.get_running_loop()

    async def _check_sub(sub: str):
        try:
            ip = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, sub),
                timeout=DNS_PROBE_TIMEOUT)  # W2.4
            if ip and not is_private_ip(ip) and ip not in ctx.cdn_ips and not is_cdn_ip(ip, ctx.cdn_ips):
                return sub, ip
        except (socket.gaierror, OSError, asyncio.TimeoutError):
            pass
        return sub, None

    results = await bounded_gather(*[_check_sub(sub) for sub in subdomain_candidates])
    for sub, ip in results:
        if ip:
            sub_ips.add(ip)
            ctx.all_subdomains.add(sub)
            print(f"  {C.G}    {sub} -> {ip} (non-CDN){C.RS}")

    if sub_ips:
        print(f"  {C.G}    Found {len(sub_ips)} non-CDN IPs from subdomains{C.RS}")
    else:
        print(f"  {C.DM}    All subdomains resolve to CDN or NXDOMAIN{C.RS}")
    return sub_ips


async def discover_mx_txt(ctx: OriginIPContext) -> set[str]:
    """Method 4: MX/TXT/NS Record Analysis."""
    print(f"  {C.CY}  [4] MX/TXT/NS Record Analysis...{C.RS}")
    mx_ips: set[str] = set()
    loop = asyncio.get_running_loop()

    mx_subs = [f'mail.{ctx.domain}', f'smtp.{ctx.domain}', f'pop.{ctx.domain}',
               f'imap.{ctx.domain}', f'webmail.{ctx.domain}']
    ns_subs = [f'ns1.{ctx.domain}', f'ns2.{ctx.domain}']
    all_check = mx_subs + ns_subs

    async def _check(sub: str):
        try:
            ip = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, sub),
                timeout=DNS_PROBE_TIMEOUT)  # W2.4
            if ip and not is_private_ip(ip) and ip not in ctx.cdn_ips and not is_cdn_ip(ip, ctx.cdn_ips):
                return sub, ip
        except (socket.gaierror, OSError, asyncio.TimeoutError):
            pass
        return sub, None

    results = await bounded_gather(*[_check(s) for s in all_check])
    for sub, ip in results:
        if ip:
            mx_ips.add(ip)
            print(f"  {C.G}    {sub} -> {ip}{C.RS}")

    if HAS_DNS:
        try:
            txt_answers = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: dns.resolver.resolve(ctx.domain, 'TXT')),
                timeout=DNS_PROBE_TIMEOUT)  # W2.4
            for rdata in txt_answers:
                txt_str = str(rdata)
                if 'v=spf1' in txt_str.lower():
                    for part in txt_str.split():
                        ip_match = re.match(r'ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d+)?)', part)
                        if ip_match:
                            base_ip = ip_match.group(1).split('/')[0]
                            if not is_private_ip(base_ip) and base_ip not in ctx.cdn_ips and not is_cdn_ip(base_ip, ctx.cdn_ips):
                                mx_ips.add(base_ip)
                                print(f"  {C.G}    SPF: ip4:{ip_match.group(1)}{C.RS}")
        except asyncio.TimeoutError:
            pass
        except Exception:  # dns.resolver raises DNSException subclasses (NXDOMAIN, NoAnswer, etc.)
            pass

        try:
            ns_answers = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: dns.resolver.resolve(ctx.domain, 'NS')),
                timeout=DNS_PROBE_TIMEOUT)  # W2.4
            ns_hosts = [str(rdata).rstrip('.') for rdata in ns_answers]

            async def _resolve_ns(ns_host: str):
                try:
                    ns_ip = await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, ns_host),
                        timeout=DNS_PROBE_TIMEOUT)  # W2.4
                    if ns_ip and not is_private_ip(ns_ip) and ns_ip not in ctx.cdn_ips and not is_cdn_ip(ns_ip, ctx.cdn_ips):
                        return ns_host, ns_ip
                except (socket.gaierror, OSError, asyncio.TimeoutError):
                    pass
                return ns_host, None

            ns_results = await bounded_gather(*[_resolve_ns(nh) for nh in ns_hosts])
            for ns_host, ns_ip in ns_results:
                if ns_ip:
                    mx_ips.add(ns_ip)
                    print(f"  {C.G}    NS: {ns_host} -> {ns_ip}{C.RS}")
        except asyncio.TimeoutError:
            pass
        except Exception:  # dns.resolver raises DNSException subclasses (NXDOMAIN, NoAnswer, etc.)
            print(f"  {C.DM}    NS lookup failed{C.RS}")

    if mx_ips:
        print(f"  {C.G}    MX/TXT/NS: {len(mx_ips)} non-CDN IPs{C.RS}")
    else:
        print(f"  {C.DM}    MX/TXT/NS: No non-CDN IPs{C.RS}")
    return mx_ips


async def discover_ssl_san(ctx: OriginIPContext) -> set[str]:
    """Method 5: SSL Certificate SAN extraction."""
    print(f"  {C.CY}  [5] SSL Certificate SAN extraction...{C.RS}")
    san_ips: set[str] = set()
    writer = None
    try:
        ssl_ctx = create_ssl_context(ctx.verify_ssl)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ctx.domain, 443, ssl=ssl_ctx), timeout=NETWORK_PROBE_TIMEOUT)  # W2.4
        peer_cert = writer.get_extra_info('peercert')
        if peer_cert:
            san = peer_cert.get('subjectAltName', ())
            for san_type, san_value in san:
                if san_type == 'IP Address':
                    if not is_private_ip(str(san_value)) and str(san_value) not in ctx.cdn_ips and not is_cdn_ip(str(san_value), ctx.cdn_ips):
                        san_ips.add(str(san_value))
                elif san_type == 'DNS' and ctx.domain in san_value:
                    try:
                        san_ip = await asyncio.wait_for(
                            asyncio.get_running_loop().run_in_executor(None, socket.gethostbyname, san_value),
                            timeout=DNS_PROBE_TIMEOUT)  # W2.4
                        if san_ip and not is_private_ip(san_ip) and san_ip not in ctx.cdn_ips and not is_cdn_ip(san_ip, ctx.cdn_ips):
                            san_ips.add(san_ip)
                    except (socket.gaierror, OSError, asyncio.TimeoutError):
                        pass

        if san_ips:
            print(f"  {C.G}    SSL SAN: {len(san_ips)} non-CDN IPs{C.RS}")
        else:
            print(f"  {C.DM}    SSL SAN: No non-CDN IPs in certificate{C.RS}")
    except (OSError, ssl.SSLError, ConnectionError, asyncio.TimeoutError) as e:
        print(f"  {C.Y}    SSL SAN: {type(e).__name__}{C.RS}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, RuntimeError):
                pass
    return san_ips


async def discover_external_apis(ctx: OriginIPContext, session: aiohttp.ClientSession) -> set[str]:
    """Method 6: ViewDNS + SecurityTrails."""
    if ctx.skip_slow:
        print(f"  {C.DM}  [6] External APIs: SKIPPED (origin already found){C.RS}")
        return set()
    ext_ips: set[str] = set()
    print(f"  {C.CY}  [6] External APIs (ViewDNS, SecurityTrails)...{C.RS}")
    try:
        headers_vd = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0"}
        async with session.get(f"https://viewdns.info/iphistory/?domain={ctx.domain}",
                               headers=headers_vd, ssl=ctx._ssl) as resp:
            if resp.status == 200:
                text = await safe_read_text(resp)  # W1.10: bounded read
                for match in re.finditer(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text):
                    ip = match.group(1)
                    if not is_private_ip(ip) and ip not in ctx.cdn_ips and not is_cdn_ip(ip, ctx.cdn_ips):
                        ext_ips.add(ip)
        if ext_ips:
            print(f"  {C.G}    ViewDNS: {len(ext_ips)} IPs{C.RS}")
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

    try:
        async with session.get(f"https://api.securitytrails.com/v1/domain/{ctx.domain}/subdomains",
                               headers={"Accept": "application/json"}, ssl=ctx._ssl) as resp:
            if resp.status == 200:
                data = await resp.json()
                st_subs = {f"{sub}.{ctx.domain}" for sub in data.get('subdomains', [])}
                if st_subs:
                    resolved = await resolve_subdomains(st_subs, ctx.cdn_ips)
                    ctx.all_subdomains.update(st_subs)
                    ext_ips.update(resolved)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        pass

    return ext_ips


async def discover_hackertarget(ctx: OriginIPContext, session: aiohttp.ClientSession) -> set[str]:
    """Method 7: HackerTarget API (DNS + Reverse + Pagelinks)."""
    if ctx.skip_slow:
        print(f"  {C.DM}  [7] HackerTarget: SKIPPED (origin already found){C.RS}")
        return set()
    ht_ips: set[str] = set()
    print(f"  {C.CY}  [7] HackerTarget API (DNS + Reverse + Pagelinks)...{C.RS}")

    try:
        async with session.get(
            f"https://api.hackertarget.com/dnslookup/?q={ctx.domain}",
            ssl=ctx._ssl) as resp:
            if resp.status == 200:
                text = await safe_read_text(resp)  # W1.10: bounded read
                for line in text.split('\n'):
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if not is_private_ip(ip) and ip not in ctx.cdn_ips and not is_cdn_ip(ip, ctx.cdn_ips):
                            ht_ips.add(ip)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

    try:
        main_ip = await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, socket.gethostbyname, ctx.domain),
            timeout=NETWORK_PROBE_TIMEOUT)  # W2.4
        if main_ip:
            async with session.get(
                f"https://api.hackertarget.com/reversedns/?q={main_ip}",
                ssl=ctx._ssl) as resp:
                if resp.status == 200:
                    text = await safe_read_text(resp)  # W1.10: bounded read
                    for line in text.split('\n'):
                        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            if not is_private_ip(ip) and ip not in ctx.cdn_ips and not is_cdn_ip(ip, ctx.cdn_ips):
                                ht_ips.add(ip)
    except (aiohttp.ClientError, asyncio.TimeoutError, socket.gaierror, OSError):
        pass

    try:
        async with session.get(
            f"https://api.hackertarget.com/pagelinks/?q={ctx.domain}",
            ssl=ctx._ssl) as resp:
            if resp.status == 200:
                text = await safe_read_text(resp)  # W1.10: bounded read
                for ip_match in re.finditer(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text):
                    ip = ip_match.group(1)
                    if not is_private_ip(ip) and ip not in ctx.cdn_ips and not is_cdn_ip(ip, ctx.cdn_ips):
                        ht_ips.add(ip)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

    if ht_ips:
        print(f"  {C.G}    HackerTarget: {len(ht_ips)} non-CDN IPs{C.RS}")
    else:
        print(f"  {C.DM}    HackerTarget: No non-CDN IPs{C.RS}")
    return ht_ips


async def discover_dnsdumpster(ctx: OriginIPContext, session: aiohttp.ClientSession) -> set[str]:
    """Method 8: DNSdumpster + RapidDNS."""
    if ctx.skip_slow:
        print(f"  {C.DM}  [8] DNSdumpster/RapidDNS: SKIPPED (origin already found){C.RS}")
        return set()
    dd_ips: set[str] = set()
    print(f"  {C.CY}  [8] RapidDNS + DNSdumpster...{C.RS}")
    try:
        async with session.get(
            f"https://rapiddns.io/subdomain/{ctx.domain}#result",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0"},
            ssl=ctx._ssl, timeout=scanner_timeout(total=ORIGIN_PROBE_TIMEOUT)) as resp:  # W2.4
            if resp.status == 200:
                text = await safe_read_text(resp)  # W1.10: bounded read
                for ip_match in re.finditer(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text):
                    ip = ip_match.group(1)
                    if not is_private_ip(ip) and ip not in ctx.cdn_ips and not is_cdn_ip(ip, ctx.cdn_ips):
                        dd_ips.add(ip)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

    try:
        async with session.get(
            f"https://dnsdumpster.com/static/map/{ctx.domain}.png",
            ssl=ctx._ssl, timeout=scanner_timeout(total=ORIGIN_QUICK_PROBE_TIMEOUT)) as resp:  # W2.4
            pass
        async with session.get(
            f"https://dnsdumpster.com/",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
                     "Referer": f"https://dnsdumpster.com/"},
            ssl=ctx._ssl, timeout=scanner_timeout(total=ORIGIN_PROBE_TIMEOUT)) as resp:  # W2.4
            pass
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

    if dd_ips:
        print(f"  {C.G}    RapidDNS: {len(dd_ips)} non-CDN IPs{C.RS}")
    else:
        print(f"  {C.DM}    RapidDNS/DNSdumpster: No non-CDN IPs{C.RS}")
    return dd_ips


async def discover_header_leak(ctx: OriginIPContext, session: aiohttp.ClientSession) -> set[str]:
    """Method 9: HTTP Header Analysis + Response Body Leak."""
    if ctx.skip_slow:
        print(f"  {C.DM}  [9] Header leak analysis: SKIPPED (origin already found){C.RS}")
        return set()
    leak_ips: set[str] = set()
    print(f"  {C.CY}  [9] HTTP Header + Body leak analysis...{C.RS}")

    leak_paths = [
        f"https://{ctx.domain}/",
        f"https://{ctx.domain}/api/v1/status",
        f"https://{ctx.domain}/_next/data/",
        f"https://{ctx.domain}/server-status",
        f"https://{ctx.domain}/server-info",
        f"https://{ctx.domain}/.env",
        f"https://{ctx.domain}/debug",
        f"https://{ctx.domain}/phpinfo.php",
        f"https://{ctx.domain}/wp-json/",
        f"https://{ctx.domain}/api/health",
    ]

    async def _check_leak_path(path: str, _ssl: Any) -> set[str]:
        path_ips: set[str] = set()
        try:
            async with session.get(path, ssl=_ssl,
                                   timeout=scanner_timeout(total=ORIGIN_QUICK_PROBE_TIMEOUT),  # W2.4
                                   allow_redirects=False) as resp:
                for header_name in ['X-Forwarded-For', 'X-Real-IP', 'X-Origin-IP',
                                    'X-Server-IP', 'X-Backend-IP', 'X-Internal-IP',
                                    'X-Client-IP', 'X-Remote-IP', 'Origin-IP',
                                    'CF-Connecting-IP', 'True-Client-IP']:
                    header_val = resp.headers.get(header_name, '')
                    if header_val:
                        ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', header_val)
                        if ip_match:
                            ip = ip_match.group(1)
                            if not is_private_ip(ip) and ip not in ctx.cdn_ips and not is_cdn_ip(ip, ctx.cdn_ips):
                                path_ips.add(ip)

                location = resp.headers.get('Location', '')
                if location:
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', location)
                    if ip_match:
                        ip = ip_match.group(1)
                        if not is_private_ip(ip) and ip not in ctx.cdn_ips and not is_cdn_ip(ip, ctx.cdn_ips):
                            path_ips.add(ip)

                if resp.status == 200:
                    body = await safe_read_text(resp)  # W1.10: bounded read
                    for ip_match in re.finditer(r'(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)', body[:10000]):
                        ip = ip_match.group(1)
                        if not is_private_ip(ip) and ip not in ctx.cdn_ips and not is_cdn_ip(ip, ctx.cdn_ips):
                            if not ip.startswith(('0.', '1.', '224.', '239.')):
                                path_ips.add(ip)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return path_ips

    # W2.6 FIX: Use bounded gather — leak_paths can be 10+ URLs
    all_path_results = await bounded_gather(*[_check_leak_path(p, ctx._ssl) for p in leak_paths])
    for path_ips in all_path_results:
        leak_ips.update(path_ips)

    if leak_ips:
        print(f"  {C.G}    Header/Body leak: {len(leak_ips)} non-CDN IPs{C.RS}")
    else:
        print(f"  {C.DM}    Header/Body leak: No origin IPs leaked{C.RS}")
    return leak_ips


# ═══════════════════════════════════════════════════════════════════════
# Standalone IP verification (extracted to origin_validator.py for Law 14)
# ═══════════════════════════════════════════════════════════════════════
from finder.origin_validator import verify_origin_ip  # F5-05: noqa: F401
