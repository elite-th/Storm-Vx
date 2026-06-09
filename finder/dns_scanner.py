"""DNS enumeration and origin IP discovery module.

Performs DNS record lookups, subdomain enumeration,
and origin IP discovery for CDN bypass.

The heavy origin-IP discovery logic lives in
``finder.vf_origin_discovery``; this module provides the public
``dns_enumerate`` and ``find_origin_ips`` orchestrators.
"""
from __future__ import annotations
import asyncio
import socket
import time
from typing import Dict, List

import aiohttp

from vf_common import C, ssl_param
from utils.async_helpers import bounded_gather, DNS_MAX_CONCURRENCY
from utils.session_helpers import scanner_timeout
from config.defaults import FAST_PROBE_TIMEOUT, FAST_PROBE_CONNECT, FAST_PROBE_SOCK_READ, NETWORK_PROBE_TIMEOUT, DNS_PROBE_TIMEOUT
from finder.site_profile import SiteProfile
from finder.vf_origin_discovery import (
    OriginIPContext,
    is_private_ip,
    is_cdn_ip,
    is_cdn_ip_async,
    resolve_subdomains,
    discover_crtsh,
    discover_doh,
    discover_subdomain,
    discover_mx_txt,
    discover_ssl_san,
    discover_external_apis,
    discover_hackertarget,
    discover_dnsdumpster,
    discover_header_leak,
    verify_origin_ip,
)

# Optional dns.resolver import
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


async def dns_enumerate(profile: SiteProfile, subdomain_scan: bool = False, verify_ssl: bool = True) -> SiteProfile:
    """Enumerate DNS records for the target domain.

    v14 OPTIMIZED for speed + CDN detection.
    Added timeouts to ALL DNS calls to prevent hanging.

    Args:
        profile: SiteProfile with domain info.
        subdomain_scan: Whether to enumerate subdomains.

    Returns:
        Updated SiteProfile with DNS records.
    """
    domain = profile.domain
    loop = asyncio.get_running_loop()
    _ssl = ssl_param(verify_ssl)

    # Basic DNS resolution (non-blocking) — v14: Added 5s timeout
    try:
        ips = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, None)),
            timeout=NETWORK_PROBE_TIMEOUT  # W2.4
        )
        ip_list = list(set(addr[4][0] for addr in ips))
        profile.ip_addresses = ip_list
        print(f"  {C.G}  IPs: {', '.join(ip_list)}{C.RS}")
    except asyncio.TimeoutError:
        print(f"  {C.Y}  DNS resolution timed out (5s) — skipping basic resolution{C.RS}")
    except (OSError, socket.gaierror) as e:
        print(f"  {C.R}  DNS resolution failed: {e}{C.RS}")

    # DNS record lookup — v14: 3s timeout per record type
    if HAS_DNS:
        async def _lookup(rtype):
            try:
                answers = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, rtype)),
                    timeout=DNS_PROBE_TIMEOUT  # W2.4
                )
                records = [str(r) for r in answers]
                profile.dns_records[rtype] = records
                return rtype, records
            except asyncio.TimeoutError:
                return rtype, None
            except (OSError, RuntimeError, ValueError):
                return rtype, None
            except Exception:  # dns.exception.DNSException and other unexpected DNS errors
                # dns.resolver.resolve() raises dns.exception.DNSException subclasses
                # (NXDOMAIN, NoAnswer, NoNameservers, Timeout) which inherit from
                # DNSException, NOT from OSError/ValueError.
                return rtype, None

        results = await asyncio.gather(*[_lookup(rt) for rt in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']])
        for rtype, records in results:
            if records:
                print(f"  {C.G}  {rtype}: {', '.join(records[:3])}{'...' if len(records) > 3 else ''}{C.RS}")

    # v13: CNAME-based CDN detection
    if not profile.cdn:
        cname_records = profile.dns_records.get('CNAME', [])
        cdn_cname_keywords = ['cdn', 'edge', 'cloudfront', 'cloudflare', 'akamai',
                              'arvan', 'sotoon', 'fastly', 'incap', 'sucuri',
                              'stackpath', 'azureedge', 'msecnd']
        for cname in cname_records:
            cname_lower = cname.lower().rstrip('.')
            for kw in cdn_cname_keywords:
                if kw in cname_lower:
                    profile.cdn = f"CDN (via CNAME: {cname})"
                    print(f"  {C.Y}  [CDN-DETECT] CNAME points to CDN: {cname}{C.RS}")
                    break
            if profile.cdn:
                break

    # Subdomain enumeration (common subdomains)
    if subdomain_scan:
        await _enumerate_subdomains(domain, profile)

    return profile


async def _enumerate_subdomains(domain: str, profile: SiteProfile) -> None:
    """Enumerate common subdomains — v12: parallel with short timeout"""
    common_subs = [
        'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'direct',
        'origin', 'server', 'cpanel', 'ns1', 'ns2', 'admin', 'portal',
        'api', 'dev', 'staging', 'test', 'backup', 'db', 'remote', 'vpn',
    ]
    print(f"  {C.CY}  Scanning {len(common_subs)} subdomains...{C.RS}")
    found = []

    async def check_sub(sub: str):
        fqdn = f"{sub}.{domain}"
        try:
            ip = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(None, socket.gethostbyname, fqdn),
                timeout=DNS_PROBE_TIMEOUT)  # W2.4
            found.append(fqdn)
            print(f"  {C.G}    {fqdn} -> {ip}{C.RS}")
        except (socket.gaierror, asyncio.TimeoutError):
            pass
        except (RuntimeError, ValueError, AttributeError):  # Intentional: unknown resolver errors during subdomain scan
            pass

    # W1.6 FIX: Use bounded_gather to cap concurrent DNS lookups
    await bounded_gather(*[check_sub(sub) for sub in common_subs],
                         max_concurrency=DNS_MAX_CONCURRENCY)

    profile.subdomains = found
    print(f"  {C.G}  Subdomains found: {len(found)}{C.RS}")


async def find_origin_ips(url: str, profile: SiteProfile, verify_ssl: bool = True) -> SiteProfile:
    """v12 OPTIMIZED: Discover the real origin IP behind CDN/WAF.

    Thin orchestrator — delegates discovery methods to
    ``finder.vf_origin_discovery`` and runs them in parallel.

    Args:
        url: Target URL.
        profile: SiteProfile with WAF/CDN info.

    Returns:
        Updated SiteProfile with origin IPs.
    """
    domain = profile.domain
    cdn_ips = set(profile.ip_addresses)
    _ssl = ssl_param(verify_ssl)

    # Also resolve the main domain to get CDN IPs for filtering
    if not cdn_ips:
        try:
            main_ip = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(None, socket.gethostbyname, domain),
                timeout=NETWORK_PROBE_TIMEOUT)  # W2.4
            if main_ip:
                cdn_ips.add(main_ip)
        except asyncio.TimeoutError:
            pass
        except (socket.gaierror, OSError):
            pass

    # ── Build shared context ──
    ctx = OriginIPContext(
        domain=domain,
        cdn_ips=cdn_ips,
        verify_ssl=verify_ssl,
        _ssl=_ssl,
    )

    # ═══ PRE-CLASSIFY KNOWN IPs IN PARALLEL ═══
    print(f"  {C.CY}  [PRE-SCAN] Classifying {len(profile.ip_addresses)} known IPs...{C.RS}")

    async def _classify_ip(ip: str):
        if is_private_ip(ip):
            return ip, 'private'
        if await is_cdn_ip_async(ip, cdn_ips):
            return ip, 'cdn'
        return ip, 'origin'

    # W1.6 FIX: Use bounded_gather — CDN async lookups can be slow
    classify_results = await bounded_gather(*[_classify_ip(ip) for ip in profile.ip_addresses],
                                            max_concurrency=DNS_MAX_CONCURRENCY)
    for ip, classification in classify_results:
        if classification == 'cdn':
            print(f"  {C.DM}    {ip} -> CDN IP (behind CDN/WAF){C.RS}")
        elif classification == 'origin':
            ctx.found_ips.add(ip)
            ctx.sources['dns_direct'] = [ip]
            print(f"  {C.BD}{C.G}    {ip} -> ORIGIN IP FOUND!{C.RS}")

    ctx.skip_slow = len(ctx.found_ips) > 0

    # ═══ RUN ALL EXTERNAL METHODS IN PARALLEL ═══
    timeout_fast = scanner_timeout(total=FAST_PROBE_TIMEOUT, connect=FAST_PROBE_CONNECT, sock_read=FAST_PROBE_SOCK_READ)  # W2.4
    async with aiohttp.ClientSession(timeout=timeout_fast) as session:

        method_names = ['crt.sh', 'DoH', 'Subdomain', 'MX/TXT', 'SSL-SAN',
                        'External', 'HackerTarget', 'RapidDNS', 'Header-Leak']
        method_done = [False] * 9
        spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

        async def _run_with_status(idx: int, coro):
            try:
                result = await coro
            except asyncio.CancelledError:
                raise
            except (OSError, RuntimeError, ValueError, AttributeError):  # Intentional: method errors should not crash the whole scan
                result = set()
            method_done[idx] = True
            return result

        _spinner_stop = asyncio.Event()

        async def _spinner():
            spin_idx = 0
            while not _spinner_stop.is_set():
                done_count = sum(method_done)
                total = len(method_done)
                status_parts = []
                for i, name in enumerate(method_names):
                    if method_done[i]:
                        status_parts.append(f"{C.G}✓{C.RS}{name}")
                    else:
                        status_parts.append(f"{C.Y}…{C.RS}{name}")
                spin_char = spinner_chars[spin_idx % len(spinner_chars)]
                status_line = f"  {C.CY}{spin_char}{C.RS} [{done_count}/{total}] " + " | ".join(status_parts)
                print(f"\r{status_line}{C.RS}", end='', flush=True)
                spin_idx += 1
                await asyncio.sleep(0.15)

        t_start = time.time()
        spinner_task = asyncio.create_task(_spinner())

        results = await asyncio.gather(
            _run_with_status(0, discover_crtsh(ctx, session)),
            _run_with_status(1, discover_doh(ctx, session)),
            _run_with_status(2, discover_subdomain(ctx)),
            _run_with_status(3, discover_mx_txt(ctx)),
            _run_with_status(4, discover_ssl_san(ctx)),
            _run_with_status(5, discover_external_apis(ctx, session)),
            _run_with_status(6, discover_hackertarget(ctx, session)),
            _run_with_status(7, discover_dnsdumpster(ctx, session)),
            _run_with_status(8, discover_header_leak(ctx, session)),
            return_exceptions=True,
        )

        _spinner_stop.set()
        await spinner_task
        elapsed_origin = time.time() - t_start
        done_count = sum(method_done)
        print(f"\r  {C.G}✓ Origin Discovery: {done_count}/9 methods done in {elapsed_origin:.1f}s{C.RS}    ")

        # Collect results
        method_sources = ['crt.sh', 'doh', 'subdomain', 'mx_txt', 'ssl_san', 'external',
                          'hackertarget', 'rapiddns', 'header_leak']
        for i, result in enumerate(results):
            if isinstance(result, set):
                if result:
                    ctx.sources[method_sources[i]] = list(result)
                    ctx.found_ips.update(result)

    # ═══ VERIFY FOUND IPs ═══
    verified_ips: set[str] = set()
    if ctx.found_ips:
        print(f"  {C.CY}  [FINAL] Validating {len(ctx.found_ips)} potential origin IPs...{C.RS}")
        # W1.6 FIX: Use bounded_gather — IP verification opens TCP connections
        v_results = await bounded_gather(
            *[verify_origin_ip(ip, domain, verify_ssl) for ip in ctx.found_ips],
            max_concurrency=DNS_MAX_CONCURRENCY,
        )
        for ip in v_results:
            if ip:
                verified_ips.add(ip)
                print(f"  {C.G}    Testing {ip}... VALID{C.RS}")

    # Update profile
    if verified_ips:
        profile.origin_ips = list(verified_ips)
        profile.cdn_bypass_possible = True
    elif ctx.found_ips:
        # v23: Mark unverified IPs as "potential" — don't blindly trust them
        # Only use if there are fewer than 10 (too many = likely false positives)
        if len(ctx.found_ips) <= 10:
            profile.origin_ips = list(ctx.found_ips)
            profile.cdn_bypass_possible = True
            print(f"  {C.Y}  ⚠ Using {len(ctx.found_ips)} UNVERIFIED origin IPs — may include false positives{C.RS}")
        else:
            # Too many unverified IPs = likely all false positives
            profile.origin_ips = []
            profile.cdn_bypass_possible = False
            print(f"  {C.Y}  ⚠ {len(ctx.found_ips)} unverified IPs found but too many — skipping (likely false positives){C.RS}")
    else:
        profile.origin_ips = []
        profile.cdn_bypass_possible = False

    # Print summary
    if profile.origin_ips:
        print(f"\n  ╔════════════════════════════════════════════════════════════╗")
        print(f"  ║              ORIGIN DISCOVERY COMPLETE                   ║")
        print(f"  ╚════════════════════════════════════════════════════════════╝")
        print(f"    Total scanned:  {len(ctx.found_ips) + len(ctx.all_subdomains)}")
        print(f"    CDN IPs found:  {len(cdn_ips)}")
        print(f"    Origin IPs:     {len(profile.origin_ips)}")
        print(f"")
        if verified_ips:
            print(f"    *** DIRECT ATTACK TARGETS (CDN BYPASS) ***")
            for ip in verified_ips:
                print(f"      >>> {ip} <<<")
        else:
            print(f"    Potential origin IPs (unverified):")
            for ip in profile.origin_ips[:5]:
                print(f"      ?? {ip}")
    else:
        print(f"\n  {C.R}  No origin IPs found — CDN bypass not possible{C.RS}")

    profile.origin_ip_sources = ctx.sources
    return profile
