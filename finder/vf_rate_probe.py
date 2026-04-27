#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  vf_rate_probe.py — Rate Limit Prober Module                            ║
║  Part of the STORM_VX Toolkit                                           ║
║                                                                          ║
║  Probes rate limiting by gradually increasing request rate, detecting    ║
║  thresholds, block status codes, recovery times, and per-path/per-method║
║  differences. Designed for CDN/WAF-protected targets.                    ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp


# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


class RateLimitProber:
    """
    Rate limit prober for STORM_VX.

    Gradually increases request rate to detect rate limiting thresholds,
    block status codes, recovery times, and per-path/per-method differences.
    """

    # Test paths for per-path rate limiting
    TEST_PATHS = [
        "/", "/api/", "/login", "/health", "/search",
    ]

    def __init__(self, url: str, timeout: int = 15):
        """
        Initialize RateLimitProber.

        Args:
            url: Target URL
            timeout: HTTP request timeout in seconds
        """
        self.url = url
        self.timeout = timeout
        parsed = urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

    async def run(self) -> Dict:
        """
        Run rate limit probing.

        Returns:
            Dictionary with:
                - rate_limit_detected: Whether rate limiting was detected
                - threshold_rps: Approximate requests per second threshold
                - block_status_code: Status code when rate limited
                - recovery_time_seconds: Time until blocks stop
                - per_path_limits: Dict of path -> rate limit info
        """
        print(f"\n  {C.BD}{C.CY}[*] Rate Limit Prober — {self.url}{C.RS}")
        print(f"  {C.DM}    Timeout: {self.timeout}s{C.RS}")

        t0 = time.time()

        # Step 1: Establish baseline
        print(f"  {C.B}  [1/4] Establishing baseline response...{C.RS}")
        baseline_status, baseline_body, baseline_rt = await self._get_baseline()

        # Step 2: Progressive rate increase
        print(f"  {C.B}  [2/4] Progressive rate testing...{C.RS}")
        rate_result = await self._progressive_rate_test(baseline_status)

        # Step 3: Recovery time test
        recovery_time = 0.0
        if rate_result["rate_limit_detected"]:
            print(f"  {C.B}  [3/4] Testing recovery time...{C.RS}")
            recovery_time = await self._test_recovery(baseline_status)
        else:
            print(f"  {C.DM}  [3/4] No rate limit detected, skipping recovery test{C.RS}")

        # Step 4: Per-path rate limits
        print(f"  {C.B}  [4/4] Testing per-path rate limits...{C.RS}")
        per_path = await self._test_per_path_limits(baseline_status)

        elapsed = time.time() - t0

        # Print summary
        self._print_summary(rate_result, recovery_time, per_path, elapsed)

        return {
            "rate_limit_detected": rate_result["rate_limit_detected"],
            "threshold_rps": rate_result["threshold_rps"],
            "block_status_code": rate_result["block_status_code"],
            "recovery_time_seconds": round(recovery_time, 2),
            "per_path_limits": per_path,
        }

    async def _get_baseline(self) -> Tuple[int, str, float]:
        """Get baseline response properties."""
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                t0 = time.time()
                async with session.get(self.url, ssl=False, allow_redirects=False) as resp:
                    body = await resp.text()
                    rt = time.time() - t0
                    print(f"  {C.G}    Baseline: HTTP {resp.status} | RT: {rt*1000:.0f}ms | Size: {len(body):,}B{C.RS}")
                    return resp.status, body[:500], rt
        except Exception as e:
            print(f"  {C.Y}    Baseline error: {e}{C.RS}")
            return 200, "", 1.0

    async def _progressive_rate_test(self, baseline_status: int) -> Dict:
        """
        Gradually increase request rate and monitor for blocks.

        Starts at 10 req/s, increases by 10 every 3 seconds.
        """
        result = {
            "rate_limit_detected": False,
            "threshold_rps": 0,
            "block_status_code": 0,
            "block_body_snippet": "",
        }

        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
        rps = 10
        max_rps = 150  # Don't go beyond this
        block_detected = False

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            while rps <= max_rps and not block_detected:
                print(f"  {C.CY}    Testing {rps} req/s...{C.RS}")

                # Send 'rps' requests in 1 second
                block_count = 0
                block_status = 0
                block_body = ""
                total_sent = 0
                t_start = time.time()

                tasks = []
                for i in range(rps):
                    tasks.append(self._single_request(session))

                responses = await asyncio.gather(*tasks, return_exceptions=True)

                t_elapsed = time.time() - t_start
                total_sent = len(responses)

                for resp_result in responses:
                    if isinstance(resp_result, Exception):
                        continue

                    status, body = resp_result
                    # Check for rate limit indicators
                    if self._is_rate_limited(status, body, baseline_status):
                        block_count += 1
                        block_status = status
                        block_body = body[:200] if body else ""

                actual_rps = total_sent / t_elapsed if t_elapsed > 0 else 0
                block_rate = block_count / total_sent if total_sent > 0 else 0

                status_color = C.R if block_rate > 0.3 else C.Y if block_rate > 0 else C.G
                print(
                    f"  {status_color}    RPS: {actual_rps:.1f} | "
                    f"Blocked: {block_count}/{total_sent} ({block_rate:.0%}) | "
                    f"Block status: {block_status or 'N/A'}{C.RS}"
                )

                if block_rate > 0.5:
                    block_detected = True
                    result["rate_limit_detected"] = True
                    result["threshold_rps"] = rps
                    result["block_status_code"] = block_status
                    result["block_body_snippet"] = block_body
                    print(f"  {C.R}    [!] Rate limit detected at ~{rps} req/s{C.RS}")
                    break

                # Increase RPS for next round
                rps += 10

                # Wait before next round
                await asyncio.sleep(3)

        if not block_detected and rps > max_rps:
            print(f"  {C.G}    No rate limit detected up to {max_rps} req/s{C.RS}")

        return result

    async def _single_request(
        self, session: aiohttp.ClientSession
    ) -> Tuple[int, str]:
        """Send a single GET request and return status + body snippet."""
        try:
            async with session.get(
                self.url, ssl=False, allow_redirects=False
            ) as resp:
                body = await resp.text()
                return resp.status, body[:500]
        except Exception:
            return 0, ""

    def _is_rate_limited(
        self, status: int, body: str, baseline_status: int
    ) -> bool:
        """Check if a response indicates rate limiting."""
        # Common rate limit status codes
        if status in (429, 503, 508):
            return True

        # Status code change from baseline
        if baseline_status < 400 and status >= 400:
            return True

        # Body patterns indicating rate limiting
        rate_limit_patterns = [
            "rate limit",
            "too many requests",
            "slow down",
            "throttl",
            "quota exceeded",
            "request limit",
            "try again later",
        ]
        body_lower = body.lower()
        for pattern in rate_limit_patterns:
            if pattern in body_lower:
                return True

        return False

    async def _test_recovery(self, baseline_status: int) -> float:
        """
        Test how long it takes for rate limiting to stop after blocks detected.

        Returns recovery time in seconds.
        """
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
        recovery_time = 0.0

        print(f"  {C.Y}    Waiting and checking for recovery...{C.RS}")

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            # Check every 2 seconds for up to 120 seconds
            max_wait = 120
            check_interval = 2
            waited = 0

            while waited < max_wait:
                await asyncio.sleep(check_interval)
                waited += check_interval

                # Send a test request
                try:
                    async with session.get(
                        self.url, ssl=False, allow_redirects=False
                    ) as resp:
                        body = await resp.text()
                        is_limited = self._is_rate_limited(
                            resp.status, body[:500], baseline_status
                        )

                        if not is_limited:
                            recovery_time = waited
                            print(
                                f"  {C.G}    Recovered after {waited}s "
                                f"(HTTP {resp.status}){C.RS}"
                            )
                            break
                        else:
                            print(
                                f"  {C.Y}    Still rate limited after {waited}s "
                                f"(HTTP {resp.status}){C.RS}"
                            )
                except Exception:
                    pass

            if waited >= max_wait:
                recovery_time = float(max_wait)
                print(f"  {C.R}    Did not recover within {max_wait}s{C.RS}")

        return recovery_time

    async def _test_per_path_limits(self, baseline_status: int) -> Dict:
        """Test rate limits on different paths and methods."""
        results = {}
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            for path in self.TEST_PATHS:
                url = f"{self.base_url}{path}"

                # Test GET with moderate rate
                get_result = await self._test_path_method(
                    session, url, "GET", baseline_status, rps=30, duration=3
                )

                # Test POST with moderate rate
                post_result = await self._test_path_method(
                    session, url, "POST", baseline_status, rps=20, duration=3
                )

                results[path] = {
                    "get_blocked": get_result["blocked"],
                    "get_block_rate": get_result["block_rate"],
                    "get_status_on_block": get_result["block_status"],
                    "post_blocked": post_result["blocked"],
                    "post_block_rate": post_result["block_rate"],
                    "post_status_on_block": post_result["block_status"],
                }

                status_str = ""
                if get_result["blocked"]:
                    status_str += f"{C.R}GET:blocked{C.RS} "
                else:
                    status_str += f"{C.G}GET:ok{C.RS} "
                if post_result["blocked"]:
                    status_str += f"{C.R}POST:blocked{C.RS}"
                else:
                    status_str += f"{C.G}POST:ok{C.RS}"

                print(f"  {C.DM}    {path:<20}{C.RS} {status_str}")

        return results

    async def _test_path_method(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        baseline_status: int,
        rps: int = 30,
        duration: int = 3
    ) -> Dict:
        """Test rate limiting on a specific path + method."""
        total_requests = rps * duration
        block_count = 0
        block_status = 0

        tasks = []
        for _ in range(total_requests):
            tasks.append(
                self._single_method_request(session, url, method)
            )

        # Send in batches of rps
        for i in range(0, len(tasks), rps):
            batch = tasks[i:i + rps]
            results = await asyncio.gather(*batch, return_exceptions=True)

            for resp_result in results:
                if isinstance(resp_result, Exception):
                    continue
                status, body = resp_result
                if self._is_rate_limited(status, body, baseline_status):
                    block_count += 1
                    block_status = status

            if i + rps < len(tasks):
                await asyncio.sleep(1)

        block_rate = block_count / total_requests if total_requests > 0 else 0

        return {
            "blocked": block_count > 0,
            "block_rate": round(block_rate, 2),
            "block_status": block_status,
        }

    async def _single_method_request(
        self, session: aiohttp.ClientSession, url: str, method: str
    ) -> Tuple[int, str]:
        """Send a single request with specified method."""
        try:
            if method == "GET":
                async with session.get(url, ssl=False, allow_redirects=False) as resp:
                    body = await resp.text()
                    return resp.status, body[:500]
            elif method == "POST":
                async with session.post(
                    url, data={"test": "probe"},
                    ssl=False, allow_redirects=False
                ) as resp:
                    body = await resp.text()
                    return resp.status, body[:500]
        except Exception:
            return 0, ""
        return 0, ""

    def _print_summary(
        self,
        rate_result: Dict,
        recovery_time: float,
        per_path: Dict,
        elapsed: float
    ):
        """Print formatted summary."""
        detected = rate_result["rate_limit_detected"]
        status_color = C.R if detected else C.G

        print(f"\n  {C.G}  ╔════════════════════════════════════════════════════════╗{C.RS}")
        print(f"  {C.G}  ║  Rate Limit Probe Results                             ║{C.RS}")
        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Rate Limit Detected:  {status_color}{str(detected):<30}{C.G}║{C.RS}")

        if detected:
            print(f"  {C.G}  ║  Threshold RPS:        {C.Y}{rate_result['threshold_rps']:<30}{C.G}║{C.RS}")
            print(f"  {C.G}  ║  Block Status Code:    {C.R}{rate_result['block_status_code']:<30}{C.G}║{C.RS}")
            print(f"  {C.G}  ║  Recovery Time:        {C.CY}{recovery_time:.1f}s{' ' * (26 - len(f'{recovery_time:.1f}s'))}{C.G}║{C.RS}")
        else:
            print(f"  {C.G}  ║  No rate limit detected up to 150 RPS                  ║{C.RS}")

        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Per-Path Results:                                    ║{C.RS}")
        for path, info in per_path.items():
            get_str = f"GET:{info['get_block_rate']:.0%}" if info['get_blocked'] else "GET:ok"
            post_str = f"POST:{info['post_block_rate']:.0%}" if info['post_blocked'] else "POST:ok"
            print(f"  {C.G}  ║{C.RS}  {C.W}{path:<20}{C.RS} {get_str} | {post_str}")

        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Total Time: {C.CY}{elapsed:.1f}s{C.RS}")
        print(f"  {C.G}  ╚════════════════════════════════════════════════════════╝{C.RS}")
