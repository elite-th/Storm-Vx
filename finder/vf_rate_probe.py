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
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import aiohttp

from vf_common import C, ssl_param
from utils.response_helpers import safe_read_text
from utils.session_helpers import scanner_timeout
from config.defaults import DEFAULT_RATE_PROBE_REQUESTS


class RateLimitProber:
    """
    Rate limit prober for STORM_VX.

    Gradually increases request rate to detect rate limiting thresholds,
    block status codes, recovery times, and per-path/per-method differences.
    
    BUG-FIX v35: Complete rewrite of rate control logic:
    - Actually sends at target rate (uses inter-request delays instead of
      firing all requests simultaneously with gather)
    - Lowered detection threshold from 50% to 20%
    - Per-path results now influence overall detection
    - Fixed RPS measurement to reflect actual throughput
    """

    # Test paths for per-path rate limiting
    TEST_PATHS = [
        "/", "/api/", "/login",
    ]

    # Overall max duration for the entire rate probe (seconds)
    OVERALL_TIMEOUT = 20

    def __init__(self, url: str, timeout: int = 5, verify_ssl: bool = True):
        """
        Initialize RateLimitProber.

        Args:
            url: Target URL
            timeout: HTTP request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.url = url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._ssl = ssl_param(self.verify_ssl)
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

        t0 = time.monotonic()

        try:
            # Wrap with overall timeout
            result = await asyncio.wait_for(
                self._run_inner(t0), timeout=self.OVERALL_TIMEOUT
            )
            return result
        except asyncio.TimeoutError:
            elapsed = time.monotonic() - t0
            print(f"  {C.Y}    [!] Rate probe hit {self.OVERALL_TIMEOUT}s overall timeout, returning partial results{C.RS}")
            return {
                "rate_limit_detected": False,
                "threshold_rps": 0,
                "block_status_code": 0,
                "recovery_time_seconds": 0.0,
                "per_path_limits": {},
                "timeout_truncated": True,
            }

    async def _run_inner(self, t0: float) -> Dict:
        """Inner run logic, wrapped by overall timeout."""
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

        # BUG-FIX v35: Per-path results can upgrade overall detection
        # If ANY path shows significant rate limiting, mark as detected
        if not rate_result["rate_limit_detected"]:
            for path, info in per_path.items():
                if info.get("get_block_rate", 0) >= 0.2:
                    rate_result["rate_limit_detected"] = True
                    rate_result["threshold_rps"] = 20  # Per-path threshold
                    rate_result["block_status_code"] = info.get("get_status_on_block", 0)
                    print(f"  {C.Y}    [!] Rate limit detected on path {path} "
                          f"({info['get_block_rate']:.0%} blocked){C.RS}")
                    break

        elapsed = time.monotonic() - t0

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
        timeout_cfg = scanner_timeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                t0 = time.monotonic()
                async with session.get(self.url, ssl=self._ssl, allow_redirects=False) as resp:
                    body = await safe_read_text(resp)  # W1.10: bounded read
                    rt = time.monotonic() - t0
                    print(f"  {C.G}    Baseline: HTTP {resp.status} | RT: {rt*1000:.0f}ms | Size: {len(body):,}B{C.RS}")
                    return resp.status, body[:500], rt
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"  {C.Y}    Baseline error: {e}{C.RS}")
            return 200, "", 1.0

    async def _progressive_rate_test(self, baseline_status: int) -> Dict:
        """
        Gradually increase request rate and monitor for blocks.

        BUG-FIX v35: Complete rewrite of rate control:
        - Uses rate-controlled sending (inter-request delays) instead of
          firing all requests simultaneously with gather()
        - Lowered detection threshold from 50% to 20%
        - Sends requests at the actual target rate for accurate detection
        
        The old approach (gather all at once) measured burst throughput,
        NOT rate limiting behavior. The new approach actually tests whether
        the server rate-limits at the specified requests-per-second rate.
        """
        result = {
            "rate_limit_detected": False,
            "threshold_rps": 0,
            "block_status_code": 0,
            "block_body_snippet": "",
        }

        timeout_cfg = scanner_timeout(total=self.timeout)
        # Test rates: 50, 100, 150, 200 RPS
        rps_levels = [50, 100, 150, 200]
        block_detected = False

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            for rps in rps_levels:
                if block_detected:
                    break

                print(f"  {C.CY}    Testing {rps} req/s...{C.RS}")

                block_count = 0
                block_status = 0
                block_body = ""
                total_sent = 0
                t_start = time.monotonic()

                # BUG-FIX v35: Rate-controlled sending
                # Send requests with inter-request delays to achieve target RPS
                # At N RPS, delay between requests = 1/N seconds
                inter_delay = 1.0 / rps
                # Limit total test duration to 3 seconds per rate level
                test_duration = 3.0

                # Create tasks that respect the target rate
                tasks = []
                send_count = int(rps * test_duration)  # Total requests in test_duration
                # Cap at reasonable number to avoid overwhelming the event loop
                send_count = min(send_count, 200)

                # Use semaphore-based rate control
                # Fire requests in batches with delays between batches
                batch_size = max(5, rps // 10)  # 10 batches per second
                num_batches = (send_count + batch_size - 1) // batch_size
                batch_delay = batch_size / rps  # Delay between batches

                for batch_idx in range(num_batches):
                    if block_detected:
                        break

                    batch_start = batch_idx * batch_size
                    batch_end = min(batch_start + batch_size, send_count)
                    batch_tasks = []

                    for i in range(batch_start, batch_end):
                        batch_tasks.append(self._single_request(session))

                    # Fire this batch
                    batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

                    for resp_result in batch_results:
                        if isinstance(resp_result, Exception):
                            continue
                        total_sent += 1
                        status, body = resp_result
                        if self._is_rate_limited(status, body, baseline_status):
                            block_count += 1
                            block_status = status
                            block_body = body[:200] if body else ""

                    # Check if we already have enough evidence (early exit)
                    current_rate = block_count / total_sent if total_sent > 0 else 0
                    if current_rate > 0.5 and total_sent >= 10:
                        # High block rate, no need to continue this level
                        block_detected = True
                        break

                    # Delay between batches to approximate target rate
                    if batch_idx < num_batches - 1:
                        await asyncio.sleep(batch_delay)

                t_elapsed = time.monotonic() - t_start
                # If we didn't send any, skip
                if total_sent == 0:
                    continue

                actual_rps = total_sent / t_elapsed if t_elapsed > 0 else 0
                block_rate = block_count / total_sent if total_sent > 0 else 0

                status_color = C.R if block_rate > 0.3 else C.Y if block_rate > 0 else C.G
                print(
                    f"  {status_color}    RPS: {actual_rps:.1f} | "
                    f"Blocked: {block_count}/{total_sent} ({block_rate:.0%}) | "
                    f"Block status: {block_status or 'N/A'}{C.RS}"
                )

                # BUG-FIX v35: Lowered threshold from 50% to 20%
                # Many CDNs/WAFs use gradual rate limiting starting at low percentages
                # 20% block rate is strong evidence of rate limiting
                if block_rate >= 0.20:
                    block_detected = True
                    result["rate_limit_detected"] = True
                    result["threshold_rps"] = rps
                    result["block_status_code"] = block_status
                    result["block_body_snippet"] = block_body
                    print(f"  {C.R}    [!] Rate limit detected at ~{rps} req/s "
                          f"({block_rate:.0%} blocked){C.RS}")
                    break

                # Wait before next rate level if we saw some blocks
                if block_count > 0:
                    await asyncio.sleep(0.5)

        if not block_detected:
            print(f"  {C.G}    No rate limit detected up to {rps_levels[-1]} req/s{C.RS}")

        return result

    async def _single_request(
        self, session: aiohttp.ClientSession
    ) -> Tuple[int, str]:
        """Send a single GET request and return status + body snippet."""
        try:
            async with session.get(
                self.url, ssl=self._ssl, allow_redirects=False
            ) as resp:
                body = await safe_read_text(resp)  # W1.10: bounded read
                return resp.status, body[:500]
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return 0, ""

    def _is_rate_limited(
        self, status: int, body: str, baseline_status: int
    ) -> bool:
        """Check if a response indicates rate limiting.
        
        BUG-FIX v35: Handle redirect baselines properly.
        If baseline is 3xx, we should NOT consider a different 3xx as
        rate limiting. Only 429, 503, 508, or status >= 400 when baseline
        was < 400 indicates rate limiting.
        """
        # Common rate limit status codes
        if status in (429, 503, 508):
            return True

        # Status code change from baseline
        # BUG-FIX v35: Only consider it rate limiting if baseline was
        # successful (< 400) and we get an error (>= 400)
        # Do NOT flag different redirect codes or 0 (connection error) as rate limiting
        if status == 0:
            # Connection error / timeout — could be rate limiting but also
            # could be network issues. Count it only if we already have
            # evidence from other responses (don't false-positive on timeouts)
            return False
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

        v16: Uses faster 1s intervals with 10s max (was 2-12s intervals, 30s max).
        Returns recovery time in seconds.
        """
        timeout_cfg = scanner_timeout(total=self.timeout)
        recovery_time = 0.0

        check_interval = 1

        print(f"  {C.Y}    Waiting and checking for recovery...{C.RS}")

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            max_wait = 10
            waited = 0

            while waited < max_wait:
                await asyncio.sleep(check_interval)
                waited += check_interval

                # Send a test request
                try:
                    async with session.get(
                        self.url, ssl=self._ssl, allow_redirects=False
                    ) as resp:
                        body = await safe_read_text(resp)  # W1.10: bounded read
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
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

            if waited >= max_wait:
                recovery_time = float(max_wait)
                print(f"  {C.R}    Did not recover within {max_wait}s{C.RS}")

        return recovery_time

    async def _test_per_path_limits(self, baseline_status: int) -> Dict:
        """Test rate limits on different paths and methods (in parallel).
        
        BUG-FIX v35: Also test POST for login-related paths since
        many sites only rate-limit POST requests (login attempts).
        """
        results = {}
        timeout_cfg = scanner_timeout(total=self.timeout)

        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            # v35: Test both GET and POST for more complete detection
            tasks = []
            task_paths = []
            for path in self.TEST_PATHS:
                url = f"{self.base_url}{path}"
                # GET test
                # FIX-9: Use DEFAULT_RATE_PROBE_REQUESTS instead of hardcoded 20
                tasks.append(self._test_path_method(
                    session, url, "GET", baseline_status,
                    rps=DEFAULT_RATE_PROBE_REQUESTS, duration=1
                ))
                task_paths.append((path, "GET"))
                # POST test (important for login/api paths)
                tasks.append(self._test_path_method(
                    session, url, "POST", baseline_status,
                    rps=DEFAULT_RATE_PROBE_REQUESTS, duration=1
                ))
                task_paths.append((path, "POST"))

            all_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Assemble results per path
            for (path, method), res in zip(task_paths, all_results):
                if isinstance(res, Exception):
                    res = {"blocked": False, "block_rate": 0.0, "block_status": 0}

                if path not in results:
                    results[path] = {
                        "get_blocked": False,
                        "get_block_rate": 0.0,
                        "get_status_on_block": 0,
                        "post_blocked": False,
                        "post_block_rate": 0.0,
                        "post_status_on_block": 0,
                    }

                if method == "GET":
                    results[path]["get_blocked"] = res["blocked"]
                    results[path]["get_block_rate"] = res["block_rate"]
                    results[path]["get_status_on_block"] = res["block_status"]
                else:
                    results[path]["post_blocked"] = res["blocked"]
                    results[path]["post_block_rate"] = res["block_rate"]
                    results[path]["post_status_on_block"] = res["block_status"]

            # Print status for each path
            for path in self.TEST_PATHS:
                if path not in results:
                    continue
                info = results[path]
                get_str = f"{C.R}GET:{info['get_block_rate']:.0%}{C.RS}" if info.get("get_blocked") else f"{C.G}GET:ok{C.RS}"
                post_str = f"{C.R}POST:{info['post_block_rate']:.0%}{C.RS}" if info.get("post_blocked") else f"{C.G}POST:ok{C.RS}"

                print(f"  {C.DM}    {path:<20}{C.RS} {get_str} | {post_str}")

        return results

    async def _test_path_method(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        baseline_status: int,
        rps: int = DEFAULT_RATE_PROBE_REQUESTS,
        duration: int = 1
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

        # BUG-FIX v35: Send in smaller batches with delays for rate control
        batch_size = max(5, rps // 5)
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)

            for resp_result in results:
                if isinstance(resp_result, Exception):
                    continue
                status, body = resp_result
                if self._is_rate_limited(status, body, baseline_status):
                    block_count += 1
                    block_status = status

            if i + batch_size < len(tasks):
                await asyncio.sleep(0.2)

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
                async with session.get(url, ssl=self._ssl, allow_redirects=False) as resp:
                    body = await safe_read_text(resp)  # W1.10: bounded read
                    return resp.status, body[:500]
            elif method == "POST":
                async with session.post(
                    url, data={"test": "probe"},
                    ssl=self._ssl, allow_redirects=False
                ) as resp:
                    body = await safe_read_text(resp)  # W1.10: bounded read
                    return resp.status, body[:500]
        except (aiohttp.ClientError, asyncio.TimeoutError):
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
            print(f"  {C.G}  ║  No rate limit detected up to 200 RPS                  ║{C.RS}")

        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Per-Path Results:                                    ║{C.RS}")
        for path, info in per_path.items():
            get_str = f"GET:{info['get_block_rate']:.0%}" if info['get_blocked'] else "GET:ok"
            post_str = f"POST:{info['post_block_rate']:.0%}" if info['post_blocked'] else "POST:ok"
            print(f"  {C.G}  ║{C.RS}  {C.W}{path:<20}{C.RS} {get_str} | {post_str}")

        print(f"  {C.G}  ╠════════════════════════════════════════════════════════╣{C.RS}")
        print(f"  {C.G}  ║  Total Time: {C.CY}{elapsed:.1f}s{C.RS}")
        print(f"  {C.G}  ╚════════════════════════════════════════════════════════╝{C.RS}")
