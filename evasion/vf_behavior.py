#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Behavioral Mimic — VF_EVASION Module                                   ║
║  Make attack traffic look like real user browsing                       ║
║                                                                          ║
║  WAFs detect bot traffic by timing patterns. Real users:                 ║
║  - Load a page, then resources, then pause to "read"                    ║
║  - Have correlated request sequences (page → CSS → JS → images → API)  ║
║  - Have log-normal timing (not uniform random)                          ║
║  - Occasionally have long pauses (reading) or rapid-fire actions        ║
║                                                                          ║
║  This module simulates realistic user behavior patterns to make         ║
║  attack traffic indistinguishable from real browsing.                   ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import math
import random
import time
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin


# ═══════════════════════════════════════════════════════════════════════════════
# Color Codes
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# User Behavior Phase Enum
# ═══════════════════════════════════════════════════════════════════════════════

class BehaviorPhase(Enum):
    PAGE_LOAD = "page_load"           # GET main HTML page
    CSS_LOAD = "css_load"             # Load CSS resources
    JS_LOAD = "js_load"               # Load JS resources
    IMAGE_LOAD = "image_load"         # Load images
    API_CALL = "api_call"             # JS-triggered API call
    READING = "reading"               # User reading/pausing
    NAVIGATE = "navigate"             # Navigate to another page
    RAPID_CLICK = "rapid_click"       # Rapid-fire clicking
    SESSION_END = "session_end"       # End of user session


# ═══════════════════════════════════════════════════════════════════════════════
# Simulated User Session
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SimulatedUser:
    """A simulated user with a browsing pattern."""
    user_id: int = 0
    page_views: int = 0
    max_page_views: int = 0
    current_phase: BehaviorPhase = BehaviorPhase.PAGE_LOAD
    previous_page: str = "/"
    current_page: str = "/"
    session_start: float = 0.0
    last_request_time: float = 0.0
    pages_in_session: List[str] = field(default_factory=list)

    @property
    def session_complete(self) -> bool:
        return self.page_views >= self.max_page_views


# ═══════════════════════════════════════════════════════════════════════════════
# Behavioral Mimic
# ═══════════════════════════════════════════════════════════════════════════════

class BehavioralMimic:
    """
    Behavioral Mimicry — make attack traffic look like real user browsing.

    Simulates realistic user behavior patterns:
    1. GET homepage (500-2000ms delay)
    2. Load CSS resources (100-300ms after page load)
    3. Load JS resources (200-500ms after page load)
    4. Load images (300-800ms after page load)
    5. Scroll/click simulation → GET another page (2000-5000ms delay)
    6. API calls from JS (500-1500ms after page load)
    7. Pause and "read" (3000-10000ms)
    8. Navigate to another page → repeat

    Generates natural timing with log-normal distribution for delays,
    correlated requests, occasional long pauses, and occasional rapid-fire
    actions. WAF sees natural browsing patterns, not bot-like uniform timing.
    """

    def __init__(self, url: str, page_targets: List[str], resource_targets: List[str]):
        """
        Args:
            url: Target URL
            page_targets: List of page paths to simulate browsing (e.g. ["/", "/about", "/contact"])
            resource_targets: List of resource paths to simulate loading (e.g. ["/style.css", "/app.js"])
        """
        self.url = url
        parsed = urlparse(url)
        self.domain = parsed.netloc.split(':')[0]
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

        self.page_targets = page_targets or ["/"]
        self.resource_targets = resource_targets or []

        # User session tracking
        self._users: Dict[int, SimulatedUser] = {}
        self._next_user_id: int = 0
        self._max_pages_per_session: Tuple[int, int] = (10, 30)  # Random range

        # Response learning
        self._response_history: List[Dict] = []
        self._avg_response_time: float = 1.0
        self._block_rate: float = 0.0
        self._total_requests: int = 0
        self._blocked_requests: int = 0

        # Timing calibration based on network (Iran internet)
        self._network_latency_base: float = 0.3  # Base latency for Iran
        self._timing_multiplier: float = 1.0

    def get_next_action(self) -> Dict:
        """
        Get the next simulated user action.

        Returns:
            Dict with keys:
                method: str      — HTTP method (GET, POST, etc.)
                path: str        — URL path
                headers: dict    — Headers for this request
                delay: float     — Delay in seconds before this request
                description: str — Human-readable description of the action
        """
        # Get or create a user for this action
        user = self._get_active_user()

        if user.session_complete:
            # Start a new user session
            user = self._start_new_user()

        action = self._generate_action(user)
        return action

    def _get_active_user(self) -> SimulatedUser:
        """Get an active user or create one if none exists."""
        # Find a user that hasn't completed their session
        for user in self._users.values():
            if not user.session_complete:
                return user

        # All users completed, start a new one
        return self._start_new_user()

    def _start_new_user(self) -> SimulatedUser:
        """Start a new simulated user session."""
        user_id = self._next_user_id
        self._next_user_id += 1

        max_pages = random.randint(*self._max_pages_per_session)

        user = SimulatedUser(
            user_id=user_id,
            max_page_views=max_pages,
            current_phase=BehaviorPhase.PAGE_LOAD,
            previous_page="/",
            current_page="/",
            session_start=time.time(),
            last_request_time=time.time(),
        )

        self._users[user_id] = user

        # Keep only last 50 users in memory
        if len(self._users) > 50:
            oldest = min(self._users.keys())
            del self._users[oldest]

        print(f"  {C.DM}[BEHAVIOR] New user #{user_id} — session of {max_pages} page views{C.RS}")

        return user

    def _generate_action(self, user: SimulatedUser) -> Dict:
        """
        Generate the next action for a user based on their current phase.

        Simulates the natural flow of a browsing session.
        """
        phase = user.current_phase

        if phase == BehaviorPhase.PAGE_LOAD:
            return self._action_page_load(user)
        elif phase == BehaviorPhase.CSS_LOAD:
            return self._action_resource_load(user, "css", BehaviorPhase.JS_LOAD)
        elif phase == BehaviorPhase.JS_LOAD:
            return self._action_resource_load(user, "js", BehaviorPhase.IMAGE_LOAD)
        elif phase == BehaviorPhase.IMAGE_LOAD:
            return self._action_resource_load(user, "img", BehaviorPhase.API_CALL)
        elif phase == BehaviorPhase.API_CALL:
            return self._action_api_call(user)
        elif phase == BehaviorPhase.READING:
            return self._action_reading(user)
        elif phase == BehaviorPhase.NAVIGATE:
            return self._action_navigate(user)
        elif phase == BehaviorPhase.RAPID_CLICK:
            return self._action_rapid_click(user)
        elif phase == BehaviorPhase.SESSION_END:
            return self._action_session_end(user)
        else:
            return self._action_page_load(user)

    def _action_page_load(self, user: SimulatedUser) -> Dict:
        """Simulate loading a page."""
        # Choose a page to visit
        if user.page_views == 0:
            path = "/"
        else:
            path = random.choice(self.page_targets)

        user.current_page = path
        user.page_views += 1

        # Transition to CSS load phase after page
        user.current_phase = BehaviorPhase.CSS_LOAD

        # Delay for initial page load
        delay = self._log_normal_delay(1.0, 0.5)  # 500-2000ms typical

        return {
            "method": "GET",
            "path": path,
            "headers": self._page_headers(user),
            "delay": delay,
            "description": f"User #{user.user_id} loads page {path}",
        }

    def _action_resource_load(self, user: SimulatedUser, resource_type: str,
                               next_phase: BehaviorPhase) -> Dict:
        """Simulate loading a CSS/JS/image resource."""
        # Pick a resource path or generate one
        matching = [r for r in self.resource_targets if resource_type in r.lower()]

        if matching:
            path = random.choice(matching)
        else:
            # Generate plausible resource paths
            if resource_type == "css":
                path = random.choice([
                    "/static/css/style.css",
                    "/assets/css/main.css",
                    "/css/app.css",
                    f"/static/css/{random.randint(1,5)}.css",
                ])
            elif resource_type == "js":
                path = random.choice([
                    "/static/js/app.js",
                    "/assets/js/main.js",
                    "/js/chunk.js",
                    f"/static/js/{random.randint(1,5)}.js",
                ])
            else:  # img
                path = random.choice([
                    "/static/img/logo.png",
                    "/assets/images/hero.jpg",
                    "/images/banner.webp",
                    f"/img/photo{random.randint(1,10)}.jpg",
                ])

        # Transition phase
        user.current_phase = next_phase

        # Timing: resources load after page with specific delays
        if resource_type == "css":
            delay = self._log_normal_delay(0.15, 0.08)  # 100-300ms
        elif resource_type == "js":
            delay = self._log_normal_delay(0.3, 0.15)   # 200-500ms
        else:  # img
            delay = self._log_normal_delay(0.5, 0.25)   # 300-800ms

        return {
            "method": "GET",
            "path": path,
            "headers": self._resource_headers(user, resource_type),
            "delay": delay,
            "description": f"User #{user.user_id} loads {resource_type}: {path}",
        }

    def _action_api_call(self, user: SimulatedUser) -> Dict:
        """Simulate a JS-triggered API call."""
        # Decide what happens next: read, navigate, or rapid-click
        r = random.random()

        if r < 0.5:
            user.current_phase = BehaviorPhase.READING
        elif r < 0.8:
            user.current_phase = BehaviorPhase.NAVIGATE
        elif r < 0.95:
            user.current_phase = BehaviorPhase.RAPID_CLICK
        else:
            user.current_phase = BehaviorPhase.SESSION_END

        # API paths
        api_path = random.choice([
            f"/api/v1/data?page={random.randint(1, 10)}",
            f"/api/stats?_={int(time.time() * 1000)}",
            f"/api/user/me",
            f"/api/content?category={random.choice(['news', 'blog', 'products'])}",
            f"/api/search?q={random.choice(['test', 'hello', 'data'])}",
        ])

        # API calls happen 500-1500ms after page load
        delay = self._log_normal_delay(0.8, 0.4)

        return {
            "method": "GET",
            "path": api_path,
            "headers": self._api_headers(user),
            "delay": delay,
            "description": f"User #{user.user_id} API call: {api_path}",
        }

    def _action_reading(self, user: SimulatedUser) -> Dict:
        """Simulate user reading a page — long pause then navigate."""
        user.current_phase = BehaviorPhase.NAVIGATE

        # Long pause: 3000-10000ms, log-normal
        delay = self._log_normal_delay(5.0, 3.0)
        delay = min(delay, 15.0)  # Cap at 15 seconds

        # During reading, no request is sent — just delay
        # Return a "no-op" that just adds delay before next navigation
        return {
            "method": "GET",
            "path": user.current_page,  # Re-request same page (user scrolled)
            "headers": self._page_headers(user),
            "delay": delay,
            "description": f"User #{user.user_id} reading {user.current_page} ({delay:.1f}s pause)",
        }

    def _action_navigate(self, user: SimulatedUser) -> Dict:
        """Simulate navigating to another page."""
        user.previous_page = user.current_page

        # Pick a new page
        path = random.choice(self.page_targets)
        user.current_page = path

        user.current_phase = BehaviorPhase.PAGE_LOAD
        user.page_views += 1

        # Navigation delay: 2000-5000ms
        delay = self._log_normal_delay(3.0, 1.0)

        return {
            "method": "GET",
            "path": path,
            "headers": self._page_headers(user),
            "delay": delay,
            "description": f"User #{user.user_id} navigates to {path}",
        }

    def _action_rapid_click(self, user: SimulatedUser) -> Dict:
        """Simulate rapid-fire clicking — user quickly browsing multiple pages."""
        user.previous_page = user.current_page
        path = random.choice(self.page_targets)
        user.current_page = path
        user.page_views += 1

        # 50% chance another rapid click, 50% settle into reading
        if random.random() < 0.5 and not user.session_complete:
            user.current_phase = BehaviorPhase.RAPID_CLICK
        else:
            user.current_phase = BehaviorPhase.READING

        # Rapid: 200-800ms
        delay = self._log_normal_delay(0.4, 0.15)

        return {
            "method": "GET",
            "path": path,
            "headers": self._page_headers(user),
            "delay": delay,
            "description": f"User #{user.user_id} rapid-click → {path}",
        }

    def _action_session_end(self, user: SimulatedUser) -> Dict:
        """End of user session — start a new user."""
        # Mark user as complete
        user.page_views = user.max_page_views

        # Start a new user
        new_user = self._start_new_user()
        new_user.current_phase = BehaviorPhase.PAGE_LOAD

        return {
            "method": "GET",
            "path": "/",
            "headers": self._page_headers(new_user),
            "delay": self._log_normal_delay(2.0, 1.0),
            "description": f"User #{user.user_id} session ended, new user #{new_user.user_id}",
        }

    def _page_headers(self, user: SimulatedUser) -> Dict[str, str]:
        """Headers for a page request (document navigation)."""
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.9", "fa-IR,fa;q=0.9,en;q=0.8"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": urljoin(self.base_url, user.previous_page),
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Cache-Control": "max-age=0",
        }
        return headers

    def _resource_headers(self, user: SimulatedUser, resource_type: str) -> Dict[str, str]:
        """Headers for a resource request (CSS/JS/image)."""
        dest_map = {
            "css": "style",
            "js": "script",
            "img": "image",
        }

        accept_map = {
            "css": "text/css,*/*;q=0.1",
            "js": "*/*",
            "img": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
        }

        headers = {
            "Accept": accept_map.get(resource_type, "*/*"),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": urljoin(self.base_url, user.current_page),
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Dest": dest_map.get(resource_type, "empty"),
        }
        return headers

    def _api_headers(self, user: SimulatedUser) -> Dict[str, str]:
        """Headers for an API call (XHR/fetch)."""
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": urljoin(self.base_url, user.current_page),
            "X-Requested-With": "XMLHttpRequest",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
        }
        return headers

    def _log_normal_delay(self, mean: float, sigma: float) -> float:
        """
        Generate a delay from a log-normal distribution.

        Real user timing follows log-normal, not uniform random.
        This produces natural-looking delays with occasional outliers.

        Args:
            mean: Mean delay in seconds
            sigma: Standard deviation (log scale)

        Returns:
            Delay in seconds (minimum 0.05s)
        """
        # Log-normal: exp(normal(log(mean), sigma))
        mu = math.log(max(mean, 0.01))
        delay = random.gauss(mu, sigma)
        delay = math.exp(delay)

        # Add network latency for Iran
        delay += self._network_latency_base * random.uniform(0.5, 1.5)

        # Apply timing multiplier (adjusted based on server response)
        delay *= self._timing_multiplier

        # Clamp to reasonable range
        delay = max(0.05, min(delay, 20.0))

        return delay

    def record_response(self, status: int, body_len: int, rt: float):
        """
        Learn from server responses to calibrate behavior.

        Args:
            status: HTTP status code
            body_len: Response body length in bytes
            rt: Response time in seconds
        """
        self._total_requests += 1

        # Track blocking (ArvanCloud: 403/429/500/503)
        is_blocked = status in (403, 429, 500, 503)
        if is_blocked:
            self._blocked_requests += 1

        # Update block rate
        self._block_rate = self._blocked_requests / max(self._total_requests, 1)

        # Update average response time
        self._avg_response_time = (
            self._avg_response_time * 0.9 + rt * 0.1
        )

        # Adjust timing based on blocking
        if self._block_rate > 0.5:
            # Being blocked a lot — slow down (look more human)
            self._timing_multiplier = min(3.0, self._timing_multiplier * 1.05)
        elif self._block_rate < 0.1:
            # Not being blocked — can speed up
            self._timing_multiplier = max(0.5, self._timing_multiplier * 0.98)

        # Record for analysis
        self._response_history.append({
            "status": status,
            "body_len": body_len,
            "rt": rt,
            "blocked": is_blocked,
            "ts": time.time(),
        })

        # Keep last 1000 responses
        if len(self._response_history) > 1000:
            self._response_history = self._response_history[-500:]

    def get_session_timing(self) -> float:
        """
        Get natural delay for next request based on current session state.

        Returns:
            Delay in seconds
        """
        # Base delay depends on current phase
        base = self._log_normal_delay(1.5, 0.8)

        # Adjust for network conditions
        if self._avg_response_time > 3.0:
            # Server is slow — user would naturally wait longer
            base *= 1.5
        elif self._avg_response_time < 0.3:
            # Server is fast — user browses faster
            base *= 0.8

        return base

    @property
    def active_users(self) -> int:
        """Number of active simulated users."""
        return sum(1 for u in self._users.values() if not u.session_complete)

    @property
    def current_phase_description(self) -> str:
        """Description of current behavior phase."""
        for user in self._users.values():
            if not user.session_complete:
                return f"User #{user.user_id}: {user.current_phase.value} (page {user.page_views}/{user.max_page_views})"
        return "No active users"

    def get_stats(self) -> Dict:
        """Get behavioral mimic statistics."""
        return {
            "total_requests": self._total_requests,
            "blocked_requests": self._blocked_requests,
            "block_rate": self._block_rate,
            "avg_response_time": self._avg_response_time,
            "timing_multiplier": self._timing_multiplier,
            "active_users": self.active_users,
            "total_sessions": self._next_user_id,
            "current_phase": self.current_phase_description,
        }
