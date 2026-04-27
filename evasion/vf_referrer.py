#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  Referrer Chain Spoofer — VF_EVASION Module                             ║
║  Make requests look like they come from organic sources                 ║
║                                                                          ║
║  WAFs and CDN rate-limiters may treat traffic differently based on      ║
║  the Referer header. Traffic from search engines (Google, Bing) is      ║
║  typically not rate-limited because it represents organic visitors.     ║
║                                                                          ║
║  This module:                                                            ║
║  - Generates realistic Referer headers from multiple sources            ║
║  - Supports search engines, social media, direct traffic, internal      ║
║  - Generates realistic search queries in Persian and English            ║
║  - Includes proper query parameters (utm_source, fbclid, gclid, etc.)  ║
║  - Rotates between sources with realistic distribution                  ║
║  - Each request gets a consistent "browsing session" referrer chain    ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import random
import string
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field


# ═══════════════════════════════════════════════════════════════════════════════
# Color Codes
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# Referrer Source Types
# ═══════════════════════════════════════════════════════════════════════════════

class ReferrerSource(Enum):
    GOOGLE = "google"
    GOOGLE_IRAN = "google_iran"
    BING = "bing"
    YAHOO = "yahoo"
    DUCKDUCKGO = "duckduckgo"
    TWITTER = "twitter"
    FACEBOOK = "facebook"
    LINKEDIN = "linkedin"
    TELEGRAM = "telegram"
    DIRECT = "direct"
    INTERNAL = "internal"


# ═══════════════════════════════════════════════════════════════════════════════
# Search Queries Database
# ═══════════════════════════════════════════════════════════════════════════════

# Realistic search queries in Persian (Iranian users)
PERSIAN_QUERIES = [
    "خرید آنلاین",          # online shopping
    "قیمت دلار امروز",      # dollar price today
    "آموزش برنامه نویسی",   # programming tutorial
    "بهترین گوشی ۱۴۰۳",     # best phone 2024
    "دانلود فیلم",          # download movie
    "اخبار ایران",          # Iran news
    "پزشک متخصص تهران",     # specialist doctor tehran
    "رستوران خوب اصفهان",   # good restaurant isfahan
    "بلیط هواپیما",         # plane ticket
    "مشاوره حقوقی",         # legal consultation
    "دوره آموزشی",          # training course
    "بانک و خدمات مالی",    # bank and financial services
    "سیستم عامل ویندوز",    # windows operating system
    "طراحی سایت",           # web design
    "هاست و دامنه",         # host and domain
    "سرور مجازی",           # virtual server
    "امنیت سایبری",         # cybersecurity
    "سئو سایت",             # website SEO
    "فروشگاه اینترنتی",     # online store
    "اپلیکیشن موبایل",      # mobile application
]

# English search queries (also common in Iran)
ENGLISH_QUERIES = [
    "best vpn for iran",
    "python tutorial",
    "web hosting cheap",
    "cloudflare alternatives",
    "cdn services comparison",
    "website optimization",
    "api testing tools",
    "linux server setup",
    "nginx configuration",
    "docker tutorial",
    "react vs vue",
    "database design",
    "ssl certificate free",
    "email hosting services",
    "domain registration",
    "backup solutions",
    "monitoring tools",
    "load balancer setup",
    "caching strategies",
    "security best practices",
]

# Telegram channel names (for telegram referrer)
TELEGRAM_CHANNELS = [
    "iran_tech", "digital_market", "tech_news_ir",
    "programming_fa", "web_dev_ir", "startup_iran",
    "crypto_iran", "security_fa", "linux_ir",
    "python_fa", "hosting_ir", "devops_fa",
]


# ═══════════════════════════════════════════════════════════════════════════════
# Source Distribution (realistic web traffic distribution)
# ═══════════════════════════════════════════════════════════════════════════════

SOURCE_DISTRIBUTION = {
    ReferrerSource.GOOGLE: 0.30,
    ReferrerSource.GOOGLE_IRAN: 0.10,
    ReferrerSource.DIRECT: 0.15,
    ReferrerSource.TWITTER: 0.05,
    ReferrerSource.FACEBOOK: 0.05,
    ReferrerSource.TELEGRAM: 0.05,
    ReferrerSource.LINKEDIN: 0.03,
    ReferrerSource.BING: 0.08,
    ReferrerSource.YAHOO: 0.04,
    ReferrerSource.DUCKDUCKGO: 0.05,
    ReferrerSource.INTERNAL: 0.10,
}


# ═══════════════════════════════════════════════════════════════════════════════
# Referrer Chain Spoofer
# ═══════════════════════════════════════════════════════════════════════════════

class ReferrerChainSpoofer:
    """
    Referrer Chain Spoofing — make requests look like they come from organic sources.

    Generates realistic Referer headers from multiple sources:
    - Google search (with realistic query parameters)
    - Google Iran (Persian language)
    - Bing, Yahoo, DuckDuckGo
    - Social media: Twitter/X, Facebook, LinkedIn, Telegram
    - Direct traffic (no Referer)
    - Internal referral (from target domain)

    For search engines, generates realistic search queries in Persian and English.
    Includes proper query parameters for each source (utm_source, fbclid, gclid, etc.)
    Rotates between sources with realistic distribution (40% Google, 15% Direct, etc.)
    """

    def __init__(self, target_domain: str):
        """
        Args:
            target_domain: The target domain (e.g. "example.com")
        """
        self.target_domain = target_domain

        # Current session state
        self._current_source: ReferrerSource = ReferrerSource.GOOGLE
        self._session_source: Optional[ReferrerSource] = None  # Fixed source for current "session"
        self._session_request_count: int = 0
        self._session_max_requests: int = random.randint(3, 15)
        self._previous_path: str = "/"
        self._current_query: str = ""

        # Statistics
        self._source_counts: Dict[str, int] = {s.value: 0 for s in ReferrerSource}
        self._total_referers_generated: int = 0

        # Pre-built weighted list for fast sampling
        self._weighted_sources: List[ReferrerSource] = []
        for source, weight in SOURCE_DISTRIBUTION.items():
            count = int(weight * 100)
            self._weighted_sources.extend([source] * count)

    def get_referer(self, path: str = "/") -> str:
        """
        Generate a realistic Referer header.

        Args:
            path: Current request path (used for internal referrals)

        Returns:
            Realistic Referer header string
        """
        self._check_session_rotation()

        # Use session source if active, otherwise pick new
        if self._session_source and self._session_request_count < self._session_max_requests:
            source = self._session_source
            self._session_request_count += 1
        else:
            source = self._pick_source()
            self._session_source = source
            self._session_request_count = 1
            self._session_max_requests = random.randint(3, 15)

        self._current_source = source
        self._source_counts[source.value] += 1
        self._total_referers_generated += 1
        self._previous_path = path

        referer = self._build_referer(source, path)

        return referer

    def get_full_headers(self, path: str = "/") -> Dict[str, str]:
        """
        Get full headers with spoofed referrer chain.

        Includes Referer, appropriate UTM/tracking parameters,
        and browser-like headers.

        Args:
            path: Current request path

        Returns:
            Dict of headers with spoofed referrer
        """
        referer = self.get_referer(path)
        headers = self._build_full_headers(referer, path)
        return headers

    def rotate_source(self):
        """
        Rotate to a different referrer source.

        Explicitly forces a source rotation, breaking the current
        "session" and starting a new one.
        """
        self._session_source = None
        self._session_request_count = 0

        # Pick a new source, weighted
        self._current_source = self._pick_source()
        self._session_source = self._current_source
        self._session_request_count = 0

        print(f"  {C.DM}[REFERRER] Rotated to source: {self._current_source.value}{C.RS}")

    def _pick_source(self) -> ReferrerSource:
        """Pick a source based on realistic distribution."""
        return random.choice(self._weighted_sources)

    def _check_session_rotation(self):
        """Check if the current "browsing session" should rotate source."""
        if self._session_request_count >= self._session_max_requests:
            self._session_source = None
            self._session_request_count = 0
            self._session_max_requests = random.randint(3, 15)

    def _build_referer(self, source: ReferrerSource, path: str) -> str:
        """Build a realistic Referer URL for the given source."""
        query = self._random_query()

        if source == ReferrerSource.GOOGLE:
            return self._google_referer(query)

        elif source == ReferrerSource.GOOGLE_IRAN:
            return self._google_iran_referer(query)

        elif source == ReferrerSource.BING:
            return self._bing_referer(query)

        elif source == ReferrerSource.YAHOO:
            return self._yahoo_referer(query)

        elif source == ReferrerSource.DUCKDUCKGO:
            return self._duckduckgo_referer(query)

        elif source == ReferrerSource.TWITTER:
            return self._twitter_referer()

        elif source == ReferrerSource.FACEBOOK:
            return self._facebook_referer()

        elif source == ReferrerSource.LINKEDIN:
            return self._linkedin_referer()

        elif source == ReferrerSource.TELEGRAM:
            return self._telegram_referer()

        elif source == ReferrerSource.DIRECT:
            # Direct traffic — no Referer
            return ""

        elif source == ReferrerSource.INTERNAL:
            return self._internal_referer(path)

        return ""

    def _google_referer(self, query: str) -> str:
        """Google search referrer."""
        encoded_q = urllib.parse.quote_plus(query)
        # Google uses various URL patterns
        variant = random.random()
        if variant < 0.6:
            # Standard search
            return f"https://www.google.com/search?q={encoded_q}"
        elif variant < 0.8:
            # With source and client parameters
            return (f"https://www.google.com/search?q={encoded_q}"
                    f"&source=hp&ei={self._random_ei()}")
        else:
            # With UTM parameters
            return (f"https://www.google.com/search?q={encoded_q}"
                    f"&source=web&gws_rd=ssl")

    def _google_iran_referer(self, query: str) -> str:
        """Google Iran search referrer (Persian language)."""
        encoded_q = urllib.parse.quote_plus(query)
        return (f"https://www.google.com/search?q={encoded_q}"
                f"&hl=fa&source=hp&ei={self._random_ei()}")

    def _bing_referer(self, query: str) -> str:
        """Bing search referrer."""
        encoded_q = urllib.parse.quote_plus(query)
        return f"https://www.bing.com/search?q={encoded_q}&form=QBLH"

    def _yahoo_referer(self, query: str) -> str:
        """Yahoo search referrer."""
        encoded_q = urllib.parse.quote_plus(query)
        return f"https://search.yahoo.com/search?p={encoded_q}&fr=yfp-t"

    def _duckduckgo_referer(self, query: str) -> str:
        """DuckDuckGo search referrer."""
        encoded_q = urllib.parse.quote_plus(query)
        return f"https://duckduckgo.com/?q={encoded_q}&ia=web"

    def _twitter_referer(self) -> str:
        """Twitter/X referrer."""
        variant = random.random()
        if variant < 0.5:
            return "https://t.co/" + self._random_path(6)
        elif variant < 0.8:
            return "https://twitter.com/"
        else:
            return "https://x.com/"

    def _facebook_referer(self) -> str:
        """Facebook referrer."""
        variant = random.random()
        if variant < 0.5:
            return "https://www.facebook.com/"
        elif variant < 0.8:
            return "https://l.facebook.com/" + self._random_path(12)
        else:
            return "https://m.facebook.com/"

    def _linkedin_referer(self) -> str:
        """LinkedIn referrer."""
        variant = random.random()
        if variant < 0.6:
            return "https://www.linkedin.com/"
        else:
            return "https://www.linkedin.com/feed/"

    def _telegram_referer(self) -> str:
        """Telegram referrer (common in Iran)."""
        channel = random.choice(TELEGRAM_CHANNELS)
        variant = random.random()
        if variant < 0.7:
            return f"https://t.me/{channel}"
        else:
            return f"https://t.me/s/{channel}"  # Public channel preview

    def _internal_referer(self, current_path: str) -> str:
        """Internal referral (from within the target domain)."""
        # Pick a different page than current
        internal_paths = ["/", "/about", "/contact", "/blog", "/products",
                          "/services", "/faq", "/support", "/news"]
        path = random.choice([p for p in internal_paths if p != current_path] or ["/"])
        return f"https://{self.target_domain}{path}"

    def _random_query(self) -> str:
        """Generate a realistic search query (Persian or English)."""
        if random.random() < 0.6:
            # Persian query (more common for Iranian users)
            query = random.choice(PERSIAN_QUERIES)
        else:
            # English query
            query = random.choice(ENGLISH_QUERIES)

        # Sometimes append site-specific terms
        if random.random() < 0.3:
            query += " " + self.target_domain.replace(".ir", "").replace(".com", "")

        self._current_query = query
        return query

    def _random_ei(self) -> str:
        """Generate a random Google 'ei' parameter (looks like base64-ish)."""
        chars = string.ascii_letters + string.digits + "_-"
        return ''.join(random.choices(chars, k=random.randint(16, 24)))

    def _random_path(self, length: int) -> str:
        """Generate a random URL path segment."""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choices(chars, k=length))

    def _build_full_headers(self, referer: str, path: str) -> Dict[str, str]:
        """
        Build complete headers with spoofed referrer and tracking parameters.

        Includes proper UTM parameters, click IDs, and browser headers.
        """
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
        }

        # Add Referer if not direct traffic
        if referer:
            headers["Referer"] = referer

        # Add source-specific headers and parameters
        source = self._current_source

        if source == ReferrerSource.GOOGLE:
            # Google organic → gclid sometimes present (for ads)
            if random.random() < 0.2:
                headers["X-Goog-Source"] = "organic"
            # Sec-Fetch headers for navigation from search
            headers["Sec-Fetch-Site"] = "cross-site"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Dest"] = "document"

        elif source == ReferrerSource.TWITTER:
            headers["Sec-Fetch-Site"] = "cross-site"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Dest"] = "document"

        elif source == ReferrerSource.FACEBOOK:
            headers["Sec-Fetch-Site"] = "cross-site"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Dest"] = "document"

        elif source == ReferrerSource.INTERNAL:
            headers["Sec-Fetch-Site"] = "same-origin"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-User"] = "?1"

        elif source == ReferrerSource.DIRECT:
            # Direct traffic — no Referer, no Sec-Fetch-Site
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-User"] = "?1"

        else:
            # Other search engines and social
            headers["Sec-Fetch-Site"] = "cross-site"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Dest"] = "document"

        return headers

    def get_utm_params(self, path: str = "/") -> Dict[str, str]:
        """
        Generate UTM/tracking parameters appropriate for the current source.

        Returns:
            Dict of UTM parameters to append to the URL
        """
        source = self._current_source
        params = {}

        if source == ReferrerSource.GOOGLE:
            if random.random() < 0.3:
                # Google Ads click
                params["gclid"] = "CjwKCAjw_" + self._random_path(20)
            params["utm_source"] = "google"
            params["utm_medium"] = "organic"

        elif source == ReferrerSource.GOOGLE_IRAN:
            params["utm_source"] = "google"
            params["utm_medium"] = "organic"
            params["hl"] = "fa"

        elif source == ReferrerSource.BING:
            if random.random() < 0.2:
                params["msclkid"] = self._random_path(30)
            params["utm_source"] = "bing"
            params["utm_medium"] = "organic"

        elif source == ReferrerSource.FACEBOOK:
            params["fbclid"] = "IwAR" + self._random_path(20)
            params["utm_source"] = "facebook"
            params["utm_medium"] = "social"

        elif source == ReferrerSource.TWITTER:
            params["utm_source"] = "twitter"
            params["utm_medium"] = "social"

        elif source == ReferrerSource.TELEGRAM:
            params["utm_source"] = "telegram"
            params["utm_medium"] = "social"

        elif source == ReferrerSource.LINKEDIN:
            params["utm_source"] = "linkedin"
            params["utm_medium"] = "social"

        elif source == ReferrerSource.YAHOO:
            params["utm_source"] = "yahoo"
            params["utm_medium"] = "organic"

        elif source == ReferrerSource.DUCKDUCKGO:
            params["utm_source"] = "duckduckgo"
            params["utm_medium"] = "organic"

        elif source == ReferrerSource.INTERNAL:
            params["utm_source"] = self.target_domain
            params["utm_medium"] = "referral"

        return params

    def get_url_with_params(self, base_path: str = "/") -> str:
        """
        Get a URL with tracking parameters appended.

        Args:
            base_path: Base path to append parameters to

        Returns:
            URL with appropriate UTM/tracking parameters
        """
        params = self.get_utm_params(base_path)
        if not params:
            return base_path

        separator = "&" if "?" in base_path else "?"
        param_str = urllib.parse.urlencode(params)
        return f"{base_path}{separator}{param_str}"

    @property
    def current_source(self) -> str:
        """Current referrer source name."""
        return self._current_source.value

    @property
    def source_distribution(self) -> Dict[str, float]:
        """Actual source distribution (based on generated referers)."""
        if self._total_referers_generated == 0:
            return {s.value: 0.0 for s in ReferrerSource}

        return {
            source.value: count / self._total_referers_generated
            for source, count in self._source_counts.items()
        }

    def get_stats(self) -> Dict:
        """Get referrer chain spoofer statistics."""
        return {
            "total_referers": self._total_referers_generated,
            "current_source": self._current_source.value,
            "source_counts": dict(self._source_counts),
            "source_distribution": self.source_distribution,
            "session_request_count": self._session_request_count,
            "session_max_requests": self._session_max_requests,
        }
