"""Technology detection helper functions.

Pure functions for detecting web technologies from site profiles.
Extracted from engine.py for reusability.

Architecture: Phase 2 — TechDetectorHelpers Extraction
"""

from __future__ import annotations

import json
import re
from typing import Any

from urllib.parse import urlparse

from finder.signatures import CDN_KEYWORDS

from logging_config import get_logger

logger = get_logger(__name__)

# SPA framework names used for detection heuristics
_SPA_FRAMEWORKS = ("React", "Vue.js", "Angular", "Next.js", "Nuxt.js", "Svelte")

# GraphQL indicators searched for in HTML content
_GRAPHQL_INDICATORS = (
    "apollo", "urql", "relay", "graphql-tag",
    "ApolloClient", "createApolloClient",
    "graphql.execute", "/graphql",
)

# Common SPA routes used as fallback when link extraction yields few results
_COMMON_SPA_ROUTES = (
    "/dashboard", "/profile", "/settings", "/users",
    "/products", "/orders", "/search", "/api/v1",
    "/auth/login", "/auth/register", "/auth/callback",
)


def is_spa(profile: Any, html: str = "") -> bool:
    """Detect if the site is a Single Page Application.

    Checks frontend frameworks, technology detections, and heuristics
    (small HTML + many scripts) to determine SPA status.

    Args:
        profile: SiteProfile with frontend_frameworks, technologies,
                 html_size, and scripts attributes.
        html: Raw HTML content (used as fallback, not currently needed).

    Returns:
        True if the site appears to be a SPA.
    """
    for fw in profile.frontend_frameworks:
        if any(sfw in fw for sfw in _SPA_FRAMEWORKS):
            return True
    for tech in profile.technologies:
        if tech["name"] in _SPA_FRAMEWORKS and tech["confidence"] > 0.3:
            return True
    if profile.html_size < 5000 and len(profile.scripts) >= 3:
        return True
    return False


def is_nextjs(profile: Any, html: str = "") -> bool:
    """Check if the site uses Next.js.

    Looks for Next.js in detected technologies (confidence > 0.3)
    or Next.js markers in HTML (__NEXT_DATA__, _next/static).

    Args:
        profile: SiteProfile with technologies attribute.
        html: Raw HTML content to search for Next.js markers.

    Returns:
        True if the site appears to use Next.js.
    """
    for tech in profile.technologies:
        if tech["name"] == "Next.js" and tech["confidence"] > 0.3:
            return True
    return "__NEXT_DATA__" in html or "_next/static" in html


def has_graphql(profile: Any, html: str = "") -> bool:
    """Check if the site uses GraphQL.

    Searches API endpoints, found paths, HTML content, and script
    sources for GraphQL indicators.

    Args:
        profile: SiteProfile with api_endpoints, found_paths,
                 and scripts attributes.
        html: Raw HTML content to search for GraphQL indicators.

    Returns:
        True if GraphQL usage is detected.
    """
    for ep in profile.api_endpoints:
        if "graphql" in ep.lower():
            return True
    for fp in profile.found_paths:
        if "graphql" in fp.get("path", "").lower():
            return True
    html_lower = html.lower()
    for indicator in _GRAPHQL_INDICATORS:
        if indicator.lower() in html_lower:
            return True
    for script in profile.scripts:
        if "graphql" in script.lower() or "apollo" in script.lower():
            return True
    return False


def is_origin_resource(url: str, profile: Any,
                       cdn_keywords: tuple[str, ...] = CDN_KEYWORDS) -> bool:
    """Check if a resource URL is served from the origin (not CDN).

    Compares the resource hostname against the site domain and
    CDN keyword list. Resources matching the site domain are origin;
    resources containing CDN keywords are not.

    Args:
        url: The resource URL to check.
        profile: SiteProfile with domain attribute.
        cdn_keywords: Tuple of CDN hostname keywords for detection.

    Returns:
        True if the resource appears to be served from the origin.
    """
    try:
        parsed = urlparse(url)
        resource_host = parsed.netloc.split(":")[0]
        if resource_host == profile.domain:
            return True
        resource_lower = resource_host.lower()
        for kw in cdn_keywords:
            if kw in resource_lower:
                return False
        return True
    except (ValueError, AttributeError, TypeError):
        logger.debug("is_origin_resource URL parse error", exc_info=True)
        return False


def detect_spa_framework(profile: Any) -> str | None:
    """Identify which SPA framework is being used.

    Searches detected technologies for known SPA frameworks
    with confidence > 0.3.

    Args:
        profile: SiteProfile with technologies attribute.

    Returns:
        Framework name string, or None if no SPA framework detected.
    """
    for tech in profile.technologies:
        if tech["name"] in _SPA_FRAMEWORKS and tech["confidence"] > 0.3:
            return tech["name"]
    return None


def find_graphql_endpoint(profile: Any, html: str = "") -> str | None:
    """Find the GraphQL endpoint URL.

    Searches API endpoints and found paths for GraphQL references,
    falling back to a default /graphql path if GraphQL usage is
    detected but no explicit endpoint is found.

    Args:
        profile: SiteProfile with api_endpoints, found_paths,
                 scheme, and domain attributes.
        html: Raw HTML content for GraphQL detection.

    Returns:
        Full GraphQL endpoint URL, or None if not found.
    """
    for ep in profile.api_endpoints:
        if "graphql" in ep.lower():
            return ep if ep.startswith("http") else f"{profile.scheme}://{profile.domain}{ep}"
    for fp in profile.found_paths:
        fp_path = fp.get("path", "")
        if "graphql" in fp_path.lower():
            return f"{profile.scheme}://{profile.domain}{fp_path}"
    if has_graphql(profile, html):
        return f"{profile.scheme}://{profile.domain}/graphql"
    return None


def extract_spa_routes(profile: Any) -> list[str]:
    """Extract client-side routes from a SPA application.

    Collects same-domain paths from discovered links, then adds
    common SPA route patterns as fallback targets.

    Args:
        profile: SiteProfile with links, scheme, and domain attributes.

    Returns:
        List of route paths/URLs (max 30).
    """
    routes: list[str] = []
    for link in profile.links:
        parsed = urlparse(link)
        if parsed.netloc == profile.domain:
            path = parsed.path
            if path and path != "/" and path not in routes:
                routes.append(path)
    for route in _COMMON_SPA_ROUTES:
        full = f"{profile.scheme}://{profile.domain}{route}"
        if full not in routes:
            routes.append(full)
    return routes[:30]


def extract_next_data_routes(profile: Any, html: str = "") -> list[str]:
    """Extract Next.js _next/data routes from __NEXT_DATA__.

    Parses the __NEXT_DATA__ script tag to extract the build ID
    and page path, constructing the _next/data JSON route.

    Args:
        profile: SiteProfile (used for Next.js detection context).
        html: Raw HTML content containing __NEXT_DATA__ script.

    Returns:
        List of _next/data route paths.
    """
    routes: list[str] = []
    if not is_nextjs(profile, html):
        return routes
    next_data_match = re.search(
        r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.DOTALL
    )
    if next_data_match:
        try:
            data = json.loads(next_data_match.group(1))
            build_id = data.get("buildId", "")
            if build_id:
                page_path = data.get("page", "")
                if page_path:
                    routes.append(f"/_next/data/{build_id}{page_path}.json")
        except (json.JSONDecodeError, KeyError):
            pass
    return routes
