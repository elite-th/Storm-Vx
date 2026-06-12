"""Target determination builder.

Extracted from AttackProfileGenerator._determine_page_targets()
and _determine_resource_targets() (Task 2.3).

Pure functions — take profile + needed params, return a value.
"""

from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from finder.site_profile import SiteProfile
from finder.vf_tech_helpers import is_spa, is_origin_resource


def determine_page_targets(profile: SiteProfile) -> List[str]:
    """Determine which pages to target.

    Args:
        profile: The site profile with discovered information.

    Returns:
        List of page URL strings (max 50).
    """
    p = profile
    pages: List[str] = []
    domain = p.domain
    for link in p.links:
        link_parsed = urlparse(link)
        if link_parsed.netloc == domain:
            page = link.split('?')[0].split('#')[0]
            if page not in pages and page.startswith('http'):
                pages.append(page)

    if p.viewstate_present or (p.backend_lang and "ASP.NET" in p.backend_lang):
        pages.extend([
            f"{p.scheme}://{domain}/Default.aspx",
            f"{p.scheme}://{domain}/Login.aspx",
            f"{p.scheme}://{domain}/Home.aspx",
            f"{p.scheme}://{domain}/About.aspx",
            f"{p.scheme}://{domain}/Contact.aspx",
        ])

    if p.cms and "WordPress" in p.cms:
        pages.extend([
            f"{p.scheme}://{domain}/wp-admin/",
            f"{p.scheme}://{domain}/wp-login.php",
            f"{p.scheme}://{domain}/",
            f"{p.scheme}://{domain}/feed/",
            f"{p.scheme}://{domain}/wp-json/wp/v2/posts",
            # v34: New WordPress heavy endpoints
            f"{p.scheme}://{domain}/wp-cron.php",
            f"{p.scheme}://{domain}/wp-admin/admin-ajax.php",
            f"{p.scheme}://{domain}/wp-json/wp/v2/pages",
            f"{p.scheme}://{domain}/wp-json/wp/v2/users",
            f"{p.scheme}://{domain}/wp-json/wp/v2/search",
        ])

    if p.api_endpoints:
        pages.extend([f"{p.scheme}://{domain}{ep}" for ep in p.api_endpoints
                     if not ep.startswith('http')])

    for fp in p.found_paths:
        # BUG-104: Use fp.get('path') to avoid KeyError on malformed entries
        path = fp.get('path')
        if not path:
            continue
        full_url = f"{p.scheme}://{domain}{path}"
        if full_url not in pages:
            pages.append(full_url)

    pages = list(dict.fromkeys(pages))[:50]
    return pages


def determine_resource_targets(profile: SiteProfile,
                               html: str = "") -> List[str]:
    """Determine which resources to target.

    Args:
        profile: The site profile with discovered information.
        html: Optional raw HTML content for SPA detection.

    Returns:
        List of resource URL strings (max 30).
    """
    p = profile
    resources = list(p.images) + list(p.stylesheets) + list(p.scripts)
    domain = p.domain

    absolute_resources: List[str] = []
    for r in resources:
        if r.startswith('http://') or r.startswith('https://'):
            absolute_resources.append(r)
        elif r.startswith('//'):
            absolute_resources.append(f"{p.scheme}:{r}")
        elif r.startswith('/'):
            absolute_resources.append(f"{p.scheme}://{domain}{r}")
        else:
            absolute_resources.append(f"{p.scheme}://{domain}/{r}")
    resources = absolute_resources

    if is_spa(p, html):
        resources = [r for r in resources if is_origin_resource(r, p)]

    if p.cms and "WordPress" in p.cms:
        resources.extend([
            f"{p.scheme}://{domain}/wp-includes/js/jquery/jquery.js",
            f"{p.scheme}://{domain}/wp-includes/css/dist/block-library/style.min.css",
        ])

    if p.viewstate_present:
        resources.extend([
            f"{p.scheme}://{domain}/WebResource.axd?d=test",
            f"{p.scheme}://{domain}/ScriptResource.axd?d=test",
        ])

    resources = list(dict.fromkeys(resources))[:30]
    return resources
