"""Technology detection and content analysis module.

Analyzes HTML content, headers, cookies, scripts, and meta tags
to identify the target's technology stack.
"""
from __future__ import annotations
import re
from typing import Dict, List, Any
from urllib.parse import urlparse, urljoin


from vf_common import C
from finder.signatures import TECH_SIGNATURES, TechCategory
from finder.site_profile import SiteProfile
from config.defaults import (
    MAX_DISCOVERED_LINKS, MAX_DISCOVERED_SCRIPTS,
    MAX_DISCOVERED_IMAGES, MAX_DISCOVERED_ENDPOINTS,
)


# ─── Content Analysis ────────────────────────────────────────────────────────

def analyze_content(html: str, url: str, profile: SiteProfile) -> SiteProfile:
    """Analyze HTML content for forms, scripts, links, images, etc.

    Args:
        html: Raw HTML content.
        url: Target URL (for resolving relative links).
        profile: SiteProfile to populate.

    Returns:
        Updated SiteProfile.
    """
    if not html:
        return profile

    # Extract meta tags
    for m in re.finditer(r'<meta\s+[^>]*>', html, re.IGNORECASE):
        tag = m.group(0)
        name_match = re.search(r'name=["\']?([^"\'>\s]+)["\']?', tag)
        content_match = re.search(r'content=["\']?([^"\'>]+)["\']?', tag)
        if name_match and content_match:
            profile.meta_tags[name_match.group(1)] = content_match.group(1)

    # Also check property= for og: tags
    for m in re.finditer(r'<meta\s+property=["\']?([^"\'>\s]+)["\']?\s+content=["\']?([^"\'>]+)["\']?', html, re.IGNORECASE):
        profile.meta_tags[m.group(1)] = m.group(2)

    # Extract forms
    form_pattern = re.finditer(r'<form\s+([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
    for i, form_match in enumerate(form_pattern):
        form_attrs = form_match.group(1)
        form_html = form_match.group(2)

        action_match = re.search(r'action=["\']?([^"\'>\s]+)["\']?', form_attrs)
        method_match = re.search(r'method=["\']?([^"\'>\s]+)["\']?', form_attrs, re.IGNORECASE)

        form_info = {
            "index": i,
            "action": action_match.group(1) if action_match else "",
            "method": (method_match.group(1) or "GET").upper() if method_match else "GET",
            "fields": [],
            "hidden_fields": [],
        }

        # Extract input fields
        for inp in re.finditer(r'<input\s+([^>]*)>', form_html, re.IGNORECASE):
            attrs = inp.group(1)
            name_m = re.search(r'name=["\']?([^"\'>\s]+)["\']?', attrs)
            type_m = re.search(r'type=["\']?([^"\'>\s]+)["\']?', attrs, re.IGNORECASE)
            value_m = re.search(r'value=["\']?([^"\'>]*)["\']?', attrs)

            field_name = name_m.group(1) if name_m else ""
            field_type = (type_m.group(1) or "text").lower() if type_m else "text"
            field_value = value_m.group(1) if value_m else ""

            if field_type == "hidden":
                form_info["hidden_fields"].append({"name": field_name, "value": field_value})
                if field_name and field_name not in profile.hidden_fields:
                    profile.hidden_fields.append(field_name)
            else:
                form_info["fields"].append({
                    "name": field_name,
                    "type": field_type,
                    "value": field_value,
                })

        profile.forms.append(form_info)

    # Check ASP.NET specific
    if '__VIEWSTATE' in html:
        profile.viewstate_present = True
    if '__EVENTVALIDATION' in html:
        profile.eventvalidation_present = True

    # Detect login fields
    _detect_login_fields(html, profile)

    # Extract scripts
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = m.group(1)
        # v23: Skip data:, blob:, javascript: URIs — they're inline, not downloadable
        if not src.startswith(('data:', 'blob:', 'javascript:')):
            if len(profile.scripts) < MAX_DISCOVERED_SCRIPTS:
                profile.scripts.append(src)
            elif len(profile.scripts) == MAX_DISCOVERED_SCRIPTS:
                import logging
                logging.getLogger(__name__).warning(f"BUG-043: Truncating scripts at {MAX_DISCOVERED_SCRIPTS}")

    # Extract stylesheets
    for m in re.finditer(r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']', html, re.IGNORECASE):
        profile.stylesheets.append(m.group(1))

    # Extract images
    for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        if len(profile.images) < MAX_DISCOVERED_IMAGES:
            profile.images.append(m.group(1))
        elif len(profile.images) == MAX_DISCOVERED_IMAGES:
            import logging
            logging.getLogger(__name__).warning(f"BUG-043: Truncating images at {MAX_DISCOVERED_IMAGES}")

    # Extract links
    parsed = urlparse(url)
    domain = parsed.netloc
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        link = m.group(1)
        if link.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:')):
            continue
        if link.startswith('/'):
            link = f"{profile.scheme}://{domain}{link}"
        elif not link.startswith('http'):
            link = urljoin(url, link)
        if len(profile.links) < MAX_DISCOVERED_LINKS:
            profile.links.append(link)
        elif len(profile.links) == MAX_DISCOVERED_LINKS:
            import logging
            logging.getLogger(__name__).warning(f"BUG-043: Truncating links at {MAX_DISCOVERED_LINKS}")

    # Extract API endpoints
    api_patterns = [
        r'fetch\(["\']([^"\']+)["\']',
        r'\.ajax\({[^}]*url:\s*["\']([^"\']+)["\']',
        r'\.get\(["\']([^"\']+)["\']',
        r'\.post\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'url:\s*["\'](/api/[^"\']+)["\']',
        r'["\'](/api/[^"\']+)["\']',
    ]
    for pattern in api_patterns:
        for m in re.finditer(pattern, html, re.IGNORECASE):
            endpoint = m.group(1)
            if endpoint not in profile.api_endpoints:
                if len(profile.api_endpoints) < MAX_DISCOVERED_ENDPOINTS:
                    profile.api_endpoints.append(endpoint)
                elif len(profile.api_endpoints) == MAX_DISCOVERED_ENDPOINTS:
                    import logging
                    logging.getLogger(__name__).warning(f"BUG-043: Truncating api_endpoints at {MAX_DISCOVERED_ENDPOINTS}")

    # Print summary
    print(f"  {C.G}  Forms: {len(profile.forms)} | Scripts: {len(profile.scripts)} | Links: {len(profile.links)}{C.RS}")
    print(f"  {C.G}  Hidden Fields: {len(profile.hidden_fields)} | Images: {len(profile.images)} | APIs: {len(profile.api_endpoints)}{C.RS}")
    if profile.viewstate_present:
        print(f"  {C.Y}  ASP.NET ViewState: DETECTED{C.RS}")
    if profile.eventvalidation_present:
        print(f"  {C.Y}  ASP.NET EventValidation: DETECTED{C.RS}")
    if profile.login_fields:
        print(f"  {C.Y}  Login Fields: {profile.login_fields}{C.RS}")

    # v18: Detect educational/student site category
    _detect_site_category(html, url, profile)

    return profile


def _detect_login_fields(html: str, profile: SiteProfile) -> None:
    """Detect login form field names."""
    username_field = "username"
    password_field = "password"

    patterns_user = [
        r'name=["\']?([^"\'>\s]*(?:[Uu]ser|[Ee]mail|[Ll]ogin)[^"\'>\s]*)["\']?',
    ]
    patterns_pass = [
        r'name=["\']?([^"\'>\s]*(?:[Pp]ass|[Pp]wd)[^"\'>\s]*)["\']?',
    ]

    for p in patterns_user:
        m = re.search(p, html)
        if m:
            username_field = m.group(1)
            break

    for p in patterns_pass:
        m = re.search(p, html)
        if m:
            password_field = m.group(1)
            break

    profile.login_fields = {
        "username": username_field,
        "password": password_field,
    }


# ─── Technology Detection ─────────────────────────────────────────────────────

def detect_technologies(html: str, profile: SiteProfile) -> SiteProfile:
    """Detect technologies based on headers, HTML, cookies, and scripts.

    Args:
        html: Raw HTML content.
        profile: SiteProfile with populated headers/cookies/scripts.

    Returns:
        Updated SiteProfile with technologies detected.
    """
    detected = {}

    for tech_name, sig in TECH_SIGNATURES.items():
        confidence = 0.0
        evidence = []

        # Check headers
        for header_name, pattern in sig.get("headers", {}).items():
            header_val = profile.headers.get(header_name, '')
            if header_val and re.search(pattern, header_val, re.IGNORECASE):
                confidence += 0.4
                evidence.append(f"Header: {header_name}={header_val}")

        # Check HTML content
        for pattern in sig.get("html", []):
            if re.search(pattern, html, re.IGNORECASE):
                confidence += 0.25
                evidence.append(f"HTML: {pattern}")

        # Check cookies
        for cookie_pattern in sig.get("cookies", []):
            for cookie_name in profile.cookies:
                if cookie_pattern.lower() in cookie_name.lower():
                    confidence += 0.3
                    evidence.append(f"Cookie: {cookie_name}")

        # Check meta tags
        for meta_name, meta_pattern in sig.get("meta", {}).items():
            meta_content = profile.meta_tags.get(meta_name, '')
            if meta_content and re.search(meta_pattern, meta_content, re.IGNORECASE):
                confidence += 0.5
                evidence.append(f"Meta: {meta_name}={meta_content}")

        # Check scripts
        for script_pattern in sig.get("scripts", []):
            for script in profile.scripts:
                if re.search(script_pattern, script, re.IGNORECASE):
                    confidence += 0.3
                    evidence.append(f"Script: {script[:50]}")

        if confidence > 0.2:
            detected[tech_name] = {
                "name": tech_name,
                "category": sig.get("category", "Unknown"),
                "confidence": min(confidence, 1.0),
                "evidence": evidence,
            }

    # Sort by confidence
    sorted_tech = sorted(detected.values(), key=lambda x: x["confidence"], reverse=True)
    profile.technologies = sorted_tech

    # Categorize
    for tech in sorted_tech:
        cat = tech["category"]
        name = tech["name"]
        if cat == "Web Server" and not profile.server:
            profile.server = name
        elif cat == "Backend Language" and not profile.backend_lang:
            profile.backend_lang = name
        elif cat == "Backend Framework":
            if not profile.backend_framework or tech["confidence"] > 0.5:
                profile.backend_framework = name
        elif cat == "Frontend Framework":
            profile.frontend_frameworks.append(name)
        elif cat == "CMS":
            profile.cms = name
        elif "WAF" in cat:
            profile.waf = name
            profile.waf_confidence = tech["confidence"]
            # FIX: "WAF / CDN" category should set BOTH waf and cdn fields.
            if "CDN" in cat:
                profile.cdn = name
        elif "CDN" in cat:
            profile.cdn = name

    # Print detected technologies
    for tech in sorted_tech:
        conf_bar = int(tech["confidence"] * 10)
        bar = f"{'|' * conf_bar}{'.' * (10 - conf_bar)}"
        conf_color = C.G if tech["confidence"] > 0.7 else C.Y if tech["confidence"] > 0.4 else C.DM
        print(f"  {conf_color}  {tech['name']:<25} [{bar}] {tech['confidence']:.0%} {C.DM}({tech['category']}){C.RS}")

    # ─── Post-detection: Smart CDN identification ───
    if not profile.cdn:
        server_header = (profile.headers.get('Server', '') or '').lower()
        if 'cdn' in server_header:
            cdn_name = profile.headers.get('Server', 'Unknown CDN')
            profile.cdn = cdn_name
            print(f"  {C.Y}  [CDN-DETECT] Server header contains 'CDN': {cdn_name}{C.RS}")

    return profile


# ─── Site Category Detection (v18) ───────────────────────────────────────────

def _detect_site_category(html: str, url: str, profile: SiteProfile) -> None:
    """v18: Auto-detect site category (educational, conferencing, etc.)

    Uses multiple heuristics:
    1. HTML content keywords (Persian + English)
    2. URL path patterns
    3. Form field names
    4. API endpoint patterns
    5. Meta tags / page title
    6. Link text analysis

    Sets profile.site_category and profile.edu_indicators
    """
    p = profile
    html_lower = html.lower()
    url_lower = p.url.lower()
    domain_lower = p.domain.lower()
    title = p.meta_tags.get('title', '') + ' ' + p.meta_tags.get('og:title', '')
    title_lower = title.lower()
    all_text = f"{html_lower} {url_lower} {title_lower}"

    # ═══ Educational / Student Site Detection ═══
    edu_score = 0
    edu_indicators = []
    edu_endpoints = []

    # --- 1. Persian keywords in HTML content ---
    persian_edu_keywords = [
        ('دانش\u200cآموز', 3), ('دانش آموز', 3),
        ('نمره', 3), ('نمرات', 3), ('کارنامه', 3),
        ('معلم', 2), ('آموزش', 2), ('دبیرستان', 3),
        ('ابتدایی', 2), ('متوسطه', 2), ('پایه', 1),
        ('مدرسه', 2), ('کلاس', 1), ('درس', 1),
        ('امتحان', 2), ('آزمون', 2), ('ارزیابی', 2),
        ('عدالت آموزشی', 3), ('سامانه آموزش', 3),
        ('حضور و غیاب', 2), ('حضورغیاب', 2),
        ('برنامه درسی', 2), ('واحد', 1), ('نیمسال', 2),
        ('دانشگاه', 2), ('دانشجو', 2), ('استاد', 1),
        ('ترم', 1), ('قبول', 1), ('مردود', 1),
        ('معدل', 3), ('معدل تراکمی', 3),
    ]
    for keyword, weight in persian_edu_keywords:
        if keyword in all_text:
            edu_score += weight
            edu_indicators.append(f"کلمه فارسی: «{keyword}» (+{weight})")

    # --- 2. English keywords ---
    english_edu_keywords = [
        ('student', 2), ('grade', 2), ('grades', 2),
        ('report card', 3), ('gpa', 3), ('transcript', 3),
        ('classroom', 2), ('attendance', 2), ('semester', 2),
        ('school', 2), ('academy', 2), ('teacher', 1),
        ('exam', 2), ('quiz', 1), ('score', 1),
        ('curriculum', 2), ('enrollment', 2),
    ]
    for keyword, weight in english_edu_keywords:
        if keyword in all_text:
            edu_score += weight
            edu_indicators.append(f"English keyword: '{keyword}' (+{weight})")

    # --- 3. URL path patterns ---
    edu_url_patterns = [
        (r'/student', 2), (r'/grade', 2), (r'/grades', 2),
        (r'/report.?card', 3), (r'/attendance', 2),
        (r'/exam', 2), (r'/quiz', 1), (r'/class', 1),
        (r'/course', 2), (r'/enroll', 2), (r'/transcript', 3),
        (r'/dashboard/student', 3), (r'/panel/student', 3),
        (r'/parent', 2), (r'/teacher', 2), (r'/admin.*grade', 3),
    ]
    for pattern, weight in edu_url_patterns:
        if re.search(pattern, url_lower):
            edu_score += weight
            edu_indicators.append(f"URL pattern: '{pattern}' (+{weight})")

    # --- 4. Domain patterns ---
    edu_domain_patterns = [
        ('school', 2), ('edu', 3), ('academy', 2),
        ('student', 2), ('grade', 2), ('class', 1),
        ('myschool', 3), ('nekar', 2), ('navid', 2),
        ('mokhtarnameh', 2), ('roshd', 2), ('mirath', 2),
    ]
    for pattern, weight in edu_domain_patterns:
        if pattern in domain_lower:
            edu_score += weight
            edu_indicators.append(f"Domain contains: '{pattern}' (+{weight})")

    # --- 5. Form field analysis ---
    all_field_names = ' '.join(
        f.get('name', '') for form in p.forms for f in form.get('fields', [])
    ).lower()
    edu_form_fields = [
        ('student_id', 3), ('studentid', 3), ('national_code', 3),
        ('nationalcode', 3), ('codemelli', 3), ('code_melli', 3),
        ('grade_id', 2), ('class_id', 2), ('course_id', 2),
        ('term', 1), ('semester', 2), ('lesson', 2),
    ]
    for pattern, weight in edu_form_fields:
        if pattern in all_field_names:
            edu_score += weight
            edu_indicators.append(f"Form field: '{pattern}' (+{weight})")

    # --- 6. API endpoint patterns ---
    for ep in p.api_endpoints:
        ep_lower = ep.lower()
        if any(kw in ep_lower for kw in ['/student', '/grade', '/course', '/exam',
                                          '/attendance', '/transcript', '/report',
                                          '/class/', '/enroll', '/parent']):
            edu_score += 2
            edu_indicators.append(f"API endpoint: '{ep}' (+2)")
            edu_endpoints.append(ep)

    # --- 7. Common Iranian educational platform paths ---
    edu_paths_to_check = [
        '/student/login', '/student/grades', '/student/attendance',
        '/parent/login', '/parent/grades', '/teacher/login',
        '/admin/students', '/admin/grades', '/admin/courses',
        '/api/students', '/api/grades', '/api/courses',
        '/api/v1/students', '/api/v1/grades',
        '/report/card', '/report/grades', '/report/attendance',
        '/dashboard/grades', '/dashboard/attendance',
        '/auth/student', '/auth/parent', '/auth/teacher',
        '/login/student', '/login/parent',
        '/print/grades', '/export/grades', '/export/pdf',
    ]
    for path in edu_paths_to_check:
        if path in url_lower or path in html_lower:
            edu_score += 2
            edu_indicators.append(f"Edu path found: '{path}' (+2)")
            edu_endpoints.append(path)

    # ═══ Conferencing Site Detection ═══
    conf_score = 0
    conf_keywords = ['skyroom', 'bigbluebutton', 'jitsi', 'adobe connect',
                    'webinar', 'conference', 'meeting room', 'screen share',
                    'اسکای روم', 'کنفرانس', 'کلاس آنلاین', 'وبینار',
                    '/room/', '/ch/', '/meeting/', '/live/']
    for kw in conf_keywords:
        if kw in all_text:
            conf_score += 2

    # ═══ Category Decision ═══
    # v5: Improved category detection — added NEWS/MEDIA category and
    # raised threshold to prevent false educational classification.
    # Persian news sites often contain words like "آموزش" (education),
    # "درس" (lesson) in article content, which don't indicate the site
    # IS an educational platform — they're just news articles about education.

    # v5: NEWS / MEDIA site detection
    news_score = 0
    news_indicators = []

    # Persian news keywords (strong indicators of a news site)
    persian_news_keywords = [
        ('خبر', 2), ('خبرگزاری', 3), ('روزنامه', 3), ('خبرنامه', 2),
        ('تیتر', 2), ('شاخص', 1), ('آخرین اخبار', 3), ('آرشیو خبری', 3),
        ('گزارش', 2), ('مصاحبه', 2), ('سرمایه‌گذاری', 1),
        ('فناوری', 2), ('تکنولوژی', 2), ('دیجیتال', 2),
        ('اقتصاد', 2), ('سیاست', 2), ('ورزش', 2),
        ('جامعه', 1), ('فرهنگ', 1), ('هنر', 1),
    ]
    for keyword, weight in persian_news_keywords:
        if keyword in all_text:
            news_score += weight
            news_indicators.append(f"Persian news: «{keyword}» (+{weight})")

    # English news keywords
    english_news_keywords = [
        ('breaking news', 3), ('latest news', 3), ('headline', 2),
        ('newsroom', 3), ('journalist', 2), ('press release', 2),
        ('correspondent', 2), ('editorial', 2), ('opinion piece', 2),
        ('trending', 1), ('viral', 1),
    ]
    for keyword, weight in english_news_keywords:
        if keyword in all_text:
            news_score += weight
            news_indicators.append(f"English news: '{keyword}' (+{weight})")

    # News-specific URL patterns
    news_url_patterns = [
        (r'/news', 2), (r'/article', 2), (r'/post/', 2),
        (r'/category/', 1), (r'/tag/', 1), (r'/archive', 2),
        (r'/\d{4}/\d{2}', 3),  # Date-based URLs (/2024/01/) = news/blog
    ]
    for pattern, weight in news_url_patterns:
        if re.search(pattern, url_lower):
            news_score += weight
            news_indicators.append(f"News URL: '{pattern}' (+{weight})")

    # News-specific meta patterns
    news_meta_patterns = [
        ('article:published_time', 3), ('article:section', 2),
        ('article:tag', 2), ('news_keywords', 3),
    ]
    for meta_key, weight in news_meta_patterns:
        if meta_key in str(p.meta_tags).lower():
            news_score += weight
            news_indicators.append(f"News meta: '{meta_key}' (+{weight})")

    # Domain-based news detection
    news_domain_patterns = [
        ('news', 3), ('khabar', 3), ('digiato', 3), ('zoomit', 3),
        ('techrasa', 3), ('mashreghnews', 3), ('isna', 3), ('irna', 3),
        ('tasnim', 3), ('mehrnews', 3), ('entekhab', 3), ('tabnak', 3),
        ('yjc', 3), ('ana', 2), ('shafaqna', 2),
    ]
    for pattern, weight in news_domain_patterns:
        if pattern in domain_lower:
            news_score += weight
            news_indicators.append(f"News domain: '{pattern}' (+{weight})")

    # v5: Negative signals — reduce edu_score if news indicators are strong
    # If the site looks like a news site, common Persian words like "آموزش"
    # are just article topics, not indicators of an educational platform.
    # Only strong, specific edu signals (like login/student portal paths)
    # should override this.
    if news_score >= 6:
        # Reduce edu_score for weak indicators (keyword matches in content)
        # but keep edu_score from strong signals (URL paths, form fields, domain)
        weak_edu = 0
        strong_edu = 0
        for ind in edu_indicators:
            if any(s in ind for s in ['URL pattern', 'Form field', 'Edu path', 'API endpoint', 'Domain contains']):
                strong_edu += 1
            else:
                weak_edu += 1
        # Only count strong educational signals when news indicators are present
        edu_score = min(edu_score, strong_edu * 5)

    if edu_score >= 8:
        p.site_category = 'educational'
        p.edu_indicators = edu_indicators[:10]
        p.edu_endpoints = list(set(edu_endpoints))
        print(f"\n  {C.BD}{C.G}  ╔══════════════════════════════════════════════════════╗{C.RS}")
        print(f"  {C.BD}{C.G}  ║  SITE CATEGORY: EDUCATIONAL / STUDENT PORTAL       ║{C.RS}")
        print(f"  {C.BD}{C.G}  ╚══════════════════════════════════════════════════════╝{C.RS}")
        print(f"  {C.Y}  Confidence Score: {edu_score}/50+{C.RS}")
        for ind in p.edu_indicators[:5]:
            print(f"  {C.DM}    • {ind}{C.RS}")
        if len(p.edu_indicators) > 5:
            print(f"  {C.DM}    ... and {len(p.edu_indicators)-5} more indicators{C.RS}")
        if p.edu_endpoints:
            print(f"  {C.CY}  Edu endpoints discovered: {len(p.edu_endpoints)}{C.RS}")
            for ep in p.edu_endpoints[:5]:
                print(f"  {C.CY}    → {ep}{C.RS}")
    elif news_score >= 6:
        p.site_category = 'news'
        print(f"\n  {C.BD}{C.CY}  ╔══════════════════════════════════════════════════════╗{C.RS}")
        print(f"  {C.BD}{C.CY}  ║  SITE CATEGORY: NEWS / MEDIA                       ║{C.RS}")
        print(f"  {C.BD}{C.CY}  ╚══════════════════════════════════════════════════════╝{C.RS}")
        print(f"  {C.Y}  Confidence Score: {news_score}/20+{C.RS}")
        for ind in news_indicators[:5]:
            print(f"  {C.DM}    • {ind}{C.RS}")
    elif conf_score >= 4:
        p.site_category = 'conferencing'
        print(f"\n  {C.BD}{C.B}  ╔══════════════════════════════════════════════════════╗{C.RS}")
        print(f"  {C.BD}{C.B}  ║  SITE CATEGORY: CONFERENCING / WEBINAR             ║{C.RS}")
        print(f"  {C.BD}{C.B}  ╚══════════════════════════════════════════════════════╝{C.RS}")
    else:
        p.site_category = 'generic'
