"""Technology fingerprint signatures and deep scan paths.

Contains the Wappalyzer-like signature database used for technology detection,
the list of paths for deep scanning, and shared CDN keyword lists.

BUG-033: CDN_KEYWORDS and CDN_DOMAIN_SUFFIXES were previously duplicated
across engine.py, deep_scanner.py, and vf_js_scanner.py. They are now
defined here as the single source of truth.
"""
from __future__ import annotations
from enum import Enum
from typing import Dict, List, Any


# ═══════════════════════════════════════════════════════════════════════════════
# CDN Detection Keywords (BUG-033: moved from duplicated definitions)
# ═══════════════════════════════════════════════════════════════════════════════

# Keywords for substring matching against hostname/path (used in engine.py, deep_scanner.py)
CDN_KEYWORDS: tuple[str, ...] = (
    "cdn", "cloudfront", "cloudflare", "akamai", "fastly",
    "cdnstatic", "static", "assets", "s3", "amazonaws",
    "arvan", "arvancloud", "sotoon", "cdn77",
    "azureedge", "msecnd", "cdn.jsdelivr",
    "unpkg", "cdnjs", "googleapis",
    "gstatic", "fbcdn", "twimg",
)

# Domain suffixes for more precise CDN detection (used in vf_js_scanner.py)
CDN_DOMAIN_SUFFIXES: frozenset[str] = frozenset([
    'cdn.', 'cloudfront.net', 'cloudflare.com', 'akamai',
    'fastly', 'cdnstatic', 'static', 'assets.',
    'amazonaws.com', 'arvan', 'arvancloud', 'sotoon', 'cdn77',
    'azureedge.net', 'msecnd.net', 'cdn.jsdelivr.net',
    'unpkg.com', 'cdnjs.cloudflare.com', 'googleapis.com',
    'gstatic.com', 'fbcdn.net', 'twimg.com',
    'bootstrapcdn', 'jquery.com', 'wp.com',
    'gravatar.com', 'sharethis.com',
])


class TechCategory(str, Enum):
    """Technology categories for classification."""
    WEB_SERVER = "Web Server"
    BACKEND_LANGUAGE = "Backend Language"
    BACKEND_FRAMEWORK = "Backend Framework"
    FRONTEND_FRAMEWORK = "Frontend Framework"
    CSS_FRAMEWORK = "CSS Framework"
    JS_LIBRARY = "JavaScript Library"
    CMS = "CMS"
    WAF_CDN = "WAF / CDN"
    WAF = "WAF"
    WAF_LB = "WAF / Load Balancer"
    DATABASE = "Database"
    ANALYTICS = "Analytics"


# ═══════════════════════════════════════════════════════════════════════════════
# Technology Fingerprint Database (Wappalyzer-like)
# ═══════════════════════════════════════════════════════════════════════════════

TECH_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # ─── Web Servers ───
    "Apache": {
        "headers": {"Server": r"Apache(/[\d.]+)?"},
        "category": "Web Server",
    },
    "Nginx": {
        "headers": {"Server": r"nginx(/[\d.]+)?"},
        "category": "Web Server",
    },
    "IIS": {
        "headers": {"Server": r"Microsoft-IIS(/[\d.]+)?"},
        "category": "Web Server",
    },
    "LiteSpeed": {
        "headers": {"Server": r"LiteSpeed"},
        "category": "Web Server",
    },
    "Caddy": {
        "headers": {"Server": r"Caddy"},
        "category": "Web Server",
    },
    "OpenResty": {
        "headers": {"Server": r"OpenResty"},
        "category": "Web Server",
    },

    # ─── Backend Languages / Frameworks ───
    "ASP.NET": {
        "headers": {
            "X-AspNet-Version": r".+",
            "X-Powered-By": r"ASP\.NET",
        },
        "html": [
            r'__VIEWSTATE',
            r'__EVENTVALIDATION',
            r'__EVENTTARGET',
            r'aspnetForm',
            r'/WebResource\.axd',
            r'/ScriptResource\.axd',
            r'\.aspx',
        ],
        "cookies": ["ASP.NET_SessionId", "ASPSESSIONID"],
        "category": "Backend Framework",
    },
    "PHP": {
        "headers": {
            "X-Powered-By": r"PHP(/[\d.]+)?",
            "Server": r"PHP",
        },
        "html": [r'\.php', r'PHPSESSID', r'X-Powered-By: PHP'],
        "cookies": ["PHPSESSID", "laravel_session"],
        "category": "Backend Language",
    },
    "Laravel": {
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "html": [r'laravel', r'csrf-token'],
        "headers": {"X-Powered-By": r"Laravel"},
        "category": "Backend Framework",
    },
    "Django": {
        "cookies": ["csrftoken", "sessionid"],
        "html": [r'csrfmiddlewaretoken', r'__django'],
        "category": "Backend Framework",
    },
    "Express.js": {
        "headers": {"X-Powered-By": r"Express"},
        "category": "Backend Framework",
    },
    "Next.js": {
        "html": [
            r'__NEXT_DATA__',
            r'_next/static',
            r'_next/image',
        ],
        "headers": {"X-Powered-By": r"Next\.js"},
        "category": "Backend Framework",
    },
    "Flask": {
        "headers": {"Server": r"Werkzeug"},
        "cookies": ["session"],
        "category": "Backend Framework",
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": r"Phusion Passenger"},
        "cookies": ["_session_id"],
        "html": [r'authenticity_token', r'turbolinks'],
        "category": "Backend Framework",
    },
    "Spring Boot": {
        "headers": {"X-Application-Context": r".+"},
        "cookies": ["JSESSIONID"],
        "category": "Backend Framework",
    },
    "FastAPI": {
        "html": [r'fastapi', r'openapi\.json', r'swagger'],
        "category": "Backend Framework",
    },

    # ─── CMS ───
    "WordPress": {
        "html": [
            r'wp-content',
            r'wp-includes',
            r'wp-admin',
            r'WordPress',
            r'wp-json',
        ],
        "headers": {"Link": r'<[^>]+>; rel="https://api\.w\.org/"'},
        "cookies": ["wordpress_", "wp-settings-"],
        "meta": {"generator": r"WordPress"},
        "category": "CMS",
    },
    "Drupal": {
        "html": [r'Drupal', r'sites/default', r'misc/drupal\.js'],
        "headers": {"X-Generator": r"Drupal"},
        "meta": {"generator": r"Drupal"},
        "category": "CMS",
    },
    "Joomla": {
        "html": [r'/media/jui/', r'Joomla!', r'com_content'],
        "meta": {"generator": r"Joomla!"},
        "category": "CMS",
    },
    "DotNetNuke (DNN)": {
        "html": [r'DNN', r'dotnetnuke', r'/DesktopModules/'],
        "meta": {"generator": r"DotNetNuke"},
        "cookies": ["dnn_IsMobile"],
        "category": "CMS",
    },
    "SharePoint": {
        "headers": {"SharePoint": r".+", "SPRequestGuid": r".+"},
        "html": [r'_layouts/', r'SharePoint'],
        "category": "CMS",
    },

    # ─── Frontend Frameworks ───
    "React": {
        "html": [
            r'react',
            r'_reactRootContainer',
            r'data-reactroot',
            r'reactjs',
        ],
        "scripts": [r'react', r'react-dom'],
        "category": "Frontend Framework",
    },
    "Vue.js": {
        "html": [r'data-v-[a-f0-9]', r'__vue__', r'vue-app'],
        "scripts": [r'vue'],
        "category": "Frontend Framework",
    },
    "Angular": {
        "html": [r'ng-app', r'ng-controller', r'_nghost', r'ng-version'],
        "scripts": [r'angular', r'@angular'],
        "category": "Frontend Framework",
    },
    "jQuery": {
        "scripts": [r'jquery'],
        "html": [r'jquery', r'jQuery'],
        "category": "JavaScript Library",
    },
    "Bootstrap": {
        "html": [r'bootstrap\.min\.css', r'bootstrap\.css', r'btn-primary'],
        "category": "CSS Framework",
    },
    "Tailwind CSS": {
        "html": [r'tailwind', r'flex.*gap-'],
        "category": "CSS Framework",
    },

    # ─── WAF / CDN ───
    "Cloudflare": {
        "headers": {"CF-Ray": r".+", "CF-Cache-Status": r".+", "Server": r"cloudflare"},
        "html": [r'cf-browser-verification', r'Cloudflare', r'cf_chl_opt'],
        "cookies": ["__cf_bm", "cf_clearance"],
        "category": "WAF / CDN",
    },
    "ArvanCloud": {
        "headers": {"Server": r"[Aa]rvan"},
        "html": [r'arvancloud', r'ArvanCloud'],
        "category": "WAF / CDN",
    },
    "ModSecurity": {
        "headers": {"Server": r"Mod_Security", "X-Mod-Security": r".+"},
        "category": "WAF",
    },
    "Sucuri": {
        "headers": {"X-Sucuri-ID": r".+", "Server": r"Sucuri"},
        "category": "WAF / CDN",
    },
    "Imperva (Incapsula)": {
        "headers": {"X-CDN": r"Incapsula", "X-Iinfo": r".+"},
        "cookies": ["visid_incap", "incap_ses"],
        "category": "WAF / CDN",
    },
    "Akamai": {
        "headers": {"X-Akamai-Transformed": r".+", "X-Cache": r"Akamai"},
        "category": "WAF / CDN",
    },
    "AWS WAF / CloudFront": {
        "headers": {"X-Cache": r".*CloudFront.*", "Via": r".*CloudFront.*"},
        "cookies": ["AWSALB", "aws-waf-token"],
        "category": "WAF / CDN",
    },
    "F5 BIG-IP": {
        "headers": {"Server": r"BigIP", "X-WA-Info": r".+"},
        "cookies": ["BIGipServer"],
        "category": "WAF / Load Balancer",
    },
    "Barracuda": {
        "headers": {"Server": r"Barracuda"},
        "category": "WAF",
    },
    "Sotoon": {
        "headers": {"Server": r"Sotoon"},
        "html": [r'sotoon'],
        "category": "WAF / CDN",
    },

    # ─── Databases (detected via error messages) ───
    "MySQL": {
        "html": [r'mysql', r'MySQL Error', r'Warning: mysql_'],
        "category": "Database",
    },
    "PostgreSQL": {
        "html": [r'PostgreSQL', r'pg_query'],
        "category": "Database",
    },
    "MSSQL": {
        "html": [r'Microsoft SQL Server', r'SqlException', r'SQL Server error'],
        "category": "Database",
    },
    "MongoDB": {
        "html": [r'mongo', r'MongoError', r'mongod'],
        "category": "Database",
    },

    # ─── Analytics / Tracking ───
    "Google Analytics": {
        "scripts": [r'google-analytics', r'gtag', r'GA-'],
        "category": "Analytics",
    },
    "Google Tag Manager": {
        "scripts": [r'googletagmanager', r'GTM-'],
        "category": "Analytics",
    },
    "Yandex Metrika": {
        "scripts": [r'metrika', r'yaCounter'],
        "category": "Analytics",
    },
}

# Common paths for deep scanning
DEEP_PATHS: List[str] = [
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD",
    "/wp-admin/", "/wp-login.php", "/administrator/",
    "/admin/", "/admin/login", "/api/", "/api/v1/",
    "/swagger.json", "/openapi.json", "/graphql",
    "/.well-known/security.txt", "/favicon.ico",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/elmah.axd", "/trace.axd", "/Web.config",
    "/phpinfo.php", "/info.php", "/server-status",
    "/.htaccess", "/wp-config.php.bak",
    "/login", "/signin", "/auth/login",
    "/forgot-password", "/register", "/signup",
    "/health", "/status", "/ping",
    "/.well-known/openid-configuration",
]
