"""Site profile data structure for reconnaissance results.

Contains the SiteProfile dataclass that holds all discovered information
about a target website during the scanning phase.

BUG-030 fix (FR-P3-014): Converted from hand-written constructor to
@dataclass with __post_init__ for URL parsing.  All public APIs
(from_dict, to_dict, get) preserved for backward compatibility.

Pydantic validation is available through the ``validate_attack_profile()``
instance method and ``validate_profile()`` classmethod, which use the
models defined in ``finder.profile_models``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any
from urllib.parse import urlparse

from logging_config import get_logger
logger = get_logger(__name__)


@dataclass
class SiteProfile:
    """Complete technology profile of a target website.

    All scan results are stored in this single data structure,
    which is then serialized to VF_PROFILE.json for the attack engine.

    BUG-030 fix: Converted to @dataclass.  URL-derived fields (scheme,
    host, port, path, domain) are computed in __post_init__ from the
    required ``url`` field.  All other fields have defaults matching
    the original hand-written constructor.
    """

    # ─── Required field ───
    url: str

    # ─── URL-derived fields (computed in __post_init__) ───
    scheme: str = ""
    host: str | None = None
    port: int = 80
    path: str = ""
    domain: str = ""

    # ─── Schema version ───
    version: int = 1  # v26: Matches PROFILE_SCHEMA_VERSION in config/defaults.py

    # ─── Scan results ───
    scan_time: float = 0.0
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    server: str | None = None
    server_version: str | None = None
    os_guess: str | None = None
    backend_lang: str | None = None
    backend_framework: str | None = None
    frontend_frameworks: List[str] = field(default_factory=list)
    cms: str | None = None
    waf: str | None = None
    waf_confidence: float = 0.0
    cdn: str | None = None

    # ─── HTTP details ───
    status_code: int | None = None
    response_time: float = 0.0
    page_size: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    security_headers: Dict[str, Any] = field(default_factory=dict)
    redirect_chain: List[str] = field(default_factory=list)

    # ─── SSL/TLS ───
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    ssl_enabled: bool | None = False

    # ─── Content ───
    html_size: int = 0
    forms: List[Dict[str, Any]] = field(default_factory=list)
    hidden_fields: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    stylesheets: List[str] = field(default_factory=list)
    images: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    meta_tags: Dict[str, str] = field(default_factory=dict)

    # ─── ASP.NET specific ───
    viewstate_present: bool = False
    eventvalidation_present: bool = False
    login_fields: Dict[str, str] = field(default_factory=dict)

    # ─── Performance baseline ───
    baseline_rt: float = 0.0
    baseline_rts: List[float] = field(default_factory=list)
    rate_limit_detected: bool = False
    rate_limit_threshold: int | None = None

    # ─── DNS ───
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    ip_addresses: List[str] = field(default_factory=list)
    hosting_provider: str | None = None
    subdomains: List[str] = field(default_factory=list)

    # ─── Deep scan ───
    found_paths: List[Dict[str, Any]] = field(default_factory=list)
    sensitive_files: List[str] = field(default_factory=list)

    # ─── Origin IP (bypass CDN) ───
    origin_ips: List[str] = field(default_factory=list)
    origin_ip_sources: Dict[str, List[str]] = field(default_factory=dict)
    cdn_bypass_possible: bool = False

    # ─── Site category detection ───
    site_category: str | None = None
    edu_indicators: List[str] = field(default_factory=list)
    edu_endpoints: List[str] = field(default_factory=list)

    # ─── Attack recommendations (generated at end) ───
    attack_profile: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Parse URL and populate derived fields."""
        parsed = urlparse(self.url)
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.path = parsed.path
        self.domain = parsed.netloc.split(':')[0]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SiteProfile:
        """Create a SiteProfile from a dictionary (e.g., loaded from JSON).

        Handles key name differences between JSON format and SiteProfile
        attributes (e.g., "backend_language" → backend_lang,
        "response_time_ms" → response_time in seconds).

        Args:
            data: Dictionary loaded from VF_PROFILE.json or similar source.

        Returns:
            Populated SiteProfile instance.
        """
        url = data.get("url", "")
        profile = cls(url)

        # ─── URL-derived fields ───
        profile.scheme = data.get("scheme", profile.scheme)
        profile.host = data.get("host", profile.host)
        profile.port = data.get("port", profile.port)
        profile.domain = data.get("domain", profile.domain)

        # ─── Schema version ───
        profile.version = data.get("version", profile.version)

        # ─── Scan results ───
        profile.scan_time = data.get("scan_time", profile.scan_time)
        profile.technologies = data.get("technologies", profile.technologies)
        profile.server = data.get("server", profile.server)
        profile.server_version = data.get("server_version", profile.server_version)
        profile.os_guess = data.get("os_guess", profile.os_guess)
        # JSON key "backend_language" maps to attribute "backend_lang"
        profile.backend_lang = data.get("backend_lang") or data.get("backend_language", profile.backend_lang)
        profile.backend_framework = data.get("backend_framework", profile.backend_framework)
        profile.frontend_frameworks = data.get("frontend_frameworks", profile.frontend_frameworks)
        profile.cms = data.get("cms", profile.cms)
        profile.waf = data.get("waf", profile.waf)
        profile.waf_confidence = data.get("waf_confidence", profile.waf_confidence)
        profile.cdn = data.get("cdn", profile.cdn)

        # ─── HTTP details ───
        profile.status_code = data.get("status_code", profile.status_code)
        # JSON key "response_time_ms" → response_time (seconds)
        response_time_ms = data.get("response_time_ms")
        if response_time_ms is not None:
            profile.response_time = response_time_ms / 1000.0
        else:
            profile.response_time = data.get("response_time", profile.response_time)
        # JSON key "page_size_bytes" → page_size
        profile.page_size = data.get("page_size_bytes") or data.get("page_size", profile.page_size)
        profile.headers = data.get("headers", profile.headers)
        profile.cookies = data.get("cookies", profile.cookies)
        profile.security_headers = data.get("security_headers", profile.security_headers)
        profile.redirect_chain = data.get("redirect_chain", profile.redirect_chain)

        # ─── SSL/TLS ───
        profile.ssl_info = data.get("ssl_info", profile.ssl_info)
        profile.ssl_enabled = data.get("ssl_enabled", profile.ssl_enabled)

        # ─── Content ───
        profile.html_size = data.get("html_size", profile.html_size)
        profile.forms = data.get("forms", profile.forms)
        profile.hidden_fields = data.get("hidden_fields", profile.hidden_fields)
        profile.scripts = data.get("scripts", profile.scripts)
        profile.stylesheets = data.get("stylesheets", profile.stylesheets)
        profile.images = data.get("images", profile.images)
        profile.links = data.get("links", profile.links)
        profile.api_endpoints = data.get("api_endpoints", profile.api_endpoints)
        profile.meta_tags = data.get("meta_tags", profile.meta_tags)

        # ─── ASP.NET specific ───
        profile.viewstate_present = data.get("viewstate_present", profile.viewstate_present)
        profile.eventvalidation_present = data.get("eventvalidation_present", profile.eventvalidation_present)
        profile.login_fields = data.get("login_fields", profile.login_fields)

        # ─── Performance baseline ───
        # JSON key "baseline_rt_ms" → baseline_rt (seconds)
        baseline_rt_ms = data.get("baseline_rt_ms")
        if baseline_rt_ms is not None:
            profile.baseline_rt = baseline_rt_ms / 1000.0
        else:
            profile.baseline_rt = data.get("baseline_rt", profile.baseline_rt)
        profile.baseline_rts = data.get("baseline_rts", profile.baseline_rts)
        profile.rate_limit_detected = data.get("rate_limit_detected", profile.rate_limit_detected)
        profile.rate_limit_threshold = data.get("rate_limit_threshold", profile.rate_limit_threshold)

        # ─── DNS ───
        profile.dns_records = data.get("dns_records", profile.dns_records)
        profile.ip_addresses = data.get("ip_addresses", profile.ip_addresses)
        profile.hosting_provider = data.get("hosting_provider", profile.hosting_provider)
        profile.subdomains = data.get("subdomains", profile.subdomains)

        # ─── Deep scan ───
        profile.found_paths = data.get("found_paths", profile.found_paths)
        profile.sensitive_files = data.get("sensitive_files", profile.sensitive_files)

        # ─── Origin IP (bypass CDN) ───
        profile.origin_ips = data.get("origin_ips", profile.origin_ips)
        profile.origin_ip_sources = data.get("origin_ip_sources", profile.origin_ip_sources)
        profile.cdn_bypass_possible = data.get("cdn_bypass_possible", profile.cdn_bypass_possible)

        # ─── Site category detection ───
        profile.site_category = data.get("site_category", profile.site_category)
        profile.edu_indicators = data.get("edu_indicators", profile.edu_indicators)
        profile.edu_endpoints = data.get("edu_endpoints", profile.edu_endpoints)

        # ─── Attack recommendations ───
        profile.attack_profile = data.get("attack_profile", profile.attack_profile)

        return profile

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-compatible access for backward compatibility.

        Allows code that expects a dict-style ``profile.get("key", default)``
        to work transparently with a SiteProfile object.  Handles the key-name
        differences between JSON serialization and Python attribute names.

        Args:
            key: The profile key (same names used in VF_PROFILE.json).
            default: Value to return if the attribute is missing or None.

        Returns:
            The attribute value, or *default* if not found / None.
        """
        # Map JSON-serialized key names to SiteProfile attribute names.
        # NOTE: Keys that need unit conversion (ms → seconds) are handled
        # separately in _UNIT_CONVERT_KEYS below, NOT in _KEY_MAP, because
        # the raw attribute value must be transformed (not just renamed).
        _KEY_MAP: Dict[str, str] = {
            "backend_language": "backend_lang",
            "page_size_bytes": "page_size",
        }
        # Keys that require unit conversion: JSON stores ms, attributes store seconds.
        # These return the value in the *serialized* unit (ms) to match to_dict().
        _UNIT_CONVERT_KEYS: Dict[str, str] = {
            "response_time_ms": "response_time",   # attribute is seconds; get() returns ms
            "baseline_rt_ms": "baseline_rt",       # attribute is seconds; get() returns ms
        }
        # Computed keys that don't map to single attributes
        _COMPUTED_KEYS = {
            "scripts_count": lambda p: len(p.scripts),
            "stylesheets_count": lambda p: len(p.stylesheets),
            "images_count": lambda p: len(p.images),
            "links_count": lambda p: len(p.links),
            "page_size_human": lambda p: p._human_size(p.page_size),
        }

        if key in _COMPUTED_KEYS:
            try:
                return _COMPUTED_KEYS[key](self)
            except (AttributeError, TypeError):
                return default

        # Handle keys that need unit conversion (ms ↔ seconds)
        if key in _UNIT_CONVERT_KEYS:
            attr_name = _UNIT_CONVERT_KEYS[key]
            value = getattr(self, attr_name, None)
            if value is None:
                return default
            return value * 1000.0  # Convert seconds → ms (matches to_dict() output)

        attr_name = _KEY_MAP.get(key, key)
        value = getattr(self, attr_name, None)
        if value is None:
            return default
        return value

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the profile to a dictionary for JSON output."""
        return {
            "version": self.version,
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "domain": self.domain,
            "scan_time": round(self.scan_time, 2),
            "technologies": self.technologies,
            "server": self.server,
            "server_version": self.server_version,
            "os_guess": self.os_guess,
            "backend_language": self.backend_lang,
            "backend_framework": self.backend_framework,
            "frontend_frameworks": self.frontend_frameworks,
            "cms": self.cms,
            "waf": self.waf,
            "waf_confidence": self.waf_confidence,
            "cdn": self.cdn,
            "status_code": self.status_code,
            "response_time_ms": round(self.response_time * 1000, 1),
            "page_size_bytes": self.page_size,
            "page_size_human": self._human_size(self.page_size),
            "headers": self.headers,
            "cookies": self.cookies,
            "security_headers": self.security_headers,
            "ssl_enabled": self.ssl_enabled,
            "ssl_info": self.ssl_info,
            "html_size": self.html_size,
            "forms": self.forms,
            "hidden_fields": self.hidden_fields,
            "scripts": self.scripts,
            "scripts_count": len(self.scripts),
            "stylesheets_count": len(self.stylesheets),
            "images_count": len(self.images),
            "links_count": len(self.links),
            "api_endpoints": self.api_endpoints,
            "meta_tags": self.meta_tags,
            "viewstate_present": self.viewstate_present,
            "eventvalidation_present": self.eventvalidation_present,
            "login_fields": self.login_fields,
            "baseline_rt_ms": round(self.baseline_rt * 1000, 1),
            "rate_limit_detected": self.rate_limit_detected,
            "rate_limit_threshold": self.rate_limit_threshold,
            "dns_records": self.dns_records,
            "ip_addresses": self.ip_addresses,
            "hosting_provider": self.hosting_provider,
            "subdomains": self.subdomains,
            "found_paths": self.found_paths,
            "sensitive_files": self.sensitive_files,
            "origin_ips": self.origin_ips,
            "origin_ip_sources": self.origin_ip_sources,
            "cdn_bypass_possible": self.cdn_bypass_possible,
            "site_category": self.site_category,
            "edu_indicators": self.edu_indicators,
            "edu_endpoints": self.edu_endpoints,
            "attack_profile": self.attack_profile,
        }

    @staticmethod
    def _human_size(size: int) -> str:
        """Convert bytes to human-readable size string."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    # ─── Pydantic Validation Methods ────────────────────────────────────

    def validate_attack_profile(self) -> finder.profile_models.AttackProfile:
        """Validate the attack_profile dict using Pydantic.

        Returns:
            A validated AttackProfile Pydantic model instance.

        Raises:
            pydantic.ValidationError: If the attack_profile contains
                invalid data (e.g., negative worker counts, bad URLs).
        """
        from finder.profile_models import AttackProfile
        return AttackProfile(**self.attack_profile)

    @classmethod
    def validate_profile(cls, data: Dict[str, Any]) -> finder.profile_models.ProfileSchema:
        """Validate a full profile dict using Pydantic.

        Useful for validating data loaded from VF_PROFILE.json before
        passing it to ``from_dict()``.

        Args:
            data: Dictionary loaded from VF_PROFILE.json.

        Returns:
            A validated ProfileSchema Pydantic model instance.

        Raises:
            pydantic.ValidationError: If the profile data is invalid.
        """
        from finder.profile_models import ProfileSchema
        return ProfileSchema(**data)
