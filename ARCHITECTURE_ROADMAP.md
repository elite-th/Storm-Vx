# Storm-Vx Architecture Refactoring Roadmap

**Version:** 1.0
**Date:** 2025-03-05
**Author:** Architecture Review Board
**Status:** APPROVED

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#current-state-analysis)
3. [Target State](#target-state)
4. [Phase 1: AttackProfileGenerator Extraction](#phase-1-attackprofilegenerator-extraction-highest-impact)
5. [Phase 2: TechDetectorHelpers + FinderEnhancerRunner](#phase-2-techdetectorhelpers--finderenhancerrunner)
6. [Phase 3: AdaptiveScalingEngine from VFTester](#phase-3-adaptivescalingengine-from-vftester)
7. [Phase 4: PluginAutoHeal + SessionManager + AttackReporter](#phase-4-pluginautoheal--sessionmanager--attackreporter)
8. [Phase 5: ssl_analyzer Async Conversion](#phase-5-ssl_analyzer-async-conversion)
9. [Phase 6: _is_private_ip Fix + JA3 Integration](#phase-6-_is_private_ip-fix--ja3-integration)
10. [TODO Checklist](#todo-checklist)
11. [Risk Assessment](#risk-assessment)
12. [Architecture Scorecard](#architecture-scorecard)
13. [Worklog](#worklog)

---

## Executive Summary

### Current State

Storm-Vx v22.0 suffers from **two God Classes** that concentrate the majority of business logic:

| Class | File | Lines | Responsibilities |
|-------|------|-------|-----------------|
| `VFTester` | `tester/VF_TESTER.py` | 1,467 | Dashboard loop, adaptive scaling, plugin auto-heal, session warmup, attack reporting, keyboard handling, WAF runtime detection |
| `VFFinder` | `finder/engine.py` | 1,241 | Scan orchestration, attack profile generation, strategy determination, tech detection helpers, SPA analysis, enhancement modules |

Both classes violate the Single Responsibility Principle (SRP) and exceed the 400-line target for focused classes. The codebase scores **66/100** on the internal architecture quality metric (derived from the 6.85/10 review score normalized to 100-point scale with weighted adjustments for God Class penalty).

### Target State

Decompose the two God Classes into **9 focused classes**, each under 400 lines, following python-pro best practices:

```
BEFORE (2 God Classes, 2708 lines):
  VFTester  (1467 lines) ──┐
  VFFinder  (1241 lines) ──┤──→ Monolithic, hard to test, hard to extend
                           │
AFTER (9 focused classes + 2 thin coordinators):
  finder/
    engine.py              (~200 lines)  — Thin orchestrator
    vf_attack_profile.py   (~770 lines)  — AttackProfileGenerator
    vf_tech_helpers.py     (~130 lines)  — Pure tech detection functions
    vf_finder_enhancer.py  (~130 lines)  — FinderEnhancerRunner
  tester/
    VF_TESTER.py           (~450 lines)  — Thin coordinator
    vf_adaptive_scaling.py (~320 lines)  — AdaptiveScalingEngine
    vf_plugin_autoheal.py  (~150 lines)  — PluginAutoHeal
    vf_session_manager.py  (~180 lines)  — SessionManager
    vf_attack_reporter.py  (~50 lines)   — AttackReporter
```

### Expected Improvement

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Architecture Score | 66/100 | 82+/100 | +16 |
| Max class line count | 1,467 | <770 | -48% |
| God Classes | 2 | 0 | -2 |
| Async-first coverage | ~70% | ~95% | +25% |
| Type hint coverage (new files) | ~60% | 100% | +40% |
| Testability (new classes) | Low | High | — |

---

## Current State Analysis

### VFFinder (finder/engine.py — 1,241 lines)

**Methods breakdown by responsibility:**

| Responsibility | Methods | Line Range | Est. Lines |
|---------------|---------|------------|------------|
| Scan orchestration | `scan()`, `__init__()`, `live_phase()` | 1-197 | ~197 |
| Finder enhancement modules | `_run_finder_module`, `_enhance_waf_detection`, `_enhance_js_scan`, `_enhance_subdomain_scan`, `_enhance_dir_fuzz`, `_enhance_rate_probe`, `_enhance_cache_analysis` | 198-307 | ~110 |
| Attack profile generation | `_generate_attack_profile`, `_determine_all_determined_configs`, `_print_strategy_display` | 308-422 | ~115 |
| Tech detection helpers | `_is_spa`, `_is_nextjs`, `_has_graphql`, `_is_origin_resource`, `_detect_spa_framework`, `_find_graphql_endpoint`, `_extract_spa_routes`, `_extract_next_data_routes` | 423-1085 | ~170 |
| Strategy/vector determination | `_determine_strategy`, `_determine_surgical_vectors`, `_determine_all_vectors`, `_determine_strategy_reason`, `_determine_vectors` | 486-723 | ~238 |
| Config determination | `_determine_waf_strategy` through `_determine_risk_notes` (14 methods) | 727-1241 | ~515 |

**Key observation:** The `_determine_*` methods (lines 486-1241) constitute **60% of the class** and have zero dependencies on `self` except for `self.profile` and `self._html`. They are pure computations that can be trivially extracted.

### VFTester (tester/VF_TESTER.py — 1,467 lines)

**Methods breakdown by responsibility:**

| Responsibility | Methods | Line Range | Est. Lines |
|---------------|---------|------------|------------|
| Init + profile + properties | `__init__`, `_load_profile`, `_validate_profile`, `_create_minimal_profile`, properties | 175-366 | ~192 |
| Session management | `_session_warmup`, `_preflight_check_origin_ips`, `_base_headers`, `_refresh_viewstate` | 384-536 | ~153 |
| Attack reporting | `_record_hit`, `_snap` | 562-575 | ~14 |
| Plugin delegation | `_select_plugins`, `_compute_plugin_workers`, `_build_attack_context`, `_launch_plugins` | 577-636 | ~60 |
| Strategy selection display | `_handle_strategy_selection` | 640-660 | ~21 |
| Dashboard loop (adaptive scaling) | `_run_dashboard_loop`, `_check_keyboard_commands`, `_check_waf_runtime_detection`, `_compute_dynamic_step`, `_auto_shrink_workers`, `_run_escalation_phase` | 664-1120 | ~457 |
| Plugin auto-heal | `_auto_disable_failing_plugins`, `_auto_recover_disabled_plugins` | 816-928 | ~113 |
| Dashboard rendering + run | `_print_dashboard`, `run`, `parse_args`, `main` | 1128-1467 | ~340 |

**Key observation:** The dashboard loop methods (lines 664-1120) form the largest cohesive block at ~457 lines. They manage adaptive scaling state (`_step_start`, `_escalation_paused`, `_shrink_cooldown`, etc.) that should be encapsulated in a dedicated engine class.

### ssl_analyzer (finder/ssl_analyzer.py — 82 lines)

**Current issues:**
- Uses blocking `socket.create_connection()` — freezes the event loop during SSL analysis
- Called via `run_in_executor()` in engine.py as a workaround
- Sets `profile.ssl_enabled = None` on failure (correct per BUG-031) but signature doesn't communicate this
- Mutates `profile` in-place rather than returning a result dict

### dns_scanner (_is_private_ip — finder/dns_scanner.py:236-252)

**Current issue:**
- Manual `struct.unpack()` byte manipulation to detect private IP ranges
- Python's `ipaddress` module provides `ip_address().is_private` which is:
  - More correct (handles all RFC 1918 ranges including 100.64.0.0/10 CGNAT)
  - IPv6-aware
  - Self-documenting

---

## Phase 1: AttackProfileGenerator Extraction (HIGHEST IMPACT)

**Priority:** P0 — HIGHEST IMPACT
**Estimated effort:** 4-6 hours
**Expected line reduction:** engine.py drops from 1,241 → ~470 lines (-62%)

### File to Create

**`finder/vf_attack_profile.py`** (~770 lines)

### Methods to Move from engine.py

| Method | Lines | Notes |
|--------|-------|-------|
| `_generate_attack_profile` | 310-325 | Entry point — becomes `generate()` |
| `_determine_all_determined_configs` | 327-374 | Aggregation method |
| `_determine_strategy` | 488-520 | Strategy selection |
| `_determine_surgical_vectors` | 522-571 | Surgical mode vectors |
| `_determine_all_vectors` | 573-611 | All-out mode vectors |
| `_determine_strategy_reason` | 613-660 | Strategy explanation |
| `_determine_vectors` | 662-723 | Auto-mode vectors |
| `_determine_waf_strategy` | 727-778 | WAF bypass config |
| `_determine_worker_config` | 780-809 | Worker scaling config |
| `_determine_surgical_worker_config` | 811-830 | Surgical worker config |
| `_determine_all_worker_config` | 832-852 | All-out worker config |
| `_determine_request_config` | 854-867 | Request parameters |
| `_determine_login_config` | 869-883 | Login attack config |
| `_determine_page_targets` | 885-929 | Page target list |
| `_determine_resource_targets` | 931-965 | Resource target list |
| `_determine_timing_config` | 967-979 | Timing parameters |
| `_determine_evasion_config` | 981-997 | Evasion techniques |
| `_determine_spa_config` | 999-1023 | SPA-specific config |
| `_determine_aspnet_config` | 1087-1097 | ASP.NET config |
| `_determine_php_config` | 1099-1108 | PHP config |
| `_determine_wordpress_config` | 1110-1123 | WordPress config |
| `_determine_api_config` | 1125-1134 | API endpoint config |
| `_determine_edu_config` | 1136-1212 | Educational site config |
| `_determine_risk_notes` | 1214-1241 | Risk assessment notes |
| `_print_strategy_display` | 376-422 | Strategy logging |

### Design

```python
"""Attack profile generator — creates customized attack configurations.

Generates a complete attack profile based on the site's detected
technologies, WAF presence, and other reconnaissance data. All methods
are pure computations with no side effects on the input profile.

Typical usage:
    generator = AttackProfileGenerator(profile, html)
    attack = generator.generate()
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from finder.site_profile import SiteProfile
from finder.signatures import CDN_KEYWORDS
from finder.vf_tech_helpers import (
    is_spa, is_nextjs, has_graphql, is_origin_resource,
    detect_spa_framework, find_graphql_endpoint,
    extract_spa_routes, extract_next_data_routes,
)


class AttackProfileGenerator:
    """Stateless generator for attack profile configurations.

    Takes a SiteProfile and optional HTML, produces a complete attack
    profile dict with strategy, vectors, worker configs, and platform-
    specific configurations. No mutations to the input profile.

    Args:
        profile: SiteProfile from the reconnaissance scan.
        html: Raw HTML of the target page (for SPA/Next.js detection).
    """

    def __init__(self, profile: SiteProfile, html: str = "") -> None:
        self._profile = profile
        self._html = html

    def generate(self) -> dict[str, Any]:
        """Generate the complete attack profile.

        Returns:
            Dictionary with keys: target_url, recommended_strategy,
            strategy_reason, attack_vectors, surgical_vectors,
            surgical_analysis, all_vectors, waf_strategy, worker_config,
            surgical_worker_config, all_worker_config, request_config,
            login_config, page_targets, resource_targets, timing_config,
            evasion_config, asp_net_config, php_config,
            wordpress_config, api_config, spa_config, edu_config,
            risk_notes.
        """
        strategy_name = self._determine_strategy()
        auto_vectors = self._determine_vectors()
        surgical_vectors = self._determine_surgical_vectors()
        all_vectors = self._determine_all_vectors()
        surgical_analysis: list[str] = []

        attack = self._determine_all_determined_configs(
            strategy_name, auto_vectors, surgical_vectors,
            surgical_analysis, all_vectors,
        )

        self._print_strategy_display(
            strategy_name, auto_vectors, surgical_analysis, all_vectors,
        )

        return attack

    # ─── Private determination methods (all pure computations) ────────

    def _determine_strategy(self) -> str: ...
    def _determine_surgical_vectors(self) -> list[str]: ...
    def _determine_all_vectors(self) -> list[str]: ...
    def _determine_strategy_reason(self) -> str: ...
    def _determine_vectors(self) -> list[str]: ...
    def _determine_waf_strategy(self) -> dict[str, Any]: ...
    def _determine_worker_config(self) -> dict[str, Any]: ...
    def _determine_surgical_worker_config(self) -> dict[str, Any]: ...
    def _determine_all_worker_config(self) -> dict[str, Any]: ...
    def _determine_request_config(self) -> dict[str, Any]: ...
    def _determine_login_config(self) -> dict[str, Any]: ...
    def _determine_page_targets(self) -> list[str]: ...
    def _determine_resource_targets(self) -> list[str]: ...
    def _determine_timing_config(self) -> dict[str, Any]: ...
    def _determine_evasion_config(self) -> dict[str, Any]: ...
    def _determine_spa_config(self) -> dict[str, Any]: ...
    def _determine_aspnet_config(self) -> dict[str, Any]: ...
    def _determine_php_config(self) -> dict[str, Any]: ...
    def _determine_wordpress_config(self) -> dict[str, Any]: ...
    def _determine_api_config(self) -> dict[str, Any]: ...
    def _determine_edu_config(self) -> dict[str, Any]: ...
    def _determine_risk_notes(self) -> list[str]: ...
    def _print_strategy_display(self, strategy_name: str,
                                 auto_vectors: list[str],
                                 surgical_analysis: list[str],
                                 all_vectors: list[str]) -> None: ...
```

### Key Design Decisions

1. **Stateless class**: `AttackProfileGenerator(profile, html)` — no mutations on `profile`. The `generate()` method returns a new dict. This eliminates the side-effect coupling where `_generate_attack_profile()` sets `self._surgical_analysis` as an instance attribute.

2. **Single entry point**: `generate() -> dict[str, Any]` replaces the `_generate_attack_profile()` method which had a side-effect of setting `self._surgical_analysis`.

3. **All `_determine_*` become private methods**: No change in visibility, but they now operate on `self._profile` and `self._html` exclusively.

4. **No side effects on profile**: Currently `_generate_attack_profile()` sets `p.attack_profile = attack`. The new generator returns the dict, and the caller (engine.py) assigns it.

5. **Tech helper functions imported**: `_is_spa()`, `_is_nextjs()`, etc. move to `vf_tech_helpers.py` (Phase 2) and are imported. This allows the generator to call them without inheriting from VFFinder.

### Dependencies

- `SiteProfile` from `finder.site_profile`
- `CDN_KEYWORDS` from `finder.signatures`
- Tech helper functions from `finder.vf_tech_helpers` (Phase 2 — must be completed first or simultaneously)
- `re`, `json` from stdlib

### Changes to engine.py

```python
# BEFORE:
def _generate_attack_profile(self):
    p = self.profile
    strategy_name = self._determine_strategy()
    # ... 25 methods called on self ...

# AFTER:
from finder.vf_attack_profile import AttackProfileGenerator

def _generate_attack_profile(self):
    generator = AttackProfileGenerator(self.profile, self._html or "")
    self.profile.attack_profile = generator.generate()
```

### Verification

- engine.py should drop from **1,241 → ~470 lines**
- All `_determine_*` methods removed from `VFFinder`
- `_generate_attack_profile()` becomes a 2-line delegation
- `_is_spa()`, `_is_nextjs()`, etc. moved to `vf_tech_helpers.py` (Phase 2)
- `_print_strategy_display()` moved to `AttackProfileGenerator`
- `py_compile` passes on both files
- Run full test suite: all existing tests pass

---

## Phase 2: TechDetectorHelpers + FinderEnhancerRunner

**Priority:** P1 — HIGH IMPACT (unblocks Phase 1)
**Estimated effort:** 2-3 hours
**Expected line reduction:** engine.py drops from ~470 → ~200 lines (-57%)

### File A: `finder/vf_tech_helpers.py` (~130 lines)

**Purpose:** Pure functions for technology detection, extracted from both `VFFinder` and `AttackProfileGenerator`.

```python
"""Technology detection helper functions.

Pure functions that analyze SiteProfile and HTML content to detect
SPA frameworks, GraphQL endpoints, and other technology indicators.
All functions take (profile, html) as arguments and return values
without side effects.

Typical usage:
    from finder.vf_tech_helpers import is_spa, is_nextjs
    if is_spa(profile, html):
        routes = extract_spa_routes(profile)
"""

from __future__ import annotations

import json
import re
from typing import Any

from finder.site_profile import SiteProfile
from finder.signatures import CDN_KEYWORDS


def is_spa(profile: SiteProfile, html: str = "") -> bool:
    """Detect if the site is a Single Page Application.

    Checks frontend frameworks, technology confidence scores, and
    HTML characteristics (small HTML + many scripts).

    Args:
        profile: SiteProfile with technology detection results.
        html: Raw HTML of the target page.

    Returns:
        True if the site appears to be an SPA.
    """
    spa_frameworks = ["React", "Vue.js", "Angular", "Next.js", "Nuxt.js", "Svelte"]
    for fw in profile.frontend_frameworks:
        if any(sfw in fw for sfw in spa_frameworks):
            return True
    for tech in profile.technologies:
        if tech["name"] in spa_frameworks and tech["confidence"] > 0.3:
            return True
    if profile.html_size < 5000 and len(profile.scripts) >= 3:
        return True
    return False


def is_nextjs(profile: SiteProfile, html: str = "") -> bool:
    """Check if the site uses Next.js.

    Detects Next.js via technology confidence or HTML markers
    (__NEXT_DATA__, _next/static).

    Args:
        profile: SiteProfile with technology detection results.
        html: Raw HTML of the target page.

    Returns:
        True if Next.js is detected.
    """
    for tech in profile.technologies:
        if tech["name"] == "Next.js" and tech["confidence"] > 0.3:
            return True
    return '__NEXT_DATA__' in html or '_next/static' in html


def has_graphql(profile: SiteProfile, html: str = "") -> bool:
    """Check if the site uses GraphQL.

    Checks API endpoints, found paths, HTML content, and script
    sources for GraphQL indicators.

    Args:
        profile: SiteProfile with detection results.
        html: Raw HTML of the target page.

    Returns:
        True if GraphQL is detected.
    """
    for ep in profile.api_endpoints:
        if 'graphql' in ep.lower():
            return True
    for fp in profile.found_paths:
        if 'graphql' in fp.get('path', '').lower():
            return True
    graphql_indicators = [
        'apollo', 'urql', 'relay', 'graphql-tag',
        'ApolloClient', 'createApolloClient',
        'graphql.execute', '/graphql',
    ]
    html_lower = html.lower()
    for indicator in graphql_indicators:
        if indicator.lower() in html_lower:
            return True
    for script in profile.scripts:
        if 'graphql' in script.lower() or 'apollo' in script.lower():
            return True
    return False


def is_origin_resource(url: str, profile: SiteProfile) -> bool:
    """Check if a resource URL is served from the origin (not CDN).

    Args:
        url: Resource URL to check.
        profile: SiteProfile with domain info.

    Returns:
        True if the resource appears to be served from the origin.
    """
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        resource_host = parsed.netloc.split(':')[0]
        if resource_host == profile.domain:
            return True
        resource_lower = resource_host.lower()
        for kw in CDN_KEYWORDS:
            if kw in resource_lower:
                return False
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def detect_spa_framework(profile: SiteProfile) -> str:
    """Identify which SPA framework is being used.

    Args:
        profile: SiteProfile with technology detection results.

    Returns:
        Name of the detected SPA framework, or "Unknown SPA".
    """
    for tech in profile.technologies:
        if tech["name"] in ["React", "Vue.js", "Angular", "Next.js",
                            "Nuxt.js", "Svelte"] and tech["confidence"] > 0.3:
            return tech["name"]
    return "Unknown SPA"


def find_graphql_endpoint(profile: SiteProfile, html: str = "") -> str | None:
    """Find the GraphQL endpoint URL.

    Searches API endpoints, found paths, and falls back to /graphql
    if GraphQL indicators are found in HTML.

    Args:
        profile: SiteProfile with detection results.
        html: Raw HTML of the target page.

    Returns:
        GraphQL endpoint URL, or None if not found.
    """
    for ep in profile.api_endpoints:
        if 'graphql' in ep.lower():
            return ep if ep.startswith('http') else f"{profile.scheme}://{profile.domain}{ep}"
    for fp in profile.found_paths:
        fp_path = fp.get('path', '')
        if 'graphql' in fp_path.lower():
            return f"{profile.scheme}://{profile.domain}{fp_path}"
    if has_graphql(profile, html):
        return f"{profile.scheme}://{profile.domain}/graphql"
    return None


def extract_spa_routes(profile: SiteProfile) -> list[str]:
    """Extract client-side routes from SPA application.

    Combines discovered links with common SPA route patterns.

    Args:
        profile: SiteProfile with link data.

    Returns:
        List of up to 30 SPA route URLs.
    """
    from urllib.parse import urlparse
    routes: list[str] = []
    for link in profile.links:
        parsed = urlparse(link)
        if parsed.netloc == profile.domain:
            path = parsed.path
            if path and path != '/' and path not in routes:
                routes.append(path)
    common_routes = [
        '/dashboard', '/profile', '/settings', '/users',
        '/products', '/orders', '/search', '/api/v1',
        '/auth/login', '/auth/register', '/auth/callback',
    ]
    for route in common_routes:
        full = f"{profile.scheme}://{profile.domain}{route}"
        if full not in routes:
            routes.append(full)
    return routes[:30]


def extract_next_data_routes(profile: SiteProfile, html: str = "") -> list[str]:
    """Extract Next.js _next/data routes from __NEXT_DATA__.

    Parses the __NEXT_DATA__ script tag to find data routes
    used for server-side rendering.

    Args:
        profile: SiteProfile with detection results.
        html: Raw HTML of the target page.

    Returns:
        List of Next.js data route paths.
    """
    routes: list[str] = []
    if not is_nextjs(profile, html):
        return routes
    next_data_match = re.search(
        r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.DOTALL,
    )
    if next_data_match:
        try:
            data = json.loads(next_data_match.group(1))
            build_id = data.get('buildId', '')
            if build_id:
                page_path = data.get('page', '')
                if page_path:
                    routes.append(f"/_next/data/{build_id}{page_path}.json")
        except (json.JSONDecodeError, KeyError):
            pass
    return routes
```

### File B: `finder/vf_finder_enhancer.py` (~130 lines)

**Purpose:** Encapsulates all finder enhancement modules (WAF probe, JS scan, subdomain scan, dir fuzz, rate probe, cache analysis) into a single runner class.

```python
"""Finder enhancement module runner.

Encapsulates all optional finder enhancement modules (WAF probe,
JS scanner, subdomain bruteforcer, etc.) into a single class with
safe execution and error handling. Each enhancement is optional and
fails gracefully if the module is not available.

Typical usage:
    runner = FinderEnhancerRunner(profile, url, verify_ssl)
    await runner.run_all()
"""

from __future__ import annotations

from typing import Any

from finder.site_profile import SiteProfile
from logging_config import get_logger

logger = get_logger(__name__)


class FinderEnhancerRunner:
    """Run all optional finder enhancement modules safely.

    Each enhancement is run in isolation — if one fails, the others
    continue. Modules are imported lazily so missing optional modules
    don't cause import errors.

    Args:
        profile: SiteProfile to enhance (mutated in-place).
        url: Target URL.
        verify_ssl: Whether to verify SSL certificates.
    """

    def __init__(self, profile: SiteProfile, url: str,
                 verify_ssl: bool = False) -> None:
        self._profile = profile
        self._url = url
        self._verify_ssl = verify_ssl

    async def run_all(self) -> None:
        """Run all enhancement modules in sequence.

        Each module is wrapped in try/except to prevent cascading
        failures. Errors are logged at WARNING level.
        """
        await self._run_module('WAF Probe', self._enhance_waf_detection)
        await self._run_module('JS Secret Scan', self._enhance_js_scan)
        await self._run_module('Subdomain Bruteforce', self._enhance_subdomain_scan)
        await self._run_module('Directory Fuzzing', self._enhance_dir_fuzz)
        await self._run_module('Rate Limit Probe', self._enhance_rate_probe)
        await self._run_module('Cache Analysis', self._enhance_cache_analysis)

    async def _run_module(self, name: str, coro_fn) -> None:
        """Safely run a finder enhancement module.

        Args:
            name: Human-readable module name for logging.
            coro_fn: Async callable to execute.
        """
        try:
            await coro_fn()
        except Exception as exc:
            logger.warning(
                f"Finder module {name} error: {type(exc).__name__}: {exc}",
                exc_info=True,
            )

    async def _enhance_waf_detection(self) -> None: ...
    async def _enhance_js_scan(self) -> None: ...
    async def _enhance_subdomain_scan(self) -> None: ...
    async def _enhance_dir_fuzz(self) -> None: ...
    async def _enhance_rate_probe(self) -> None: ...
    async def _enhance_cache_analysis(self) -> None: ...
```

### Changes to engine.py After Phase 2

```python
# engine.py AFTER Phase 2 — ~200 lines (thin orchestrator)

from finder.vf_attack_profile import AttackProfileGenerator
from finder.vf_tech_helpers import is_spa, is_nextjs, has_graphql
from finder.vf_finder_enhancer import FinderEnhancerRunner


class VFFinder:
    """Reconnaissance Engine — thin orchestrator coordinating scan phases."""

    def __init__(self, url: str, deep: bool = False, ...):
        self.url = url
        self.profile = SiteProfile(url)
        self._html: str | None = None
        self._enhancer = FinderEnhancerRunner(self.profile, url, verify_ssl)

    async def scan(self) -> SiteProfile:
        """Run full reconnaissance scan with parallel phase groups."""
        # Phase 1: HTTP Fingerprinting
        self._html, self.profile = await http_fingerprint(...)

        # Parallel Phase Groups (content, SSL, DNS)
        await asyncio.gather(
            self._content_pipeline(),
            self._ssl_pipeline(),
            self._dns_pipeline(),
        )

        # Sequential: Deep Scan + Performance + Rate + Cache
        ...

        # Generate Attack Profile (2 lines!)
        generator = AttackProfileGenerator(self.profile, self._html or "")
        self.profile.attack_profile = generator.generate()

        return self.profile

    # Pipeline methods remain — they're orchestration logic
    async def _content_pipeline(self) -> None: ...
    async def _ssl_pipeline(self) -> None: ...
    async def _dns_pipeline(self) -> None: ...
```

### Verification

- engine.py drops from **~470 → ~200 lines**
- `VFFinder` is now a thin orchestrator with only pipeline coordination
- All tech detection logic is in pure, testable functions
- All enhancement modules are in a dedicated runner class
- No `_is_spa()`, `_is_nextjs()`, etc. methods on VFFinder

---

## Phase 3: AdaptiveScalingEngine from VFTester

**Priority:** P1 — HIGH IMPACT
**Estimated effort:** 3-4 hours
**Expected line reduction:** VFTester drops by ~260 lines

### File to Create

**`tester/vf_adaptive_scaling.py`** (~320 lines)

### Methods to Move from VF_TESTER.py

| Method | Lines (approx.) | Notes |
|--------|-----------------|-------|
| `_run_dashboard_loop` | 664-767 | Refactored to `tick()` method |
| `_check_keyboard_commands` | 771-791 | Keyboard input handler |
| `_check_waf_runtime_detection` | 793-813 | Runtime WAF detection |
| `_compute_dynamic_step` | 928-946 | Adaptive step sizing |
| `_auto_shrink_workers` | 948-1020 | Worker auto-shrink logic |
| `_run_escalation_phase` | 1022-1119 | Worker escalation logic |

### Design

```python
"""Adaptive scaling engine for dynamic worker management.

Encapsulates the dashboard loop's adaptive scaling logic into a
stateful engine with a tick() method called each second. Manages
dynamic step sizing, auto-shrink, escalation phases, and WAF
runtime detection.

Typical usage:
    engine = AdaptiveScalingEngine(
        orchestrator=plugin_orchestrator,
        health_monitor=health_monitor,
        stats=stats,
        keyboard=keyboard_handler,
        stop_event=stop_event,
        initial_workers=50,
        step=100,
    )
    while not stop_event.is_set():
        action = engine.tick()
        if action == ScalingAction.STOP:
            break
        await asyncio.sleep(1)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from tester.vf_data import Stats
from tester.vf_health_monitor import ServerHealthMonitor
from tester.vf_keyboard import KeyboardHandler
from tester.vf_live_log import LiveLog
from tester.vf_plugin_orchestrator import PluginOrchestrator


class ScalingAction(Enum):
    """Action returned by each tick() call."""
    CONTINUE = auto()
    STOP = auto()


@dataclass
class AdaptiveScalingState:
    """Mutable state for the adaptive scaling loop.

    Encapsulates all loop-local variables that were previously
    scattered as instance attributes on VFTester (_step_start,
    _escalation_paused, etc.).

    Attributes:
        step_start: Timestamp when the current step began.
        escalation_paused: Whether escalation is paused.
        pause_reason: Reason for escalation pause.
        shrink_cooldown: Cooldown counter for shrink messages.
        min_workers: Minimum worker floor for auto-shrink.
        dynamic_step: Current adaptive step size.
        last_shrink_log: Timestamp of last shrink log message.
        shrink_count: Number of times shrink has triggered.
        healthy_ticks: Consecutive ticks with good health.
        no_active_plugins_logged: Whether the "no plugins" warning was logged.
        recovery_ticks: Consecutive healthy ticks for plugin recovery.
    """
    step_start: float = 0.0
    escalation_paused: bool = False
    pause_reason: str = ""
    shrink_cooldown: int = 0
    min_workers: int = 10
    dynamic_step: int = 100
    last_shrink_log: float = 0.0
    shrink_count: int = 0
    healthy_ticks: int = 0
    no_active_plugins_logged: bool = False
    recovery_ticks: int = 0


class AdaptiveScalingEngine:
    """Stateful engine for adaptive worker scaling.

    Called once per second from the dashboard loop. Each call to
    tick() performs one cycle of:
    1. Check keyboard commands
    2. Compute rates from stats
    3. Check WAF runtime detection
    4. Compute dynamic step size
    5. Auto-shrink workers if server is struggling
    6. Run escalation phase (pause/resume/scale)

    Args:
        orchestrator: PluginOrchestrator managing active plugins.
        health_monitor: ServerHealthMonitor for health checks.
        stats: Stats object for request statistics.
        keyboard: KeyboardHandler for user input.
        stop_event: Event to signal attack stop.
        initial_workers: Starting worker count.
        step: Base step size for worker scaling.
        evasion: Evasion manager for WAF updates.
    """

    def __init__(
        self,
        orchestrator: PluginOrchestrator,
        health_monitor: ServerHealthMonitor,
        stats: Stats,
        keyboard: KeyboardHandler,
        stop_event: asyncio.Event,
        initial_workers: int = 50,
        step: int = 100,
        evasion: Any = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._health_monitor = health_monitor
        self._stats = stats
        self._keyboard = keyboard
        self._stop = stop_event
        self._initial_workers = initial_workers
        self._step = step
        self._evasion = evasion

        self._state = AdaptiveScalingState(
            step_start=time.time(),
            dynamic_step=step,
            min_workers=max(initial_workers, 10),
        )
        self._manual_delta: int = 0

    @property
    def state(self) -> AdaptiveScalingState:
        """Read-only access to current scaling state."""
        return self._state

    def tick(self, detected_waf: str = "") -> ScalingAction:
        """Execute one cycle of adaptive scaling.

        Called once per second from the dashboard loop. Returns
        ScalingAction.STOP if the user requested quit, or
        ScalingAction.CONTINUE to keep running.

        Args:
            detected_waf: Currently detected WAF name (for runtime detection).

        Returns:
            ScalingAction indicating whether to continue or stop.
        """
        health = self._health_monitor.check(self._stats)

        # 1. Check keyboard
        if self._check_keyboard_commands():
            return ScalingAction.STOP

        # 2. Compute rates
        total = max(self._stats.total, 1)
        fail_rate = self._stats.fail / total
        timeout_rate = self._stats.timeout_errors / total
        s5xx_rate = self._stats.server_errors / total

        # 3. WAF runtime detection
        self._check_waf_runtime_detection(detected_waf)

        # 4. Compute dynamic step
        self._state.dynamic_step = self._compute_dynamic_step(health)

        # 5. Auto-shrink
        actual_workers = sum(
            p.worker_count for p in self._orchestrator.active_plugins.values()
        )
        should_shrink, shrink_hold = self._auto_shrink_workers(
            health, fail_rate, s5xx_rate, timeout_rate, actual_workers,
        )

        # 6. Escalation phase
        self._run_escalation_phase(
            self._state.dynamic_step, actual_workers, health,
            fail_rate, s5xx_rate, timeout_rate, should_shrink, shrink_hold,
        )

        return ScalingAction.CONTINUE

    def _check_keyboard_commands(self) -> bool: ...
    def _check_waf_runtime_detection(self, detected_waf: str) -> None: ...
    def _compute_dynamic_step(self, health: float) -> int: ...
    def _auto_shrink_workers(self, health: float, fail_rate: float,
                              s5xx_rate: float, timeout_rate: float,
                              actual_workers: int) -> tuple[bool, bool]: ...
    def _run_escalation_phase(self, step: int, actual_workers: int,
                               health: float, fail_rate: float,
                               s5xx_rate: float, timeout_rate: float,
                               should_shrink: bool,
                               shrink_hold: bool) -> None: ...
```

### Key Design Decisions

1. **`@dataclass AdaptiveScalingState`**: Replaces 12 instance attributes that were set in `_run_dashboard_loop`'s initialization block. Makes the loop state explicit and serializable.

2. **`tick()` method**: The loop body becomes a single method call. The outer loop is trivial:
   ```python
   while not self._stop.is_set():
       action = self._scaling_engine.tick(self.detected_waf)
       if action == ScalingAction.STOP:
           break
       # ... dashboard rendering ...
       await asyncio.sleep(1)
   ```

3. **`ScalingAction` enum**: Return value communicates whether to continue or stop, replacing the `break` statements scattered through the loop.

4. **Dependency injection**: All dependencies (orchestrator, health_monitor, stats, keyboard, stop_event) are injected via `__init__`. No global state access.

### Verification

- VFTester drops by ~260 lines (dashboard loop + extracted methods)
- `_run_dashboard_loop` becomes a thin 15-line loop
- All scaling state is in `AdaptiveScalingState` dataclass
- `tick()` is independently testable (inject mocks)

---

## Phase 4: PluginAutoHeal + SessionManager + AttackReporter

**Priority:** P2 — MEDIUM IMPACT
**Estimated effort:** 2-3 hours
**Expected line reduction:** VFTester drops from ~450 → ~450 (but with 3 more focused classes extracted)

### File A: `tester/vf_plugin_autoheal.py` (~150 lines)

**Methods to extract:**
- `_auto_disable_failing_plugins` (lines 816-846)
- `_auto_recover_disabled_plugins` (lines 848-928)

```python
"""Plugin auto-heal module — monitors and recovers failing plugins.

Monitors plugin error rates and automatically disables plugins with
catastrophic failure rates (>97%). When server health recovers,
attempts to re-enable disabled plugins with fresh instances.

Typical usage:
    healer = PluginAutoHeal(registry, orchestrator)
    healer.check_and_heal(stats_dict, health=0.8)
"""

from __future__ import annotations

from typing import Any

from plugin_system import PluginRegistry
from tester.vf_plugin_orchestrator import PluginOrchestrator, ORIGIN_PLUGINS
from logging_config import get_logger

logger = get_logger(__name__)


class PluginAutoHeal:
    """Monitor and recover failing plugins.

    Handles two scenarios:
    1. Auto-disable origin plugins with >97% error rate (their failures
       are client-side, e.g. unreachable origin IPs)
    2. Auto-recover disabled plugins when server health improves
       (health > 0.6 for 5+ consecutive ticks)

    Args:
        registry: PluginRegistry for creating fresh plugin instances.
        orchestrator: PluginOrchestrator managing active/disabled plugins.
    """

    def __init__(self, registry: PluginRegistry,
                 orchestrator: PluginOrchestrator) -> None:
        self._registry = registry
        self._orchestrator = orchestrator
        self._recovery_ticks: int = 0

    def check_and_heal(self, health: float) -> int:
        """Run one cycle of plugin health monitoring.

        1. Disable origin plugins with >97% error rate
        2. Recover disabled plugins if health > 0.6 for 5+ ticks

        Args:
            health: Current server health score (0.0-1.0).

        Returns:
            Updated actual_workers count after healing.
        """
        self._auto_disable_failing_plugins()
        return self._auto_recover_disabled_plugins(health)

    def _auto_disable_failing_plugins(self) -> int: ...
    def _auto_recover_disabled_plugins(self, health: float) -> int: ...
```

### File B: `tester/vf_session_manager.py` (~180 lines)

**Methods to extract:**
- `_session_warmup` (lines 387-436)
- `_preflight_check_origin_ips` (lines 438-535)

```python
"""Session management — warmup and origin IP validation.

Handles session warmup (visiting target to establish cookies) and
preflight origin IP validation (HTTP-based check that origin IPs
actually serve the target site).

Typical usage:
    manager = SessionManager(url, domain, profile, ssl_ctx, evasion)
    await manager.warmup(session)
    valid = await manager.preflight_check_origin_ips()
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

import aiohttp

from finder.site_profile import SiteProfile
from logging_config import get_logger

logger = get_logger(__name__)


class SessionManager:
    """Manage session warmup and origin IP validation.

    Args:
        url: Target URL.
        domain: Target domain (without port).
        profile: SiteProfile with origin IPs and other data.
        ssl_ctx: SSL context for HTTPS connections.
        evasion: Evasion manager for cookie updates.
        base_headers_fn: Callable returning base request headers.
    """

    def __init__(
        self,
        url: str,
        domain: str,
        profile: SiteProfile,
        ssl_ctx: ssl.SSLContext,
        evasion: Any,
        base_headers_fn: Any,
    ) -> None:
        self._url = url
        self._domain = domain
        self._profile = profile
        self._ssl_ctx = ssl_ctx
        self._evasion = evasion
        self._base_headers_fn = base_headers_fn

    async def warmup(self, session: aiohttp.ClientSession) -> None:
        """Visit target URL to establish cookies before attack.

        Many WAFs set challenge cookies on the first visit. This
        warmup ensures the session has valid cookies before the
        attack starts. Also feeds cookies to the evasion manager.
        """
        ...

    async def preflight_check_origin_ips(self) -> bool:
        """HTTP-based origin IP validation.

        For each origin IP, sends an HTTP request with the target
        domain's Host header. Validates that the IP actually serves
        the target site. Falls back to TCP check if HTTP fails.
        """
        ...
```

### File C: `tester/vf_attack_reporter.py` (~50 lines)

**Methods to extract:**
- `_record_hit` (lines 562-573)
- `_snap` (lines 1132-1141)

```python
"""Attack result reporting — records hits and snapshots.

Thin wrapper around Stats, LiveLog, and AdaptiveTimeout that
provides a single entry point for recording attack results.

Typical usage:
    reporter = AttackReporter(stats, live_log, adaptive_timeout)
    reporter.record_hit(mode="page_flood", ok=True, code=200, rt=0.15)
"""

from __future__ import annotations

from typing import Any

from tester.vf_data import HitResult, Stats
from tester.vf_live_log import LiveLog


class AttackReporter:
    """Record attack hits and periodic snapshots.

    Wraps Stats, LiveLog, and AdaptiveTimeout into a single
    recording interface used by plugin callbacks.

    Args:
        stats: Stats object for aggregate counters.
        live_log: LiveLog for recent activity display.
        adaptive_timeout: AdaptiveTimeout for RT tracking.
    """

    def __init__(
        self,
        stats: Stats,
        live_log: LiveLog,
        adaptive_timeout: Any,
        snap_list: list[dict[str, Any]],
    ) -> None:
        self._stats = stats
        self._live_log = live_log
        self._adaptive_timeout = adaptive_timeout
        self._snaps = snap_list

    def record_hit(
        self,
        mode: str,
        ok: bool,
        code: int,
        rt: float,
        err: str = "",
        url: str = "",
        hint: str = "",
    ) -> None:
        """Record a hit result into stats and live log.

        Args:
            mode: Attack mode/plugin name.
            ok: Whether the request succeeded.
            code: HTTP status code.
            rt: Response time in seconds.
            err: Error message (if any).
            url: Target URL.
            hint: Additional context hint.
        """
        hit = HitResult(ok=ok, code=code, rt=rt, mode=mode,
                        err=err, url=url, hint=hint)
        self._stats.record(hit)
        self._live_log.add({
            "mode": mode, "code": code, "rt": rt,
            "err": err, "url": url, "hint": hint,
        })
        if hit.rt > 0:
            self._adaptive_timeout.record(hit.rt)

    def snap(self) -> None:
        """Take a snapshot of current stats for time-series analysis."""
        self._snaps.append({
            "t": self._stats.elapsed,
            "ok": self._stats.ok,
            "fail": self._stats.fail,
            "total": self._stats.total,
            "workers": self._stats.users,
        })
```

### Verification

- VFTester's `_record_hit` and `_snap` methods become delegations
- `_session_warmup` and `_preflight_check_origin_ips` become `SessionManager` methods
- `_auto_disable_failing_plugins` and `_auto_recover_disabled_plugins` become `PluginAutoHeal` methods
- Each new class is independently testable with mock dependencies

---

## Phase 5: ssl_analyzer Async Conversion

**Priority:** P2 — MEDIUM IMPACT
**Estimated effort:** 1-2 hours
**Files modified:** `finder/ssl_analyzer.py`, `finder/engine.py`

### Current State

```python
# finder/ssl_analyzer.py (CURRENT — blocking)
def analyze_ssl(profile: SiteProfile, verify_ssl: bool = False) -> SiteProfile:
    """Blocking SSL analysis using socket.create_connection()."""
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # ... parse cert ...
```

Called via workaround in engine.py:
```python
# finder/engine.py (CURRENT — run_in_executor workaround)
await asyncio.get_running_loop().run_in_executor(
    None, lambda: analyze_ssl(self.profile, verify_ssl=self.verify_ssl)
)
```

### Target State

```python
# finder/ssl_analyzer.py (TARGET — async-native)
async def analyze_ssl(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
    verify_ssl: bool = False,
) -> dict[str, Any]:
    """Analyze SSL/TLS configuration of the target.

    Uses asyncio.open_connection() instead of socket.create_connection()
    to avoid blocking the event loop.

    Args:
        host: Target hostname.
        port: Target port (default 443).
        timeout: Connection timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        Dictionary with keys:
            ssl_enabled: bool | None — True if SSL works, None if undetermined
            protocol: str — TLS protocol version (e.g. "TLSv1.3")
            cipher: str — Primary cipher suite name
            cipher_bits: int — Cipher key length in bits
            issuer_org: str — Certificate issuer organization
            subject_cn: str — Certificate subject common name
            valid_from: str — Certificate validity start
            valid_to: str — Certificate validity end
    """
    import ssl as _ssl
    import asyncio

    if verify_ssl:
        context = _ssl.create_default_context()
    else:
        context = _ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = _ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=context, server_hostname=host,
            ),
            timeout=timeout,
        )

        try:
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object is None:
                return {"ssl_enabled": None}

            protocol = ssl_object.version()
            cipher = ssl_object.cipher()
            cert_dict = ssl_object.getpeercert()

            # Parse certificate (same logic as current)
            issuer: dict[str, str] = {}
            subject: dict[str, str] = {}
            if cert_dict and isinstance(cert_dict, dict):
                # ... parse issuer/subject ...
                pass

            return {
                "ssl_enabled": True,
                "protocol": protocol,
                "cipher": cipher[0] if cipher else "Unknown",
                "cipher_bits": cipher[2] if cipher else 0,
                "issuer_org": issuer.get('organizationName', 'Unknown'),
                "subject_cn": subject.get('commonName', 'Unknown'),
                "valid_from": cert_dict.get('notBefore', 'Unknown') if cert_dict else 'Unknown',
                "valid_to": cert_dict.get('notAfter', 'Unknown') if cert_dict else 'Unknown',
            }
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, IOError):
                pass

    except Exception:
        # BUG-031: Cannot determine SSL status on failure — don't assume True
        return {"ssl_enabled": None}
```

### Changes to engine.py

```python
# BEFORE:
async def _ssl_pipeline(self):
    if self.profile.scheme == 'https':
        await asyncio.get_running_loop().run_in_executor(
            None, lambda: analyze_ssl(self.profile, verify_ssl=self.verify_ssl)
        )

# AFTER:
async def _ssl_pipeline(self):
    if self.profile.scheme == 'https':
        result = await analyze_ssl(
            self.profile.host, self.profile.port,
            verify_ssl=self.verify_ssl,
        )
        self.profile.ssl_info = {k: v for k, v in result.items() if k != 'ssl_enabled'}
        self.profile.ssl_enabled = result.get('ssl_enabled')
```

### Key Design Decisions

1. **Signature change**: `analyze_ssl(profile) -> SiteProfile` becomes `analyze_ssl(host, port, ...) -> dict`. This follows the principle of "functions should return data, not mutate inputs."

2. **Return type includes `ssl_enabled: bool | None`**: The `None` case (from BUG-031) is now explicit in the return type rather than silently set on the profile.

3. **No more `run_in_executor`**: The async-native version can be directly `await`ed in the SSL pipeline, eliminating the thread pool overhead.

4. **Caller assigns result**: engine.py receives the dict and assigns it to the profile. This makes the data flow explicit.

### Verification

- `analyze_ssl` is now an async function with proper type hints
- No more `run_in_executor` workaround in engine.py
- `ssl_enabled: bool | None` is explicitly returned in the result dict
- All existing SSL analysis behavior is preserved
- `py_compile` passes

---

## Phase 6: _is_private_ip Fix + JA3 Integration

**Priority:** P3 — LOW IMPACT (correctness + future capability)
**Estimated effort:** 2-3 hours

### File A: `finder/dns_scanner.py` — _is_private_ip Fix

**Current implementation (lines 236-252):**

```python
def _is_private_ip(ip: str) -> bool:
    try:
        packed = socket.inet_aton(ip)
        numeric = struct.unpack('!I', packed)[0]
        private_ranges = [
            (0x0A000000, 0x0AFFFFFF),  # 10.x.x.x
            (0xAC100000, 0xAC1FFFFF),  # 172.16-31.x.x
            (0xC0A80000, 0xC0A8FFFF),  # 192.168.x.x
            (0x7F000000, 0x7FFFFFFF),  # 127.x.x.x
            (0xA9FE0000, 0xA9FEFFFF),  # 169.254.x.x
        ]
        for start, end in private_ranges:
            if start <= numeric <= end:
                return True
    except (OSError, struct.error):
        pass
    return False
```

**Target implementation:**

```python
import ipaddress

def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range.

    Uses the ipaddress module for RFC-correct detection including
    CGNAT (100.64.0.0/10), link-local, loopback, and multicast ranges.
    Also handles IPv6 addresses that the struct-based implementation
    would silently reject.

    Args:
        ip: IP address string (IPv4 or IPv6).

    Returns:
        True if the address is private, loopback, link-local,
        reserved, or multicast.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False
```

**Behavioral differences:**
- New implementation detects **CGNAT range** (100.64.0.0/10) — old one misses it
- New implementation handles **IPv6** (e.g., `::1`, `fc00::`) — old one silently returns False
- New implementation detects **multicast** (224.0.0.0/4) — old one misses it
- This is a correctness improvement, not a behavioral regression

### File B: `evasion/vf_tls_client.py` (~100 lines) — tls-client Wrapper

**Purpose:** Wrapper for the `tls-client` library that provides true JA3 fingerprint cloning (not the approximate approach in `vf_fp_cloner.py`).

```python
"""TLS client wrapper for true JA3 fingerprint cloning.

Provides an optional integration with the tls-client library for
producing authentic browser TLS fingerprints. Falls back to the
existing ssl-based approach if tls-client is not installed.

The existing BrowserFingerprintCloner (vf_fp_cloner.py) cannot
produce identical JA3 hashes because Python's ssl module doesn't
control TLS extension ordering, GREASE, or signature algorithms.
This module uses tls-client (which wraps curl-impersonate) for
true fingerprint matching.

Typical usage:
    client = TLSClientWrapper()
    if client.is_available:
        response = await client.request("GET", url, profile="chrome_122")
    else:
        # Fall back to existing approach
        pass
"""

from __future__ import annotations

from typing import Any

from logging_config import get_logger

logger = get_logger(__name__)

# Optional dependency — not required for core functionality
try:
    import tls_client
    HAS_TLS_CLIENT = True
except ImportError:
    HAS_TLS_CLIENT = False


class TLSClientWrapper:
    """Wrapper for tls-client library with graceful fallback.

    If tls-client is not installed, is_available returns False
    and all methods fall back to no-op or raise ImportError.

    Args:
        profile: Browser profile name (e.g. "chrome_122").
    """

    def __init__(self, profile: str = "chrome_120") -> None:
        if not HAS_TLS_CLIENT:
            self._session = None
            return

        try:
            self._session = tls_client.Session(
                client_identifier=profile,
                random_tls_extension_order=True,
            )
        except (ValueError, TypeError):
            self._session = None

    @property
    def is_available(self) -> bool:
        """Whether tls-client is installed and a session was created."""
        return self._session is not None

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        data: bytes | str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Send an HTTP request with a realistic browser TLS fingerprint.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Target URL.
            headers: Request headers.
            data: Request body.
            timeout: Request timeout in seconds.

        Returns:
            Dictionary with keys: status_code, headers, content, rt.

        Raises:
            RuntimeError: If tls-client is not available.
        """
        if not self.is_available:
            raise RuntimeError("tls-client not available — install with: pip install tls-client")

        # tls-client is synchronous — run in executor
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self._sync_request,
            method, url, headers, data, timeout,
        )

    def _sync_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        data: bytes | str | None,
        timeout: float,
    ) -> dict[str, Any]:
        """Synchronous request execution (runs in thread pool)."""
        response = self._session.request(
            method=method,
            url=url,
            headers=headers or {},
            data=data,
            timeout_seconds=timeout,
        )
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers) if response.headers else {},
            "content": response.content,
            "rt": response.elapsed if hasattr(response, 'elapsed') else 0.0,
        }
```

### Changes to `evasion/vf_fp_cloner.py`

Add optional tls-client integration to `BrowserFingerprintCloner`:

```python
# In BrowserFingerprintCloner.__init__:
from evasion.vf_tls_client import TLSClientWrapper
self._tls_client = TLSClientWrapper()

# In probe_target():
if self._tls_client.is_available:
    # Use tls-client for probing (true JA3)
    ...
else:
    # Fall back to current ssl-based approach
    ...
```

### Key Design Decisions

1. **Optional dependency**: `tls-client` is not required. The wrapper returns `is_available = False` gracefully.

2. **No breaking changes**: The existing `BrowserFingerprintCloner` continues to work without `tls-client`. The new wrapper is additive.

3. **`_is_private_ip` uses `ipaddress`**: The `struct.unpack` approach is correct for the ranges it covers but misses several RFC ranges (CGNAT, multicast). The stdlib approach is more correct and more maintainable.

4. **Sync → async bridge**: `tls-client` is synchronous, so we use `run_in_executor` for async compatibility. This is acceptable because the `tls-client` requests are I/O-bound and the thread pool handles them well.

### Verification

- `_is_private_ip` passes all existing test cases plus new IPv6/CGNAT cases
- `TLSClientWrapper.is_available` is `False` when `tls-client` is not installed
- `TLSClientWrapper.is_available` is `True` when `tls-client` is installed
- Existing `BrowserFingerprintCloner` tests pass unchanged
- `py_compile` passes on all modified files

---

## TODO Checklist

### Phase 1: AttackProfileGenerator Extraction

- [ ] Create `finder/vf_attack_profile.py` with `AttackProfileGenerator` class definition and full type hints
- [ ] Move `_generate_attack_profile` from engine.py — rename to `generate()`
- [ ] Move `_determine_all_determined_configs` from engine.py
- [ ] Move `_determine_strategy` from engine.py
- [ ] Move `_determine_surgical_vectors` from engine.py
- [ ] Move `_determine_all_vectors` from engine.py
- [ ] Move `_determine_strategy_reason` from engine.py
- [ ] Move `_determine_vectors` from engine.py
- [ ] Move `_determine_waf_strategy` from engine.py
- [ ] Move `_determine_worker_config` from engine.py
- [ ] Move `_determine_surgical_worker_config` from engine.py
- [ ] Move `_determine_all_worker_config` from engine.py
- [ ] Move `_determine_request_config` from engine.py
- [ ] Move `_determine_login_config` from engine.py
- [ ] Move `_determine_page_targets` from engine.py
- [ ] Move `_determine_resource_targets` from engine.py
- [ ] Move `_determine_timing_config` from engine.py
- [ ] Move `_determine_evasion_config` from engine.py
- [ ] Move `_determine_spa_config` from engine.py
- [ ] Move `_determine_aspnet_config` from engine.py
- [ ] Move `_determine_php_config` from engine.py
- [ ] Move `_determine_wordpress_config` from engine.py
- [ ] Move `_determine_api_config` from engine.py
- [ ] Move `_determine_edu_config` from engine.py
- [ ] Move `_determine_risk_notes` from engine.py
- [ ] Move `_print_strategy_display` from engine.py
- [ ] Update method signatures — add type hints where missing (`dict[str, Any]`, `list[str]`, etc.)
- [ ] Add `__init__(self, profile: SiteProfile, html: str = "")` with dependency injection
- [ ] Replace `self._is_spa()` calls with `is_spa(self._profile, self._html)` imports from vf_tech_helpers
- [ ] Replace `self._is_nextjs()` calls with `is_nextjs(self._profile, self._html)` imports
- [ ] Replace `self._has_graphql()` calls with `has_graphql(self._profile, self._html)` imports
- [ ] Replace `self._is_origin_resource(url)` calls with `is_origin_resource(url, self._profile)` imports
- [ ] Replace `self._detect_spa_framework()` calls with `detect_spa_framework(self._profile)` imports
- [ ] Replace `self._find_graphql_endpoint()` calls with `find_graphql_endpoint(self._profile, self._html)` imports
- [ ] Replace `self._extract_spa_routes()` calls with `extract_spa_routes(self._profile)` imports
- [ ] Replace `self._extract_next_data_routes()` calls with `extract_next_data_routes(self._profile, self._html)` imports
- [ ] Update engine.py to import and delegate: `generator = AttackProfileGenerator(self.profile, self._html or "")`
- [ ] Update engine.py `_generate_attack_profile()` to 2-line delegation
- [ ] Remove all 25 moved methods from engine.py
- [ ] Verify syntax with `py_compile` on both files
- [ ] Update any cross-references in other files (VF_FINDER.py, tests)
- [ ] Add module docstring with Google style
- [ ] Write unit tests for `AttackProfileGenerator.generate()` with mock SiteProfile
- [ ] Append worklog entry

### Phase 2: TechDetectorHelpers + FinderEnhancerRunner

- [ ] Create `finder/vf_tech_helpers.py` with pure function definitions and type hints
- [ ] Move `_is_spa()` → `is_spa(profile, html)` — add profile param, remove self
- [ ] Move `_is_nextjs()` → `is_nextjs(profile, html)` — add profile param, remove self
- [ ] Move `_has_graphql()` → `has_graphql(profile, html)` — add profile param, remove self
- [ ] Move `_is_origin_resource(url)` → `is_origin_resource(url, profile)` — add profile param
- [ ] Move `_detect_spa_framework()` → `detect_spa_framework(profile)` — add profile param
- [ ] Move `_find_graphql_endpoint()` → `find_graphql_endpoint(profile, html)` — add params
- [ ] Move `_extract_spa_routes()` → `extract_spa_routes(profile)` — add profile param
- [ ] Move `_extract_next_data_routes()` → `extract_next_data_routes(profile, html)` — add params
- [ ] Add Google-style docstrings to all functions
- [ ] Add `from __future__ import annotations` for modern type hint syntax
- [ ] Create `finder/vf_finder_enhancer.py` with `FinderEnhancerRunner` class
- [ ] Move `_run_finder_module` → `FinderEnhancerRunner._run_module`
- [ ] Move `_enhance_waf_detection` → `FinderEnhancerRunner._enhance_waf_detection`
- [ ] Move `_enhance_js_scan` → `FinderEnhancerRunner._enhance_js_scan`
- [ ] Move `_enhance_subdomain_scan` → `FinderEnhancerRunner._enhance_subdomain_scan`
- [ ] Move `_enhance_dir_fuzz` → `FinderEnhancerRunner._enhance_dir_fuzz`
- [ ] Move `_enhance_rate_probe` → `FinderEnhancerRunner._enhance_rate_probe`
- [ ] Move `_enhance_cache_analysis` → `FinderEnhancerRunner._enhance_cache_analysis`
- [ ] Add `run_all()` method as single entry point
- [ ] Update engine.py to instantiate `FinderEnhancerRunner` in `__init__`
- [ ] Update engine.py pipeline methods to call `self._enhancer.run_module()` instead of `self._enhance_*()`
- [ ] Remove all moved methods from engine.py
- [ ] Remove `_is_spa`, `_is_nextjs`, `_has_graphql`, `_is_origin_resource` from engine.py
- [ ] Verify syntax with `py_compile` on all modified files
- [ ] Update any cross-references (AttackProfileGenerator imports from Phase 1)
- [ ] Add module docstrings with Google style
- [ ] Write unit tests for tech helper functions with mock SiteProfile
- [ ] Write unit tests for FinderEnhancerRunner with mock modules
- [ ] Append worklog entry

### Phase 3: AdaptiveScalingEngine from VFTester

- [ ] Create `tester/vf_adaptive_scaling.py` with `AdaptiveScalingState` dataclass
- [ ] Create `ScalingAction` enum (CONTINUE, STOP)
- [ ] Create `AdaptiveScalingEngine` class with dependency injection
- [ ] Move `_run_dashboard_loop` logic → `AdaptiveScalingEngine.tick()`
- [ ] Move `_check_keyboard_commands` → `AdaptiveScalingEngine._check_keyboard_commands()`
- [ ] Move `_check_waf_runtime_detection` → `AdaptiveScalingEngine._check_waf_runtime_detection()`
- [ ] Move `_compute_dynamic_step` → `AdaptiveScalingEngine._compute_dynamic_step()`
- [ ] Move `_auto_shrink_workers` → `AdaptiveScalingEngine._auto_shrink_workers()`
- [ ] Move `_run_escalation_phase` → `AdaptiveScalingEngine._run_escalation_phase()`
- [ ] Replace loop-local attributes (`_step_start`, `_escalation_paused`, etc.) with `AdaptiveScalingState` fields
- [ ] Update VFTester to instantiate `AdaptiveScalingEngine` in `__init__`
- [ ] Update VFTester `_run_dashboard_loop` to thin loop calling `self._scaling_engine.tick()`
- [ ] Remove all moved methods from VFTester
- [ ] Add type hints to all new methods
- [ ] Add Google-style docstrings
- [ ] Verify syntax with `py_compile`
- [ ] Write unit tests for `AdaptiveScalingEngine.tick()` with mock dependencies
- [ ] Append worklog entry

### Phase 4: PluginAutoHeal + SessionManager + AttackReporter

- [ ] Create `tester/vf_plugin_autoheal.py` with `PluginAutoHeal` class
- [ ] Move `_auto_disable_failing_plugins` → `PluginAutoHeal._auto_disable_failing_plugins()`
- [ ] Move `_auto_recover_disabled_plugins` → `PluginAutoHeal._auto_recover_disabled_plugins()`
- [ ] Add `check_and_heal(health: float) -> int` entry point
- [ ] Create `tester/vf_session_manager.py` with `SessionManager` class
- [ ] Move `_session_warmup` → `SessionManager.warmup(session)`
- [ ] Move `_preflight_check_origin_ips` → `SessionManager.preflight_check_origin_ips()`
- [ ] Add type hints for `aiohttp.ClientSession` parameters
- [ ] Create `tester/vf_attack_reporter.py` with `AttackReporter` class
- [ ] Move `_record_hit` → `AttackReporter.record_hit()`
- [ ] Move `_snap` → `AttackReporter.snap()`
- [ ] Update VFTester to instantiate all three new classes in `__init__`
- [ ] Update VFTester to delegate calls to new classes
- [ ] Remove all moved methods from VFTester
- [ ] Add Google-style docstrings
- [ ] Verify syntax with `py_compile`
- [ ] Write unit tests for `PluginAutoHeal` with mock registry/orchestrator
- [ ] Write unit tests for `SessionManager.warmup()` with mock aiohttp session
- [ ] Write unit tests for `AttackReporter.record_hit()` with mock stats
- [ ] Append worklog entry

### Phase 5: ssl_analyzer Async Conversion

- [ ] Change `analyze_ssl` signature: `def analyze_ssl(profile, verify_ssl) -> SiteProfile` → `async def analyze_ssl(host, port, timeout, verify_ssl) -> dict[str, Any]`
- [ ] Replace `socket.create_connection()` with `asyncio.open_connection()`
- [ ] Replace `context.wrap_socket()` with `ssl=context` parameter to `open_connection()`
- [ ] Extract SSL object via `writer.get_extra_info('ssl_object')`
- [ ] Update return type: dict with `ssl_enabled: bool | None`
- [ ] Move certificate parsing logic (issuer, subject) into new function
- [ ] Ensure `writer.close()` and `await writer.wait_closed()` in finally block
- [ ] Update engine.py `_ssl_pipeline` to call `await analyze_ssl(host, port, ...)`
- [ ] Remove `run_in_executor` workaround from engine.py
- [ ] Assign result dict to `self.profile.ssl_info` and `self.profile.ssl_enabled` in engine.py
- [ ] Add Google-style docstring with Args and Returns sections
- [ ] Verify syntax with `py_compile`
- [ ] Write unit tests for async `analyze_ssl` with mock connection
- [ ] Append worklog entry

### Phase 6: _is_private_ip Fix + JA3 Integration

- [ ] Replace `_is_private_ip` in dns_scanner.py with `ipaddress.ip_address().is_private` implementation
- [ ] Add `import ipaddress` to dns_scanner.py
- [ ] Remove `struct.unpack` approach and `private_ranges` list
- [ ] Verify new implementation detects CGNAT (100.64.0.0/10) range
- [ ] Verify new implementation handles IPv6 addresses
- [ ] Verify new implementation handles invalid strings (returns False)
- [ ] Create `evasion/vf_tls_client.py` with `TLSClientWrapper` class
- [ ] Add `try: import tls_client` with graceful fallback
- [ ] Implement `is_available` property
- [ ] Implement `async request()` method with `run_in_executor` bridge
- [ ] Implement `_sync_request()` method wrapping tls_client.Session
- [ ] Add optional integration in `vf_fp_cloner.py` BrowserFingerprintCloner
- [ ] Add Google-style docstrings
- [ ] Verify syntax with `py_compile`
- [ ] Write unit tests for new `_is_private_ip` with IPv4/IPv6 edge cases
- [ ] Write unit tests for `TLSClientWrapper` with and without tls-client installed
- [ ] Append worklog entry

---

## Risk Assessment

### Phase 1: AttackProfileGenerator Extraction — **MEDIUM Risk**

| Factor | Assessment |
|--------|-----------|
| **Risk Level** | MEDIUM |
| **Lines changed** | ~770 lines moved + ~50 lines modified in engine.py |
| **Potential breakage** | `_surgical_analysis` attribute used externally; self._html access pattern changes |
| **Test coverage** | No existing tests for attack profile generation |
| **Rollback strategy** | Revert engine.py; delete vf_attack_profile.py |

**Breakage points:**
1. `_surgical_analysis` was set as `self._surgical_analysis` inside `_determine_surgical_vectors()` and read by `_handle_strategy_selection()` in VFTester. After extraction, this value needs to be returned from `generate()` and passed explicitly.
2. `self._html` access in the generator — must be passed as a constructor argument, not accessed from `self._html` on the finder.
3. `_print_strategy_display` uses `logger` which must be imported in the new module.

**Mitigation:**
- Return `surgical_analysis` as part of the `generate()` return dict
- Add integration test that creates a SiteProfile and verifies `generate()` output structure
- Run full test suite after extraction

### Phase 2: TechDetectorHelpers + FinderEnhancerRunner — **LOW Risk**

| Factor | Assessment |
|--------|-----------|
| **Risk Level** | LOW |
| **Lines changed** | ~300 lines moved + ~30 lines modified in engine.py |
| **Potential breakage** | Function signature changes (self → profile param) |
| **Test coverage** | No existing tests for tech helpers |
| **Rollback strategy** | Revert engine.py; delete vf_tech_helpers.py, vf_finder_enhancer.py |

**Breakage points:**
1. `is_spa()`, `is_nextjs()`, etc. change from instance methods to module functions. All callers must be updated.
2. `_is_origin_resource(url)` gains a `profile` parameter — must update all call sites.
3. FinderEnhancerRunner mutates `self._profile` in-place (same as current behavior), but the mutation now happens inside a different class.

**Mitigation:**
- Use grep to find all call sites of `_is_spa`, `_is_nextjs`, `_has_graphql`, `_is_origin_resource`
- The enhancement modules already have try/except around imports, so missing modules still fail gracefully

### Phase 3: AdaptiveScalingEngine — **MEDIUM Risk**

| Factor | Assessment |
|--------|-----------|
| **Risk Level** | MEDIUM |
| **Lines changed** | ~320 lines moved + ~50 lines modified in VFTester |
| **Potential breakage** | Dashboard loop timing, escalation thresholds, shrink behavior |
| **Test coverage** | No existing tests for dashboard loop |
| **Rollback strategy** | Revert VFTester; delete vf_adaptive_scaling.py |

**Breakage points:**
1. Loop-local attributes (`_step_start`, `_escalation_paused`, `_shrink_cooldown`, etc.) move from VFTester instance to `AdaptiveScalingState` dataclass. Any code that reads these attributes (e.g., dashboard rendering) must access them via `self._scaling_engine.state.xxx`.
2. `_check_waf_runtime_detection` reads `self.detected_waf` and calls `self._evasion.set_waf()`. These must be passed as method arguments or injected dependencies.
3. `_auto_shrink_workers` and `_run_escalation_phase` access `self._active_plugins` (which is a property delegating to the orchestrator). The new class must hold a reference to the orchestrator.
4. The `_consecutive_shrinks` and `_healthy_ticks` state was previously on the VFTester instance. Moving them to `AdaptiveScalingState` requires all state reads/writes to go through `self._state`.

**Mitigation:**
- Keep the `tick()` method signature simple and pass all needed external state as arguments
- Write a unit test that simulates 100 ticks with known inputs and verifies output
- The AdaptiveScalingState dataclass makes it easy to snapshot/restore state for debugging

### Phase 4: PluginAutoHeal + SessionManager + AttackReporter — **LOW Risk**

| Factor | Assessment |
|--------|-----------|
| **Risk Level** | LOW |
| **Lines changed** | ~380 lines moved + ~30 lines modified in VFTester |
| **Potential breakage** | Plugin recovery creates fresh instances — BUG-202 fix must be preserved |
| **Test coverage** | No existing tests for auto-heal or session management |
| **Rollback strategy** | Revert VFTester; delete 3 new files |

**Breakage points:**
1. `_auto_recover_disabled_plugins` creates fresh plugin instances via `self._registry.get_class(pname)`. The `PluginAutoHeal` class must receive the registry reference.
2. `_session_warmup` uses `self._evasion.update_cookies(cookies)` — the `SessionManager` must receive the evasion reference.
3. `_preflight_check_origin_ips` mutates `self.profile.origin_ips` — the `SessionManager` must receive the profile reference.

**Mitigation:**
- All dependencies are injected via `__init__` — no hidden global state
- The BUG-202 fix (fresh instance instead of cached) is preserved in the move
- SessionManager methods are async and can be tested with mock aiohttp sessions

### Phase 5: ssl_analyzer Async Conversion — **MEDIUM Risk**

| Factor | Assessment |
|--------|-----------|
| **Risk Level** | MEDIUM |
| **Lines changed** | ~82 lines rewritten + ~10 lines modified in engine.py |
| **Potential breakage** | SSL certificate parsing, error handling paths, ssl_enabled None case |
| **Test coverage** | No existing tests for SSL analysis |
| **Rollback strategy** | Revert ssl_analyzer.py and engine.py |

**Breakage points:**
1. `asyncio.open_connection(ssl=context, server_hostname=host)` performs the TLS handshake during connection. The current code does `socket.create_connection()` then `context.wrap_socket()` as two steps. If the server requires SNI or specific TLS extensions, the behavior may differ.
2. `getpeercert()` returns `None` when `verify_mode = CERT_NONE`. The current code handles this with `cert_dict and isinstance(cert_dict, dict)` checks. Must verify the async version behaves the same.
3. The `ssl_object.cipher()` call may return `None` in some TLS 1.3 configurations where cipher negotiation happens after the handshake.

**Mitigation:**
- Test against a known HTTPS server before deploying
- Add explicit `if cipher is None` guard
- Keep the `ssl_enabled: None` return on failure (BUG-031)
- The `writer.get_extra_info('ssl_object')` pattern is used in `vf_fp_cloner.py` already (line 298) and works correctly

### Phase 6: _is_private_ip Fix + JA3 Integration — **LOW Risk**

| Factor | Assessment |
|--------|-----------|
| **Risk Level** | LOW |
| **Lines changed** | ~20 lines rewritten in dns_scanner.py + ~100 lines new in vf_tls_client.py |
| **Potential breakage** | `_is_private_ip` behavior changes (more correct, but different) |
| **Test coverage** | No existing tests for _is_private_ip |
| **Rollback strategy** | Revert dns_scanner.py; delete vf_tls_client.py |

**Breakage points:**
1. `ipaddress.ip_address().is_private` includes **more ranges** than the manual implementation:
   - CGNAT: 100.64.0.0/10 — previously treated as public, now private
   - Benchmark: 198.51.100.0/24 (TEST-NET-2) — previously public, now reserved
   - This is a **correctness improvement** — these IPs should never be targeted
2. `tls-client` is a C extension — may fail to install on some platforms. The `try/except ImportError` fallback handles this.
3. `tls_client.Session.request()` is synchronous — we bridge with `run_in_executor`. This adds a small overhead but avoids blocking the event loop.

**Mitigation:**
- The `_is_private_ip` change is strictly more conservative (rejects more IPs, never accepts previously-rejected ones)
- `TLSClientWrapper.is_available` property makes it safe to check before use
- No existing code calls `tls-client` — this is purely additive

---

## Architecture Scorecard

### Before (Current State)

| Metric | Score | Notes |
|--------|-------|-------|
| Single Responsibility | 4/10 | 2 God Classes with 6+ responsibilities each |
| Dependency Injection | 5/10 | Some DI (ProfileLoader, DashboardRenderer), but many self-references |
| Type Hint Coverage | 6/10 | Good on new code, missing on older methods |
| Async-First | 7/10 | ssl_analyzer still blocking, tls-client sync |
| Testability | 4/10 | God Classes hard to unit test |
| Class Size Discipline | 3/10 | Two classes >1000 lines |
| **Overall** | **66/100** | |

### After (Target State)

| Metric | Score | Notes |
|--------|-------|-------|
| Single Responsibility | 8/10 | Each class has one clear responsibility |
| Dependency Injection | 8/10 | All new classes use constructor injection |
| Type Hint Coverage | 9/10 | 100% on new files, existing code preserved |
| Async-First | 9/10 | ssl_analyzer async, tls-client bridged |
| Testability | 8/10 | Each class independently testable with mocks |
| Class Size Discipline | 8/10 | Largest new class: AttackProfileGenerator ~770 lines |
| **Overall** | **83/100** | |

---

## Worklog

### Entry 1: Roadmap Created

**Date:** 2025-03-05
**Agent:** Architecture Review Board
**Task:** Create comprehensive architecture refactoring roadmap

**Analysis performed:**
- Read VF_TESTER.py (1,467 lines) — identified 6 responsibility clusters
- Read engine.py (1,241 lines) — identified 6 responsibility clusters
- Read ssl_analyzer.py (82 lines) — identified blocking I/O issue
- Read dns_scanner.py (lines 236-252) — identified _is_private_ip correctness issue
- Read vf_fp_cloner.py (578 lines) — identified tls-client integration opportunity
- Reviewed REVIEW_SCORE_REPORT.md — confirmed 6.85/10 overall score
- Reviewed worklog.md — confirmed previous refactoring history

**Decisions made:**
1. Phase 1 (AttackProfileGenerator) is HIGHEST IMPACT because it removes 60% of engine.py
2. Phase 2 must be completed before or simultaneously with Phase 1 (tech helpers are dependencies)
3. Phase 3 is next highest impact (removes largest cohesive block from VFTester)
4. Phases 5 and 6 are lower priority but improve correctness and future capability
5. Each phase has explicit rollback strategy to minimize risk

**Next actions:**
1. Execute Phase 2 first (unblocks Phase 1)
2. Execute Phase 1 (highest impact)
3. Execute Phase 3 (next highest impact)
4. Execute Phase 4 (medium impact)
5. Execute Phase 5 (async correctness)
6. Execute Phase 6 (correctness + future capability)
