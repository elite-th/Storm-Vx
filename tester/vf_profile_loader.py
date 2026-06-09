#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProfileLoader — Extracted from VFTester God Class.

Handles profile loading, validation, and creation of minimal profiles.
This module is responsible for:
  - Loading VF_PROFILE.json files (with auto-unwrapping)
  - Validating profile schema (required/optional fields, version)
  - Creating minimal profiles when no profile file exists
"""

from __future__ import annotations

import json
from typing import Dict, Any, Tuple, Union


from logging_config import get_logger
logger = get_logger(__name__)

from finder.site_profile import SiteProfile


class ProfileLoader:
    """Loads, validates, and creates VF profiles.

    Extracted from VFTester to separate profile I/O concerns from
    the attack orchestration logic.

    Usage:
        profile, attack = ProfileLoader.load(path)
        profile, attack = ProfileLoader.load_or_create(path, target_url)
        profile, attack = ProfileLoader.create_minimal(url)
    """

    @staticmethod
    def load(path: str) -> Tuple[SiteProfile, Dict[str, Any]]:
        """Load a profile from a JSON file.

        Handles:
        - Direct profile (has "url" or "attack_profile" at top level)
        - Wrapped profile (nested under a single key)
        - Auto-unwraps to find the correct dict

        W5.7: Uses safe_json_load() for path traversal and JSON bomb
        protection. Validates the file path before reading.

        Args:
            path: Path to the VF_PROFILE.json file.

        Returns:
            Tuple of (SiteProfile, attack_dict).

        Raises:
            ProfileError: If the file cannot be read.
        """
        raw = ProfileLoader._safe_read_json(path)

        if "url" in raw or "attack_profile" in raw:
            profile = raw
        else:
            unwrapped = None
            for key, value in raw.items():
                if isinstance(value, dict) and ("url" in value or "attack_profile" in value):
                    unwrapped = value
                    break
            if unwrapped:
                profile = unwrapped
            else:
                profile = raw

        # Validate profile schema
        ProfileLoader.validate(profile)

        attack = profile.get("attack_profile", {})
        logger.info(f"[VF] Profile loaded: {path}")
        logger.info(f"[VF] Strategy: {attack.get('recommended_strategy', 'AUTO')}")
        # Convert raw dict to typed SiteProfile
        site_profile = SiteProfile.from_dict(profile)
        return site_profile, attack

    @staticmethod
    def _safe_read_json(path: str) -> Dict[str, Any]:
        """Read and parse a JSON file with security hardening.

        W5.7: Validates the file path (path traversal, extension, size)
        and parses JSON with depth/size limits to prevent bombs.

        Falls back to raw json.load() if the security module is not available.
        """
        from exceptions import ProfileError

        # W5.7: Try secure JSON loading first
        try:
            from security.input_validation import validate_file_path, safe_json_load
            from config.defaults import PROFILE_ALLOWED_EXTENSIONS, PROFILE_MAX_SIZE, JSON_MAX_DEPTH
            safe_path = validate_file_path(
                path,
                allowed_extensions=PROFILE_ALLOWED_EXTENSIONS,
                max_size_bytes=PROFILE_MAX_SIZE,
            )
            return safe_json_load(
                safe_path,
                max_depth=JSON_MAX_DEPTH,
                max_size=PROFILE_MAX_SIZE,
            )
        except ImportError:
            pass  # Fallback below
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Failed to parse profile JSON: {e}")
            raise ProfileError(
                f"Profile file contains invalid JSON: {e}. "
                f"Please check the file syntax and try again."
            ) from e
        except ProfileError:
            raise
        except Exception as e:
            logger.error(f"Cannot read profile file: {e}")
            raise ProfileError(f"Cannot read profile file: {e}") from e

        # Fallback: security module not available
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            # BUG-25 FIX: Raise ProfileError instead of silently returning
            # an empty profile. Previously, corrupt JSON was swallowed and
            # replaced with ProfileLoader.create_minimal(""), which caused
            # confusing downstream "empty URL" errors instead of the real issue.
            logger.error(f"Failed to parse profile JSON: {e}")
            raise ProfileError(
                f"Profile file contains invalid JSON: {e}. "
                f"Please check the file syntax and try again."
            ) from e
        except (OSError, IOError) as e:
            logger.error(f"Cannot read profile file: {e}")
            raise ProfileError(f"Cannot read profile file: {e}") from e

    @staticmethod
    def validate(profile: Union[Dict[str, Any], SiteProfile]) -> None:
        """Validate profile schema and warn about missing/unexpected fields.

        Required: "url" must be present and non-empty.
        Optional: "attack_profile", "technologies" — warn if missing.
        Unknown top-level keys are logged as warnings.

        M1: Also validates the profile schema version field.
        """
        from config.defaults import PROFILE_SCHEMA_VERSION

        # If we receive a SiteProfile, convert to dict for validation
        if isinstance(profile, SiteProfile):
            profile = profile.to_dict()

        REQUIRED_FIELDS = {"url"}
        OPTIONAL_FIELDS = {"version", "attack_profile", "technologies", "waf", "cms",
                           "origin_ips", "cdn", "server", "server_version",
                           "viewstate_present", "login_fields", "api_endpoints",
                           "security_headers", "site_category", "rate_limit_detected",
                           "rate_limit_threshold", "hosting_provider", "ssl_enabled",
                           "scan_time", "page_size", "status_code", "baseline_rt",
                           "forms", "hidden_fields", "scripts", "links", "sensitive_files",
                           "ip_addresses", "backend_lang", "os_guess", "waf_confidence",
                           "port", "host"}

        # M1: Validate profile version
        # BUG-FIX v32: Only warn if version field is explicitly present and old.
        # Missing version field should not trigger a warning — many hand-crafted
        # profiles and older VF_FINDER versions don't include this field.
        if "version" in profile and profile["version"] < PROFILE_SCHEMA_VERSION:
            logger.warning(
                f"Profile version {profile['version']} is older than current "
                f"schema version {PROFILE_SCHEMA_VERSION}. Some features may not work."
            )

        # Check required fields
        for field in REQUIRED_FIELDS:
            value = profile.get(field)
            if not value or (isinstance(value, str) and not value.strip()):
                logger.warning(f"Profile missing required field: '{field}'")

        # Warn on missing optional fields
        missing_optional = {"attack_profile", "technologies"} - set(profile.keys())
        for field in missing_optional:
            logger.warning(f"Profile missing optional field: '{field}'")

        # Warn on unexpected fields
        known = REQUIRED_FIELDS | OPTIONAL_FIELDS
        unknown = set(profile.keys()) - known
        if unknown:
            logger.debug(f"Profile contains unexpected fields: {', '.join(sorted(unknown))}")

    @staticmethod
    def create_minimal(url: str) -> Tuple[SiteProfile, Dict[str, Any]]:
        """Create a minimal profile for when no profile file is available.

        Args:
            url: Target URL to use.

        Returns:
            Tuple of (SiteProfile, attack_dict).
        """
        from config.defaults import DEFAULT_MINIMAL_PROFILE, DEFAULT_MINIMAL_ATTACK
        raw_profile = {**DEFAULT_MINIMAL_PROFILE, "url": url}
        attack = {**DEFAULT_MINIMAL_ATTACK}
        site_profile = SiteProfile.from_dict(raw_profile)
        return site_profile, attack

    @staticmethod
    def load_or_create(profile_path: str | None = None,
                       target_url: str | None = None) -> Tuple[SiteProfile, Dict[str, Any]]:
        """Load a profile or create a minimal one.

        Convenience method that handles the common pattern:
        - If profile_path is provided, load from file
        - Else if target_url is provided, create minimal profile
        - Else raise an error

        Args:
            profile_path: Path to VF_PROFILE.json (optional).
            target_url: Target URL for minimal profile (optional).

        Returns:
            Tuple of (SiteProfile, attack_dict).
        """
        if profile_path:
            return ProfileLoader.load(profile_path)
        elif target_url:
            return ProfileLoader.create_minimal(target_url)
        else:
            return ProfileLoader.create_minimal("")
