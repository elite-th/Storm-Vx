#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF Profile Manager — Attack Profile Save/Load                       ║
║     Part of the STORM_VX Infrastructure                                 ║
║                                                                           ║
║  Save and load VF_FINDER output as JSON profiles so you don't            ║
║  have to re-scan targets. Features versioning, comparison, and           ║
║  quick-load of the last used profile.                                    ║
║                                                                           ║
║  Usage:                                                                  ║
║    from infra.vf_profile_manager import ProfileManager                   ║
║    pm = ProfileManager()                                                 ║
║    pm.save_profile("target1", finder_output_dict)                       ║
║    profile = pm.load_profile("target1")                                  ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import os
import json
import time
import hashlib
import shutil
from typing import Dict, List, Any
from urllib.parse import urlparse
from datetime import datetime
from logging_config import get_logger
logger = get_logger(__name__)

from vf_common import C


# ═══════════════════════════════════════════════════════════════════════════════
# Profile Manager
# ═══════════════════════════════════════════════════════════════════════════════

class ProfileManager:
    """
    Attack Profile Save/Load manager for STORM_VX.

    Saves VF_FINDER output as JSON profiles with versioning,
    comparison, and quick-load capabilities. Avoids re-scanning
    targets by persisting reconnaissance data.
    """

    PROFILE_VERSION = "1.0"
    METADATA_FILE = "_metadata.json"
    LAST_USED_FILE = "_last_used.json"

    def __init__(self, profiles_dir: str = "profiles"):
        """
        Initialize ProfileManager.

        Args:
            profiles_dir: Directory to store profile files.
                          Defaults to 'profiles' relative to the project root.
        """
        # Resolve to project root if relative
        if not os.path.isabs(profiles_dir):
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            profiles_dir = os.path.join(project_root, profiles_dir)

        self.profiles_dir = profiles_dir
        os.makedirs(self.profiles_dir, exist_ok=True)

    # ─── Save / Load ───────────────────────────────────────────────────────

    def save_profile(self, name: str, profile: Dict) -> str:
        """
        Save a profile to disk as JSON.

        Args:
            name: Profile name (will be sanitized for filesystem).
            profile: Profile dictionary (VF_FINDER output or similar).

        Returns:
            File path of the saved profile.
        """
        safe_name = self._sanitize_name(name)
        profile_path = os.path.join(self.profiles_dir, f"{safe_name}.json")

        # Enrich profile with metadata
        profile["_meta"] = {
            "name": name,
            "safe_name": safe_name,
            "version": self.PROFILE_VERSION,
            "saved_at": datetime.now().isoformat(),
            "saved_ts": time.time(),  # wall-clock
            "checksum": self._checksum(profile),
        }

        # Versioning: keep previous version if exists
        if os.path.exists(profile_path):
            version_dir = os.path.join(self.profiles_dir, ".versions", safe_name)
            os.makedirs(version_dir, exist_ok=True)
            try:
                with open(profile_path, "r", encoding="utf-8") as f:
                    old_data = json.load(f)
                ts = old_data.get("_meta", {}).get("saved_ts", 0)
                version_file = os.path.join(version_dir, f"v_{int(ts)}.json")
                with open(version_file, "w", encoding="utf-8") as vf:
                    json.dump(old_data, vf, indent=2, ensure_ascii=False, default=str)
            except (OSError, json.JSONDecodeError) as e:
                logger.debug(f"Version backup failed: {e}")

        # Write profile
        with open(profile_path, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2, ensure_ascii=False, default=str)

        # Update metadata index
        self._update_metadata(safe_name, profile)

        # Update last used
        self._set_last_used(safe_name)

        logger.info(f"[PROFILE] Saved: {name}")
        logger.info(f"Path: {profile_path}")

        return profile_path

    def load_profile(self, name: str) -> Dict:
        """
        Load a profile from disk.

        Args:
            name: Profile name to load.

        Returns:
            Profile dictionary.

        Raises:
            FileNotFoundError: If profile does not exist.
        """
        safe_name = self._sanitize_name(name)
        profile_path = os.path.join(self.profiles_dir, f"{safe_name}.json")

        if not os.path.exists(profile_path):
            logger.warning(f"[PROFILE] Not found: {name}")
            raise FileNotFoundError(f"Profile '{name}' not found at {profile_path}")

        with open(profile_path, "r", encoding="utf-8") as f:
            profile = json.load(f)

        # Update last used
        self._set_last_used(safe_name)

        # Update last-accessed timestamp in metadata
        meta = profile.get("_meta", {})
        meta["last_loaded_at"] = datetime.now().isoformat()
        profile["_meta"] = meta

        logger.info(f"[PROFILE] Loaded: {name}")

        return profile

    # ─── List / Delete ─────────────────────────────────────────────────────

    def list_profiles(self) -> List[Dict]:
        """
        List all saved profiles with metadata.

        Returns:
            List of dictionaries, each containing profile metadata.
        """
        metadata = self._load_metadata()
        profiles = []

        for filename in os.listdir(self.profiles_dir):
            if filename.endswith(".json") and not filename.startswith("_"):
                filepath = os.path.join(self.profiles_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    meta = data.get("_meta", {})
                    entry = {
                        "name": meta.get("name", filename.replace(".json", "")),
                        "safe_name": filename.replace(".json", ""),
                        "saved_at": meta.get("saved_at", "Unknown"),
                        "version": meta.get("version", "?"),
                        "target_url": data.get("url", data.get("target", "Unknown")),
                        "server": data.get("server", "?"),
                        "waf": data.get("waf", "None"),
                        "technologies_count": len(data.get("technologies", [])),
                        "filepath": filepath,
                    }
                    profiles.append(entry)
                except (json.JSONDecodeError, ValueError, KeyError, TypeError, OSError) as e:
                    profiles.append({
                        "name": filename.replace(".json", ""),
                        "safe_name": filename.replace(".json", ""),
                        "error": str(e),
                        "filepath": filepath,
                    })

        # Sort by saved_at descending
        profiles.sort(key=lambda x: x.get("saved_at", ""), reverse=True)

        return profiles

    def delete_profile(self, name: str) -> bool:
        """
        Delete a saved profile.

        Args:
            name: Profile name to delete.

        Returns:
            True if deleted, False if not found.
        """
        safe_name = self._sanitize_name(name)
        profile_path = os.path.join(self.profiles_dir, f"{safe_name}.json")

        if not os.path.exists(profile_path):
            logger.warning(f"[PROFILE] Not found: {name}")
            return False

        # Backup before delete
        backup_dir = os.path.join(self.profiles_dir, ".deleted")
        os.makedirs(backup_dir, exist_ok=True)
        try:
            shutil.copy2(profile_path, os.path.join(backup_dir, f"{safe_name}_{int(time.time())}.json"))  # wall-clock
        except (OSError, IOError) as e:
            logger.debug(f"Profile backup before delete failed: {e}")

        os.remove(profile_path)

        # Clean metadata
        metadata = self._load_metadata()
        metadata.pop(safe_name, None)
        self._save_metadata(metadata)

        logger.warning(f"[PROFILE] Deleted: {name}")
        return True

    # ─── Export ────────────────────────────────────────────────────────────

    def export_profile(self, name: str, format: str = "json") -> str:
        """
        Export a profile in the specified format.

        Args:
            name: Profile name to export.
            format: Output format — "json" or "txt".

        Returns:
            File path of the exported file.
        """
        profile = self.load_profile(name)
        safe_name = self._sanitize_name(name)
        export_dir = os.path.join(self.profiles_dir, "exports")
        os.makedirs(export_dir, exist_ok=True)

        if format.lower() == "json":
            export_path = os.path.join(export_dir, f"{safe_name}_export.json")
            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=2, ensure_ascii=False, default=str)
        elif format.lower() == "txt":
            export_path = os.path.join(export_dir, f"{safe_name}_export.txt")
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(self._profile_to_text(profile))
        else:
            raise ValueError(f"Unsupported export format: {format}")

        logger.info(f"[PROFILE] Exported: {name} as {format}")
        logger.info(f"Path: {export_path}")
        return export_path

    # ─── Auto-Name ─────────────────────────────────────────────────────────

    def auto_name(self, url: str) -> str:
        """
        Generate an automatic profile name from a URL.

        Args:
            url: Target URL.

        Returns:
            Generated profile name.
        """
        parsed = urlparse(url)
        domain = parsed.hostname or parsed.netloc or "unknown"
        # Remove www prefix
        domain = domain.replace("www.", "")
        # Replace dots and hyphens with underscores
        name = domain.replace(".", "_").replace("-", "_")
        # Add timestamp suffix for uniqueness
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{name}_{ts}"

    # ─── Quick-Load ────────────────────────────────────────────────────────

    def load_last_used(self) -> Dict | None:
        """
        Load the last used profile automatically.

        Returns:
            Profile dictionary, or None if no last-used record.
        """
        last_used_path = os.path.join(self.profiles_dir, self.LAST_USED_FILE)
        if not os.path.exists(last_used_path):
            logger.warning(f"[PROFILE] No last-used profile found")
            return None

        try:
            with open(last_used_path, "r", encoding="utf-8") as f:
                last = json.load(f)
            safe_name = last.get("safe_name", "")
            if safe_name:
                return self.load_profile(safe_name)
        except (OSError, json.JSONDecodeError, ValueError, KeyError) as e:
            logger.error(f"Error loading last-used profile: {e}", exc_info=True)
            logger.warning(f"[PROFILE] Error loading last-used: {e}")

        return None

    # ─── Compare ───────────────────────────────────────────────────────────

    def compare_profiles(self, name1: str, name2: str) -> Dict[str, Any]:
        """
        Compare two profiles and return the differences.

        Args:
            name1: First profile name.
            name2: Second profile name.

        Returns:
            Dictionary with added, removed, and changed fields.
        """
        p1 = self.load_profile(name1)
        p2 = self.load_profile(name2)

        diff = {
            "profile1": name1,
            "profile2": name2,
            "added": {},
            "removed": {},
            "changed": {},
        }

        all_keys = set(list(p1.keys()) + list(p2.keys()))
        for key in all_keys:
            v1 = p1.get(key)
            v2 = p2.get(key)
            if key == "_meta":
                continue
            if v1 is None and v2 is not None:
                diff["added"][key] = v2
            elif v1 is not None and v2 is None:
                diff["removed"][key] = v1
            elif v1 != v2:
                diff["changed"][key] = {"from": v1, "to": v2}

        # Print comparison summary
        logger.info(f"\n  [COMPARE] {name1} vs {name2}")
        logger.info(f"Added:   {len(diff['added'])} fields")
        logger.info(f"Removed: {len(diff['removed'])} fields")
        logger.info(f"Changed: {len(diff['changed'])} fields")

        for key, change in diff["changed"].items():
            if isinstance(change["from"], (str, int, float, bool)):
                logger.info(f"{key}: {change['from']} -> {change['to']}")

        return diff

    # ─── Print ─────────────────────────────────────────────────────────────

    def print_profiles(self):
        """Print a formatted list of all saved profiles."""
        profiles = self.list_profiles()

        if not profiles:
            logger.info(f"\n  [PROFILE] No saved profiles")
            return

        logger.info(f"\n  {'='*60}")
        logger.info(f"Saved Attack Profiles")
        logger.info(f"{'='*60}")

        for i, p in enumerate(profiles, 1):
            if "error" in p:
                logger.warning(f"{i}. {p['name']} — ERROR: {p['error']}")
                continue

            url = p.get("target_url", "?")
            server = p.get("server", "?")
            waf = p.get("waf", "None")
            tech_count = p.get("technologies_count", 0)
            saved = p.get("saved_at", "?")

            logger.info(f"{i}. {p['name']}")
            logger.info(f"  URL: {url}")
            logger.info(f"  Server: {server} | WAF: {waf} | Techs: {tech_count}")
            logger.info(f"  Saved: {saved}")

        logger.info(f"{'='*60}\n")

    def print_profile_details(self, name: str):
        """Print detailed information about a specific profile."""
        profile = self.load_profile(name)

        logger.info(f"\n  {'='*60}")
        logger.info(f"  Profile: {name}")
        logger.info(f"{'='*60}")

        meta = profile.get("_meta", {})
        logger.info(f"  Version:   {meta.get('version', '?')}")
        logger.info(f"  Saved:     {meta.get('saved_at', '?')}")
        logger.info(f"  URL:       {profile.get('url', profile.get('target', '?'))}")
        logger.info(f"  Server:    {profile.get('server', '?')}")
        logger.info(f"  WAF:       {profile.get('waf', 'None')}")
        logger.info(f"  Backend:   {profile.get('backend_language', profile.get('backend_framework', '?'))}")
        logger.info(f"  CMS:       {profile.get('cms', 'None')}")

        technologies = profile.get("technologies", [])
        if technologies:
            logger.info(f"\n  Technologies ({len(technologies)}):")
            for tech in technologies[:15]:
                tname = tech.get("name", "?")
                conf = tech.get("confidence", 0)
                cat = tech.get("category", "?")
                conf_bar = int(conf * 10)
                bar = "|" * conf_bar + "." * (10 - conf_bar)
                cc = C.G if conf > 0.7 else C.Y if conf > 0.4 else C.DM
                logger.info(f"  {cc}{tname:<25} [{bar}] {conf:.0%} ({cat}){C.RS}")

        logger.info(f"{'='*60}\n")

    # ─── Internal Helpers ──────────────────────────────────────────────────

    def _sanitize_name(self, name: str) -> str:
        """Sanitize a profile name for safe filesystem usage."""
        name = name.strip().replace(" ", "_")
        keep = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        name = "".join(c for c in name if c in keep)
        if not name:
            name = f"profile_{int(time.time())}"  # wall-clock
        return name[:128]

    def _checksum(self, data: Any) -> str:
        """Generate a checksum for profile data integrity."""
        raw = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:12]

    def _load_metadata(self) -> Dict:
        """Load the metadata index file."""
        meta_path = os.path.join(self.profiles_dir, self.METADATA_FILE)
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                logger.debug(f"Metadata load failed: {e}")
                return {}
        return {}

    def _save_metadata(self, metadata: Dict):
        """Save the metadata index file."""
        meta_path = os.path.join(self.profiles_dir, self.METADATA_FILE)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)

    def _update_metadata(self, safe_name: str, profile: Dict):
        """Update a single entry in the metadata index."""
        metadata = self._load_metadata()
        meta = profile.get("_meta", {})
        metadata[safe_name] = {
            "name": meta.get("name", safe_name),
            "saved_at": meta.get("saved_at", ""),
            "target_url": profile.get("url", profile.get("target", "")),
            "checksum": meta.get("checksum", ""),
        }
        self._save_metadata(metadata)

    def _set_last_used(self, safe_name: str):
        """Record the last-used profile."""
        last_path = os.path.join(self.profiles_dir, self.LAST_USED_FILE)
        data = {"safe_name": safe_name, "loaded_at": datetime.now().isoformat()}
        with open(last_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _profile_to_text(self, profile: Dict) -> str:
        """Convert a profile dict to a human-readable text format."""
        lines = []
        lines.append("=" * 60)
        lines.append("STORM_VX Attack Profile")
        lines.append("=" * 60)
        lines.append("")

        meta = profile.get("_meta", {})
        lines.append(f"Name:    {meta.get('name', '?')}")
        lines.append(f"Version: {meta.get('version', '?')}")
        lines.append(f"Saved:   {meta.get('saved_at', '?')}")
        lines.append(f"URL:     {profile.get('url', profile.get('target', '?'))}")
        lines.append(f"Server:  {profile.get('server', '?')}")
        lines.append(f"WAF:     {profile.get('waf', 'None')}")
        lines.append(f"CMS:     {profile.get('cms', 'None')}")
        lines.append("")

        technologies = profile.get("technologies", [])
        if technologies:
            lines.append("Technologies:")
            for tech in technologies:
                lines.append(f"  - {tech.get('name', '?')} ({tech.get('category', '?')}) "
                             f"confidence: {tech.get('confidence', 0):.0%}")

        # Attack profile
        attack = profile.get("attack_profile", {})
        if attack:
            lines.append("")
            lines.append("Attack Profile:")
            for key, val in attack.items():
                lines.append(f"  {key}: {val}")

        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VF Profile Manager — Attack Profile Save/Load")
    parser.add_argument("command", choices=["list", "show", "delete", "export", "last"],
                        help="Command to execute")
    parser.add_argument("--name", help="Profile name")
    parser.add_argument("--format", default="json", choices=["json", "txt"],
                        help="Export format")

    args = parser.parse_args()
    pm = ProfileManager()

    if args.command == "list":
        pm.print_profiles()
    elif args.command == "show":
        if not args.name:
            logger.error(f"--name is required for show")
            exit(1)
        pm.print_profile_details(args.name)
    elif args.command == "delete":
        if not args.name:
            logger.error(f"--name is required for delete")
            exit(1)
        pm.delete_profile(args.name)
    elif args.command == "export":
        if not args.name:
            logger.error(f"--name is required for export")
            exit(1)
        pm.export_profile(args.name, format=args.format)
    elif args.command == "last":
        profile = pm.load_last_used()
        if profile:
            logger.info(f"[PROFILE] Last-used profile loaded successfully")
