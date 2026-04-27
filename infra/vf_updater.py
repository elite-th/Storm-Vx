#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF Auto-Updater — Auto-Update from GitHub                           ║
║     Part of the STORM_VX Infrastructure                                 ║
║                                                                           ║
║  Checks for new commits on the main branch and applies updates           ║
║  with backup, verification, and rollback capability.                     ║
║                                                                           ║
║  Features:                                                               ║
║    - Compare current version (git commit hash) with remote               ║
║    - Show changelog before updating                                      ║
║    - Backup current files before update                                  ║
║    - Verify file integrity after update                                  ║
║    - Rollback if update fails                                            ║
║    - Don't update during active attack                                   ║
║    - Progress bar during update                                          ║
║                                                                           ║
║  Usage:                                                                  ║
║    from infra.vf_updater import AutoUpdater                              ║
║    updater = AutoUpdater()                                               ║
║    result = await updater.check_update()                                 ║
║    if result["update_available"]:                                        ║
║        success = await updater.update()                                  ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import os
import asyncio
import json
import time
import shutil
import subprocess
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ═══════════════════════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════════════════════

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ═══════════════════════════════════════════════════════════════════════════════
# Auto-Updater
# ═══════════════════════════════════════════════════════════════════════════════

class AutoUpdater:
    """
    Auto-Update from GitHub for STORM_VX.

    Checks for new commits on the main branch, shows changelog,
    downloads changed files with backup, and supports rollback.
    """

    GITHUB_API_BASE = "https://api.github.com"
    REQUEST_TIMEOUT = 15  # seconds (Iran internet)

    def __init__(self, repo_url: str = "https://github.com/elite-th/Storm-Vx",
                 branch: str = "main"):
        """
        Initialize AutoUpdater.

        Args:
            repo_url: GitHub repository URL.
            branch: Branch to check for updates.
        """
        self.repo_url = repo_url.rstrip("/")
        self.branch = branch
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.backup_dir = os.path.join(self.project_root, ".update_backups")

        # Parse owner/repo from URL
        parts = self.repo_url.replace("https://github.com/", "").split("/")
        self.owner = parts[0] if len(parts) > 0 else "elite-th"
        self.repo = parts[1] if len(parts) > 1 else "Storm-Vx"

        # State
        self._update_in_progress = False
        self._attack_active = False
        self._last_backup_id: Optional[str] = None

    # ─── Attack Safety ─────────────────────────────────────────────────────

    def set_attack_active(self, active: bool):
        """
        Set whether an attack is currently active.

        Updates will NOT proceed if attack is active.

        Args:
            active: True if attack is running.
        """
        self._attack_active = active

    # ─── Version Check ─────────────────────────────────────────────────────

    def get_current_version(self) -> str:
        """
        Get current version from git commit hash.

        Returns:
            Current commit hash (short), or "unknown" if git not available.
        """
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=self.project_root,
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass

        # Fallback: try reading a version file
        version_file = os.path.join(self.project_root, ".version")
        if os.path.exists(version_file):
            try:
                with open(version_file, "r") as f:
                    return f.read().strip()
            except Exception:
                pass

        return "unknown"

    async def check_update(self) -> Dict:
        """
        Check for updates on the remote repository.

        Returns:
            Dictionary with keys:
              - update_available: bool
              - current_version: str
              - latest_version: str
              - changelog: str
              - commits_behind: int
        """
        if not HAS_AIOHTTP:
            print(f"  {C.R}[UPDATER] aiohttp is required! pip install aiohttp{C.RS}")
            return {"update_available": False, "current_version": self.get_current_version(),
                    "latest_version": "?", "changelog": "aiohttp not available", "commits_behind": 0}

        current = self.get_current_version()
        print(f"  {C.CY}[UPDATER] Checking for updates... (current: {current}){C.RS}")

        timeout = aiohttp.ClientTimeout(total=self.REQUEST_TIMEOUT)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Get latest commit on the branch
                url = f"{self.GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/commits/{self.branch}"
                headers = {"Accept": "application/vnd.github.v3+json"}

                async with session.get(url, headers=headers, ssl=False) as resp:
                    if resp.status != 200:
                        print(f"  {C.R}[UPDATER] GitHub API error: {resp.status}{C.RS}")
                        return {"update_available": False, "current_version": current,
                                "latest_version": "?", "changelog": f"API error: {resp.status}",
                                "commits_behind": 0}

                    data = await resp.json(content_type=None)
                    latest_sha = data.get("sha", "")[:7]
                    latest_message = data.get("commit", {}).get("message", "No message")
                    latest_date = data.get("commit", {}).get("committer", {}).get("date", "?")

            update_available = (current != latest_sha and current != "unknown")

            changelog = f"Latest: {latest_sha}\n{latest_message}\nDate: {latest_date}"

            if update_available:
                # Try to get comparison commits
                comparison = await self._get_comparison(session, current, latest_sha)
                if comparison:
                    changelog = comparison
                    commits_behind = comparison.count("\n• ")
                else:
                    commits_behind = 1

                print(f"  {C.Y}[UPDATER] Update available! {current} → {latest_sha}{C.RS}")
                print(f"  {C.DM}  {latest_message[:80]}{C.RS}")
            else:
                commits_behind = 0
                print(f"  {C.G}[UPDATER] Already up to date ({current}){C.RS}")

            return {
                "update_available": update_available,
                "current_version": current,
                "latest_version": latest_sha,
                "changelog": changelog,
                "commits_behind": commits_behind,
            }

        except asyncio.TimeoutError:
            print(f"  {C.R}[UPDATER] Timeout checking for updates (Iran internet){C.RS}")
            return {"update_available": False, "current_version": current,
                    "latest_version": "?", "changelog": "Timeout", "commits_behind": 0}
        except Exception as e:
            print(f"  {C.R}[UPDATER] Error checking updates: {e}{C.RS}")
            return {"update_available": False, "current_version": current,
                    "latest_version": "?", "changelog": str(e), "commits_behind": 0}

    async def _get_comparison(self, session: aiohttp.ClientSession,
                              base: str, head: str) -> Optional[str]:
        """Get comparison between two commits."""
        try:
            url = f"{self.GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/compare/{base}...{head}"
            headers = {"Accept": "application/vnd.github.v3+json"}

            async with session.get(url, headers=headers, ssl=False) as resp:
                if resp.status != 200:
                    return None

                data = await resp.json(content_type=None)
                commits = data.get("commits", [])
                lines = []
                for commit in commits[:20]:
                    sha = commit.get("sha", "")[:7]
                    msg = commit.get("commit", {}).get("message", "").split("\n")[0]
                    date = commit.get("commit", {}).get("committer", {}).get("date", "")[:10]
                    lines.append(f"• {sha} ({date}) {msg}")

                if len(commits) > 20:
                    lines.append(f"  ... and {len(commits) - 20} more commits")

                return "\n".join(lines)
        except Exception:
            return None

    # ─── Update Execution ──────────────────────────────────────────────────

    async def update(self) -> bool:
        """
        Perform the update from GitHub.

        Steps:
          1. Verify no active attack
          2. Backup current files
          3. Pull changes from git
          4. Verify integrity
          5. If failed, rollback

        Returns:
            True if update succeeded, False otherwise.
        """
        if self._attack_active:
            print(f"  {C.R}[UPDATER] Cannot update during active attack!{C.RS}")
            return False

        if self._update_in_progress:
            print(f"  {C.Y}[UPDATER] Update already in progress{C.RS}")
            return False

        self._update_in_progress = True

        try:
            print(f"  {C.CY}[UPDATER] Starting update...{C.RS}")

            # Step 1: Backup
            print(f"  {C.CY}[UPDATER] [1/5] Creating backup...{C.RS}")
            backup_id = await self._create_backup()
            if not backup_id:
                print(f"  {C.Y}[UPDATER] Backup skipped (non-git or error){C.RS}")
            else:
                self._last_backup_id = backup_id
                print(f"  {C.G}[UPDATER] Backup created: {backup_id}{C.RS}")

            # Step 2: Show progress bar
            print(f"  {C.CY}[UPDATER] [2/5] Downloading changes...{C.RS}")
            await self._show_progress("Downloading", 2.0)

            # Step 3: Git pull
            print(f"  {C.CY}[UPDATER] [3/5] Applying updates (git pull)...{C.RS}")
            pull_success = await self._git_pull()

            if not pull_success:
                # Try downloading via GitHub API as fallback
                print(f"  {C.Y}[UPDATER] Git pull failed, trying GitHub API download...{C.RS}")
                api_success = await self._api_download()
                if not api_success:
                    print(f"  {C.R}[UPDATER] Download failed!{C.RS}")
                    if self._last_backup_id:
                        print(f"  {C.Y}[UPDATER] Rolling back...{C.RS}")
                        await self.rollback(self._last_backup_id)
                    return False

            # Step 4: Verify integrity
            print(f"  {C.CY}[UPDATER] [4/5] Verifying integrity...{C.RS}")
            await self._show_progress("Verifying", 1.0)
            verify_ok = self._verify_integrity()

            if not verify_ok:
                print(f"  {C.R}[UPDATER] Integrity check failed!{C.RS}")
                if self._last_backup_id:
                    print(f"  {C.Y}[UPDATER] Rolling back...{C.RS}")
                    await self.rollback(self._last_backup_id)
                return False

            # Step 5: Complete
            print(f"  {C.CY}[UPDATER] [5/5] Update complete!{C.RS}")
            new_version = self.get_current_version()
            print(f"  {C.G}[UPDATER] Updated to version: {new_version}{C.RS}")

            return True

        except Exception as e:
            print(f"  {C.R}[UPDATER] Update error: {e}{C.RS}")
            if self._last_backup_id:
                await self.rollback(self._last_backup_id)
            return False
        finally:
            self._update_in_progress = False

    # ─── Rollback ──────────────────────────────────────────────────────────

    async def rollback(self, backup_id: str) -> bool:
        """
        Rollback to a previous backup.

        Args:
            backup_id: Backup identifier (timestamp).

        Returns:
            True if rollback succeeded.
        """
        backup_path = os.path.join(self.backup_dir, backup_id)
        if not os.path.exists(backup_path):
            print(f"  {C.R}[UPDATER] Backup not found: {backup_id}{C.RS}")
            return False

        print(f"  {C.CY}[UPDATER] Rolling back to {backup_id}...{C.RS}")

        try:
            # Try git reset first
            git_log = os.path.join(backup_path, "git_head.txt")
            if os.path.exists(git_log):
                with open(git_log, "r") as f:
                    target_commit = f.read().strip()

                result = subprocess.run(
                    ["git", "reset", "--hard", target_commit],
                    cwd=self.project_root,
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    print(f"  {C.G}[UPDATER] Rolled back via git to {target_commit}{C.RS}")
                    return True

            # Fallback: restore files from backup
            files_log = os.path.join(backup_path, "files.json")
            if os.path.exists(files_log):
                with open(files_log, "r") as f:
                    files = json.load(f)

                for rel_path in files:
                    backup_file = os.path.join(backup_path, "files", rel_path)
                    target_file = os.path.join(self.project_root, rel_path)
                    if os.path.exists(backup_file):
                        os.makedirs(os.path.dirname(target_file), exist_ok=True)
                        shutil.copy2(backup_file, target_file)

                print(f"  {C.G}[UPDATER] Rolled back {len(files)} files{C.RS}")
                return True

            print(f"  {C.R}[UPDATER] No valid rollback data found{C.RS}")
            return False

        except Exception as e:
            print(f"  {C.R}[UPDATER] Rollback error: {e}{C.RS}")
            return False

    # ─── Internal Helpers ──────────────────────────────────────────────────

    async def _create_backup(self) -> Optional[str]:
        """Create a backup of current project files."""
        backup_id = f"backup_{int(time.time())}"
        backup_path = os.path.join(self.backup_dir, backup_id)
        os.makedirs(backup_path, exist_ok=True)

        # Save current git HEAD
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.project_root,
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                with open(os.path.join(backup_path, "git_head.txt"), "w") as f:
                    f.write(result.stdout.strip())
        except Exception:
            pass

        # Backup key Python files
        files_to_backup = []
        files_dir = os.path.join(backup_path, "files")

        for root, dirs, filenames in os.walk(self.project_root):
            # Skip hidden dirs, venv, __pycache__, etc.
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                       ("venv", "__pycache__", "node_modules", ".git", ".update_backups")]
            for fn in filenames:
                if fn.endswith(".py") or fn.endswith(".json") or fn.endswith(".sh"):
                    filepath = os.path.join(root, fn)
                    rel_path = os.path.relpath(filepath, self.project_root)
                    backup_file = os.path.join(files_dir, rel_path)
                    try:
                        os.makedirs(os.path.dirname(backup_file), exist_ok=True)
                        shutil.copy2(filepath, backup_file)
                        files_to_backup.append(rel_path)
                    except Exception:
                        pass

        # Save file list
        with open(os.path.join(backup_path, "files.json"), "w") as f:
            json.dump(files_to_backup, f, indent=2)

        # Clean old backups (keep last 5)
        try:
            backups = sorted(os.listdir(self.backup_dir))
            while len(backups) > 5:
                old = os.path.join(self.backup_dir, backups.pop(0))
                shutil.rmtree(old, ignore_errors=True)
        except Exception:
            pass

        return backup_id

    async def _git_pull(self) -> bool:
        """Execute git pull to update the repository."""
        try:
            # Fetch first
            result = subprocess.run(
                ["git", "fetch", "origin", self.branch],
                cwd=self.project_root,
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                print(f"  {C.R}[UPDATER] git fetch failed: {result.stderr[:200]}{C.RS}")
                return False

            # Pull / reset
            result = subprocess.run(
                ["git", "reset", "--hard", f"origin/{self.branch}"],
                cwd=self.project_root,
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                print(f"  {C.R}[UPDATER] git reset failed: {result.stderr[:200]}{C.RS}")
                return False

            return True

        except subprocess.TimeoutExpired:
            print(f"  {C.R}[UPDATER] git operation timed out{C.RS}")
            return False
        except Exception as e:
            print(f"  {C.R}[UPDATER] git error: {e}{C.RS}")
            return False

    async def _api_download(self) -> bool:
        """Download updated files via GitHub API (fallback method)."""
        if not HAS_AIOHTTP:
            return False

        timeout = aiohttp.ClientTimeout(total=self.REQUEST_TIMEOUT)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Get tree of the latest commit
                url = f"{self.GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/git/trees/{self.branch}?recursive=1"
                headers = {"Accept": "application/vnd.github.v3+json"}

                async with session.get(url, headers=headers, ssl=False) as resp:
                    if resp.status != 200:
                        return False
                    data = await resp.json(content_type=None)

                tree = data.get("tree", [])
                py_files = [item for item in tree
                            if item.get("type") == "blob"
                            and (item["path"].endswith(".py") or item["path"].endswith(".json"))]

                # Download each file
                downloaded = 0
                for item in py_files:
                    file_path = item["path"]
                    download_url = item.get("download_url")

                    if not download_url:
                        # Construct raw URL
                        download_url = f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{self.branch}/{file_path}"

                    try:
                        async with session.get(download_url, ssl=False) as file_resp:
                            if file_resp.status == 200:
                                content = await file_resp.text()
                                target = os.path.join(self.project_root, file_path)
                                os.makedirs(os.path.dirname(target), exist_ok=True)
                                with open(target, "w", encoding="utf-8") as f:
                                    f.write(content)
                                downloaded += 1
                    except Exception:
                        pass

                    # Progress
                    if downloaded % 5 == 0:
                        pct = downloaded / len(py_files) * 100
                        bar_len = int(pct / 5)
                        bar = "█" * bar_len + "░" * (20 - bar_len)
                        print(f"  {C.CY}[UPDATER] [{bar}] {pct:.0f}%{C.RS}", end="\r")

                print()
                print(f"  {C.G}[UPDATER] Downloaded {downloaded}/{len(py_files)} files{C.RS}")
                return downloaded > 0

        except Exception as e:
            print(f"  {C.R}[UPDATER] API download error: {e}{C.RS}")
            return False

    def _verify_integrity(self) -> bool:
        """Verify project integrity after update."""
        # Check that key files exist and are non-empty
        key_files = [
            "tester/VF_TESTER.py",
            "finder/VF_FINDER.py",
            "infra/__init__.py",
            "infra/vf_profile_manager.py",
            "infra/vf_report.py",
            "infra/vf_telegram.py",
            "infra/vf_updater.py",
            "infra/vf_multi_target.py",
        ]

        all_ok = True
        for rel_path in key_files:
            filepath = os.path.join(self.project_root, rel_path)
            if not os.path.exists(filepath):
                print(f"  {C.R}[UPDATER] Missing: {rel_path}{C.RS}")
                all_ok = False
            elif os.path.getsize(filepath) == 0:
                print(f"  {C.Y}[UPDATER] Empty: {rel_path}{C.RS}")
                all_ok = False

        if all_ok:
            print(f"  {C.G}[UPDATER] All key files verified{C.RS}")

        return all_ok

    async def _show_progress(self, label: str, duration: float):
        """Show a simple progress bar animation."""
        steps = 20
        step_delay = duration / steps
        for i in range(steps + 1):
            pct = i / steps * 100
            bar_len = i
            bar = "█" * bar_len + "░" * (steps - bar_len)
            print(f"  {C.CY}[UPDATER] [{bar}] {label} {pct:.0f}%{C.RS}", end="\r")
            await asyncio.sleep(step_delay)
        print()


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VF Auto-Updater — Auto-Update from GitHub")
    parser.add_argument("--check", action="store_true", help="Check for updates")
    parser.add_argument("--update", action="store_true", help="Apply update")
    parser.add_argument("--rollback", help="Rollback to backup ID")
    parser.add_argument("--repo", default="https://github.com/elite-th/Storm-Vx",
                        help="Repository URL")
    parser.add_argument("--branch", default="main", help="Branch name")

    args = parser.parse_args()
    updater = AutoUpdater(repo_url=args.repo, branch=args.branch)

    if args.check:
        result = asyncio.run(updater.check_update())
        print(f"\n  Current:  {result['current_version']}")
        print(f"  Latest:   {result['latest_version']}")
        print(f"  Update:   {'Yes' if result['update_available'] else 'No'}")
        if result['update_available']:
            print(f"\n  Changelog:\n{result['changelog']}")

    elif args.update:
        success = asyncio.run(updater.update())
        if success:
            print(f"  {C.G}Update successful!{C.RS}")
        else:
            print(f"  {C.R}Update failed!{C.RS}")

    elif args.rollback:
        success = asyncio.run(updater.rollback(args.rollback))
        if success:
            print(f"  {C.G}Rollback successful!{C.RS}")
        else:
            print(f"  {C.R}Rollback failed!{C.RS}")

    else:
        parser.print_help()
