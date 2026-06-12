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
import re
import pathlib
from typing import Dict, List, Any
from datetime import datetime

from vf_common import C, ssl_param
from utils.response_helpers import safe_read_text
from utils.session_helpers import scanner_timeout
from logging_config import get_logger
logger = get_logger(__name__)

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


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

    # SEC-013: Async-safe subprocess wrapper — runs subprocess.run
    # in a thread executor to avoid blocking the event loop.
    @staticmethod
    async def _run_git(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        """Run a git command in a thread executor to avoid blocking the event loop.

        Args:
            *args: Git command arguments (e.g., "rev-parse", "--short", "HEAD")
            timeout: Command timeout in seconds

        Returns:
            CompletedProcess instance
        """
        cmd = ["git"] + list(args)
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                cmd, cwd=project_root,
                capture_output=True, text=True, timeout=timeout,
            )
        )
        return result
    REQUEST_TIMEOUT = 15  # seconds (Iran internet)

    def __init__(self, repo_url: str = "https://github.com/elite-th/Storm-Vx",
                 branch: str = "main", verify_ssl: bool = True):
        """
        Initialize AutoUpdater.

        Args:
            repo_url: GitHub repository URL.
            branch: Branch to check for updates.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.repo_url = repo_url.rstrip("/")
        # A3 FIX: Sanitize branch name to prevent command injection in subprocess calls
        # Only allow alphanumeric, dash, dot, slash (valid git ref characters)
        if not re.match(r'^[a-zA-Z0-9._/\-]+$', branch):
            raise ValueError(f"Invalid branch name: {branch!r}. Only alphanumeric, dash, dot, slash allowed.")
        self.branch = branch
        self.verify_ssl = verify_ssl
        # BUG-006 fix: Use pathlib.Path for safe path composition and traversal checks
        self.project_root = pathlib.Path(__file__).resolve().parent.parent
        self.backup_dir = self.project_root / ".update_backups"

        # Parse owner/repo from URL
        parts = self.repo_url.replace("https://github.com/", "").split("/")
        self.owner = parts[0] if len(parts) > 0 else "elite-th"
        self.repo = parts[1] if len(parts) > 1 else "Storm-Vx"
        # A3 FIX: Validate owner and repo names too
        for name, label in [(self.owner, "owner"), (self.repo, "repo")]:
            if not re.match(r'^[a-zA-Z0-9._\-]+$', name):
                raise ValueError(f"Invalid GitHub {label} name: {name!r}")

        # State
        self._update_in_progress = False
        self._attack_active = False
        self._last_backup_id: str | None = None

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
                cwd=str(self.project_root),
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.debug(f"Git version check failed: {e}")

        # Fallback: try reading a version file
        version_file = str(self.project_root / ".version")
        if os.path.exists(version_file):
            try:
                with open(version_file, "r") as f:
                    return f.read().strip()
            except (OSError, IOError) as e:
                logger.debug(f"Version file read failed: {e}")

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
            logger.error(f"[UPDATER] aiohttp is required! pip install aiohttp")
            return {"update_available": False, "current_version": self.get_current_version(),
                    "latest_version": "?", "changelog": "aiohttp not available", "commits_behind": 0}

        current = self.get_current_version()
        logger.info(f"[UPDATER] Checking for updates... (current: {current})")

        timeout = scanner_timeout(total=self.REQUEST_TIMEOUT)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Get latest commit on the branch
                url = f"{self.GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/commits/{self.branch}"
                headers = {"Accept": "application/vnd.github.v3+json"}

                async with session.get(url, headers=headers, ssl=ssl_param(self.verify_ssl)) as resp:
                    if resp.status != 200:
                        logger.error(f"[UPDATER] GitHub API error: {resp.status}")
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

                logger.info(f"[UPDATER] Update available! {current} → {latest_sha}")
                logger.info(f"[UPDATER] {latest_message[:80]}")
            else:
                commits_behind = 0
                logger.info(f"[UPDATER] Already up to date ({current})")

            return {
                "update_available": update_available,
                "current_version": current,
                "latest_version": latest_sha,
                "changelog": changelog,
                "commits_behind": commits_behind,
            }

        except asyncio.TimeoutError:
            logger.warning(f"[UPDATER] Timeout checking for updates (Iran internet)")
            return {"update_available": False, "current_version": current,
                    "latest_version": "?", "changelog": "Timeout", "commits_behind": 0}
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as e:
            logger.error(f"[UPDATER] Error checking updates: {e}", exc_info=True)
            return {"update_available": False, "current_version": current,
                    "latest_version": "?", "changelog": str(e), "commits_behind": 0}

    async def _get_comparison(self, session: aiohttp.ClientSession,
                              base: str, head: str) -> str | None:
        """Get comparison between two commits."""
        try:
            url = f"{self.GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/compare/{base}...{head}"
            headers = {"Accept": "application/vnd.github.v3+json"}

            async with session.get(url, headers=headers, ssl=ssl_param(self.verify_ssl)) as resp:
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
        except (KeyError, TypeError, ValueError) as e:
            logger.debug(f"Changelog parsing failed: {e}")
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
            logger.warning(f"[UPDATER] Cannot update during active attack!")
            return False

        if self._update_in_progress:
            logger.warning(f"[UPDATER] Update already in progress")
            return False

        self._update_in_progress = True

        try:
            logger.info(f"[UPDATER] Starting update...")

            # Step 1: Backup
            logger.info(f"[UPDATER] [1/5] Creating backup...")
            backup_id = await self._create_backup()
            if not backup_id:
                logger.info(f"[UPDATER] Backup skipped (non-git or error)")
            else:
                self._last_backup_id = backup_id
                logger.info(f"[UPDATER] Backup created: {backup_id}")

            # Step 2: Show progress bar
            logger.info(f"[UPDATER] [2/5] Downloading changes...")
            await self._show_progress("Downloading", 2.0)

            # Step 3: Git pull
            logger.info(f"[UPDATER] [3/5] Applying updates (git pull)...")
            pull_success = await self._git_pull()

            if not pull_success:
                # Try downloading via GitHub API as fallback
                logger.warning(f"[UPDATER] Git pull failed, trying GitHub API download...")
                api_success = await self._api_download()
                if not api_success:
                    logger.warning(f"[UPDATER] Download failed!")
                    if self._last_backup_id:
                        logger.warning(f"[UPDATER] Rolling back...")
                        await self.rollback(self._last_backup_id)
                    return False

            # Step 4: Verify integrity
            logger.info(f"[UPDATER] [4/5] Verifying integrity...")
            await self._show_progress("Verifying", 1.0)
            verify_ok = self._verify_integrity()

            if not verify_ok:
                logger.warning(f"[UPDATER] Integrity check failed!")
                if self._last_backup_id:
                    logger.warning(f"[UPDATER] Rolling back...")
                    await self.rollback(self._last_backup_id)
                return False

            # Step 5: Complete
            logger.info(f"[UPDATER] [5/5] Update complete!")
            new_version = self.get_current_version()
            logger.info(f"[UPDATER] Updated to version: {new_version}")

            return True

        except (OSError, RuntimeError, ValueError, asyncio.TimeoutError) as e:
            logger.error(f"[UPDATER] Update error: {e}", exc_info=True)
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
        backup_path = str(self.backup_dir / backup_id)
        if not os.path.exists(backup_path):
            logger.error(f"[UPDATER] Backup not found: {backup_id}")
            return False

        logger.warning(f"[UPDATER] Rolling back to {backup_id}...")

        try:
            # Try git reset first
            git_log = os.path.join(backup_path, "git_head.txt")
            if os.path.exists(git_log):
                with open(git_log, "r") as f:
                    target_commit = f.read().strip()

                result = await self._run_git("reset", "--hard", target_commit, timeout=30)
                if result.returncode == 0:
                    logger.info(f"[UPDATER] Rolled back via git to {target_commit}")
                    return True

            # Fallback: restore files from backup
            files_log = os.path.join(backup_path, "files.json")
            if os.path.exists(files_log):
                with open(files_log, "r") as f:
                    files = json.load(f)

                for rel_path in files:
                    backup_file = os.path.join(backup_path, "files", rel_path)
                    target_file = str(self.project_root / rel_path)
                    if os.path.exists(backup_file):
                        os.makedirs(os.path.dirname(target_file), exist_ok=True)
                        shutil.copy2(backup_file, target_file)

                logger.info(f"[UPDATER] Rolled back {len(files)} files")
                return True

            logger.warning(f"[UPDATER] No valid rollback data found")
            return False

        except (OSError, IOError, json.JSONDecodeError, shutil.Error, RuntimeError) as e:
            logger.error(f"[UPDATER] Rollback error: {e}", exc_info=True)
            return False

    # ─── Internal Helpers ──────────────────────────────────────────────────

    async def _create_backup(self) -> str | None:
        """Create a backup of current project files."""
        backup_id = f"backup_{int(time.time())}"  # wall-clock
        backup_path = str(self.backup_dir / backup_id)
        os.makedirs(backup_path, exist_ok=True)

        # Save current git HEAD
        try:
            result = await self._run_git("rev-parse", "HEAD", timeout=10)
            if result.returncode == 0:
                with open(os.path.join(backup_path, "git_head.txt"), "w") as f:
                    f.write(result.stdout.strip())
        except (OSError, subprocess.TimeoutExpired) as e:
            logger.debug(f"Git HEAD backup failed: {e}")

        # Backup key Python files
        files_to_backup = []
        files_dir = os.path.join(backup_path, "files")

        for root, dirs, filenames in os.walk(str(self.project_root)):
            # Skip hidden dirs, venv, __pycache__, etc.
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                       ("venv", "__pycache__", "node_modules", ".git", ".update_backups")]
            for fn in filenames:
                if fn.endswith(".py") or fn.endswith(".json") or fn.endswith(".sh"):
                    filepath = os.path.join(root, fn)
                    rel_path = os.path.relpath(filepath, str(self.project_root))
                    backup_file = os.path.join(files_dir, rel_path)
                    try:
                        os.makedirs(os.path.dirname(backup_file), exist_ok=True)
                        shutil.copy2(filepath, backup_file)
                        files_to_backup.append(rel_path)
                    except (OSError, IOError) as e:
                        logger.debug(f"Backup copy failed for {rel_path}: {e}")

        # Save file list
        with open(os.path.join(backup_path, "files.json"), "w") as f:
            json.dump(files_to_backup, f, indent=2)

        # Clean old backups (keep last 5)
        try:
            backups = sorted(os.listdir(str(self.backup_dir)))
            while len(backups) > 5:
                old = str(self.backup_dir / backups.pop(0))
                shutil.rmtree(old, ignore_errors=True)
        except OSError as e:
            logger.debug(f"Old backup cleanup failed: {e}")

        return backup_id

    async def _git_pull(self) -> bool:
        """Execute git pull to update the repository."""
        try:
            # Fetch first
            result = await self._run_git("fetch", "origin", self.branch, timeout=60)
            if result.returncode != 0:
                logger.warning(f"[UPDATER] git fetch failed: {result.stderr[:200]}")
                return False

            # Pull / reset
            result = await self._run_git("reset", "--hard", f"origin/{self.branch}", timeout=60)
            if result.returncode != 0:
                logger.warning(f"[UPDATER] git reset failed: {result.stderr[:200]}")
                return False

            return True

        except subprocess.TimeoutExpired:
            logger.warning(f"[UPDATER] Git operation timed out")
            return False
        except (OSError, RuntimeError) as e:
            logger.error(f"[UPDATER] git error: {e}", exc_info=True)
            return False

    async def _api_download(self) -> bool:
        """Download updated files via GitHub API (fallback method)."""
        if not HAS_AIOHTTP:
            return False

        timeout = scanner_timeout(total=self.REQUEST_TIMEOUT)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Get tree of the latest commit
                url = f"{self.GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/git/trees/{self.branch}?recursive=1"
                headers = {"Accept": "application/vnd.github.v3+json"}

                async with session.get(url, headers=headers, ssl=ssl_param(self.verify_ssl)) as resp:
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

                    # BUG-006 fix: Validate path stays within project_root
                    # Secondary check: reject obviously malicious paths before resolution
                    if (not file_path
                            or os.path.isabs(file_path)
                            or any(p == '..' for p in file_path.replace('\\', '/').split('/'))):
                        logger.warning(f"SEC-006: Rejected unsafe path: {file_path!r}")
                        continue
                    # Primary check: resolve and verify containment
                    resolved = (self.project_root / file_path).resolve()
                    if not resolved.is_relative_to(self.project_root.resolve()):
                        logger.warning(f"SEC-006: Path traversal detected, skipping: {file_path}")
                        continue

                    download_url = item.get("download_url")

                    if not download_url:
                        # Construct raw URL
                        download_url = f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{self.branch}/{file_path}"

                    try:
                        async with session.get(download_url, ssl=ssl_param(self.verify_ssl)) as file_resp:
                            if file_resp.status == 200:
                                content = await safe_read_text(file_resp)
                                target = str(self.project_root / file_path)
                                os.makedirs(os.path.dirname(target), exist_ok=True)
                                with open(target, "w", encoding="utf-8") as f:
                                    f.write(content)
                                downloaded += 1
                    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, UnicodeDecodeError) as dl_err:
                        logger.debug(f"Failed to download {file_path}: {dl_err}")

                    # Progress
                    if downloaded % 5 == 0:
                        pct = downloaded / len(py_files) * 100
                        bar_len = int(pct / 5)
                        bar = "█" * bar_len + "░" * (20 - bar_len)
                        logger.debug(f"[UPDATER] [{bar}] {pct:.0f}%")

                logger.info(f"[UPDATER] Downloaded {downloaded}/{len(py_files)} files")
                return downloaded > 0

        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError, KeyError) as e:
            logger.error(f"[UPDATER] API download error: {e}", exc_info=True)
            return False

    def _verify_integrity(self) -> bool:
        """Verify project integrity after update.
        
        A4 FIX: Now computes SHA-256 hashes of key files and checks
        they contain valid Python syntax (not just non-empty).
        C3 FIX: Expanded key files list to include core modules.
        """
        # Check that key files exist and contain valid Python
        key_files = [
            "tester/VF_TESTER.py",
            "finder/VF_FINDER.py",
            "infra/__init__.py",
            "infra/vf_profile_manager.py",
            "infra/vf_report.py",
            "infra/vf_telegram.py",
            "infra/vf_updater.py",
            "infra/vf_multi_target.py",
            # C3 FIX: Added core modules to integrity check
            "vf_common.py",
            "vf_validator.py",
            "vf_network.py",
            "plugin_system.py",
            "exceptions.py",
        ]

        all_ok = True
        for rel_path in key_files:
            filepath = str(self.project_root / rel_path)
            if not os.path.exists(filepath):
                logger.warning(f"[UPDATER] Missing: {rel_path}")
                all_ok = False
                continue
            elif os.path.getsize(filepath) == 0:
                logger.warning(f"[UPDATER] Empty: {rel_path}")
                all_ok = False
                continue
            
            # A4 FIX: Compute SHA-256 hash for integrity tracking
            try:
                sha256 = hashlib.sha256()
                with open(filepath, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        sha256.update(chunk)
                file_hash = sha256.hexdigest()
                logger.debug(f"Integrity check: {rel_path} SHA-256={file_hash[:16]}...")
            except OSError as e:
                logger.debug(f"Cannot hash {rel_path}: {e}")
            
            # A4 FIX: Verify Python files parse correctly (no corrupt downloads)
            if rel_path.endswith('.py'):
                try:
                    import ast
                    with open(filepath, 'r', encoding='utf-8') as f:
                        ast.parse(f.read())
                except SyntaxError as e:
                    logger.warning(f"[UPDATER] Syntax error in {rel_path}: {e}")
                    all_ok = False
                except (OSError, UnicodeDecodeError) as e:
                    logger.warning(f"[UPDATER] Cannot verify {rel_path}: {e}")
                    all_ok = False

        if all_ok:
            logger.info(f"[UPDATER] All key files verified (integrity + syntax)")

        return all_ok

    async def _show_progress(self, label: str, duration: float):
        """Show a simple progress bar animation."""
        steps = 20
        step_delay = duration / steps
        for i in range(steps + 1):
            pct = i / steps * 100
            bar_len = i
            bar = "█" * bar_len + "░" * (steps - bar_len)
            logger.debug(f"[UPDATER] [{bar}] {label} {pct:.0f}%")
            await asyncio.sleep(step_delay)


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
        logger.info(f"\n  Current:  {result['current_version']}")
        logger.info(f"Latest:   {result['latest_version']}")
        logger.info(f"Update:   {'Yes' if result['update_available'] else 'No'}")
        if result['update_available']:
            logger.info(f"\n  Changelog:\n{result['changelog']}")

    elif args.update:
        success = asyncio.run(updater.update())
        if success:
            logger.info(f"[UPDATER] Update successful!")
        else:
            logger.error(f"[UPDATER] Update failed!")

    elif args.rollback:
        success = asyncio.run(updater.rollback(args.rollback))
        if success:
            logger.info(f"[UPDATER] Rollback successful!")
        else:
            logger.error(f"[UPDATER] Rollback failed!")

    else:
        parser.print_help()
