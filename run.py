#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     STORM_VX v3.0 — Full Pipeline Launcher (Python)                     ║
║     Replaces run.bat — cross-platform, no path issues                   ║
║                                                                           ║
║  Full Pipeline: FINDER (deep scan) -> TESTER (auto attack)              ║
║                                                                           ║
║  FIXES vs run.bat:                                                       ║
║  - No "unexpected at this time" errors from parentheses in path          ║
║  - No null-byte encoding issues                                          ║
║  - Works on Windows, Linux, macOS                                        ║
║  - Proper error handling and cleanup                                     ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage:
  python run.py                          (interactive — prompts for URL)
  python run.py https://target.com       (auto mode)
  python run.py --no-deep https://t.com  (skip deep scan)
  python run.py --profile profile.json   (skip FINDER, use existing profile)

Keyboard Controls (during attack):
  +   Increase workers (+step)
  -   Decrease workers (-step)
  q   Quit gracefully
"""

from __future__ import annotations

import os
import sys
import io
import json
import subprocess
import platform
import shutil
import argparse
import time
import signal
from pathlib import Path
from typing import Optional


from logging_config import ensure_utf8_console


# ═══════════════════════════════════════════════════════════════════════════════
# UTF-8 Console Setup
# ═══════════════════════════════════════════════════════════════════════════════

# NOTE: ensure_utf8_console() is now called inside main() (BUG-048 fix).
# Previously it was called at module level, causing side effects when
# importing this module for testing.


# ═══════════════════════════════════════════════════════════════════════════════
# ANSI Colors — imported from vf_common (BUG-046: removed duplicate C class)
# ═══════════════════════════════════════════════════════════════════════════════

from vf_common import C


# ═══════════════════════════════════════════════════════════════════════════════
# Root Directory Detection
# ═══════════════════════════════════════════════════════════════════════════════

# ROOT_DIR = directory where run.py lives (no trailing separator issues)
ROOT_DIR = Path(__file__).resolve().parent


# ═══════════════════════════════════════════════════════════════════════════════
# Banner
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner():
    """Display the STORM_VX ASCII art banner."""
    print(f"""
  {C.NEON_GREEN}SSSSS  TTTTT  OOO  RRRR  M   M       V       V  X  X{C.RS}
  {C.NEON_GREEN}SS       T   O   O R   R MM MM        V     V    X  X{C.RS}
  {C.NEON_GREEN}SSSSS    T   O   O RRRR  M M M         V   V      XX{C.RS}
  {C.NEON_GREEN}   SS    T   O   O R   R M   M          V V      X  X{C.RS}
  {C.NEON_GREEN}SSSSS    T    OOO  R   R M   M           V      X  X{C.RS}
""")
    print(f"                    {C.NEON_CYAN}BY ELiteTH{C.RS}")
    print()
    print(f"  {C.BD}+==================================================+")
    print(f"  :              S T O R M _ V X  v3.0              :")
    print(f"  :           Full Pipeline - FINDER + TESTER        :")
    print(f"  +==================================================+{C.RS}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# Admin Check (Windows)
# ═══════════════════════════════════════════════════════════════════════════════

def is_admin() -> bool:
    """Check if running with administrator/root privileges."""
    if platform.system() == 'Windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (OSError, AttributeError):
            return False
    else:
        return os.geteuid() == 0


def request_admin_windows():
    """Request UAC elevation on Windows (re-launches self as admin)."""
    if platform.system() != 'Windows':
        return False
    try:
        import ctypes
        script = str(Path(__file__).resolve())
        params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        return True
    except (OSError, AttributeError) as e:
        print(f"  {C.R}[ERROR] Failed to elevate: {e}{C.RS}")
        print(f"  {C.Y}[INFO] Right-click run.py → 'Run as administrator'{C.RS}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# File Discovery
# ═══════════════════════════════════════════════════════════════════════════════

def find_file(name: str, search_paths: list[Path]) -> Optional[Path]:
    """Search for a file in the given paths."""
    for sp in search_paths:
        candidate = sp / name
        if candidate.is_file():
            return candidate
    return None


def discover_components():
    """Find VF_FINDER.py and VF_TESTER.py."""
    finder_path = find_file("VF_FINDER.py", [ROOT_DIR, ROOT_DIR / "finder"])
    tester_path = find_file("VF_TESTER.py", [ROOT_DIR / "tester", ROOT_DIR])

    return finder_path, tester_path


# ═══════════════════════════════════════════════════════════════════════════════
# PYTHONPATH Setup
# ═══════════════════════════════════════════════════════════════════════════════

def setup_pythonpath():
    """Add all Storm-Vx subdirectories to PYTHONPATH so imports work."""
    subdirs = ["finder", "tester", "evasion", "infra", "ui", "config"]
    paths_to_add = [str(ROOT_DIR)]
    for sub in subdirs:
        sub_path = ROOT_DIR / sub
        if sub_path.is_dir():
            paths_to_add.append(str(sub_path))

    existing = os.environ.get("PYTHONPATH", "")
    new_paths = ";".join(paths_to_add) if platform.system() == "Windows" else ":".join(paths_to_add)
    os.environ["PYTHONPATH"] = f"{new_paths}{os.pathsep}{existing}" if existing else new_paths

    # Also add to sys.path so this process can find modules too
    for p in paths_to_add:
        if p not in sys.path:
            sys.path.insert(0, p)


# ═══════════════════════════════════════════════════════════════════════════════
# Dependency Check
# ═══════════════════════════════════════════════════════════════════════════════

def check_python_version():
    """Ensure Python 3.10+ is available."""
    if sys.version_info < (3, 10):
        print(f"  {C.R}[ERROR] Python 3.10+ required. Current: {sys.version}{C.RS}")
        print(f"  {C.Y}[INFO] Download from https://www.python.org/downloads/{C.RS}")
        sys.exit(1)
    print(f"  {C.G}[OK] Python: {sys.version.split()[0]}{C.RS}")


def check_and_install_deps():
    """Check if required dependencies are installed, install if missing."""
    print(f"  {C.CY}[CHECK] Verifying Python dependencies...{C.RS}")

    missing = []
    try:
        import aiohttp
    except ImportError:
        missing.append("aiohttp")

    try:
        import httpx
    except ImportError:
        missing.append("httpx[http2]")

    try:
        import bs4
    except ImportError:
        missing.append("beautifulsoup4")

    if missing:
        print(f"  {C.R}[ERROR] Missing required packages: {', '.join(missing)}{C.RS}")
        print(f"  {C.Y}[INFO] Install manually:{C.RS}")
        print(f"          pip install {' '.join(missing)}")
        sys.exit(1)
    else:
        print(f"  {C.G}[OK] Dependencies ready{C.RS}")


# ═══════════════════════════════════════════════════════════════════════════════
# Target URL Input
# ═══════════════════════════════════════════════════════════════════════════════

def get_target_url(args) -> str:
    """Get target URL from args or interactive prompt."""
    url = args.url
    if not url:
        print(f"  --------------------------------------------------")
        print(f"   Enter target URL (e.g. https://target.com)")
        print(f"  --------------------------------------------------")
        print()
        try:
            # BUG-046: Support non-interactive mode (piped input, CI/CD)
            if not sys.stdin.isatty():
                url = sys.stdin.readline().strip()
            else:
                url = input(f"   URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {C.R}[ERROR] No URL provided.{C.RS}")
            sys.exit(1)

    if not url:
        print(f"  {C.R}[ERROR] No URL provided.{C.RS}")
        sys.exit(1)

    # Auto-add https://
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 1: VF_FINDER
# ═══════════════════════════════════════════════════════════════════════════════

def run_finder(finder_path: Path, target_url: str, profile_path: Path,
               finder_flags: list[str], extra_flags: list[str]) -> bool:
    """Run VF_FINDER to scan the target and generate a profile.

    Returns:
        True if profile was created successfully, False otherwise.
    """
    print()
    print(f"  {C.BD}==================================================")
    print(f"  [PHASE 1] VF_FINDER - Deep Reconnaissance Scan")
    print(f"  =================================================={C.RS}")
    print(f"  Target : {C.NEON_CYAN}{target_url}{C.RS}")
    print(f"  Mode   : DEEP SCAN + DNS")
    print()

    cmd = [
        sys.executable, str(finder_path),
        target_url,
        *finder_flags,
        *extra_flags,
        "--output", str(profile_path),
    ]

    try:
        result = subprocess.run(cmd, cwd=str(ROOT_DIR))
        finder_exit = result.returncode
    except (OSError, subprocess.SubprocessError) as e:
        print(f"  {C.R}[ERROR] Failed to run FINDER: {e}{C.RS}")
        finder_exit = 1

    if finder_exit != 0:
        print()
        print(f"  {C.Y}[WARN] FINDER exited with code {finder_exit}. Attempting to continue...{C.RS}")
        print()

    if profile_path.is_file():
        print()
        print(f"  {C.G}[OK] Profile saved: VF_PROFILE.json{C.RS}")
        print()
        return True

    # Create minimal profile
    print()
    print(f"  {C.Y}[WARN] FINDER did not create profile. Creating minimal profile...{C.RS}")
    print()
    minimal = {
        "url": target_url,
        "waf": None,
        "cms": None,
        "viewstate_present": False,
        "technologies": [],
        "attack_profile": {
            "recommended_strategy": "GENERIC_FLOOD",
            "attack_vectors": ["LOGIN_FLOOD", "PAGE_FLOOD", "RESOURCE_FLOOD"],
            "worker_config": {
                "initial_workers": 50,
                "max_workers": 10000,
                "step": 100,
                "step_duration": 3
            },
            "page_targets": [],
            "resource_targets": [],
            "waf_strategy": {"detected": False},
            "request_config": {"delay_between_requests_ms": 10},
            "evasion_config": {"rotate_user_agent": True, "cache_bust": True}
        }
    }
    try:
        with open(profile_path, 'w', encoding='utf-8') as f:
            json.dump(minimal, f, ensure_ascii=False, indent=2)
        return True
    except (OSError, IOError) as e:
        print(f"  {C.R}[ERROR] Failed to create minimal profile: {e}{C.RS}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: VF_TESTER
# ═══════════════════════════════════════════════════════════════════════════════

def run_tester(tester_path: Path, profile_path: Path, no_auto_select: bool = False,
               behavior_mode: str = "default") -> int:
    """Run VF_TESTER with the generated profile.

    Returns:
        Exit code from VF_TESTER.
    """
    print(f"  {C.BD}==================================================")
    print(f"  [PHASE 2] VF_TESTER - Adaptive Attack Engine")
    print(f"  =================================================={C.RS}")
    print(f"  Profile : VF_PROFILE.json")
    print(f"  Strategy: Auto (with user confirmation)")
    if behavior_mode != "default":
        print(f"  Behavior: {behavior_mode}")
    print()
    print(f"  {C.Y}[CONTROLS] + = more workers | - = fewer workers | Q = quit{C.RS}")
    print()

    cmd = [
        sys.executable, str(tester_path),
        "--profile", str(profile_path),
    ]

    # Phase 2: Pass auto-select flags to tester
    if no_auto_select:
        cmd.append("--no-auto-select")

    # BUG-022 FIX: Pass behavior mode to tester
    if behavior_mode != "default":
        cmd.extend(["--behavior-mode", behavior_mode])

    try:
        result = subprocess.run(cmd, cwd=str(ROOT_DIR))
        return result.returncode
    except (OSError, subprocess.SubprocessError) as e:
        print(f"  {C.R}[ERROR] Failed to run TESTER: {e}{C.RS}")
        return 1


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Argument Parser
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    """Parse command-line arguments."""
    p = argparse.ArgumentParser(
        description="STORM_VX v3.0 — Full Pipeline: FINDER + TESTER",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                          (interactive — prompts for URL)
  python run.py https://target.com       (auto mode)
  python run.py --no-deep https://t.com  (skip deep scan)
  python run.py --no-dns https://t.com   (skip DNS enumeration)
  python run.py --fresh https://t.com    (force fresh scan, ignore cache)
  python run.py --profile VF_PROFILE.json (skip FINDER, use existing profile)

Keyboard Controls (during attack):
  +   Increase workers (+step)
  -   Decrease workers (-step)
  q   Quit gracefully
""")
    p.add_argument("url", nargs="?", default=None,
                   help="Target URL to scan and attack")
    p.add_argument("--no-deep", action="store_true",
                   help="Skip deep path scanning")
    p.add_argument("--no-dns", action="store_true",
                   help="Skip DNS enumeration")
    p.add_argument("--fresh", action="store_true",
                   help="Force fresh scan (ignore cache)")
    p.add_argument("--profile", default=None,
                   help="Use existing profile (skip FINDER phase)")
    p.add_argument("--no-admin", action="store_true",
                   help="Skip admin privilege check/elevation")
    p.add_argument("--verify-ssl", action="store_true",
                   help="Enable SSL certificate verification (default: disabled for testing)")
    p.add_argument("--auto-select", action="store_true", default=True,
                   help="Enable auto-select plugin effectiveness tracking (default: enabled)")
    p.add_argument("--no-auto-select", action="store_true",
                   help="Disable auto-select plugin effectiveness tracking")
    p.add_argument("--behavior-mode", default="default",
                   choices=["default", "aggressive", "stealth"],
                   help="Behavior mode: default (balanced), aggressive (fast, less stealth), stealth (slow, high mimicry)")
    return p.parse_args()


# ═══════════════════════════════════════════════════════════════════════════════
# Main Pipeline
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    # BUG-048: Moved ensure_utf8_console() into main() to prevent side effects
    # when importing this module for testing.
    ensure_utf8_console()

    args = parse_args()

    # ─── Banner ───
    print_banner()

    # ─── Admin Check ───
    if not args.no_admin:
        if is_admin():
            print(f"  {C.G}[OK] Running as Administrator{C.RS}")
        else:
            print(f"  {C.Y}[INFO] Not running as Administrator{C.RS}")
            if platform.system() == 'Windows':
                print(f"  {C.Y}[INFO] Requesting Administrator privileges...{C.RS}")
                if request_admin_windows():
                    sys.exit(0)  # Elevated process launched; exit this one
                else:
                    print(f"  {C.Y}[INFO] Continuing without admin privileges...{C.RS}")
    else:
        print(f"  {C.DM}[INFO] Admin check skipped (--no-admin){C.RS}")

    print(f"  {C.CY}[MODE] FINDER (Deep Scan) -- TESTER (Auto Attack){C.RS}")
    print()
    print(f"  {C.DM}[DEBUG] ROOT_DIR = \"{ROOT_DIR}\"{C.RS}")

    # ─── Setup PYTHONPATH ───
    setup_pythonpath()

    # ─── Dependency Check ───
    check_python_version()
    check_and_install_deps()
    print()

    # ─── File Discovery ───
    finder_path, tester_path = discover_components()

    # If --profile given, skip FINDER phase
    if args.profile:
        profile_path = Path(args.profile).resolve()
        if not profile_path.is_file():
            print(f"  {C.R}[ERROR] Profile not found: {profile_path}{C.RS}")
            sys.exit(1)
        print(f"  {C.G}[OK] Using existing profile: {profile_path}{C.RS}")
        print()
    else:
        # ─── FINDER Phase ───
        if not finder_path:
            print(f"  {C.R}[ERROR] VF_FINDER.py not found!{C.RS}")
            print(f"  {C.Y}[INFO] Searched in:{C.RS}")
            print(f"          {ROOT_DIR}{os.sep}")
            print(f"          {ROOT_DIR}{os.sep}finder{os.sep}")
            print(f"  {C.Y}[INFO] Make sure you extracted ALL files from the zip{C.RS}")
            sys.exit(1)

        if not tester_path:
            print(f"  {C.R}[ERROR] VF_TESTER.py not found!{C.RS}")
            print(f"  {C.Y}[INFO] Searched in:{C.RS}")
            print(f"          {ROOT_DIR}{os.sep}tester{os.sep}")
            print(f"          {ROOT_DIR}{os.sep}")
            print(f"  {C.Y}[INFO] Make sure you extracted ALL files from the zip{C.RS}")
            sys.exit(1)

        print(f"  {C.G}[OK] FINDER : {finder_path}{C.RS}")
        print(f"  {C.G}[OK] TESTER : {tester_path}{C.RS}")
        print()

        # ─── Get Target URL ───
        target_url = get_target_url(args)
        print(f"  {C.NEON_GREEN}[TARGET] {target_url}{C.RS}")
        print()

        # ─── Build finder flags ───
        finder_flags = []
        if not args.no_deep:
            finder_flags.append("--deep")
        if not args.no_dns:
            finder_flags.append("--dns")
        if args.verify_ssl:
            finder_flags.append("--verify-ssl")

        extra_flags = []
        if args.fresh:
            extra_flags.append("--fresh")

        profile_path = ROOT_DIR / "VF_PROFILE.json"

        # Run FINDER
        finder_ok = run_finder(finder_path, target_url, profile_path,
                               finder_flags, extra_flags)

        print(f"  {C.BD}==================================================")
        print(f"  [DONE] FINDER scan completed.")
        print(f"  =================================================={C.RS}")
        print()

        if not finder_ok or not profile_path.is_file():
            print(f"  {C.R}[ERROR] No profile available. Cannot start TESTER.{C.RS}")
            sys.exit(1)

    # ─── TESTER Phase ───
    if not tester_path:
        # Try again in case we skipped FINDER
        tester_path = find_file("VF_TESTER.py", [ROOT_DIR / "tester", ROOT_DIR])

    if not tester_path:
        print(f"  {C.R}[ERROR] VF_TESTER.py not found!{C.RS}")
        sys.exit(1)

    tester_exit = run_tester(tester_path, profile_path,
                              no_auto_select=args.no_auto_select,
                              behavior_mode=args.behavior_mode)

    if tester_exit != 0:
        print()
        print(f"  {C.Y}[WARN] TESTER exited with code {tester_exit}.{C.RS}")
        print(f"  {C.Y}[HINT] Make sure Python dependencies are installed:{C.RS}")
        print(f"          pip install aiohttp httpx beautifulsoup4")
        print()

    print()
    print(f"  {C.BD}==================================================")
    print(f"  [DONE] STORM_VX Pipeline Completed")
    print(f"  =================================================={C.RS}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {C.Y}[STOPPED] Interrupted by user.{C.RS}")
        sys.exit(130)
