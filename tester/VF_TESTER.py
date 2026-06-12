#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF_TESTER — Adaptive Attack Engine (Plugin Architecture)            ║
║     Part of the VF (Vector-Finder) Architecture                         ║
║                                                                           ║
║  All attack vectors are now implemented as plugins:                      ║
║  - Adding a new attack = creating one .py file in tester/               ║
║  - No changes to VF_TESTER.py needed for new attacks                    ║
║  - Automatic discovery via PluginRegistry                               ║
║  - Dynamic scaling via plugin.scale(delta)                              ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝

Usage:
  # Auto mode: scan + attack (runs FINDER first)
  python VF_TESTER.py https://target.com

  # Profile mode: use existing FINDER profile
  python VF_TESTER.py --profile VF_PROFILE.json

  # Manual overrides
  python VF_TESTER.py --profile VF_PROFILE.json --max-workers 5000 --crash-mode

Keyboard Controls (during run):
  +   Increase workers (+step)
  -   Decrease workers (-step)
  q   Quit gracefully

Requirements:
  pip install aiohttp httpx[http2] aiohttp-socks beautifulsoup4
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import ssl
import platform

from logging_config import ensure_utf8_console, get_logger
logger = get_logger(__name__)

from vf_common import C, T

# ─── Split Module Imports ───
from tester.vf_tester_core import VFTesterCore
from tester.vf_tester_strategy import VFTesterStrategy

IS_WINDOWS = platform.system() == 'Windows'


# ═══════════════════════════════════════════════════════════════════════════════
# VFTester — Backward-compatible facade (inherits core + strategy)
# ═══════════════════════════════════════════════════════════════════════════════

class VFTester(VFTesterStrategy, VFTesterCore):
    """
    VF_TESTER reads a VF_PROFILE.json from VF_FINDER and automatically
    configures an optimized, adaptive attack strategy using the plugin system.

    This class is a facade that combines:
      - VFTesterCore: constructor, properties, stop/start lifecycle, helpers
      - VFTesterStrategy: strategy selection, plugin orchestration, run loop

    All public API is preserved for backward compatibility:
      - VFTester(url), VFTester(profile_path=...)
      - .run(), .stop(), .stats, .max_workers, etc.
    """

    pass  # All methods inherited from VFTesterStrategy + VFTesterCore


__all__ = ['VFTester']


# ═══ Entry Point ═══
def parse_args():
    p = argparse.ArgumentParser(
        description="VF_TESTER — Adaptive Attack Engine (Plugin Architecture)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("url", nargs="?", default=None, help="Target URL")
    p.add_argument("--profile", default=None, help="VF_PROFILE.json path")
    p.add_argument("--max-workers", type=int, default=None)
    p.add_argument("--crash-mode", action="store_true")
    p.add_argument("--verify-ssl", action="store_true", help="Enable SSL certificate verification (default: disabled for testing)")
    p.add_argument("--authorized-only", action="store_true", help="Require domain confirmation before attack starts")
    p.add_argument("--auto-select", action="store_true", default=True, help="Enable auto-select plugin effectiveness tracking (default: enabled)")
    p.add_argument("--no-auto-select", action="store_true", help="Disable auto-select plugin effectiveness tracking")
    p.add_argument("--behavior-mode", default="default",
                   choices=["default", "aggressive", "stealth"],
                   help="Behavior mode: default (balanced), aggressive (fast), stealth (slow, high mimicry)")
    return p.parse_args()


async def main():
    """Legacy entry point — kept for backward compatibility.

    New code should use the __main__ block which includes signal handlers.
    """
    # BUG-048: Moved ensure_utf8_console() into main() to prevent side effects
    # when importing this module for testing.
    ensure_utf8_console()

    args = parse_args()

    if args.profile:
        tester = VFTester(profile_path=args.profile, behavior_mode=args.behavior_mode)
    elif args.url:
        tester = VFTester(target_url=args.url, behavior_mode=args.behavior_mode)
    else:
        logger.error(f"\n  [ERROR] Provide a URL or --profile")
        print(f"  Usage: python VF_TESTER.py https://target.com")
        print(f"         python VF_TESTER.py --profile VF_PROFILE.json\n")
        return

    if args.max_workers:
        tester.max_workers = args.max_workers

    # S1b: Override SSL verification if --verify-ssl flag is set
    if args.verify_ssl:
        tester._verify_ssl = True
        tester._ssl_ctx = ssl.create_default_context()
        tester._session_mgr.ssl_ctx = tester._ssl_ctx  # sync with SessionManager

    # S6: Store authorized-only flag
    tester._authorized_only = args.authorized_only

    # Phase 2: Auto-select effectiveness tracking
    if args.no_auto_select:
        tester.auto_select_enabled = False

    await tester.run()


if __name__ == "__main__":
    from logging_config import setup_logger
    import logging
    setup_logger(level=logging.DEBUG)

    # Global reference for signal handlers
    _current_tester: VFTester | None = None

    # BUG-FIX: Replaced signal.signal() with loop.add_signal_handler().
    # The old approach called sync stop() from a signal handler context,
    # which is unsafe because:
    # 1. task.cancel() from signal context modifies task state outside the event loop
    # 2. The signal handler can interrupt the event loop mid-operation
    # 3. Calling async code (stop_and_wait) from sync signal handlers is impossible
    #
    # The new approach uses loop.add_signal_handler() which schedules a callback
    # on the event loop, ensuring all cleanup happens in the event loop thread.

    def _make_signal_handler(loop: asyncio.AbstractEventLoop):
        """Create a signal handler that safely stops the tester via the event loop."""
        def _handler():
            global _current_tester
            logger.info("Received signal, initiating graceful shutdown...")
            if _current_tester is not None:
                # Schedule the async stop on the event loop (thread-safe)
                loop.call_soon_threadsafe(_current_tester.stop)
        return _handler

    try:
        async def _run():
            global _current_tester
            args = parse_args()

            if args.profile:
                tester = VFTester(profile_path=args.profile, behavior_mode=args.behavior_mode)
            elif args.url:
                tester = VFTester(target_url=args.url, behavior_mode=args.behavior_mode)
            else:
                logger.error(f"\n  [ERROR] Provide a URL or --profile")
                print(f"  Usage: python VF_TESTER.py https://target.com")
                print(f"         python VF_TESTER.py --profile VF_PROFILE.json\n")
                return

            if args.max_workers:
                tester.max_workers = args.max_workers

            # S1b: Override SSL verification if --verify-ssl flag is set
            if args.verify_ssl:
                tester._verify_ssl = True
                tester._ssl_ctx = ssl.create_default_context()
                tester._session_mgr.ssl_ctx = tester._ssl_ctx  # sync with SessionManager

            # S6: Store authorized-only flag
            tester._authorized_only = args.authorized_only

            # Phase 2: Auto-select effectiveness tracking
            if args.no_auto_select:
                tester.auto_select_enabled = False

            _current_tester = tester

            # BUG-FIX: Register signal handlers via loop.add_signal_handler()
            # This is the asyncio-safe way to handle signals — the callback runs
            # on the event loop thread, not in the signal handler context.
            if not IS_WINDOWS:
                loop = asyncio.get_running_loop()
                _handler = _make_signal_handler(loop)
                try:
                    loop.add_signal_handler(signal.SIGINT, _handler)
                    loop.add_signal_handler(signal.SIGTERM, _handler)
                except (OSError, ValueError, RuntimeError):
                    pass  # Can't set signal handler in non-main thread or no loop

            # v27: Attack loop — ask user after each run if they want to continue
            while True:
                await tester.run()

                # Ask user if they want to attack again (with a new target or same)
                print()
                print(f"  {C.BD}{T('accent')}[?]{C.RS} {C.W}Attack again? {C.BD}[r]=same target  [n]=new URL  [q]=quit{C.RS} ", end="", flush=True)
                try:
                    answer = input().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break

                if answer in ("q", "quit", "exit", "خروج"):
                    logger.info(f"\n  [EXIT] Goodbye.\n")
                    break
                elif answer in ("n", "new", "جدید"):
                    print(f"  {C.W}Enter new target URL: {C.RS}", end="", flush=True)
                    try:
                        new_url = input().strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        break
                    if not new_url:
                        logger.info(f"[EXIT] No URL provided. Goodbye.\n")
                        break
                    # Auto-add https://
                    if not new_url.startswith(("http://", "https://")):
                        new_url = "https://" + new_url
                    tester = VFTester(target_url=new_url)
                    if args.max_workers:
                        tester.max_workers = args.max_workers
                    _current_tester = tester
                elif answer in ("r", "repeat", "retry", "دوباره"):
                    # Re-run with same target — state reset now handled in run()
                    pass
                else:
                    logger.info(f"\n  [EXIT] Goodbye.\n")
                    break

        asyncio.run(_run())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except asyncio.CancelledError:
        logger.debug("Tasks cancelled during shutdown")
    except SystemExit:
        raise
    except (RuntimeError, OSError, ValueError, AttributeError, ConnectionError) as exc:
        logger.error(f"Unexpected error: {exc}")
