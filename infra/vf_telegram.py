#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     VF Telegram Controller — Remote Control via Telegram                 ║
║     Part of the STORM_VX Infrastructure                                 ║
║                                                                           ║
║  Control STORM_VX from Telegram with real-time status updates,           ║
║  attack control commands, and automatic alerting.                        ║
║                                                                           ║
║  Commands:                                                               ║
║    /start_attack <url>  — Start attack on target                         ║
║    /stop               — Stop current attack                             ║
║    /status             — Get current attack stats                        ║
║    /workers <N>        — Change worker count                             ║
║    /method <name>      — Switch attack method                            ║
║    /bypass <level>     — Change bypass level                             ║
║    /report             — Generate and send report                        ║
║    /help               — Show available commands                         ║
║                                                                           ║
║  Bot token and chat_id can be set via:                                   ║
║    - Environment variables: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID         ║
║    - .env file in project root                                           ║
║    - Constructor arguments                                               ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import os
import asyncio
import json
import time
from typing import Dict, Optional, Callable, Any
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
# Telegram Controller
# ═══════════════════════════════════════════════════════════════════════════════

class TelegramController:
    """
    Telegram Remote Control for STORM_VX.

    Provides a Telegram bot interface to start/stop attacks,
    monitor stats, and receive automatic alerts.
    """

    TELEGRAM_API_BASE = "https://api.telegram.org"
    POLL_TIMEOUT = 30  # long-polling timeout in seconds
    UPDATE_INTERVAL = 30  # seconds between auto-status updates
    RATE_LIMIT_COOLDOWN = 1.0  # seconds between messages (rate limiting)

    def __init__(self, bot_token: str = "", chat_id: str = ""):
        """
        Initialize TelegramController.

        Args:
            bot_token: Telegram bot token. Falls back to env var TELEGRAM_BOT_TOKEN.
            chat_id: Allowed chat ID. Falls back to env var TELEGRAM_CHAT_ID.
        """
        self.bot_token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")

        # Try loading from .env file
        if not self.bot_token or not self.chat_id:
            self._load_env_file()

        self._running = False
        self._last_update_id = 0
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_message_ts: float = 0
        self._update_task: Optional[asyncio.Task] = None

        # Attack control callbacks
        self._start_func: Optional[Callable] = None
        self._stop_func: Optional[Callable] = None
        self._stats_func: Optional[Callable] = None
        self._workers_func: Optional[Callable] = None
        self._method_func: Optional[Callable] = None
        self._bypass_func: Optional[Callable] = None
        self._report_func: Optional[Callable] = None

    # ─── Environment ───────────────────────────────────────────────────────

    def _load_env_file(self):
        """Load bot_token and chat_id from .env file."""
        env_paths = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
            os.path.join(os.getcwd(), ".env"),
        ]
        for env_path in env_paths:
            if os.path.exists(env_path):
                try:
                    with open(env_path, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("#") or "=" not in line:
                                continue
                            key, _, value = line.partition("=")
                            key = key.strip()
                            value = value.strip().strip('"').strip("'")
                            if key == "TELEGRAM_BOT_TOKEN" and not self.bot_token:
                                self.bot_token = value
                            elif key == "TELEGRAM_CHAT_ID" and not self.chat_id:
                                self.chat_id = value
                except Exception:
                    pass

    # ─── Control Registration ──────────────────────────────────────────────

    def set_attack_control(self, start_func: Callable, stop_func: Callable,
                           stats_func: Callable, workers_func: Callable = None,
                           method_func: Callable = None, bypass_func: Callable = None,
                           report_func: Callable = None):
        """
        Register callbacks for attack control.

        Args:
            start_func: async function(url: str) -> str — start attack, returns status message.
            stop_func: async function() -> str — stop attack, returns status message.
            stats_func: async function() -> Dict — get current stats dict.
            workers_func: async function(n: int) -> str — change workers, returns status.
            method_func: async function(name: str) -> str — switch method, returns status.
            bypass_func: async function(level: str) -> str — change bypass level, returns status.
            report_func: async function() -> str — generate report, returns file path.
        """
        self._start_func = start_func
        self._stop_func = stop_func
        self._stats_func = stats_func
        self._workers_func = workers_func
        self._method_func = method_func
        self._bypass_func = bypass_func
        self._report_func = report_func

    # ─── Bot Lifecycle ─────────────────────────────────────────────────────

    async def start(self):
        """Start the Telegram bot polling loop."""
        if not HAS_AIOHTTP:
            print(f"  {C.R}[TELEGRAM] aiohttp is required! pip install aiohttp{C.RS}")
            return

        if not self.bot_token:
            print(f"  {C.R}[TELEGRAM] No bot token configured. Set TELEGRAM_BOT_TOKEN.{C.RS}")
            return

        self._running = True
        timeout = aiohttp.ClientTimeout(total=self.POLL_TIMEOUT + 10)
        self._session = aiohttp.ClientSession(timeout=timeout)

        # Verify bot token
        me = await self._api_request("getMe")
        if not me or not me.get("ok"):
            print(f"  {C.R}[TELEGRAM] Invalid bot token or API error{C.RS}")
            await self.stop()
            return

        bot_name = me.get("result", {}).get("username", "unknown")
        print(f"  {C.G}[TELEGRAM] Bot started: @{bot_name}{C.RS}")
        if self.chat_id:
            print(f"  {C.DM}  Chat ID: {self.chat_id}{C.RS}")

        # Send startup message
        await self.send_status("🟢 STORM_VX Telegram Controller online. Type /help for commands.")

        # Start auto-update task
        self._update_task = asyncio.create_task(self._auto_update_loop())

        # Start polling loop
        try:
            while self._running:
                await self._poll_updates()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"  {C.R}[TELEGRAM] Polling error: {e}{C.RS}")
        finally:
            await self.stop()

    async def stop(self):
        """Stop the Telegram bot."""
        self._running = False

        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass
            self._update_task = None

        if self._session:
            try:
                await self.send_status("🔴 STORM_VX Telegram Controller offline.")
            except Exception:
                pass
            await self._session.close()
            self._session = None

        print(f"  {C.Y}[TELEGRAM] Bot stopped{C.RS}")

    # ─── Polling ───────────────────────────────────────────────────────────

    async def _poll_updates(self):
        """Long-poll for updates from Telegram API."""
        params = {
            "offset": self._last_update_id + 1,
            "timeout": self.POLL_TIMEOUT,
            "allowed_updates": json.dumps(["message"]),
        }

        result = await self._api_request("getUpdates", params)
        if not result or not result.get("ok"):
            await asyncio.sleep(2)
            return

        for update in result.get("result", []):
            self._last_update_id = update.get("update_id", 0)
            message = update.get("message", {})
            await self._handle_message(message)

    async def _handle_message(self, message: Dict):
        """Handle an incoming Telegram message."""
        msg_chat_id = str(message.get("chat", {}).get("id", ""))
        text = message.get("text", "").strip()
        from_user = message.get("from", {}).get("username", "unknown")

        # Security: only respond to authorized chat
        if self.chat_id and msg_chat_id != self.chat_id:
            return

        if not text.startswith("/"):
            return

        # Parse command and arguments
        parts = text.split(maxsplit=1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        print(f"  {C.CY}[TELEGRAM] Command: {command} {args} (from @{from_user}){C.RS}")

        # Dispatch command
        try:
            if command == "/start_attack" or command == "/start":
                await self._cmd_start_attack(args)
            elif command == "/stop":
                await self._cmd_stop()
            elif command == "/status":
                await self._cmd_status()
            elif command == "/workers":
                await self._cmd_workers(args)
            elif command == "/method":
                await self._cmd_method(args)
            elif command == "/bypass":
                await self._cmd_bypass(args)
            elif command == "/report":
                await self._cmd_report()
            elif command == "/help":
                await self._cmd_help()
            else:
                await self.send_status(f"❓ Unknown command: {command}\nType /help for available commands.")
        except Exception as e:
            await self.send_status(f"❌ Error executing {command}: {str(e)[:200]}")

    # ─── Command Handlers ──────────────────────────────────────────────────

    async def _cmd_start_attack(self, url: str):
        """Handle /start_attack command."""
        if not url:
            await self.send_status("❌ Usage: /start_attack <url>")
            return
        if not self._start_func:
            await self.send_status("❌ Attack start function not registered")
            return

        msg = await self._start_func(url)
        await self.send_status(f"🚀 Attack started\n{msg}")

    async def _cmd_stop(self):
        """Handle /stop command."""
        if not self._stop_func:
            await self.send_status("❌ Attack stop function not registered")
            return
        msg = await self._stop_func()
        await self.send_status(f"⏹ Attack stopped\n{msg}")

    async def _cmd_status(self):
        """Handle /status command."""
        if not self._stats_func:
            await self.send_status("❌ Stats function not registered")
            return
        stats = await self._stats_func()
        await self.send_stats(stats)

    async def _cmd_workers(self, args: str):
        """Handle /workers command."""
        if not self._workers_func:
            await self.send_status("❌ Workers function not registered")
            return
        try:
            n = int(args.strip())
        except ValueError:
            await self.send_status("❌ Usage: /workers <number>")
            return
        msg = await self._workers_func(n)
        await self.send_status(f"⚙️ Workers changed\n{msg}")

    async def _cmd_method(self, args: str):
        """Handle /method command."""
        if not self._method_func:
            await self.send_status("❌ Method function not registered")
            return
        method_name = args.strip()
        if not method_name:
            await self.send_status("❌ Usage: /method <name>")
            return
        msg = await self._method_func(method_name)
        await self.send_status(f"🔄 Method changed\n{msg}")

    async def _cmd_bypass(self, args: str):
        """Handle /bypass command."""
        if not self._bypass_func:
            await self.send_status("❌ Bypass function not registered")
            return
        level = args.strip()
        if not level:
            await self.send_status("❌ Usage: /bypass <level>")
            return
        msg = await self._bypass_func(level)
        await self.send_status(f"🛡️ Bypass level changed\n{msg}")

    async def _cmd_report(self):
        """Handle /report command."""
        if not self._report_func:
            await self.send_status("❌ Report function not registered")
            return
        path = await self._report_func()
        if path:
            await self.send_status(f"📊 Report generated: {path}")
        else:
            await self.send_status("❌ Failed to generate report")

    async def _cmd_help(self):
        """Handle /help command."""
        help_text = (
            "📖 *STORM_VX Telegram Commands*\n\n"
            "🚀 `/start_attack <url>` — Start attack\n"
            "⏹ `/stop` — Stop current attack\n"
            "📊 `/status` — Current attack stats\n"
            "⚙️ `/workers <N>` — Change worker count\n"
            "🔄 `/method <name>` — Switch attack method\n"
            "🛡️ `/bypass <level>` — Change bypass level\n"
            "📈 `/report` — Generate report\n"
            "❓ `/help` — This message\n\n"
            "_Auto-updates every 30 seconds_"
        )
        await self._send_message(help_text, parse_mode="Markdown")

    # ─── Auto Updates ──────────────────────────────────────────────────────

    async def _auto_update_loop(self):
        """Send periodic status updates to Telegram."""
        while self._running:
            try:
                await asyncio.sleep(self.UPDATE_INTERVAL)
                if not self._running:
                    break

                if self._stats_func:
                    stats = await self._stats_func()
                    if stats and stats.get("total", 0) > 0:
                        await self.send_stats(stats)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"  {C.R}[TELEGRAM] Auto-update error: {e}{C.RS}")
                await asyncio.sleep(5)

    # ─── Message Sending ───────────────────────────────────────────────────

    async def send_status(self, message: str):
        """
        Send a status message to Telegram.

        Args:
            message: Text to send.
        """
        await self._rate_limit()
        await self._send_message(message)

    async def send_stats(self, stats: Dict):
        """
        Send formatted attack stats to Telegram.

        Args:
            stats: Dictionary with attack statistics.
        """
        total = stats.get("total", 0)
        success_rate = stats.get("success_rate", 0)
        rps = stats.get("rps", stats.get("rrps", 0))
        peak_rps = stats.get("peak_rps", 0)
        workers = stats.get("workers", 0)
        bypass = stats.get("bypass_level", "N/A")
        waf = stats.get("waf", "None")
        target = stats.get("target", "N/A")
        duration = stats.get("duration", 0)

        # Format duration
        if duration < 60:
            dur_str = f"{duration:.0f}s"
        elif duration < 3600:
            dur_str = f"{duration/60:.1f}m"
        else:
            dur_str = f"{duration/3600:.1f}h"

        # Build status emoji
        if success_rate > 0.7:
            status_emoji = "🟢"
        elif success_rate > 0.4:
            status_emoji = "🟡"
        else:
            status_emoji = "🔴"

        msg = (
            f"{status_emoji} *STORM_VX Status*\n\n"
            f"🎯 Target: `{target}`\n"
            f"⏱ Duration: {dur_str}\n"
            f"📊 Requests: {total:,}\n"
            f"✅ Success: {success_rate:.1%}\n"
            f"⚡ RPS: {rps:,.0f} (peak: {peak_rps:,.0f})\n"
            f"👷 Workers: {workers}\n"
            f"🛡 Bypass: {bypass}\n"
            f"🔥 WAF: {waf}"
        )

        await self._send_message(msg, parse_mode="Markdown")

    async def send_alert(self, alert_type: str, message: str):
        """
        Send an alert message (for significant events).

        Args:
            alert_type: Type of alert (waf, crash, error, etc.).
            message: Alert message.
        """
        emoji = {
            "waf": "🛡️⚠️",
            "crash": "💥🔥",
            "error": "❌",
            "server_dying": "💀",
            "success": "✅",
        }.get(alert_type, "⚠️")

        await self._send_message(f"{emoji} *ALERT*: {message}", parse_mode="Markdown")

    # ─── Telegram API ──────────────────────────────────────────────────────

    async def _api_request(self, method: str, params: Dict = None) -> Optional[Dict]:
        """
        Make a request to the Telegram Bot API.

        Args:
            method: API method name.
            params: Request parameters.

        Returns:
            JSON response dictionary, or None on error.
        """
        if not self._session or not self.bot_token:
            return None

        url = f"{self.TELEGRAM_API_BASE}/bot{self.bot_token}/{method}"

        try:
            async with self._session.post(url, json=params) as resp:
                if resp.status == 200:
                    return await resp.json(content_type=None)
                elif resp.status == 429:
                    # Rate limited by Telegram
                    retry_after = resp.headers.get("Retry-After", "2")
                    print(f"  {C.Y}[TELEGRAM] Rate limited, retry after {retry_after}s{C.RS}")
                    await asyncio.sleep(float(retry_after))
                    return None
                else:
                    text = await resp.text()
                    print(f"  {C.R}[TELEGRAM] API error {resp.status}: {text[:200]}{C.RS}")
                    return None
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            print(f"  {C.R}[TELEGRAM] API request error: {e}{C.RS}")
            return None

    async def _send_message(self, text: str, parse_mode: str = None):
        """
        Send a message via Telegram API.

        Args:
            text: Message text.
            parse_mode: Parse mode (e.g., "Markdown", "HTML").
        """
        if not self.chat_id:
            print(f"  {C.Y}[TELEGRAM] No chat_id configured, skipping message{C.RS}")
            return

        # Truncate long messages (Telegram limit is 4096 chars)
        if len(text) > 4000:
            text = text[:3997] + "..."

        params = {
            "chat_id": self.chat_id,
            "text": text,
        }
        if parse_mode:
            params["parse_mode"] = parse_mode

        result = await self._api_request("sendMessage", params)
        if result and result.get("ok"):
            print(f"  {C.G}[TELEGRAM] Message sent{C.RS}")
        else:
            err = result.get("description", "Unknown error") if result else "No response"
            print(f"  {C.R}[TELEGRAM] Send failed: {err}{C.RS}")

    async def _rate_limit(self):
        """Enforce rate limiting between messages."""
        now = time.time()
        elapsed = now - self._last_message_ts
        if elapsed < self.RATE_LIMIT_COOLDOWN:
            await asyncio.sleep(self.RATE_LIMIT_COOLDOWN - elapsed)
        self._last_message_ts = time.time()


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VF Telegram Controller — Remote Control via Telegram")
    parser.add_argument("--bot-token", default="", help="Telegram bot token")
    parser.add_argument("--chat-id", default="", help="Allowed Telegram chat ID")

    args = parser.parse_args()

    if not args.bot_token and not os.environ.get("TELEGRAM_BOT_TOKEN"):
        print(f"  {C.R}[TELEGRAM] Bot token required! Use --bot-token or set TELEGRAM_BOT_TOKEN{C.RS}")
        exit(1)

    controller = TelegramController(bot_token=args.bot_token, chat_id=args.chat_id)

    # Demo callbacks
    async def demo_start(url):
        return f"Started attack on {url} (demo mode)"

    async def demo_stop():
        return "Attack stopped (demo mode)"

    async def demo_stats():
        return {"total": 1000, "success_rate": 0.75, "rps": 500, "peak_rps": 800,
                "workers": 200, "bypass_level": "AGGRESSIVE", "waf": "None",
                "target": "demo.local", "duration": 120}

    controller.set_attack_control(demo_start, demo_stop, demo_stats)

    try:
        asyncio.run(controller.start())
    except KeyboardInterrupt:
        print(f"\n  {C.Y}[TELEGRAM] Interrupted{C.RS}")
