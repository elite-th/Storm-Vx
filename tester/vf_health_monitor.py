#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vf_health_monitor — Server health monitoring during attacks.

Provides the ServerHealthMonitor class that tracks server health based on
response statistics and determines if the server is under stress.

v28: REDESIGNED for attack tool context.
The old logic treated server 5xx errors as "server dying" which triggered
auto-shrink. For an attack tool, server 5xx = attack is WORKING.
New logic:
  - health_score primarily reflects CLIENT connectivity (can we reach server?)
  - server_dying flag is now much harder to trigger (only extreme conditions)
  - server_struggling flag added (5xx > 30%) — server is under attack load
  - 5xx errors contribute LESS to health penalty (server responding = good)
  - Timeouts contribute MORE (we can't reach server = bad)
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tester.vf_data import Stats


class ServerHealthMonitor:
    """Monitors server health during attack.

    v28: Health score now reflects CLIENT PERSPECTIVE primarily:
    - Can we reach the server? (timeouts, connection errors)
    - Is the server responding? (5xx = responding but struggling = good for attack)
    - Is the server completely down? (no response at all)

    The health score is used by AdaptiveScalingEngine to decide whether
    to escalate or shrink. For an attack tool:
      - LOW health (we can't connect) → shrink workers
      - MEDIUM health (server returning 5xx) → MAINTAIN or INCREASE pressure
      - HIGH health (server responding normally) → escalate normally

    Score ranges from 0.0 (dead) to 1.0 (healthy).
    """

    def __init__(self):
        self.health_score: float = 1.0
        self.server_dying: bool = False
        self.crash_mode_active: bool = False
        self.server_struggling: bool = False  # v28: New — server under load
        self._client_error_rate: float = 0.0
        self._server_5xx_rate: float = 0.0
        self._timeout_rate: float = 0.0
        self._fail_rate: float = 0.0
        self._rate_limit_rate: float = 0.0

    def record(self, result: object) -> None:
        """Record a health result from a plugin.

        Currently health is computed from Stats in check(), so this is
        a no-op. This method exists to prevent AttributeError when plugins
        call context.health().
        """
        pass

    def check(self, stats: Stats) -> float:
        """Check server health based on stats. Returns health score 0-1.

        v28: REDESIGNED for attack tool context.

        The old formula heavily penalized 5xx errors, causing the attack
        to shrink when the server was struggling (which is the GOAL).
        New formula:
          - Timeouts (can't reach server) are PRIMARY penalty driver
          - Fail rate (general) is SECONDARY
          - 5xx errors are TERTIARY — server IS responding, just failing
          - Rate limits are informational

        This means:
          - If server returns lots of 5xx but we CAN connect → health stays
            reasonable (server is under load = attack working)
          - If we CAN'T connect (timeouts) → health drops fast (shrink needed)
        """
        if stats.total < 10:
            return 1.0

        total = max(stats.total, 1)

        # Raw rates
        self._server_5xx_rate = stats.server_errors / total
        self._timeout_rate = stats.timeout_errors / total
        self._client_error_rate = stats.client_errors / total
        self._fail_rate = stats.fail / total
        self._rate_limit_rate = stats.rate_limited / total

        # v29: Fixed double-counting of timeouts in penalty formula.
        # BUG: stats.fail includes timeouts (code=0 with error), so using both
        # timeout_rate and fail_rate in the penalty counted timeouts 1.5x:
        #   timeout_rate * 0.5 + fail_rate * 0.25  → timeouts counted at 0.75x
        #   This caused death spiral: high timeouts → inflated penalty → health
        #   drops → more shrink → less traffic → timeout rate stays high.
        # FIX: Use non-timeout fail rate to avoid double-counting.
        non_timeout_fail = max(stats.fail - stats.timeout_errors, 0)
        non_timeout_fail_rate = non_timeout_fail / total

        # v28→v29: Redesigned penalty formula for attack tool
        # Timeouts = we can't reach the server → STRONGEST signal
        # Non-timeout fail rate = connection refused, DNS errors, etc. → moderate
        # 5xx = server IS responding, just failing → WEAK signal (attack working!)
        # Rate limits = WAF blocking → informational
        penalty = (
            self._timeout_rate * 0.5 +          # Can't reach server — strongest signal
            non_timeout_fail_rate * 0.25 +       # Non-timeout failures — moderate signal
            self._server_5xx_rate * 0.1 +        # Server failing — weak (attack working!)
            self._rate_limit_rate * 0.15          # WAF/CDN blocking — informational
        )

        self.health_score = max(0.0, min(1.0, 1.0 - penalty))

        # v28: server_struggling — server is under load (5xx > 30%)
        # This is DIFFERENT from server_dying — it means the attack is working
        self.server_struggling = (
            self._server_5xx_rate > 0.30 or      # >30% 5xx = server struggling
            self._rate_limit_rate > 0.40          # >40% rate limited = server defending
        )

        # v29: server_dying — ONLY for extreme cases where the server
        # is completely unresponsive (not just returning errors)
        # For an attack tool, 5xx errors are NOT "dying" — they're "struggling"
        # v29: Use non_timeout_fail_rate to avoid double-counting with timeout_rate
        self.server_dying = (
            self._timeout_rate > 0.60 or          # >60% timeouts = server unreachable
            (self._timeout_rate > 0.40 and non_timeout_fail_rate > 0.30)  # Combo: high timeout + non-timeout fails
        )

        # v29: crash_mode — server completely dead
        # v29: Use non_timeout_fail_rate for the combo check
        self.crash_mode_active = (
            self._timeout_rate > 0.80 or          # >80% timeouts = server basically dead
            (self._timeout_rate > 0.50 and non_timeout_fail_rate > 0.40)  # Extreme combo
        )

        return self.health_score


__all__ = ['ServerHealthMonitor']
