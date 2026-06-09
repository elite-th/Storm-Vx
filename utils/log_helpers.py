#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""log_helpers — Live logging utilities extracted from vf_common.py.

W2.1 EXTRACTION: Canonical source for live_log, live_ok, live_warn, live_eta.
These functions have ZERO dependencies on C (Colors), T (themes), or any other
vf_common domain — only on logging_config.get_logger.

Backward compatibility: vf_common.py re-exports these symbols so existing
`from vf_common import live_log` continues to work.
"""
from __future__ import annotations

from logging_config import get_logger

logger = get_logger(__name__)


def live_log(msg: str):
    """Log a general log message."""
    logger.info(msg)


def live_ok(msg: str):
    """Log a success message."""
    logger.info(msg)


def live_warn(msg: str):
    """Log a warning message."""
    logger.warning(msg)


def live_eta(elapsed: float, progress: float, label: str = ""):
    """Log an ETA estimate based on elapsed time and progress."""
    if progress <= 0:
        return
    remaining = (elapsed / progress) * (1.0 - progress)
    label_str = f" {label}" if label else ""
    logger.debug(f"[ETA{label_str}] {elapsed:.1f}s elapsed, ~{remaining:.0f}s remaining")
