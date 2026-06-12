"""config — Centralized configuration for Storm-Vx.

W2.4 ACTIVATION: All configuration constants are defined in config.defaults
and re-exported here for convenient access:

    from config import DEFAULT_TIMEOUT_SECONDS, VERIFY_SSL

Settings dataclasses for structured access are in config.settings.
"""
from config.defaults import *  # noqa: F401,F403 — re-export all constants
from config.settings import ConnectionSettings, WorkerSettings, Settings  # noqa: F401
