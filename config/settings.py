"""Storm-Vx Settings — Dataclass-based configuration with validation.

Loads settings from environment variables, config file, or defaults.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Any

from config.defaults import (
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_READ_TIMEOUT_SECONDS,
    DEFAULT_INITIAL_WORKERS,
    DEFAULT_MAX_WORKERS,
    DEFAULT_STEP,
    DEFAULT_STEP_DURATION,
    DEFAULT_REQUEST_DELAY_MS,
    DEFAULT_KEEPALIVE_TIMEOUT,
    DEFAULT_DNS_CACHE_TTL,
    DEFAULT_CONNECTION_LIMIT,
    DEFAULT_PER_HOST_LIMIT,
    DEFAULT_POOL_MAX_SIZE,
    DEFAULT_POOL_RECYCLE_INTERVAL,
    DEFAULT_POOL_RECYCLE_MAX_AGE,
    DEFAULT_POOL_DEAD_CLEANUP_INTERVAL,
    VERIFY_SSL,
    OTEL_ENABLED,
    OTEL_ENDPOINT,
    OTEL_SERVICE_NAME,
    OTEL_SAMPLE_RATE,
    OTEL_EXPORT_TIMEOUT_MS,
    SECURITY_STRICT_MODE,
    SSRF_PROTECTION_ENABLED,
    REDACT_SECRETS_ENABLED,
    JSON_MAX_DEPTH,
    JSON_MAX_SIZE,
    URL_MAX_LENGTH,
    PROFILE_MAX_SIZE,
    PLUGIN_MAX_SIZE,
)


@dataclass
class ConnectionSettings:
    """Network and connection configuration.

    W3.2 FIX: All defaults now reference config/defaults.py constants
    instead of hardcoded values. Previously, connect_timeout=5 and
    read_timeout=8 differed from defaults (3 and 10 respectively).
    """
    timeout: int = DEFAULT_TIMEOUT_SECONDS
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT_SECONDS  # W3.2: was hardcoded 5
    read_timeout: int = DEFAULT_READ_TIMEOUT_SECONDS        # W3.2: was hardcoded 8
    keepalive_timeout: int = DEFAULT_KEEPALIVE_TIMEOUT
    dns_cache_ttl: int = DEFAULT_DNS_CACHE_TTL
    connection_limit: int = DEFAULT_CONNECTION_LIMIT
    per_host_limit: int = DEFAULT_PER_HOST_LIMIT            # W3.2: new field
    verify_ssl: bool = VERIFY_SSL  # Phase 0: defaults to False (attack mode)
    follow_redirects: bool = True

    # Phase 0: Connection pool lifecycle
    pool_max_size: int = DEFAULT_POOL_MAX_SIZE
    pool_recycle_interval: int = DEFAULT_POOL_RECYCLE_INTERVAL
    pool_recycle_max_age: int = DEFAULT_POOL_RECYCLE_MAX_AGE
    pool_dead_cleanup_interval: int = DEFAULT_POOL_DEAD_CLEANUP_INTERVAL


@dataclass
class WorkerSettings:
    """Worker scaling configuration."""
    initial_workers: int = DEFAULT_INITIAL_WORKERS
    max_workers: int = DEFAULT_MAX_WORKERS
    step: int = DEFAULT_STEP
    step_duration: int = DEFAULT_STEP_DURATION
    request_delay_ms: int = DEFAULT_REQUEST_DELAY_MS
    cache_bust: bool = True
    ua_rotation: bool = True


@dataclass
class Settings:
    """Main Storm-Vx configuration."""
    connection: ConnectionSettings = field(default_factory=ConnectionSettings)
    workers: WorkerSettings = field(default_factory=WorkerSettings)
    log_level: str = "INFO"
    log_file: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings from environment variables.

        Environment variables:
            STORM_VX_TIMEOUT: Request timeout in seconds
            STORM_VX_MAX_WORKERS: Maximum worker count
            STORM_VX_LOG_LEVEL: Logging level
            STORM_VX_LOG_FILE: Log file path
        """
        settings = cls()

        # A6 FIX: Wrap int() conversions in try/except to prevent
        # unhandled ValueError on invalid environment variable values
        if timeout := os.environ.get("STORM_VX_TIMEOUT"):
            try:
                settings.connection.timeout = int(timeout)
            except ValueError:
                from logging_config import get_logger
                get_logger(__name__).warning(f"Invalid STORM_VX_TIMEOUT={timeout!r}, using default")
        if max_workers := os.environ.get("STORM_VX_MAX_WORKERS"):
            try:
                settings.workers.max_workers = int(max_workers)
            except ValueError:
                from logging_config import get_logger
                get_logger(__name__).warning(f"Invalid STORM_VX_MAX_WORKERS={max_workers!r}, using default")
        if log_level := os.environ.get("STORM_VX_LOG_LEVEL"):
            settings.log_level = log_level.upper()
        if log_file := os.environ.get("STORM_VX_LOG_FILE"):
            settings.log_file = log_file

        # A6 FIX: Validate settings after loading from env
        settings.validate()
        return settings

    def validate(self) -> None:
        """Validate settings and raise ConfigurationError if invalid."""
        from exceptions import ConfigurationError

        if self.workers.max_workers < 1:
            raise ConfigurationError(f"max_workers must be >= 1, got {self.workers.max_workers}")
        if self.workers.initial_workers < 1:
            raise ConfigurationError(f"initial_workers must be >= 1, got {self.workers.initial_workers}")
        if self.workers.step < 1:
            raise ConfigurationError(f"step must be >= 1, got {self.workers.step}")
        if self.connection.timeout < 1:
            raise ConfigurationError(f"timeout must be >= 1, got {self.connection.timeout}")
        # A9-continued: Additional validation
        valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level.upper() not in valid_log_levels:
            raise ConfigurationError(
                f"log_level must be one of {valid_log_levels}, got '{self.log_level}'"
            )
        if self.connection.connect_timeout <= 0:
            raise ConfigurationError(
                f"connect_timeout must be > 0, got {self.connection.connect_timeout}"
            )
        if self.connection.read_timeout <= 0:
            raise ConfigurationError(
                f"read_timeout must be > 0, got {self.connection.read_timeout}"
            )
        if self.workers.step_duration <= 0:
            raise ConfigurationError(
                f"step_duration must be > 0, got {self.workers.step_duration}"
            )
        if self.workers.request_delay_ms < 0:
            raise ConfigurationError(
                f"request_delay_ms must be >= 0, got {self.workers.request_delay_ms}"
            )


@dataclass
class TracingSettings:
    """OpenTelemetry tracing configuration.

    W5.6: All defaults reference config/defaults.py constants.
    Override via environment variables:
        STORM_VX_TRACING_ENABLED : "true" to enable
        STORM_VX_OTEL_ENDPOINT   : OTLP gRPC endpoint
        STORM_VX_SERVICE_NAME    : Service name in traces
    """
    enabled: bool = OTEL_ENABLED
    endpoint: str = OTEL_ENDPOINT
    service_name: str = OTEL_SERVICE_NAME
    sample_rate: float = OTEL_SAMPLE_RATE
    export_timeout_ms: int = OTEL_EXPORT_TIMEOUT_MS

    @classmethod
    def from_env(cls) -> "TracingSettings":
        """Load tracing settings from environment variables."""
        settings = cls()
        if os.environ.get("STORM_VX_TRACING_ENABLED", "").lower() in ("true", "1", "yes"):
            settings.enabled = True
        if endpoint := os.environ.get("STORM_VX_OTEL_ENDPOINT"):
            settings.endpoint = endpoint
        if name := os.environ.get("STORM_VX_SERVICE_NAME"):
            settings.service_name = name
        if rate := os.environ.get("STORM_VX_OTEL_SAMPLE_RATE"):
            try:
                settings.sample_rate = float(rate)
            except ValueError:
                pass
        return settings


@dataclass
class SecuritySettings:
    """Security hardening configuration.

    W5.7: All defaults reference config/defaults.py constants.
    Override via environment variables:
        STORM_VX_SECURITY_STRICT   : "true" to enable strict mode
        STORM_VX_SSRF_PROTECTION   : "false" to disable SSRF protection
        STORM_VX_REDACT_SECRETS    : "false" to disable secret redaction
    """
    strict_mode: bool = SECURITY_STRICT_MODE
    ssrf_protection: bool = SSRF_PROTECTION_ENABLED
    redact_secrets: bool = REDACT_SECRETS_ENABLED
    json_max_depth: int = JSON_MAX_DEPTH
    json_max_size: int = JSON_MAX_SIZE
    url_max_length: int = URL_MAX_LENGTH
    profile_max_size: int = PROFILE_MAX_SIZE
    plugin_max_size: int = PLUGIN_MAX_SIZE

    @classmethod
    def from_env(cls) -> "SecuritySettings":
        """Load security settings from environment variables."""
        settings = cls()
        if os.environ.get("STORM_VX_SECURITY_STRICT", "").lower() in ("true", "1", "yes"):
            settings.strict_mode = True
        if os.environ.get("STORM_VX_SSRF_PROTECTION", "").lower() in ("false", "0", "no"):
            settings.ssrf_protection = False
        if os.environ.get("STORM_VX_REDACT_SECRETS", "").lower() in ("false", "0", "no"):
            settings.redact_secrets = False
        if depth := os.environ.get("STORM_VX_JSON_MAX_DEPTH"):
            try:
                settings.json_max_depth = int(depth)
            except ValueError:
                pass
        if size := os.environ.get("STORM_VX_JSON_MAX_SIZE"):
            try:
                settings.json_max_size = int(size)
            except ValueError:
                pass
        return settings
