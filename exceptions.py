"""Storm-Vx Custom Exceptions.

Central location for all project-specific exception classes.
"""
from __future__ import annotations


class ConfigurationError(Exception):
    """Raised when configuration validation fails."""
    pass


class ValidationError(ValueError):
    """Raised when input validation fails."""
    pass


class ProfileError(Exception):
    """Raised when profile loading or parsing fails."""
    pass


class PluginError(Exception):
    """Raised when plugin loading or execution fails."""
    pass


class NetworkError(Exception):
    """Raised when network operations fail after retries."""
    pass


class OperationTimeoutError(Exception):
    """Raised when a network or operation timeout occurs.

    Distinct from the built-in TimeoutError (which is OSError-derived)
    to avoid confusion with asyncio.TimeoutError. This is a
    project-specific timeout for attack operations and adaptive
    timeout tracking. Renamed from TimeoutError to avoid shadowing
    the Python built-in.
    """
    pass


class SessionError(Exception):
    """Raised when session management fails.

    Covers aiohttp session creation failures, connection pool
    exhaustion, and session lifecycle errors.
    """
    pass


class TargetUnreachableError(NetworkError):
    """Raised when the target server is completely unreachable.

    This indicates a fundamental connectivity issue (DNS failure,
    connection refused, no route to host) rather than a transient
    network error. All origin IPs failing validation also raises this.
    """
    pass
