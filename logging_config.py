"""Storm-Vx Logging Configuration.

Provides structured logging with ANSI color support for terminal output.
Replaces scattered print() calls with proper logging.

Also provides ``ensure_utf8_console()`` (migrated from the deprecated
``_bootstrap.py``) to guarantee UTF-8 output on Windows terminals.

W5.1 UPGRADE: Now delegates to observability.logging_ext when the
observability package is available. Falls back to the legacy
AnsiColorFormatter when it isn't. This preserves backward compatibility
while enabling structured JSON logging via environment variables:

  - STORM_VX_LOG_FORMAT=json   → JSON log output
  - STORM_VX_LOG_LEVEL=DEBUG   → Override log level
  - STORM_VX_LOG_FILE=/path    → File logging (always JSON)
"""
from __future__ import annotations

import io
import logging
import os
import sys


class AnsiColorFormatter(logging.Formatter):
    """Logging formatter that adds ANSI color codes to terminal output."""

    # ANSI color codes
    COLORS = {
        logging.DEBUG: '\033[2m',       # Dim
        logging.INFO: '\033[92m',       # Green
        logging.WARNING: '\033[93m',    # Yellow
        logging.ERROR: '\033[91m',      # Red
        logging.CRITICAL: '\033[1m\033[91m',  # Bold Red
    }
    RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.RESET)
        # Add prefix based on level
        prefix = {
            logging.DEBUG: '  ○',
            logging.INFO: '  ✓',
            logging.WARNING: '  ⚠',
            logging.ERROR: '  ✗',
            logging.CRITICAL: '  ‼',
        }.get(record.levelno, '  •')

        message = super().format(record)
        return f"{color}{prefix}{self.RESET} {message}"


def _use_structured_logging() -> bool:
    """Check if structured logging should be activated."""
    return os.environ.get("STORM_VX_LOG_FORMAT", "text").lower() == "json"


def setup_logger(
    name: str = "storm_vx",
    level: int = logging.INFO,
    log_file: str | None = None,
) -> logging.Logger:
    """Configure and return a logger with ANSI color output.

    W5.1: When STORM_VX_LOG_FORMAT=json, delegates to the observability
    subsystem for structured JSON logging. Otherwise, uses the legacy
    ANSI color formatter.

    Args:
        name: Logger name.
        level: Logging level (default: INFO).
        log_file: Optional file path for file logging.

    Returns:
        Configured logger instance.
    """
    # W5.1: Try structured logging first
    if _use_structured_logging():
        try:
            from observability.logging_ext import configure_root_logger
            return configure_root_logger(
                log_format="json",
                level=level,
                log_file=log_file or "",
            )
        except ImportError:
            pass  # Fall through to legacy

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent duplicate handlers — only add if logger has none
    if not logger.handlers:
        # Console handler with ANSI colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_formatter = AnsiColorFormatter('%(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    # Optional file handler (no colors) — always add if log_file specified and not already present
    if log_file:
        # Check if file handler for this path already exists
        has_file_handler = any(
            isinstance(h, logging.FileHandler) and getattr(h, 'baseFilename', '') == log_file
            for h in logger.handlers
        )
        if not has_file_handler:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                datefmt='%H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)

    return logger


# Module-level logger for convenience
logger = setup_logger()


def get_logger(name: str = "storm_vx") -> logging.Logger:
    """Get a named logger for a submodule.

    W5.1: When STORM_VX_LOG_FORMAT=json, returns a structured logger
    from the observability subsystem. Otherwise, returns a standard
    logging.Logger with the same name.

    Args:
        name: Logger name (usually module __name__).

    Returns:
        Logger instance.
    """
    # W5.1: Try structured logging
    if _use_structured_logging():
        try:
            from observability.logging_ext import get_structured_logger
            return get_structured_logger(name)
        except ImportError:
            pass

    return logging.getLogger(name)


class NullByteFilter(io.TextIOBase):
    """Wrapper that strips null bytes before writing to the underlying stream.

    On Windows, ``sys.stdout.write()`` raises
    ``ValueError: embedded null character`` when the string contains
    ``\\x00``.  This wrapper transparently removes null bytes so that
    ``print()`` / ``logging`` never crash regardless of the data flowing
    through them.

    Only the ``write()`` method is overridden; all other attributes are
    delegated to the wrapped stream via ``__getattr__``.
    """

    def __init__(self, stream: io.TextIOBase) -> None:
        self._stream = stream

    def write(self, s: str) -> int:
        """Write *s* with null bytes stripped; return the underlying stream's write count.

        If *s* is not a string (unexpected but possible via broken
        downstream code), convert to ``str()`` first to avoid crashes.
        """
        if not isinstance(s, str):
            s = str(s)
        cleaned = s.replace('\x00', '')
        return self._stream.write(cleaned)

    def flush(self) -> None:
        self._stream.flush()

    def __getattr__(self, name: str):
        """Delegate all other attribute access to the wrapped stream."""
        return getattr(self._stream, name)


def ensure_utf8_console() -> None:
    """Ensure stdout/stderr use UTF-8 on Windows for Unicode box-drawing.

    Also wraps streams with :class:`NullByteFilter` so that null bytes
    (``\\x00``) in output strings never cause
    ``ValueError: embedded null character`` on Windows.

    Migrated from the deprecated ``_bootstrap.py``.  Call this early in
    main entry points (VF_FINDER, VF_TESTER) so that Unicode output
    renders correctly on Windows terminals.
    """
    if sys.platform != "win32":
        return
    for attr in ('stdout', 'stderr'):
        stream = getattr(sys, attr)
        try:
            # Step 1: ensure UTF-8 encoding with 'replace' error handling
            if hasattr(stream, 'reconfigure'):
                stream.reconfigure(encoding='utf-8', errors='replace')
            elif hasattr(stream, 'buffer'):
                replacement = io.TextIOWrapper(
                    stream.buffer, encoding='utf-8', errors='replace'
                )
                stream = replacement

            # Step 2: wrap with NullByteFilter to prevent \x00 crashes
            if not isinstance(stream, NullByteFilter):
                stream = NullByteFilter(stream)

            setattr(sys, attr, stream)
        except (OSError, ValueError, AttributeError):
            pass
