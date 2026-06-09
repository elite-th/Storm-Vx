"""Storm-Vx bootstrap — DEPRECATED.

.. deprecated:: 22.0
   This module is deprecated. The project now uses proper package installation
   via ``pip install -e .`` (configured in pyproject.toml) to make all modules
   importable without manual sys.path manipulation.

   The ``ensure_paths()`` function is no longer called anywhere in the codebase.
   It is retained here only for backward compatibility in case any external
   scripts still reference it.

   The ``_ensure_utf8_console()`` function has been moved to ``logging_config.py``
   as ``ensure_utf8_console()`` and is called from the main entry points.
   The local copy now delegates to the canonical version.
"""
import sys
import os
import io
import warnings

from logging_config import ensure_utf8_console as _canonical_ensure_utf8_console


def _ensure_utf8_console():
    """Ensure stdout/stderr use UTF-8 on Windows for Unicode box-drawing.

    .. deprecated:: 22.0
       Use :func:`logging_config.ensure_utf8_console` instead.
       This wrapper delegates to the canonical implementation.
    """
    warnings.warn(
        "_ensure_utf8_console() is deprecated — use "
        "logging_config.ensure_utf8_console() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    _canonical_ensure_utf8_console()


# Apply UTF-8 console fix on import (Windows) — delegates to logging_config
_ensure_utf8_console()


def ensure_paths(file_path: str | None = None) -> str:
    """Ensure all Storm-Vx directories are in sys.path.

    .. deprecated:: 22.0
       Use ``pip install -e .`` instead. This function is a no-op that
       emits a DeprecationWarning.

    Args:
        file_path: Ignored. Retained for API compatibility.

    Returns:
        The project root directory path (best-effort).
    """
    warnings.warn(
        "ensure_paths() is deprecated — use 'pip install -e .' for proper "
        "package installation. See pyproject.toml for configuration.",
        DeprecationWarning,
        stacklevel=2,
    )
    # Best-effort root detection for backward compatibility
    if file_path:
        caller_dir = os.path.dirname(os.path.abspath(file_path))
        parent = os.path.normpath(os.path.join(caller_dir, '..'))
        subdirs = {'tester', 'finder', 'evasion', 'infra'}
        return parent if os.path.basename(caller_dir) in subdirs else caller_dir
    return os.path.dirname(os.path.abspath(__file__))
