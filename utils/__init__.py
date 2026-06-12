"""utils — Shared utility modules extracted from vf_common.py.

Each sub-module owns a single responsibility domain:
  - ssl_helpers: SSL parameter computation for aiohttp/httpx
  - async_helpers: Bounded concurrency utilities (W1.6)
  - response_helpers: Safe response body reading with size limits (W1.10)
  - session_helpers: Session & connector factories with resource controls (W3.2)
  - random_helpers: Random string, UA, and token generators (W2.1)
  - log_helpers: Live logging utilities (W2.1)
  - terminal_width: Terminal width detection (W2.1)
  - unicode_helpers: Unicode-aware string helpers (W2.1)
  - colors: ANSI color constants and RGB helpers (W2.1)
  - themes: Theme engine with 8 themes and per-instance theming (W2.1)
  - box_drawing: Box-drawing helpers for terminal UI (W2.1)
  - progress: Progress bar and sparkline rendering (W2.1)
  - formatting: Display formatting utilities (W2.1)

Extraction follows the compatibility facade pattern:
  - New modules are the canonical source
  - vf_common.py re-exports for backward compatibility
  - No existing import breaks
"""
