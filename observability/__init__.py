"""observability — Production observability for Storm-Vx.

Submodules:
  - logging_ext : Structured JSON logging, log enrichment, error codes
  - metrics     : Prometheus-compatible metrics instrumentation
  - health      : Health check and diagnostics endpoints
  - resilience  : Circuit breaker, retry with backoff
  - tracing     : OpenTelemetry distributed tracing (W5.6)
"""
from __future__ import annotations

__all__: list[str] = []
