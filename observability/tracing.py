"""observability.tracing — OpenTelemetry distributed tracing for Storm-Vx.

W5.6 OPENTELEMETRY TRACING:

  Provides distributed tracing across scan and attack pipelines with:
  1. Tracer singleton — lazy init, zero-overhead when OTel not installed
  2. No-op span stubs — all operations are safe no-ops when disabled
  3. Pipeline instrumentation — scan phases, attack runs, HTTP requests
  4. Context bridging — links OTel trace_id/span_id to log correlation_id
  5. aiohttp TraceConfig — auto-instruments all HTTP requests

DESIGN PRINCIPLES:
  - Zero-breakage: existing code works identically when OTel is not installed
  - Opt-in tracing: set STORM_VX_TRACING_ENABLED=true to activate
  - Low overhead: no-op stubs have near-zero cost when disabled
  - No coupling: tracer is independent of metrics/health/resilience
  - Context propagation: trace_id bridges to correlation_id in structured logs

ENVIRONMENT VARIABLES:
  - STORM_VX_TRACING_ENABLED : "true" to enable (default: disabled)
  - STORM_VX_OTEL_ENDPOINT   : OTLP gRPC endpoint (default: localhost:4317)
  - STORM_VX_SERVICE_NAME    : Service name for OTel resource (default: storm-vx)

USAGE:
  from observability.tracing import tracer, span, traced

  # Get a tracer (no-op when disabled)
  t = tracer("storm_vx.scan")

  # Manual span creation
  with t.start_as_current_span("http_fingerprint") as s:
      s.set_attribute("url", target_url)

  # Decorator shortcut
  @traced("storm_vx.scan.phase")
  async def scan_phase(url):
      ...

  # Context manager shortcut
  async with span("storm_vx.attack.request", url=target, method="GET"):
      resp = await session.get(url)
"""
from __future__ import annotations

import asyncio
import functools
import os
import time
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from typing import Any, Callable, Optional, TypeVar, Awaitable

from logging_config import get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# OTel Import Guard — Graceful fallback when not installed
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.sdk.trace import TracerProvider as _TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor as _BatchSpanProcessor
    from opentelemetry.sdk.resources import Resource as _Resource
    from opentelemetry.sdk.trace.sampling import ParentBasedTraceIdRatio as _ParentBasedTraceIdRatio
    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False

# Optional OTLP exporter (may not be installed even if OTel SDK is)
try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as _OTLPSpanExporter
    HAS_OTLP_EXPORTER = True
except ImportError:
    HAS_OTLP_EXPORTER = False


# ═══════════════════════════════════════════════════════════════════════════════
# Tracing Context Variables — Bridge to logging correlation_id
# ═══════════════════════════════════════════════════════════════════════════════

otel_trace_id: ContextVar[str] = ContextVar("otel_trace_id", default="")
otel_span_id: ContextVar[str] = ContextVar("otel_span_id", default="")


def _format_trace_id(tid: int) -> str:
    """Format an OTel trace ID as a 32-char hex string."""
    return format(tid, "032x")


def _format_span_id(sid: int) -> str:
    """Format an OTel span ID as a 16-char hex string."""
    return format(sid, "016x")


# ═══════════════════════════════════════════════════════════════════════════════
# No-op Span — Zero-overhead stub when OTel is not installed/disabled
# ═══════════════════════════════════════════════════════════════════════════════

class NoopSpan:
    """No-op span when OpenTelemetry is not installed or tracing is disabled.

    All operations are safe no-ops with near-zero overhead.
    Supports the same interface as opentelemetry.trace.Span.
    """

    def __enter__(self) -> "NoopSpan":
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    async def __aenter__(self) -> "NoopSpan":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass

    def set_attribute(self, key: str, value: Any) -> "NoopSpan":
        return self

    def set_attributes(self, attributes: dict[str, Any]) -> "NoopSpan":
        return self

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> "NoopSpan":
        return self

    def record_exception(self, exception: BaseException,
                         attributes: dict[str, Any] | None = None) -> "NoopSpan":
        return self

    def update_name(self, name: str) -> "NoopSpan":
        return self

    def is_recording(self) -> bool:
        return False

    def end(self, end_time: int | None = None) -> None:
        pass

    @property
    def context(self) -> None:
        return None

    def get_span_context(self) -> None:
        return None


class NoopTracer:
    """No-op tracer when OpenTelemetry is not installed or tracing is disabled.

    Returns NoopSpan instances that are safe to use as context managers.
    """

    def start_span(self, name: str, **kwargs: Any) -> NoopSpan:
        return NoopSpan()

    def start_as_current_span(self, name: str, **kwargs: Any) -> NoopSpan:
        return NoopSpan()


# Singleton no-op instances (avoid repeated allocation)
_NOOP_SPAN = NoopSpan()
_NOOP_TRACER = NoopTracer()


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration — Reads from environment / config defaults
# ═══════════════════════════════════════════════════════════════════════════════

_TRACING_ENABLED_ENV = "STORM_VX_TRACING_ENABLED"
_OTEL_ENDPOINT_ENV = "STORM_VX_OTEL_ENDPOINT"
_SERVICE_NAME_ENV = "STORM_VX_SERVICE_NAME"


def _is_tracing_enabled() -> bool:
    """Check if tracing is enabled via environment variable."""
    return os.environ.get(_TRACING_ENABLED_ENV, "").lower() in ("true", "1", "yes")


def _get_otel_endpoint() -> str:
    """Get the OTLP gRPC endpoint from environment."""
    return os.environ.get(_OTEL_ENDPOINT_ENV, "localhost:4317")


def _get_service_name() -> str:
    """Get the service name from environment."""
    return os.environ.get(_SERVICE_NAME_ENV, "storm-vx")


# ═══════════════════════════════════════════════════════════════════════════════
# Tracer Provider Initialization — Lazy, once-only
# ═══════════════════════════════════════════════════════════════════════════════

_provider_initialized: bool = False
_tracer_provider: Any = None


def init_tracing(
    *,
    endpoint: str = "",
    service_name: str = "",
    sample_rate: float = 1.0,
    force: bool = False,
) -> bool:
    """Initialize the OpenTelemetry tracer provider.

    This should be called once at application startup. Subsequent calls
    are no-ops unless force=True.

    Args:
        endpoint: OTLP gRPC endpoint (e.g., "localhost:4317").
            Auto-detected from STORM_VX_OTEL_ENDPOINT if empty.
        service_name: Service name for OTel resource.
            Auto-detected from STORM_VX_SERVICE_NAME if empty.
        sample_rate: Trace sampling rate (0.0 to 1.0, default: 1.0 = all).
        force: Force re-initialization even if already initialized.

    Returns:
        True if tracing was successfully initialized, False otherwise.
    """
    global _provider_initialized, _tracer_provider

    if _provider_initialized and not force:
        return _tracer_provider is not None

    _provider_initialized = True

    if not HAS_OTEL:
        logger.debug("OpenTelemetry SDK not installed — tracing disabled")
        return False

    if not _is_tracing_enabled():
        logger.debug("Tracing disabled (STORM_VX_TRACING_ENABLED not set)")
        return False

    try:
        ep = endpoint or _get_otel_endpoint()
        svc = service_name or _get_service_name()

        # Create resource with service name
        resource = _Resource.create({"service.name": svc})

        # Create TracerProvider with sampling
        sampler = _ParentBasedTraceIdRatio(rate=sample_rate) if sample_rate < 1.0 else None
        provider_kwargs: dict[str, Any] = {"resource": resource}
        if sampler is not None:
            provider_kwargs["sampler"] = sampler

        provider = _TracerProvider(**provider_kwargs)

        # Add OTLP exporter if available
        if HAS_OTLP_EXPORTER:
            exporter = _OTLPSpanExporter(endpoint=ep, insecure=True)
            processor = _BatchSpanProcessor(exporter)
            provider.add_span_processor(processor)
            logger.info(f"OTel tracing initialized — endpoint={ep}, service={svc}, sample_rate={sample_rate}")
        else:
            # Default to ConsoleSpanExporter for development
            try:
                from opentelemetry.sdk.trace.export import ConsoleSpanExporter
                processor = _BatchSpanProcessor(ConsoleSpanExporter())
                provider.add_span_processor(processor)
                logger.info(f"OTel tracing initialized (console) — service={svc}")
            except ImportError:
                logger.warning("No OTel exporter available — spans will be dropped")

        _otel_trace.set_tracer_provider(provider)
        _tracer_provider = provider
        return True

    except Exception as exc:
        logger.warning(f"Failed to initialize OTel tracing: {exc}")
        _tracer_provider = None
        return False


def shutdown_tracing() -> None:
    """Gracefully shutdown the tracer provider.

    Flushes any pending spans to the exporter before shutdown.
    Should be called at application exit.
    """
    global _provider_initialized, _tracer_provider

    if _tracer_provider is not None:
        try:
            _tracer_provider.shutdown()
            logger.debug("OTel tracer provider shut down")
        except Exception as exc:
            logger.debug(f"Error shutting down OTel tracer: {exc}")

    _provider_initialized = False
    _tracer_provider = None


# ═══════════════════════════════════════════════════════════════════════════════
# Tracer Factory — Returns real or no-op tracer
# ═══════════════════════════════════════════════════════════════════════════════

def tracer(name: str = "storm-vx") -> Any:
    """Get a named tracer instance.

    Returns a real OTel tracer if tracing is enabled and initialized,
    otherwise returns a NoopTracer that is safe to use as context managers.

    Args:
        name: Tracer name (usually module __name__ or component name).

    Returns:
        OTel Tracer or NoopTracer instance.
    """
    if not HAS_OTEL or not _is_tracing_enabled():
        return _NOOP_TRACER

    if not _provider_initialized:
        init_tracing()

    if _tracer_provider is not None:
        try:
            return _otel_trace.get_tracer(name)
        except Exception:
            return _NOOP_TRACER

    return _NOOP_TRACER


# ═══════════════════════════════════════════════════════════════════════════════
# Span Helpers — Context managers and decorators for easy instrumentation
# ═══════════════════════════════════════════════════════════════════════════════

@contextmanager
def span(name: str, **attributes: Any):
    """Synchronous context manager for creating a span.

    Usage:
        with span("storm_vx.scan.http_fingerprint", url=target) as s:
            s.set_attribute("status_code", 200)

    Args:
        name: Span name (e.g., "storm_vx.scan.phase").
        **attributes: Key-value pairs to set as span attributes.
    """
    t = tracer()
    with t.start_as_current_span(name) as s:
        # Set attributes if span is recording
        if s.is_recording():
            for key, value in attributes.items():
                s.set_attribute(key, value)
            # Bridge trace_id to context vars for log enrichment
            ctx = s.get_span_context()
            if ctx is not None:
                otel_trace_id.set(_format_trace_id(ctx.trace_id))
                otel_span_id.set(_format_span_id(ctx.span_id))
                # Also set correlation_id in logging context
                try:
                    from observability.logging_ext import correlation_id
                    correlation_id.set(_format_trace_id(ctx.trace_id)[:12])
                except ImportError:
                    pass
        yield s


@asynccontextmanager
async def async_span(name: str, **attributes: Any):
    """Async context manager for creating a span.

    Usage:
        async with async_span("storm_vx.attack.request", url=url) as s:
            resp = await session.get(url)

    Args:
        name: Span name.
        **attributes: Key-value pairs to set as span attributes.
    """
    t = tracer()
    with t.start_as_current_span(name) as s:
        if s.is_recording():
            for key, value in attributes.items():
                s.set_attribute(key, value)
            ctx = s.get_span_context()
            if ctx is not None:
                otel_trace_id.set(_format_trace_id(ctx.trace_id))
                otel_span_id.set(_format_span_id(ctx.span_id))
                try:
                    from observability.logging_ext import correlation_id
                    correlation_id.set(_format_trace_id(ctx.trace_id)[:12])
                except ImportError:
                    pass
        yield s


T = TypeVar("T")


def traced(name: str, **static_attributes: Any) -> Callable:
    """Decorator that wraps a function in a span.

    Works with both sync and async functions.

    Usage:
        @traced("storm_vx.scan.phase", component="finder")
        async def scan_phase(url: str):
            ...

    Args:
        name: Span name.
        **static_attributes: Static attributes set on every span.
    """

    def decorator(func: Callable) -> Callable:

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            t = tracer()
            with t.start_as_current_span(name) as s:
                if s.is_recording():
                    for key, value in static_attributes.items():
                        s.set_attribute(key, value)
                    s.set_attribute("function", func.__name__)
                    ctx = s.get_span_context()
                    if ctx is not None:
                        otel_trace_id.set(_format_trace_id(ctx.trace_id))
                        otel_span_id.set(_format_span_id(ctx.span_id))
                try:
                    result = await func(*args, **kwargs)
                    if s.is_recording():
                        s.set_attribute("success", True)
                    return result
                except Exception as exc:
                    if s.is_recording():
                        s.set_attribute("success", False)
                        s.record_exception(exc)
                    raise

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            t = tracer()
            with t.start_as_current_span(name) as s:
                if s.is_recording():
                    for key, value in static_attributes.items():
                        s.set_attribute(key, value)
                    s.set_attribute("function", func.__name__)
                try:
                    result = func(*args, **kwargs)
                    if s.is_recording():
                        s.set_attribute("success", True)
                    return result
                except Exception as exc:
                    if s.is_recording():
                        s.set_attribute("success", False)
                        s.record_exception(exc)
                    raise

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline-Specific Tracers — Named tracers for each subsystem
# ═══════════════════════════════════════════════════════════════════════════════

def scan_tracer() -> Any:
    """Get a tracer for the scan pipeline (VF_FINDER)."""
    return tracer("storm-vx.scan")


def attack_tracer() -> Any:
    """Get a tracer for the attack pipeline (VF_TESTER)."""
    return tracer("storm-vx.attack")


def network_tracer() -> Any:
    """Get a tracer for network/HTTP operations."""
    return tracer("storm-vx.network")


def plugin_tracer(plugin_name: str = "") -> Any:
    """Get a tracer for a specific plugin.

    Args:
        plugin_name: Plugin name (e.g., "page_flood").
            If empty, returns the generic plugin tracer.
    """
    name = f"storm-vx.plugin.{plugin_name}" if plugin_name else "storm-vx.plugin"
    return tracer(name)


# ═══════════════════════════════════════════════════════════════════════════════
# aiohttp TraceConfig Integration — Auto-instrument HTTP requests
# ═══════════════════════════════════════════════════════════════════════════════

def create_otel_trace_config() -> Any:
    """Create an aiohttp TraceConfig that creates spans for HTTP requests.

    This auto-instruments all HTTP requests made through sessions that
    include this trace config. Each request gets its own span with
    method, URL, and status code attributes.

    Returns None if tracing is disabled (no TraceConfig needed).

    Usage:
        from observability.tracing import create_otel_trace_config

        trace_config = create_otel_trace_config()
        trace_configs = [tc for tc in [existing_config, trace_config] if tc is not None]

        session = aiohttp.ClientSession(trace_configs=trace_configs)
    """
    if not HAS_OTEL or not _is_tracing_enabled():
        return None

    try:
        import aiohttp

        t = network_tracer()

        async def _on_request_start(session: Any, ctx: Any, params: Any):
            span_ctx = t.start_as_current_span(
                f"HTTP {params.method}",
                attributes={
                    "http.method": params.method,
                    "http.url": str(params.url),
                    "component": "aiohttp",
                },
            )
            span_ctx.__enter__()
            # Store span on trace request context for later access
            ctx._otel_span = span_ctx

        async def _on_request_end(session: Any, ctx: Any, params: Any):
            span_obj = getattr(ctx, '_otel_span', None)
            if span_obj is not None:
                if hasattr(span_obj, 'is_recording') and span_obj.is_recording():
                    span_obj.set_attribute("http.status_code", params.response.status)
                span_obj.__exit__(None, None, None)

        async def _on_request_exception(session: Any, ctx: Any, params: Any):
            span_obj = getattr(ctx, '_otel_span', None)
            if span_obj is not None:
                if hasattr(span_obj, 'is_recording') and span_obj.is_recording():
                    span_obj.set_attribute("http.error", str(params.exception))
                    span_obj.record_exception(params.exception)
                span_obj.__exit__(None, None, None)

        trace_config = aiohttp.TraceConfig()
        trace_config.on_request_start.append(_on_request_start)
        trace_config.on_request_end.append(_on_request_end)
        trace_config.on_request_exception.append(_on_request_exception)

        return trace_config

    except ImportError:
        return None
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Tracing Status — Query current state
# ═══════════════════════════════════════════════════════════════════════════════

def is_tracing_active() -> bool:
    """Check if tracing is currently active (enabled and initialized)."""
    return HAS_OTEL and _is_tracing_enabled() and _tracer_provider is not None


def get_tracing_status() -> dict[str, Any]:
    """Get current tracing status for health checks and diagnostics.

    Returns:
        Dict with tracing configuration and status info.
    """
    return {
        "enabled": _is_tracing_enabled(),
        "active": is_tracing_active(),
        "otel_installed": HAS_OTEL,
        "otlp_exporter_installed": HAS_OTLP_EXPORTER,
        "endpoint": _get_otel_endpoint(),
        "service_name": _get_service_name(),
        "provider_initialized": _provider_initialized,
    }


def get_current_trace_info() -> dict[str, str]:
    """Get current trace context info (trace_id, span_id).

    Useful for adding to log entries or HTTP headers for
    distributed trace correlation.

    Returns:
        Dict with trace_id and span_id (empty strings if no active span).
    """
    trace_id = otel_trace_id.get("")
    span_id = otel_span_id.get("")

    # If OTel is active, try to get from current span
    if HAS_OTEL and _is_tracing_enabled():
        try:
            current_span = _otel_trace.get_current_span()
            ctx = current_span.get_span_context()
            if ctx is not None and ctx.trace_id != 0:
                trace_id = _format_trace_id(ctx.trace_id)
                span_id = _format_span_id(ctx.span_id)
        except Exception:
            pass

    return {
        "trace_id": trace_id,
        "span_id": span_id,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Module Exports
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = [
    # Core
    "tracer",
    "span",
    "async_span",
    "traced",
    "init_tracing",
    "shutdown_tracing",
    # No-op stubs
    "NoopSpan",
    "NoopTracer",
    "HAS_OTEL",
    "HAS_OTLP_EXPORTER",
    # Pipeline tracers
    "scan_tracer",
    "attack_tracer",
    "network_tracer",
    "plugin_tracer",
    # aiohttp integration
    "create_otel_trace_config",
    # Context variables
    "otel_trace_id",
    "otel_span_id",
    # Status
    "is_tracing_active",
    "get_tracing_status",
    "get_current_trace_info",
]
