#!/usr/bin/env python3
"""Microbenchmarks for performance-optimized security subsystem.

Measures throughput and allocation behavior for:
  - should_redact()
  - redact_secrets() / redact_secrets_inplace()
  - redact_string()
  - is_private_ip()

Run: python -m tests.bench_performance_optimizations
"""
from __future__ import annotations

import json
import sys
import time
from typing import Any, Dict

# Ensure project root is on sys.path
sys.path.insert(0, ".")


def _bench(label: str, fn, iterations: int = 100_000) -> Dict[str, Any]:
    """Run a benchmark and return timing results."""
    # Warmup
    for _ in range(1000):
        fn()
    
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - start
    
    per_call_ns = (elapsed / iterations) * 1_000_000_000
    throughput = iterations / elapsed
    
    return {
        "label": label,
        "iterations": iterations,
        "total_s": round(elapsed, 4),
        "per_call_ns": round(per_call_ns, 1),
        "throughput_per_sec": round(throughput, 0),
    }


def bench_should_redact() -> None:
    """Benchmark should_redact() — OPT-2 target."""
    from security.secrets_guard import should_redact
    
    # Common log keys (should be cached after first call)
    common_keys = ["message", "level", "logger", "timestamp", "correlation_id", "component", "target", "worker_id"]
    sensitive_keys = ["password", "api_key", "token", "secret", "cookie", "authorization"]
    
    print("\n" + "=" * 70)
    print("BENCHMARK: should_redact()")
    print("=" * 70)
    
    # Non-sensitive keys (majority of log keys)
    for key in common_keys:
        result = _bench(f"should_redact('{key}') → False", lambda k=key: should_redact(k))
        print(f"  {result['label']:50s}  {result['per_call_ns']:>8.1f} ns/call  {result['throughput_per_sec']:>10.0f} calls/sec")
    
    # Sensitive keys (less common but must be detected)
    for key in sensitive_keys:
        result = _bench(f"should_redact('{key}') → True", lambda k=key: should_redact(k))
        print(f"  {result['label']:50s}  {result['per_call_ns']:>8.1f} ns/call  {result['throughput_per_sec']:>10.0f} calls/sec")


def bench_redact_secrets() -> None:
    """Benchmark redact_secrets() vs redact_secrets_inplace() — OPT-3 target."""
    from security.secrets_guard import redact_secrets, redact_secrets_inplace
    
    # Typical log entry dict
    log_entry = {
        "timestamp": "2025-03-05T14:30:00.123Z",
        "level": "ERROR",
        "logger": "tester.vf_basic_api_flood",
        "message": "Connection refused",
        "correlation_id": "abc123def456",
        "component": "basic_api_flood",
        "target": "example.com",
        "extra": {"status": 503, "retry": True},
    }
    
    # Log entry with a secret
    log_entry_with_secret = {
        **log_entry,
        "api_key": "sk-1234567890abcdef",
    }
    
    print("\n" + "=" * 70)
    print("BENCHMARK: redact_secrets() vs redact_secrets_inplace()")
    print("=" * 70)
    
    for label, data_fn in [
        ("redact_secrets(clean dict)", lambda: dict(log_entry)),
        ("redact_secrets_inplace(clean dict)", lambda: dict(log_entry)),
        ("redact_secrets(secret dict)", lambda: dict(log_entry_with_secret)),
        ("redact_secrets_inplace(secret dict)", lambda: dict(log_entry_with_secret)),
    ]:
        if "inplace" in label:
            result = _bench(label, lambda d=data_fn: redact_secrets_inplace(d), iterations=50_000)
        else:
            result = _bench(label, lambda d=data_fn: redact_secrets(d), iterations=50_000)
        print(f"  {result['label']:50s}  {result['per_call_ns']:>8.1f} ns/call  {result['throughput_per_sec']:>10.0f} calls/sec")


def bench_redact_string() -> None:
    """Benchmark redact_string() — μOPT-1 target."""
    from security.secrets_guard import redact_string
    
    print("\n" + "=" * 70)
    print("BENCHMARK: redact_string()")
    print("=" * 70)
    
    cases = [
        ("clean message", "Request completed in 120ms"),
        ("with bearer", "Authorization: bearer abc123def456ghi789"),
        ("with key=value", "Login with password=supersecret123"),
        ("with URL creds", "Connecting to https://user:pass@example.com"),
        ("AWS key", "Using AWS key AKIAIOSFODNN7EXAMPLE"),
    ]
    
    for label, text in cases:
        result = _bench(f"redact_string({label})", lambda t=text: redact_string(t), iterations=50_000)
        print(f"  {result['label']:50s}  {result['per_call_ns']:>8.1f} ns/call  {result['throughput_per_sec']:>10.0f} calls/sec")


def bench_is_private_ip() -> None:
    """Benchmark is_private_ip() — OPT-6 target."""
    from security.input_validation import is_private_ip
    
    print("\n" + "=" * 70)
    print("BENCHMARK: is_private_ip()")
    print("=" * 70)
    
    cases = [
        ("127.0.0.1 (loopback)", "127.0.0.1"),
        ("10.0.0.1 (RFC1918)", "10.0.0.1"),
        ("192.168.1.1 (RFC1918)", "192.168.1.1"),
        ("8.8.8.8 (public)", "8.8.8.8"),
        ("1.1.1.1 (public)", "1.1.1.1"),
        ("224.0.0.1 (multicast)", "224.0.0.1"),
        ("::1 (IPv6 loopback)", "::1"),
        ("::ffff:127.0.0.1 (mapped)", "::ffff:127.0.0.1"),
    ]
    
    for label, ip in cases:
        result = _bench(f"is_private_ip({label})", lambda i=ip: is_private_ip(i), iterations=50_000)
        print(f"  {result['label']:50s}  {result['per_call_ns']:>8.1f} ns/call  {result['throughput_per_sec']:>10.0f} calls/sec")


def bench_is_redaction_enabled() -> None:
    """Benchmark _is_redaction_enabled() — OPT-1 target."""
    from security.secrets_guard import _is_redaction_enabled
    
    print("\n" + "=" * 70)
    print("BENCHMARK: _is_redaction_enabled() (cached)")
    print("=" * 70)
    
    result = _bench("_is_redaction_enabled() (cached)", _is_redaction_enabled, iterations=1_000_000)
    print(f"  {result['label']:50s}  {result['per_call_ns']:>8.1f} ns/call  {result['throughput_per_sec']:>10.0f} calls/sec")


def main() -> None:
    print("STORM VX Security Subsystem — Performance Microbenchmarks")
    print("=" * 70)
    print(f"Python {sys.version}")
    print()
    
    bench_is_redaction_enabled()
    bench_should_redact()
    bench_redact_secrets()
    bench_redact_string()
    bench_is_private_ip()
    
    print("\n" + "=" * 70)
    print("BENCHMARK COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
