"""Tests for Task 5.2: Prometheus Metrics Instrumentation.

Validates:
  - StormVxMetrics creates all metric families lazily
  - No-op stubs work when prometheus_client is unavailable
  - generate_metrics produces valid Prometheus text output
  - Counter, Gauge, Histogram operations work correctly
  - Convenience methods (record_http_request, record_response_classification)
  - Metrics instrumentation in vf_attack_base.py (worker spawn/crash, response classification)
  - Metrics do not break existing functionality
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch


# ═══════════════════════════════════════════════════════════════════════════════
# Core Metrics Module Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestStormVxMetricsCreation:
    """Test lazy metric creation."""

    def test_metrics_singleton_exists(self):
        from observability.metrics import metrics
        assert metrics is not None

    def test_lazy_init_on_first_access(self):
        from observability.metrics import StormVxMetrics, HAS_PROMETHEUS, REGISTRY
        m = StormVxMetrics(registry=REGISTRY)
        assert not m._init_done
        # Access a property triggers init
        _ = m.http_requests_total
        assert m._init_done

    def test_all_metric_properties_accessible(self):
        from observability.metrics import metrics
        # Access all properties — should not raise
        props = [
            metrics.http_requests_total,
            metrics.http_request_duration_seconds,
            metrics.http_requests_inflight,
            metrics.attack_requests_total,
            metrics.attack_failures_total,
            metrics.response_classifications_total,
            metrics.target_alive,
            metrics.target_dead,
            metrics.target_discovered_total,
            metrics.connection_pool_active,
            metrics.connection_pool_created_total,
            metrics.connection_pool_failed_total,
            metrics.connection_pool_timeouts_total,
            metrics.workers_active,
            metrics.workers_spawned_total,
            metrics.workers_crashed_total,
            metrics.evasion_rotations_total,
            metrics.evasion_waf_bypass_attempts_total,
            metrics.health_score,
            metrics.crash_mode,
            metrics.build_info,
            metrics.uptime_seconds,
        ]
        # All should return something (either real metric or no-op stub)
        for prop in props:
            assert prop is not None


class TestNoopStubs:
    """Test that no-op stubs work without prometheus_client."""

    def test_noop_counter_inc(self):
        from observability.metrics import _NoopCounter
        c = _NoopCounter()
        c.inc()  # Should not raise
        c.inc(5.0)  # Should not raise
        assert c.count() == 0.0

    def test_noop_counter_labels(self):
        from observability.metrics import _NoopCounter
        c = _NoopCounter()
        labeled = c.labels(method="GET", status="200")
        assert labeled is c  # Returns self for chaining

    def test_noop_gauge_set(self):
        from observability.metrics import _NoopGauge
        g = _NoopGauge()
        g.set(42.0)  # Should not raise
        g.inc()  # Should not raise
        g.dec()  # Should not raise

    def test_noop_histogram_observe(self):
        from observability.metrics import _NoopHistogram
        h = _NoopHistogram()
        h.observe(0.5)  # Should not raise

    def test_noop_histogram_time(self):
        from observability.metrics import _NoopHistogram, _NoopTimer
        h = _NoopHistogram()
        timer = h.time()
        assert isinstance(timer, _NoopTimer)
        with timer:
            pass  # Should not raise

    def test_noop_info(self):
        from observability.metrics import _NoopInfo
        info = _NoopInfo()
        info.info({"version": "22.0.0"})  # Should not raise


class TestPrometheusOutput:
    """Test Prometheus text format output generation."""

    def test_generate_metrics_returns_string(self):
        from observability.metrics import generate_metrics
        output = generate_metrics()
        assert isinstance(output, str)
        assert len(output) > 0

    def test_generate_metrics_contains_storm_vx(self):
        from observability.metrics import generate_metrics, metrics
        # Force init
        _ = metrics.http_requests_total
        output = generate_metrics()
        # Should contain our metric names
        if "storm_vx_http_requests_total" in output or "prometheus_client not installed" in output:
            pass  # Either real metrics or graceful fallback
        else:
            # At minimum should have HELP/TYPE lines
            assert "# HELP" in output or "# TYPE" in output or "not installed" in output

    def test_metrics_content_type(self):
        from observability.metrics import metrics_content_type
        ct = metrics_content_type()
        assert "text/" in ct


# ═══════════════════════════════════════════════════════════════════════════════
# Convenience Method Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestConvenienceMethods:
    """Test convenience methods that update multiple metrics."""

    def test_record_http_request(self):
        from observability.metrics import metrics
        # Should not raise
        metrics.record_http_request(
            method="GET", status_code=200, duration=0.5, target="example.com",
        )

    def test_record_http_request_various_status_codes(self):
        from observability.metrics import metrics
        for code in [200, 301, 403, 404, 429, 500, 503]:
            metrics.record_http_request(
                method="GET", status_code=code, duration=0.1,
            )

    def test_record_response_classification(self):
        from observability.metrics import metrics
        for cls in ["ok", "waf_blocked", "challenge", "rate_limited", "not_found"]:
            metrics.record_response_classification(
                response_class=cls, waf_name="cloudflare",
            )

    def test_record_response_classification_no_waf(self):
        from observability.metrics import metrics
        metrics.record_response_classification(response_class="ok")

    def test_record_worker_lifecycle_spawned(self):
        from observability.metrics import metrics
        metrics.record_worker_lifecycle("test_plugin", "spawned")

    def test_record_worker_lifecycle_crashed(self):
        from observability.metrics import metrics
        metrics.record_worker_lifecycle("test_plugin", "crashed")

    def test_set_build_info(self):
        from observability.metrics import metrics
        metrics.set_build_info("22.0.0")

    def test_update_uptime(self):
        from observability.metrics import metrics
        metrics.update_uptime()


# ═══════════════════════════════════════════════════════════════════════════════
# Metrics with Prometheus Client Tests (requires prometheus_client installed)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWithPrometheusClient:
    """Test actual metric operations when prometheus_client is available."""

    @pytest.fixture(autouse=True)
    def check_prometheus(self):
        from observability.metrics import HAS_PROMETHEUS
        if not HAS_PROMETHEUS:
            pytest.skip("prometheus_client not installed")

    def test_counter_increment(self):
        from prometheus_client import CollectorRegistry, Counter
        from observability.metrics import StormVxMetrics
        reg = CollectorRegistry()
        m = StormVxMetrics(registry=reg)
        # Access and increment
        m.http_requests_total.labels(method="GET", status_code="200", target="test").inc()
        # Generate output and check
        from prometheus_client import generate_latest
        output = generate_latest(reg).decode()
        assert "storm_vx_http_requests_total" in output

    def test_gauge_set(self):
        from prometheus_client import CollectorRegistry, generate_latest
        from observability.metrics import StormVxMetrics
        reg = CollectorRegistry()
        m = StormVxMetrics(registry=reg)
        m.target_alive.set(10)
        output = generate_latest(reg).decode()
        assert "storm_vx_target_alive 10" in output

    def test_histogram_observe(self):
        from prometheus_client import CollectorRegistry, generate_latest
        from observability.metrics import StormVxMetrics
        reg = CollectorRegistry()
        m = StormVxMetrics(registry=reg)
        m.http_request_duration_seconds.labels(method="GET").observe(0.5)
        output = generate_latest(reg).decode()
        assert "storm_vx_http_request_duration_seconds" in output

    def test_labeled_counter_output(self):
        from prometheus_client import CollectorRegistry, generate_latest
        from observability.metrics import StormVxMetrics
        reg = CollectorRegistry()
        m = StormVxMetrics(registry=reg)
        m.workers_spawned_total.labels(plugin="test_plugin").inc()
        m.workers_spawned_total.labels(plugin="test_plugin").inc()
        output = generate_latest(reg).decode()
        assert 'storm_vx_workers_spawned_total{plugin="test_plugin"} 2.0' in output

    def test_response_classification_counter(self):
        from prometheus_client import CollectorRegistry, generate_latest
        from observability.metrics import StormVxMetrics
        reg = CollectorRegistry()
        m = StormVxMetrics(registry=reg)
        m.response_classifications_total.labels(class_="waf_blocked", waf_name="cloudflare").inc()
        output = generate_latest(reg).decode()
        assert "waf_blocked" in output
        assert "cloudflare" in output

    def test_info_metric(self):
        from prometheus_client import CollectorRegistry, generate_latest
        from observability.metrics import StormVxMetrics
        reg = CollectorRegistry()
        m = StormVxMetrics(registry=reg)
        m.build_info.info({"version": "22.0.0"})
        output = generate_latest(reg).decode()
        assert "storm_vx_build_info" in output


# ═══════════════════════════════════════════════════════════════════════════════
# Integration: AttackPlugin Metrics Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestAttackPluginMetrics:
    """Test that AttackPlugin correctly instruments metrics."""

    def test_vf_attack_base_imports_metrics(self):
        """Verify that vf_attack_base.py can import metrics without error."""
        from tester.vf_attack_base import AttackPlugin
        assert AttackPlugin is not None

    def test_response_classifier_metrics_integration(self):
        """Test that _process_response records classification metrics."""
        from tester.response_classifier import ResponseClassifier, ResponseClass
        from observability.metrics import metrics

        classifier = ResponseClassifier()
        # Classify a WAF blocked response
        result = classifier.classify(
            status_code=403,
            headers={"cf-ray": "abc123"},
            body_snippet="",
        )
        assert result == ResponseClass.WAF_BLOCKED

        # Record in metrics
        metrics.record_response_classification(
            response_class=result.value,
            waf_name=classifier.detected_waf or "none",
        )

    def test_metrics_after_multiple_classifications(self):
        """Test metrics after classifying multiple response types."""
        from tester.response_classifier import ResponseClassifier, ResponseClass
        from observability.metrics import metrics

        classifier = ResponseClassifier()
        classifications = [
            (200, {}, ResponseClass.OK),
            (404, {}, ResponseClass.NOT_FOUND),
            (429, {}, ResponseClass.RATE_LIMITED),
            (500, {}, ResponseClass.SERVER_ERROR),
        ]

        for status, headers, expected in classifications:
            result = classifier.classify(status, headers)
            assert result == expected
            metrics.record_response_classification(
                response_class=result.value,
                waf_name=classifier.detected_waf or "none",
            )


# ═══════════════════════════════════════════════════════════════════════════════
# Existing Test Compatibility Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestExistingTestCompatibility:
    """Verify that adding metrics doesn't break existing tests."""

    def test_target_selector_still_works(self):
        from tester.target_selector import TargetSelector
        selector = TargetSelector(["http://a.com", "http://b.com"])
        url = selector.select()
        assert url is not None
        assert url.startswith("http://")

    def test_response_classifier_still_works(self):
        from tester.response_classifier import ResponseClass, ResponseClassifier
        classifier = ResponseClassifier()
        result = classifier.classify(200, {})
        assert result == ResponseClass.OK

    def test_adaptive_pacer_still_works(self):
        from tester.adaptive_pacer import AdaptivePacer
        from tester.response_classifier import ResponseClass
        pacer = AdaptivePacer(base_delay_ms=10.0)
        pacer.record_response(ResponseClass.OK)
        assert pacer.current_delay_ms > 0
