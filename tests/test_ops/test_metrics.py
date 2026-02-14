"""Tests for ops.metrics — Story 11.1."""

from __future__ import annotations

import pytest

from ops.metrics import (
    ALL_METRICS,
    ATLAS_DETECTION_METRICS,
    BATCH_SCHEDULER_METRICS,
    CONTEXT_GATEWAY_METRICS,
    CTEM_NORMALISER_METRICS,
    ENTITY_PARSER_METRICS,
    KAFKA_METRICS,
    LLM_ROUTER_METRICS,
    ORCHESTRATOR_METRICS,
    SENTINEL_ADAPTER_METRICS,
    SERVICE_METRICS,
    SERVICES,
    MetricDef,
    MetricType,
)


# ── MetricDef ─────────────────────────────────────────────────────

class TestMetricDef:
    def test_counter(self):
        m = MetricDef(
            name="test_total",
            metric_type=MetricType.COUNTER,
            description="A test counter",
        )
        assert m.name == "test_total"
        assert m.metric_type == MetricType.COUNTER
        assert m.labels == ()
        assert m.buckets == ()

    def test_histogram_with_buckets(self):
        m = MetricDef(
            name="test_histogram",
            metric_type=MetricType.HISTOGRAM,
            description="A test histogram",
            labels=("tier",),
            buckets=(0.1, 0.5, 1.0),
        )
        assert m.buckets == (0.1, 0.5, 1.0)
        assert m.labels == ("tier",)

    def test_gauge_with_labels(self):
        m = MetricDef(
            name="test_gauge",
            metric_type=MetricType.GAUGE,
            description="A test gauge",
            labels=("state",),
        )
        assert m.metric_type == MetricType.GAUGE

    def test_frozen(self):
        m = MetricDef(name="x", metric_type=MetricType.COUNTER, description="x")
        with pytest.raises(AttributeError):
            m.name = "changed"


# ── MetricType ────────────────────────────────────────────────────

class TestMetricType:
    def test_values(self):
        assert MetricType.COUNTER.value == "counter"
        assert MetricType.GAUGE.value == "gauge"
        assert MetricType.HISTOGRAM.value == "histogram"

    def test_count(self):
        assert len(MetricType) == 3


# ── Service metric groups ─────────────────────────────────────────

class TestServiceMetrics:
    def test_context_gateway_metrics(self):
        assert len(CONTEXT_GATEWAY_METRICS) == 5
        names = {m.name for m in CONTEXT_GATEWAY_METRICS}
        assert "aluskort_llm_calls_total" in names
        assert "aluskort_llm_call_latency_seconds" in names
        assert "aluskort_llm_cost_usd_total" in names

    def test_entity_parser_metrics(self):
        assert len(ENTITY_PARSER_METRICS) == 3
        names = {m.name for m in ENTITY_PARSER_METRICS}
        assert "aluskort_entity_alerts_processed_total" in names

    def test_llm_router_metrics(self):
        assert len(LLM_ROUTER_METRICS) == 3
        names = {m.name for m in LLM_ROUTER_METRICS}
        assert "aluskort_routing_decisions_total" in names
        assert "aluskort_escalation_total" in names

    def test_orchestrator_metrics(self):
        assert len(ORCHESTRATOR_METRICS) == 5
        names = {m.name for m in ORCHESTRATOR_METRICS}
        assert "aluskort_investigations_active" in names
        assert "aluskort_investigations_by_state" in names
        assert "aluskort_investigation_duration_seconds" in names

    def test_ctem_normaliser_metrics(self):
        assert len(CTEM_NORMALISER_METRICS) == 2

    def test_atlas_detection_metrics(self):
        assert len(ATLAS_DETECTION_METRICS) == 3
        names = {m.name for m in ATLAS_DETECTION_METRICS}
        assert "aluskort_detection_alerts_triggered_total" in names

    def test_batch_scheduler_metrics(self):
        assert len(BATCH_SCHEDULER_METRICS) == 3
        names = {m.name for m in BATCH_SCHEDULER_METRICS}
        assert "aluskort_batch_sla_breaches_total" in names

    def test_kafka_metrics(self):
        assert len(KAFKA_METRICS) == 3
        names = {m.name for m in KAFKA_METRICS}
        assert "aluskort_kafka_consumer_lag" in names
        assert "aluskort_kafka_produce_errors_total" in names

    def test_sentinel_adapter_metrics(self):
        assert len(SENTINEL_ADAPTER_METRICS) == 2


# ── SERVICE_METRICS map ──────────────────────────────────────────

class TestServiceMetricsMap:
    def test_all_services_present(self):
        expected = {
            "context-gateway", "entity-parser", "llm-router",
            "orchestrator", "ctem-normaliser", "atlas-detection",
            "batch-scheduler", "sentinel-adapter",
        }
        assert set(SERVICE_METRICS.keys()) == expected

    def test_services_list(self):
        assert len(SERVICES) == 8


# ── ALL_METRICS ───────────────────────────────────────────────────

class TestAllMetrics:
    def test_total_count(self):
        expected = (5 + 3 + 3 + 5 + 2 + 3 + 3 + 3 + 2)
        assert len(ALL_METRICS) == expected

    def test_all_have_aluskort_prefix(self):
        for m in ALL_METRICS:
            assert m.name.startswith("aluskort_"), f"{m.name} missing prefix"

    def test_unique_names(self):
        names = [m.name for m in ALL_METRICS]
        assert len(names) == len(set(names)), "Duplicate metric names found"

    def test_all_have_descriptions(self):
        for m in ALL_METRICS:
            assert m.description, f"{m.name} missing description"

    def test_histograms_have_buckets(self):
        for m in ALL_METRICS:
            if m.metric_type == MetricType.HISTOGRAM:
                assert m.buckets, f"{m.name} is histogram but has no buckets"
