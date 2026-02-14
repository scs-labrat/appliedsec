"""Prometheus metric definitions — Story 11.1.

Defines all ALUSKORT service metrics as data structures that can be
registered with prometheus_client at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class MetricType(str, Enum):
    """Prometheus metric types."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


@dataclass(frozen=True)
class MetricDef:
    """A Prometheus metric definition."""

    name: str
    metric_type: MetricType
    description: str
    labels: tuple[str, ...] = ()
    buckets: tuple[float, ...] = ()


# ── Context Gateway metrics ───────────────────────────────────────

CONTEXT_GATEWAY_METRICS: list[MetricDef] = [
    MetricDef(
        name="aluskort_llm_calls_total",
        metric_type=MetricType.COUNTER,
        description="Total LLM API calls",
        labels=("tier", "task_type", "model_id"),
    ),
    MetricDef(
        name="aluskort_llm_call_latency_seconds",
        metric_type=MetricType.HISTOGRAM,
        description="LLM call latency in seconds",
        labels=("tier", "task_type"),
        buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0),
    ),
    MetricDef(
        name="aluskort_llm_cost_usd_total",
        metric_type=MetricType.COUNTER,
        description="Total LLM API cost in USD",
        labels=("tier", "model_id"),
    ),
    MetricDef(
        name="aluskort_llm_confidence",
        metric_type=MetricType.HISTOGRAM,
        description="LLM response confidence scores",
        labels=("tier", "task_type"),
        buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
    ),
    MetricDef(
        name="aluskort_llm_injection_detections_total",
        metric_type=MetricType.COUNTER,
        description="Prompt injection detections",
        labels=("detection_type",),
    ),
]

# ── Entity Parser metrics ─────────────────────────────────────────

ENTITY_PARSER_METRICS: list[MetricDef] = [
    MetricDef(
        name="aluskort_entity_alerts_processed_total",
        metric_type=MetricType.COUNTER,
        description="Total alerts processed by entity parser",
        labels=("source",),
    ),
    MetricDef(
        name="aluskort_entity_parsing_latency_seconds",
        metric_type=MetricType.HISTOGRAM,
        description="Entity parsing latency",
        labels=("source",),
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0),
    ),
    MetricDef(
        name="aluskort_entities_extracted_total",
        metric_type=MetricType.COUNTER,
        description="Total entities extracted",
        labels=("entity_type",),
    ),
]

# ── LLM Router metrics ───────────────────────────────────────────

LLM_ROUTER_METRICS: list[MetricDef] = [
    MetricDef(
        name="aluskort_routing_decisions_total",
        metric_type=MetricType.COUNTER,
        description="Total routing decisions",
        labels=("task_type", "tier"),
    ),
    MetricDef(
        name="aluskort_escalation_total",
        metric_type=MetricType.COUNTER,
        description="Total tier escalations",
        labels=("from_tier", "to_tier"),
    ),
    MetricDef(
        name="aluskort_routing_cost_saved_usd",
        metric_type=MetricType.GAUGE,
        description="Estimated cost saved by tier routing",
        labels=("tier",),
    ),
]

# ── Orchestrator metrics ──────────────────────────────────────────

ORCHESTRATOR_METRICS: list[MetricDef] = [
    MetricDef(
        name="aluskort_investigations_active",
        metric_type=MetricType.GAUGE,
        description="Currently active investigations",
    ),
    MetricDef(
        name="aluskort_investigations_by_state",
        metric_type=MetricType.GAUGE,
        description="Investigation count per state",
        labels=("state",),
    ),
    MetricDef(
        name="aluskort_investigation_duration_seconds",
        metric_type=MetricType.HISTOGRAM,
        description="Investigation total duration",
        labels=("classification",),
        buckets=(10, 30, 60, 120, 300, 600, 1800, 3600, 14400),
    ),
    MetricDef(
        name="aluskort_state_transitions_total",
        metric_type=MetricType.COUNTER,
        description="Investigation state transitions",
        labels=("from_state", "to_state"),
    ),
    MetricDef(
        name="aluskort_fp_shortcircuit_total",
        metric_type=MetricType.COUNTER,
        description="FP short-circuit closures",
        labels=("pattern_id",),
    ),
]

# ── CTEM Normaliser metrics ───────────────────────────────────────

CTEM_NORMALISER_METRICS: list[MetricDef] = [
    MetricDef(
        name="aluskort_ctem_exposures_normalised_total",
        metric_type=MetricType.COUNTER,
        description="Total CTEM exposures normalised",
        labels=("source", "severity"),
    ),
    MetricDef(
        name="aluskort_ctem_normalisation_latency_seconds",
        metric_type=MetricType.HISTOGRAM,
        description="CTEM normalisation latency",
        labels=("source",),
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0),
    ),
]

# ── ATLAS Detection metrics ──────────────────────────────────────

ATLAS_DETECTION_METRICS: list[MetricDef] = [
    MetricDef(
        name="aluskort_detection_rules_evaluated_total",
        metric_type=MetricType.COUNTER,
        description="Total detection rule evaluations",
        labels=("rule_id",),
    ),
    MetricDef(
        name="aluskort_detection_alerts_triggered_total",
        metric_type=MetricType.COUNTER,
        description="Total detection alerts triggered",
        labels=("rule_id", "severity"),
    ),
    MetricDef(
        name="aluskort_detection_evaluation_latency_seconds",
        metric_type=MetricType.HISTOGRAM,
        description="Detection rule evaluation latency",
        labels=("rule_id",),
        buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0),
    ),
]

# ── Batch Scheduler metrics ──────────────────────────────────────

BATCH_SCHEDULER_METRICS: list[MetricDef] = [
    MetricDef(
        name="aluskort_batch_jobs_submitted_total",
        metric_type=MetricType.COUNTER,
        description="Total batch jobs submitted",
    ),
    MetricDef(
        name="aluskort_batch_tasks_queued",
        metric_type=MetricType.GAUGE,
        description="Current tasks in batch queue",
    ),
    MetricDef(
        name="aluskort_batch_sla_breaches_total",
        metric_type=MetricType.COUNTER,
        description="Batch jobs that breached 24h SLA",
    ),
]

# ── Kafka shared metrics ─────────────────────────────────────────

KAFKA_METRICS: list[MetricDef] = [
    MetricDef(
        name="aluskort_kafka_consumer_lag",
        metric_type=MetricType.GAUGE,
        description="Kafka consumer lag per topic/partition",
        labels=("topic", "partition", "consumer_group"),
    ),
    MetricDef(
        name="aluskort_kafka_produce_errors_total",
        metric_type=MetricType.COUNTER,
        description="Kafka produce errors",
        labels=("topic",),
    ),
    MetricDef(
        name="aluskort_kafka_messages_consumed_total",
        metric_type=MetricType.COUNTER,
        description="Total Kafka messages consumed",
        labels=("topic", "consumer_group"),
    ),
]

# ── Sentinel Adapter metrics ─────────────────────────────────────

SENTINEL_ADAPTER_METRICS: list[MetricDef] = [
    MetricDef(
        name="aluskort_sentinel_events_ingested_total",
        metric_type=MetricType.COUNTER,
        description="Total Sentinel events ingested",
        labels=("severity",),
    ),
    MetricDef(
        name="aluskort_sentinel_ingest_latency_seconds",
        metric_type=MetricType.HISTOGRAM,
        description="Sentinel event ingestion latency",
        buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 5.0),
    ),
]

# ── Service → metric map ─────────────────────────────────────────

SERVICE_METRICS: dict[str, list[MetricDef]] = {
    "context-gateway": CONTEXT_GATEWAY_METRICS,
    "entity-parser": ENTITY_PARSER_METRICS,
    "llm-router": LLM_ROUTER_METRICS,
    "orchestrator": ORCHESTRATOR_METRICS,
    "ctem-normaliser": CTEM_NORMALISER_METRICS,
    "atlas-detection": ATLAS_DETECTION_METRICS,
    "batch-scheduler": BATCH_SCHEDULER_METRICS,
    "sentinel-adapter": SENTINEL_ADAPTER_METRICS,
}

ALL_METRICS: list[MetricDef] = (
    CONTEXT_GATEWAY_METRICS
    + ENTITY_PARSER_METRICS
    + LLM_ROUTER_METRICS
    + ORCHESTRATOR_METRICS
    + CTEM_NORMALISER_METRICS
    + ATLAS_DETECTION_METRICS
    + BATCH_SCHEDULER_METRICS
    + KAFKA_METRICS
    + SENTINEL_ADAPTER_METRICS
)

SERVICES = list(SERVICE_METRICS.keys())
