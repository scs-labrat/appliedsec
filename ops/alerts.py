"""Prometheus alerting rules — Story 11.2.

Defines alerting rules as data structures that can be rendered to
Prometheus alertmanager YAML.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class AlertRule:
    """A Prometheus alerting rule definition."""

    alert_name: str
    expr: str
    for_duration: str
    severity: AlertSeverity
    summary: str
    description: str
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    def to_prometheus_rule(self) -> dict:
        """Render as a Prometheus alerting rule dict."""
        rule: dict = {
            "alert": self.alert_name,
            "expr": self.expr,
            "for": self.for_duration,
            "labels": {
                "severity": self.severity.value,
                **self.labels,
            },
            "annotations": {
                "summary": self.summary,
                "description": self.description,
                **self.annotations,
            },
        }
        return rule


# ── LLM Circuit Breaker ──────────────────────────────────────────

LLM_CIRCUIT_BREAKER_ALERT = AlertRule(
    alert_name="AluskortLLMCircuitBreakerOpen",
    expr='aluskort_llm_circuit_breaker_state{state="open"} == 1',
    for_duration="1m",
    severity=AlertSeverity.CRITICAL,
    summary="LLM circuit breaker is OPEN",
    description=(
        "The Anthropic API circuit breaker has opened. "
        "ALUSKORT is operating in deterministic-only mode. "
        "Verify Anthropic API status and check degradation mode."
    ),
    labels={"component": "context-gateway"},
)

# ── Kafka Consumer Lag ────────────────────────────────────────────

KAFKA_LAG_ALERT = AlertRule(
    alert_name="AluskortKafkaConsumerLagHigh",
    expr="aluskort_kafka_consumer_lag > 1000",
    for_duration="5m",
    severity=AlertSeverity.WARNING,
    summary="Kafka consumer lag exceeds 1000 messages",
    description=(
        "Consumer lag on topic {{ $labels.topic }} partition "
        "{{ $labels.partition }} for group {{ $labels.consumer_group }} "
        "has exceeded 1000 messages for 5 minutes. "
        "Check consumer health and consider scaling."
    ),
    labels={"component": "kafka"},
)

KAFKA_LAG_CRITICAL_ALERT = AlertRule(
    alert_name="AluskortKafkaConsumerLagCritical",
    expr="aluskort_kafka_consumer_lag > 10000",
    for_duration="5m",
    severity=AlertSeverity.CRITICAL,
    summary="Kafka consumer lag exceeds 10000 messages",
    description=(
        "Consumer lag on topic {{ $labels.topic }} has exceeded 10000 "
        "messages. Immediate investigation required — possible stuck consumer."
    ),
    labels={"component": "kafka"},
)

# ── Stuck Investigations ─────────────────────────────────────────

STUCK_INVESTIGATION_ALERT = AlertRule(
    alert_name="AluskortInvestigationStuck",
    expr=(
        'aluskort_investigations_by_state{state="awaiting_human"} > 0 '
        "and time() - aluskort_investigation_awaiting_human_since > 10800"
    ),
    for_duration="5m",
    severity=AlertSeverity.CRITICAL,
    summary="Investigation stuck in AWAITING_HUMAN > 3 hours",
    description=(
        "An investigation has been in AWAITING_HUMAN state for over "
        "3 hours. The SOC lead should review pending approval actions "
        "and either approve or reject."
    ),
    labels={"component": "orchestrator"},
)

# ── Cost Overrun ──────────────────────────────────────────────────

COST_SOFT_ALERT = AlertRule(
    alert_name="AluskortMonthlySpendSoftLimit",
    expr="aluskort_llm_cost_usd_total > 500",
    for_duration="1m",
    severity=AlertSeverity.WARNING,
    summary="Monthly API spend exceeds $500 soft limit",
    description=(
        "Monthly Anthropic API spend has exceeded the $500 soft limit. "
        "Current spend: ${{ $value }}. Review spend breakdown by tier "
        "and task type. Check for escalation storms or batch spikes."
    ),
    labels={"component": "context-gateway"},
)

COST_HARD_ALERT = AlertRule(
    alert_name="AluskortMonthlySpendHardCap",
    expr="aluskort_llm_cost_usd_total > 1000",
    for_duration="1m",
    severity=AlertSeverity.CRITICAL,
    summary="Monthly API spend exceeds $1000 hard cap",
    description=(
        "Monthly Anthropic API spend has exceeded the $1000 hard cap. "
        "New LLM calls will be rejected. Immediate action required."
    ),
    labels={"component": "context-gateway"},
)

# ── Batch SLA ─────────────────────────────────────────────────────

BATCH_SLA_ALERT = AlertRule(
    alert_name="AluskortBatchSLABreach",
    expr="aluskort_batch_sla_breaches_total > 0",
    for_duration="1m",
    severity=AlertSeverity.WARNING,
    summary="Batch job breached 24-hour SLA",
    description=(
        "One or more batch jobs have exceeded the 24-hour SLA. "
        "Check batch job status and Anthropic Batch API health."
    ),
    labels={"component": "batch-scheduler"},
)

# ── Detection Rule Failures ───────────────────────────────────────

DETECTION_FAILURE_ALERT = AlertRule(
    alert_name="AluskortDetectionRuleFailure",
    expr="rate(aluskort_detection_rules_evaluated_total[5m]) == 0",
    for_duration="15m",
    severity=AlertSeverity.WARNING,
    summary="Detection rules stopped evaluating",
    description=(
        "No detection rule evaluations in the last 15 minutes. "
        "The detection runner may have stopped or crashed."
    ),
    labels={"component": "atlas-detection"},
)

# ── Registry ──────────────────────────────────────────────────────

ALL_ALERT_RULES: list[AlertRule] = [
    LLM_CIRCUIT_BREAKER_ALERT,
    KAFKA_LAG_ALERT,
    KAFKA_LAG_CRITICAL_ALERT,
    STUCK_INVESTIGATION_ALERT,
    COST_SOFT_ALERT,
    COST_HARD_ALERT,
    BATCH_SLA_ALERT,
    DETECTION_FAILURE_ALERT,
]


def render_prometheus_rules() -> dict:
    """Render all alert rules as a Prometheus rule group."""
    return {
        "groups": [
            {
                "name": "aluskort.rules",
                "rules": [r.to_prometheus_rule() for r in ALL_ALERT_RULES],
            }
        ]
    }
