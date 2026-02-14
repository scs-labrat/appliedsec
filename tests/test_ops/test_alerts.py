"""Tests for ops.alerts — Story 11.2."""

from __future__ import annotations

import pytest

from ops.alerts import (
    ALL_ALERT_RULES,
    BATCH_SLA_ALERT,
    COST_HARD_ALERT,
    COST_SOFT_ALERT,
    DETECTION_FAILURE_ALERT,
    KAFKA_LAG_ALERT,
    KAFKA_LAG_CRITICAL_ALERT,
    LLM_CIRCUIT_BREAKER_ALERT,
    STUCK_INVESTIGATION_ALERT,
    AlertRule,
    AlertSeverity,
    render_prometheus_rules,
)


# ── AlertSeverity ─────────────────────────────────────────────────

class TestAlertSeverity:
    def test_values(self):
        assert AlertSeverity.CRITICAL.value == "critical"
        assert AlertSeverity.WARNING.value == "warning"
        assert AlertSeverity.INFO.value == "info"


# ── AlertRule ─────────────────────────────────────────────────────

class TestAlertRule:
    def test_frozen(self):
        with pytest.raises(AttributeError):
            LLM_CIRCUIT_BREAKER_ALERT.alert_name = "changed"

    def test_to_prometheus_rule(self):
        rule = AlertRule(
            alert_name="TestAlert",
            expr="up == 0",
            for_duration="5m",
            severity=AlertSeverity.WARNING,
            summary="Test alert",
            description="A test",
            labels={"team": "soc"},
        )
        rendered = rule.to_prometheus_rule()
        assert rendered["alert"] == "TestAlert"
        assert rendered["expr"] == "up == 0"
        assert rendered["for"] == "5m"
        assert rendered["labels"]["severity"] == "warning"
        assert rendered["labels"]["team"] == "soc"
        assert rendered["annotations"]["summary"] == "Test alert"


# ── Individual alert rules ────────────────────────────────────────

class TestLLMCircuitBreaker:
    def test_name(self):
        assert LLM_CIRCUIT_BREAKER_ALERT.alert_name == "AluskortLLMCircuitBreakerOpen"

    def test_severity(self):
        assert LLM_CIRCUIT_BREAKER_ALERT.severity == AlertSeverity.CRITICAL

    def test_component(self):
        assert LLM_CIRCUIT_BREAKER_ALERT.labels["component"] == "context-gateway"


class TestKafkaLag:
    def test_warning_threshold(self):
        assert "1000" in KAFKA_LAG_ALERT.expr

    def test_warning_severity(self):
        assert KAFKA_LAG_ALERT.severity == AlertSeverity.WARNING

    def test_critical_threshold(self):
        assert "10000" in KAFKA_LAG_CRITICAL_ALERT.expr

    def test_critical_severity(self):
        assert KAFKA_LAG_CRITICAL_ALERT.severity == AlertSeverity.CRITICAL


class TestStuckInvestigation:
    def test_name(self):
        assert STUCK_INVESTIGATION_ALERT.alert_name == "AluskortInvestigationStuck"

    def test_severity(self):
        assert STUCK_INVESTIGATION_ALERT.severity == AlertSeverity.CRITICAL

    def test_3_hour_threshold(self):
        assert "10800" in STUCK_INVESTIGATION_ALERT.expr

    def test_component(self):
        assert STUCK_INVESTIGATION_ALERT.labels["component"] == "orchestrator"


class TestCostAlerts:
    def test_soft_limit(self):
        assert "500" in COST_SOFT_ALERT.expr
        assert COST_SOFT_ALERT.severity == AlertSeverity.WARNING

    def test_hard_cap(self):
        assert "1000" in COST_HARD_ALERT.expr
        assert COST_HARD_ALERT.severity == AlertSeverity.CRITICAL


class TestBatchSLA:
    def test_name(self):
        assert BATCH_SLA_ALERT.alert_name == "AluskortBatchSLABreach"

    def test_severity(self):
        assert BATCH_SLA_ALERT.severity == AlertSeverity.WARNING

    def test_component(self):
        assert BATCH_SLA_ALERT.labels["component"] == "batch-scheduler"


class TestDetectionFailure:
    def test_name(self):
        assert DETECTION_FAILURE_ALERT.alert_name == "AluskortDetectionRuleFailure"

    def test_for_duration(self):
        assert DETECTION_FAILURE_ALERT.for_duration == "15m"


# ── ALL_ALERT_RULES ──────────────────────────────────────────────

class TestAllAlertRules:
    def test_count(self):
        assert len(ALL_ALERT_RULES) == 8

    def test_unique_names(self):
        names = [r.alert_name for r in ALL_ALERT_RULES]
        assert len(names) == len(set(names))

    def test_all_have_expr(self):
        for r in ALL_ALERT_RULES:
            assert r.expr, f"{r.alert_name} missing expr"

    def test_all_have_summary(self):
        for r in ALL_ALERT_RULES:
            assert r.summary, f"{r.alert_name} missing summary"

    def test_all_have_component_label(self):
        for r in ALL_ALERT_RULES:
            assert "component" in r.labels, f"{r.alert_name} missing component"


# ── render_prometheus_rules ───────────────────────────────────────

class TestRenderPrometheus:
    def test_structure(self):
        output = render_prometheus_rules()
        assert "groups" in output
        assert len(output["groups"]) == 1
        assert output["groups"][0]["name"] == "aluskort.rules"

    def test_rule_count(self):
        output = render_prometheus_rules()
        rules = output["groups"][0]["rules"]
        assert len(rules) == 8

    def test_each_rule_has_required_fields(self):
        output = render_prometheus_rules()
        for rule in output["groups"][0]["rules"]:
            assert "alert" in rule
            assert "expr" in rule
            assert "for" in rule
            assert "labels" in rule
            assert "annotations" in rule
            assert "severity" in rule["labels"]
