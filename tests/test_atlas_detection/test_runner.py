"""Tests for atlas_detection.runner — Stories 9.3 / 9.4."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from atlas_detection.models import DetectionResult, DetectionRule, SAFETY_RELEVANT_RULES
from atlas_detection.runner import DetectionRunner, detection_to_alert, ALERT_TOPIC
from shared.schemas.alert import CanonicalAlert


# ── Helpers ───────────────────────────────────────────────────────

class StubRule(DetectionRule):
    """A controllable test rule."""

    rule_id = "ATLAS-DETECT-STUB"
    frequency = __import__("datetime").timedelta(hours=1)
    lookback = __import__("datetime").timedelta(hours=6)

    def __init__(self, results=None, should_raise=False):
        self._results = results or []
        self._should_raise = should_raise

    async def evaluate(self, db, now=None):
        if self._should_raise:
            raise RuntimeError("boom")
        return self._results


def _result(triggered=True, **overrides) -> DetectionResult:
    defaults = dict(
        rule_id="ATLAS-DETECT-STUB",
        triggered=triggered,
        alert_title="Test alert",
        alert_severity="High",
        atlas_technique="AML.T0020",
        confidence=0.85,
        evidence={"key": "val"},
        timestamp="2025-06-15T12:00:00+00:00",
    )
    defaults.update(overrides)
    return DetectionResult(**defaults)


# ── detection_to_alert ────────────────────────────────────────────

class TestDetectionToAlert:
    def test_basic_conversion(self):
        result = _result()
        alert = detection_to_alert(result)
        assert isinstance(alert, CanonicalAlert)
        assert alert.source == "atlas"
        assert alert.severity == "high"
        assert "AML.T0020" in alert.techniques

    def test_alert_id_format(self):
        result = _result()
        alert = detection_to_alert(result)
        assert alert.alert_id == "ATLAS-DETECT-STUB-2025-06-15T12:00:00+00:00"

    def test_both_techniques(self):
        result = _result(
            atlas_technique="AML.T0020",
            attack_technique="T1565.001",
        )
        alert = detection_to_alert(result)
        assert len(alert.techniques) == 2
        assert "AML.T0020" in alert.techniques
        assert "T1565.001" in alert.techniques

    def test_no_techniques(self):
        result = _result(atlas_technique="", attack_technique="")
        alert = detection_to_alert(result)
        assert alert.techniques == []

    def test_raw_payload_fields(self):
        result = _result(
            confidence=0.9,
            requires_immediate_action=True,
            safety_relevant=True,
        )
        alert = detection_to_alert(result)
        assert alert.raw_payload["confidence"] == 0.9
        assert alert.raw_payload["requires_immediate_action"] is True
        assert alert.raw_payload["safety_relevant"] is True

    def test_severity_lowercase(self):
        result = _result(alert_severity="Critical")
        alert = detection_to_alert(result)
        assert alert.severity == "critical"

    def test_description_prefix(self):
        result = _result(alert_title="Physics DoS")
        alert = detection_to_alert(result)
        assert alert.description == "ATLAS detection: Physics DoS"


# ── DetectionRunner ───────────────────────────────────────────────

class TestDetectionRunner:
    def test_rules_property(self):
        r1, r2 = StubRule(), StubRule()
        runner = DetectionRunner(rules=[r1, r2], db=None)
        assert len(runner.rules) == 2
        assert runner.rules is not runner._rules

    @pytest.mark.asyncio
    async def test_run_rule_triggered(self):
        result = _result(triggered=True)
        rule = StubRule(results=[result])
        producer = AsyncMock()
        runner = DetectionRunner(rules=[rule], db=None, kafka_producer=producer)
        results = await runner.run_rule(rule)
        assert len(results) == 1
        producer.produce.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_run_rule_not_triggered(self):
        result = _result(triggered=False)
        rule = StubRule(results=[result])
        producer = AsyncMock()
        runner = DetectionRunner(rules=[rule], db=None, kafka_producer=producer)
        results = await runner.run_rule(rule)
        assert len(results) == 1
        producer.produce.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_run_rule_exception_returns_empty(self):
        rule = StubRule(should_raise=True)
        runner = DetectionRunner(rules=[rule], db=None)
        results = await runner.run_rule(rule)
        assert results == []

    @pytest.mark.asyncio
    async def test_run_all(self):
        r1 = StubRule(results=[_result(rule_id="R1")])
        r2 = StubRule(results=[_result(rule_id="R2")])
        r1.rule_id = "R1"
        r2.rule_id = "R2"
        runner = DetectionRunner(rules=[r1, r2], db=None)
        all_results = await runner.run_all()
        assert "R1" in all_results
        assert "R2" in all_results

    @pytest.mark.asyncio
    async def test_publish_no_producer(self):
        result = _result(triggered=True)
        rule = StubRule(results=[result])
        runner = DetectionRunner(rules=[rule], db=None, kafka_producer=None)
        results = await runner.run_rule(rule)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_publish_failure_logged(self):
        result = _result(triggered=True)
        rule = StubRule(results=[result])
        producer = AsyncMock()
        producer.produce.side_effect = RuntimeError("kafka down")
        runner = DetectionRunner(rules=[rule], db=None, kafka_producer=producer)
        results = await runner.run_rule(rule)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_safety_relevant_flag_set(self):
        """Runner marks safety_relevant when rule_id in SAFETY_RELEVANT_RULES."""
        result = _result(
            rule_id="ATLAS-DETECT-004",
            triggered=True,
            safety_relevant=False,
        )

        class SafetyStub(StubRule):
            rule_id = "ATLAS-DETECT-004"

        rule = SafetyStub(results=[result])
        producer = AsyncMock()
        runner = DetectionRunner(rules=[rule], db=None, kafka_producer=producer)
        results = await runner.run_rule(rule)
        assert results[0].safety_relevant is True

    @pytest.mark.asyncio
    async def test_publish_topic(self):
        assert ALERT_TOPIC == "alerts.raw"
        result = _result(triggered=True)
        rule = StubRule(results=[result])
        producer = AsyncMock()
        runner = DetectionRunner(rules=[rule], db=None, kafka_producer=producer)
        await runner.run_rule(rule)
        call_args = producer.produce.call_args
        assert call_args[0][0] == "alerts.raw"

    @pytest.mark.asyncio
    async def test_run_all_empty_rules(self):
        runner = DetectionRunner(rules=[], db=None)
        all_results = await runner.run_all()
        assert all_results == {}
