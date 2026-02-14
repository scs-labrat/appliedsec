"""Tests for atlas_detection.models — Story 9.1."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

from atlas_detection.models import (
    DetectionResult,
    DetectionRule,
    SAFETY_CONFIDENCE_FLOORS,
    SAFETY_RELEVANT_RULES,
)


# ── DetectionResult ───────────────────────────────────────────────

class TestDetectionResult:
    def test_defaults(self):
        r = DetectionResult(rule_id="TEST-001", triggered=True)
        assert r.rule_id == "TEST-001"
        assert r.triggered is True
        assert r.alert_title == ""
        assert r.alert_severity == "Medium"
        assert r.confidence == 0.0
        assert r.evidence == {}
        assert r.entities == []
        assert r.requires_immediate_action is False
        assert r.safety_relevant is False

    def test_auto_timestamp(self):
        r = DetectionResult(rule_id="X", triggered=False)
        ts = datetime.fromisoformat(r.timestamp)
        assert ts.tzinfo is not None
        diff = abs((datetime.now(timezone.utc) - ts).total_seconds())
        assert diff < 5

    def test_explicit_timestamp(self):
        ts = "2025-01-15T10:00:00+00:00"
        r = DetectionResult(rule_id="X", triggered=True, timestamp=ts)
        assert r.timestamp == ts

    def test_evidence_dict(self):
        ev = {"user_id": "alice", "count": 42}
        r = DetectionResult(rule_id="X", triggered=True, evidence=ev)
        assert r.evidence["user_id"] == "alice"
        assert r.evidence["count"] == 42

    def test_entities_list(self):
        ent = [{"type": "user", "id": "bob"}]
        r = DetectionResult(rule_id="X", triggered=True, entities=ent)
        assert len(r.entities) == 1
        assert r.entities[0]["id"] == "bob"

    def test_all_fields(self):
        r = DetectionResult(
            rule_id="ATLAS-DETECT-005",
            triggered=True,
            alert_title="Physics DoS",
            alert_severity="Critical",
            atlas_technique="AML.T0029",
            attack_technique="T1499",
            threat_model_ref="TM-14",
            confidence=0.9,
            evidence={"key": "val"},
            entities=[{"type": "host", "id": "edge-1"}],
            requires_immediate_action=True,
            safety_relevant=True,
            timestamp="2025-06-01T00:00:00+00:00",
        )
        assert r.alert_severity == "Critical"
        assert r.requires_immediate_action is True


# ── Safety constants ──────────────────────────────────────────────

class TestSafetyConstants:
    def test_safety_confidence_floors(self):
        assert SAFETY_CONFIDENCE_FLOORS["ATLAS-DETECT-005"] == 0.7
        assert SAFETY_CONFIDENCE_FLOORS["ATLAS-DETECT-009"] == 0.7
        assert len(SAFETY_CONFIDENCE_FLOORS) == 2

    def test_safety_relevant_rules(self):
        assert "ATLAS-DETECT-004" in SAFETY_RELEVANT_RULES
        assert "ATLAS-DETECT-005" in SAFETY_RELEVANT_RULES
        assert "ATLAS-DETECT-009" in SAFETY_RELEVANT_RULES
        assert len(SAFETY_RELEVANT_RULES) == 3

    def test_safety_relevant_immutable(self):
        with pytest.raises(AttributeError):
            SAFETY_RELEVANT_RULES.add("NEW-RULE")


# ── DetectionRule ABC ─────────────────────────────────────────────

class ConcreteRule(DetectionRule):
    rule_id = "TEST-RULE"
    frequency = timedelta(hours=1)
    lookback = timedelta(hours=6)

    async def evaluate(self, db, now=None):
        return []


class SafetyConcreteRule(DetectionRule):
    rule_id = "ATLAS-DETECT-005"
    frequency = timedelta(minutes=5)
    lookback = timedelta(minutes=15)

    async def evaluate(self, db, now=None):
        return []


class TestDetectionRule:
    def test_concrete_rule_properties(self):
        rule = ConcreteRule()
        assert rule.rule_id == "TEST-RULE"
        assert rule.frequency == timedelta(hours=1)
        assert rule.lookback == timedelta(hours=6)

    def test_is_safety_relevant_false(self):
        rule = ConcreteRule()
        assert rule.is_safety_relevant is False

    def test_is_safety_relevant_true(self):
        rule = SafetyConcreteRule()
        assert rule.is_safety_relevant is True

    def test_confidence_floor_no_floor(self):
        rule = ConcreteRule()
        assert rule._apply_confidence_floor(0.3) == 0.3

    def test_confidence_floor_applied(self):
        rule = SafetyConcreteRule()
        assert rule._apply_confidence_floor(0.3) == 0.7

    def test_confidence_floor_above(self):
        rule = SafetyConcreteRule()
        assert rule._apply_confidence_floor(0.9) == 0.9

    @pytest.mark.asyncio
    async def test_evaluate_returns_list(self):
        rule = ConcreteRule()
        results = await rule.evaluate(None)
        assert results == []

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            DetectionRule()
