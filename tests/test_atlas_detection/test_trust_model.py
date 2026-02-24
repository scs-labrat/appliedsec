"""Tests for ATLAS telemetry trust model — Story 14.7.

Tests trust fields, downgrade logic, rule-level trust, and orchestrator
trust constraints.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from atlas_detection.models import (
    TRUST_DOWNGRADE_FACTOR,
    UNTRUSTED_TELEMETRY_SOURCES,
    DetectionResult,
    DetectionRule,
)
from atlas_detection.rules import (
    ALL_RULES,
    EdgeCompromiseRule,
    SensorSpoofingRule,
)
from shared.schemas.investigation import DecisionEntry, GraphState, InvestigationState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _ConcreteRule(DetectionRule):
    """Concrete rule for testing base class methods."""

    rule_id = "TEST-TRUST"
    frequency = timedelta(hours=1)
    lookback = timedelta(hours=6)

    async def evaluate(self, db, now=None):
        return []


def _db(*fetch_many_returns, fetch_one_return=None):
    """Build a mock DB with sequential fetch_many return values."""
    mock = AsyncMock()
    mock.fetch_many = AsyncMock(side_effect=list(fetch_many_returns))
    mock.fetch_one = AsyncMock(return_value=fetch_one_return)
    return mock


# ---------------------------------------------------------------------------
# TestTrustModelFields (Task 1 — AC: 1, 4)
# ---------------------------------------------------------------------------

class TestTrustModelFields:
    """AC-1: Trust model fields and constants."""

    def test_default_trust_is_trusted(self):
        """DetectionResult defaults to trusted telemetry."""
        r = DetectionResult(rule_id="TEST", triggered=True)
        assert r.telemetry_trust_level == "trusted"
        assert r.attestation_status == ""

    def test_untrusted_sources_defined(self):
        """UNTRUSTED_TELEMETRY_SOURCES contains expected sources."""
        assert "edge_node_telemetry" in UNTRUSTED_TELEMETRY_SOURCES
        assert "opcua_telemetry" in UNTRUSTED_TELEMETRY_SOURCES
        assert len(UNTRUSTED_TELEMETRY_SOURCES) == 2

    def test_downgrade_factor(self):
        """TRUST_DOWNGRADE_FACTOR is 0.7."""
        assert TRUST_DOWNGRADE_FACTOR == 0.7


# ---------------------------------------------------------------------------
# TestTrustDowngrade (Task 2 — AC: 2)
# ---------------------------------------------------------------------------

class TestTrustDowngrade:
    """AC-2: Trust downgrade on DetectionRule base class."""

    def test_untrusted_source_downgrades_confidence(self):
        """Untrusted telemetry source multiplies confidence by 0.7."""
        rule = _ConcreteRule()
        conf, trust = rule._apply_trust_downgrade(0.85, "opcua_telemetry")
        assert conf == pytest.approx(0.85 * 0.7)
        assert trust == "untrusted"

    def test_trusted_source_unchanged(self):
        """Non-untrusted source returns confidence unchanged."""
        rule = _ConcreteRule()
        conf, trust = rule._apply_trust_downgrade(0.85, "databricks_audit")
        assert conf == 0.85
        assert trust == "trusted"

    def test_edge_node_telemetry_untrusted(self):
        """edge_node_telemetry is classified as untrusted."""
        rule = _ConcreteRule()
        conf, trust = rule._apply_trust_downgrade(0.90, "edge_node_telemetry")
        assert trust == "untrusted"
        assert conf == pytest.approx(0.90 * 0.7)

    def test_floor_then_downgrade(self):
        """Floor applies first, then downgrade reduces below floor.

        For ATLAS-DETECT-009 (floor=0.7), confidence 0.85:
        floor(0.85) = 0.85, downgrade = 0.85 * 0.7 = 0.595
        The downgrade IS allowed to go below the floor — this is
        by design for untrusted telemetry.
        """
        from atlas_detection.models import SAFETY_CONFIDENCE_FLOORS

        class SafetyRule(DetectionRule):
            rule_id = "ATLAS-DETECT-009"
            frequency = timedelta(minutes=5)
            lookback = timedelta(minutes=15)

            async def evaluate(self, db, now=None):
                return []

        rule = SafetyRule()
        floored = rule._apply_confidence_floor(0.85)
        assert floored == 0.85
        downgraded, trust = rule._apply_trust_downgrade(floored, "opcua_telemetry")
        assert downgraded == pytest.approx(0.85 * 0.7)
        assert trust == "untrusted"


# ---------------------------------------------------------------------------
# TestTM06TrustLevel (Task 3 — AC: 1, 2)
# ---------------------------------------------------------------------------

class TestTM06TrustLevel:
    """AC-1,2: SensorSpoofingRule (TM-06) applies trust downgrade."""

    @pytest.mark.asyncio
    async def test_sensor_spoofing_has_untrusted_trust(self):
        """SensorSpoofingRule results have untrusted trust level."""
        db = _db(
            [{"edge_node_id": "edge-1", "sensor_count": 10,
              "data_points_received": 500, "protocol_violations": 0,
              "connection_state": "open"}],
            [{"edge_node_id": "edge-1", "avg_points": 100,
              "stddev_points": 20, "avg_sensors": 10}],
        )
        rule = SensorSpoofingRule()
        results = await rule.evaluate(db)
        assert len(results) == 1
        assert results[0].telemetry_trust_level == "untrusted"
        assert results[0].attestation_status == "unavailable"

    @pytest.mark.asyncio
    async def test_sensor_spoofing_confidence_downgraded(self):
        """SensorSpoofingRule confidence is multiplied by 0.7."""
        db = _db(
            [{"edge_node_id": "edge-1", "sensor_count": 10,
              "data_points_received": 500, "protocol_violations": 0,
              "connection_state": "open"}],
            [{"edge_node_id": "edge-1", "avg_points": 100,
              "stddev_points": 20, "avg_sensors": 10}],
        )
        rule = SensorSpoofingRule()
        results = await rule.evaluate(db)
        # Floor(0.85) = 0.85 (floor is 0.7), then downgrade: 0.85 * 0.7 = 0.595
        assert results[0].confidence == pytest.approx(0.85 * 0.7)


# ---------------------------------------------------------------------------
# TestTM04TrustLevel (Task 3 — AC: 1, 2)
# ---------------------------------------------------------------------------

class TestTM04TrustLevel:
    """AC-1,2: EdgeCompromiseRule (TM-04) applies trust downgrade."""

    @pytest.mark.asyncio
    async def test_edge_compromise_untrusted_trust(self):
        """EdgeCompromiseRule results have untrusted trust level."""
        db = _db(
            [{"edge_node_id": "node-1", "boot_attestation": "fail",
              "model_weight_hash": "abc", "disk_integrity": "ok",
              "cpu_utilisation": 0.5, "memory_utilisation": 0.4}],
        )
        rule = EdgeCompromiseRule()
        results = await rule.evaluate(db)
        assert len(results) == 1
        assert results[0].telemetry_trust_level == "untrusted"
        assert results[0].attestation_status == "fail"
        assert results[0].threat_model_ref == "TM-04"

    @pytest.mark.asyncio
    async def test_edge_compromise_confidence_downgraded(self):
        """EdgeCompromiseRule confidence is multiplied by 0.7."""
        db = _db(
            [{"edge_node_id": "node-1", "boot_attestation": "fail",
              "model_weight_hash": "abc", "disk_integrity": "ok",
              "cpu_utilisation": 0.3, "memory_utilisation": 0.3}],
        )
        rule = EdgeCompromiseRule()
        results = await rule.evaluate(db)
        # attestation_failed -> raw 0.85, floor(0.85) = 0.85, downgrade: 0.85 * 0.7
        assert results[0].confidence == pytest.approx(0.85 * 0.7)

    @pytest.mark.asyncio
    async def test_edge_compromise_missing_attestation(self):
        """Missing boot_attestation treated as unavailable."""
        db = _db(
            [{"edge_node_id": "node-2", "boot_attestation": "",
              "model_weight_hash": "abc", "disk_integrity": "ok",
              "cpu_utilisation": 0.3, "memory_utilisation": 0.3}],
        )
        rule = EdgeCompromiseRule()
        results = await rule.evaluate(db)
        assert len(results) == 1
        assert results[0].attestation_status == "unavailable"

    @pytest.mark.asyncio
    async def test_edge_compromise_disk_fail(self):
        """Disk integrity failure triggers detection."""
        db = _db(
            [{"edge_node_id": "node-3", "boot_attestation": "pass",
              "model_weight_hash": "abc", "disk_integrity": "fail",
              "cpu_utilisation": 0.3, "memory_utilisation": 0.3}],
        )
        rule = EdgeCompromiseRule()
        results = await rule.evaluate(db)
        assert len(results) == 1
        assert results[0].attestation_status == "pass"

    @pytest.mark.asyncio
    async def test_edge_compromise_high_cpu(self):
        """High CPU triggers detection."""
        db = _db(
            [{"edge_node_id": "node-4", "boot_attestation": "pass",
              "model_weight_hash": "abc", "disk_integrity": "ok",
              "cpu_utilisation": 0.98, "memory_utilisation": 0.3}],
        )
        rule = EdgeCompromiseRule()
        results = await rule.evaluate(db)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_edge_compromise_no_trigger_normal(self):
        """Normal telemetry does not trigger detection."""
        db = _db(
            [{"edge_node_id": "node-5", "boot_attestation": "pass",
              "model_weight_hash": "abc", "disk_integrity": "ok",
              "cpu_utilisation": 0.3, "memory_utilisation": 0.3}],
        )
        rule = EdgeCompromiseRule()
        results = await rule.evaluate(db)
        assert len(results) == 0

    def test_registry_includes_edge_compromise(self):
        """ALL_RULES includes EdgeCompromiseRule."""
        assert EdgeCompromiseRule in ALL_RULES
        assert len(ALL_RULES) == 11


# ---------------------------------------------------------------------------
# TestTrustAwareOrchestrator (Task 4 — AC: 3)
# ---------------------------------------------------------------------------

class TestTrustAwareOrchestrator:
    """AC-3: Untrusted-only detections force human review."""

    def test_untrusted_only_forces_human_review(self):
        """All untrusted ATLAS detections force AWAITING_HUMAN."""
        from orchestrator.graph import InvestigationGraph

        graph = self._make_graph()
        state = GraphState(
            investigation_id="inv-1",
            alert_id="a-1",
            tenant_id="t-001",
            atlas_techniques=[
                {"telemetry_trust_level": "untrusted", "attestation_status": "fail"},
                {"telemetry_trust_level": "untrusted", "attestation_status": "unavailable"},
            ],
            state=InvestigationState.REASONING,
        )

        result = graph._apply_trust_constraint(state)
        assert result.state == InvestigationState.AWAITING_HUMAN
        assert result.requires_human_approval is True
        # Check decision chain entry
        trust_entries = [
            d for d in result.decision_chain
            if (d.step if isinstance(d, DecisionEntry) else d.get("step", "")) == "trust_constraint"
        ]
        assert len(trust_entries) == 1

    def test_mixed_trust_allows_normal_processing(self):
        """Mixed trusted/untrusted does not force human review."""
        graph = self._make_graph()
        state = GraphState(
            investigation_id="inv-2",
            alert_id="a-2",
            tenant_id="t-001",
            atlas_techniques=[
                {"telemetry_trust_level": "untrusted", "attestation_status": "fail"},
                {"telemetry_trust_level": "trusted", "attestation_status": "pass"},
            ],
            state=InvestigationState.REASONING,
        )

        result = graph._apply_trust_constraint(state)
        assert result.state == InvestigationState.REASONING  # Unchanged

    def test_all_trusted_allows_normal_processing(self):
        """All trusted detections allow normal processing."""
        graph = self._make_graph()
        state = GraphState(
            investigation_id="inv-3",
            alert_id="a-3",
            tenant_id="t-001",
            atlas_techniques=[
                {"telemetry_trust_level": "trusted"},
            ],
            state=InvestigationState.REASONING,
        )

        result = graph._apply_trust_constraint(state)
        assert result.state == InvestigationState.REASONING

    def test_no_atlas_techniques_unchanged(self):
        """No ATLAS detections: state unchanged."""
        graph = self._make_graph()
        state = GraphState(
            investigation_id="inv-4",
            alert_id="a-4",
            tenant_id="t-001",
            atlas_techniques=[],
            state=InvestigationState.REASONING,
        )

        result = graph._apply_trust_constraint(state)
        assert result.state == InvestigationState.REASONING

    def test_attestation_status_recorded_in_decision_chain(self):
        """Attestation status is recorded in decision chain for mixed trust."""
        graph = self._make_graph()
        state = GraphState(
            investigation_id="inv-5",
            alert_id="a-5",
            tenant_id="t-001",
            atlas_techniques=[
                {"telemetry_trust_level": "trusted", "attestation_status": "pass"},
                {"telemetry_trust_level": "untrusted", "attestation_status": "fail"},
            ],
            state=InvestigationState.REASONING,
        )

        result = graph._apply_trust_constraint(state)
        trust_entries = [
            d for d in result.decision_chain
            if (d.step if isinstance(d, DecisionEntry) else d.get("step", "")) == "trust_assessment"
        ]
        assert len(trust_entries) == 1
        entry = trust_entries[0]
        assert "fail" in entry.attestation_status
        assert "pass" in entry.attestation_status

    # ── Helper ────────────────────────────────────────────────

    @staticmethod
    def _make_graph():
        """Create InvestigationGraph with all-mock dependencies."""
        from orchestrator.graph import InvestigationGraph

        return InvestigationGraph(
            repository=MagicMock(),
            ioc_extractor=MagicMock(),
            context_enricher=MagicMock(),
            ctem_correlator=MagicMock(),
            atlas_mapper=MagicMock(),
            reasoning_agent=MagicMock(),
            response_agent=MagicMock(),
        )


# ---------------------------------------------------------------------------
# TestDecisionEntryAttestation (Task 4 — AC: 4)
# ---------------------------------------------------------------------------

class TestDecisionEntryAttestation:
    """AC-4: attestation_status field on DecisionEntry."""

    def test_attestation_status_default_empty(self):
        """DecisionEntry.attestation_status defaults to empty string."""
        entry = DecisionEntry()
        assert entry.attestation_status == ""

    def test_attestation_status_set(self):
        """DecisionEntry.attestation_status can be set."""
        entry = DecisionEntry(
            step="test",
            agent="test_agent",
            attestation_status="fail",
        )
        assert entry.attestation_status == "fail"
