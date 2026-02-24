"""Tests for AuditContext, AuditDecision, AuditOutcome, AuditRecord — Story 13.1."""

import pytest
from pydantic import ValidationError

from shared.schemas.audit import AuditContext, AuditDecision, AuditOutcome, AuditRecord
from shared.schemas.event_taxonomy import EventTaxonomy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_record(**overrides) -> AuditRecord:
    """Create a minimal valid AuditRecord with optional overrides."""
    defaults = dict(
        audit_id="01234567-89ab-cdef-0123-456789abcdef",
        tenant_id="tenant-1",
        timestamp="2026-02-21T12:00:00Z",
        event_type="alert.classified",
        actor_type="agent",
        actor_id="reasoning_agent",
    )
    defaults.update(overrides)
    return AuditRecord(**defaults)


# ---------------------------------------------------------------------------
# TestAuditContext (AC-3)
# ---------------------------------------------------------------------------

class TestAuditContext:
    """AC-3: AuditContext captures LLM context, retrieval, taxonomy, risk, env."""

    def test_defaults_are_empty(self):
        ctx = AuditContext()
        assert ctx.llm_provider == ""
        assert ctx.llm_model_id == ""
        assert ctx.llm_input_tokens == 0
        assert ctx.llm_output_tokens == 0
        assert ctx.llm_cost_usd == 0.0
        assert ctx.llm_extended_thinking_used is False
        assert ctx.retrieval_stores_queried == []
        assert ctx.risk_state == ""
        assert ctx.degradation_level == "full"

    def test_llm_fields_populate(self):
        ctx = AuditContext(
            llm_provider="anthropic",
            llm_model_id="claude-sonnet-4-5-20250929",
            llm_model_tier="tier_1",
            llm_input_tokens=5000,
            llm_output_tokens=1200,
            llm_cost_usd=0.024,
            llm_latency_ms=850,
            llm_extended_thinking_used=True,
        )
        assert ctx.llm_provider == "anthropic"
        assert ctx.llm_model_id == "claude-sonnet-4-5-20250929"
        assert ctx.llm_input_tokens == 5000
        assert ctx.llm_cost_usd == 0.024
        assert ctx.llm_extended_thinking_used is True

    def test_evidence_refs_list(self):
        ctx = AuditContext(evidence_refs=["ref-1", "ref-2", "ref-3"])
        assert len(ctx.evidence_refs) == 3
        assert "ref-2" in ctx.evidence_refs

    def test_retrieval_fields_populate(self):
        ctx = AuditContext(
            retrieval_stores_queried=["qdrant", "neo4j"],
            retrieval_results_count=15,
            retrieval_results_used=5,
            retrieval_sources=["qdrant:incidents", "neo4j:graph"],
        )
        assert ctx.retrieval_stores_queried == ["qdrant", "neo4j"]
        assert ctx.retrieval_results_count == 15
        assert ctx.retrieval_results_used == 5


# ---------------------------------------------------------------------------
# TestAuditDecision (AC-4)
# ---------------------------------------------------------------------------

class TestAuditDecision:
    """AC-4: AuditDecision captures decision_type, classification, confidence."""

    def test_defaults_are_empty(self):
        d = AuditDecision()
        assert d.decision_type == ""
        assert d.classification == ""
        assert d.confidence == 0.0
        assert d.reasoning_summary == ""
        assert d.constraints_applied == []

    def test_populated_decision(self):
        d = AuditDecision(
            decision_type="classify",
            classification="true_positive",
            confidence=0.92,
            confidence_basis="llm_classification",
            severity_assigned="high",
            reasoning_summary="High confidence TP based on IOC enrichment",
            constraints_applied=["require_human_approval_for_critical"],
            alternatives_considered=["auto_close", "escalate"],
        )
        assert d.decision_type == "classify"
        assert d.confidence == 0.92
        assert len(d.constraints_applied) == 1
        assert len(d.alternatives_considered) == 2

    def test_confidence_range_accepts_boundary(self):
        d = AuditDecision(confidence=0.0)
        assert d.confidence == 0.0
        d2 = AuditDecision(confidence=1.0)
        assert d2.confidence == 1.0


# ---------------------------------------------------------------------------
# TestAuditOutcome (AC-5)
# ---------------------------------------------------------------------------

class TestAuditOutcome:
    """AC-5: AuditOutcome captures outcome_status, action, approval, feedback."""

    def test_defaults_are_empty(self):
        o = AuditOutcome()
        assert o.outcome_status == ""
        assert o.action_taken == ""
        assert o.duration_ms == 0
        assert o.cost_incurred_usd == 0.0
        assert o.analyst_feedback_correct is None
        assert o.analyst_feedback_rating is None

    def test_approval_fields(self):
        o = AuditOutcome(
            outcome_status="pending_approval",
            approval_requested_from="soc-team",
            approval_channel="slack",
            approval_latency_ms=45000,
        )
        assert o.outcome_status == "pending_approval"
        assert o.approval_requested_from == "soc-team"
        assert o.approval_channel == "slack"
        assert o.approval_latency_ms == 45000

    def test_feedback_fields(self):
        o = AuditOutcome(
            analyst_feedback_correct=True,
            analyst_feedback_rating=5,
            analyst_feedback_comment="Accurate classification",
            analyst_feedback_timestamp="2026-02-21T14:00:00Z",
        )
        assert o.analyst_feedback_correct is True
        assert o.analyst_feedback_rating == 5
        assert o.analyst_feedback_comment == "Accurate classification"


# ---------------------------------------------------------------------------
# TestAuditRecord (AC-1)
# ---------------------------------------------------------------------------

class TestAuditRecord:
    """AC-1: AuditRecord required fields, validators, nested models."""

    def test_required_fields_enforced(self):
        with pytest.raises(ValidationError):
            AuditRecord()  # type: ignore[call-arg]

    def test_minimal_valid_record(self):
        r = _make_record()
        assert r.audit_id == "01234567-89ab-cdef-0123-456789abcdef"
        assert r.tenant_id == "tenant-1"
        assert r.event_type == "alert.classified"
        assert r.actor_type == "agent"
        assert r.actor_id == "reasoning_agent"

    def test_event_type_validated_against_taxonomy(self):
        with pytest.raises(ValidationError, match="Invalid event_type"):
            _make_record(event_type="not.a.real.event")

    def test_all_taxonomy_values_accepted(self):
        for event in EventTaxonomy:
            r = _make_record(event_type=event.value)
            assert r.event_type == event.value

    def test_severity_validated(self):
        with pytest.raises(ValidationError, match="Invalid severity"):
            _make_record(severity="unknown")

    def test_severity_valid_values(self):
        for sev in ("info", "warning", "critical"):
            r = _make_record(severity=sev)
            assert r.severity == sev

    def test_nested_models_instantiate(self):
        r = _make_record()
        assert isinstance(r.context, AuditContext)
        assert isinstance(r.decision, AuditDecision)
        assert isinstance(r.outcome, AuditOutcome)

    def test_record_version_defaults(self):
        r = _make_record()
        assert r.record_version == "1.0"

    def test_full_record_with_nested(self):
        r = _make_record(
            context=AuditContext(llm_provider="anthropic", llm_cost_usd=0.05),
            decision=AuditDecision(decision_type="classify", confidence=0.95),
            outcome=AuditOutcome(outcome_status="success", action_taken="classified"),
        )
        assert r.context.llm_provider == "anthropic"
        assert r.decision.confidence == 0.95
        assert r.outcome.outcome_status == "success"

    def test_serialisation_round_trip(self):
        r = _make_record(
            entity_ids=["e1", "e2"],
            context=AuditContext(evidence_refs=["ref-1"]),
        )
        data = r.model_dump()
        r2 = AuditRecord(**data)
        assert r2.audit_id == r.audit_id
        assert r2.entity_ids == ["e1", "e2"]
        assert r2.context.evidence_refs == ["ref-1"]
