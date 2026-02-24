"""Audit trail models — Story 13.1.

Defines :class:`AuditContext`, :class:`AuditDecision`, :class:`AuditOutcome`,
and :class:`AuditRecord` Pydantic v2 models for the immutable audit trail.
"""

from __future__ import annotations

from pydantic import BaseModel, field_validator

from shared.schemas.event_taxonomy import EventCategory, EventTaxonomy


class AuditContext(BaseModel):
    """Contextual information captured alongside an audit event.

    Callers populate only the fields relevant to their event type;
    all fields default to empty/zero values.
    """

    # LLM context
    llm_provider: str = ""
    llm_model_id: str = ""
    llm_model_tier: str = ""
    llm_system_prompt_hash: str = ""
    llm_user_content_hash: str = ""
    llm_prompt_template_id: str = ""
    llm_prompt_template_version: str = ""
    llm_input_tokens: int = 0
    llm_output_tokens: int = 0
    llm_cache_read_tokens: int = 0
    llm_cache_write_tokens: int = 0
    llm_cost_usd: float = 0.0
    llm_latency_ms: int = 0
    llm_raw_response_hash: str = ""
    llm_extended_thinking_used: bool = False
    llm_tool_use_schema: str = ""

    # Retrieval context
    retrieval_stores_queried: list[str] = []
    retrieval_query_hashes: list[str] = []
    retrieval_results_count: int = 0
    retrieval_results_used: int = 0
    retrieval_token_budget: int = 0
    retrieval_token_used: int = 0
    retrieval_sources: list[str] = []

    # Taxonomy context
    taxonomy_version_attack: str = ""
    taxonomy_version_atlas: str = ""
    techniques_identified: list[str] = []
    techniques_validated: list[str] = []
    techniques_quarantined: list[str] = []

    # Risk context
    risk_state: str = ""
    risk_data_freshness_hours: float = 0.0
    ctem_exposures_matched: int = 0
    similar_incidents_found: int = 0
    fp_patterns_checked: int = 0
    fp_pattern_matched: str = ""

    # Environment
    degradation_level: str = "full"
    provider_health: dict = {}
    evidence_refs: list[str] = []


class AuditDecision(BaseModel):
    """Captures the decision made during an audit event."""

    decision_type: str = ""
    classification: str = ""
    confidence: float = 0.0
    confidence_basis: str = ""
    severity_assigned: str = ""
    recommended_actions: list[str] = []
    reasoning_summary: str = ""
    constraints_applied: list[str] = []
    alternatives_considered: list[str] = []


class AuditOutcome(BaseModel):
    """Captures the outcome/result of an audit event."""

    outcome_status: str = ""
    action_taken: str = ""
    action_target: str = ""
    error_details: str = ""
    duration_ms: int = 0
    state_before: str = ""
    state_after: str = ""
    cost_incurred_usd: float = 0.0

    # Approval fields
    approval_requested_from: str = ""
    approval_received_from: str = ""
    approval_channel: str = ""
    approval_latency_ms: int = 0
    approval_comment: str = ""

    # Analyst feedback
    analyst_feedback_correct: bool | None = None
    analyst_feedback_rating: int | None = None
    analyst_feedback_comment: str = ""
    analyst_feedback_timestamp: str = ""


class AuditRecord(BaseModel):
    """Top-level audit record — the immutable unit of the audit trail.

    Every auditable event in ALUSKORT produces exactly one AuditRecord.
    """

    # Identity
    audit_id: str
    tenant_id: str
    sequence_number: int = 0
    previous_hash: str = ""

    # Time
    timestamp: str
    ingested_at: str = ""

    # Event
    event_type: str
    event_category: str = ""
    severity: str = "info"

    # Actor
    actor_type: str
    actor_id: str
    actor_permissions: list[str] = []

    # References
    investigation_id: str = ""
    alert_id: str = ""
    entity_ids: list[str] = []

    # Nested models
    context: AuditContext = AuditContext()
    decision: AuditDecision = AuditDecision()
    outcome: AuditOutcome = AuditOutcome()

    # Integrity
    record_hash: str = ""
    record_version: str = "1.0"

    @field_validator("event_type")
    @classmethod
    def _validate_event_type(cls, v: str) -> str:
        """Ensure event_type is a valid EventTaxonomy member."""
        valid = {e.value for e in EventTaxonomy}
        if v not in valid:
            msg = f"Invalid event_type '{v}'. Must be one of: {sorted(valid)}"
            raise ValueError(msg)
        return v

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        """Ensure severity is info, warning, or critical."""
        allowed = {"info", "warning", "critical"}
        if v not in allowed:
            msg = f"Invalid severity '{v}'. Must be one of: {sorted(allowed)}"
            raise ValueError(msg)
        return v
