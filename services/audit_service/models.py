"""Audit service local models — Story 13.6.

Defines :class:`EvidencePackage` for the evidence package API.
"""

from __future__ import annotations

from pydantic import BaseModel


class EvidencePackage(BaseModel):
    """Self-contained evidence package for an investigation."""

    package_id: str = ""
    investigation_id: str = ""
    tenant_id: str = ""
    generated_at: str = ""
    generated_by: str = "aluskort-audit-service v1.0"

    source_alert: dict = {}
    raw_alert_payload: dict = {}

    events: list[dict] = []
    state_transitions: list[dict] = []
    retrieval_context: list[dict] = []
    llm_interactions: list[dict] = []

    final_classification: str = ""
    final_confidence: float = 0.0
    final_severity: str = ""

    reasoning_chain: list[str] = []
    techniques_mapped: list[str] = []

    actions_recommended: list[str] = []
    actions_executed: list[dict] = []
    actions_pending: list[dict] = []

    approvals: list[dict] = []
    analyst_feedback: list[dict] = []

    chain_verified: bool = False
    chain_verification_errors: list[str] = []

    package_hash: str = ""
