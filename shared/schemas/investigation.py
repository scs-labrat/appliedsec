"""Investigation state machine and graph state models."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class InvestigationState(str, Enum):
    """Investigation lifecycle states (LangGraph node transitions)."""

    RECEIVED = "received"
    PARSING = "parsing"
    ENRICHING = "enriching"
    REASONING = "reasoning"
    AWAITING_HUMAN = "awaiting_human"
    RESPONDING = "responding"
    CLOSED = "closed"
    FAILED = "failed"


class AgentRole(str, Enum):
    """Roles within the investigation graph."""

    IOC_EXTRACTOR = "ioc_extractor"
    CONTEXT_ENRICHER = "context_enricher"
    REASONING_AGENT = "reasoning_agent"
    RESPONSE_AGENT = "response_agent"
    CTEM_CORRELATOR = "ctem_correlator"
    ATLAS_MAPPER = "atlas_mapper"


class GraphState(BaseModel):
    """Explicit state object persisted to Postgres for each investigation."""

    investigation_id: str
    state: InvestigationState = InvestigationState.RECEIVED
    alert_id: str = ""
    tenant_id: str = ""
    entities: dict[str, Any] = {}
    ioc_matches: list[Any] = []
    ueba_context: list[Any] = []
    ctem_exposures: list[Any] = []
    atlas_techniques: list[Any] = []
    similar_incidents: list[Any] = []
    playbook_matches: list[Any] = []
    decision_chain: list[Any] = []
    classification: str = ""
    confidence: float = 0.0
    severity: str = ""
    recommended_actions: list[Any] = []
    requires_human_approval: bool = False
    risk_state: str = "unknown"
    llm_calls: int = 0
    total_cost_usd: float = 0.0
    queries_executed: int = Field(default=0)
