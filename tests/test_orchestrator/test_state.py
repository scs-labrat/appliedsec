"""Tests for investigation state models — Story 7.1."""

import pytest

from shared.schemas.investigation import (
    AgentRole,
    GraphState,
    InvestigationState,
)


class TestInvestigationState:
    def test_eight_states(self):
        assert len(InvestigationState) == 8

    def test_state_values(self):
        assert InvestigationState.RECEIVED.value == "received"
        assert InvestigationState.PARSING.value == "parsing"
        assert InvestigationState.ENRICHING.value == "enriching"
        assert InvestigationState.REASONING.value == "reasoning"
        assert InvestigationState.AWAITING_HUMAN.value == "awaiting_human"
        assert InvestigationState.RESPONDING.value == "responding"
        assert InvestigationState.CLOSED.value == "closed"
        assert InvestigationState.FAILED.value == "failed"

    def test_string_enum(self):
        assert isinstance(InvestigationState.RECEIVED, str)
        assert InvestigationState.RECEIVED == "received"


class TestAgentRole:
    def test_six_roles(self):
        assert len(AgentRole) == 6

    def test_role_values(self):
        assert AgentRole.IOC_EXTRACTOR.value == "ioc_extractor"
        assert AgentRole.CONTEXT_ENRICHER.value == "context_enricher"
        assert AgentRole.REASONING_AGENT.value == "reasoning_agent"
        assert AgentRole.RESPONSE_AGENT.value == "response_agent"
        assert AgentRole.CTEM_CORRELATOR.value == "ctem_correlator"
        assert AgentRole.ATLAS_MAPPER.value == "atlas_mapper"


class TestGraphState:
    def test_defaults(self):
        gs = GraphState(investigation_id="inv-001")
        assert gs.state == InvestigationState.RECEIVED
        assert gs.alert_id == ""
        assert gs.tenant_id == ""
        assert gs.entities == {}
        assert gs.ioc_matches == []
        assert gs.ueba_context == []
        assert gs.ctem_exposures == []
        assert gs.atlas_techniques == []
        assert gs.similar_incidents == []
        assert gs.playbook_matches == []
        assert gs.decision_chain == []
        assert gs.classification == ""
        assert gs.confidence == 0.0
        assert gs.severity == ""
        assert gs.recommended_actions == []
        assert gs.requires_human_approval is False
        assert gs.risk_state == "unknown"
        assert gs.llm_calls == 0
        assert gs.total_cost_usd == 0.0
        assert gs.queries_executed == 0

    def test_full_state(self):
        gs = GraphState(
            investigation_id="inv-002",
            state=InvestigationState.REASONING,
            alert_id="alert-123",
            tenant_id="tenant-A",
            severity="critical",
            confidence=0.85,
            classification="true_positive",
            llm_calls=3,
            total_cost_usd=0.15,
        )
        assert gs.investigation_id == "inv-002"
        assert gs.state == InvestigationState.REASONING
        assert gs.confidence == 0.85

    def test_serialisation_round_trip(self):
        gs = GraphState(
            investigation_id="inv-003",
            state=InvestigationState.ENRICHING,
            entities={"hosts": [{"primary_value": "web-01"}]},
            decision_chain=[{"agent": "test", "action": "init"}],
        )
        json_str = gs.model_dump_json()
        gs2 = GraphState.model_validate_json(json_str)
        assert gs2.investigation_id == "inv-003"
        assert gs2.state == InvestigationState.ENRICHING
        assert gs2.entities["hosts"][0]["primary_value"] == "web-01"
        assert len(gs2.decision_chain) == 1

    def test_state_mutation(self):
        gs = GraphState(investigation_id="inv-004")
        gs.state = InvestigationState.PARSING
        gs.llm_calls += 1
        gs.decision_chain.append({"agent": "test", "action": "parse"})
        assert gs.state == InvestigationState.PARSING
        assert gs.llm_calls == 1
        assert len(gs.decision_chain) == 1
