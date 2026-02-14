"""Tests for GraphState and InvestigationState — AC-1.1.4, AC-1.1.5."""

from shared.schemas.investigation import AgentRole, GraphState, InvestigationState


class TestInvestigationStateCoverage:
    """AC-1.1.5: InvestigationState has exactly 8 members."""

    def test_enum_has_eight_members(self):
        members = list(InvestigationState)
        assert len(members) == 8

    def test_enum_member_names(self):
        expected = {
            "RECEIVED",
            "PARSING",
            "ENRICHING",
            "REASONING",
            "AWAITING_HUMAN",
            "RESPONDING",
            "CLOSED",
            "FAILED",
        }
        assert {m.name for m in InvestigationState} == expected

    def test_enum_member_values(self):
        expected = {
            "received",
            "parsing",
            "enriching",
            "reasoning",
            "awaiting_human",
            "responding",
            "closed",
            "failed",
        }
        assert {m.value for m in InvestigationState} == expected


class TestAgentRole:
    def test_enum_has_six_members(self):
        assert len(list(AgentRole)) == 6

    def test_enum_member_names(self):
        expected = {
            "IOC_EXTRACTOR",
            "CONTEXT_ENRICHER",
            "REASONING_AGENT",
            "RESPONSE_AGENT",
            "CTEM_CORRELATOR",
            "ATLAS_MAPPER",
        }
        assert {m.name for m in AgentRole} == expected


class TestGraphStateDefaults:
    """AC-1.1.4: GraphState defaults to RECEIVED with empty lists and zeroes."""

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

    def test_state_can_transition(self):
        gs = GraphState(
            investigation_id="inv-002", state=InvestigationState.ENRICHING
        )
        assert gs.state == InvestigationState.ENRICHING
