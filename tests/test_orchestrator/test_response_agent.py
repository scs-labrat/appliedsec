"""Tests for Response Agent — Story 7.5."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from shared.schemas.investigation import GraphState, InvestigationState
from orchestrator.agents.response_agent import (
    ApprovalGate,
    ResponseAgent,
    APPROVAL_TIMEOUT_HOURS,
    TIER_AUTO,
    TIER_REQUIRES_APPROVAL,
)


@pytest.fixture
def mock_postgres():
    pg = AsyncMock()
    pg.fetch_many = AsyncMock(return_value=[])
    return pg


@pytest.fixture
def mock_producer():
    prod = AsyncMock()
    prod.produce = AsyncMock()
    return prod


@pytest.fixture
def agent(mock_postgres, mock_producer):
    return ResponseAgent(
        postgres_client=mock_postgres,
        kafka_producer=mock_producer,
    )


@pytest.fixture
def state():
    return GraphState(
        investigation_id="inv-001",
        state=InvestigationState.RESPONDING,
        severity="high",
        recommended_actions=[
            {"action": "monitor", "target": "web-01", "tier": 0},
            {"action": "send_alert", "target": "soc@company.com", "tier": 0},
        ],
        entities={"tactics": ["T1566"], "attack_techniques": ["T1566"]},
    )


class TestResponseAgent:
    @pytest.mark.asyncio
    async def test_closes_investigation(self, agent, state):
        result = await agent.execute(state)
        assert result.state == InvestigationState.CLOSED

    @pytest.mark.asyncio
    async def test_queries_playbooks(self, agent, state, mock_postgres):
        await agent.execute(state)
        mock_postgres.fetch_many.assert_called_once()

    @pytest.mark.asyncio
    async def test_stores_playbook_matches(self, agent, state, mock_postgres):
        mock_postgres.fetch_many.return_value = [
            {"playbook_id": "PB-001", "title": "Phishing Response", "tactics": "T1566", "techniques": ["T1566"], "steps": []},
        ]
        result = await agent.execute(state)
        assert len(result.playbook_matches) == 1

    @pytest.mark.asyncio
    async def test_publishes_auto_actions(self, agent, state, mock_producer):
        await agent.execute(state)
        # Two auto actions should be published
        assert mock_producer.produce.call_count == 2

    @pytest.mark.asyncio
    async def test_no_producer_no_crash(self, mock_postgres, state):
        agent = ResponseAgent(postgres_client=mock_postgres, kafka_producer=None)
        result = await agent.execute(state)
        assert result.state == InvestigationState.CLOSED


class TestActionClassification:
    def test_auto_actions(self, agent):
        actions = [
            {"action": "monitor", "tier": 0},
            {"action": "alert", "tier": 1},
        ]
        auto, gated = agent._classify_actions(actions)
        assert len(auto) == 2
        assert len(gated) == 0

    def test_gated_actions(self, agent):
        actions = [
            {"action": "isolate_endpoint", "tier": 2},
            {"action": "disable_account", "tier": 2},
        ]
        auto, gated = agent._classify_actions(actions)
        assert len(auto) == 0
        assert len(gated) == 2

    def test_mixed_actions(self, agent):
        actions = [
            {"action": "monitor", "tier": 0},
            {"action": "isolate_endpoint", "tier": 2},
        ]
        auto, gated = agent._classify_actions(actions)
        assert len(auto) == 1
        assert len(gated) == 1

    def test_non_dict_skipped(self, agent):
        actions = ["not_a_dict", None, 42]
        auto, gated = agent._classify_actions(actions)
        assert len(auto) == 0
        assert len(gated) == 0


class TestApprovalGate:
    def test_create_gate(self):
        gate = ApprovalGate()
        state = GraphState(investigation_id="inv-001")
        pending = [{"action": "isolate", "tier": 2}]
        result = gate.create_gate(state, pending)
        assert result["investigation_id"] == "inv-001"
        assert result["state"] == "awaiting_approval"
        assert len(result["pending_actions"]) == 1
        assert result["assigned_to"] is None

    def test_gate_not_expired(self):
        gate = ApprovalGate()
        deadline = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
        record = {"approval_deadline": deadline}
        assert gate.is_expired(record) is False

    def test_gate_expired(self):
        gate = ApprovalGate()
        deadline = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        record = {"approval_deadline": deadline}
        assert gate.is_expired(record) is True

    def test_gate_no_deadline(self):
        gate = ApprovalGate()
        assert gate.is_expired({}) is True

    def test_resolve_approved(self):
        gate = ApprovalGate()
        state = GraphState(
            investigation_id="inv-001",
            state=InvestigationState.AWAITING_HUMAN,
        )
        result = gate.resolve(state, approved=True)
        assert result.state == InvestigationState.RESPONDING

    def test_resolve_rejected(self):
        gate = ApprovalGate()
        state = GraphState(
            investigation_id="inv-001",
            state=InvestigationState.AWAITING_HUMAN,
        )
        result = gate.resolve(state, approved=False)
        assert result.state == InvestigationState.CLOSED

    def test_timeout_hours_constant(self):
        assert APPROVAL_TIMEOUT_HOURS == 4

    def test_tier_constants(self):
        assert TIER_AUTO == 0
        assert TIER_REQUIRES_APPROVAL == 2
