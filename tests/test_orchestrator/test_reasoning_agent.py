"""Tests for Reasoning Agent — Story 7.4."""

import json

import pytest
from unittest.mock import AsyncMock, MagicMock

from shared.schemas.investigation import GraphState, InvestigationState
from orchestrator.agents.reasoning_agent import (
    ReasoningAgent,
    _build_reasoning_context,
    _parse_classification,
    ESCALATION_CONFIDENCE_THRESHOLD,
    DESTRUCTIVE_ACTION_TIER,
)


def _make_gateway_response(classification_data: dict) -> MagicMock:
    return MagicMock(
        content=json.dumps(classification_data),
        metrics=MagicMock(cost_usd=0.05),
    )


@pytest.fixture
def mock_gateway():
    gw = AsyncMock()
    gw.complete = AsyncMock(return_value=_make_gateway_response({
        "classification": "true_positive",
        "confidence": 0.85,
        "severity": "high",
        "attack_techniques": ["T1566"],
        "atlas_techniques": [],
        "recommended_actions": [
            {"action": "monitor", "target": "web-01", "tier": 0, "rationale": "Watch"},
        ],
        "reasoning": "Suspicious phishing attempt detected.",
    }))
    return gw


@pytest.fixture
def mock_escalation():
    esc = MagicMock()
    esc.should_escalate = MagicMock(return_value=False)
    esc.record_escalation = MagicMock()
    return esc


@pytest.fixture
def agent(mock_gateway, mock_escalation):
    return ReasoningAgent(
        gateway=mock_gateway,
        escalation_manager=mock_escalation,
    )


@pytest.fixture
def state():
    return GraphState(
        investigation_id="inv-001",
        alert_id="alert-001",
        tenant_id="tenant-A",
        state=InvestigationState.ENRICHING,
        severity="high",
        entities={"ips": [{"primary_value": "10.0.0.1"}]},
    )


class TestClassification:
    @pytest.mark.asyncio
    async def test_classifies_alert(self, agent, state):
        result = await agent.execute(state)
        assert result.classification == "true_positive"
        assert result.confidence == 0.85

    @pytest.mark.asyncio
    async def test_sets_severity(self, agent, state):
        result = await agent.execute(state)
        assert result.severity == "high"

    @pytest.mark.asyncio
    async def test_extracts_techniques(self, agent, state):
        result = await agent.execute(state)
        assert "T1566" in result.entities.get("attack_techniques", [])

    @pytest.mark.asyncio
    async def test_sets_recommended_actions(self, agent, state):
        result = await agent.execute(state)
        assert len(result.recommended_actions) == 1
        assert result.recommended_actions[0]["action"] == "monitor"

    @pytest.mark.asyncio
    async def test_increments_llm_calls(self, agent, state):
        result = await agent.execute(state)
        assert result.llm_calls == 1

    @pytest.mark.asyncio
    async def test_tracks_cost(self, agent, state):
        result = await agent.execute(state)
        assert result.total_cost_usd == pytest.approx(0.05)


class TestRouting:
    @pytest.mark.asyncio
    async def test_auto_close_path(self, agent, state):
        """High confidence + no destructive actions → RESPONDING."""
        result = await agent.execute(state)
        assert result.state == InvestigationState.RESPONDING
        assert result.requires_human_approval is False

    @pytest.mark.asyncio
    async def test_destructive_action_requires_approval(self, agent, state, mock_gateway):
        mock_gateway.complete.return_value = _make_gateway_response({
            "classification": "true_positive",
            "confidence": 0.9,
            "severity": "critical",
            "recommended_actions": [
                {"action": "isolate_endpoint", "target": "web-01", "tier": 2},
            ],
        })
        result = await agent.execute(state)
        assert result.state == InvestigationState.AWAITING_HUMAN
        assert result.requires_human_approval is True

    @pytest.mark.asyncio
    async def test_low_confidence_critical_requires_approval(self, agent, state, mock_gateway):
        mock_gateway.complete.return_value = _make_gateway_response({
            "classification": "suspicious",
            "confidence": 0.4,
            "severity": "critical",
            "recommended_actions": [],
        })
        result = await agent.execute(state)
        assert result.state == InvestigationState.AWAITING_HUMAN

    @pytest.mark.asyncio
    async def test_low_confidence_medium_auto_closes(self, agent, state, mock_gateway):
        mock_gateway.complete.return_value = _make_gateway_response({
            "classification": "suspicious",
            "confidence": 0.4,
            "severity": "medium",
            "recommended_actions": [],
        })
        result = await agent.execute(state)
        assert result.state == InvestigationState.RESPONDING


class TestEscalation:
    @pytest.mark.asyncio
    async def test_escalation_triggered(self, agent, state, mock_gateway, mock_escalation):
        mock_escalation.should_escalate.return_value = True
        # First call: low confidence; second call (escalated): higher confidence
        mock_gateway.complete.side_effect = [
            _make_gateway_response({
                "classification": "suspicious",
                "confidence": 0.4,
                "severity": "critical",
                "recommended_actions": [],
            }),
            _make_gateway_response({
                "classification": "true_positive",
                "confidence": 0.85,
                "severity": "critical",
                "recommended_actions": [],
            }),
        ]
        result = await agent.execute(state)
        assert result.confidence == 0.85
        assert result.llm_calls == 2
        mock_escalation.record_escalation.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_escalation_without_manager(self, state, mock_gateway):
        agent = ReasoningAgent(gateway=mock_gateway, escalation_manager=None)
        result = await agent.execute(state)
        assert result.llm_calls == 1


class TestHelpers:
    def test_build_reasoning_context(self, state):
        ctx = _build_reasoning_context(state)
        data = json.loads(ctx)
        assert data["alert_id"] == "alert-001"
        assert data["severity"] == "high"

    def test_parse_classification_valid(self):
        data = {"classification": "true_positive", "confidence": 0.9}
        result = _parse_classification(json.dumps(data))
        assert result["classification"] == "true_positive"

    def test_parse_classification_invalid(self):
        result = _parse_classification("not json")
        assert result == {}

    def test_escalation_threshold_constant(self):
        assert ESCALATION_CONFIDENCE_THRESHOLD == 0.6

    def test_destructive_tier_constant(self):
        assert DESTRUCTIVE_ACTION_TIER == 2
