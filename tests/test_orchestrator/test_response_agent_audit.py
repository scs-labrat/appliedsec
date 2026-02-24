"""Tests for AuditProducer integration in Response Agent — Story 13.8, Task 5."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from orchestrator.agents.response_agent import ApprovalGate, ResponseAgent
from shared.schemas.investigation import GraphState, InvestigationState


def _make_state(**overrides):
    defaults = {
        "investigation_id": "inv-1",
        "alert_id": "alert-1",
        "tenant_id": "t1",
        "severity": "medium",
        "entities": {},
        "recommended_actions": [],
    }
    defaults.update(overrides)
    return GraphState(**defaults)


class TestResponseAgentAudit:
    """AC-5: approval and response events emitted via AuditProducer."""

    @pytest.mark.asyncio
    async def test_response_executed_emitted(self):
        """response.executed emitted when auto action is executed."""
        audit = MagicMock()
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[])

        agent = ResponseAgent(postgres_client=db, audit_producer=audit)
        state = _make_state(recommended_actions=[
            {"action": "log_event", "target": "siem", "tier": 0},
        ])

        result = await agent.execute(state)

        exec_calls = [c for c in audit.emit.call_args_list
                      if c[1].get("event_type") == "response.executed"]
        assert len(exec_calls) >= 1
        assert exec_calls[0][1]["investigation_id"] == "inv-1"

    @pytest.mark.asyncio
    async def test_approval_requested_emitted(self):
        """approval.requested emitted when approval gate is created."""
        audit = MagicMock()
        gate = ApprovalGate()
        state = _make_state()

        gate.create_gate(state, [{"action": "isolate_host", "tier": 2}])
        # The gate itself doesn't emit — the agent does when it creates the gate.
        # Test the emit helper directly.
        agent = ResponseAgent(postgres_client=AsyncMock(), audit_producer=audit)
        agent._emit_audit_event(
            state, "approval.requested", "approval",
            context={"pending_actions": ["isolate_host"]},
        )

        audit.emit.assert_called_once()
        call_kwargs = audit.emit.call_args[1]
        assert call_kwargs["event_type"] == "approval.requested"
        assert call_kwargs["event_category"] == "approval"

    @pytest.mark.asyncio
    async def test_approval_granted_emitted(self):
        """approval.granted emitted on approval resolution."""
        audit = MagicMock()
        agent = ResponseAgent(postgres_client=AsyncMock(), audit_producer=audit)
        state = _make_state()

        agent._emit_audit_event(state, "approval.granted", "approval")

        call_kwargs = audit.emit.call_args[1]
        assert call_kwargs["event_type"] == "approval.granted"

    @pytest.mark.asyncio
    async def test_no_exception_when_audit_producer_is_none(self):
        """Backward compat: works without audit_producer."""
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[])
        agent = ResponseAgent(postgres_client=db)
        state = _make_state()
        result = await agent.execute(state)
        assert result.state == InvestigationState.CLOSED

    @pytest.mark.asyncio
    async def test_audit_emit_failure_does_not_block(self):
        """Fire-and-forget: audit failure doesn't block response agent."""
        audit = MagicMock()
        audit.emit.side_effect = Exception("Kafka down")
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[])

        agent = ResponseAgent(postgres_client=db, audit_producer=audit)
        state = _make_state()
        result = await agent.execute(state)
        assert result.state == InvestigationState.CLOSED
