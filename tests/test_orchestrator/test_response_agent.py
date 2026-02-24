"""Tests for Response Agent — Stories 7.5, 15.5."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from shared.schemas.investigation import GraphState, InvestigationState
from orchestrator.agents.response_agent import (
    ApprovalGate,
    APPROVAL_TIMEOUT_BY_SEVERITY,
    ResponseAgent,
    APPROVAL_TIMEOUT_HOURS,
    TIER_AUTO,
    TIER_REQUIRES_APPROVAL,
    get_timeout_hours,
)
from orchestrator.executor_constraints import ExecutorConstraints


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


# ---------- Executor constraint integration — Task 3 (Story 12.9) -----------

class TestExecutorConstraintIntegration:
    """Constraint enforcement in ResponseAgent._execute_action()."""

    @pytest.mark.asyncio
    async def test_allowlisted_playbook_executes(self):
        pg = AsyncMock()
        pg.fetch_many = AsyncMock(return_value=[])
        producer = AsyncMock()
        producer.produce = AsyncMock()
        constraints = ExecutorConstraints(
            allowlisted_playbooks=frozenset({"PB-001"}),
        )
        agent = ResponseAgent(
            postgres_client=pg, kafka_producer=producer, constraints=constraints,
        )
        state = GraphState(
            investigation_id="inv-c01",
            state=InvestigationState.RESPONDING,
            severity="high",
            recommended_actions=[
                {"action": "execute_playbook", "target": "PB-001", "tier": 0},
            ],
        )
        result = await agent.execute(state)
        assert result.state == InvestigationState.CLOSED
        # Published as "executed" (not blocked)
        calls = producer.produce.call_args_list
        assert any(
            c.args[1].get("status") == "executed"
            for c in calls
        )

    @pytest.mark.asyncio
    async def test_non_allowlisted_playbook_blocked(self):
        pg = AsyncMock()
        pg.fetch_many = AsyncMock(return_value=[])
        producer = AsyncMock()
        producer.produce = AsyncMock()
        constraints = ExecutorConstraints(
            allowlisted_playbooks=frozenset({"PB-001"}),
        )
        agent = ResponseAgent(
            postgres_client=pg, kafka_producer=producer, constraints=constraints,
        )
        state = GraphState(
            investigation_id="inv-c02",
            state=InvestigationState.RESPONDING,
            severity="high",
            recommended_actions=[
                {"action": "execute_playbook", "target": "PB-999", "tier": 0},
            ],
        )
        result = await agent.execute(state)
        assert result.state == InvestigationState.CLOSED
        # Published as "blocked" with constraint type
        calls = producer.produce.call_args_list
        blocked = [c for c in calls if c.args[1].get("status") == "blocked"]
        assert len(blocked) >= 1
        assert blocked[0].args[1]["constraint_blocked_type"] == "unauthorized_playbook"

    @pytest.mark.asyncio
    async def test_auto_close_with_confidence_and_fp_passes(self):
        pg = AsyncMock()
        pg.fetch_many = AsyncMock(return_value=[])
        producer = AsyncMock()
        producer.produce = AsyncMock()
        agent = ResponseAgent(
            postgres_client=pg, kafka_producer=producer,
        )
        state = GraphState(
            investigation_id="inv-c03",
            state=InvestigationState.RESPONDING,
            severity="low",
            confidence=0.95,
            classification="false_positive",
            recommended_actions=[
                {"action": "auto_close", "target": "inv-c03", "tier": 0},
            ],
        )
        result = await agent.execute(state)
        calls = producer.produce.call_args_list
        assert any(c.args[1].get("status") == "executed" for c in calls)

    @pytest.mark.asyncio
    async def test_auto_close_without_fp_match_blocked(self):
        pg = AsyncMock()
        pg.fetch_many = AsyncMock(return_value=[])
        producer = AsyncMock()
        producer.produce = AsyncMock()
        agent = ResponseAgent(
            postgres_client=pg, kafka_producer=producer,
        )
        state = GraphState(
            investigation_id="inv-c04",
            state=InvestigationState.RESPONDING,
            severity="low",
            confidence=0.95,
            classification="true_positive",  # not false_positive → fp_matched=False
            recommended_actions=[
                {"action": "auto_close", "target": "inv-c04", "tier": 0},
            ],
        )
        result = await agent.execute(state)
        calls = producer.produce.call_args_list
        blocked = [c for c in calls if c.args[1].get("status") == "blocked"]
        assert len(blocked) >= 1
        assert blocked[0].args[1]["constraint_blocked_type"] == "insufficient_criteria"

    @pytest.mark.asyncio
    async def test_routing_policy_change_blocked(self):
        pg = AsyncMock()
        pg.fetch_many = AsyncMock(return_value=[])
        producer = AsyncMock()
        producer.produce = AsyncMock()
        agent = ResponseAgent(
            postgres_client=pg, kafka_producer=producer,
        )
        state = GraphState(
            investigation_id="inv-c05",
            state=InvestigationState.RESPONDING,
            severity="high",
            recommended_actions=[
                {"action": "modify_routing_policy", "target": "tier-0", "tier": 0},
            ],
        )
        result = await agent.execute(state)
        calls = producer.produce.call_args_list
        blocked = [c for c in calls if c.args[1].get("status") == "blocked"]
        assert len(blocked) >= 1
        assert blocked[0].args[1]["constraint_blocked_type"] == "routing_policy_change"

    @pytest.mark.asyncio
    async def test_backward_compat_no_constraints_param(self):
        """ResponseAgent with no constraints parameter uses DEFAULT_CONSTRAINTS."""
        pg = AsyncMock()
        pg.fetch_many = AsyncMock(return_value=[])
        agent = ResponseAgent(postgres_client=pg, kafka_producer=None)
        state = GraphState(
            investigation_id="inv-c06",
            state=InvestigationState.RESPONDING,
            severity="low",
            recommended_actions=[
                {"action": "monitor", "target": "web-01", "tier": 0},
            ],
        )
        result = await agent.execute(state)
        assert result.state == InvestigationState.CLOSED


# ---------- Story 15.5: Configurable approval timeout -------------------------

class TestApprovalTimeout:
    """Task 1 — Severity-based timeout configuration (AC-1)."""

    def test_critical_timeout_1h(self):
        assert get_timeout_hours("critical") == 1

    def test_high_timeout_2h(self):
        assert get_timeout_hours("high") == 2

    def test_medium_timeout_4h(self):
        assert get_timeout_hours("medium") == 4

    def test_low_timeout_8h(self):
        assert get_timeout_hours("low") == 8

    def test_unknown_severity_defaults_4h(self):
        assert get_timeout_hours("unknown") == 4

    def test_tenant_override_takes_precedence(self):
        overrides = {"critical": 2, "high": 3}
        assert get_timeout_hours("critical", overrides) == 2
        assert get_timeout_hours("high", overrides) == 3
        # Medium not overridden → falls back to default
        assert get_timeout_hours("medium", overrides) == 4


class TestApprovalGateSeverity:
    """Task 2 — ApprovalGate with severity-aware timeout (AC-1, AC-4)."""

    def test_critical_severity_1h(self):
        gate = ApprovalGate(severity="critical")
        assert gate.timeout_hours == 1

    def test_tenant_override_used(self):
        gate = ApprovalGate(
            severity="critical", tenant_overrides={"critical": 3}
        )
        assert gate.timeout_hours == 3

    def test_default_gate_still_4h(self):
        """Backward compat: ApprovalGate() with no params = 4 hours."""
        gate = ApprovalGate()
        assert gate.timeout_hours == 4

    def test_severity_map_constant(self):
        assert APPROVAL_TIMEOUT_BY_SEVERITY == {
            "critical": 1, "high": 2, "medium": 4, "low": 8,
        }


class TestHalfTimeoutEscalation:
    """Task 3 — 50% timeout escalation (AC-2)."""

    def test_escalation_triggered_at_50pct(self):
        """Past 50% of timeout → should_escalate returns True."""
        gate = ApprovalGate(severity="critical")  # 1h timeout
        # Deadline 10 minutes from now → 50 min elapsed out of 60 = 83%
        deadline = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        record = {"approval_deadline": deadline}
        assert gate.should_escalate(record) is True

    def test_not_triggered_before_50pct(self):
        """Before 50% of timeout → should_escalate returns False."""
        gate = ApprovalGate(severity="critical")  # 1h timeout
        # Deadline 55 minutes from now → 5 min elapsed out of 60 = 8%
        deadline = (datetime.now(timezone.utc) + timedelta(minutes=55)).isoformat()
        record = {"approval_deadline": deadline}
        assert gate.should_escalate(record) is False

    def test_not_retriggered_after_first(self):
        """Should only fire once — second call returns False."""
        gate = ApprovalGate(severity="critical")
        deadline = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        record = {"approval_deadline": deadline}
        assert gate.should_escalate(record) is True
        assert gate.should_escalate(record) is False  # not re-triggered

    def test_half_timeout_no_deadline(self):
        """Missing deadline → half_timeout_reached returns True."""
        gate = ApprovalGate(severity="high")
        assert gate.half_timeout_reached({}) is True


class TestCriticalTimeout:
    """Task 4 — Critical-severity timeout behavior (AC-3)."""

    def test_critical_timeout_escalates(self):
        """Critical timeout sets 'escalated', does NOT close."""
        gate = ApprovalGate(severity="critical")
        state = GraphState(
            investigation_id="inv-esc-01",
            state=InvestigationState.AWAITING_HUMAN,
        )
        result = gate.resolve(state, approved=False)
        assert result.classification == "escalated"
        # Investigation stays open (NOT CLOSED)
        assert result.state == InvestigationState.AWAITING_HUMAN

    def test_high_timeout_escalates(self):
        """High severity also escalates on timeout."""
        gate = ApprovalGate(severity="high")
        state = GraphState(
            investigation_id="inv-esc-02",
            state=InvestigationState.AWAITING_HUMAN,
        )
        result = gate.resolve(state, approved=False)
        assert result.classification == "escalated"
        assert result.state == InvestigationState.AWAITING_HUMAN

    def test_medium_timeout_closes(self):
        """Medium severity closes on timeout (existing behavior)."""
        gate = ApprovalGate(severity="medium")
        state = GraphState(
            investigation_id="inv-esc-03",
            state=InvestigationState.AWAITING_HUMAN,
        )
        result = gate.resolve(state, approved=False)
        assert result.classification == "rejected"
        assert result.state == InvestigationState.CLOSED

    def test_escalation_state_set_correctly(self):
        """timeout_behavior is 'escalate' for critical/high, 'close' for others."""
        assert ApprovalGate(severity="critical").timeout_behavior == "escalate"
        assert ApprovalGate(severity="high").timeout_behavior == "escalate"
        assert ApprovalGate(severity="medium").timeout_behavior == "close"
        assert ApprovalGate(severity="low").timeout_behavior == "close"


# ---------- F6: Zero/negative tenant timeout override -------------------------

class TestTimeoutClamping:
    def test_zero_override_clamped_to_1h(self):
        """Zero timeout override should be clamped to minimum 1 hour."""
        assert get_timeout_hours("critical", {"critical": 0}) == 1

    def test_negative_override_clamped_to_1h(self):
        """Negative timeout override should be clamped to minimum 1 hour."""
        assert get_timeout_hours("high", {"high": -5}) == 1
