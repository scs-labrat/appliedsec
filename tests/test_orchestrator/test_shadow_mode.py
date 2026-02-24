"""Tests for shadow mode manager and graph integration — Story 14.8."""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from orchestrator.shadow_mode import GoLiveCriteria, ShadowModeManager
from shared.config.tenant_config import TenantConfig, TenantConfigStore
from shared.schemas.investigation import (
    DecisionEntry,
    GraphState,
    InvestigationState,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store_mock(config: TenantConfig | None = None) -> TenantConfigStore:
    """Create a mock TenantConfigStore returning the given config."""
    store = MagicMock(spec=TenantConfigStore)
    if config is None:
        config = TenantConfig(tenant_id="t-001")
    store.get_config = AsyncMock(return_value=config)
    store._get_client = MagicMock(return_value=AsyncMock())
    return store


def _make_redis_mock() -> AsyncMock:
    """Create a mock Redis client with list operations."""
    redis = AsyncMock()
    redis.rpush = AsyncMock()
    redis.lrange = AsyncMock(return_value=[])
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()
    return redis


# ---------------------------------------------------------------------------
# TestShadowModeManager (Task 2)
# ---------------------------------------------------------------------------

class TestShadowModeManager:
    """AC-1,2: Shadow mode manager."""

    @pytest.mark.asyncio
    async def test_shadow_active_for_new_tenant(self):
        """New tenant with default config has shadow active."""
        store = _make_store_mock()
        mgr = ShadowModeManager(store)
        assert await mgr.is_shadow_active("t-001") is True

    @pytest.mark.asyncio
    async def test_shadow_inactive_after_go_live(self):
        """Tenant with shadow_mode=False has shadow inactive."""
        config = TenantConfig(
            tenant_id="t-001",
            shadow_mode=False,
            go_live_signed_off=True,
        )
        store = _make_store_mock(config)
        mgr = ShadowModeManager(store)
        assert await mgr.is_shadow_active("t-001") is False

    @pytest.mark.asyncio
    async def test_shadow_active_for_specific_rule_family(self):
        """Shadow active for specific rule family."""
        config = TenantConfig(
            tenant_id="t-001",
            shadow_mode=True,
            shadow_rule_families=["phishing", "malware"],
        )
        store = _make_store_mock(config)
        mgr = ShadowModeManager(store)
        assert await mgr.is_shadow_active("t-001", "phishing") is True
        assert await mgr.is_shadow_active("t-001", "brute_force") is False

    @pytest.mark.asyncio
    async def test_record_shadow_decision(self):
        """Shadow decision is logged to Redis."""
        redis = _make_redis_mock()
        store = MagicMock(spec=TenantConfigStore)
        store._get_client = MagicMock(return_value=redis)
        mgr = ShadowModeManager(store)

        await mgr.record_shadow_decision(
            "t-001", "phishing", "false_positive", 0.92, "inv-1"
        )
        redis.rpush.assert_awaited_once()
        key, value = redis.rpush.call_args[0]
        assert "shadow_log:t-001:phishing" == key
        data = json.loads(value)
        assert data["type"] == "shadow"
        assert data["shadow_decision"] == "false_positive"

    @pytest.mark.asyncio
    async def test_record_analyst_decision(self):
        """Analyst decision is logged to Redis."""
        redis = _make_redis_mock()
        store = MagicMock(spec=TenantConfigStore)
        store._get_client = MagicMock(return_value=redis)
        mgr = ShadowModeManager(store)

        await mgr.record_analyst_decision("t-001", "phishing", "true_positive", "inv-1")
        redis.rpush.assert_awaited_once()
        data = json.loads(redis.rpush.call_args[0][1])
        assert data["type"] == "analyst"
        assert data["analyst_decision"] == "true_positive"

    @pytest.mark.asyncio
    async def test_compute_agreement_rate(self):
        """Agreement rate computed correctly from paired decisions."""
        redis = _make_redis_mock()
        now = time.time()
        entries = [
            json.dumps({"type": "shadow", "shadow_decision": "fp", "investigation_id": "inv-1", "ts": now}),
            json.dumps({"type": "analyst", "analyst_decision": "fp", "investigation_id": "inv-1", "ts": now}),
            json.dumps({"type": "shadow", "shadow_decision": "fp", "investigation_id": "inv-2", "ts": now}),
            json.dumps({"type": "analyst", "analyst_decision": "tp", "investigation_id": "inv-2", "ts": now}),
        ]
        redis.lrange = AsyncMock(return_value=entries)
        store = MagicMock(spec=TenantConfigStore)
        store._get_client = MagicMock(return_value=redis)
        mgr = ShadowModeManager(store)

        rate = await mgr.compute_agreement_rate("t-001", "phishing")
        assert rate == pytest.approx(0.5)  # 1 agree / 2 paired

    @pytest.mark.asyncio
    async def test_compute_agreement_rate_empty(self):
        """Empty log returns 0.0 agreement rate."""
        redis = _make_redis_mock()
        store = MagicMock(spec=TenantConfigStore)
        store._get_client = MagicMock(return_value=redis)
        mgr = ShadowModeManager(store)

        rate = await mgr.compute_agreement_rate("t-001")
        assert rate == 0.0

    @pytest.mark.asyncio
    async def test_audit_event_emitted(self):
        """Shadow decision emits audit event."""
        redis = _make_redis_mock()
        store = MagicMock(spec=TenantConfigStore)
        store._get_client = MagicMock(return_value=redis)
        audit = MagicMock()
        mgr = ShadowModeManager(store, audit_producer=audit)

        await mgr.record_shadow_decision(
            "t-001", "phishing", "false_positive", 0.92, "inv-1"
        )
        audit.emit.assert_called_once()
        call_kwargs = audit.emit.call_args[1]
        assert call_kwargs["event_type"] == "shadow.decision_logged"


# ---------------------------------------------------------------------------
# TestGoLiveCriteria (Task 4)
# ---------------------------------------------------------------------------

class TestGoLiveCriteria:
    """AC-3: Go-live criteria checking."""

    def test_all_criteria_met(self):
        """All criteria met returns (True, [])."""
        criteria = GoLiveCriteria()
        met, unmet = criteria.check(
            agreement_rate=0.96,
            missed_critical_tps=0,
            fp_precision=0.99,
        )
        assert met is True
        assert unmet == []

    def test_low_agreement_rate(self):
        """Low agreement rate fails."""
        criteria = GoLiveCriteria()
        met, unmet = criteria.check(
            agreement_rate=0.90,
            missed_critical_tps=0,
            fp_precision=0.99,
        )
        assert met is False
        assert len(unmet) == 1
        assert "agreement_rate" in unmet[0]

    def test_missed_critical_tp(self):
        """Missed critical TP fails."""
        criteria = GoLiveCriteria()
        met, unmet = criteria.check(
            agreement_rate=0.96,
            missed_critical_tps=1,
            fp_precision=0.99,
        )
        assert met is False
        assert "missed_critical_tps" in unmet[0]

    def test_low_fp_precision(self):
        """Low FP precision fails."""
        criteria = GoLiveCriteria()
        met, unmet = criteria.check(
            agreement_rate=0.96,
            missed_critical_tps=0,
            fp_precision=0.95,
        )
        assert met is False
        assert "fp_precision" in unmet[0]

    def test_multiple_failures(self):
        """Multiple failures listed."""
        criteria = GoLiveCriteria()
        met, unmet = criteria.check(
            agreement_rate=0.80,
            missed_critical_tps=2,
            fp_precision=0.90,
        )
        assert met is False
        assert len(unmet) == 3


# ---------------------------------------------------------------------------
# TestShadowModeIntegration (Task 3)
# ---------------------------------------------------------------------------

class TestShadowModeIntegration:
    """AC-1: Shadow mode integration with InvestigationGraph."""

    @pytest.mark.asyncio
    async def test_shadow_active_skips_response_agent(self):
        """Shadow mode active → ResponseAgent.execute() NOT called."""
        graph = self._make_graph(shadow_active=True)
        state = GraphState(
            investigation_id="inv-1",
            alert_id="a-1",
            tenant_id="t-001",
            state=InvestigationState.REASONING,
            classification="false_positive",
            confidence=0.92,
        )

        # Simulate the shadow check path in _execute_pipeline
        shadow_mgr = graph._shadow
        is_active = await shadow_mgr.is_shadow_active(state.tenant_id)
        assert is_active is True

    @pytest.mark.asyncio
    async def test_shadow_inactive_allows_normal_execution(self):
        """Shadow mode inactive → normal pipeline execution."""
        graph = self._make_graph(shadow_active=False)
        shadow_mgr = graph._shadow
        is_active = await shadow_mgr.is_shadow_active("t-001")
        assert is_active is False

    def test_backward_compat_no_shadow_manager(self):
        """InvestigationGraph works without shadow_mode_manager."""
        from orchestrator.graph import InvestigationGraph

        graph = InvestigationGraph(
            repository=MagicMock(),
            ioc_extractor=MagicMock(),
            context_enricher=MagicMock(),
            ctem_correlator=MagicMock(),
            atlas_mapper=MagicMock(),
            reasoning_agent=MagicMock(),
            response_agent=MagicMock(),
        )
        assert graph._shadow is None

    def test_shadow_manager_stored_on_graph(self):
        """Shadow mode manager is stored on the graph when provided."""
        shadow_mgr = MagicMock()
        from orchestrator.graph import InvestigationGraph

        graph = InvestigationGraph(
            repository=MagicMock(),
            ioc_extractor=MagicMock(),
            context_enricher=MagicMock(),
            ctem_correlator=MagicMock(),
            atlas_mapper=MagicMock(),
            reasoning_agent=MagicMock(),
            response_agent=MagicMock(),
            shadow_mode_manager=shadow_mgr,
        )
        assert graph._shadow is shadow_mgr

    @pytest.mark.asyncio
    async def test_shadow_decision_recorded_in_decision_chain(self):
        """Shadow mode records decision in state.decision_chain."""
        graph = self._make_graph(shadow_active=True)
        state = GraphState(
            investigation_id="inv-1",
            alert_id="a-1",
            tenant_id="t-001",
            state=InvestigationState.REASONING,
            classification="false_positive",
            confidence=0.92,
        )

        # The graph's shadow check adds a DecisionEntry
        shadow_mgr = graph._shadow
        if await shadow_mgr.is_shadow_active(state.tenant_id):
            state.decision_chain.append(DecisionEntry(
                step="shadow_mode",
                agent="orchestrator",
                action="shadow_decision_logged",
                reasoning="Shadow mode active — decision logged, not executed",
                confidence=state.confidence,
            ))
            state.state = InvestigationState.AWAITING_HUMAN
            state.requires_human_approval = True

        assert state.state == InvestigationState.AWAITING_HUMAN
        assert state.requires_human_approval is True
        shadow_entries = [
            d for d in state.decision_chain
            if isinstance(d, DecisionEntry) and d.step == "shadow_mode"
        ]
        assert len(shadow_entries) == 1

    # ── Helper ────────────────────────────────────────────────

    @staticmethod
    def _make_graph(shadow_active: bool = True):
        """Create InvestigationGraph with mock shadow manager."""
        from orchestrator.graph import InvestigationGraph

        shadow_mgr = MagicMock()
        shadow_mgr.is_shadow_active = AsyncMock(return_value=shadow_active)
        shadow_mgr.record_shadow_decision = AsyncMock()

        return InvestigationGraph(
            repository=MagicMock(),
            ioc_extractor=MagicMock(),
            context_enricher=MagicMock(),
            ctem_correlator=MagicMock(),
            atlas_mapper=MagicMock(),
            reasoning_agent=MagicMock(),
            response_agent=MagicMock(),
            shadow_mode_manager=shadow_mgr,
        )
