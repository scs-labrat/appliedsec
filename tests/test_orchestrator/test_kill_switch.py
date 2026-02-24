"""Tests for kill switch manager — Story 14.3."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from orchestrator.kill_switch import KILL_SWITCH_DIMENSIONS, KillSwitchManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_redis_mock() -> AsyncMock:
    """Create a mock Redis client that stores keys in a dict."""
    store: dict[str, str] = {}
    mock = AsyncMock()

    async def _set(key: str, value: str, **kwargs) -> None:
        store[key] = value

    async def _get(key: str) -> str | None:
        return store.get(key)

    async def _delete(key: str) -> int:
        if key in store:
            del store[key]
            return 1
        return 0

    mock.set = AsyncMock(side_effect=_set)
    mock.get = AsyncMock(side_effect=_get)
    mock.delete = AsyncMock(side_effect=_delete)
    mock._store = store  # For test inspection
    return mock


def _make_redis_client_mock() -> MagicMock:
    """Create a mock RedisClient wrapper with _client attribute."""
    inner = _make_redis_mock()
    client = MagicMock()
    client._client = inner
    return client


# ---------------------------------------------------------------------------
# TestKillSwitchManager (Task 1)
# ---------------------------------------------------------------------------

class TestKillSwitchManager:
    """AC-1,4,5: Kill switch activation/deactivation/checking."""

    @pytest.mark.asyncio
    async def test_activate_sets_redis_key(self):
        """Activating sets the correct Redis key with metadata."""
        redis = _make_redis_client_mock()
        mgr = KillSwitchManager(redis)
        await mgr.activate("tenant", "t-001", "analyst@org", reason="incident")

        key = "kill_switch:tenant:t-001"
        assert key in redis._client._store
        data = json.loads(redis._client._store[key])
        assert data["activated_by"] == "analyst@org"
        assert data["reason"] == "incident"
        assert data["dimension"] == "tenant"

    @pytest.mark.asyncio
    async def test_is_killed_returns_true_for_active_switch(self):
        """is_killed returns True when tenant switch is active."""
        redis = _make_redis_client_mock()
        mgr = KillSwitchManager(redis)
        await mgr.activate("tenant", "t-001", "analyst@org")

        assert await mgr.is_killed(tenant_id="t-001") is True

    @pytest.mark.asyncio
    async def test_is_killed_returns_false_when_no_switch(self):
        """is_killed returns False when no switches are active."""
        redis = _make_redis_client_mock()
        mgr = KillSwitchManager(redis)

        assert await mgr.is_killed(tenant_id="t-001") is False

    @pytest.mark.asyncio
    async def test_deactivate_removes_key(self):
        """Deactivating removes the Redis key."""
        redis = _make_redis_client_mock()
        mgr = KillSwitchManager(redis)
        await mgr.activate("tenant", "t-001", "analyst@org")
        assert await mgr.is_killed(tenant_id="t-001") is True

        await mgr.deactivate("tenant", "t-001", "analyst@org")
        assert await mgr.is_killed(tenant_id="t-001") is False

    @pytest.mark.asyncio
    async def test_audit_event_emitted_on_activate(self):
        """Audit producer receives kill_switch.activated event."""
        redis = _make_redis_client_mock()
        audit = AsyncMock()
        mgr = KillSwitchManager(redis, audit_producer=audit)

        await mgr.activate("tenant", "t-001", "analyst@org")
        audit.emit.assert_awaited_once()
        call_kwargs = audit.emit.call_args[1]
        assert call_kwargs["event_type"] == "kill_switch.activated"
        assert call_kwargs["data"]["dimension"] == "tenant"

    @pytest.mark.asyncio
    async def test_audit_event_emitted_on_deactivate(self):
        """Audit producer receives kill_switch.deactivated event."""
        redis = _make_redis_client_mock()
        audit = AsyncMock()
        mgr = KillSwitchManager(redis, audit_producer=audit)

        await mgr.deactivate("tenant", "t-001", "analyst@org")
        call_kwargs = audit.emit.call_args[1]
        assert call_kwargs["event_type"] == "kill_switch.deactivated"

    @pytest.mark.asyncio
    async def test_per_technique_kill_switch(self):
        """Technique-level kill switch blocks matching alerts."""
        redis = _make_redis_client_mock()
        mgr = KillSwitchManager(redis)
        await mgr.activate("technique", "T1078", "analyst@org")

        assert await mgr.is_killed(
            tenant_id="t-001", technique_id="T1078"
        ) is True
        # Different technique not killed
        assert await mgr.is_killed(
            tenant_id="t-001", technique_id="T1059"
        ) is False

    @pytest.mark.asyncio
    async def test_per_pattern_kill_switch(self):
        """Pattern-level kill switch blocks that specific pattern."""
        redis = _make_redis_client_mock()
        mgr = KillSwitchManager(redis)
        await mgr.activate("pattern", "pat-123", "analyst@org")

        assert await mgr.is_killed(
            tenant_id="t-001", pattern_id="pat-123"
        ) is True
        assert await mgr.is_killed(
            tenant_id="t-001", pattern_id="pat-999"
        ) is False

    @pytest.mark.asyncio
    async def test_per_datasource_kill_switch(self):
        """Datasource-level kill switch blocks that datasource."""
        redis = _make_redis_client_mock()
        mgr = KillSwitchManager(redis)
        await mgr.activate("datasource", "sentinel", "analyst@org")

        assert await mgr.is_killed(
            tenant_id="t-001", data_source="sentinel"
        ) is True
        assert await mgr.is_killed(
            tenant_id="t-001", data_source="crowdstrike"
        ) is False

    @pytest.mark.asyncio
    async def test_invalid_dimension_raises(self):
        """Invalid dimension raises ValueError."""
        redis = _make_redis_client_mock()
        mgr = KillSwitchManager(redis)
        with pytest.raises(ValueError, match="Invalid dimension"):
            await mgr.activate("invalid_dim", "val", "analyst@org")

    @pytest.mark.asyncio
    async def test_dimensions_constant(self):
        """Kill switch dimensions are the expected four."""
        assert KILL_SWITCH_DIMENSIONS == (
            "tenant", "pattern", "technique", "datasource"
        )

    @pytest.mark.asyncio
    async def test_no_audit_producer_no_error(self):
        """Works fine without audit producer (None)."""
        redis = _make_redis_client_mock()
        mgr = KillSwitchManager(redis, audit_producer=None)
        await mgr.activate("tenant", "t-001", "analyst@org")
        assert await mgr.is_killed(tenant_id="t-001") is True


# ---------------------------------------------------------------------------
# TestKillSwitchIntegration (Task 3)
# ---------------------------------------------------------------------------

class TestKillSwitchIntegration:
    """AC-1,5: Kill switch integration with FPShortCircuit."""

    @pytest.mark.asyncio
    async def test_kill_switch_active_blocks_match(self):
        """When kill switch is active, FPShortCircuit returns no match."""
        from orchestrator.fp_shortcircuit import FPShortCircuit, FPMatchResult
        from shared.schemas.investigation import GraphState

        # Set up Redis with one approved FP pattern
        redis = AsyncMock()
        redis.list_fp_patterns = AsyncMock(return_value=["fp:pat-001"])
        redis.get_fp_pattern = AsyncMock(return_value={
            "status": "approved",
            "alert_name_regex": ".*Brute.*",
            "entity_patterns": [],
        })

        # Set up kill switch
        ks_redis = _make_redis_client_mock()
        ks = KillSwitchManager(ks_redis)
        await ks.activate("tenant", "t-001", "analyst@org")

        shortcircuit = FPShortCircuit(redis, kill_switch_manager=ks)
        state = GraphState(investigation_id="inv-1", alert_id="a-1", tenant_id="t-001")
        result = await shortcircuit.check(
            state, "Brute Force Login", tenant_id="t-001"
        )
        assert result.matched is False

    @pytest.mark.asyncio
    async def test_kill_switch_inactive_allows_match(self):
        """When no kill switch active, FPShortCircuit matches normally."""
        from orchestrator.fp_shortcircuit import FPShortCircuit

        redis = AsyncMock()
        redis.list_fp_patterns = AsyncMock(return_value=["fp:pat-001"])
        redis.get_fp_pattern = AsyncMock(return_value={
            "status": "approved",
            "alert_name_regex": ".*Brute.*",
            "entity_patterns": [],
        })

        ks_redis = _make_redis_client_mock()
        ks = KillSwitchManager(ks_redis)
        # No kill switch activated

        shortcircuit = FPShortCircuit(redis, kill_switch_manager=ks)
        from shared.schemas.investigation import GraphState
        state = GraphState(investigation_id="inv-1", alert_id="a-1", tenant_id="t-001")
        result = await shortcircuit.check(
            state, "Brute Force Login", tenant_id="t-001"
        )
        assert result.matched is True

    @pytest.mark.asyncio
    async def test_no_kill_switch_manager_backward_compat(self):
        """FPShortCircuit with no kill_switch_manager works as before."""
        from orchestrator.fp_shortcircuit import FPShortCircuit

        redis = AsyncMock()
        redis.list_fp_patterns = AsyncMock(return_value=["fp:pat-001"])
        redis.get_fp_pattern = AsyncMock(return_value={
            "status": "approved",
            "alert_name_regex": ".*Brute.*",
            "entity_patterns": [],
        })

        shortcircuit = FPShortCircuit(redis)  # No kill_switch_manager
        from shared.schemas.investigation import GraphState
        state = GraphState(investigation_id="inv-1", alert_id="a-1", tenant_id="t-001")
        result = await shortcircuit.check(state, "Brute Force Login")
        assert result.matched is True

    @pytest.mark.asyncio
    async def test_per_pattern_kill_switch_blocks_specific_pattern(self):
        """Per-pattern kill switch blocks that pattern but not others."""
        from orchestrator.fp_shortcircuit import FPShortCircuit
        from shared.schemas.investigation import GraphState

        redis = AsyncMock()
        redis.list_fp_patterns = AsyncMock(return_value=["fp:t-001:blocked-pat", "fp:t-001:allowed-pat"])

        async def _get_pattern(tenant, pid):
            if pid == "blocked-pat":
                return {
                    "status": "approved",
                    "alert_name_regex": ".*Brute.*",
                    "entity_patterns": [],
                }
            elif pid == "allowed-pat":
                return {
                    "status": "approved",
                    "alert_name_regex": ".*Brute.*",
                    "entity_patterns": [],
                }
            return None

        redis.get_fp_pattern = AsyncMock(side_effect=_get_pattern)

        ks_redis = _make_redis_client_mock()
        ks = KillSwitchManager(ks_redis)
        await ks.activate("pattern", "blocked-pat", "analyst@org")

        shortcircuit = FPShortCircuit(redis, kill_switch_manager=ks)
        state = GraphState(investigation_id="inv-1", alert_id="a-1", tenant_id="t-001")
        result = await shortcircuit.check(
            state, "Brute Force Login", tenant_id="t-001"
        )
        # blocked-pat is killed, but allowed-pat should still match
        assert result.matched is True
        assert result.pattern_id == "allowed-pat"
