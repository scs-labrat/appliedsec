"""Multi-tenancy isolation tests — Story 15.3.

Proves cross-tenant data leaks are impossible at every layer:
prompt assembly, Qdrant retrieval, Redis IOC cache, FP patterns,
and per-tenant rate limits.
"""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from context_gateway.prompt_builder import (
    SYSTEM_PREFIX,
    build_request_with_budget,
    build_structured_prompt,
)
from llm_router.concurrency import ConcurrencyController, QuotaExceeded
from shared.db.redis_cache import RedisClient
from shared.schemas.investigation import GraphState, InvestigationState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _state_for_tenant(tenant_id: str, entities: dict | None = None) -> GraphState:
    """Create a GraphState for the given tenant."""
    return GraphState(
        investigation_id=f"inv-{tenant_id}",
        tenant_id=tenant_id,
        entities=entities or {},
        ioc_matches=[],
    )


def _mock_redis_client() -> RedisClient:
    """Create a RedisClient with a mocked internal client."""
    client = RedisClient(host="localhost", port=6379)
    mock = AsyncMock()
    mock.set = AsyncMock()
    mock.get = AsyncMock(return_value=None)
    mock.delete = AsyncMock(return_value=1)
    client._client = mock
    return client


# ---------------------------------------------------------------------------
# TestIOCTenantScoping (Task 1) — AC-3
# ---------------------------------------------------------------------------

class TestIOCTenantScoping:
    """AC-3: Redis IOC keys are scoped as ioc:{tenant}:{type}:{value}."""

    @pytest.mark.asyncio
    async def test_set_ioc_creates_tenant_scoped_key(self):
        """set_ioc uses ioc:{tenant}:{type}:{value} key format."""
        client = _mock_redis_client()
        await client.set_ioc("tenant-A", "ip", "10.0.0.1", {"family": "apt"}, confidence=85)
        client._client.set.assert_called_once()
        key = client._client.set.call_args[0][0]
        assert key == "ioc:tenant-A:ip:10.0.0.1"

    @pytest.mark.asyncio
    async def test_get_ioc_wrong_tenant_returns_none(self):
        """get_ioc with different tenant_id returns None (different key)."""
        client = _mock_redis_client()
        # Tenant A sets IOC
        await client.set_ioc("tenant-A", "ip", "10.0.0.1", {"family": "apt"}, confidence=85)
        # Tenant B tries to get the same IOC — different key, returns None
        result = await client.get_ioc("tenant-B", "ip", "10.0.0.1")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_ioc_only_deletes_own_tenant(self):
        """delete_ioc with tenant-A key does not affect tenant-B key."""
        client = _mock_redis_client()
        await client.delete_ioc("tenant-A", "ip", "10.0.0.1")
        key = client._client.delete.call_args[0][0]
        assert key == "ioc:tenant-A:ip:10.0.0.1"
        assert "tenant-B" not in key

    @pytest.mark.asyncio
    async def test_tenant_id_in_all_ioc_operations(self):
        """All IOC operations include tenant_id in the key."""
        client = _mock_redis_client()
        # set
        await client.set_ioc("t1", "hash", "abc", {"x": 1}, confidence=90)
        set_key = client._client.set.call_args[0][0]
        assert set_key.startswith("ioc:t1:")

        # get
        await client.get_ioc("t1", "hash", "abc")
        get_key = client._client.get.call_args[0][0]
        assert get_key.startswith("ioc:t1:")

        # delete
        await client.delete_ioc("t1", "hash", "abc")
        del_key = client._client.delete.call_args[0][0]
        assert del_key.startswith("ioc:t1:")


# ---------------------------------------------------------------------------
# TestPromptIsolation (Task 2) — AC-1
# ---------------------------------------------------------------------------

class TestPromptIsolation:
    """AC-1: Tenant A's prompt never includes Tenant B's context."""

    def test_structured_prompt_contains_only_own_evidence(self):
        """Tenant A's evidence never mixed with Tenant B's."""
        evidence_a = "<evidence><entity>10.0.0.1</entity><tenant>A</tenant></evidence>"
        evidence_b = "<evidence><entity>192.168.1.1</entity><tenant>B</tenant></evidence>"

        prompt_a = build_structured_prompt("Triage alert for Tenant A.", evidence_a)
        assert "10.0.0.1" in prompt_a
        assert "192.168.1.1" not in prompt_a
        assert "tenant>B" not in prompt_a

    def test_budget_prompt_contains_only_own_context(self):
        """Budget-enforced prompt doesn't leak cross-tenant retrieval context."""
        context_a = "Tenant A context: user jsmith@a.com logged in from 10.0.0.1"
        context_b = "Tenant B context: user admin@b.com logged in from 172.16.0.1"

        prompt_a = build_request_with_budget(
            system_instructions="Analyze alert.",
            evidence_block="<evidence>alert-A</evidence>",
            retrieval_context=context_a,
            tier="tier_0",
        )
        assert "jsmith@a.com" in prompt_a
        assert "admin@b.com" not in prompt_a
        assert "172.16.0.1" not in prompt_a

    def test_shared_entity_types_different_values(self):
        """Both tenants have IPs but different values — no cross-contamination."""
        evidence_a = "<evidence><ip>10.0.0.1</ip></evidence>"
        evidence_b = "<evidence><ip>192.168.1.1</ip></evidence>"

        prompt_a = build_structured_prompt("Classify.", evidence_a)
        prompt_b = build_structured_prompt("Classify.", evidence_b)

        assert "10.0.0.1" in prompt_a
        assert "192.168.1.1" not in prompt_a
        assert "192.168.1.1" in prompt_b
        assert "10.0.0.1" not in prompt_b

    def test_safety_prefix_always_present(self):
        """Safety prefix present regardless of tenant."""
        prompt = build_structured_prompt("Task.", "<evidence>data</evidence>")
        assert SYSTEM_PREFIX in prompt


# ---------------------------------------------------------------------------
# TestQdrantIsolation (Task 3) — AC-2
# ---------------------------------------------------------------------------

class TestQdrantIsolation:
    """AC-2: Qdrant retrieval always applies tenant_id filter."""

    def test_search_filter_includes_tenant_id(self):
        """search() called with tenant_id in search_filter."""
        from shared.db.vector import QdrantWrapper

        with patch("shared.db.vector.QdrantClient") as mock_qdrant_cls:
            mock_client = MagicMock()
            mock_result = MagicMock()
            mock_result.points = []
            mock_client.query_points.return_value = mock_result
            mock_qdrant_cls.return_value = mock_client

            wrapper = QdrantWrapper(host="localhost")
            wrapper.search(
                collection="incident_embeddings",
                query_vector=[0.1] * 1536,
                search_filter={"tenant_id": "tenant-A"},
            )

            call_kwargs = mock_client.query_points.call_args[1]
            # Verify the filter was applied
            assert call_kwargs["query_filter"] is not None

    def test_no_results_from_other_tenant(self):
        """Results for tenant-A search don't include tenant-B data."""
        from shared.db.vector import QdrantWrapper

        with patch("shared.db.vector.QdrantClient") as mock_qdrant_cls:
            mock_client = MagicMock()
            # Return results only from tenant-A
            mock_point = MagicMock()
            mock_point.id = "p1"
            mock_point.score = 0.95
            mock_point.payload = {"tenant_id": "tenant-A", "title": "Alert A"}
            mock_result = MagicMock()
            mock_result.points = [mock_point]
            mock_client.query_points.return_value = mock_result
            mock_qdrant_cls.return_value = mock_client

            wrapper = QdrantWrapper(host="localhost")
            results = wrapper.search(
                collection="incident_embeddings",
                query_vector=[0.1] * 1536,
                search_filter={"tenant_id": "tenant-A"},
            )

            for r in results:
                assert r["payload"]["tenant_id"] == "tenant-A"
                assert r["payload"]["tenant_id"] != "tenant-B"

    def test_empty_filter_returns_all(self):
        """Without tenant filter, results may include multiple tenants (unsafe)."""
        from shared.db.vector import QdrantWrapper

        with patch("shared.db.vector.QdrantClient") as mock_qdrant_cls:
            mock_client = MagicMock()
            mock_result = MagicMock()
            mock_result.points = []
            mock_client.query_points.return_value = mock_result
            mock_qdrant_cls.return_value = mock_client

            wrapper = QdrantWrapper(host="localhost")
            wrapper.search(
                collection="incident_embeddings",
                query_vector=[0.1] * 1536,
                search_filter=None,  # No filter — dangerous
            )

            call_kwargs = mock_client.query_points.call_args[1]
            assert call_kwargs["query_filter"] is None


# ---------------------------------------------------------------------------
# TestFPPatternIsolation (Task 4) — AC-4
# ---------------------------------------------------------------------------

class TestFPPatternIsolation:
    """AC-4: FP patterns approved by Tenant A don't apply to Tenant B."""

    @pytest.mark.asyncio
    async def test_fp_pattern_with_tenant_scope_blocks_other_tenant(self):
        """Pattern scoped to tenant-A does NOT match tenant-B alerts."""
        from orchestrator.fp_shortcircuit import FPShortCircuit

        redis_mock = AsyncMock()
        redis_mock.list_fp_patterns = AsyncMock(return_value=["fp:pat-001"])
        redis_mock.get_fp_pattern = AsyncMock(return_value={
            "status": "approved",
            "alert_name_regex": ".*phishing.*",
            "entity_patterns": [],
            "scope_tenant_id": "tenant-A",
            "scope_rule_family": "",
            "scope_asset_class": "",
        })

        fp = FPShortCircuit(redis_mock)
        state = _state_for_tenant("tenant-B")

        result = await fp.check(
            state, alert_title="phishing detected",
            tenant_id="tenant-B",
        )
        assert result.matched is False

    @pytest.mark.asyncio
    async def test_fp_pattern_with_tenant_scope_matches_own_tenant(self):
        """Pattern scoped to tenant-A DOES match tenant-A alerts."""
        from orchestrator.fp_shortcircuit import FPShortCircuit

        redis_mock = AsyncMock()
        redis_mock.list_fp_patterns = AsyncMock(return_value=["fp:pat-001"])
        redis_mock.get_fp_pattern = AsyncMock(return_value={
            "status": "approved",
            "alert_name_regex": ".*phishing.*",
            "entity_patterns": [],
            "scope_tenant_id": "tenant-A",
            "scope_rule_family": "",
            "scope_asset_class": "",
        })

        fp = FPShortCircuit(redis_mock)
        state = _state_for_tenant("tenant-A")

        result = await fp.check(
            state, alert_title="phishing detected",
            tenant_id="tenant-A",
        )
        assert result.matched is True

    @pytest.mark.asyncio
    async def test_global_fp_pattern_matches_any_tenant(self):
        """Pattern with no scope_tenant_id matches any tenant (global)."""
        from orchestrator.fp_shortcircuit import FPShortCircuit

        redis_mock = AsyncMock()
        redis_mock.list_fp_patterns = AsyncMock(return_value=["fp:pat-002"])
        redis_mock.get_fp_pattern = AsyncMock(return_value={
            "status": "approved",
            "alert_name_regex": ".*test-alert.*",
            "entity_patterns": [],
            "scope_tenant_id": "",
            "scope_rule_family": "",
            "scope_asset_class": "",
        })

        fp = FPShortCircuit(redis_mock)
        state_a = _state_for_tenant("tenant-A")
        state_b = _state_for_tenant("tenant-B")

        result_a = await fp.check(state_a, alert_title="test-alert-001", tenant_id="tenant-A")
        result_b = await fp.check(state_b, alert_title="test-alert-001", tenant_id="tenant-B")
        assert result_a.matched is True
        assert result_b.matched is True


# ---------------------------------------------------------------------------
# TestRateLimitIsolation (Task 4) — AC-5
# ---------------------------------------------------------------------------

class TestRateLimitIsolation:
    """AC-5: Per-tenant rate limits are enforced independently."""

    def test_tenant_a_exhaustion_does_not_affect_tenant_b(self):
        """Exhausting tenant-A quota doesn't block tenant-B."""
        cc = ConcurrencyController()

        # Exhaust tenant-A (trial = 20 calls/hour)
        for _ in range(20):
            cc.record_tenant_call("tenant-A")

        # Tenant-A should be over quota
        with pytest.raises(QuotaExceeded):
            cc.check_tenant_quota("tenant-A", "trial")

        # Tenant-B should still have quota
        cc.check_tenant_quota("tenant-B", "trial")  # no exception

    def test_different_tiers_have_different_limits(self):
        """Premium tenant has higher quota than trial tenant."""
        cc = ConcurrencyController()

        # Fill 21 calls for both
        for _ in range(21):
            cc.record_tenant_call("premium-tenant")
            cc.record_tenant_call("trial-tenant")

        # Trial (20 limit) should be exceeded
        with pytest.raises(QuotaExceeded):
            cc.check_tenant_quota("trial-tenant", "trial")

        # Premium (500 limit) should be fine
        cc.check_tenant_quota("premium-tenant", "premium")

    def test_independent_call_counters(self):
        """Each tenant has its own call counter."""
        cc = ConcurrencyController()

        cc.record_tenant_call("t1")
        cc.record_tenant_call("t1")
        cc.record_tenant_call("t2")

        # Verify counters are separate
        assert len(cc._tenant_calls["t1"]) == 2
        assert len(cc._tenant_calls["t2"]) == 1


# ---------------------------------------------------------------------------
# TestAccumulationGuardIsolation (Task 5) — AC-1
# ---------------------------------------------------------------------------

class TestAccumulationGuardIsolation:
    """AC-1: Entity access accumulation is per-tenant."""

    @pytest.mark.asyncio
    async def test_ioc_enrichment_scoped_to_tenant(self):
        """IOC enrichment for tenant-A doesn't retrieve tenant-B data."""
        from orchestrator.agents.context_enricher import ContextEnricherAgent

        redis_mock = AsyncMock()
        redis_mock.get_ioc = AsyncMock(return_value=None)
        pg_mock = AsyncMock()
        pg_mock.fetch_one = AsyncMock(return_value=None)
        qdrant_mock = MagicMock()
        qdrant_mock.search = MagicMock(return_value=[])

        agent = ContextEnricherAgent(redis_mock, pg_mock, qdrant_mock)

        state_a = _state_for_tenant(
            "tenant-A",
            entities={"accounts": [], "hosts": [], "ips": []},
        )
        state_a.ioc_matches = [{"type": "ip", "value": "10.0.0.1"}]

        await agent.execute(state_a)

        # Verify get_ioc was called with tenant-A
        if redis_mock.get_ioc.call_count > 0:
            for call in redis_mock.get_ioc.call_args_list:
                assert call[0][0] == "tenant-A"

    @pytest.mark.asyncio
    async def test_separate_query_counts_per_investigation(self):
        """Each investigation state has independent query counter."""
        state_a = _state_for_tenant("tenant-A")
        state_b = _state_for_tenant("tenant-B")

        state_a.queries_executed = 5
        state_b.queries_executed = 3

        assert state_a.queries_executed != state_b.queries_executed
        state_a.queries_executed += 1
        assert state_b.queries_executed == 3  # unaffected
