"""Tests for FP canary rollout manager — Story 14.3."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from orchestrator.fp_canary import (
    DEFAULT_MAX_DISAGREEMENT_RATE,
    DEFAULT_PROMOTION_THRESHOLD,
    FPCanaryManager,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_redis_mock() -> AsyncMock:
    """Create a mock async Redis that stores counters in a dict."""
    store: dict[str, str] = {}
    mock = AsyncMock()

    async def _get(key: str) -> str | None:
        return store.get(key)

    async def _set(key: str, value: str, **kwargs) -> None:
        store[key] = value

    async def _incr(key: str) -> int:
        val = int(store.get(key, "0")) + 1
        store[key] = str(val)
        return val

    mock.get = AsyncMock(side_effect=_get)
    mock.set = AsyncMock(side_effect=_set)
    mock.incr = AsyncMock(side_effect=_incr)
    mock._store = store
    return mock


def _make_redis_client_mock() -> MagicMock:
    """Create a mock RedisClient wrapper with _client attribute."""
    inner = _make_redis_mock()
    client = MagicMock()
    client._client = inner
    return client


# ---------------------------------------------------------------------------
# TestFPCanaryManager (Task 2)
# ---------------------------------------------------------------------------

class TestFPCanaryManager:
    """AC-2,3: Canary shadow decisions, promotion, disagreement blocking."""

    @pytest.mark.asyncio
    async def test_record_increments_counters(self):
        """Recording shadow decision increments total and agree/disagree."""
        redis = _make_redis_client_mock()
        canary = FPCanaryManager(redis)

        await canary.record_shadow_decision("pat-1", "auto_close", "auto_close")
        store = redis._client._store
        assert store.get("canary:pat-1:total") == "1"
        assert store.get("canary:pat-1:agree") == "1"

    @pytest.mark.asyncio
    async def test_disagreement_recorded(self):
        """Disagreeing decisions increment disagree counter."""
        redis = _make_redis_client_mock()
        canary = FPCanaryManager(redis)

        await canary.record_shadow_decision("pat-1", "auto_close", "escalate")
        store = redis._client._store
        assert store.get("canary:pat-1:total") == "1"
        assert store.get("canary:pat-1:disagree") == "1"

    @pytest.mark.asyncio
    async def test_get_canary_stats(self):
        """Stats reflect recorded decisions correctly."""
        redis = _make_redis_client_mock()
        canary = FPCanaryManager(redis)

        # 3 agreements, 1 disagreement
        for _ in range(3):
            await canary.record_shadow_decision("pat-1", "auto_close", "auto_close")
        await canary.record_shadow_decision("pat-1", "auto_close", "escalate")

        stats = await canary.get_canary_stats("pat-1")
        assert stats["total_decisions"] == 4
        assert stats["agreements"] == 3
        assert stats["disagreements"] == 1
        assert stats["agreement_rate"] == pytest.approx(0.75)

    @pytest.mark.asyncio
    async def test_promotes_after_threshold_agreements(self):
        """Pattern promotes after 50 correct decisions with low disagreement."""
        redis = _make_redis_client_mock()
        canary = FPCanaryManager(redis)

        for _ in range(50):
            await canary.record_shadow_decision("pat-1", "auto_close", "auto_close")

        assert await canary.should_promote("pat-1") is True

    @pytest.mark.asyncio
    async def test_does_not_promote_below_threshold(self):
        """Pattern does NOT promote if total < promotion_threshold."""
        redis = _make_redis_client_mock()
        canary = FPCanaryManager(redis)

        for _ in range(49):
            await canary.record_shadow_decision("pat-1", "auto_close", "auto_close")

        assert await canary.should_promote("pat-1") is False

    @pytest.mark.asyncio
    async def test_does_not_promote_high_disagreement(self):
        """Pattern does NOT promote if disagreement > 5%."""
        redis = _make_redis_client_mock()
        canary = FPCanaryManager(redis)

        # 47 agreements, 3 disagreements = 6% disagreement
        for _ in range(47):
            await canary.record_shadow_decision("pat-1", "auto_close", "auto_close")
        for _ in range(3):
            await canary.record_shadow_decision("pat-1", "auto_close", "escalate")

        assert await canary.should_promote("pat-1") is False

    @pytest.mark.asyncio
    async def test_promote_updates_pattern_status(self):
        """Promote changes pattern status from shadow to active in Redis."""
        redis = _make_redis_client_mock()
        canary = FPCanaryManager(redis)

        # Pre-store a shadow pattern
        redis._client._store["fp:pat-1"] = json.dumps({
            "pattern_id": "pat-1",
            "status": "shadow",
        })

        await canary.promote("pat-1")
        updated = json.loads(redis._client._store["fp:pat-1"])
        assert updated["status"] == "active"

    @pytest.mark.asyncio
    async def test_default_constants(self):
        """Default promotion threshold and max disagreement rate."""
        assert DEFAULT_PROMOTION_THRESHOLD == 50
        assert DEFAULT_MAX_DISAGREEMENT_RATE == 0.05

    @pytest.mark.asyncio
    async def test_custom_threshold(self):
        """Custom promotion threshold is respected."""
        redis = _make_redis_client_mock()
        canary = FPCanaryManager(redis, promotion_threshold=10)

        for _ in range(10):
            await canary.record_shadow_decision("pat-1", "auto_close", "auto_close")

        assert await canary.should_promote("pat-1") is True


# ---------------------------------------------------------------------------
# TestShadowStatus (Task 4)
# ---------------------------------------------------------------------------

class TestShadowStatus:
    """AC-2: Shadow status in FPPatternStatus and FPShortCircuit."""

    def test_shadow_status_valid_enum(self):
        """SHADOW is a valid FPPatternStatus value."""
        from batch_scheduler.models import FPPatternStatus
        assert FPPatternStatus.SHADOW.value == "shadow"

    def test_fp_pattern_status_has_seven_values(self):
        """FPPatternStatus has 7 values including SHADOW, EXPIRED, REVOKED."""
        from batch_scheduler.models import FPPatternStatus
        assert len(FPPatternStatus) == 7

    @pytest.mark.asyncio
    async def test_shadow_patterns_skipped_in_matching(self):
        """Shadow patterns are excluded from active FP matching."""
        from orchestrator.fp_shortcircuit import FPShortCircuit
        from shared.schemas.investigation import GraphState

        redis = AsyncMock()
        redis.list_fp_patterns = AsyncMock(return_value=["fp:shadow-pat"])
        redis.get_fp_pattern = AsyncMock(return_value={
            "status": "shadow",
            "alert_name_regex": ".*Brute.*",
            "entity_patterns": [],
        })

        shortcircuit = FPShortCircuit(redis)
        state = GraphState(investigation_id="inv-1", alert_id="a-1", tenant_id="t-001")
        result = await shortcircuit.check(state, "Brute Force Login")
        assert result.matched is False
