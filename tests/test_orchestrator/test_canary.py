"""Tests for canary rollout strategy — Story 14.9."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from orchestrator.canary import (
    CANARY_ACTIVE,
    CANARY_PROMOTED,
    CANARY_ROLLED_BACK,
    CanaryConfig,
    CanaryEvaluator,
    CanaryRolloutManager,
    CanarySlice,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _old_date(days_ago: int = 10) -> str:
    """Return an ISO timestamp from `days_ago` days in the past."""
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _make_manager(audit: MagicMock | None = None) -> CanaryRolloutManager:
    """Create a CanaryRolloutManager with mock dependencies."""
    kill_switch = AsyncMock()
    shadow = AsyncMock()
    return CanaryRolloutManager(kill_switch, shadow, audit_producer=audit)


# ---------------------------------------------------------------------------
# TestCanarySlice (Task 1)
# ---------------------------------------------------------------------------

class TestCanarySlice:
    """AC-1: CanarySlice configuration."""

    def test_defaults(self):
        """Slice has correct defaults."""
        s = CanarySlice(slice_id="s-1", dimension="tenant", value="t-001")
        assert s.status == CANARY_ACTIVE
        assert s.promoted_at == ""
        assert s.created_at != ""

    def test_age_days(self):
        """age_days computed from created_at."""
        s = CanarySlice(
            slice_id="s-1", dimension="tenant", value="t-001",
            created_at=_old_date(10),
        )
        assert s.age_days >= 9.9

    def test_config_defaults(self):
        """CanaryConfig has correct defaults."""
        cfg = CanaryConfig()
        assert cfg.promotion_days == 7
        assert cfg.min_precision == 0.98
        assert cfg.rollback_precision == 0.95


# ---------------------------------------------------------------------------
# TestCanaryRolloutManager (Task 2)
# ---------------------------------------------------------------------------

class TestCanaryRolloutManager:
    """AC-1,2,3,4: Canary promotion and rollback."""

    @pytest.mark.asyncio
    async def test_promote_after_7_days_precision_met(self):
        """Promote when 7 days passed, precision >= 98%, 0 missed TPs."""
        mgr = _make_manager()
        s = CanarySlice(
            slice_id="s-1", dimension="rule_family", value="phishing",
            created_at=_old_date(8),
        )
        result = await mgr.check_promotion(s, precision=0.99, missed_tps=0)
        assert result == "promote"

    @pytest.mark.asyncio
    async def test_continue_if_too_young(self):
        """Continue when < 7 days, even if precision is met."""
        mgr = _make_manager()
        s = CanarySlice(
            slice_id="s-2", dimension="rule_family", value="phishing",
            created_at=_old_date(3),
        )
        result = await mgr.check_promotion(s, precision=0.99, missed_tps=0)
        assert result == "continue"

    @pytest.mark.asyncio
    async def test_rollback_on_low_precision(self):
        """Rollback when precision drops below 95%."""
        mgr = _make_manager()
        s = CanarySlice(
            slice_id="s-3", dimension="tenant", value="t-001",
            created_at=_old_date(10),
        )
        result = await mgr.check_promotion(s, precision=0.93, missed_tps=0)
        assert result == "rollback"

    @pytest.mark.asyncio
    async def test_rollback_on_missed_tp(self):
        """Rollback when any missed TP detected."""
        mgr = _make_manager()
        s = CanarySlice(
            slice_id="s-4", dimension="rule_family", value="malware",
            created_at=_old_date(10),
        )
        result = await mgr.check_promotion(s, precision=0.99, missed_tps=1)
        assert result == "rollback"

    @pytest.mark.asyncio
    async def test_promote_sets_status(self):
        """promote() sets slice status to promoted."""
        mgr = _make_manager()
        s = CanarySlice(
            slice_id="s-5", dimension="rule_family", value="phishing",
            created_at=_old_date(8),
        )
        await mgr.promote(s)
        assert s.status == CANARY_PROMOTED
        assert s.promoted_at != ""

    @pytest.mark.asyncio
    async def test_rollback_activates_kill_switch(self):
        """rollback() activates kill switch for the affected dimension."""
        mgr = _make_manager()
        s = CanarySlice(
            slice_id="s-6", dimension="tenant", value="t-001",
            created_at=_old_date(10),
        )
        await mgr.rollback(s, "precision_below_threshold")
        assert s.status == CANARY_ROLLED_BACK
        mgr._kill_switch.activate.assert_awaited_once()
        call_kwargs = mgr._kill_switch.activate.call_args[1]
        assert call_kwargs["dimension"] == "tenant"
        assert call_kwargs["value"] == "t-001"

    @pytest.mark.asyncio
    async def test_rollback_emits_audit_event(self):
        """rollback() emits audit event."""
        audit = MagicMock()
        mgr = _make_manager(audit=audit)
        s = CanarySlice(
            slice_id="s-7", dimension="rule_family", value="malware",
            created_at=_old_date(10),
        )
        await mgr.rollback(s, "missed_tp")
        audit.emit.assert_called()
        call_kwargs = audit.emit.call_args[1]
        assert call_kwargs["event_type"] == "canary.rolled_back"

    @pytest.mark.asyncio
    async def test_promote_emits_audit_event(self):
        """promote() emits audit event."""
        audit = MagicMock()
        mgr = _make_manager(audit=audit)
        s = CanarySlice(
            slice_id="s-8", dimension="tenant", value="t-001",
            created_at=_old_date(8),
        )
        await mgr.promote(s)
        audit.emit.assert_called_once()
        call_kwargs = audit.emit.call_args[1]
        assert call_kwargs["event_type"] == "canary.promoted"

    @pytest.mark.asyncio
    async def test_rollout_history(self):
        """get_rollout_history() returns all events."""
        mgr = _make_manager()
        s1 = CanarySlice(slice_id="s-a", dimension="tenant", value="t-001", created_at=_old_date(8))
        s2 = CanarySlice(slice_id="s-b", dimension="tenant", value="t-002", created_at=_old_date(10))
        await mgr.promote(s1)
        await mgr.rollback(s2, "missed_tp")

        history = await mgr.get_rollout_history()
        assert len(history) == 2
        assert history[0]["action"] == "promote"
        assert history[1]["action"] == "rollback"

    @pytest.mark.asyncio
    async def test_continue_when_precision_between_thresholds(self):
        """Continue when precision >= 95% but < 98%."""
        mgr = _make_manager()
        s = CanarySlice(
            slice_id="s-9", dimension="rule_family", value="phishing",
            created_at=_old_date(8),
        )
        result = await mgr.check_promotion(s, precision=0.96, missed_tps=0)
        assert result == "continue"


# ---------------------------------------------------------------------------
# TestCanaryEvaluator (Task 3)
# ---------------------------------------------------------------------------

class TestCanaryEvaluator:
    """AC-1,2,3: Canary evaluation loop."""

    @pytest.mark.asyncio
    async def test_evaluates_active_slices_only(self):
        """Only active slices are evaluated."""
        mgr = _make_manager()
        fp_eval = MagicMock()
        fp_eval.get_evaluation = MagicMock(return_value=None)
        evaluator = CanaryEvaluator(mgr, fp_eval)

        config = CanaryConfig(slices=[
            CanarySlice(slice_id="s-1", dimension="tenant", value="t-001",
                        created_at=_old_date(8)),
            CanarySlice(slice_id="s-2", dimension="tenant", value="t-002",
                        created_at=_old_date(8), status=CANARY_PROMOTED),
        ])
        decisions = await evaluator.evaluate_all_slices(config)
        # Only s-1 should be evaluated (s-2 is already promoted)
        assert len(decisions) == 1
        assert decisions[0]["slice_id"] == "s-1"

    @pytest.mark.asyncio
    async def test_triggers_promotion(self):
        """Evaluator triggers promotion when criteria met."""
        mgr = _make_manager()
        eval_result = MagicMock()
        eval_result.precision = 0.99
        eval_result.false_positives = 0
        fp_eval = MagicMock()
        fp_eval.get_evaluation = MagicMock(return_value=eval_result)
        evaluator = CanaryEvaluator(mgr, fp_eval)

        s = CanarySlice(
            slice_id="s-1", dimension="rule_family", value="phishing",
            created_at=_old_date(8),
        )
        config = CanaryConfig(slices=[s])
        decisions = await evaluator.evaluate_all_slices(config)
        assert decisions[0]["action"] == "promote"
        assert s.status == CANARY_PROMOTED

    @pytest.mark.asyncio
    async def test_triggers_rollback_on_missed_tp(self):
        """Evaluator triggers rollback when missed TP detected."""
        mgr = _make_manager()
        eval_result = MagicMock()
        eval_result.precision = 0.99
        eval_result.false_positives = 2  # missed TPs
        fp_eval = MagicMock()
        fp_eval.get_evaluation = MagicMock(return_value=eval_result)
        evaluator = CanaryEvaluator(mgr, fp_eval)

        s = CanarySlice(
            slice_id="s-2", dimension="tenant", value="t-001",
            created_at=_old_date(10),
        )
        config = CanaryConfig(slices=[s])
        decisions = await evaluator.evaluate_all_slices(config)
        assert decisions[0]["action"] == "rollback"
        assert s.status == CANARY_ROLLED_BACK
        mgr._kill_switch.activate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_continues_when_criteria_not_met(self):
        """Evaluator continues when slice is too young."""
        mgr = _make_manager()
        eval_result = MagicMock()
        eval_result.precision = 0.99
        eval_result.false_positives = 0
        fp_eval = MagicMock()
        fp_eval.get_evaluation = MagicMock(return_value=eval_result)
        evaluator = CanaryEvaluator(mgr, fp_eval)

        s = CanarySlice(
            slice_id="s-3", dimension="rule_family", value="malware",
            created_at=_old_date(3),
        )
        config = CanaryConfig(slices=[s])
        decisions = await evaluator.evaluate_all_slices(config)
        assert decisions[0]["action"] == "continue"
        assert s.status == CANARY_ACTIVE
