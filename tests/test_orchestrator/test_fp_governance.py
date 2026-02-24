"""Tests for FP pattern governance — Story 14.4."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from orchestrator.fp_governance import (
    EXPIRY_DAYS,
    FPGovernanceManager,
    GovernanceError,
    matches_scope,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pattern(**overrides) -> dict:
    """Create a minimal FP pattern dict for testing."""
    base = {
        "pattern_id": "pat-001",
        "status": "pending_review",
        "approved_by_1": "",
        "approved_by_2": "",
        "expiry_date": "",
        "reaffirmed_date": "",
        "reaffirmed_by": "",
        "scope_rule_family": "",
        "scope_tenant_id": "",
        "scope_asset_class": "",
        "alert_name_regex": ".*Brute.*",
        "entity_patterns": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# TestFPPatternGovernanceFields (Task 1)
# ---------------------------------------------------------------------------

class TestFPPatternGovernanceFields:
    """AC-4: Governance fields on FPPattern model."""

    def test_governance_fields_default(self):
        """New FPPattern has governance fields defaulting to empty."""
        from batch_scheduler.models import FPPattern
        p = FPPattern()
        assert p.approved_by_1 == ""
        assert p.approved_by_2 == ""
        assert p.expiry_date == ""
        assert p.reaffirmed_date == ""
        assert p.reaffirmed_by == ""
        assert p.scope_rule_family == ""
        assert p.scope_tenant_id == ""
        assert p.scope_asset_class == ""

    def test_expired_status_valid(self):
        """EXPIRED is a valid FPPatternStatus value."""
        from batch_scheduler.models import FPPatternStatus
        assert FPPatternStatus.EXPIRED.value == "expired"

    def test_revoked_status_valid(self):
        """REVOKED is a valid FPPatternStatus value."""
        from batch_scheduler.models import FPPatternStatus
        assert FPPatternStatus.REVOKED.value == "revoked"

    def test_status_enum_count(self):
        """FPPatternStatus now has 7 values."""
        from batch_scheduler.models import FPPatternStatus
        assert len(FPPatternStatus) == 7


# ---------------------------------------------------------------------------
# TestFPGovernanceManager (Task 2)
# ---------------------------------------------------------------------------

class TestFPGovernanceManager:
    """AC-1,2,3: Two-person approval, expiry, revoke."""

    def test_first_approval_sets_approver_1(self):
        """First approve() sets approved_by_1, status stays pending."""
        mgr = FPGovernanceManager()
        pattern = _make_pattern()
        result = mgr.approve(pattern, "alice@org")
        assert result["approved_by_1"] == "alice@org"
        assert result["approved_by_2"] == ""
        assert result["status"] == "pending_review"

    def test_second_approval_completes(self):
        """Second distinct approver completes approval with expiry."""
        mgr = FPGovernanceManager()
        pattern = _make_pattern(approved_by_1="alice@org")
        result = mgr.approve(pattern, "bob@org")
        assert result["approved_by_2"] == "bob@org"
        assert result["status"] == "approved"
        assert result["expiry_date"] != ""
        assert result["approval_date"] != ""

    def test_same_person_twice_rejected(self):
        """Same person as both approvers raises GovernanceError."""
        mgr = FPGovernanceManager()
        pattern = _make_pattern(approved_by_1="alice@org")
        with pytest.raises(GovernanceError, match="Same person"):
            mgr.approve(pattern, "alice@org")

    def test_expiry_detected(self):
        """Expired patterns are detected by check_expiry."""
        mgr = FPGovernanceManager()
        old_date = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
        patterns = [
            _make_pattern(pattern_id="expired-1", status="approved", expiry_date=old_date),
            _make_pattern(pattern_id="fresh-1", status="approved",
                          expiry_date=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat()),
        ]
        expired = mgr.check_expiry(patterns)
        assert expired == ["expired-1"]

    def test_already_expired_not_double_reported(self):
        """Patterns with status 'expired' are not reported again."""
        mgr = FPGovernanceManager()
        old_date = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
        patterns = [
            _make_pattern(pattern_id="already-expired", status="expired", expiry_date=old_date),
        ]
        expired = mgr.check_expiry(patterns)
        assert expired == []

    def test_reaffirmation_extends_expiry(self):
        """Reaffirmation resets expiry to 90 days from now."""
        mgr = FPGovernanceManager()
        old_date = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        pattern = _make_pattern(status="approved", expiry_date=old_date)

        result = mgr.reaffirm(pattern, "carol@org")
        assert result["reaffirmed_by"] == "carol@org"
        assert result["reaffirmed_date"] != ""

        new_expiry = datetime.fromisoformat(result["expiry_date"])
        expected_min = datetime.now(timezone.utc) + timedelta(days=89)
        assert new_expiry > expected_min

    def test_reaffirmation_reactivates_expired(self):
        """Reaffirming an expired pattern sets status back to approved."""
        mgr = FPGovernanceManager()
        pattern = _make_pattern(status="expired")
        result = mgr.reaffirm(pattern, "carol@org")
        assert result["status"] == "approved"

    def test_revoke_sets_status_and_returns_investigations(self):
        """Revoke sets status to 'revoked' and returns investigation IDs."""
        mgr = FPGovernanceManager()
        pattern = _make_pattern(status="approved")
        inv_ids = ["inv-001", "inv-002"]
        result = mgr.revoke(pattern, "dave@org", closed_investigations=inv_ids)
        assert pattern["status"] == "revoked"
        assert result == ["inv-001", "inv-002"]

    def test_expiry_days_constant(self):
        """EXPIRY_DAYS is 90."""
        assert EXPIRY_DAYS == 90


# ---------------------------------------------------------------------------
# TestBlastRadiusScope (Task 3)
# ---------------------------------------------------------------------------

class TestBlastRadiusScope:
    """AC-5: Blast-radius scoping for FP patterns."""

    def test_global_pattern_matches_everything(self):
        """Pattern with empty scope matches any alert."""
        pattern = _make_pattern()
        assert matches_scope(pattern, "brute_force", "t-001", "server") is True

    def test_scoped_pattern_matches_within_scope(self):
        """Scoped pattern matches alert within its scope."""
        pattern = _make_pattern(
            scope_rule_family="brute_force",
            scope_tenant_id="t-001",
        )
        assert matches_scope(pattern, "brute_force", "t-001", "server") is True

    def test_scoped_pattern_rejects_wrong_tenant(self):
        """Scoped pattern rejects alert from different tenant."""
        pattern = _make_pattern(
            scope_rule_family="brute_force",
            scope_tenant_id="t-001",
        )
        assert matches_scope(pattern, "brute_force", "t-002", "server") is False

    def test_scoped_pattern_rejects_wrong_rule_family(self):
        """Scoped pattern rejects alert from different rule family."""
        pattern = _make_pattern(scope_rule_family="impossible_travel")
        assert matches_scope(pattern, "brute_force", "t-001", "server") is False

    def test_scoped_pattern_rejects_wrong_asset_class(self):
        """Scoped pattern rejects alert from different asset class."""
        pattern = _make_pattern(scope_asset_class="workstation")
        assert matches_scope(pattern, "brute_force", "t-001", "server") is False

    @pytest.mark.asyncio
    async def test_scope_enforced_in_fp_shortcircuit(self):
        """FPShortCircuit.check() respects scope — wrong scope means no match."""
        from orchestrator.fp_shortcircuit import FPShortCircuit
        from shared.schemas.investigation import GraphState

        redis = AsyncMock()
        redis.list_fp_patterns = AsyncMock(return_value=["fp:scoped-pat"])
        redis.get_fp_pattern = AsyncMock(return_value={
            "status": "approved",
            "alert_name_regex": ".*Brute.*",
            "entity_patterns": [],
            "scope_rule_family": "impossible_travel",
            "scope_tenant_id": "",
            "scope_asset_class": "",
        })

        shortcircuit = FPShortCircuit(redis)
        state = GraphState(investigation_id="inv-1", alert_id="a-1", tenant_id="t-001")
        result = await shortcircuit.check(
            state, "Brute Force Login",
            tenant_id="t-001",
            alert_rule_family="brute_force",
        )
        assert result.matched is False

    @pytest.mark.asyncio
    async def test_scope_match_allows_fp(self):
        """FPShortCircuit.check() matches when scope matches."""
        from orchestrator.fp_shortcircuit import FPShortCircuit
        from shared.schemas.investigation import GraphState

        redis = AsyncMock()
        redis.list_fp_patterns = AsyncMock(return_value=["fp:scoped-pat"])
        redis.get_fp_pattern = AsyncMock(return_value={
            "status": "approved",
            "alert_name_regex": ".*Brute.*",
            "entity_patterns": [],
            "scope_rule_family": "brute_force",
            "scope_tenant_id": "",
            "scope_asset_class": "",
        })

        shortcircuit = FPShortCircuit(redis)
        state = GraphState(investigation_id="inv-1", alert_id="a-1", tenant_id="t-001")
        result = await shortcircuit.check(
            state, "Brute Force Login",
            tenant_id="t-001",
            alert_rule_family="brute_force",
        )
        assert result.matched is True


# ---------------------------------------------------------------------------
# TestRollbackWorkflow (Task 4)
# ---------------------------------------------------------------------------

class TestRollbackWorkflow:
    """AC-3: Rollback re-opens investigations closed by revoked pattern."""

    @pytest.mark.asyncio
    async def test_rollback_reopens_investigations(self):
        """rollback_pattern re-opens matching investigations."""
        mgr = FPGovernanceManager()
        pg = AsyncMock()
        pg.fetch = AsyncMock(return_value=[
            {"investigation_id": "inv-001", "state": "CLOSED"},
            {"investigation_id": "inv-002", "state": "CLOSED"},
        ])
        pg.execute = AsyncMock()

        count = await mgr.rollback_pattern("pat-001", pg)
        assert count == 2
        assert pg.execute.await_count == 2

    @pytest.mark.asyncio
    async def test_rollback_returns_zero_when_none_found(self):
        """rollback_pattern returns 0 when no matching investigations."""
        mgr = FPGovernanceManager()
        pg = AsyncMock()
        pg.fetch = AsyncMock(return_value=[])

        count = await mgr.rollback_pattern("pat-999", pg)
        assert count == 0

    @pytest.mark.asyncio
    async def test_rollback_emits_audit_event(self):
        """rollback_pattern emits fp_pattern.revoked audit events."""
        audit = AsyncMock()
        mgr = FPGovernanceManager(audit_producer=audit)
        pg = AsyncMock()
        pg.fetch = AsyncMock(return_value=[
            {"investigation_id": "inv-001", "state": "CLOSED"},
        ])
        pg.execute = AsyncMock()

        await mgr.rollback_pattern("pat-001", pg)
        audit.emit.assert_awaited_once()
        call_kwargs = audit.emit.call_args[1]
        assert call_kwargs["event_type"] == "fp_pattern.revoked"
        assert call_kwargs["data"]["pattern_id"] == "pat-001"
        assert call_kwargs["data"]["outcome"]["state_before"] == "CLOSED"
        assert call_kwargs["data"]["outcome"]["state_after"] == "PARSING"

    @pytest.mark.asyncio
    async def test_rollback_count_correct(self):
        """rollback_pattern count matches number of rows updated."""
        mgr = FPGovernanceManager()
        pg = AsyncMock()
        pg.fetch = AsyncMock(return_value=[
            {"investigation_id": f"inv-{i}", "state": "CLOSED"}
            for i in range(5)
        ])
        pg.execute = AsyncMock()

        count = await mgr.rollback_pattern("pat-001", pg)
        assert count == 5
