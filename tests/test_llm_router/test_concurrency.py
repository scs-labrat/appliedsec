"""Tests for concurrency controller — Story 6.2."""

import time

import pytest
from unittest.mock import patch

from llm_router.concurrency import (
    PRIORITY_LIMITS,
    TENANT_QUOTAS,
    ConcurrencyController,
    QuotaExceeded,
)


@pytest.fixture
def ctrl():
    return ConcurrencyController()


# ---------- Priority concurrency slots ----------------------------------------

class TestConcurrencySlots:
    def test_acquire_succeeds(self, ctrl):
        assert ctrl.acquire("critical") is True

    def test_acquire_up_to_limit(self, ctrl):
        limit = PRIORITY_LIMITS["critical"].max_concurrent
        for _ in range(limit):
            assert ctrl.acquire("critical") is True
        assert ctrl.acquire("critical") is False

    def test_release_frees_slot(self, ctrl):
        limit = PRIORITY_LIMITS["normal"].max_concurrent
        for _ in range(limit):
            ctrl.acquire("normal")
        assert ctrl.acquire("normal") is False
        ctrl.release("normal")
        assert ctrl.acquire("normal") is True

    def test_release_never_negative(self, ctrl):
        ctrl.release("low")
        ctrl.release("low")
        assert ctrl.get_active("low") == 0

    def test_unknown_priority_always_allows(self, ctrl):
        assert ctrl.acquire("unknown_priority") is True

    def test_get_active_count(self, ctrl):
        ctrl.acquire("high")
        ctrl.acquire("high")
        assert ctrl.get_active("high") == 2

    def test_independent_priorities(self, ctrl):
        """Different priorities have independent slots."""
        for _ in range(PRIORITY_LIMITS["low"].max_concurrent):
            ctrl.acquire("low")
        assert ctrl.acquire("low") is False
        assert ctrl.acquire("critical") is True


# ---------- RPM rate limits ---------------------------------------------------

class TestRPMLimits:
    def test_rpm_blocks_at_limit(self, ctrl):
        """When RPM limit is reached, acquire fails even if slots are free."""
        limit = PRIORITY_LIMITS["low"]
        # Fill RPM by acquiring and releasing
        for _ in range(limit.max_rpm):
            ctrl.acquire("low")
            ctrl.release("low")
        # All slots free but RPM exhausted
        assert ctrl.acquire("low") is False

    def test_rpm_resets_after_window(self, ctrl):
        """Timestamps older than 60s are pruned."""
        limit = PRIORITY_LIMITS["low"]
        now = time.monotonic()
        # Inject old timestamps
        ctrl._timestamps["low"] = [now - 61] * limit.max_rpm
        assert ctrl.acquire("low") is True


# ---------- Priority limits constants -----------------------------------------

class TestPriorityLimits:
    def test_critical_highest_concurrency(self):
        assert PRIORITY_LIMITS["critical"].max_concurrent == 8

    def test_low_lowest_concurrency(self):
        assert PRIORITY_LIMITS["low"].max_concurrent == 2

    def test_all_priorities_defined(self):
        assert set(PRIORITY_LIMITS.keys()) == {"critical", "high", "normal", "low"}

    def test_rpm_ordering(self):
        assert PRIORITY_LIMITS["critical"].max_rpm > PRIORITY_LIMITS["high"].max_rpm
        assert PRIORITY_LIMITS["high"].max_rpm > PRIORITY_LIMITS["normal"].max_rpm
        assert PRIORITY_LIMITS["normal"].max_rpm > PRIORITY_LIMITS["low"].max_rpm


# ---------- Utilisation metrics -----------------------------------------------

class TestUtilisation:
    def test_empty_utilisation(self, ctrl):
        util = ctrl.get_utilisation()
        assert len(util) == 4
        for priority in PRIORITY_LIMITS:
            assert util[priority]["active"] == 0
            assert util[priority]["utilisation"] == 0

    def test_partial_utilisation(self, ctrl):
        ctrl.acquire("critical")
        ctrl.acquire("critical")
        util = ctrl.get_utilisation()
        assert util["critical"]["active"] == 2
        assert util["critical"]["max_concurrent"] == 8
        assert util["critical"]["utilisation"] == 0.25


# ---------- Tenant quotas -----------------------------------------------------

class TestTenantQuotas:
    def test_standard_quota(self):
        assert TENANT_QUOTAS["standard"] == 100

    def test_premium_quota(self):
        assert TENANT_QUOTAS["premium"] == 500

    def test_trial_quota(self):
        assert TENANT_QUOTAS["trial"] == 20

    def test_check_under_quota(self, ctrl):
        ctrl.record_tenant_call("tenant-1")
        ctrl.check_tenant_quota("tenant-1", "standard")  # should not raise

    def test_check_over_quota_raises(self, ctrl):
        for _ in range(100):
            ctrl.record_tenant_call("tenant-2")
        with pytest.raises(QuotaExceeded, match="tenant-2"):
            ctrl.check_tenant_quota("tenant-2", "standard")

    def test_trial_quota_small(self, ctrl):
        for _ in range(20):
            ctrl.record_tenant_call("trial-1")
        with pytest.raises(QuotaExceeded):
            ctrl.check_tenant_quota("trial-1", "trial")

    def test_premium_quota_large(self, ctrl):
        for _ in range(100):
            ctrl.record_tenant_call("prem-1")
        ctrl.check_tenant_quota("prem-1", "premium")  # should not raise

    def test_unknown_tier_uses_standard(self, ctrl):
        for _ in range(100):
            ctrl.record_tenant_call("unk-1")
        with pytest.raises(QuotaExceeded):
            ctrl.check_tenant_quota("unk-1", "unknown_tier")

    def test_quota_resets_after_hour(self, ctrl):
        now = time.monotonic()
        ctrl._tenant_calls["old-tenant"] = [now - 3601] * 200
        ctrl.check_tenant_quota("old-tenant", "standard")  # should not raise

    def test_separate_tenants(self, ctrl):
        for _ in range(100):
            ctrl.record_tenant_call("t-full")
        ctrl.record_tenant_call("t-ok")
        ctrl.check_tenant_quota("t-ok", "standard")  # should not raise
