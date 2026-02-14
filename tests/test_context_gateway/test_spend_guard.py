"""Tests for spend guard — Story 5.6."""

from __future__ import annotations

import pytest

from context_gateway.spend_guard import (
    DEFAULT_MONTHLY_HARD_CAP,
    DEFAULT_MONTHLY_SOFT_ALERT,
    SpendGuard,
    SpendLimitExceeded,
)


class TestDefaults:
    def test_hard_cap(self):
        assert DEFAULT_MONTHLY_HARD_CAP == 1000.0

    def test_soft_alert(self):
        assert DEFAULT_MONTHLY_SOFT_ALERT == 500.0


class TestRecordAndQuery:
    def test_records_cost(self):
        sg = SpendGuard()
        sg.record(0.05, model_id="sonnet", task_type="triage", tenant_id="t1")
        assert sg.monthly_total == pytest.approx(0.05)
        assert sg.call_count == 1

    def test_multiple_records(self):
        sg = SpendGuard()
        sg.record(0.10)
        sg.record(0.20)
        sg.record(0.30)
        assert sg.monthly_total == pytest.approx(0.60)
        assert sg.call_count == 3


class TestAggregations:
    def test_total_by_model(self):
        sg = SpendGuard()
        sg.record(0.10, model_id="sonnet")
        sg.record(0.05, model_id="haiku")
        sg.record(0.20, model_id="sonnet")
        totals = sg.total_by_model()
        assert totals["sonnet"] == pytest.approx(0.30)
        assert totals["haiku"] == pytest.approx(0.05)

    def test_total_by_task_type(self):
        sg = SpendGuard()
        sg.record(0.10, task_type="triage")
        sg.record(0.20, task_type="investigate")
        totals = sg.total_by_task_type()
        assert totals["triage"] == pytest.approx(0.10)
        assert totals["investigate"] == pytest.approx(0.20)

    def test_total_by_tenant(self):
        sg = SpendGuard()
        sg.record(0.10, tenant_id="t1")
        sg.record(0.20, tenant_id="t2")
        totals = sg.total_by_tenant()
        assert totals["t1"] == pytest.approx(0.10)
        assert totals["t2"] == pytest.approx(0.20)


class TestHardCap:
    def test_under_cap_passes(self):
        sg = SpendGuard(monthly_hard_cap=100.0)
        sg.record(50.0)
        sg.check_budget()  # should not raise

    def test_at_cap_raises(self):
        sg = SpendGuard(monthly_hard_cap=100.0)
        sg.record(100.0)
        with pytest.raises(SpendLimitExceeded):
            sg.check_budget()

    def test_over_cap_raises(self):
        sg = SpendGuard(monthly_hard_cap=100.0)
        sg.record(101.0)
        with pytest.raises(SpendLimitExceeded):
            sg.check_budget()

    def test_exception_message(self):
        sg = SpendGuard(monthly_hard_cap=50.0)
        sg.record(60.0)
        with pytest.raises(SpendLimitExceeded, match="hard cap"):
            sg.check_budget()


class TestSoftAlert:
    def test_fires_once(self):
        sg = SpendGuard(monthly_soft_alert=10.0)
        sg.record(11.0)
        assert sg._soft_alert_fired is True

    def test_does_not_fire_below_threshold(self):
        sg = SpendGuard(monthly_soft_alert=10.0)
        sg.record(5.0)
        assert sg._soft_alert_fired is False
