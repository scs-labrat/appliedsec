"""Tests for escalation manager — Story 6.3."""

import time

import pytest
from unittest.mock import patch

from llm_router.escalation import (
    APPLICABLE_SEVERITIES,
    CONFIDENCE_THRESHOLD,
    EXTENDED_THINKING_BUDGET,
    MAX_ESCALATIONS_PER_HOUR,
    EscalationManager,
    EscalationPolicy,
)
from llm_router.models import ModelTier


@pytest.fixture
def mgr():
    return EscalationManager()


@pytest.fixture
def custom_mgr():
    policy = EscalationPolicy(
        confidence_threshold=0.5,
        applicable_severities=frozenset({"critical"}),
        max_escalations_per_hour=3,
    )
    return EscalationManager(policy)


# ---------- Policy defaults ---------------------------------------------------

class TestPolicyDefaults:
    def test_default_threshold(self):
        assert CONFIDENCE_THRESHOLD == 0.6

    def test_default_severities(self):
        assert APPLICABLE_SEVERITIES == frozenset({"critical", "high"})

    def test_default_max_escalations(self):
        assert MAX_ESCALATIONS_PER_HOUR == 10

    def test_extended_thinking_budget(self):
        assert EXTENDED_THINKING_BUDGET == 8192

    def test_policy_dataclass(self):
        p = EscalationPolicy()
        assert p.confidence_threshold == 0.6
        assert p.max_escalations_per_hour == 10

    def test_custom_policy(self, custom_mgr):
        assert custom_mgr.policy.confidence_threshold == 0.5
        assert custom_mgr.policy.max_escalations_per_hour == 3


# ---------- should_escalate logic ---------------------------------------------

class TestShouldEscalate:
    def test_low_confidence_critical(self, mgr):
        assert mgr.should_escalate(0.4, "critical") is True

    def test_low_confidence_high(self, mgr):
        assert mgr.should_escalate(0.5, "high") is True

    def test_confidence_at_threshold(self, mgr):
        assert mgr.should_escalate(0.6, "critical") is False

    def test_above_threshold(self, mgr):
        assert mgr.should_escalate(0.8, "critical") is False

    def test_zero_confidence(self, mgr):
        assert mgr.should_escalate(0.0, "critical") is True

    def test_medium_severity_rejected(self, mgr):
        assert mgr.should_escalate(0.3, "medium") is False

    def test_low_severity_rejected(self, mgr):
        assert mgr.should_escalate(0.1, "low") is False

    def test_informational_rejected(self, mgr):
        assert mgr.should_escalate(0.1, "informational") is False

    def test_custom_threshold(self, custom_mgr):
        assert custom_mgr.should_escalate(0.49, "critical") is True
        assert custom_mgr.should_escalate(0.50, "critical") is False

    def test_custom_severities(self, custom_mgr):
        assert custom_mgr.should_escalate(0.3, "high") is False  # not in custom set


# ---------- Budget enforcement ------------------------------------------------

class TestBudgetEnforcement:
    def test_budget_starts_full(self, mgr):
        assert mgr.budget_remaining == 10

    def test_escalation_decrements_budget(self, mgr):
        mgr.record_escalation()
        assert mgr.budget_remaining == 9

    def test_budget_exhaustion_blocks(self, mgr):
        for _ in range(10):
            mgr.record_escalation()
        assert mgr.should_escalate(0.3, "critical") is False
        assert mgr.budget_remaining == 0

    def test_budget_resets_after_hour(self, mgr):
        now = time.monotonic()
        mgr._escalation_timestamps = [now - 3601] * 10
        assert mgr.budget_remaining == 10
        assert mgr.should_escalate(0.3, "critical") is True

    def test_custom_budget(self, custom_mgr):
        assert custom_mgr.budget_remaining == 3
        for _ in range(3):
            custom_mgr.record_escalation()
        assert custom_mgr.should_escalate(0.3, "critical") is False

    def test_escalations_this_hour_count(self, mgr):
        mgr.record_escalation()
        mgr.record_escalation()
        assert mgr.escalations_this_hour == 2


# ---------- Escalation tier ---------------------------------------------------

class TestEscalationTier:
    def test_escalation_target(self, mgr):
        assert mgr.get_escalation_tier() == ModelTier.TIER_1_PLUS

    def test_tier_is_opus(self, mgr):
        tier = mgr.get_escalation_tier()
        assert tier.value == "tier_1+"
