"""Tests for LLM Router routing logic — Story 6.1."""

import pytest

from llm_router.models import (
    MODEL_REGISTRY,
    ModelTier,
    TaskContext,
)
from llm_router.router import LLMRouter, TASK_TIER_MAP


@pytest.fixture
def router():
    return LLMRouter()


# ---------- TASK_TIER_MAP completeness ----------------------------------------

class TestTaskTierMap:
    def test_tier0_tasks(self):
        tier0 = [k for k, v in TASK_TIER_MAP.items() if v == ModelTier.TIER_0]
        assert "ioc_extraction" in tier0
        assert "log_summarisation" in tier0
        assert "alert_classification" in tier0
        assert "severity_assessment" in tier0
        assert len(tier0) == 6

    def test_tier1_tasks(self):
        tier1 = [k for k, v in TASK_TIER_MAP.items() if v == ModelTier.TIER_1]
        assert "investigation" in tier1
        assert "ctem_correlation" in tier1
        assert "atlas_reasoning" in tier1
        assert "attack_path_analysis" in tier1
        assert len(tier1) == 6

    def test_tier2_tasks(self):
        tier2 = [k for k, v in TASK_TIER_MAP.items() if v == ModelTier.TIER_2]
        assert "fp_pattern_training" in tier2
        assert "playbook_generation" in tier2
        assert "detection_rule_generation" in tier2
        assert len(tier2) == 6

    def test_total_mapped_tasks(self):
        assert len(TASK_TIER_MAP) == 18


# ---------- Base routing (override 1) ----------------------------------------

class TestBaseRouting:
    def test_tier0_task(self, router):
        ctx = TaskContext(task_type="ioc_extraction")
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_0
        assert "haiku" in decision.model_config.model_id
        assert decision.max_tokens == 2048
        assert decision.temperature == 0.1

    def test_tier1_task(self, router):
        ctx = TaskContext(task_type="investigation")
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1
        assert "sonnet" in decision.model_config.model_id
        assert decision.max_tokens == 8192

    def test_tier2_task(self, router):
        ctx = TaskContext(task_type="fp_pattern_training")
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_2
        assert decision.model_config.batch_eligible is True
        assert decision.max_tokens == 16384

    def test_unknown_task_defaults_tier1(self, router):
        ctx = TaskContext(task_type="unknown_task_xyz")
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1

    def test_reason_includes_base(self, router):
        ctx = TaskContext(task_type="ioc_extraction")
        decision = router.route(ctx)
        assert "base=tier_0" in decision.reason


# ---------- Time budget override (override 2) ---------------------------------

class TestTimeBudgetOverride:
    def test_low_budget_forces_tier0(self, router):
        ctx = TaskContext(task_type="investigation", time_budget_seconds=2)
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_0
        assert "time_budget<3s" in decision.reason

    def test_exact_3s_no_override(self, router):
        ctx = TaskContext(task_type="investigation", time_budget_seconds=3)
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1

    def test_1s_budget_overrides_tier1(self, router):
        ctx = TaskContext(task_type="attack_path_analysis", time_budget_seconds=1)
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_0


# ---------- Severity override (override 3) ------------------------------------

class TestSeverityOverride:
    def test_critical_with_reasoning_upgrades(self, router):
        ctx = TaskContext(
            task_type="ioc_extraction",
            alert_severity="critical",
            requires_reasoning=True,
        )
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1

    def test_critical_without_reasoning_no_upgrade(self, router):
        ctx = TaskContext(
            task_type="ioc_extraction",
            alert_severity="critical",
            requires_reasoning=False,
        )
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_0

    def test_high_severity_no_upgrade(self, router):
        ctx = TaskContext(
            task_type="ioc_extraction",
            alert_severity="high",
            requires_reasoning=True,
        )
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_0  # only critical triggers

    def test_already_tier1_no_double_upgrade(self, router):
        ctx = TaskContext(
            task_type="investigation",
            alert_severity="critical",
            requires_reasoning=True,
        )
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1  # already tier 1


# ---------- Context size override (override 4) --------------------------------

class TestContextSizeOverride:
    def test_large_context_upgrades_tier0(self, router):
        ctx = TaskContext(task_type="ioc_extraction", context_tokens=150_000)
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1
        assert "context>100k" in decision.reason

    def test_100k_exact_no_upgrade(self, router):
        ctx = TaskContext(task_type="ioc_extraction", context_tokens=100_000)
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_0

    def test_large_context_tier1_stays(self, router):
        ctx = TaskContext(task_type="investigation", context_tokens=150_000)
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1  # already tier 1, no upgrade


# ---------- Escalation override (override 5) ----------------------------------

class TestEscalationOverride:
    def test_low_confidence_critical_escalates(self, router):
        ctx = TaskContext(
            task_type="investigation",
            alert_severity="critical",
            previous_confidence=0.4,
        )
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1_PLUS
        assert decision.use_extended_thinking is True
        assert "low_confidence_escalation" in decision.reason

    def test_low_confidence_high_escalates(self, router):
        ctx = TaskContext(
            task_type="investigation",
            alert_severity="high",
            previous_confidence=0.3,
        )
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1_PLUS

    def test_confidence_at_threshold_no_escalation(self, router):
        ctx = TaskContext(
            task_type="investigation",
            alert_severity="critical",
            previous_confidence=0.6,
        )
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1

    def test_low_confidence_medium_no_escalation(self, router):
        ctx = TaskContext(
            task_type="investigation",
            alert_severity="medium",
            previous_confidence=0.3,
        )
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1

    def test_no_previous_confidence_no_escalation(self, router):
        ctx = TaskContext(
            task_type="investigation",
            alert_severity="critical",
        )
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1


# ---------- Override interaction tests ----------------------------------------

class TestOverrideInteractions:
    def test_time_budget_beats_severity(self, router):
        """Time budget < 3s takes precedence over critical severity."""
        ctx = TaskContext(
            task_type="investigation",
            time_budget_seconds=1,
            alert_severity="critical",
            requires_reasoning=True,
        )
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_0

    def test_escalation_beats_time_budget(self, router):
        """Low confidence escalation overrides time budget (applied last)."""
        ctx = TaskContext(
            task_type="investigation",
            time_budget_seconds=1,
            alert_severity="critical",
            previous_confidence=0.3,
        )
        decision = router.route(ctx)
        assert decision.tier == ModelTier.TIER_1_PLUS

    def test_prompt_caching_enabled(self, router):
        ctx = TaskContext(task_type="ioc_extraction")
        decision = router.route(ctx)
        assert decision.use_prompt_caching is True

    def test_model_config_matches_tier(self, router):
        for task_type in TASK_TIER_MAP:
            ctx = TaskContext(task_type=task_type)
            decision = router.route(ctx)
            assert decision.model_config is MODEL_REGISTRY[decision.tier]
