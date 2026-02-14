"""Tests for LLM Router data models — Story 6.1."""

import pytest

from llm_router.models import (
    MODEL_REGISTRY,
    SEVERITY_QUEUE_MAP,
    TIER_DEFAULTS,
    AnthropicModelConfig,
    ModelTier,
    RoutingDecision,
    TaskContext,
)


# ---------- ModelTier enum ---------------------------------------------------

class TestModelTier:
    def test_four_tiers(self):
        assert len(ModelTier) == 4

    def test_tier_values(self):
        assert ModelTier.TIER_0.value == "tier_0"
        assert ModelTier.TIER_1.value == "tier_1"
        assert ModelTier.TIER_1_PLUS.value == "tier_1+"
        assert ModelTier.TIER_2.value == "tier_2"

    def test_string_enum(self):
        assert isinstance(ModelTier.TIER_0, str)
        assert ModelTier.TIER_0 == "tier_0"

    def test_from_value(self):
        assert ModelTier("tier_1+") is ModelTier.TIER_1_PLUS


# ---------- AnthropicModelConfig ---------------------------------------------

class TestAnthropicModelConfig:
    def test_haiku_config(self):
        cfg = MODEL_REGISTRY[ModelTier.TIER_0]
        assert "haiku" in cfg.model_id
        assert cfg.cost_per_mtok_input == 0.80
        assert cfg.cost_per_mtok_output == 4.0
        assert cfg.supports_extended_thinking is False
        assert cfg.batch_eligible is False

    def test_sonnet_config(self):
        cfg = MODEL_REGISTRY[ModelTier.TIER_1]
        assert "sonnet" in cfg.model_id
        assert cfg.cost_per_mtok_input == 3.0
        assert cfg.cost_per_mtok_output == 15.0
        assert cfg.supports_prompt_caching is True

    def test_opus_config(self):
        cfg = MODEL_REGISTRY[ModelTier.TIER_1_PLUS]
        assert "opus" in cfg.model_id
        assert cfg.supports_extended_thinking is True
        assert cfg.cost_per_mtok_input == 15.0

    def test_batch_config(self):
        cfg = MODEL_REGISTRY[ModelTier.TIER_2]
        assert cfg.batch_eligible is True
        assert cfg.cost_per_mtok_input == 1.5  # 50% discount

    def test_all_tiers_in_registry(self):
        for tier in ModelTier:
            assert tier in MODEL_REGISTRY

    def test_max_context_200k(self):
        for cfg in MODEL_REGISTRY.values():
            assert cfg.max_context_tokens == 200_000

    def test_custom_config(self):
        cfg = AnthropicModelConfig(
            model_id="test-model",
            max_context_tokens=100_000,
            cost_per_mtok_input=1.0,
            cost_per_mtok_output=5.0,
        )
        assert cfg.supports_tool_use is True  # default


# ---------- TaskContext ------------------------------------------------------

class TestTaskContext:
    def test_defaults(self):
        ctx = TaskContext(task_type="ioc_extraction")
        assert ctx.context_tokens == 0
        assert ctx.time_budget_seconds == 30
        assert ctx.alert_severity == "medium"
        assert ctx.tenant_tier == "standard"
        assert ctx.requires_reasoning is False
        assert ctx.previous_confidence is None

    def test_full_context(self):
        ctx = TaskContext(
            task_type="investigation",
            context_tokens=150_000,
            time_budget_seconds=60,
            alert_severity="critical",
            tenant_tier="premium",
            requires_reasoning=True,
            previous_confidence=0.4,
        )
        assert ctx.task_type == "investigation"
        assert ctx.context_tokens == 150_000
        assert ctx.previous_confidence == 0.4


# ---------- RoutingDecision --------------------------------------------------

class TestRoutingDecision:
    def test_basic_decision(self):
        cfg = MODEL_REGISTRY[ModelTier.TIER_0]
        decision = RoutingDecision(
            tier=ModelTier.TIER_0,
            model_config=cfg,
            max_tokens=2048,
            temperature=0.1,
        )
        assert decision.use_extended_thinking is False
        assert decision.use_prompt_caching is True
        assert decision.reason == ""

    def test_extended_thinking_decision(self):
        cfg = MODEL_REGISTRY[ModelTier.TIER_1_PLUS]
        decision = RoutingDecision(
            tier=ModelTier.TIER_1_PLUS,
            model_config=cfg,
            max_tokens=16384,
            temperature=0.2,
            use_extended_thinking=True,
            reason="escalation",
        )
        assert decision.use_extended_thinking is True
        assert decision.reason == "escalation"


# ---------- TIER_DEFAULTS ----------------------------------------------------

class TestTierDefaults:
    def test_all_tiers_have_defaults(self):
        for tier in ModelTier:
            assert tier in TIER_DEFAULTS
            assert "max_tokens" in TIER_DEFAULTS[tier]
            assert "temperature" in TIER_DEFAULTS[tier]

    def test_tier0_fastest(self):
        assert TIER_DEFAULTS[ModelTier.TIER_0]["max_tokens"] == 2048

    def test_tier1plus_largest(self):
        assert TIER_DEFAULTS[ModelTier.TIER_1_PLUS]["max_tokens"] == 16384

    def test_temperatures(self):
        assert TIER_DEFAULTS[ModelTier.TIER_0]["temperature"] == 0.1
        assert TIER_DEFAULTS[ModelTier.TIER_2]["temperature"] == 0.3


# ---------- SEVERITY_QUEUE_MAP -----------------------------------------------

class TestSeverityQueueMap:
    def test_all_severities_mapped(self):
        expected = {"critical", "high", "medium", "low", "informational"}
        assert set(SEVERITY_QUEUE_MAP.keys()) == expected

    def test_critical_highest_priority(self):
        assert SEVERITY_QUEUE_MAP["critical"] == "jobs.llm.priority.critical"

    def test_informational_maps_to_low(self):
        assert SEVERITY_QUEUE_MAP["informational"] == "jobs.llm.priority.low"

    def test_queue_name_pattern(self):
        for queue in SEVERITY_QUEUE_MAP.values():
            assert queue.startswith("jobs.llm.priority.")
