"""Tests for LLMProvider, TaskCapabilities, ModelConfig, and capability matching — Story 12.2."""

from llm_router.router import TASK_CAPABILITIES, TASK_TIER_MAP, _matches_capabilities
from shared.schemas.routing import LLMProvider, ModelConfig, TaskCapabilities


class TestLLMProvider:
    """AC-1: LLMProvider enum has exactly 4 members."""

    def test_enum_has_four_members(self):
        assert len(list(LLMProvider)) == 4

    def test_enum_member_names(self):
        expected = {"ANTHROPIC", "OPENAI", "LOCAL", "GROQ"}
        assert {m.name for m in LLMProvider} == expected

    def test_enum_member_values(self):
        expected = {"anthropic", "openai", "local", "groq"}
        assert {m.value for m in LLMProvider} == expected

    def test_enum_is_str(self):
        assert isinstance(LLMProvider.ANTHROPIC, str)
        assert LLMProvider.ANTHROPIC == "anthropic"


class TestTaskCapabilities:
    """AC-2: TaskCapabilities dataclass with correct defaults."""

    def test_defaults(self):
        tc = TaskCapabilities()
        assert tc.requires_tool_use is False
        assert tc.requires_json_reliability is False
        assert tc.max_context_tokens == 8192
        assert tc.latency_slo_seconds == 30
        assert tc.requires_extended_thinking is False

    def test_custom_values(self):
        tc = TaskCapabilities(
            requires_tool_use=True,
            requires_json_reliability=True,
            max_context_tokens=100_000,
            latency_slo_seconds=3,
            requires_extended_thinking=True,
        )
        assert tc.requires_tool_use is True
        assert tc.requires_json_reliability is True
        assert tc.max_context_tokens == 100_000
        assert tc.latency_slo_seconds == 3
        assert tc.requires_extended_thinking is True

    def test_serialisation_round_trip(self):
        tc = TaskCapabilities(requires_tool_use=True, max_context_tokens=50_000)
        data = tc.model_dump()
        tc2 = TaskCapabilities(**data)
        assert tc2.requires_tool_use is True
        assert tc2.max_context_tokens == 50_000


class TestModelConfig:
    """AC-1, 2: ModelConfig with provider and capabilities."""

    def test_construction(self):
        mc = ModelConfig(
            provider=LLMProvider.ANTHROPIC,
            model_id="claude-sonnet-4-5-20250929",
            max_context_tokens=200_000,
            cost_per_mtok_input=3.0,
            cost_per_mtok_output=15.0,
        )
        assert mc.provider == LLMProvider.ANTHROPIC
        assert mc.model_id == "claude-sonnet-4-5-20250929"
        assert mc.max_context_tokens == 200_000
        assert mc.cost_per_mtok_input == 3.0
        assert mc.cost_per_mtok_output == 15.0

    def test_provider_field(self):
        mc = ModelConfig(
            provider=LLMProvider.OPENAI,
            model_id="gpt-4o",
            max_context_tokens=128_000,
            cost_per_mtok_input=5.0,
            cost_per_mtok_output=15.0,
        )
        assert mc.provider == LLMProvider.OPENAI

    def test_capability_defaults(self):
        mc = ModelConfig(
            provider=LLMProvider.ANTHROPIC,
            model_id="test",
            max_context_tokens=100,
            cost_per_mtok_input=1.0,
            cost_per_mtok_output=1.0,
        )
        assert mc.supports_extended_thinking is False
        assert mc.supports_tool_use is True
        assert mc.supports_prompt_caching is True
        assert mc.batch_eligible is False
        assert mc.capabilities == TaskCapabilities()

    def test_capabilities_field(self):
        caps = TaskCapabilities(requires_tool_use=True, max_context_tokens=100_000)
        mc = ModelConfig(
            provider=LLMProvider.ANTHROPIC,
            model_id="test",
            max_context_tokens=200_000,
            cost_per_mtok_input=1.0,
            cost_per_mtok_output=1.0,
            capabilities=caps,
        )
        assert mc.capabilities.requires_tool_use is True
        assert mc.capabilities.max_context_tokens == 100_000

    def test_serialisation_round_trip(self):
        mc = ModelConfig(
            provider=LLMProvider.GROQ,
            model_id="llama-3",
            max_context_tokens=8192,
            cost_per_mtok_input=0.1,
            cost_per_mtok_output=0.1,
            supports_prompt_caching=False,
        )
        data = mc.model_dump()
        mc2 = ModelConfig(**data)
        assert mc2.provider == LLMProvider.GROQ
        assert mc2.model_id == "llama-3"
        assert mc2.supports_prompt_caching is False


class TestTaskCapabilitiesMapping:
    """AC-2: All 18 tasks have capability entries."""

    def test_all_tasks_have_capabilities(self):
        for task in TASK_TIER_MAP:
            assert task in TASK_CAPABILITIES, f"Missing TASK_CAPABILITIES for {task}"

    def test_no_extra_capabilities(self):
        for task in TASK_CAPABILITIES:
            assert task in TASK_TIER_MAP, f"Extra TASK_CAPABILITIES for {task}"

    def test_tier0_tasks_have_low_latency(self):
        tier0_tasks = [t for t, tier in TASK_TIER_MAP.items() if tier.value == "tier_0"]
        for task in tier0_tasks:
            assert TASK_CAPABILITIES[task].latency_slo_seconds == 3

    def test_tier2_tasks_have_batch_latency(self):
        tier2_tasks = [t for t, tier in TASK_TIER_MAP.items() if tier.value == "tier_2"]
        for task in tier2_tasks:
            assert TASK_CAPABILITIES[task].latency_slo_seconds == 86_400


class TestCapabilityMatching:
    """AC-2: Model capability matching logic."""

    def _make_model(self, **overrides) -> ModelConfig:
        defaults = dict(
            provider=LLMProvider.ANTHROPIC,
            model_id="test",
            max_context_tokens=200_000,
            cost_per_mtok_input=1.0,
            cost_per_mtok_output=1.0,
        )
        defaults.update(overrides)
        return ModelConfig(**defaults)

    def test_full_capability_model_matches_any(self):
        model = self._make_model(supports_tool_use=True, supports_extended_thinking=True)
        caps = TaskCapabilities(
            requires_tool_use=True, requires_extended_thinking=True, max_context_tokens=100_000,
        )
        assert _matches_capabilities(model, caps) is True

    def test_tool_use_mismatch(self):
        model = self._make_model(supports_tool_use=False)
        caps = TaskCapabilities(requires_tool_use=True)
        assert _matches_capabilities(model, caps) is False

    def test_extended_thinking_mismatch(self):
        model = self._make_model(supports_extended_thinking=False)
        caps = TaskCapabilities(requires_extended_thinking=True)
        assert _matches_capabilities(model, caps) is False

    def test_context_too_small(self):
        model = self._make_model(max_context_tokens=4096)
        caps = TaskCapabilities(max_context_tokens=100_000)
        assert _matches_capabilities(model, caps) is False

    def test_no_requirements_always_matches(self):
        model = self._make_model(supports_tool_use=False, supports_extended_thinking=False)
        caps = TaskCapabilities()
        assert _matches_capabilities(model, caps) is True
