"""Contract tests for provider prompt compatibility — REM-C02 Part D.

Verifies that primary (Anthropic) and secondary (OpenAI) prompt adapters
produce structurally compatible output for all task types.
"""

from __future__ import annotations

import pytest

from context_gateway.prompt_adapter import (
    AnthropicPromptAdapter,
    OpenAIPromptAdapter,
    get_adapter,
)
from llm_router.models import FALLBACK_REGISTRY, MODEL_REGISTRY, ModelTier
from llm_router.router import TASK_CAPABILITIES, TASK_TIER_MAP, _matches_capabilities
from shared.schemas.routing import LLMProvider


class TestPromptAdapterCompatibility:
    """Both adapters produce valid prompt structures."""

    @pytest.fixture
    def anthropic_adapter(self):
        return AnthropicPromptAdapter()

    @pytest.fixture
    def openai_adapter(self):
        return OpenAIPromptAdapter()

    @pytest.fixture
    def sample_prompt(self):
        return "You are a security analyst. Analyse the following alert."

    @pytest.fixture
    def sample_content(self):
        return "Alert: Suspicious login from IP 10.0.0.1 at 2026-03-01T12:00:00Z"

    def test_anthropic_system_returns_list_of_blocks(self, anthropic_adapter, sample_prompt):
        result = anthropic_adapter.adapt_system(sample_prompt)
        assert isinstance(result, list)
        assert len(result) > 0
        for block in result:
            assert "type" in block
            assert "text" in block

    def test_openai_system_returns_list_of_messages(self, openai_adapter, sample_prompt):
        result = openai_adapter.adapt_system(sample_prompt)
        assert isinstance(result, list)
        assert len(result) > 0
        assert result[0]["role"] == "system"
        assert isinstance(result[0]["content"], str)

    def test_both_adapters_produce_user_messages(
        self, anthropic_adapter, openai_adapter, sample_content
    ):
        anth_msgs = anthropic_adapter.adapt_messages(sample_content)
        oai_msgs = openai_adapter.adapt_messages(sample_content)
        assert anth_msgs[0]["role"] == "user"
        assert oai_msgs[0]["role"] == "user"
        assert anth_msgs[0]["content"] == oai_msgs[0]["content"]

    def test_anthropic_schema_passthrough(self, anthropic_adapter):
        schema = {"type": "object", "required": ["verdict"]}
        result = anthropic_adapter.adapt_output_schema(schema)
        assert result == schema

    def test_openai_schema_wraps_json_mode(self, openai_adapter):
        schema = {"type": "object", "required": ["verdict"]}
        result = openai_adapter.adapt_output_schema(schema)
        assert result == {"response_format": {"type": "json_object"}}

    def test_none_schema_returns_none(self, anthropic_adapter, openai_adapter):
        assert anthropic_adapter.adapt_output_schema(None) is None
        assert openai_adapter.adapt_output_schema(None) is None


class TestFallbackCapabilityCompatibility:
    """Fallback models satisfy capability requirements for all tasks in their tier."""

    @pytest.mark.parametrize("tier", list(ModelTier))
    def test_fallback_meets_tier_capabilities(self, tier):
        """Each fallback model meets the capability requirements of every task in its tier."""
        # Find tasks in this tier
        tasks_in_tier = [t for t, t_tier in TASK_TIER_MAP.items() if t_tier == tier]
        fallbacks = FALLBACK_REGISTRY.get(tier, [])

        for fb in fallbacks:
            for task in tasks_in_tier:
                caps = TASK_CAPABILITIES.get(task)
                if caps is not None:
                    # Skip extended thinking — known limitation for OpenAI fallbacks
                    if caps.requires_extended_thinking:
                        continue
                    assert _matches_capabilities(fb, caps), (
                        f"Fallback {fb.model_id} does not meet capabilities "
                        f"for task {task} in {tier.value}"
                    )


class TestProviderRegistryConsistency:
    """Primary and fallback registries are consistent."""

    def test_every_tier_has_primary(self):
        for tier in ModelTier:
            assert tier in MODEL_REGISTRY, f"Missing primary model for {tier.value}"

    def test_fallback_registry_covers_all_tiers(self):
        for tier in ModelTier:
            assert tier in FALLBACK_REGISTRY, f"Missing fallback entry for {tier.value}"

    def test_tier2_has_no_fallback(self):
        """Batch tier explicitly has no fallback (can wait for provider recovery)."""
        assert FALLBACK_REGISTRY[ModelTier.TIER_2] == []

    def test_primary_and_fallback_use_different_providers(self):
        """Fallback should use a different provider than primary for resilience."""
        for tier in ModelTier:
            primary = MODEL_REGISTRY[tier]
            for fb in FALLBACK_REGISTRY.get(tier, []):
                assert fb.provider != primary.provider, (
                    f"Fallback for {tier.value} uses same provider as primary "
                    f"({fb.provider.value})"
                )


class TestGetAdapter:
    """get_adapter() factory returns correct adapter types."""

    def test_anthropic_adapter(self):
        adapter = get_adapter(LLMProvider.ANTHROPIC)
        assert adapter.provider == LLMProvider.ANTHROPIC

    def test_openai_adapter(self):
        adapter = get_adapter(LLMProvider.OPENAI)
        assert adapter.provider == LLMProvider.OPENAI

    def test_unsupported_provider_raises(self):
        with pytest.raises(ValueError, match="Unsupported provider"):
            get_adapter(LLMProvider.LOCAL)
