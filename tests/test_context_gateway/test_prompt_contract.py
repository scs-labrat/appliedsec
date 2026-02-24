"""Contract tests for prompt schema compatibility — Story 12.5.

Verifies that Anthropic and OpenAI prompt adapters produce structurally
compatible output for all Tier 0 and Tier 1 task types.
"""

from __future__ import annotations

import pytest

from context_gateway.prompt_adapter import AnthropicPromptAdapter, OpenAIPromptAdapter
from context_gateway.prompt_builder import SYSTEM_PREFIX
from llm_router.models import ModelTier
from llm_router.router import TASK_TIER_MAP


# Collect Tier 0 and Tier 1 task types
_TIER_0_AND_1_TASKS = sorted(
    task for task, tier in TASK_TIER_MAP.items()
    if tier in (ModelTier.TIER_0, ModelTier.TIER_1)
)


class TestPromptSchemaContract:
    """Both adapters produce structurally compatible prompts for all tasks."""

    @pytest.fixture(autouse=True)
    def setup_adapters(self):
        self.anthropic = AnthropicPromptAdapter()
        self.openai = OpenAIPromptAdapter()

    @pytest.mark.parametrize("task_type", _TIER_0_AND_1_TASKS)
    def test_both_adapters_include_safety_prefix(self, task_type: str):
        """Safety prefix appears in adapted system prompt for both providers."""
        task_prompt = f"Perform {task_type} analysis on the following alert."

        anthropic_blocks = self.anthropic.adapt_system(task_prompt)
        openai_blocks = self.openai.adapt_system(task_prompt)

        # Extract text content from each format
        anthropic_text = anthropic_blocks[0]["text"]
        openai_text = openai_blocks[0]["content"]

        assert SYSTEM_PREFIX in anthropic_text, f"Anthropic missing safety prefix for {task_type}"
        assert SYSTEM_PREFIX in openai_text, f"OpenAI missing safety prefix for {task_type}"

    @pytest.mark.parametrize("task_type", _TIER_0_AND_1_TASKS)
    def test_both_adapters_produce_valid_structure(self, task_type: str):
        """Both adapters return list[dict] for system and messages."""
        task_prompt = f"Perform {task_type} analysis."
        user_content = f"Alert data for {task_type}"

        for adapter in (self.anthropic, self.openai):
            system = adapter.adapt_system(task_prompt)
            messages = adapter.adapt_messages(user_content)

            assert isinstance(system, list), f"{adapter.provider}: system not a list"
            assert len(system) >= 1, f"{adapter.provider}: system empty"
            assert isinstance(system[0], dict), f"{adapter.provider}: system[0] not dict"

            assert isinstance(messages, list), f"{adapter.provider}: messages not a list"
            assert len(messages) >= 1, f"{adapter.provider}: messages empty"
            assert messages[0]["role"] == "user", f"{adapter.provider}: first message not user"

    @pytest.mark.parametrize("task_type", _TIER_0_AND_1_TASKS)
    def test_same_task_prompt_produces_same_content(self, task_type: str):
        """Both adapters carry the same task prompt text (different format)."""
        task_prompt = f"Perform {task_type} analysis."

        anthropic_blocks = self.anthropic.adapt_system(task_prompt)
        openai_blocks = self.openai.adapt_system(task_prompt)

        anthropic_text = anthropic_blocks[0]["text"]
        openai_text = openai_blocks[0]["content"]

        assert task_prompt in anthropic_text
        assert task_prompt in openai_text
