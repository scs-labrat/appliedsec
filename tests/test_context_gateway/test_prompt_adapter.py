"""Tests for prompt adapters — Story 12.5."""

from __future__ import annotations

import pytest

from context_gateway.prompt_adapter import (
    AnthropicPromptAdapter,
    OpenAIPromptAdapter,
    PromptAdapter,
    get_adapter,
)
from context_gateway.prompt_builder import SYSTEM_PREFIX
from shared.schemas.routing import LLMProvider


# ---------- AnthropicPromptAdapter — Task 1 -----------------------------------

class TestAnthropicAdapter:
    """AnthropicPromptAdapter produces Anthropic-compatible prompt format."""

    def setup_method(self):
        self.adapter = AnthropicPromptAdapter()

    def test_provider_is_anthropic(self):
        assert self.adapter.provider == LLMProvider.ANTHROPIC

    def test_adapt_system_returns_cache_control_blocks(self):
        blocks = self.adapter.adapt_system("Classify this alert.")
        assert isinstance(blocks, list)
        assert len(blocks) == 1
        assert blocks[0]["type"] == "text"
        assert blocks[0]["cache_control"] == {"type": "ephemeral"}

    def test_adapt_system_includes_safety_prefix(self):
        blocks = self.adapter.adapt_system("Analyse threat indicators.")
        text = blocks[0]["text"]
        assert SYSTEM_PREFIX in text
        assert "Analyse threat indicators." in text

    def test_adapt_messages_format(self):
        messages = self.adapter.adapt_messages("Some user content")
        assert isinstance(messages, list)
        assert len(messages) == 1
        assert messages[0]["role"] == "user"
        assert messages[0]["content"] == "Some user content"

    def test_adapt_output_schema_passthrough(self):
        schema = {"type": "object", "properties": {"verdict": {"type": "string"}}}
        result = self.adapter.adapt_output_schema(schema)
        assert result == schema

    def test_adapt_output_schema_none(self):
        result = self.adapter.adapt_output_schema(None)
        assert result is None


# ---------- OpenAIPromptAdapter — Task 2 --------------------------------------

class TestOpenAIAdapter:
    """OpenAIPromptAdapter produces OpenAI-compatible prompt format."""

    def setup_method(self):
        self.adapter = OpenAIPromptAdapter()

    def test_provider_is_openai(self):
        assert self.adapter.provider == LLMProvider.OPENAI

    def test_adapt_system_no_cache_control(self):
        blocks = self.adapter.adapt_system("Classify this alert.")
        assert isinstance(blocks, list)
        assert len(blocks) == 1
        assert "cache_control" not in blocks[0]

    def test_adapt_system_has_role_system(self):
        blocks = self.adapter.adapt_system("Classify this alert.")
        assert blocks[0]["role"] == "system"
        assert "content" in blocks[0]

    def test_adapt_system_includes_safety_prefix(self):
        blocks = self.adapter.adapt_system("Analyse threat indicators.")
        content = blocks[0]["content"]
        assert SYSTEM_PREFIX in content
        assert "Analyse threat indicators." in content

    def test_adapt_messages_format(self):
        messages = self.adapter.adapt_messages("Some user content")
        assert isinstance(messages, list)
        assert len(messages) == 1
        assert messages[0]["role"] == "user"
        assert messages[0]["content"] == "Some user content"

    def test_adapt_output_schema_with_json_directive(self):
        schema = {"type": "object", "properties": {"verdict": {"type": "string"}}}
        result = self.adapter.adapt_output_schema(schema)
        assert result == {"response_format": {"type": "json_object"}}

    def test_adapt_output_schema_none_returns_none(self):
        result = self.adapter.adapt_output_schema(None)
        assert result is None


# ---------- PromptAdapterFactory — Task 3 -------------------------------------

class TestAdapterFactory:
    """get_adapter() dispatches to the correct adapter."""

    def test_anthropic_returns_anthropic_adapter(self):
        adapter = get_adapter(LLMProvider.ANTHROPIC)
        assert isinstance(adapter, AnthropicPromptAdapter)

    def test_openai_returns_openai_adapter(self):
        adapter = get_adapter(LLMProvider.OPENAI)
        assert isinstance(adapter, OpenAIPromptAdapter)

    def test_unsupported_provider_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            get_adapter(LLMProvider.LOCAL)

    def test_groq_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            get_adapter(LLMProvider.GROQ)
