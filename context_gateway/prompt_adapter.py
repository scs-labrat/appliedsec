"""Per-provider prompt adapters — Story 12.5.

Translates internal ALUSKORT prompt format to provider-specific
message structures for Anthropic and OpenAI.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from context_gateway.prompt_builder import build_cached_system_blocks, build_system_prompt
from shared.schemas.routing import LLMProvider


class PromptAdapter(ABC):
    """Abstract base for provider-specific prompt formatting."""

    @property
    @abstractmethod
    def provider(self) -> LLMProvider: ...

    @abstractmethod
    def adapt_system(self, task_prompt: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def adapt_messages(self, user_content: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def adapt_output_schema(self, schema: dict | None) -> dict | None: ...


class AnthropicPromptAdapter(PromptAdapter):
    """Anthropic Messages API format with cache_control blocks."""

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.ANTHROPIC

    def adapt_system(self, task_prompt: str) -> list[dict[str, Any]]:
        return build_cached_system_blocks(task_prompt)

    def adapt_messages(self, user_content: str) -> list[dict[str, Any]]:
        return [{"role": "user", "content": user_content}]

    def adapt_output_schema(self, schema: dict | None) -> dict | None:
        return schema


class OpenAIPromptAdapter(PromptAdapter):
    """OpenAI Chat Completions API format."""

    @property
    def provider(self) -> LLMProvider:
        return LLMProvider.OPENAI

    def adapt_system(self, task_prompt: str) -> list[dict[str, Any]]:
        full_prompt = build_system_prompt(task_prompt)
        return [{"role": "system", "content": full_prompt}]

    def adapt_messages(self, user_content: str) -> list[dict[str, Any]]:
        return [{"role": "user", "content": user_content}]

    def adapt_output_schema(self, schema: dict | None) -> dict | None:
        if schema is None:
            return None
        return {"response_format": {"type": "json_object"}}


def get_adapter(provider: LLMProvider) -> PromptAdapter:
    """Return the prompt adapter for *provider*."""
    adapters: dict[LLMProvider, type[PromptAdapter]] = {
        LLMProvider.ANTHROPIC: AnthropicPromptAdapter,
        LLMProvider.OPENAI: OpenAIPromptAdapter,
    }
    cls = adapters.get(provider)
    if cls is None:
        raise ValueError(f"Unsupported provider for prompt adaptation: {provider.value}")
    return cls()
