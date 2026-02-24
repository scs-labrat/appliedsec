"""Provider-neutral routing schemas — Story 12.2.

Defines :class:`LLMProvider` enum, :class:`TaskCapabilities` model, and
:class:`ModelConfig` model for multi-provider LLM routing.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    LOCAL = "local"
    GROQ = "groq"


class TaskCapabilities(BaseModel):
    """Capability requirements for a task type."""

    requires_tool_use: bool = False
    requires_json_reliability: bool = False
    max_context_tokens: int = 8192
    latency_slo_seconds: int = 30
    requires_extended_thinking: bool = False


class ModelConfig(BaseModel):
    """Provider-neutral model configuration and pricing."""

    provider: LLMProvider
    model_id: str
    max_context_tokens: int
    cost_per_mtok_input: float
    cost_per_mtok_output: float
    supports_extended_thinking: bool = False
    supports_tool_use: bool = True
    supports_prompt_caching: bool = True
    batch_eligible: bool = False
    capabilities: TaskCapabilities = TaskCapabilities()
