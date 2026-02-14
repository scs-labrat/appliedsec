"""LLM Router data models — Story 6.1.

Defines tiers, model configs, routing decisions, and task context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ModelTier(str, Enum):
    """Four-tier model architecture."""

    TIER_0 = "tier_0"       # Haiku  — fast, cheap
    TIER_1 = "tier_1"       # Sonnet — deep reasoning
    TIER_1_PLUS = "tier_1+" # Opus   — complex / escalation
    TIER_2 = "tier_2"       # Sonnet Batch — offline


@dataclass
class AnthropicModelConfig:
    """Per-model capabilities and pricing."""

    model_id: str
    max_context_tokens: int
    cost_per_mtok_input: float
    cost_per_mtok_output: float
    supports_extended_thinking: bool = False
    supports_tool_use: bool = True
    supports_prompt_caching: bool = True
    batch_eligible: bool = False


# ---- model registry --------------------------------------------------------

MODEL_REGISTRY: dict[ModelTier, AnthropicModelConfig] = {
    ModelTier.TIER_0: AnthropicModelConfig(
        model_id="claude-haiku-4-5-20251001",
        max_context_tokens=200_000,
        cost_per_mtok_input=0.80,
        cost_per_mtok_output=4.0,
    ),
    ModelTier.TIER_1: AnthropicModelConfig(
        model_id="claude-sonnet-4-5-20250929",
        max_context_tokens=200_000,
        cost_per_mtok_input=3.0,
        cost_per_mtok_output=15.0,
    ),
    ModelTier.TIER_1_PLUS: AnthropicModelConfig(
        model_id="claude-opus-4-6",
        max_context_tokens=200_000,
        cost_per_mtok_input=15.0,
        cost_per_mtok_output=75.0,
        supports_extended_thinking=True,
    ),
    ModelTier.TIER_2: AnthropicModelConfig(
        model_id="claude-sonnet-4-5-20250929",
        max_context_tokens=200_000,
        cost_per_mtok_input=1.5,
        cost_per_mtok_output=7.5,
        batch_eligible=True,
    ),
}


# ---- routing data ----------------------------------------------------------

@dataclass
class TaskContext:
    """Input to the router — describes the task to be routed."""

    task_type: str
    context_tokens: int = 0
    time_budget_seconds: int = 30
    alert_severity: str = "medium"
    tenant_tier: str = "standard"
    requires_reasoning: bool = False
    previous_confidence: float | None = None


@dataclass
class RoutingDecision:
    """Output of the router — the selected model and parameters."""

    tier: ModelTier
    model_config: AnthropicModelConfig
    max_tokens: int
    temperature: float
    use_extended_thinking: bool = False
    use_prompt_caching: bool = True
    reason: str = ""


# ---- default parameters per tier -------------------------------------------

TIER_DEFAULTS: dict[ModelTier, dict[str, int | float]] = {
    ModelTier.TIER_0: {"max_tokens": 2048, "temperature": 0.1},
    ModelTier.TIER_1: {"max_tokens": 8192, "temperature": 0.2},
    ModelTier.TIER_1_PLUS: {"max_tokens": 16384, "temperature": 0.2},
    ModelTier.TIER_2: {"max_tokens": 16384, "temperature": 0.3},
}


# ---- severity → priority queue mapping ------------------------------------

SEVERITY_QUEUE_MAP: dict[str, str] = {
    "critical": "jobs.llm.priority.critical",
    "high": "jobs.llm.priority.high",
    "medium": "jobs.llm.priority.normal",
    "low": "jobs.llm.priority.low",
    "informational": "jobs.llm.priority.low",
}
