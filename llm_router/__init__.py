"""LLM Router — tiered model selection and priority-based routing."""

from llm_router.concurrency import ConcurrencyController, QuotaExceeded
from llm_router.escalation import EscalationManager, EscalationPolicy
from llm_router.metrics import RoutingMetrics, TierOutcome
from llm_router.models import (
    MODEL_REGISTRY,
    SEVERITY_QUEUE_MAP,
    TIER_DEFAULTS,
    AnthropicModelConfig,
    ModelTier,
    RoutingDecision,
    TaskContext,
)
from llm_router.router import LLMRouter, TASK_TIER_MAP

__all__ = [
    "AnthropicModelConfig",
    "ConcurrencyController",
    "EscalationManager",
    "EscalationPolicy",
    "LLMRouter",
    "MODEL_REGISTRY",
    "ModelTier",
    "QuotaExceeded",
    "RoutingDecision",
    "RoutingMetrics",
    "SEVERITY_QUEUE_MAP",
    "TASK_TIER_MAP",
    "TIER_DEFAULTS",
    "TaskContext",
    "TierOutcome",
]
