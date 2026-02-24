"""LLM Router — Stories 6.1, 12.2, 12.3.

Maps task types to model tiers via ``TASK_TIER_MAP`` and applies
routing overrides for severity, context size, and time budget.
Capability matching validates the selected model meets task requirements.
Health-aware fallback selects secondary providers when primary is unavailable.
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from llm_router.models import (
    FALLBACK_REGISTRY,
    MODEL_REGISTRY,
    TIER_DEFAULTS,
    ModelConfig,
    ModelTier,
    RoutingDecision,
    TaskContext,
)
from shared.schemas.routing import TaskCapabilities

if TYPE_CHECKING:
    from llm_router.circuit_breaker import ProviderHealthRegistry
    from llm_router.metrics import RoutingMetrics

logger = logging.getLogger(__name__)

# ---- task → base tier mapping ----------------------------------------------

TASK_TIER_MAP: dict[str, ModelTier] = {
    # Tier 0 — Haiku (fast, cheap)
    "ioc_extraction": ModelTier.TIER_0,
    "log_summarisation": ModelTier.TIER_0,
    "entity_normalisation": ModelTier.TIER_0,
    "fp_suggestion": ModelTier.TIER_0,
    "alert_classification": ModelTier.TIER_0,
    "severity_assessment": ModelTier.TIER_0,
    # Tier 1 — Sonnet (deep reasoning)
    "investigation": ModelTier.TIER_1,
    "ctem_correlation": ModelTier.TIER_1,
    "atlas_reasoning": ModelTier.TIER_1,
    "attack_path_analysis": ModelTier.TIER_1,
    "incident_report": ModelTier.TIER_1,
    "playbook_selection": ModelTier.TIER_1,
    # Tier 2 — Sonnet Batch (offline)
    "fp_pattern_training": ModelTier.TIER_2,
    "playbook_generation": ModelTier.TIER_2,
    "agent_red_team": ModelTier.TIER_2,
    "detection_rule_generation": ModelTier.TIER_2,
    "retrospective_analysis": ModelTier.TIER_2,
    "threat_landscape_summary": ModelTier.TIER_2,
}

# ---- task → capability requirements (Story 12.2) ----------------------------

TASK_CAPABILITIES: dict[str, TaskCapabilities] = {
    # Tier 0 — fast, cheap
    "ioc_extraction": TaskCapabilities(
        requires_json_reliability=True, max_context_tokens=4096, latency_slo_seconds=3,
    ),
    "log_summarisation": TaskCapabilities(
        max_context_tokens=8192, latency_slo_seconds=3,
    ),
    "entity_normalisation": TaskCapabilities(
        requires_json_reliability=True, max_context_tokens=4096, latency_slo_seconds=3,
    ),
    "fp_suggestion": TaskCapabilities(
        requires_json_reliability=True, max_context_tokens=4096, latency_slo_seconds=3,
    ),
    "alert_classification": TaskCapabilities(
        requires_json_reliability=True, max_context_tokens=4096, latency_slo_seconds=3,
    ),
    "severity_assessment": TaskCapabilities(
        requires_json_reliability=True, max_context_tokens=4096, latency_slo_seconds=3,
    ),
    # Tier 1 — deep reasoning
    "investigation": TaskCapabilities(
        requires_tool_use=True, requires_json_reliability=True, max_context_tokens=100_000,
    ),
    "ctem_correlation": TaskCapabilities(
        requires_tool_use=True, requires_json_reliability=True, max_context_tokens=50_000,
    ),
    "atlas_reasoning": TaskCapabilities(
        requires_tool_use=True, requires_json_reliability=True, max_context_tokens=50_000,
    ),
    "attack_path_analysis": TaskCapabilities(
        requires_tool_use=True, requires_json_reliability=True, max_context_tokens=100_000,
    ),
    "incident_report": TaskCapabilities(
        requires_json_reliability=True, max_context_tokens=50_000,
    ),
    "playbook_selection": TaskCapabilities(
        requires_tool_use=True, requires_json_reliability=True, max_context_tokens=50_000,
    ),
    # Tier 2 — batch (offline)
    "fp_pattern_training": TaskCapabilities(
        requires_json_reliability=True, max_context_tokens=200_000, latency_slo_seconds=86_400,
    ),
    "playbook_generation": TaskCapabilities(
        requires_tool_use=True, requires_json_reliability=True,
        max_context_tokens=100_000, latency_slo_seconds=86_400,
    ),
    "agent_red_team": TaskCapabilities(
        requires_tool_use=True, requires_json_reliability=True,
        max_context_tokens=200_000, latency_slo_seconds=86_400,
    ),
    "detection_rule_generation": TaskCapabilities(
        requires_tool_use=True, requires_json_reliability=True,
        max_context_tokens=100_000, latency_slo_seconds=86_400,
    ),
    "retrospective_analysis": TaskCapabilities(
        requires_json_reliability=True, max_context_tokens=200_000, latency_slo_seconds=86_400,
    ),
    "threat_landscape_summary": TaskCapabilities(
        max_context_tokens=200_000, latency_slo_seconds=86_400,
    ),
}


def _matches_capabilities(model: ModelConfig, caps: TaskCapabilities) -> bool:
    """Check whether *model* satisfies all *caps* requirements."""
    if caps.requires_tool_use and not model.supports_tool_use:
        return False
    if caps.requires_extended_thinking and not model.supports_extended_thinking:
        return False
    if caps.max_context_tokens > model.max_context_tokens:
        return False
    return True


# Tier ordering for ``max()`` comparisons
_TIER_ORDER = {
    ModelTier.TIER_0: 0,
    ModelTier.TIER_1: 1,
    ModelTier.TIER_1_PLUS: 2,
    ModelTier.TIER_2: 0,  # batch is not "higher" than tier 0
}


def _tier_max(a: ModelTier, b: ModelTier) -> ModelTier:
    return a if _TIER_ORDER[a] >= _TIER_ORDER[b] else b


class LLMRouter:
    """Routes tasks to the most cost-effective model tier.

    Optionally accepts a :class:`ProviderHealthRegistry` for health-aware
    fallback and a :class:`RoutingMetrics` for provider selection tracking.
    """

    def __init__(
        self,
        health_registry: ProviderHealthRegistry | None = None,
        metrics: RoutingMetrics | None = None,
        audit_producer: Any | None = None,
    ) -> None:
        self._health = health_registry
        self._metrics = metrics
        self._audit = audit_producer

    def route(self, ctx: TaskContext) -> RoutingDecision:
        """Determine the optimal model tier for *ctx*.

        Applies the following override chain (in order):

        1. Base tier from ``TASK_TIER_MAP``.
        2. **Time budget** < 3 s → force Tier 0.
        3. **Critical severity** + requires_reasoning → min Tier 1.
        4. **Context tokens** > 100 K → min Tier 1.
        5. **Low confidence escalation** (previous_confidence < 0.6
           on critical / high) → Tier 1+.
        6. Capability validation (log-only).
        7. Populate fallback_configs from ``FALLBACK_REGISTRY``.
        8. Health-aware primary selection (swap to fallback if primary down).
        """
        reasons: list[str] = []

        # 1 — base tier
        base = TASK_TIER_MAP.get(ctx.task_type, ModelTier.TIER_1)
        tier = base
        reasons.append(f"base={base.value}")

        # 2 — time budget override (fastest wins)
        if ctx.time_budget_seconds < 3:
            tier = ModelTier.TIER_0
            reasons.append("time_budget<3s→tier_0")

        # 3 — severity override
        elif ctx.alert_severity == "critical" and ctx.requires_reasoning:
            tier = _tier_max(tier, ModelTier.TIER_1)
            if tier != base:
                reasons.append("critical+reasoning→min_tier_1")

        # 4 — context size override
        if ctx.context_tokens > 100_000 and tier == ModelTier.TIER_0:
            tier = ModelTier.TIER_1
            reasons.append("context>100k→tier_1")

        # 5 — escalation
        if (
            ctx.previous_confidence is not None
            and ctx.previous_confidence < 0.6
            and ctx.alert_severity in ("critical", "high")
        ):
            tier = ModelTier.TIER_1_PLUS
            reasons.append("low_confidence_escalation→tier_1+")

        # Build decision
        config = MODEL_REGISTRY[tier]
        defaults = TIER_DEFAULTS[tier]

        # 6 — capability validation (log-only)
        caps = TASK_CAPABILITIES.get(ctx.task_type)
        if caps is not None and not _matches_capabilities(config, caps):
            logger.warning(
                "Model %s does not meet capability requirements for task %s",
                config.model_id, ctx.task_type,
            )

        # 7 — populate fallback_configs from FALLBACK_REGISTRY
        fallback_configs: list[ModelConfig] = []
        for fb in FALLBACK_REGISTRY.get(tier, []):
            if caps is None or _matches_capabilities(fb, caps):
                fallback_configs.append(fb)

        # 8 — health-aware primary selection
        is_fallback = False
        if self._health is not None and not self._health.is_available(config.provider):
            primary_provider = config.provider.value
            replaced = False
            for i, fb in enumerate(fallback_configs):
                if self._health.is_available(fb.provider):
                    config = fb
                    fallback_configs = fallback_configs[:i] + fallback_configs[i + 1:]
                    reasons.append(
                        f"primary_unavailable→fallback({config.provider.value})"
                    )
                    replaced = True
                    is_fallback = True
                    self._emit_provider_failover(
                        ctx, primary_provider, config.provider.value,
                    )
                    break
            if not replaced:
                logger.warning(
                    "Primary provider %s unavailable and no healthy fallback for tier %s",
                    MODEL_REGISTRY[tier].provider.value, tier.value,
                )

        # 9 — record provider selection metrics
        if self._metrics is not None:
            self._metrics.record_provider_selection(
                provider=config.provider.value,
                tier=tier.value,
                is_fallback=is_fallback,
            )

        # 10 — compute degradation level (Story 12.4)
        degradation_level = "full_capability"
        if self._health is not None:
            degradation_level = self._health.compute_degradation_level().value
            if degradation_level != "full_capability":
                reasons.append(f"degradation={degradation_level}")

        return RoutingDecision(
            tier=tier,
            model_config=config,
            max_tokens=int(defaults["max_tokens"]),
            temperature=float(defaults["temperature"]),
            use_extended_thinking=tier == ModelTier.TIER_1_PLUS,
            use_prompt_caching=config.supports_prompt_caching,
            reason="; ".join(reasons),
            fallback_configs=fallback_configs,
            degradation_level=degradation_level,
        )

    # ── Audit helpers (fire-and-forget) ─────────────────────────

    def _emit_provider_failover(
        self, ctx: TaskContext, primary_provider: str, fallback_provider: str,
    ) -> None:
        if self._audit is None:
            return
        try:
            self._audit.emit(
                tenant_id=getattr(ctx, "tenant_id", "unknown"),
                event_type="routing.provider_failover",
                event_category="decision",
                actor_type="system",
                actor_id="llm-router",
                context={
                    "primary_provider": primary_provider,
                    "fallback_provider": fallback_provider,
                    "task_type": ctx.task_type,
                },
            )
        except (ValueError, KeyError, TypeError):
            logger.error("Audit emit data error for routing.provider_failover", exc_info=True)
        except Exception:
            logger.warning("Audit emit failed for routing.provider_failover", exc_info=True)
