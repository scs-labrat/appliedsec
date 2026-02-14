"""LLM Router — Story 6.1.

Maps task types to model tiers via ``TASK_TIER_MAP`` and applies
routing overrides for severity, context size, and time budget.
"""

from __future__ import annotations

import logging

from llm_router.models import (
    MODEL_REGISTRY,
    TIER_DEFAULTS,
    ModelTier,
    RoutingDecision,
    TaskContext,
)

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
    """Routes tasks to the most cost-effective model tier."""

    def route(self, ctx: TaskContext) -> RoutingDecision:
        """Determine the optimal model tier for *ctx*.

        Applies the following override chain (in order):

        1. Base tier from ``TASK_TIER_MAP``.
        2. **Time budget** < 3 s → force Tier 0.
        3. **Critical severity** + requires_reasoning → min Tier 1.
        4. **Context tokens** > 100 K → min Tier 1.
        5. **Low confidence escalation** (previous_confidence < 0.6
           on critical / high) → Tier 1+.
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

        return RoutingDecision(
            tier=tier,
            model_config=config,
            max_tokens=int(defaults["max_tokens"]),
            temperature=float(defaults["temperature"]),
            use_extended_thinking=tier == ModelTier.TIER_1_PLUS,
            use_prompt_caching=config.supports_prompt_caching,
            reason="; ".join(reasons),
        )
