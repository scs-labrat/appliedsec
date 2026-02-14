"""Reasoning Agent — Story 7.4.

Tier 1 (Sonnet) classification with structured output, escalation
to Tier 1+ (Opus) on low confidence for critical/high severity.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from shared.schemas.investigation import GraphState, InvestigationState

logger = logging.getLogger(__name__)

REASONING_SYSTEM_PROMPT = (
    "You are a SOC analyst AI. Classify the security alert using the enriched "
    "context provided. Return JSON with fields: classification (true_positive, "
    "false_positive, suspicious, investigation_required), confidence (0.0-1.0), "
    "severity (critical, high, medium, low), attack_techniques (list of ATT&CK IDs), "
    "atlas_techniques (list of ATLAS IDs), recommended_actions (list of "
    "{action, target, tier, rationale}), reasoning (explanation)."
)

ESCALATION_CONFIDENCE_THRESHOLD = 0.6
ESCALATION_SEVERITIES = frozenset({"critical", "high"})
DESTRUCTIVE_ACTION_TIER = 2


class ReasoningAgent:
    """Multi-hop classification with escalation logic."""

    def __init__(
        self,
        gateway: Any,
        escalation_manager: Any | None = None,
    ) -> None:
        self._gateway = gateway
        self._escalation = escalation_manager

    async def execute(self, state: GraphState) -> GraphState:
        """Classify the alert using Sonnet, escalate to Opus if needed.

        State transition: ENRICHING → REASONING → RESPONDING | AWAITING_HUMAN.
        """
        state.state = InvestigationState.REASONING

        # Build context for LLM
        context = _build_reasoning_context(state)

        from context_gateway.gateway import GatewayRequest

        request = GatewayRequest(
            agent_id="reasoning_agent",
            task_type="investigation",
            system_prompt=REASONING_SYSTEM_PROMPT,
            user_content=context,
            tenant_id=state.tenant_id,
        )
        response = await self._gateway.complete(request)
        state.llm_calls += 1
        if response.metrics:
            state.total_cost_usd += response.metrics.cost_usd

        # Parse classification
        result = _parse_classification(response.content)
        state.classification = result.get("classification", "investigation_required")
        state.confidence = result.get("confidence", 0.0)
        state.severity = result.get("severity", state.severity or "medium")
        state.recommended_actions = result.get("recommended_actions", [])

        # Merge techniques
        attack_techs = result.get("attack_techniques", [])
        atlas_techs = result.get("atlas_techniques", [])
        if attack_techs:
            existing = state.entities.get("attack_techniques", [])
            state.entities["attack_techniques"] = list(set(existing + attack_techs))
        if atlas_techs:
            state.atlas_techniques.extend(
                {"atlas_id": t, "source": "reasoning"} for t in atlas_techs
                if not any(a.get("atlas_id") == t for a in state.atlas_techniques)
            )

        # Check escalation
        if self._needs_escalation(state):
            state = await self._escalate(state, context)

        # Determine next state
        if self._needs_human_approval(state):
            state.requires_human_approval = True
            state.state = InvestigationState.AWAITING_HUMAN
        else:
            state.state = InvestigationState.RESPONDING

        return state

    def _needs_escalation(self, state: GraphState) -> bool:
        """Check if we should escalate to Opus."""
        if self._escalation is None:
            return False
        return self._escalation.should_escalate(
            state.confidence, state.severity
        )

    async def _escalate(self, state: GraphState, context: str) -> GraphState:
        """Re-analyse with Opus (Tier 1+)."""
        from context_gateway.gateway import GatewayRequest

        request = GatewayRequest(
            agent_id="reasoning_agent_escalated",
            task_type="investigation",
            system_prompt=REASONING_SYSTEM_PROMPT + "\n\nThis is an escalated analysis. Be thorough.",
            user_content=context,
            tenant_id=state.tenant_id,
        )
        response = await self._gateway.complete(request)
        state.llm_calls += 1
        if response.metrics:
            state.total_cost_usd += response.metrics.cost_usd

        result = _parse_classification(response.content)
        # Only update if escalated result has higher confidence
        if result.get("confidence", 0) > state.confidence:
            state.classification = result.get("classification", state.classification)
            state.confidence = result.get("confidence", state.confidence)
            state.severity = result.get("severity", state.severity)
            state.recommended_actions = result.get(
                "recommended_actions", state.recommended_actions
            )

        if self._escalation:
            self._escalation.record_escalation()

        return state

    def _needs_human_approval(self, state: GraphState) -> bool:
        """Check if any action requires human approval."""
        # Destructive actions require approval
        for action in state.recommended_actions:
            if isinstance(action, dict) and action.get("tier", 0) >= DESTRUCTIVE_ACTION_TIER:
                return True

        # Low confidence on critical/high requires human review
        if (
            state.confidence < ESCALATION_CONFIDENCE_THRESHOLD
            and state.severity in ESCALATION_SEVERITIES
        ):
            return True

        return False


def _build_reasoning_context(state: GraphState) -> str:
    """Build JSON context string for the reasoning LLM."""
    ctx = {
        "alert_id": state.alert_id,
        "severity": state.severity,
        "entities": state.entities,
        "ioc_matches": state.ioc_matches,
        "ueba_context": state.ueba_context,
        "ctem_exposures": state.ctem_exposures,
        "atlas_techniques": state.atlas_techniques,
        "similar_incidents": state.similar_incidents,
        "risk_state": state.risk_state,
    }
    return json.dumps(ctx, default=str)


def _parse_classification(content: str) -> dict[str, Any]:
    """Parse classification JSON from LLM response."""
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, TypeError):
        pass
    return {}
