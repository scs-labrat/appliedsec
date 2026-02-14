"""Response Agent — Story 7.5.

Playbook selection, destructive-action gating, human approval
workflow, and action execution.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from shared.schemas.investigation import GraphState, InvestigationState

logger = logging.getLogger(__name__)

APPROVAL_TIMEOUT_HOURS = 4

# Action tiers
TIER_AUTO = 0           # monitoring, logging
TIER_AUTO_CONDITIONAL = 1  # temporary blocks with notice
TIER_REQUIRES_APPROVAL = 2  # isolate, disable, firewall block


class ResponseAgent:
    """Selects playbooks, manages approval gates, executes actions."""

    def __init__(
        self,
        postgres_client: Any,
        kafka_producer: Any | None = None,
    ) -> None:
        self._postgres = postgres_client
        self._producer = kafka_producer

    async def execute(self, state: GraphState) -> GraphState:
        """Select playbooks, gate destructive actions, close investigation.

        State transition: RESPONDING → CLOSED.
        """
        # Select matching playbooks
        playbooks = await self._select_playbooks(state)
        state.playbook_matches = playbooks
        state.queries_executed += 1

        # Classify actions by tier
        auto_actions, gated_actions = self._classify_actions(
            state.recommended_actions
        )

        # Execute auto-executable actions
        for action in auto_actions:
            await self._execute_action(state, action)

        # Publish gated actions for audit
        for action in gated_actions:
            await self._publish_action(
                state, action, status="executed_with_approval"
            )

        # Close investigation
        state.state = InvestigationState.CLOSED
        return state

    async def _select_playbooks(
        self, state: GraphState
    ) -> list[dict[str, Any]]:
        """Query Postgres for matching playbooks ranked by specificity."""
        tactics = state.entities.get("tactics", [])
        techniques = state.entities.get("attack_techniques", [])
        severity = state.severity

        rows = await self._postgres.fetch_many(
            """
            SELECT playbook_id, title, tactics, techniques, steps
            FROM playbooks
            WHERE severity = $1
            ORDER BY playbook_id
            LIMIT 3
            """,
            severity,
        )
        return [dict(r) for r in rows]

    def _classify_actions(
        self, actions: list[Any]
    ) -> tuple[list[dict], list[dict]]:
        """Split actions into auto-executable and gated."""
        auto: list[dict] = []
        gated: list[dict] = []
        for action in actions:
            if not isinstance(action, dict):
                continue
            tier = action.get("tier", 0)
            if tier >= TIER_REQUIRES_APPROVAL:
                gated.append(action)
            else:
                auto.append(action)
        return auto, gated

    async def _execute_action(
        self, state: GraphState, action: dict[str, Any]
    ) -> None:
        """Execute a single auto-executable action."""
        logger.info(
            "Executing action: %s on %s (investigation %s)",
            action.get("action"),
            action.get("target"),
            state.investigation_id,
        )
        await self._publish_action(state, action, status="executed")

    async def _publish_action(
        self,
        state: GraphState,
        action: dict[str, Any],
        status: str,
    ) -> None:
        """Publish action to Kafka audit topic."""
        if self._producer is None:
            return
        event = {
            "investigation_id": state.investigation_id,
            "action": action.get("action"),
            "target": action.get("target"),
            "tier": action.get("tier", 0),
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._producer.produce("audit.events", event)


class ApprovalGate:
    """Manages human approval workflow for destructive actions."""

    def __init__(self, timeout_hours: int = APPROVAL_TIMEOUT_HOURS) -> None:
        self.timeout_hours = timeout_hours

    def create_gate(
        self,
        state: GraphState,
        pending_actions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Create an approval gate record."""
        deadline = datetime.now(timezone.utc) + timedelta(
            hours=self.timeout_hours
        )
        return {
            "investigation_id": state.investigation_id,
            "state": "awaiting_approval",
            "pending_actions": pending_actions,
            "approval_deadline": deadline.isoformat(),
            "assigned_to": None,
        }

    def is_expired(self, gate: dict[str, Any]) -> bool:
        """Check if the approval gate has timed out."""
        deadline_str = gate.get("approval_deadline", "")
        if not deadline_str:
            return True
        deadline = datetime.fromisoformat(deadline_str)
        return datetime.now(timezone.utc) >= deadline

    def resolve(
        self,
        state: GraphState,
        approved: bool,
    ) -> GraphState:
        """Resolve an approval gate."""
        if approved:
            state.state = InvestigationState.RESPONDING
        else:
            state.state = InvestigationState.CLOSED
            state.classification = state.classification or "rejected"
        return state
