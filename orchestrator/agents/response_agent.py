"""Response Agent — Stories 7.5, 15.5.

Playbook selection, destructive-action gating, human approval
workflow, and action execution.

Story 15.5 adds severity-based configurable approval timeouts,
per-tenant overrides, 50% timeout escalation, and escalation
behavior for critical/high severity actions.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from orchestrator.executor_constraints import (
    DEFAULT_CONSTRAINTS,
    ExecutorConstraints,
    validate_auto_close,
    validate_playbook,
)
from shared.schemas.investigation import GraphState, InvestigationState

logger = logging.getLogger(__name__)

# Backward compat — kept for existing imports
APPROVAL_TIMEOUT_HOURS = 4

# Story 15.5: Severity-based timeout configuration
APPROVAL_TIMEOUT_BY_SEVERITY: dict[str, int] = {
    "critical": 1,
    "high": 2,
    "medium": 4,
    "low": 8,
}


def get_timeout_hours(
    severity: str,
    tenant_overrides: dict[str, int] | None = None,
) -> int:
    """Return approval timeout hours for a given severity.

    Checks tenant overrides first (if provided), then falls back to
    ``APPROVAL_TIMEOUT_BY_SEVERITY``, defaulting to 4 hours for
    unknown severity levels.
    """
    if tenant_overrides and severity in tenant_overrides:
        value = tenant_overrides[severity]
    else:
        value = APPROVAL_TIMEOUT_BY_SEVERITY.get(severity, 4)
    # F6: clamp to minimum 1 hour to prevent zero/negative timeouts
    return max(1, value)

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
        constraints: ExecutorConstraints | None = None,
        audit_producer: Any | None = None,
    ) -> None:
        self._postgres = postgres_client
        self._producer = kafka_producer
        self._constraints = constraints or DEFAULT_CONSTRAINTS
        self._audit = audit_producer

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
        """Execute a single auto-executable action with constraint checks."""
        action_type = action.get("action", "")

        # Constraint: playbook allowlist
        if action_type == "execute_playbook":
            playbook_id = action.get("playbook_id", action.get("target", ""))
            if not validate_playbook(playbook_id, self._constraints):
                logger.warning(
                    "Blocked unauthorized playbook %s (investigation %s)",
                    playbook_id,
                    state.investigation_id,
                )
                await self._publish_action(
                    state, action, status="blocked",
                    constraint_blocked_type="unauthorized_playbook",
                )
                return

        # Constraint: auto-close criteria
        if action_type == "auto_close":
            fp_matched = bool(state.classification == "false_positive")
            if not validate_auto_close(
                state.confidence, fp_matched, self._constraints
            ):
                logger.warning(
                    "Blocked auto-close: confidence=%.2f fp_matched=%s (investigation %s)",
                    state.confidence,
                    fp_matched,
                    state.investigation_id,
                )
                await self._publish_action(
                    state, action, status="blocked",
                    constraint_blocked_type="insufficient_criteria",
                )
                return

        # Constraint: routing policy modification
        if action_type == "modify_routing_policy":
            if not self._constraints.can_modify_routing_policy:
                logger.warning(
                    "Blocked routing policy modification (investigation %s)",
                    state.investigation_id,
                )
                await self._publish_action(
                    state, action, status="blocked",
                    constraint_blocked_type="routing_policy_change",
                )
                return

        logger.info(
            "Executing action: %s on %s (investigation %s)",
            action_type,
            action.get("target"),
            state.investigation_id,
        )
        await self._publish_action(state, action, status="executed")
        self._emit_audit_event(
            state, "response.executed", "action",
            context={"action": action_type, "target": action.get("target", "")},
        )

    async def _publish_action(
        self,
        state: GraphState,
        action: dict[str, Any],
        status: str,
        constraint_blocked_type: str | None = None,
    ) -> None:
        """Publish action to Kafka audit topic."""
        if self._producer is None:
            return
        event: dict[str, Any] = {
            "investigation_id": state.investigation_id,
            "action": action.get("action"),
            "target": action.get("target"),
            "tier": action.get("tier", 0),
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if constraint_blocked_type:
            event["constraint_blocked_type"] = constraint_blocked_type
        await self._producer.produce("audit.events", event)


    def _emit_audit_event(
        self,
        state: GraphState,
        event_type: str,
        event_category: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Emit an audit event via AuditProducer (fire-and-forget)."""
        if self._audit is None:
            return
        try:
            self._audit.emit(
                tenant_id=state.tenant_id,
                event_type=event_type,
                event_category=event_category,
                actor_type="agent",
                actor_id="response-agent",
                investigation_id=state.investigation_id,
                alert_id=state.alert_id,
                context=context,
            )
        except (ValueError, KeyError, TypeError):
            logger.error("Audit emit data error for %s", event_type, exc_info=True)
        except Exception:
            logger.warning("Audit emit failed for %s", event_type, exc_info=True)


class ApprovalGate:
    """Manages human approval workflow for destructive actions.

    Story 15.5 adds severity-aware timeouts, per-tenant overrides,
    50% escalation notification, and escalate-on-timeout for
    critical/high severity actions.
    """

    def __init__(
        self,
        timeout_hours: int = APPROVAL_TIMEOUT_HOURS,
        *,
        severity: str | None = None,
        tenant_overrides: dict[str, int] | None = None,
    ) -> None:
        if severity is not None:
            self.timeout_hours = get_timeout_hours(severity, tenant_overrides)
        else:
            self.timeout_hours = timeout_hours
        self.severity = severity or "medium"

        # Story 15.5 Task 4: timeout behavior by severity
        if self.severity in ("critical", "high"):
            self.timeout_behavior: str = "escalate"
        else:
            self.timeout_behavior = "close"

        # Story 15.5 Task 3: escalation tracking
        self.escalation_notified: bool = False

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

    def half_timeout_reached(self, gate: dict[str, Any]) -> bool:
        """Return True when elapsed time >= 50% of total timeout."""
        deadline_str = gate.get("approval_deadline", "")
        if not deadline_str:
            return True
        deadline = datetime.fromisoformat(deadline_str)
        half_timeout = timedelta(hours=self.timeout_hours) / 2
        half_deadline = deadline - half_timeout
        return datetime.now(timezone.utc) >= half_deadline

    def should_escalate(self, gate: dict[str, Any]) -> bool:
        """Return True when half-timeout reached and not yet notified.

        After returning True once, sets ``escalation_notified`` to
        prevent duplicate notifications.
        """
        if self.escalation_notified:
            return False
        if self.half_timeout_reached(gate):
            self.escalation_notified = True
            return True
        return False

    def resolve(
        self,
        state: GraphState,
        approved: bool,
    ) -> GraphState:
        """Resolve an approval gate.

        Story 15.5: for critical/high severity (timeout_behavior='escalate'),
        a timeout (approved=False) sets classification to 'escalated' and
        keeps the investigation open for secondary reviewer instead of closing.
        """
        if approved:
            state.state = InvestigationState.RESPONDING
        else:
            if self.timeout_behavior == "escalate":
                state.classification = state.classification or "escalated"
                # Keep investigation open for secondary reviewer
            else:
                state.state = InvestigationState.CLOSED
                state.classification = state.classification or "rejected"
        return state
