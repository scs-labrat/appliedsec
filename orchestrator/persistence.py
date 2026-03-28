"""Investigation persistence — Story 7.1.

Saves and loads GraphState to Postgres, records decision-chain entries,
and manages state transitions with audit trail.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from shared.schemas.investigation import AgentRole, GraphState, InvestigationState

logger = logging.getLogger(__name__)


def _make_decision_entry(
    agent: str,
    action: str,
    *,
    confidence: float | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an immutable decision-chain entry."""
    entry: dict[str, Any] = {
        "agent": agent,
        "action": action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if confidence is not None:
        entry["confidence"] = confidence
    if details:
        entry["details"] = details
    return entry


class InvestigationRepository:
    """Postgres persistence for GraphState with full audit trail."""

    def __init__(self, postgres_client: Any) -> None:
        self._db = postgres_client

    async def save(self, state: GraphState) -> None:
        """Insert or update an investigation record."""
        state_json = state.model_dump_json()
        await self._db.execute(
            """
            INSERT INTO investigation_state
                (investigation_id, alert_id, tenant_id, state,
                 graph_state, confidence, llm_calls, total_cost_usd,
                 created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, NOW(), NOW())
            ON CONFLICT (investigation_id) DO UPDATE SET
                state = $4,
                graph_state = $5::jsonb,
                confidence = $6,
                llm_calls = $7,
                total_cost_usd = $8,
                updated_at = NOW()
            """,
            state.investigation_id,
            state.alert_id,
            state.tenant_id,
            state.state.value,
            state_json,
            state.confidence,
            state.llm_calls,
            state.total_cost_usd,
        )

    async def load(self, investigation_id: str) -> GraphState | None:
        """Load GraphState by investigation_id."""
        row = await self._db.fetch_one(
            "SELECT graph_state FROM investigation_state WHERE investigation_id = $1",
            investigation_id,
        )
        if row is None:
            return None
        raw = row["graph_state"]
        data = raw if isinstance(raw, dict) else json.loads(raw)
        return GraphState.model_validate(data)

    async def transition(
        self,
        state: GraphState,
        new_state: InvestigationState,
        agent: str,
        action: str,
        *,
        confidence: float | None = None,
        details: dict[str, Any] | None = None,
    ) -> GraphState:
        """Transition state and persist with a new decision-chain entry."""
        entry = _make_decision_entry(
            agent, action, confidence=confidence, details=details,
        )
        state.decision_chain.append(entry)
        state.state = new_state
        await self.save(state)
        logger.info(
            "Investigation %s: %s → %s (%s)",
            state.investigation_id,
            entry["action"],
            new_state.value,
            agent,
        )

        # Story 17-7: Publish state change for WebSocket live updates
        try:
            from services.dashboard.ws import notify_state_change

            await notify_state_change(
                investigation_id=state.investigation_id,
                new_state=new_state.value,
                updated_at=entry["timestamp"],
            )
        except Exception:
            # Dashboard may not be running — non-fatal
            pass

        return state

    async def list_by_state(
        self, state: InvestigationState, limit: int = 50
    ) -> list[dict[str, Any]]:
        """List investigation summaries filtered by state."""
        return await self._db.fetch_many(
            """
            SELECT investigation_id, alert_id, tenant_id, state, updated_at
            FROM investigation_state
            WHERE state = $1
            ORDER BY updated_at DESC
            LIMIT $2
            """,
            state.value,
            limit,
        )
