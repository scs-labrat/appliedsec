"""CTEM Correlator agent — Story 7.6.

Correlates alert entities to known CTEM exposures in Postgres.
Runs in parallel during ENRICHING state.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from shared.schemas.investigation import GraphState

logger = logging.getLogger(__name__)

# SLA deadlines by severity (hours)
SLA_DEADLINES = {
    "CRITICAL": 24,
    "HIGH": 72,
    "MEDIUM": 336,   # 14 days
    "LOW": 720,      # 30 days
}

STALENESS_HOURS = 24


class CTEMCorrelatorAgent:
    """Correlates alerts against known CTEM exposures."""

    def __init__(self, postgres_client: Any) -> None:
        self._postgres = postgres_client

    async def execute(self, state: GraphState) -> GraphState:
        """Query Postgres for CTEM exposures matching alert entities."""
        asset_ids = self._extract_asset_ids(state)
        if not asset_ids:
            return state

        exposures: list[dict[str, Any]] = []
        for asset_id in asset_ids:
            rows = await self._postgres.fetch_many(
                """
                SELECT exposure_key, asset_id, asset_zone, severity,
                       ctem_score, source_tool, status, updated_at
                FROM ctem_exposures
                WHERE asset_id = $1
                  AND status NOT IN ('Verified', 'Closed')
                ORDER BY ctem_score DESC
                """,
                asset_id,
            )
            state.queries_executed += 1
            for row in rows:
                exposure = dict(row)
                exposure["stale"] = self._is_stale(exposure.get("updated_at"))
                exposure["sla_deadline_hours"] = SLA_DEADLINES.get(
                    exposure.get("severity", "").upper(), 720
                )
                exposures.append(exposure)

        state.ctem_exposures = exposures
        return state

    def _extract_asset_ids(self, state: GraphState) -> list[str]:
        """Extract asset identifiers from entities."""
        ids: list[str] = []
        for etype in ("hosts", "ips"):
            for entity in state.entities.get(etype, []):
                if isinstance(entity, dict):
                    value = entity.get("primary_value", "")
                    if value:
                        ids.append(value)
        return ids

    def _is_stale(self, updated_at: Any) -> bool:
        """Check if exposure data is older than 24 hours."""
        if updated_at is None:
            return True
        if isinstance(updated_at, str):
            try:
                updated = datetime.fromisoformat(updated_at)
            except ValueError:
                return True
        elif isinstance(updated_at, datetime):
            updated = updated_at
        else:
            return True

        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - updated
        return age.total_seconds() > STALENESS_HOURS * 3600
