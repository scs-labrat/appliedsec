"""Postgres upsert logic for CTEM exposures — Story 8.5.

ON CONFLICT preserves Verified/Closed status to prevent reopening
resolved findings.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any

from ctem_normaliser.models import CTEMExposure

logger = logging.getLogger(__name__)

_UPSERT_SQL = """
INSERT INTO ctem_exposures (
    exposure_key, ts, source_tool, title, description,
    severity, original_severity, asset_id, asset_type, asset_zone,
    exploitability_score, physical_consequence, ctem_score,
    atlas_technique, attack_technique, threat_model_ref,
    status, assigned_to, sla_deadline, remediation_guidance,
    evidence_url, tenant_id, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10,
    $11, $12, $13,
    $14, $15, $16,
    $17, $18, $19, $20,
    $21, $22, NOW(), NOW()
)
ON CONFLICT (exposure_key) DO UPDATE SET
    ts = EXCLUDED.ts,
    severity = EXCLUDED.severity,
    ctem_score = EXCLUDED.ctem_score,
    status = CASE
        WHEN ctem_exposures.status IN ('Verified', 'Closed')
        THEN ctem_exposures.status
        ELSE EXCLUDED.status
    END,
    updated_at = NOW()
"""

_FETCH_SQL = """
SELECT exposure_key, ts, source_tool, title, description,
       severity, original_severity, asset_id, asset_type, asset_zone,
       exploitability_score, physical_consequence, ctem_score,
       atlas_technique, attack_technique, threat_model_ref,
       status, assigned_to, sla_deadline, remediation_guidance,
       evidence_url, tenant_id
FROM ctem_exposures
WHERE exposure_key = $1
"""

_FETCH_BY_ASSET_SQL = """
SELECT exposure_key, severity, ctem_score, source_tool, status, sla_deadline
FROM ctem_exposures
WHERE asset_id = $1
  AND status NOT IN ('Verified', 'Closed')
ORDER BY ctem_score DESC
"""


class CTEMRepository:
    """Postgres persistence for CTEM exposures."""

    def __init__(self, postgres_client: Any) -> None:
        self._db = postgres_client

    async def upsert(self, exposure: CTEMExposure) -> None:
        """Insert or update an exposure record.

        Preserves Verified/Closed status on conflict.
        Uses parameterised SQL — no string interpolation.
        """
        await self._db.execute(
            _UPSERT_SQL,
            exposure.exposure_key,
            exposure.ts,
            exposure.source_tool,
            exposure.title,
            exposure.description,
            exposure.severity,
            exposure.original_severity,
            exposure.asset_id,
            exposure.asset_type,
            exposure.asset_zone,
            exposure.exploitability_score,
            exposure.physical_consequence,
            exposure.ctem_score,
            exposure.atlas_technique,
            exposure.attack_technique,
            exposure.threat_model_ref,
            exposure.status,
            exposure.assigned_to,
            exposure.sla_deadline,
            exposure.remediation_guidance,
            exposure.evidence_url,
            exposure.tenant_id,
        )

    async def fetch(self, exposure_key: str) -> dict[str, Any] | None:
        """Fetch an exposure by key."""
        return await self._db.fetch_one(_FETCH_SQL, exposure_key)

    async def fetch_by_asset(self, asset_id: str) -> list[dict[str, Any]]:
        """Fetch open exposures for an asset."""
        return await self._db.fetch_many(_FETCH_BY_ASSET_SQL, asset_id)
