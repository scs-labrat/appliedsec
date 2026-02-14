"""Wiz CSPM normaliser — Story 8.1."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ctem_normaliser.base import BaseNormaliser
from ctem_normaliser.models import (
    ZONE_CONSEQUENCE_FALLBACK,
    CTEMExposure,
    compute_ctem_score,
    compute_severity,
    compute_sla_deadline,
    generate_exposure_key,
)

# Wiz severity → exploitability level
_EXPLOITABILITY_MAP: dict[str, str] = {
    "CRITICAL": "high",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "low",
}

# Wiz resource type → asset_zone
_ZONE_MAP: dict[str, str] = {
    "edge": "Zone1_EdgeInference",
    "orbital": "Zone1_EdgeInference",
    "demo": "Zone4_External",
    "public": "Zone4_External",
}


class WizNormaliser(BaseNormaliser):
    """Normalises Wiz CSPM findings."""

    def __init__(self, neo4j_client: Any | None = None) -> None:
        self._neo4j = neo4j_client

    def source_name(self) -> str:
        return "wiz"

    def normalise(self, raw: dict[str, Any]) -> CTEMExposure:
        title = raw.get("title", raw.get("name", ""))
        asset_id = raw.get("resource_id", raw.get("asset_id", ""))
        original_severity = raw.get("severity", "MEDIUM").upper()
        resource_type = raw.get("resource_type", "").lower()

        # Zone classification
        asset_zone = _ZONE_MAP.get(resource_type, "Zone3_Enterprise")

        # Consequence determination (Neo4j fallback to static)
        consequence = self._get_consequence(asset_zone)

        # Exploitability from severity
        exploitability = _EXPLOITABILITY_MAP.get(original_severity, "medium")
        exploitability_score = {"high": 0.9, "medium": 0.5, "low": 0.2}.get(
            exploitability, 0.5
        )

        # Severity from matrix
        severity = compute_severity(exploitability, consequence)
        ctem_score = compute_ctem_score(exploitability_score, consequence)

        exposure_key = generate_exposure_key("wiz", title, asset_id)

        return CTEMExposure(
            exposure_key=exposure_key,
            ts=raw.get("detected_at", datetime.now(timezone.utc).isoformat()),
            source_tool="wiz",
            title=title,
            description=raw.get("description", ""),
            severity=severity,
            original_severity=original_severity,
            asset_id=asset_id,
            asset_type=raw.get("resource_type", ""),
            asset_zone=asset_zone,
            exploitability_score=exploitability_score,
            physical_consequence=consequence,
            ctem_score=ctem_score,
            atlas_technique=raw.get("atlas_technique", ""),
            attack_technique=raw.get("attack_technique", ""),
            threat_model_ref=raw.get("threat_model_ref", ""),
            status="Open",
            sla_deadline=compute_sla_deadline(severity),
            remediation_guidance=raw.get("remediation", ""),
            evidence_url=raw.get("evidence_url", raw.get("url", "")),
            tenant_id=raw.get("tenant_id", ""),
        )

    def _get_consequence(self, asset_zone: str) -> str:
        """Look up consequence from Neo4j or fall back to static map."""
        # In production, query Neo4j for zone → consequence_class
        # For now, use static fallback
        return ZONE_CONSEQUENCE_FALLBACK.get(asset_zone, "data_loss")
