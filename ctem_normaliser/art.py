"""IBM ART adversarial ML normaliser — Story 8.4."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ctem_normaliser.base import BaseNormaliser
from ctem_normaliser.models import (
    CTEMExposure,
    compute_ctem_score,
    compute_severity,
    compute_sla_deadline,
    generate_exposure_key,
)

# Attack type → (consequence, atlas_technique)
_ATTACK_MAP: dict[str, tuple[str, str]] = {
    "poisoning": ("safety_life", "AML.T0020"),
    "evasion": ("equipment", "AML.T0015"),
    "extraction": ("data_loss", "AML.T0044"),
    "inference": ("data_loss", "AML.T0044.001"),
}

DEFAULT_CONSEQUENCE = "equipment"
DEFAULT_ATLAS = "AML.T0000"


class ARTNormaliser(BaseNormaliser):
    """Normalises IBM ART adversarial ML testing results."""

    def source_name(self) -> str:
        return "art"

    def normalise(self, raw: dict[str, Any]) -> CTEMExposure:
        title = raw.get("title", raw.get("attack_name", ""))
        asset_id = raw.get("model_id", raw.get("asset_id", ""))
        attack_type = raw.get("attack_type", "").lower()

        # Consequence and ATLAS from attack type
        consequence, atlas_technique = _ATTACK_MAP.get(
            attack_type, (DEFAULT_CONSEQUENCE, DEFAULT_ATLAS)
        )

        # ATT&CK technique if provided
        attack_technique = raw.get("attack_technique", "")

        # Exploitability from success rate
        success_rate = raw.get("success_rate", 0.0)
        exploitability = _map_success_rate(success_rate)
        exploitability_score = min(max(success_rate, 0.0), 1.0)

        severity = compute_severity(exploitability, consequence)
        ctem_score = compute_ctem_score(exploitability_score, consequence)

        exposure_key = generate_exposure_key("art", title, asset_id)

        return CTEMExposure(
            exposure_key=exposure_key,
            ts=raw.get("tested_at", datetime.now(timezone.utc).isoformat()),
            source_tool="art",
            title=title,
            description=raw.get("description", ""),
            severity=severity,
            original_severity=raw.get("severity", "").upper(),
            asset_id=asset_id,
            asset_type="ml_model",
            asset_zone=raw.get("asset_zone", "Zone3_Enterprise"),
            exploitability_score=exploitability_score,
            physical_consequence=consequence,
            ctem_score=ctem_score,
            atlas_technique=atlas_technique,
            attack_technique=attack_technique,
            threat_model_ref=raw.get("threat_model_ref", ""),
            status="Open",
            sla_deadline=compute_sla_deadline(severity),
            remediation_guidance=raw.get("remediation", ""),
            evidence_url=raw.get("evidence_url", ""),
            tenant_id=raw.get("tenant_id", ""),
        )


def _map_success_rate(rate: float) -> str:
    """Map attack success rate to exploitability level."""
    if rate >= 0.7:
        return "high"
    if rate >= 0.3:
        return "medium"
    return "low"
