"""Garak LLM security normaliser — Story 8.3."""

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

# Probe type → (consequence, atlas_technique)
_PROBE_MAP: dict[str, tuple[str, str]] = {
    "escalation": ("safety_life", "AML.T0051"),
    "tool_use": ("safety_life", "AML.T0051"),
    "prompt_injection": ("safety_life", "AML.T0051"),
    "extraction": ("data_loss", "AML.T0044.001"),
    "exfiltration": ("data_loss", "AML.T0044.001"),
    "jailbreak": ("safety_life", "AML.T0051"),
    "encoding": ("data_loss", "AML.T0051"),
}

DEFAULT_ATLAS = "AML.T0051"  # LLM Prompt Injection
DEFAULT_CONSEQUENCE = "data_loss"


class GarakNormaliser(BaseNormaliser):
    """Normalises Garak LLM security test findings."""

    def source_name(self) -> str:
        return "garak"

    def normalise(self, raw: dict[str, Any]) -> CTEMExposure:
        title = raw.get("title", raw.get("probe_name", ""))
        model_name = raw.get("model_name", raw.get("asset_id", ""))
        probe_type = raw.get("probe_type", raw.get("category", "")).lower()

        # Determine consequence and ATLAS technique from probe type
        consequence, atlas_technique = _PROBE_MAP.get(
            probe_type, (DEFAULT_CONSEQUENCE, DEFAULT_ATLAS)
        )

        # Exploitability from success rate
        success_rate = raw.get("success_rate", raw.get("pass_rate", 0.0))
        exploitability = _map_success_rate(success_rate)
        exploitability_score = min(max(success_rate, 0.0), 1.0)

        severity = compute_severity(exploitability, consequence)
        ctem_score = compute_ctem_score(exploitability_score, consequence)

        asset_zone = raw.get("deployment_zone", "Zone3_Enterprise")
        exposure_key = generate_exposure_key("garak", title, model_name)

        return CTEMExposure(
            exposure_key=exposure_key,
            ts=raw.get("tested_at", datetime.now(timezone.utc).isoformat()),
            source_tool="garak",
            title=title,
            description=raw.get("description", ""),
            severity=severity,
            original_severity=raw.get("severity", "").upper(),
            asset_id=model_name,
            asset_type="llm_model",
            asset_zone=asset_zone,
            exploitability_score=exploitability_score,
            physical_consequence=consequence,
            ctem_score=ctem_score,
            atlas_technique=atlas_technique,
            attack_technique=raw.get("attack_technique", ""),
            threat_model_ref=raw.get("threat_model_ref", ""),
            status="Open",
            sla_deadline=compute_sla_deadline(severity),
            remediation_guidance=raw.get("remediation", ""),
            evidence_url=raw.get("evidence_url", ""),
            tenant_id=raw.get("tenant_id", ""),
        )


def _map_success_rate(rate: float) -> str:
    """Map probe success rate to exploitability level."""
    if rate >= 0.7:
        return "high"
    if rate >= 0.3:
        return "medium"
    return "low"
