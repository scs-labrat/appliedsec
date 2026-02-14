"""Snyk SCA normaliser — Story 8.2."""

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

# ML-related packages that escalate to safety_life consequence
_ML_PACKAGES = frozenset({
    "torch", "pytorch", "tensorflow", "tf", "sklearn", "scikit-learn",
    "keras", "onnx", "onnxruntime", "xgboost", "lightgbm",
    "transformers", "huggingface",
})


class SnykNormaliser(BaseNormaliser):
    """Normalises Snyk SCA vulnerability findings."""

    def source_name(self) -> str:
        return "snyk"

    def normalise(self, raw: dict[str, Any]) -> CTEMExposure:
        title = raw.get("title", raw.get("packageName", ""))
        asset_id = raw.get("project_id", raw.get("asset_id", ""))
        original_severity = raw.get("severity", "medium").upper()
        package_name = raw.get("packageName", "").lower()

        # CVSS exploitability sub-score → exploitability level
        cvss_exploit = raw.get("exploitability_score", raw.get("cvssExploitability", 0.0))
        exploitability = _map_cvss_exploitability(cvss_exploit)
        exploitability_score = min(max(cvss_exploit / 10.0, 0.0), 1.0)

        # Consequence: ML packages → safety_life, else data_loss
        consequence = "safety_life" if _is_ml_package(package_name) else "data_loss"

        severity = compute_severity(exploitability, consequence)
        ctem_score = compute_ctem_score(exploitability_score, consequence)

        exposure_key = generate_exposure_key("snyk", title, asset_id)

        return CTEMExposure(
            exposure_key=exposure_key,
            ts=raw.get("disclosed_at", raw.get("publicationTime", datetime.now(timezone.utc).isoformat())),
            source_tool="snyk",
            title=title,
            description=raw.get("description", ""),
            severity=severity,
            original_severity=original_severity,
            asset_id=asset_id,
            asset_type=raw.get("packageManager", ""),
            asset_zone="Zone3_Enterprise",
            exploitability_score=exploitability_score,
            physical_consequence=consequence,
            ctem_score=ctem_score,
            atlas_technique=raw.get("atlas_technique", ""),
            attack_technique=raw.get("attack_technique", raw.get("cve", "")),
            threat_model_ref=raw.get("threat_model_ref", ""),
            status="Open",
            sla_deadline=compute_sla_deadline(severity),
            remediation_guidance=raw.get("remediation", raw.get("fixedIn", "")),
            evidence_url=raw.get("url", ""),
            tenant_id=raw.get("tenant_id", ""),
        )


def _map_cvss_exploitability(score: float) -> str:
    """Map CVSS exploitability sub-score (0–10) to level."""
    if score >= 7.0:
        return "high"
    if score >= 3.0:
        return "medium"
    return "low"


def _is_ml_package(name: str) -> bool:
    """Check if a package is ML-related."""
    return any(ml in name for ml in _ML_PACKAGES)
