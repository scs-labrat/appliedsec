"""CTEM Exposure data models and scoring — shared across all normalisers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass
class CTEMExposure:
    """Normalised CTEM exposure record (22 fields)."""

    exposure_key: str
    ts: str
    source_tool: str
    title: str
    description: str = ""
    severity: str = ""           # From consequence-weighted matrix
    original_severity: str = ""  # Raw severity from the tool
    asset_id: str = ""
    asset_type: str = ""
    asset_zone: str = ""
    exploitability_score: float = 0.0   # 0.0–1.0
    physical_consequence: str = ""      # safety_life | equipment | downtime | data_loss
    ctem_score: float = 0.0             # 0.0–10.0
    atlas_technique: str = ""
    attack_technique: str = ""
    threat_model_ref: str = ""
    status: str = "Open"
    assigned_to: str = ""
    sla_deadline: str = ""
    remediation_guidance: str = ""
    evidence_url: str = ""
    tenant_id: str = ""


# ---- Consequence-weighted severity matrix ------------------------------------

SEVERITY_MATRIX: dict[tuple[str, str], str] = {
    # (exploitability, consequence) → severity
    ("high", "safety_life"): "CRITICAL",
    ("high", "equipment"): "CRITICAL",
    ("high", "downtime"): "HIGH",
    ("high", "data_loss"): "MEDIUM",
    ("medium", "safety_life"): "CRITICAL",
    ("medium", "equipment"): "HIGH",
    ("medium", "downtime"): "MEDIUM",
    ("medium", "data_loss"): "LOW",
    ("low", "safety_life"): "HIGH",
    ("low", "equipment"): "MEDIUM",
    ("low", "downtime"): "LOW",
    ("low", "data_loss"): "LOW",
}

CONSEQUENCE_WEIGHTS: dict[str, float] = {
    "safety_life": 1.0,
    "equipment": 0.8,
    "downtime": 0.5,
    "data_loss": 0.3,
}

SLA_DEADLINES: dict[str, int] = {
    "CRITICAL": 24,
    "HIGH": 72,
    "MEDIUM": 336,   # 14 days
    "LOW": 720,      # 30 days
}

# REM-H01: Expanded zone-consequence fallback — first-class module with
# comprehensive coverage.  Every asset_zone value that can appear in CTEM
# findings must have a mapping here.  Default: "data_loss" for unknown zones.
ZONE_CONSEQUENCE_FALLBACK: dict[str, str] = {
    # Purdue model zones
    "Zone0_PhysicalProcess": "safety_life",
    "Zone0_Safety": "safety_life",
    "Zone0_FieldDevices": "safety_life",
    "Zone1_EdgeInference": "equipment",
    "Zone1_BasicControl": "equipment",
    "Zone1_SensorNetwork": "equipment",
    "Zone1_PLCNetwork": "equipment",
    "Zone2_Operations": "downtime",
    "Zone2_AreaSupervisory": "downtime",
    "Zone2_SCADA": "downtime",
    "Zone2_HMI": "downtime",
    "Zone3_Enterprise": "data_loss",
    "Zone3_SiteOperations": "downtime",
    "Zone3_Manufacturing": "downtime",
    "Zone3_5_DMZ": "data_loss",
    "Zone4_External": "data_loss",
    "Zone4_Corporate": "data_loss",
    "Zone4_Cloud": "data_loss",
    "Zone5_Internet": "data_loss",
    # Cloud and IT zones
    "Cloud_Production": "downtime",
    "Cloud_Staging": "data_loss",
    "Cloud_Development": "data_loss",
    "Cloud_Management": "downtime",
    "IT_DataCenter": "downtime",
    "IT_UserWorkstations": "data_loss",
    "IT_NetworkInfra": "downtime",
    # OT-specific zones
    "OT_FieldBus": "equipment",
    "OT_ControlNetwork": "equipment",
    "OT_ProcessNetwork": "safety_life",
    "OT_SafetyInstrumentedSystem": "safety_life",
}
ZONE_CONSEQUENCE_DEFAULT = "data_loss"


def get_zone_consequence(asset_zone: str) -> str:
    """Return consequence category for a zone, with safe default.

    Uses ZONE_CONSEQUENCE_FALLBACK mapping.  Unknown zones default to
    ``"data_loss"`` (the least severe consequence) to avoid false negatives.
    """
    return ZONE_CONSEQUENCE_FALLBACK.get(asset_zone, ZONE_CONSEQUENCE_DEFAULT)


def generate_exposure_key(source_tool: str, title: str, asset_id: str) -> str:
    """Deterministic exposure key: sha256(source:title:asset)[:16]."""
    raw = f"{source_tool}:{title}:{asset_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def compute_severity(exploitability: str, consequence: str) -> str:
    """Look up severity from the consequence-weighted matrix."""
    key = (exploitability.lower(), consequence.lower())
    return SEVERITY_MATRIX.get(key, "MEDIUM")


def compute_ctem_score(exploitability_score: float, consequence: str) -> float:
    """Compute composite CTEM score: exploitability * consequence_weight * 10."""
    weight = CONSEQUENCE_WEIGHTS.get(consequence.lower(), 0.3)
    return round(exploitability_score * weight * 10, 2)


def compute_sla_deadline(severity: str, base_time: datetime | None = None) -> str:
    """Compute SLA deadline ISO string from severity."""
    base = base_time or datetime.now(timezone.utc)
    hours = SLA_DEADLINES.get(severity.upper(), 720)
    deadline = base + timedelta(hours=hours)
    return deadline.isoformat()
