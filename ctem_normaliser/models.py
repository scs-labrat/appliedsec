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

ZONE_CONSEQUENCE_FALLBACK: dict[str, str] = {
    "Zone0_PhysicalProcess": "safety_life",
    "Zone1_EdgeInference": "equipment",
    "Zone2_Operations": "downtime",
    "Zone3_Enterprise": "data_loss",
    "Zone4_External": "data_loss",
}


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
