"""Adversarial AI defense routes — MITRE ATLAS framework coverage.

Provides a dashboard for ATLAS technique coverage, detection rules,
prompt injection defense layers, and AI/ML scanning pipeline status.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_db

logger = logging.getLogger(__name__)

router = APIRouter()


# -- MITRE ATLAS Technique Coverage ----------------------------------------

ATLAS_TECHNIQUES: list[dict[str, Any]] = [
    {
        "id": "AML.T0020",
        "name": "Training Data Poisoning",
        "description": "Adversary contaminates training data to embed backdoors or degrade model accuracy. Poisoned samples cause the model to learn incorrect decision boundaries.",
        "tactic": "ML Attack Staging",
        "severity": "CRITICAL",
        "detection_rule_id": "ATLAS-DETECT-001",
    },
    {
        "id": "AML.T0015",
        "name": "Model Evasion",
        "description": "Adversary crafts inputs that cause a deployed model to produce incorrect outputs while appearing benign to human observers.",
        "tactic": "ML Evasion",
        "severity": "HIGH",
        "detection_rule_id": "ATLAS-DETECT-002",
    },
    {
        "id": "AML.T0044",
        "name": "Model Extraction/Theft",
        "description": "Adversary queries the model systematically to reconstruct a functionally equivalent copy, stealing proprietary intellectual property.",
        "tactic": "ML Model Access",
        "severity": "HIGH",
        "detection_rule_id": "ATLAS-DETECT-003",
    },
    {
        "id": "AML.T0051",
        "name": "LLM Prompt Injection",
        "description": "Adversary injects malicious instructions into LLM prompts to override system instructions, exfiltrate data, or execute unauthorized actions.",
        "tactic": "ML Evasion",
        "severity": "CRITICAL",
        "detection_rule_id": "ATLAS-DETECT-004",
    },
    {
        "id": "AML.T0043",
        "name": "Craft Adversarial Data",
        "description": "Adversary generates specially crafted inputs designed to exploit model weaknesses, including perturbation attacks and out-of-distribution samples.",
        "tactic": "ML Attack Staging",
        "severity": "HIGH",
        "detection_rule_id": "ATLAS-DETECT-005",
    },
    {
        "id": "AML.T0040",
        "name": "Model Inference API Access",
        "description": "Adversary gains access to model inference endpoints to probe behaviour, extract training data, or perform membership inference attacks.",
        "tactic": "ML Model Access",
        "severity": "MEDIUM",
        "detection_rule_id": "ATLAS-DETECT-006",
    },
]


# -- ATLAS Detection Rules -------------------------------------------------

DETECTION_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "ATLAS-DETECT-001",
        "name": "Training Data Integrity Monitor",
        "atlas_technique": "AML.T0020",
        "description": "Detects statistical drift in training data distributions indicating potential poisoning via hash validation and distribution divergence metrics.",
        "threshold": "KL-divergence > 0.15 or hash mismatch on >1% samples",
        "status": "active",
    },
    {
        "rule_id": "ATLAS-DETECT-002",
        "name": "Evasion Input Detector",
        "atlas_technique": "AML.T0015",
        "description": "Identifies adversarial perturbations in model inputs using feature squeezing and input reconstruction error analysis.",
        "threshold": "Reconstruction error > 2.5 std or squeezed prediction delta > 0.3",
        "status": "active",
    },
    {
        "rule_id": "ATLAS-DETECT-003",
        "name": "Model Extraction Query Monitor",
        "atlas_technique": "AML.T0044",
        "description": "Monitors API query patterns for systematic probing indicative of model stealing via query rate analysis and input distribution coverage.",
        "threshold": ">500 queries/hour from single source or grid-pattern input coverage >60%",
        "status": "active",
    },
    {
        "rule_id": "ATLAS-DETECT-004",
        "name": "Prompt Injection Classifier",
        "atlas_technique": "AML.T0051",
        "description": "Multi-layer classifier detecting prompt injection attempts including role changes, instruction overrides, jailbreaks, and system prompt extraction.",
        "threshold": "Injection confidence > 0.7 or pattern match on known injection signatures",
        "status": "active",
    },
    {
        "rule_id": "ATLAS-DETECT-005",
        "name": "Adversarial Input Anomaly Detector",
        "atlas_technique": "AML.T0043",
        "description": "Detects crafted adversarial data through out-of-distribution scoring and input gradient magnitude analysis.",
        "threshold": "OOD score > 0.85 or gradient magnitude > 3 std from baseline",
        "status": "active",
    },
    {
        "rule_id": "ATLAS-DETECT-006",
        "name": "Inference API Access Anomaly",
        "atlas_technique": "AML.T0040",
        "description": "Detects unusual inference API access patterns including membership inference probing and excessive boundary queries.",
        "threshold": ">200 boundary queries/session or prediction confidence histogram anomaly",
        "status": "active",
    },
    {
        "rule_id": "ATLAS-DETECT-007",
        "name": "Training Pipeline Tampering",
        "atlas_technique": "AML.T0020",
        "description": "Monitors ML training pipelines for unauthorized modifications to data loaders, augmentation functions, or loss computations.",
        "threshold": "Any unauthorized commit to training pipeline or config hash mismatch",
        "status": "active",
    },
    {
        "rule_id": "ATLAS-DETECT-008",
        "name": "Model Weight Exfiltration",
        "atlas_technique": "AML.T0044",
        "description": "Detects attempts to download or copy model weight files from storage or serving infrastructure.",
        "threshold": "Model artifact access from non-whitelisted IP or unusual download volume",
        "status": "active",
    },
    {
        "rule_id": "ATLAS-DETECT-009",
        "name": "LLM Output Validation Gate",
        "atlas_technique": "AML.T0051",
        "description": "Validates LLM outputs for leaked system prompts, unauthorized tool calls, and content policy violations before returning to users.",
        "threshold": "System prompt leakage detected or unauthorized tool call in output",
        "status": "active",
    },
    {
        "rule_id": "ATLAS-DETECT-010",
        "name": "Adversarial Robustness Regression",
        "atlas_technique": "AML.T0043",
        "description": "Continuous ART-based testing to detect robustness regression in deployed models compared to certified baselines.",
        "threshold": "Robustness score drops >10% from certified baseline",
        "status": "active",
    },
    {
        "rule_id": "ATLAS-DETECT-011",
        "name": "Membership Inference Guard",
        "atlas_technique": "AML.T0040",
        "description": "Detects membership inference attacks by monitoring for queries designed to determine if specific data points were in the training set.",
        "threshold": "Shadow model correlation > 0.8 or confidence calibration attack detected",
        "status": "disabled",
    },
]


# -- Prompt Injection Defense Patterns -------------------------------------

INJECTION_PATTERNS: list[dict[str, Any]] = [
    {"category": "role_change", "count": 3, "status": "active",
     "examples": ["Ignore previous instructions", "You are now", "Act as"]},
    {"category": "instruction_override", "count": 4, "status": "active",
     "examples": ["Do not follow", "Override system prompt", "New instructions", "Disregard all"]},
    {"category": "jailbreak", "count": 3, "status": "active",
     "examples": ["DAN mode", "Developer mode enabled", "Hypothetical scenario bypass"]},
    {"category": "system_prompt_extraction", "count": 2, "status": "active",
     "examples": ["Repeat your instructions", "What is your system prompt"]},
    {"category": "developer_mode", "count": 2, "status": "active",
     "examples": ["Enable developer mode", "Debug mode on"]},
]


# -- AI/ML Scanning Tools -------------------------------------------------

SCANNING_TOOLS: list[dict[str, Any]] = [
    {
        "tool": "Garak",
        "description": "LLM vulnerability scanner — probes for prompt injection, jailbreaks, and data exfiltration",
        "probe_types": ["escalation", "tool_use", "prompt_injection", "extraction", "exfiltration", "jailbreak", "encoding"],
        "last_scan": "Pending configuration",
        "findings_count": 0,
        "status": "configured",
    },
    {
        "tool": "ART",
        "description": "Adversarial Robustness Toolbox — tests model robustness against adversarial ML attacks",
        "probe_types": ["poisoning", "evasion", "extraction", "inference"],
        "last_scan": "Pending configuration",
        "findings_count": 0,
        "status": "configured",
    },
]


# -- Helper: query DB tables gracefully ------------------------------------

async def _get_adversarial_db_data() -> dict[str, Any]:
    """Fetch data from adversarial-relevant DB tables, gracefully handling missing tables."""
    db = get_db()
    data: dict[str, Any] = {
        "models": [],
        "inference_logs": [],
        "audit_records": [],
        "model_count": 0,
        "inference_count": 0,
        "audit_count": 0,
    }

    if db is None:
        return data

    # model_registry
    try:
        rows = await db.fetch_many(
            "SELECT * FROM model_registry ORDER BY created_at DESC LIMIT 20",
        )
        data["models"] = [dict(r) for r in rows]
        data["model_count"] = len(data["models"])
    except Exception:
        pass

    # inference_logs
    try:
        row = await db.fetch_one("SELECT count(*) AS cnt FROM inference_logs")
        data["inference_count"] = row["cnt"] if row else 0
    except Exception:
        pass

    try:
        rows = await db.fetch_many(
            "SELECT * FROM inference_logs ORDER BY created_at DESC LIMIT 10",
        )
        data["inference_logs"] = [dict(r) for r in rows]
    except Exception:
        pass

    # databricks_audit
    try:
        row = await db.fetch_one("SELECT count(*) AS cnt FROM databricks_audit")
        data["audit_count"] = row["cnt"] if row else 0
    except Exception:
        pass

    try:
        rows = await db.fetch_many(
            "SELECT * FROM databricks_audit ORDER BY created_at DESC LIMIT 10",
        )
        data["audit_records"] = [dict(r) for r in rows]
    except Exception:
        pass

    return data


# -- Endpoints -------------------------------------------------------------

@router.get("/adversarial-ai", response_class=HTMLResponse)
async def adversarial_ai_page(request: Request) -> HTMLResponse:
    """Render the Adversarial AI Defense dashboard page."""
    db_data = await _get_adversarial_db_data()

    active_rules = [r for r in DETECTION_RULES if r["status"] == "active"]
    total_patterns = sum(p["count"] for p in INJECTION_PATTERNS)

    return templates.TemplateResponse(
        request,
        "adversarial_ai/index.html",
        {
            "atlas_techniques": ATLAS_TECHNIQUES,
            "detection_rules": DETECTION_RULES,
            "injection_patterns": INJECTION_PATTERNS,
            "scanning_tools": SCANNING_TOOLS,
            "active_rules_count": len(active_rules),
            "total_rules_count": len(DETECTION_RULES),
            "total_patterns": total_patterns,
            "pattern_categories": len(INJECTION_PATTERNS),
            "models": db_data["models"],
            "model_count": db_data["model_count"],
            "inference_count": db_data["inference_count"],
            "audit_count": db_data["audit_count"],
            "inference_logs": db_data["inference_logs"],
            "audit_records": db_data["audit_records"],
        },
    )


@router.get("/api/adversarial-ai/stats")
async def api_adversarial_ai_stats() -> dict[str, Any]:
    """JSON summary of adversarial AI defense posture."""
    db_data = await _get_adversarial_db_data()

    active_rules = [r for r in DETECTION_RULES if r["status"] == "active"]
    total_patterns = sum(p["count"] for p in INJECTION_PATTERNS)

    return {
        "atlas_techniques": len(ATLAS_TECHNIQUES),
        "detection_rules": {
            "total": len(DETECTION_RULES),
            "active": len(active_rules),
            "disabled": len(DETECTION_RULES) - len(active_rules),
        },
        "injection_defense": {
            "total_patterns": total_patterns,
            "categories": len(INJECTION_PATTERNS),
            "layers": [
                "Classifier",
                "Lossy Summarization",
                "XML Evidence Isolation",
                "Output Validation",
            ],
        },
        "scanning_tools": [
            {
                "tool": t["tool"],
                "status": t["status"],
                "probe_types": len(t["probe_types"]),
                "findings": t["findings_count"],
            }
            for t in SCANNING_TOOLS
        ],
        "model_registry": {
            "count": db_data["model_count"],
        },
        "inference_activity": {
            "count": db_data["inference_count"],
        },
        "training_audit": {
            "count": db_data["audit_count"],
        },
    }
