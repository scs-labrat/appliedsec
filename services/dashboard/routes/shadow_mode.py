"""Shadow mode management routes — toggle, monitor, and evaluate shadow mode.

Provides a dashboard for managing per-rule-family shadow mode status,
viewing agreement rates, and toggling between shadow/live/disabled states.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates

logger = logging.getLogger(__name__)

router = APIRouter()


# -- Demo / fallback data ---------------------------------------------------
# Used when the real orchestrator services are unavailable (local dev, demo).

DEMO_SHADOW_ENTRIES = [
    {
        "rule_family": "fp_auto_close",
        "display_name": "False Positive Auto-Close",
        "description": "Automatically closes alerts identified as false positives based on historical patterns",
        "status": "live",
        "agreement_rate": 97.3,
        "sample_size": 412,
        "created_at": "2026-01-15T09:00:00Z",
        "last_evaluated_at": "2026-03-28T14:32:00Z",
        "go_live_criteria": ">95% agreement over 200 samples",
        "missed_critical_tps": 0,
        "fp_precision": 99.1,
    },
    {
        "rule_family": "containment_actions",
        "display_name": "Containment Actions",
        "description": "Automated network isolation and endpoint containment for confirmed threats",
        "status": "shadow",
        "agreement_rate": 89.7,
        "sample_size": 156,
        "created_at": "2026-02-20T11:00:00Z",
        "last_evaluated_at": "2026-03-28T14:32:00Z",
        "go_live_criteria": ">95% agreement over 200 samples",
        "missed_critical_tps": 1,
        "fp_precision": 96.4,
    },
    {
        "rule_family": "enrichment_routing",
        "display_name": "Enrichment Routing",
        "description": "Routes alerts to appropriate enrichment pipelines (CTI, CTEM, ATLAS)",
        "status": "shadow",
        "agreement_rate": 93.2,
        "sample_size": 287,
        "created_at": "2026-02-01T08:30:00Z",
        "last_evaluated_at": "2026-03-28T14:32:00Z",
        "go_live_criteria": ">95% agreement over 200 samples",
        "missed_critical_tps": 0,
        "fp_precision": 98.5,
    },
    {
        "rule_family": "severity_override",
        "display_name": "Severity Override",
        "description": "AI-driven severity re-classification based on context enrichment and CTEM correlation",
        "status": "shadow",
        "agreement_rate": 82.1,
        "sample_size": 98,
        "created_at": "2026-03-10T10:00:00Z",
        "last_evaluated_at": "2026-03-28T14:32:00Z",
        "go_live_criteria": ">95% agreement over 200 samples",
        "missed_critical_tps": 2,
        "fp_precision": 91.3,
    },
    {
        "rule_family": "playbook_selection",
        "display_name": "Playbook Selection",
        "description": "Automated selection and execution of response playbooks based on investigation findings",
        "status": "disabled",
        "agreement_rate": 0.0,
        "sample_size": 0,
        "created_at": "2026-03-25T16:00:00Z",
        "last_evaluated_at": None,
        "go_live_criteria": ">95% agreement over 200 samples",
        "missed_critical_tps": 0,
        "fp_precision": 0.0,
    },
    {
        "rule_family": "alert_dedup",
        "display_name": "Alert Deduplication",
        "description": "Groups and deduplicates related alerts into single investigation threads",
        "status": "live",
        "agreement_rate": 98.9,
        "sample_size": 534,
        "created_at": "2025-12-01T09:00:00Z",
        "last_evaluated_at": "2026-03-28T14:32:00Z",
        "go_live_criteria": ">95% agreement over 200 samples",
        "missed_critical_tps": 0,
        "fp_precision": 99.6,
    },
]


def _compute_summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute summary statistics from shadow mode entries."""
    total = len(entries)
    shadow_count = sum(1 for e in entries if e["status"] == "shadow")
    live_count = sum(1 for e in entries if e["status"] == "live")
    disabled_count = sum(1 for e in entries if e["status"] == "disabled")

    # Average agreement rate (only for entries with samples)
    active_entries = [e for e in entries if e["sample_size"] > 0]
    avg_agreement = (
        sum(e["agreement_rate"] for e in active_entries) / len(active_entries)
        if active_entries
        else 0.0
    )

    return {
        "total": total,
        "shadow_count": shadow_count,
        "live_count": live_count,
        "disabled_count": disabled_count,
        "avg_agreement": round(avg_agreement, 1),
    }


@router.get("/shadow-mode", response_class=HTMLResponse)
async def shadow_mode_page(request: Request) -> HTMLResponse:
    """Render the shadow mode management dashboard."""
    # In production this would query the ShadowModeManager and Redis.
    # For now we use demo/fallback data.
    entries = DEMO_SHADOW_ENTRIES
    summary = _compute_summary(entries)

    # Global shadow mode: enabled if any family is in shadow
    global_shadow_enabled = summary["shadow_count"] > 0

    return templates.TemplateResponse(
        request,
        "shadow_mode/index.html",
        {
            "entries": entries,
            "summary": summary,
            "global_shadow_enabled": global_shadow_enabled,
        },
    )


@router.post("/api/shadow-mode/toggle")
async def api_toggle_shadow(request: Request) -> dict[str, Any]:
    """Toggle shadow mode status for a rule family.

    Accepts JSON body: {"rule_family": str, "new_status": "shadow"|"live"|"disabled"}
    """
    body = await request.json()
    rule_family = body.get("rule_family", "")
    new_status = body.get("new_status", "shadow")

    if new_status not in ("shadow", "live", "disabled"):
        return {"ok": False, "error": f"Invalid status: {new_status}"}

    # In production this would update tenant config via TenantConfigStore.
    # For demo, we update the in-memory list.
    for entry in DEMO_SHADOW_ENTRIES:
        if entry["rule_family"] == rule_family:
            old_status = entry["status"]
            entry["status"] = new_status
            entry["last_evaluated_at"] = datetime.now(timezone.utc).isoformat()
            logger.info(
                "Shadow mode toggled: %s %s -> %s", rule_family, old_status, new_status,
            )
            return {
                "ok": True,
                "rule_family": rule_family,
                "old_status": old_status,
                "new_status": new_status,
            }

    return {"ok": False, "error": f"Rule family not found: {rule_family}"}


@router.get("/api/shadow-mode/stats")
async def api_shadow_stats() -> dict[str, Any]:
    """Get agreement stats for all rule families."""
    entries = DEMO_SHADOW_ENTRIES
    summary = _compute_summary(entries)

    return {
        "summary": summary,
        "entries": [
            {
                "rule_family": e["rule_family"],
                "status": e["status"],
                "agreement_rate": e["agreement_rate"],
                "sample_size": e["sample_size"],
            }
            for e in entries
        ],
    }
