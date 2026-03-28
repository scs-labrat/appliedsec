"""Canary rollout control routes — promote, rollback, and monitor canary slices.

Provides a dashboard for managing canary rollout phases, viewing promotion
history, and controlling incremental traffic promotion from shadow to full.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from services.dashboard.app import templates

logger = logging.getLogger(__name__)

router = APIRouter()


# -- Canary phases -----------------------------------------------------------
CANARY_PHASES = ["shadow", "10%", "25%", "50%", "100%"]

# -- Demo / fallback data ---------------------------------------------------

DEMO_CANARY_SLICES = [
    {
        "slice_id": "canary-001",
        "slice_name": "FP Auto-Close (Severity: Low)",
        "rule_family": "fp_auto_close",
        "dimension": "severity",
        "value": "LOW",
        "current_phase": "50%",
        "traffic_pct": 50,
        "success_rate": 98.7,
        "error_rate": 1.3,
        "start_date": "2026-02-01T09:00:00Z",
        "last_promotion_date": "2026-03-15T10:00:00Z",
        "auto_rollback_threshold": 95.0,
        "status": "active",
    },
    {
        "slice_id": "canary-002",
        "slice_name": "Enrichment Routing (All Tenants)",
        "rule_family": "enrichment_routing",
        "dimension": "tenant",
        "value": "all",
        "current_phase": "25%",
        "traffic_pct": 25,
        "success_rate": 96.2,
        "error_rate": 3.8,
        "start_date": "2026-02-15T11:00:00Z",
        "last_promotion_date": "2026-03-08T14:00:00Z",
        "auto_rollback_threshold": 95.0,
        "status": "active",
    },
    {
        "slice_id": "canary-003",
        "slice_name": "Alert Dedup (Production)",
        "rule_family": "alert_dedup",
        "dimension": "tenant",
        "value": "production",
        "current_phase": "100%",
        "traffic_pct": 100,
        "success_rate": 99.4,
        "error_rate": 0.6,
        "start_date": "2025-12-15T09:00:00Z",
        "last_promotion_date": "2026-02-28T16:00:00Z",
        "auto_rollback_threshold": 95.0,
        "status": "promoted",
    },
    {
        "slice_id": "canary-004",
        "slice_name": "Containment Actions (Critical)",
        "rule_family": "containment_actions",
        "dimension": "severity",
        "value": "CRITICAL",
        "current_phase": "shadow",
        "traffic_pct": 0,
        "success_rate": 89.1,
        "error_rate": 10.9,
        "start_date": "2026-03-20T08:00:00Z",
        "last_promotion_date": None,
        "auto_rollback_threshold": 95.0,
        "status": "active",
    },
    {
        "slice_id": "canary-005",
        "slice_name": "Severity Override (Medium)",
        "rule_family": "severity_override",
        "dimension": "severity",
        "value": "MEDIUM",
        "current_phase": "10%",
        "traffic_pct": 10,
        "success_rate": 91.8,
        "error_rate": 8.2,
        "start_date": "2026-03-10T10:00:00Z",
        "last_promotion_date": "2026-03-22T09:00:00Z",
        "auto_rollback_threshold": 95.0,
        "status": "active",
    },
]

DEMO_PROMOTION_HISTORY = [
    {
        "action": "promote",
        "slice_id": "canary-001",
        "slice_name": "FP Auto-Close (Severity: Low)",
        "from_phase": "25%",
        "to_phase": "50%",
        "precision": 98.7,
        "ts": "2026-03-15T10:00:00Z",
        "actor": "canary_scheduler",
    },
    {
        "action": "promote",
        "slice_id": "canary-003",
        "slice_name": "Alert Dedup (Production)",
        "from_phase": "50%",
        "to_phase": "100%",
        "precision": 99.4,
        "ts": "2026-02-28T16:00:00Z",
        "actor": "canary_scheduler",
    },
    {
        "action": "rollback",
        "slice_id": "canary-006",
        "slice_name": "Playbook Selection (High)",
        "from_phase": "10%",
        "to_phase": "shadow",
        "precision": 87.2,
        "reason": "precision_below_threshold",
        "ts": "2026-03-05T11:30:00Z",
        "actor": "canary_scheduler",
    },
    {
        "action": "promote",
        "slice_id": "canary-002",
        "slice_name": "Enrichment Routing (All Tenants)",
        "from_phase": "10%",
        "to_phase": "25%",
        "precision": 96.2,
        "ts": "2026-03-08T14:00:00Z",
        "actor": "canary_scheduler",
    },
    {
        "action": "promote",
        "slice_id": "canary-005",
        "slice_name": "Severity Override (Medium)",
        "from_phase": "shadow",
        "to_phase": "10%",
        "precision": 91.8,
        "ts": "2026-03-22T09:00:00Z",
        "actor": "analyst:admin",
    },
    {
        "action": "promote",
        "slice_id": "canary-003",
        "slice_name": "Alert Dedup (Production)",
        "from_phase": "25%",
        "to_phase": "50%",
        "precision": 99.1,
        "ts": "2026-02-10T09:00:00Z",
        "actor": "canary_scheduler",
    },
    {
        "action": "rollback",
        "slice_id": "canary-007",
        "slice_name": "Severity Override (Critical)",
        "from_phase": "25%",
        "to_phase": "shadow",
        "precision": 78.5,
        "reason": "missed_tps=3",
        "ts": "2026-02-18T15:45:00Z",
        "actor": "kill_switch",
    },
]


def _compute_canary_summary(
    slices: list[dict[str, Any]], history: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute summary statistics for the canary dashboard."""
    active = sum(1 for s in slices if s["status"] == "active")
    promoted = sum(1 for s in slices if s["status"] == "promoted")

    total_promotions = sum(1 for h in history if h["action"] == "promote")
    total_rollbacks = sum(1 for h in history if h["action"] == "rollback")

    # Rollbacks in last 30 days (demo: count all)
    rollbacks_30d = total_rollbacks

    # Average time to full promotion (for promoted slices)
    promoted_slices = [s for s in slices if s["status"] == "promoted"]
    if promoted_slices:
        avg_days = 0.0
        for s in promoted_slices:
            try:
                start = datetime.fromisoformat(s["start_date"].replace("Z", "+00:00"))
                end = datetime.fromisoformat(s["last_promotion_date"].replace("Z", "+00:00"))
                avg_days += (end - start).days
            except (ValueError, TypeError, AttributeError):
                pass
        avg_days = avg_days / len(promoted_slices) if promoted_slices else 0
    else:
        avg_days = 0.0

    return {
        "active_canaries": active,
        "promoted_count": promoted,
        "total_promotions": total_promotions,
        "total_rollbacks": total_rollbacks,
        "rollbacks_30d": rollbacks_30d,
        "avg_days_to_promotion": round(avg_days, 1),
    }


@router.get("/canary", response_class=HTMLResponse)
async def canary_page(request: Request) -> HTMLResponse:
    """Render the canary rollout control dashboard."""
    slices = DEMO_CANARY_SLICES
    history = sorted(DEMO_PROMOTION_HISTORY, key=lambda h: h["ts"], reverse=True)
    summary = _compute_canary_summary(slices, history)

    return templates.TemplateResponse(
        request,
        "canary/index.html",
        {
            "slices": slices,
            "history": history,
            "summary": summary,
            "phases": CANARY_PHASES,
        },
    )


@router.post("/api/canary/promote")
async def api_promote_canary(request: Request) -> dict[str, Any]:
    """Promote a canary slice to the next phase.

    Accepts JSON body: {"slice_id": str}
    """
    body = await request.json()
    slice_id = body.get("slice_id", "")

    for s in DEMO_CANARY_SLICES:
        if s["slice_id"] == slice_id:
            if s["status"] != "active":
                return {"ok": False, "error": f"Slice {slice_id} is not active"}

            current_idx = CANARY_PHASES.index(s["current_phase"]) if s["current_phase"] in CANARY_PHASES else -1
            if current_idx >= len(CANARY_PHASES) - 1:
                return {"ok": False, "error": "Already at maximum phase"}

            old_phase = s["current_phase"]
            new_phase = CANARY_PHASES[current_idx + 1]
            s["current_phase"] = new_phase
            s["traffic_pct"] = int(new_phase.replace("%", "")) if new_phase != "shadow" else 0
            s["last_promotion_date"] = datetime.now(timezone.utc).isoformat()

            if new_phase == "100%":
                s["status"] = "promoted"

            DEMO_PROMOTION_HISTORY.insert(0, {
                "action": "promote",
                "slice_id": slice_id,
                "slice_name": s["slice_name"],
                "from_phase": old_phase,
                "to_phase": new_phase,
                "precision": s["success_rate"],
                "ts": datetime.now(timezone.utc).isoformat(),
                "actor": "analyst:manual",
            })

            logger.info("Canary promoted: %s %s -> %s", slice_id, old_phase, new_phase)
            return {
                "ok": True,
                "slice_id": slice_id,
                "old_phase": old_phase,
                "new_phase": new_phase,
            }

    return {"ok": False, "error": f"Slice not found: {slice_id}"}


@router.post("/api/canary/rollback")
async def api_rollback_canary(request: Request) -> dict[str, Any]:
    """Rollback a canary slice to shadow mode.

    Accepts JSON body: {"slice_id": str, "reason": str}
    """
    body = await request.json()
    slice_id = body.get("slice_id", "")
    reason = body.get("reason", "manual_rollback")

    for s in DEMO_CANARY_SLICES:
        if s["slice_id"] == slice_id:
            old_phase = s["current_phase"]
            s["current_phase"] = "shadow"
            s["traffic_pct"] = 0
            s["status"] = "active"

            DEMO_PROMOTION_HISTORY.insert(0, {
                "action": "rollback",
                "slice_id": slice_id,
                "slice_name": s["slice_name"],
                "from_phase": old_phase,
                "to_phase": "shadow",
                "precision": s["success_rate"],
                "reason": reason,
                "ts": datetime.now(timezone.utc).isoformat(),
                "actor": "analyst:manual",
            })

            logger.warning("Canary rolled back: %s %s -> shadow (%s)", slice_id, old_phase, reason)
            return {
                "ok": True,
                "slice_id": slice_id,
                "old_phase": old_phase,
                "new_phase": "shadow",
                "reason": reason,
            }

    return {"ok": False, "error": f"Slice not found: {slice_id}"}


@router.get("/api/canary/history")
async def api_canary_history() -> dict[str, Any]:
    """Get promotion and rollback history."""
    history = sorted(DEMO_PROMOTION_HISTORY, key=lambda h: h["ts"], reverse=True)
    return {
        "history": history,
        "total": len(history),
    }


# -- Canary CRUD (add / edit / delete) --------------------------------------

class CanaryCreate(BaseModel):
    slice_name: str
    rule_family: str
    dimension: str = "severity"
    value: str = "ALL"
    auto_rollback_threshold: float = 95.0


@router.post("/api/canary/create")
async def api_create_canary(body: CanaryCreate) -> dict[str, Any]:
    """Create a new canary slice starting in shadow phase."""
    # Generate next ID
    existing_ids = [int(s["slice_id"].split("-")[1]) for s in DEMO_CANARY_SLICES if s["slice_id"].startswith("canary-")]
    next_id = max(existing_ids, default=0) + 1
    slice_id = f"canary-{next_id:03d}"

    new_slice = {
        "slice_id": slice_id,
        "slice_name": body.slice_name,
        "rule_family": body.rule_family,
        "dimension": body.dimension,
        "value": body.value,
        "current_phase": "shadow",
        "traffic_pct": 0,
        "success_rate": 0.0,
        "error_rate": 0.0,
        "start_date": datetime.now(timezone.utc).isoformat(),
        "last_promotion_date": None,
        "auto_rollback_threshold": body.auto_rollback_threshold,
        "status": "active",
    }
    DEMO_CANARY_SLICES.append(new_slice)

    DEMO_PROMOTION_HISTORY.insert(0, {
        "action": "promote",
        "slice_id": slice_id,
        "slice_name": body.slice_name,
        "from_phase": "none",
        "to_phase": "shadow",
        "precision": 0.0,
        "ts": datetime.now(timezone.utc).isoformat(),
        "actor": "analyst:manual",
    })

    logger.info("Canary created: %s — %s", slice_id, body.slice_name)
    return {"ok": True, "slice_id": slice_id, "slice": new_slice}


class CanaryUpdate(BaseModel):
    slice_name: str | None = None
    rule_family: str | None = None
    dimension: str | None = None
    value: str | None = None
    auto_rollback_threshold: float | None = None
    success_rate: float | None = None
    error_rate: float | None = None


@router.put("/api/canary/{slice_id}")
async def api_update_canary(slice_id: str, body: CanaryUpdate) -> dict[str, Any]:
    """Edit an existing canary slice configuration."""
    for s in DEMO_CANARY_SLICES:
        if s["slice_id"] == slice_id:
            updates = body.model_dump(exclude_none=True)
            for key, val in updates.items():
                s[key] = val
            logger.info("Canary updated: %s — fields: %s", slice_id, list(updates.keys()))
            return {"ok": True, "slice_id": slice_id, "updated_fields": list(updates.keys())}
    return {"ok": False, "error": f"Slice not found: {slice_id}"}


@router.delete("/api/canary/{slice_id}")
async def api_delete_canary(slice_id: str) -> dict[str, Any]:
    """Delete a canary slice."""
    for i, s in enumerate(DEMO_CANARY_SLICES):
        if s["slice_id"] == slice_id:
            removed = DEMO_CANARY_SLICES.pop(i)
            logger.info("Canary deleted: %s — %s", slice_id, removed["slice_name"])
            return {"ok": True, "slice_id": slice_id, "deleted": removed["slice_name"]}
    return {"ok": False, "error": f"Slice not found: {slice_id}"}
