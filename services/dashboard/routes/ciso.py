"""CISO Executive Dashboard — graphed metrics for C-suite reporting.

KPIs: MTTD, MTTR, automation rate, FP accuracy, cost efficiency,
risk posture, SLA compliance, and threat landscape trends.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_db

logger = logging.getLogger(__name__)

router = APIRouter()


# -- Demo metrics for when DB is unavailable ---------------------------------

def _demo_ciso_metrics() -> dict[str, Any]:
    """Rich demo data set for the CISO dashboard."""
    now = datetime.now(timezone.utc)

    # 30-day daily trend data
    daily_labels = [(now - timedelta(days=29 - i)).strftime("%b %d") for i in range(30)]

    return {
        # --- KPI Cards ---
        "mttd_seconds": 22,
        "mttd_display": "22s",
        "mttd_target": 30,
        "mttr_minutes": 8.4,
        "mttr_display": "8.4m",
        "mttr_target": 15,
        "automation_rate": 84.2,
        "automation_target": 80,
        "fp_accuracy": 98.6,
        "fp_target": 98,
        "total_investigations_30d": 4827,
        "total_auto_closed": 2941,
        "total_escalated": 312,
        "total_cost_30d": 387.42,
        "cost_target": 400,
        "cost_per_investigation": 0.08,
        "sla_compliance": 96.8,
        "sla_target": 95,
        "risk_posture_score": 78,

        # --- Chart: Daily alert volume (30 days) ---
        "daily_labels": daily_labels,
        "daily_alerts": [
            142, 156, 138, 201, 178, 165, 149, 187, 195, 211,
            168, 144, 159, 223, 198, 176, 162, 189, 205, 234,
            192, 171, 153, 218, 201, 185, 174, 196, 208, 221,
        ],
        "daily_auto_closed": [
            118, 131, 115, 172, 149, 138, 125, 158, 165, 179,
            141, 120, 134, 190, 167, 148, 136, 160, 174, 199,
            162, 144, 128, 185, 170, 156, 147, 166, 176, 187,
        ],
        "daily_escalated": [
            8, 11, 9, 14, 12, 10, 9, 13, 11, 15,
            10, 8, 10, 16, 14, 11, 9, 12, 13, 17,
            12, 10, 8, 15, 13, 11, 10, 12, 14, 16,
        ],

        # --- Chart: MTTD/MTTR trend (30 days) ---
        "daily_mttd": [
            28, 26, 25, 31, 27, 24, 23, 29, 26, 32,
            25, 22, 24, 30, 27, 23, 22, 26, 24, 28,
            23, 21, 22, 27, 24, 22, 21, 23, 22, 22,
        ],
        "daily_mttr": [
            12.1, 11.4, 10.8, 13.2, 11.9, 10.5, 10.1, 12.3, 11.0, 13.8,
            10.7, 9.8, 10.2, 12.9, 11.5, 10.0, 9.6, 11.1, 10.3, 12.0,
            9.9, 9.2, 9.0, 11.4, 10.1, 9.5, 9.1, 9.8, 8.9, 8.4,
        ],

        # --- Chart: Severity distribution (current open) ---
        "severity_open": {"critical": 3, "high": 12, "medium": 28, "low": 41, "informational": 8},

        # --- Chart: Cost trend (30 days) ---
        "daily_cost": [
            11.20, 12.80, 10.50, 16.40, 14.30, 12.10, 10.90, 15.20, 14.60, 17.80,
            12.40, 10.20, 11.80, 18.10, 15.40, 13.00, 11.60, 14.50, 15.80, 19.20,
            14.00, 12.30, 11.10, 17.50, 15.20, 13.40, 12.50, 14.80, 15.60, 16.90,
        ],

        # --- Chart: Top MITRE tactics (30 days) ---
        "top_tactics": [
            {"tactic": "Initial Access", "count": 892},
            {"tactic": "Execution", "count": 641},
            {"tactic": "Persistence", "count": 523},
            {"tactic": "Privilege Escalation", "count": 418},
            {"tactic": "Defense Evasion", "count": 387},
            {"tactic": "Lateral Movement", "count": 312},
            {"tactic": "Collection", "count": 245},
            {"tactic": "Exfiltration", "count": 189},
        ],

        # --- Chart: Automation rate trend (30 days) ---
        "daily_automation": [
            79.2, 80.1, 81.4, 82.0, 81.5, 82.8, 83.1, 82.6, 83.5, 83.0,
            83.8, 84.2, 83.9, 84.5, 84.1, 84.8, 84.3, 85.0, 84.6, 85.2,
            84.8, 85.1, 84.5, 85.3, 84.9, 85.4, 85.0, 85.2, 84.8, 84.2,
        ],

        # --- SLA compliance by severity ---
        "sla_by_severity": {
            "critical": {"total": 48, "met": 45, "pct": 93.8},
            "high": {"total": 312, "met": 298, "pct": 95.5},
            "medium": {"total": 1204, "met": 1178, "pct": 97.8},
            "low": {"total": 3263, "met": 3231, "pct": 99.0},
        },

        # --- CTEM exposure summary ---
        "ctem_summary": {
            "total": 247,
            "critical": 8,
            "high": 34,
            "medium": 89,
            "low": 116,
            "remediated_30d": 62,
            "overdue": 5,
        },

        # --- Adversarial AI summary ---
        "adversarial_summary": {
            "injection_attempts_30d": 47,
            "blocked": 47,
            "atlas_detections_30d": 12,
            "models_monitored": 6,
        },

        # --- Investigation outcomes (30d) ---
        "outcomes": {
            "true_positive": 1574,
            "false_positive": 2941,
            "escalated": 312,
        },
    }


async def _fetch_ciso_metrics() -> dict[str, Any]:
    """Fetch real metrics from DB, falling back to demo data."""
    db = get_db()
    if db is None:
        return _demo_ciso_metrics()

    metrics = _demo_ciso_metrics()  # Start with demo as baseline

    try:
        # Override with real data where available
        # Total investigations (30d)
        row = await db.fetch_one(
            "SELECT COUNT(*) AS cnt FROM investigation_state "
            "WHERE created_at >= NOW() - INTERVAL '30 days'"
        )
        if row and row["cnt"] > 0:
            metrics["total_investigations_30d"] = row["cnt"]

        # By state
        rows = await db.fetch_many(
            "SELECT state, COUNT(*) AS cnt FROM investigation_state GROUP BY state"
        )
        if rows:
            by_state = {r["state"]: r["cnt"] for r in rows}
            metrics["total_auto_closed"] = by_state.get("closed", 0)
            metrics["total_escalated"] = by_state.get("awaiting_human", 0)

        # Severity distribution (open)
        rows = await db.fetch_many(
            "SELECT graph_state->>'severity' AS sev, COUNT(*) AS cnt "
            "FROM investigation_state WHERE state NOT IN ('closed', 'failed') "
            "GROUP BY graph_state->>'severity'"
        )
        if rows:
            metrics["severity_open"] = {r["sev"]: r["cnt"] for r in rows if r["sev"]}

        # MTTC
        row = await db.fetch_one(
            "SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) AS avg_sec "
            "FROM investigation_state WHERE state = 'closed' "
            "AND updated_at >= NOW() - INTERVAL '7 days'"
        )
        if row and row["avg_sec"]:
            metrics["mttr_minutes"] = round(row["avg_sec"] / 60, 1)
            metrics["mttr_display"] = f"{metrics['mttr_minutes']}m"

        # LLM cost
        try:
            row = await db.fetch_one(
                "SELECT COALESCE(SUM(total_cost_usd), 0) AS cost "
                "FROM investigation_state WHERE created_at >= NOW() - INTERVAL '30 days'"
            )
            if row and row["cost"]:
                metrics["total_cost_30d"] = round(float(row["cost"]), 2)
        except Exception:
            pass

    except Exception as exc:
        logger.warning("CISO metrics query failed, using demo data: %s", exc)

    return metrics


@router.get("/ciso", response_class=HTMLResponse)
async def ciso_dashboard(request: Request) -> HTMLResponse:
    """Render the CISO executive dashboard."""
    metrics = await _fetch_ciso_metrics()
    return templates.TemplateResponse(
        request,
        "ciso/index.html",
        {"m": metrics},
    )


@router.get("/api/ciso/metrics")
async def api_ciso_metrics() -> dict[str, Any]:
    """JSON endpoint for CISO metrics (supports auto-refresh)."""
    return await _fetch_ciso_metrics()
