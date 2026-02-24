"""Overview metrics routes — Story 17-6.

Dashboard overview page with key operational metrics.
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


async def _fetch_metrics() -> dict[str, Any]:
    """Aggregate key metrics from the investigations table."""
    db = get_db()
    if db is None:
        return _empty_metrics()

    metrics: dict[str, Any] = {}

    try:
        # Investigations by state
        rows = await db.fetch_many(
            "SELECT state, COUNT(*) AS count FROM investigations GROUP BY state"
        )
        by_state = {dict(r)["state"]: dict(r)["count"] for r in rows}
        metrics["by_state"] = by_state
        metrics["total_open"] = sum(
            v for k, v in by_state.items() if k not in ("closed", "failed")
        )
        metrics["awaiting_human"] = by_state.get("awaiting_human", 0)

        # Severity breakdown (last 24h)
        rows = await db.fetch_many(
            """
            SELECT graphstate_json->>'severity' AS severity, COUNT(*) AS count
            FROM investigations
            WHERE updated_at >= NOW() - INTERVAL '24 hours'
            GROUP BY graphstate_json->>'severity'
            """
        )
        metrics["by_severity_24h"] = {
            dict(r)["severity"]: dict(r)["count"] for r in rows
        }
        metrics["critical_count"] = metrics["by_severity_24h"].get("critical", 0)

        # Mean time to close (last 7 days)
        row = await db.fetch_one(
            """
            SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) AS avg_seconds
            FROM investigations
            WHERE state = 'closed'
              AND updated_at >= NOW() - INTERVAL '7 days'
            """
        )
        avg_sec = dict(row).get("avg_seconds") if row else None
        metrics["mttc_seconds"] = avg_sec
        if avg_sec:
            hours = avg_sec / 3600
            metrics["mttc_display"] = f"{hours:.1f}h"
        else:
            metrics["mttc_display"] = "-"

        # FP rate
        row = await db.fetch_one(
            """
            SELECT
                COUNT(*) FILTER (WHERE graphstate_json->>'classification' = 'false_positive') AS fp_count,
                COUNT(*) AS total
            FROM investigations
            WHERE state = 'closed'
            """
        )
        d = dict(row) if row else {}
        total = d.get("total", 0)
        fp = d.get("fp_count", 0)
        metrics["fp_rate"] = f"{(fp / total * 100):.1f}%" if total > 0 else "-"

        # Active kill switches
        try:
            row = await db.fetch_one(
                "SELECT COUNT(*) AS count FROM kill_switches WHERE active = true"
            )
            metrics["active_kill_switches"] = dict(row).get("count", 0) if row else 0
        except Exception:
            metrics["active_kill_switches"] = 0

        # ATLAS detections by trust level
        try:
            rows = await db.fetch_many(
                """
                SELECT payload->>'trust_level' AS trust_level, COUNT(*) AS count
                FROM audit_records
                WHERE event_type = 'atlas.detection_fired'
                GROUP BY payload->>'trust_level'
                """
            )
            metrics["atlas_by_trust"] = {
                dict(r)["trust_level"]: dict(r)["count"] for r in rows
            }
        except Exception:
            metrics["atlas_by_trust"] = {}

    except Exception as exc:
        logger.warning("Metrics query failed: %s", exc)
        return _empty_metrics()

    return metrics


def _empty_metrics() -> dict[str, Any]:
    """Return zero-value metrics for empty/unavailable DB."""
    return {
        "by_state": {},
        "total_open": 0,
        "awaiting_human": 0,
        "by_severity_24h": {},
        "critical_count": 0,
        "mttc_seconds": None,
        "mttc_display": "-",
        "fp_rate": "-",
        "active_kill_switches": 0,
        "atlas_by_trust": {},
    }


@router.get("/overview", response_class=HTMLResponse)
async def overview_page(request: Request) -> HTMLResponse:
    """Render the overview metrics dashboard."""
    metrics = await _fetch_metrics()
    return templates.TemplateResponse(
        "overview.html",
        {"request": request, "metrics": metrics},
    )


@router.get("/api/metrics")
async def api_metrics() -> dict[str, Any]:
    """JSON endpoint for metrics (used by HTMX auto-refresh)."""
    return await _fetch_metrics()
