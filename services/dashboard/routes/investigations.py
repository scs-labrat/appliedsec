"""Investigation list routes — Story 17-2.

Provides HTML page and JSON API for listing/filtering investigations.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_db, get_repo

router = APIRouter()


async def _fetch_investigations(
    state: str = "",
    severity: str = "",
    tenant_id: str = "",
    date_from: str = "",
    date_to: str = "",
    limit: int = 25,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Query investigations with optional filters."""
    db = get_db()
    if db is None:
        return []

    query = """
        SELECT investigation_id, alert_id, tenant_id, state,
               graphstate_json->>'severity' AS severity,
               updated_at
        FROM investigations
        WHERE 1=1
    """
    params: list[Any] = []
    idx = 1

    if state:
        query += f" AND state = ${idx}"
        params.append(state)
        idx += 1
    if severity:
        query += f" AND graphstate_json->>'severity' = ${idx}"
        params.append(severity)
        idx += 1
    if tenant_id:
        query += f" AND tenant_id = ${idx}"
        params.append(tenant_id)
        idx += 1
    if date_from:
        query += f" AND updated_at >= ${idx}"
        params.append(date_from)
        idx += 1
    if date_to:
        query += f" AND updated_at <= ${idx}"
        params.append(date_to)
        idx += 1

    query += f" ORDER BY updated_at DESC LIMIT ${idx} OFFSET ${idx + 1}"
    params.extend([limit, offset])

    rows = await db.fetch_many(query, *params)
    return [dict(r) for r in rows]


@router.get("/investigations", response_class=HTMLResponse)
async def investigations_page(
    request: Request,
    state: str = Query("", description="Filter by state"),
    severity: str = Query("", description="Filter by severity"),
    tenant_id: str = Query("", description="Filter by tenant"),
    date_from: str = Query("", description="Start date"),
    date_to: str = Query("", description="End date"),
    page: int = Query(1, ge=1),
) -> HTMLResponse:
    """Render the investigations list page."""
    limit = 25
    offset = (page - 1) * limit

    try:
        investigations = await _fetch_investigations(
            state=state, severity=severity, tenant_id=tenant_id,
            date_from=date_from, date_to=date_to,
            limit=limit, offset=offset,
        )
    except Exception:
        investigations = []

    return templates.TemplateResponse(
        "investigations/list.html",
        {
            "request": request,
            "investigations": investigations,
            "filters": {
                "state": state,
                "severity": severity,
                "tenant_id": tenant_id,
                "date_from": date_from,
                "date_to": date_to,
            },
            "page": page,
        },
    )


@router.get("/api/investigations")
async def api_investigations(
    state: str = Query(""),
    severity: str = Query(""),
    tenant_id: str = Query(""),
    date_from: str = Query(""),
    date_to: str = Query(""),
    limit: int = Query(25, le=100),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """JSON endpoint for HTMX partial updates."""
    try:
        investigations = await _fetch_investigations(
            state=state, severity=severity, tenant_id=tenant_id,
            date_from=date_from, date_to=date_to,
            limit=limit, offset=offset,
        )
    except Exception:
        investigations = []

    return {"investigations": investigations, "count": len(investigations)}
