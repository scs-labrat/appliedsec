"""Approval queue routes — Story 17-5.

Page showing all AWAITING_HUMAN investigations + approve/reject actions.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_db, get_repo
from shared.schemas.investigation import InvestigationState

logger = logging.getLogger(__name__)

router = APIRouter()


async def _fetch_awaiting_investigations() -> list[dict[str, Any]]:
    """Fetch all investigations in AWAITING_HUMAN state."""
    db = get_db()
    if db is None:
        return []

    rows = await db.fetch_many(
        """
        SELECT investigation_id, alert_id, tenant_id, state,
               graphstate_json->>'severity' AS severity,
               graphstate_json->>'classification' AS classification,
               updated_at
        FROM investigations
        WHERE state = $1
        ORDER BY
            CASE graphstate_json->>'severity'
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            updated_at ASC
        """,
        InvestigationState.AWAITING_HUMAN.value,
    )
    return [dict(r) for r in rows]


@router.get("/approvals", response_class=HTMLResponse)
async def approvals_page(request: Request) -> HTMLResponse:
    """Render the approval queue page."""
    try:
        investigations = await _fetch_awaiting_investigations()
    except Exception:
        investigations = []

    return templates.TemplateResponse(
        "approvals/queue.html",
        {
            "request": request,
            "investigations": investigations,
        },
    )


@router.post("/api/investigations/{investigation_id}/approve")
async def approve_investigation(investigation_id: str) -> dict[str, str]:
    """Approve an investigation — transition to RESPONDING."""
    repo = get_repo()
    state = await repo.load(investigation_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if state.state != InvestigationState.AWAITING_HUMAN:
        raise HTTPException(
            status_code=409,
            detail=f"Investigation is in state {state.state.value}, not awaiting_human",
        )

    await repo.transition(
        state,
        InvestigationState.RESPONDING,
        agent="dashboard_analyst",
        action="approval.granted",
        details={"source": "dashboard"},
    )

    # Emit audit event
    try:
        db = get_db()
        if db is not None:
            await db.execute(
                """
                INSERT INTO audit_records (audit_id, tenant_id, event_type, event_category,
                                           investigation_id, payload, timestamp)
                VALUES (gen_random_uuid()::text, $1, $2, $3, $4, '{}'::jsonb, NOW())
                """,
                state.tenant_id,
                "approval.granted",
                "approval",
                investigation_id,
            )
    except Exception as exc:
        logger.warning("Failed to emit audit event: %s", exc)

    return {"status": "approved", "new_state": "responding"}


@router.post("/api/investigations/{investigation_id}/reject")
async def reject_investigation(investigation_id: str) -> dict[str, str]:
    """Reject an investigation — transition to CLOSED."""
    repo = get_repo()
    state = await repo.load(investigation_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if state.state != InvestigationState.AWAITING_HUMAN:
        raise HTTPException(
            status_code=409,
            detail=f"Investigation is in state {state.state.value}, not awaiting_human",
        )

    await repo.transition(
        state,
        InvestigationState.CLOSED,
        agent="dashboard_analyst",
        action="approval.denied",
        details={"source": "dashboard"},
    )

    # Emit audit event
    try:
        db = get_db()
        if db is not None:
            await db.execute(
                """
                INSERT INTO audit_records (audit_id, tenant_id, event_type, event_category,
                                           investigation_id, payload, timestamp)
                VALUES (gen_random_uuid()::text, $1, $2, $3, $4, '{}'::jsonb, NOW())
                """,
                state.tenant_id,
                "approval.denied",
                "approval",
                investigation_id,
            )
    except Exception as exc:
        logger.warning("Failed to emit audit event: %s", exc)

    return {"status": "rejected", "new_state": "closed"}
