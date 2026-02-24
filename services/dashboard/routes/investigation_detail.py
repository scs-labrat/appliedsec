"""Investigation detail routes — Story 17-3.

Full detail page for a single investigation, showing GraphState sections.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_repo

router = APIRouter()


@router.get("/investigations/{investigation_id}", response_class=HTMLResponse)
async def investigation_detail(request: Request, investigation_id: str) -> HTMLResponse:
    """Render the full investigation detail page."""
    repo = get_repo()
    state = await repo.load(investigation_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return templates.TemplateResponse(
        "investigations/detail.html",
        {
            "request": request,
            "inv": state,
        },
    )
