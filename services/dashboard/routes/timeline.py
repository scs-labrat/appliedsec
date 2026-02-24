"""Timeline routes — Story 17-4.

HTMX partial endpoint for rendering the decision chain as a timeline.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_repo

router = APIRouter()

# Agent role → display color mapping for timeline entries
_AGENT_COLORS = {
    "ioc_extractor": "purple",
    "context_enricher": "blue",
    "reasoning_agent": "orange",
    "response_agent": "green",
    "ctem_correlator": "cyan",
    "atlas_mapper": "pink",
}


@router.get("/api/investigations/{investigation_id}/timeline", response_class=HTMLResponse)
async def investigation_timeline(request: Request, investigation_id: str) -> HTMLResponse:
    """Return timeline HTML fragment for HTMX partial update."""
    repo = get_repo()
    state = await repo.load(investigation_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    entries = []
    for entry in state.decision_chain:
        if isinstance(entry, dict):
            agent = entry.get("agent", "")
            entries.append({
                "agent": agent,
                "action": entry.get("action", ""),
                "confidence": entry.get("confidence"),
                "timestamp": entry.get("timestamp", ""),
                "attestation_status": entry.get("attestation_status", ""),
                "color": _AGENT_COLORS.get(agent, "gray"),
            })
        else:
            # DecisionEntry dataclass
            entries.append({
                "agent": getattr(entry, "agent", ""),
                "action": getattr(entry, "action", ""),
                "confidence": getattr(entry, "confidence", None),
                "timestamp": getattr(entry, "timestamp", ""),
                "attestation_status": getattr(entry, "attestation_status", ""),
                "color": _AGENT_COLORS.get(getattr(entry, "agent", ""), "gray"),
            })

    return templates.TemplateResponse(
        "components/timeline.html",
        {
            "request": request,
            "entries": entries,
        },
    )
