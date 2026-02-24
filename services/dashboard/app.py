"""Dashboard FastAPI application — Story 17-1.

Analyst Investigation Dashboard: lightweight FastAPI + HTMX + Jinja2 web UI
for SOC analysts to view investigations, approve/reject actions, and monitor
system health.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Resolve paths relative to this file
_BASE_DIR = Path(__file__).resolve().parent
_TEMPLATE_DIR = _BASE_DIR / "templates"
_STATIC_DIR = _BASE_DIR / "static"

templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

app = FastAPI(title="ALUSKORT Analyst Dashboard", version="1.0.0")

# Mount static files
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ------------------------------------------------------------------
# Routes — imported after app is created to avoid circular imports
# ------------------------------------------------------------------

from services.dashboard.routes.investigations import router as investigations_router  # noqa: E402
from services.dashboard.routes.investigation_detail import router as detail_router  # noqa: E402
from services.dashboard.routes.timeline import router as timeline_router  # noqa: E402
from services.dashboard.routes.approvals import router as approvals_router  # noqa: E402
from services.dashboard.routes.metrics import router as metrics_router  # noqa: E402
from services.dashboard.middleware.auth import RBACMiddleware  # noqa: E402
from services.dashboard.ws import websocket_investigations  # noqa: E402

app.add_middleware(RBACMiddleware)

# WebSocket endpoint — Story 17-7
app.websocket("/ws/investigations")(websocket_investigations)

app.include_router(investigations_router)
app.include_router(detail_router)
app.include_router(timeline_router)
app.include_router(approvals_router)
app.include_router(metrics_router)


# ------------------------------------------------------------------
# Root + health
# ------------------------------------------------------------------


@app.get("/")
async def index() -> RedirectResponse:
    """Landing page redirects to investigation list."""
    return RedirectResponse(url="/investigations", status_code=302)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "dashboard"}


def init_app(postgres_client: Any, redis_client: Any = None) -> FastAPI:
    """Initialise dependencies and return the app."""
    from services.dashboard.deps import init_deps

    init_deps(postgres_client, redis_client)
    return app
