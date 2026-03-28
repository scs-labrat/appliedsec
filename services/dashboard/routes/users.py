"""User & Role Administration routes.

Provides user management, role assignment, and activity overview
for the ALUSKORT SOC platform. Admin-only write operations.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_db
from services.dashboard.middleware.auth import require_role

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Demo / fallback data
# ---------------------------------------------------------------------------

_now = datetime.now(timezone.utc)

DEMO_USERS: list[dict[str, Any]] = [
    {
        "user_id": "usr_001",
        "display_name": "Sarah Chen",
        "email": "s.chen@aluskort.io",
        "role": "admin",
        "title": "SOC Manager",
        "status": "active",
        "last_login": _now - timedelta(hours=2),
        "last_login_display": "2h ago",
        "investigations_handled": 342,
        "approvals_made": 189,
        "created_at": _now - timedelta(days=540),
    },
    {
        "user_id": "usr_002",
        "display_name": "Marcus Johnson",
        "email": "m.johnson@aluskort.io",
        "role": "senior_analyst",
        "title": "L3 Analyst",
        "status": "active",
        "last_login": _now - timedelta(minutes=30),
        "last_login_display": "30m ago",
        "investigations_handled": 587,
        "approvals_made": 234,
        "created_at": _now - timedelta(days=420),
    },
    {
        "user_id": "usr_003",
        "display_name": "Priya Patel",
        "email": "p.patel@aluskort.io",
        "role": "senior_analyst",
        "title": "L2 Analyst",
        "status": "active",
        "last_login": _now - timedelta(hours=1),
        "last_login_display": "1h ago",
        "investigations_handled": 415,
        "approvals_made": 156,
        "created_at": _now - timedelta(days=365),
    },
    {
        "user_id": "usr_004",
        "display_name": "James Wilson",
        "email": "j.wilson@aluskort.io",
        "role": "analyst",
        "title": "L1 Analyst",
        "status": "active",
        "last_login": _now - timedelta(minutes=15),
        "last_login_display": "15m ago",
        "investigations_handled": 203,
        "approvals_made": 0,
        "created_at": _now - timedelta(days=180),
    },
    {
        "user_id": "usr_005",
        "display_name": "Aisha Mohammed",
        "email": "a.mohammed@aluskort.io",
        "role": "analyst",
        "title": "L1 Analyst",
        "status": "active",
        "last_login": _now - timedelta(hours=4),
        "last_login_display": "4h ago",
        "investigations_handled": 178,
        "approvals_made": 0,
        "created_at": _now - timedelta(days=150),
    },
    {
        "user_id": "usr_006",
        "display_name": "David Kim",
        "email": "d.kim@aluskort.io",
        "role": "admin",
        "title": "Platform Engineer",
        "status": "active",
        "last_login": _now - timedelta(days=1),
        "last_login_display": "1d ago",
        "investigations_handled": 45,
        "approvals_made": 312,
        "created_at": _now - timedelta(days=600),
    },
    {
        "user_id": "usr_007",
        "display_name": "Elena Rodriguez",
        "email": "e.rodriguez@aluskort.io",
        "role": "senior_analyst",
        "title": "L2 Analyst",
        "status": "active",
        "last_login": _now - timedelta(hours=3),
        "last_login_display": "3h ago",
        "investigations_handled": 390,
        "approvals_made": 145,
        "created_at": _now - timedelta(days=310),
    },
    {
        "user_id": "usr_008",
        "display_name": "Tom O'Brien",
        "email": "t.obrien@aluskort.io",
        "role": "analyst",
        "title": "L1 Analyst",
        "status": "inactive",
        "last_login": _now - timedelta(days=30),
        "last_login_display": "30d ago",
        "investigations_handled": 89,
        "approvals_made": 0,
        "created_at": _now - timedelta(days=270),
    },
]


def _compute_summary(users: list[dict[str, Any]]) -> dict[str, Any]:
    """Build summary statistics from user list."""
    total = len(users)
    active = sum(1 for u in users if u["status"] == "active")
    admins = sum(1 for u in users if u["role"] == "admin")
    seniors = sum(1 for u in users if u["role"] == "senior_analyst")
    analysts = sum(1 for u in users if u["role"] == "analyst")
    return {
        "total": total,
        "active": active,
        "inactive": total - active,
        "admins": admins,
        "senior_analysts": seniors,
        "analysts": analysts,
    }


async def _fetch_users() -> list[dict[str, Any]]:
    """Load users from database, falling back to demo data."""
    db = get_db()
    if db is not None:
        try:
            rows = await db.fetch_many(
                "SELECT user_id, display_name, email, role, title, status, "
                "last_login, investigations_handled, approvals_made, created_at "
                "FROM users ORDER BY display_name"
            )
            if rows:
                users = []
                for r in rows:
                    u = dict(r)
                    # Compute display-friendly last_login string
                    if u.get("last_login"):
                        delta = datetime.now(timezone.utc) - u["last_login"]
                        if delta < timedelta(hours=1):
                            u["last_login_display"] = f"{int(delta.total_seconds() // 60)}m ago"
                        elif delta < timedelta(days=1):
                            u["last_login_display"] = f"{int(delta.total_seconds() // 3600)}h ago"
                        else:
                            u["last_login_display"] = f"{delta.days}d ago"
                    else:
                        u["last_login_display"] = "Never"
                    users.append(u)
                return users
        except Exception:
            logger.debug("Users table not available, using demo data", exc_info=True)
    return DEMO_USERS


# ---------------------------------------------------------------------------
# Page route
# ---------------------------------------------------------------------------

@router.get("/users", response_class=HTMLResponse)
async def users_page(request: Request) -> HTMLResponse:
    """Render the User & Role Administration page."""
    users = await _fetch_users()
    summary = _compute_summary(users)
    user_role = getattr(request.state, "user_role", "analyst")

    return templates.TemplateResponse(
        request,
        "users/index.html",
        {
            "users": users,
            "summary": summary,
            "user_role": user_role,
        },
    )


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@router.get("/api/users/list")
async def api_users_list() -> list[dict[str, Any]]:
    """Return the user list as JSON."""
    users = await _fetch_users()
    # Serialise datetimes
    for u in users:
        for key in ("last_login", "created_at"):
            if isinstance(u.get(key), datetime):
                u[key] = u[key].isoformat()
    return users


@router.post("/api/users/create")
@require_role("admin")
async def api_users_create(request: Request) -> dict[str, Any]:
    """Create a new user (admin only)."""
    body = await request.json()
    display_name = body.get("display_name", "").strip()
    email = body.get("email", "").strip()
    role = body.get("role", "analyst").strip().lower()
    title = body.get("title", "").strip()

    if not display_name or not email:
        raise HTTPException(400, "display_name and email are required")
    if role not in ("analyst", "senior_analyst", "admin"):
        raise HTTPException(400, f"Invalid role: {role}")

    db = get_db()
    if db is not None:
        try:
            user_id = f"usr_{uuid.uuid4().hex[:8]}"
            await db.execute(
                "INSERT INTO users (user_id, display_name, email, role, title, status, created_at) "
                "VALUES ($1, $2, $3, $4, $5, 'active', NOW())",
                user_id, display_name, email, role, title,
            )
            return {"status": "created", "user_id": user_id}
        except Exception as exc:
            raise HTTPException(500, f"Database error: {exc}")

    # Demo mode — just acknowledge
    return {"status": "created", "user_id": f"usr_{uuid.uuid4().hex[:8]}", "demo": True}


@router.post("/api/users/update-role")
@require_role("admin")
async def api_users_update_role(request: Request) -> dict[str, Any]:
    """Change a user's role (admin only)."""
    body = await request.json()
    user_id = body.get("user_id", "").strip()
    new_role = body.get("role", "").strip().lower()

    if not user_id:
        raise HTTPException(400, "user_id is required")
    if new_role not in ("analyst", "senior_analyst", "admin"):
        raise HTTPException(400, f"Invalid role: {new_role}")

    db = get_db()
    if db is not None:
        try:
            await db.execute(
                "UPDATE users SET role = $1 WHERE user_id = $2",
                new_role, user_id,
            )
            return {"status": "updated", "user_id": user_id, "role": new_role}
        except Exception as exc:
            raise HTTPException(500, f"Database error: {exc}")

    return {"status": "updated", "user_id": user_id, "role": new_role, "demo": True}


@router.post("/api/users/deactivate")
@require_role("admin")
async def api_users_deactivate(request: Request) -> dict[str, Any]:
    """Deactivate a user (admin only)."""
    body = await request.json()
    user_id = body.get("user_id", "").strip()

    if not user_id:
        raise HTTPException(400, "user_id is required")

    db = get_db()
    if db is not None:
        try:
            await db.execute(
                "UPDATE users SET status = 'inactive' WHERE user_id = $1",
                user_id,
            )
            return {"status": "deactivated", "user_id": user_id}
        except Exception as exc:
            raise HTTPException(500, f"Database error: {exc}")

    return {"status": "deactivated", "user_id": user_id, "demo": True}
