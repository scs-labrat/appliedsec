"""RBAC middleware — Story 17-8.

Header-based role extraction for MVP. Production would use OIDC/SAML.

Roles:
  - ``analyst``        — read-only
  - ``senior_analyst`` — approve/reject
  - ``admin``          — all + kill switches
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

VALID_ROLES = frozenset({"analyst", "senior_analyst", "admin"})

# Routes that don't require authentication
_PUBLIC_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})

# Role hierarchy: higher roles inherit lower role permissions
_ROLE_HIERARCHY: dict[str, set[str]] = {
    "admin": {"admin", "senior_analyst", "analyst"},
    "senior_analyst": {"senior_analyst", "analyst"},
    "analyst": {"analyst"},
}

# Route patterns → minimum required role
_PROTECTED_PATTERNS: list[tuple[str, str, str]] = [
    # (method, path_prefix, required_role)
    ("POST", "/api/investigations/", "senior_analyst"),  # approve/reject
]


class RBACMiddleware(BaseHTTPMiddleware):
    """Extract role from ``X-User-Role`` header and enforce permissions."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip auth for public paths
        if request.url.path in _PUBLIC_PATHS:
            return await call_next(request)

        # Extract role from header
        role = request.headers.get("X-User-Role", "").strip().lower()

        if not role:
            # In MVP mode, default to analyst for GET requests (read-only)
            if request.method == "GET":
                role = "analyst"
            else:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Missing X-User-Role header"},
                )

        if role not in VALID_ROLES:
            return JSONResponse(
                status_code=401,
                content={"detail": f"Invalid role: {role}"},
            )

        # Check route-level permissions
        for method, path_prefix, required_role in _PROTECTED_PATTERNS:
            if request.method == method and request.url.path.startswith(path_prefix):
                user_roles = _ROLE_HIERARCHY.get(role, set())
                if required_role not in user_roles:
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": f"Role '{role}' cannot access {method} {request.url.path}. "
                            f"Requires '{required_role}'."
                        },
                    )

        # Attach role to request state for downstream use
        request.state.user_role = role
        return await call_next(request)


def require_role(required_role: str) -> Callable:
    """Route-level decorator to enforce a minimum role.

    Usage::

        @router.post("/admin/action")
        @require_role("admin")
        async def admin_action(request: Request):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request: Request | None = kwargs.get("request")
            if request is None:
                # Try positional
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                raise HTTPException(status_code=500, detail="Request not available")

            role = getattr(request.state, "user_role", "")
            user_roles = _ROLE_HIERARCHY.get(role, set())
            if required_role not in user_roles:
                raise HTTPException(
                    status_code=403,
                    detail=f"Role '{role}' insufficient. Requires '{required_role}'.",
                )
            return await func(*args, **kwargs)

        return wrapper

    return decorator
