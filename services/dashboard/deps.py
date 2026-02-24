"""Dashboard dependency injection — Story 17-1.

Provides shared dependencies (Postgres, Redis, InvestigationRepository)
for all dashboard routes.  Follows the same pattern as
``services/audit_service/api.py``.
"""

from __future__ import annotations

from typing import Any, Optional

from orchestrator.persistence import InvestigationRepository

# Module-level singletons — set during init
_db: Any = None
_redis: Any = None
_repo: Optional[InvestigationRepository] = None


def init_deps(postgres_client: Any, redis_client: Any = None) -> None:
    """Initialise dashboard dependencies."""
    global _db, _redis, _repo
    _db = postgres_client
    _redis = redis_client
    _repo = InvestigationRepository(postgres_client)


def get_db() -> Any:
    """Return the Postgres client."""
    return _db


def get_redis() -> Any:
    """Return the Redis client."""
    return _redis


def get_repo() -> InvestigationRepository:
    """Return the InvestigationRepository singleton."""
    if _repo is None:
        raise RuntimeError("Dashboard dependencies not initialised — call init_deps()")
    return _repo
