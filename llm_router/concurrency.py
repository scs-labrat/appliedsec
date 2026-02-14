"""Concurrency controller with priority-based rate limits — Story 6.2.

Enforces per-priority concurrency limits and per-tenant hourly quotas.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PriorityRateLimit:
    max_concurrent: int
    max_rpm: int


# Per-priority concurrency and RPM limits
PRIORITY_LIMITS: dict[str, PriorityRateLimit] = {
    "critical": PriorityRateLimit(max_concurrent=8, max_rpm=200),
    "high": PriorityRateLimit(max_concurrent=6, max_rpm=100),
    "normal": PriorityRateLimit(max_concurrent=4, max_rpm=50),
    "low": PriorityRateLimit(max_concurrent=2, max_rpm=20),
}

# Per-tenant hourly quotas
TENANT_QUOTAS: dict[str, int] = {
    "premium": 500,
    "standard": 100,
    "trial": 20,
}


class QuotaExceeded(Exception):
    """Raised when a tenant exceeds their hourly call quota."""


class ConcurrencyController:
    """Manages per-priority concurrency and per-tenant rate limits."""

    def __init__(self) -> None:
        self._active: dict[str, int] = {p: 0 for p in PRIORITY_LIMITS}
        self._timestamps: dict[str, list[float]] = {p: [] for p in PRIORITY_LIMITS}
        self._tenant_calls: dict[str, list[float]] = {}

    # ------------------------------------------------------------------
    # priority concurrency
    # ------------------------------------------------------------------

    def acquire(self, priority: str) -> bool:
        """Try to acquire a concurrency slot for *priority*.

        Returns ``True`` if acquired, ``False`` if the limit is reached.
        """
        limit = PRIORITY_LIMITS.get(priority)
        if limit is None:
            return True

        # Check RPM
        now = time.monotonic()
        self._timestamps[priority] = [
            t for t in self._timestamps[priority] if now - t < 60
        ]
        if len(self._timestamps[priority]) >= limit.max_rpm:
            return False

        # Check concurrency
        if self._active[priority] >= limit.max_concurrent:
            return False

        self._active[priority] += 1
        self._timestamps[priority].append(now)
        return True

    def release(self, priority: str) -> None:
        """Release a concurrency slot."""
        if priority in self._active and self._active[priority] > 0:
            self._active[priority] -= 1

    def get_active(self, priority: str) -> int:
        return self._active.get(priority, 0)

    def get_utilisation(self) -> dict[str, dict[str, Any]]:
        """Return utilisation metrics for each priority."""
        result: dict[str, dict[str, Any]] = {}
        for priority, limit in PRIORITY_LIMITS.items():
            active = self._active[priority]
            result[priority] = {
                "active": active,
                "max_concurrent": limit.max_concurrent,
                "utilisation": active / limit.max_concurrent if limit.max_concurrent else 0,
            }
        return result

    # ------------------------------------------------------------------
    # tenant quotas
    # ------------------------------------------------------------------

    def check_tenant_quota(self, tenant_id: str, tenant_tier: str = "standard") -> None:
        """Raise :class:`QuotaExceeded` if the tenant is over quota."""
        quota = TENANT_QUOTAS.get(tenant_tier, TENANT_QUOTAS["standard"])
        now = time.monotonic()

        calls = self._tenant_calls.get(tenant_id, [])
        calls = [t for t in calls if now - t < 3600]  # last hour
        self._tenant_calls[tenant_id] = calls

        if len(calls) >= quota:
            raise QuotaExceeded(
                f"Tenant {tenant_id} ({tenant_tier}) exceeded "
                f"{quota} calls/hour ({len(calls)} used)"
            )

    def record_tenant_call(self, tenant_id: str) -> None:
        """Record a call for tenant quota tracking."""
        now = time.monotonic()
        if tenant_id not in self._tenant_calls:
            self._tenant_calls[tenant_id] = []
        self._tenant_calls[tenant_id].append(now)
