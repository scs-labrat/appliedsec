"""Spend guard and cost tracking — Story 5.6.

Enforces daily / monthly cost limits and tracks per-call costs by
tier, task type, and tenant.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DEFAULT_MONTHLY_HARD_CAP = 1000.0  # USD
DEFAULT_MONTHLY_SOFT_ALERT = 500.0  # USD


class SpendLimitExceeded(Exception):
    """Raised when the hard spend cap is hit."""


@dataclass
class CostRecord:
    """A single API call cost record."""

    cost_usd: float
    model_id: str
    task_type: str
    tenant_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SpendGuard:
    """Enforces spend limits and tracks per-call costs."""

    def __init__(
        self,
        monthly_hard_cap: float = DEFAULT_MONTHLY_HARD_CAP,
        monthly_soft_alert: float = DEFAULT_MONTHLY_SOFT_ALERT,
    ) -> None:
        self.monthly_hard_cap = monthly_hard_cap
        self.monthly_soft_alert = monthly_soft_alert
        self._records: list[CostRecord] = []
        self._soft_alert_fired = False

    # ------------------------------------------------------------------
    # recording
    # ------------------------------------------------------------------

    def record(
        self,
        cost_usd: float,
        model_id: str = "",
        task_type: str = "",
        tenant_id: str = "",
    ) -> None:
        """Record a completed API call and check limits."""
        self._records.append(
            CostRecord(
                cost_usd=cost_usd,
                model_id=model_id,
                task_type=task_type,
                tenant_id=tenant_id,
            )
        )
        self._check_soft_alert()

    # ------------------------------------------------------------------
    # guard
    # ------------------------------------------------------------------

    def check_budget(self) -> None:
        """Raise :class:`SpendLimitExceeded` if the hard cap is reached."""
        if self.monthly_total >= self.monthly_hard_cap:
            raise SpendLimitExceeded(
                f"Monthly spend ${self.monthly_total:.2f} "
                f"exceeds hard cap ${self.monthly_hard_cap:.2f}"
            )

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------

    @property
    def monthly_total(self) -> float:
        """Total spend for the current calendar month."""
        now = datetime.now(timezone.utc)
        return sum(
            r.cost_usd
            for r in self._records
            if r.timestamp.year == now.year and r.timestamp.month == now.month
        )

    def total_by_model(self) -> dict[str, float]:
        """Aggregate spend per model."""
        totals: dict[str, float] = {}
        for r in self._records:
            totals[r.model_id] = totals.get(r.model_id, 0) + r.cost_usd
        return totals

    def total_by_task_type(self) -> dict[str, float]:
        """Aggregate spend per task type."""
        totals: dict[str, float] = {}
        for r in self._records:
            totals[r.task_type] = totals.get(r.task_type, 0) + r.cost_usd
        return totals

    def total_by_tenant(self) -> dict[str, float]:
        """Aggregate spend per tenant."""
        totals: dict[str, float] = {}
        for r in self._records:
            totals[r.tenant_id] = totals.get(r.tenant_id, 0) + r.cost_usd
        return totals

    @property
    def call_count(self) -> int:
        return len(self._records)

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _check_soft_alert(self) -> None:
        if not self._soft_alert_fired and self.monthly_total >= self.monthly_soft_alert:
            self._soft_alert_fired = True
            logger.warning(
                "SPEND SOFT ALERT: Monthly spend $%.2f reached soft threshold $%.2f",
                self.monthly_total,
                self.monthly_soft_alert,
            )
