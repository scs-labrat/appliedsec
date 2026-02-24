"""Canary rollout strategy — Story 14.9.

Manages incremental promotion from shadow mode to full autonomy,
with automatic promotion criteria and rollback safety nets.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Canary slice statuses
CANARY_ACTIVE = "active"
CANARY_PROMOTED = "promoted"
CANARY_ROLLED_BACK = "rolled_back"


@dataclass
class CanarySlice:
    """A canary rollout slice targeting a specific dimension/value."""

    slice_id: str
    dimension: str  # tenant, severity, rule_family, datasource
    value: str
    created_at: str = ""
    promoted_at: str = ""
    status: str = CANARY_ACTIVE

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    @property
    def age_days(self) -> float:
        """Days since this canary slice was created."""
        try:
            created = datetime.fromisoformat(self.created_at)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - created).total_seconds() / 86400
        except (ValueError, TypeError):
            return 0.0


@dataclass
class CanaryConfig:
    """Configuration for canary rollout promotion and rollback."""

    slices: list[CanarySlice] = field(default_factory=list)
    promotion_days: int = 7
    min_precision: float = 0.98
    rollback_precision: float = 0.95


class CanaryRolloutManager:
    """Manages canary slice promotion and rollback.

    Integrates with KillSwitchManager (14.3) for rollback enforcement
    and ShadowModeManager (14.8) for shadow reversion.
    """

    def __init__(
        self,
        kill_switch_manager: Any,
        shadow_mode_manager: Any,
        audit_producer: Any | None = None,
    ) -> None:
        self._kill_switch = kill_switch_manager
        self._shadow = shadow_mode_manager
        self._audit = audit_producer
        self._history: list[dict[str, Any]] = []

    async def check_promotion(
        self,
        canary_slice: CanarySlice,
        precision: float,
        missed_tps: int,
        config: CanaryConfig | None = None,
    ) -> str:
        """Decide whether to promote, rollback, or continue a canary slice.

        Returns:
            "promote" — if age >= promotion_days, precision >= min_precision, 0 missed TPs
            "rollback" — if precision < rollback_precision or missed_tps > 0
            "continue" — otherwise
        """
        cfg = config or CanaryConfig()

        # Rollback checks first (safety takes priority)
        if missed_tps > 0:
            return "rollback"
        if precision < cfg.rollback_precision:
            return "rollback"

        # Promotion checks
        if (canary_slice.age_days >= cfg.promotion_days
                and precision >= cfg.min_precision
                and missed_tps == 0):
            return "promote"

        return "continue"

    async def promote(self, canary_slice: CanarySlice) -> None:
        """Promote a canary slice to full autonomy."""
        canary_slice.status = CANARY_PROMOTED
        canary_slice.promoted_at = datetime.now(timezone.utc).isoformat()

        event = {
            "action": "promote",
            "slice_id": canary_slice.slice_id,
            "dimension": canary_slice.dimension,
            "value": canary_slice.value,
            "promoted_at": canary_slice.promoted_at,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        self._history.append(event)
        logger.info(
            "Canary slice %s promoted: %s=%s",
            canary_slice.slice_id, canary_slice.dimension, canary_slice.value,
        )

        if self._audit is not None:
            try:
                self._audit.emit(
                    event_type="canary.promoted",
                    event_category="decision",
                    actor_type="agent",
                    actor_id="canary_rollout_manager",
                    context=event,
                )
            except Exception:
                logger.warning("Failed to emit canary.promoted audit event", exc_info=True)

    async def rollback(self, canary_slice: CanarySlice, reason: str) -> None:
        """Rollback a canary slice to shadow mode and activate kill switch.

        1. Marks slice as rolled_back
        2. Activates kill switch for the affected dimension
        3. Emits audit events
        """
        canary_slice.status = CANARY_ROLLED_BACK

        event = {
            "action": "rollback",
            "slice_id": canary_slice.slice_id,
            "dimension": canary_slice.dimension,
            "value": canary_slice.value,
            "reason": reason,
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        self._history.append(event)
        logger.warning(
            "Canary slice %s rolled back: %s=%s reason=%s",
            canary_slice.slice_id, canary_slice.dimension, canary_slice.value, reason,
        )

        # Activate kill switch for the affected dimension
        dimension_map = {
            "tenant": "tenant",
            "rule_family": "pattern",
            "severity": "tenant",
            "datasource": "datasource",
        }
        ks_dimension = dimension_map.get(canary_slice.dimension, canary_slice.dimension)
        await self._kill_switch.activate(
            dimension=ks_dimension,
            value=canary_slice.value,
            activated_by="canary_rollout_manager",
            reason=f"Canary rollback: {reason}",
        )

        if self._audit is not None:
            try:
                self._audit.emit(
                    event_type="canary.rolled_back",
                    event_category="decision",
                    actor_type="agent",
                    actor_id="canary_rollout_manager",
                    context=event,
                )
            except Exception:
                logger.warning("Failed to emit canary.rolled_back audit event", exc_info=True)

    async def get_rollout_history(self) -> list[dict[str, Any]]:
        """Return all promotion and rollback events."""
        return list(self._history)


class CanaryEvaluator:
    """Evaluates all active canary slices and triggers promotion/rollback."""

    def __init__(
        self,
        rollout_manager: CanaryRolloutManager,
        fp_evaluation: Any,
    ) -> None:
        self._manager = rollout_manager
        self._fp_eval = fp_evaluation

    async def evaluate_all_slices(
        self, config: CanaryConfig,
    ) -> list[dict[str, Any]]:
        """Evaluate each active canary slice and apply decisions.

        For each active slice:
        1. Get precision and missed TPs from FPEvaluationFramework
        2. Call check_promotion()
        3. Execute promote/rollback if needed

        Returns list of decisions made.
        """
        decisions: list[dict[str, Any]] = []

        for canary_slice in config.slices:
            if canary_slice.status != CANARY_ACTIVE:
                continue

            # Get evaluation data for this slice
            eval_result = self._fp_eval.get_evaluation(canary_slice.value)
            precision = getattr(eval_result, "precision", 1.0) if eval_result else 1.0
            missed_tps = getattr(eval_result, "false_positives", 0) if eval_result else 0

            action = await self._manager.check_promotion(
                canary_slice, precision, missed_tps, config,
            )

            if action == "promote":
                await self._manager.promote(canary_slice)
            elif action == "rollback":
                reason = "precision_below_threshold"
                if missed_tps > 0:
                    reason = f"missed_tps={missed_tps}"
                await self._manager.rollback(canary_slice, reason)

            decisions.append({
                "slice_id": canary_slice.slice_id,
                "action": action,
                "precision": precision,
                "missed_tps": missed_tps,
            })

        return decisions
