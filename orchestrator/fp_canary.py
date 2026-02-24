"""FP canary rollout manager — Story 14.3.

New FP patterns start in shadow mode and must accumulate a configurable
number of correct shadow decisions before being promoted to active.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_PROMOTION_THRESHOLD = 50
DEFAULT_MAX_DISAGREEMENT_RATE = 0.05


class FPCanaryManager:
    """Manages canary rollout for new FP patterns.

    Shadow decisions are tracked in Redis:
        canary:{pattern_id}:total    — total shadow decisions recorded
        canary:{pattern_id}:agree    — decisions that agreed with analyst
        canary:{pattern_id}:disagree — decisions that disagreed with analyst
    """

    def __init__(
        self,
        redis_client: Any,
        promotion_threshold: int = DEFAULT_PROMOTION_THRESHOLD,
        max_disagreement_rate: float = DEFAULT_MAX_DISAGREEMENT_RATE,
    ) -> None:
        self._redis = redis_client
        self._promotion_threshold = promotion_threshold
        self._max_disagreement_rate = max_disagreement_rate

    async def record_shadow_decision(
        self,
        pattern_id: str,
        pattern_decision: str,
        analyst_decision: str,
    ) -> None:
        """Record a shadow decision and whether it agrees with the analyst.

        Args:
            pattern_id: The FP pattern being evaluated.
            pattern_decision: What the FP pattern would have decided
                              (e.g. "auto_close", "escalate").
            analyst_decision: What the analyst actually decided.
        """
        agrees = pattern_decision == analyst_decision

        try:
            client = self._get_client()
            await client.incr(f"canary:{pattern_id}:total")
            if agrees:
                await client.incr(f"canary:{pattern_id}:agree")
            else:
                await client.incr(f"canary:{pattern_id}:disagree")
        except Exception:
            logger.warning(
                "Failed to record canary decision for %s", pattern_id,
                exc_info=True,
            )

    async def get_canary_stats(self, pattern_id: str) -> dict[str, Any]:
        """Return canary statistics for a pattern.

        Returns:
            dict with total_decisions, agreements, disagreements,
            agreement_rate.
        """
        try:
            client = self._get_client()
            total = int(await client.get(f"canary:{pattern_id}:total") or 0)
            agree = int(await client.get(f"canary:{pattern_id}:agree") or 0)
            disagree = int(await client.get(f"canary:{pattern_id}:disagree") or 0)
        except Exception:
            logger.warning("Failed to get canary stats for %s", pattern_id, exc_info=True)
            return {
                "total_decisions": 0,
                "agreements": 0,
                "disagreements": 0,
                "agreement_rate": 0.0,
            }

        agreement_rate = agree / total if total > 0 else 0.0

        return {
            "total_decisions": total,
            "agreements": agree,
            "disagreements": disagree,
            "agreement_rate": agreement_rate,
        }

    async def should_promote(self, pattern_id: str) -> bool:
        """Determine whether a shadow pattern is ready for promotion.

        Requires:
        - total_decisions >= promotion_threshold
        - disagreement_rate <= max_disagreement_rate
        """
        stats = await self.get_canary_stats(pattern_id)
        total = stats["total_decisions"]
        if total < self._promotion_threshold:
            return False

        disagreement_rate = stats["disagreements"] / total if total > 0 else 0.0
        return disagreement_rate <= self._max_disagreement_rate

    async def promote(self, pattern_id: str) -> None:
        """Promote a shadow pattern to active status.

        Updates the FP pattern's status in Redis from 'shadow' to 'active'.
        """
        try:
            client = self._get_client()
            import json

            raw = await client.get(f"fp:{pattern_id}")
            if raw is not None:
                pattern = json.loads(raw)
                pattern["status"] = "active"
                await client.set(f"fp:{pattern_id}", json.dumps(pattern))
                logger.info("Canary promoted pattern %s to active", pattern_id)
            else:
                logger.warning("Pattern %s not found in Redis for promotion", pattern_id)
        except Exception:
            logger.warning("Failed to promote canary pattern %s", pattern_id, exc_info=True)

    def _get_client(self) -> Any:
        """Return the underlying async Redis client."""
        if hasattr(self._redis, "_client") and self._redis._client is not None:
            return self._redis._client
        return self._redis
