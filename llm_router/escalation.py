"""Escalation manager — Story 6.3.

Upgrades Sonnet (Tier 1) calls to Opus (Tier 1+) when confidence is
below threshold on critical / high severity alerts.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from llm_router.models import ModelTier

logger = logging.getLogger(__name__)

CONFIDENCE_THRESHOLD = 0.6
MAX_ESCALATIONS_PER_HOUR = 10
APPLICABLE_SEVERITIES = frozenset({"critical", "high"})
EXTENDED_THINKING_BUDGET = 8192


@dataclass
class EscalationPolicy:
    confidence_threshold: float = CONFIDENCE_THRESHOLD
    applicable_severities: frozenset[str] = APPLICABLE_SEVERITIES
    max_escalations_per_hour: int = MAX_ESCALATIONS_PER_HOUR
    extended_thinking_budget: int = EXTENDED_THINKING_BUDGET


class EscalationManager:
    """Decides whether to escalate a Sonnet response to Opus."""

    def __init__(self, policy: EscalationPolicy | None = None) -> None:
        self.policy = policy or EscalationPolicy()
        self._escalation_timestamps: list[float] = []

    @property
    def escalations_this_hour(self) -> int:
        now = time.monotonic()
        self._escalation_timestamps = [
            t for t in self._escalation_timestamps if now - t < 3600
        ]
        return len(self._escalation_timestamps)

    @property
    def budget_remaining(self) -> int:
        return max(0, self.policy.max_escalations_per_hour - self.escalations_this_hour)

    def should_escalate(self, confidence: float, severity: str) -> bool:
        """Return ``True`` if the task should be re-analysed with Opus."""
        if confidence >= self.policy.confidence_threshold:
            return False

        if severity not in self.policy.applicable_severities:
            return False

        if self.escalations_this_hour >= self.policy.max_escalations_per_hour:
            logger.warning(
                "Escalation budget exhausted (%d/%d this hour)",
                self.escalations_this_hour,
                self.policy.max_escalations_per_hour,
            )
            return False

        return True

    def record_escalation(self) -> None:
        """Record that an escalation was performed."""
        self._escalation_timestamps.append(time.monotonic())

    def get_escalation_tier(self) -> ModelTier:
        """Return the tier to escalate to."""
        return ModelTier.TIER_1_PLUS
