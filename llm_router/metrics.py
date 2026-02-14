"""Routing metrics and outcome tracking — Story 6.4.

Tracks per-task_type:tier success rates, costs, latencies, and
confidence for routing refinement.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TierOutcome:
    """Aggregated metrics for a single task_type:tier combination."""

    total: int = 0
    success: int = 0
    total_cost_usd: float = 0.0
    total_latency_ms: float = 0.0
    confidence_sum: float = 0.0

    @property
    def success_rate(self) -> float:
        return self.success / self.total if self.total else 0.0

    @property
    def avg_cost(self) -> float:
        return self.total_cost_usd / self.total if self.total else 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.total if self.total else 0.0

    @property
    def avg_confidence(self) -> float:
        return self.confidence_sum / self.total if self.total else 0.0


class RoutingMetrics:
    """Collects per-task outcome data for routing refinement."""

    def __init__(self) -> None:
        self._outcomes: dict[str, TierOutcome] = {}

    def record_outcome(
        self,
        task_type: str,
        tier: str,
        *,
        success: bool,
        cost_usd: float = 0.0,
        latency_ms: float = 0.0,
        confidence: float = 0.0,
    ) -> None:
        """Record a completed task outcome."""
        key = f"{task_type}:{tier}"
        if key not in self._outcomes:
            self._outcomes[key] = TierOutcome()

        outcome = self._outcomes[key]
        outcome.total += 1
        if success:
            outcome.success += 1
        outcome.total_cost_usd += cost_usd
        outcome.total_latency_ms += latency_ms
        outcome.confidence_sum += confidence

    def get_outcome(self, task_type: str, tier: str) -> TierOutcome | None:
        return self._outcomes.get(f"{task_type}:{tier}")

    def get_all_outcomes(self) -> dict[str, TierOutcome]:
        return dict(self._outcomes)

    def summary(self) -> dict[str, dict[str, float]]:
        """Return a summary suitable for dashboard display."""
        result: dict[str, dict[str, float]] = {}
        for key, outcome in self._outcomes.items():
            result[key] = {
                "total": outcome.total,
                "success_rate": outcome.success_rate,
                "avg_cost": outcome.avg_cost,
                "avg_latency_ms": outcome.avg_latency_ms,
                "avg_confidence": outcome.avg_confidence,
            }
        return result
