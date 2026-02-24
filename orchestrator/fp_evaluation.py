"""FP evaluation framework — Story 14.2.

Measures auto-closure accuracy via stratified sampling, continuous
false-negative detection, and autonomy guardrails.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Precision/recall targets (AC-5)
PRECISION_TARGET = 0.98
RECALL_TARGET = 0.95
FNR_CEILING = 0.005


# ---------------------------------------------------------------------------
# Data models (Task 1)
# ---------------------------------------------------------------------------

@dataclass
class FPEvaluationResult:
    """Precision/recall evaluation result for a rule family."""

    rule_family: str
    total_closures: int = 0
    true_positives: int = 0   # correctly auto-closed (was truly FP)
    false_positives: int = 0  # incorrectly auto-closed (was actually TP)
    false_negatives: int = 0  # missed auto-close (was FP but not caught)
    precision: float = 0.0
    recall: float = 0.0
    fnr: float = 0.0

    def compute_metrics(self) -> None:
        """Recompute precision, recall, and FNR from raw counts."""
        tp = self.true_positives
        fp = self.false_positives
        fn = self.false_negatives
        self.precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        self.recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        self.fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0


@dataclass
class StratumConfig:
    """Configuration for a sampling stratum."""

    rule_family: str
    severity: str
    asset_criticality: str
    min_sample_size: int = 30


# ---------------------------------------------------------------------------
# Stratified sampling (Task 2)
# ---------------------------------------------------------------------------

class FPEvaluationFramework:
    """Stratified sampling and evaluation of FP auto-closures."""

    def compute_strata(
        self, closures: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Group closures by (rule_family, severity, asset_criticality)."""
        strata: dict[str, list[dict[str, Any]]] = {}
        for c in closures:
            key = (
                f"{c.get('rule_family', 'unknown')}"
                f":{c.get('severity', 'unknown')}"
                f":{c.get('asset_criticality', 'unknown')}"
            )
            strata.setdefault(key, []).append(c)
        return strata

    def select_sample(
        self,
        strata: dict[str, list[dict[str, Any]]],
        min_per_stratum: int = 30,
    ) -> list[dict[str, Any]]:
        """Select stratified sample: min 30 per stratum, 100% for novel patterns."""
        sample: list[dict[str, Any]] = []
        for _key, closures in strata.items():
            novel = [
                c for c in closures
                if self.is_novel_pattern(
                    c.get("pattern_id", ""),
                    c.get("pattern_created_at", ""),
                )
            ]
            non_novel = [c for c in closures if c not in novel]

            # 100% review for novel patterns (AC-2)
            sample.extend(novel)

            # For non-novel: at least min_per_stratum (minus any novel already included)
            remaining_needed = max(0, min_per_stratum - len(novel))
            if remaining_needed > 0 and non_novel:
                count = min(remaining_needed, len(non_novel))
                sample.extend(random.sample(non_novel, count))

        return sample

    def is_novel_pattern(
        self,
        pattern_id: str,
        pattern_created_at: str,
        cutoff_days: int = 30,
    ) -> bool:
        """Return True if pattern is less than cutoff_days old."""
        if not pattern_created_at:
            return False
        try:
            created = datetime.fromisoformat(pattern_created_at)
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - created
            return age.days < cutoff_days
        except (ValueError, TypeError):
            return False


# ---------------------------------------------------------------------------
# Continuous monitoring (Task 3)
# ---------------------------------------------------------------------------

class DailyFNDetector:
    """Detects potential false negatives from auto-closed alerts later escalated."""

    def check_auto_closed_escalated(
        self,
        closures: list[dict[str, Any]],
        escalations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Find alerts auto-closed but later escalated by another source."""
        escalated_ids = {e.get("alert_id") for e in escalations if e.get("alert_id")}
        flagged = []
        for c in closures:
            if c.get("alert_id") in escalated_ids:
                flagged.append(self.flag_potential_false_negative(c))
        return flagged

    def flag_potential_false_negative(self, closure: dict[str, Any]) -> dict[str, Any]:
        """Mark a closure as a potential false negative for review."""
        flagged = dict(closure)
        flagged["fn_flagged"] = True
        flagged["fn_flagged_at"] = datetime.now(timezone.utc).isoformat()
        flagged["review_status"] = "pending_review"
        return flagged


class AutonomyGuard:
    """Adjusts autonomy thresholds based on precision/recall targets."""

    def should_reduce_autonomy(self, evaluation: FPEvaluationResult) -> bool:
        """Return True if precision < 98% or FNR > 0.5%."""
        return (
            evaluation.precision < PRECISION_TARGET
            or evaluation.fnr > FNR_CEILING
        )

    def get_adjusted_threshold(
        self,
        current_threshold: float,
        evaluation: FPEvaluationResult,
    ) -> float:
        """Return raised threshold if targets not met, else current threshold.

        Raises threshold by 0.02 for each violation, capped at 0.99.
        """
        if not self.should_reduce_autonomy(evaluation):
            return current_threshold

        adjustment = 0.0
        if evaluation.precision < PRECISION_TARGET:
            adjustment += 0.02
        if evaluation.fnr > FNR_CEILING:
            adjustment += 0.02
        return min(current_threshold + adjustment, 0.99)
