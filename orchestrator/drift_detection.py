"""Concept drift detection — Story 14.5.

Monitors distribution shifts in alert source mix, technique frequency,
and entity patterns.  When drift exceeds threshold, auto-close confidence
threshold is raised from 0.90 to 0.95 (fewer auto-closes, more human review).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

NORMAL_THRESHOLD = 0.90
ELEVATED_THRESHOLD = 0.95
DEFAULT_DRIFT_THRESHOLD = 0.3

# Dimension weights for overall drift
SOURCE_WEIGHT = 0.4
TECHNIQUE_WEIGHT = 0.35
ENTITY_WEIGHT = 0.25


@dataclass
class DriftState:
    """Current state of concept drift across three dimensions."""

    source_drift: float = 0.0
    technique_drift: float = 0.0
    entity_drift: float = 0.0
    overall_drift: float = 0.0
    threshold_exceeded: bool = False
    detected_at: str = ""


class DriftDetector:
    """Detects distribution shifts across three dimensions.

    Uses Jensen-Shannon divergence to measure distributional distance
    between a current window and a baseline period.
    """

    def __init__(
        self,
        window_days: int = 7,
        baseline_days: int = 30,
        drift_threshold: float = DEFAULT_DRIFT_THRESHOLD,
    ) -> None:
        self._window_days = window_days
        self._baseline_days = baseline_days
        self._drift_threshold = drift_threshold

    def compute_source_drift(
        self,
        current_distribution: dict[str, int],
        baseline_distribution: dict[str, int],
    ) -> float:
        """Compute Jensen-Shannon divergence for alert source distributions."""
        return self._js_divergence(current_distribution, baseline_distribution)

    def compute_technique_drift(
        self,
        current_frequencies: dict[str, int],
        baseline_frequencies: dict[str, int],
    ) -> float:
        """Compute distribution shift in technique frequency."""
        return self._js_divergence(current_frequencies, baseline_frequencies)

    def compute_entity_drift(
        self,
        current_patterns: dict[str, int],
        baseline_patterns: dict[str, int],
    ) -> float:
        """Compute shift in entity type distribution."""
        return self._js_divergence(current_patterns, baseline_patterns)

    def compute_overall_drift(
        self,
        source: float,
        technique: float,
        entity: float,
    ) -> float:
        """Weighted average of three drift dimensions."""
        return (
            SOURCE_WEIGHT * source
            + TECHNIQUE_WEIGHT * technique
            + ENTITY_WEIGHT * entity
        )

    def detect(
        self,
        current_sources: dict[str, int],
        baseline_sources: dict[str, int],
        current_techniques: dict[str, int],
        baseline_techniques: dict[str, int],
        current_entities: dict[str, int],
        baseline_entities: dict[str, int],
    ) -> DriftState:
        """Run full drift detection across all three dimensions."""
        source = self.compute_source_drift(current_sources, baseline_sources)
        technique = self.compute_technique_drift(current_techniques, baseline_techniques)
        entity = self.compute_entity_drift(current_entities, baseline_entities)
        overall = self.compute_overall_drift(source, technique, entity)

        return DriftState(
            source_drift=source,
            technique_drift=technique,
            entity_drift=entity,
            overall_drift=overall,
            threshold_exceeded=overall > self._drift_threshold,
            detected_at=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def _js_divergence(
        dist_a: dict[str, int],
        dist_b: dict[str, int],
    ) -> float:
        """Compute Jensen-Shannon divergence between two count distributions.

        Returns a value between 0.0 (identical) and 1.0 (maximally different).
        """
        all_keys = set(dist_a.keys()) | set(dist_b.keys())
        if not all_keys:
            return 0.0

        total_a = sum(dist_a.values()) or 1
        total_b = sum(dist_b.values()) or 1

        # Normalize to probability distributions
        p = {k: dist_a.get(k, 0) / total_a for k in all_keys}
        q = {k: dist_b.get(k, 0) / total_b for k in all_keys}

        # Midpoint distribution
        m = {k: (p[k] + q[k]) / 2 for k in all_keys}

        # JSD = 0.5 * KL(P||M) + 0.5 * KL(Q||M)
        kl_pm = sum(
            p[k] * math.log2(p[k] / m[k])
            for k in all_keys
            if p[k] > 0 and m[k] > 0
        )
        kl_qm = sum(
            q[k] * math.log2(q[k] / m[k])
            for k in all_keys
            if q[k] > 0 and m[k] > 0
        )

        jsd = 0.5 * kl_pm + 0.5 * kl_qm
        # JSD is bounded [0, 1] for log base 2
        return min(max(jsd, 0.0), 1.0)


class ThresholdAdjuster:
    """Adjusts FP confidence threshold based on drift state.

    When drift is detected (threshold_exceeded), raises confidence
    threshold from normal (0.90) to elevated (0.95).
    Returns to normal when drift subsides.
    """

    def __init__(
        self,
        normal_threshold: float = NORMAL_THRESHOLD,
        elevated_threshold: float = ELEVATED_THRESHOLD,
    ) -> None:
        self._normal = normal_threshold
        self._elevated = elevated_threshold
        self._current_drift: DriftState | None = None

    def update(self, drift_state: DriftState) -> None:
        """Update internal state with latest drift detection result."""
        self._current_drift = drift_state

    def get_threshold(self, drift_state: DriftState | None = None) -> float:
        """Return the effective confidence threshold.

        Uses provided drift_state or the last state passed to update().
        """
        state = drift_state or self._current_drift
        if state is not None and state.threshold_exceeded:
            return self._elevated
        return self._normal

    def is_elevated(self) -> bool:
        """Return True if threshold is currently elevated."""
        if self._current_drift is not None:
            return self._current_drift.threshold_exceeded
        return False


class DriftSamplingCallback:
    """Signals FPEvaluationFramework to increase sampling when drift detected.

    Implements AC-2: drift detection triggers increased sampling rate
    for affected rule families.
    """

    def __init__(self, default_sample_multiplier: float = 1.0) -> None:
        self._multiplier = default_sample_multiplier
        self._elevated_families: set[str] = set()

    def on_drift_detected(self, rule_families: list[str]) -> None:
        """Increase sampling rate for affected rule families."""
        self._elevated_families.update(rule_families)
        self._multiplier = 2.0

    def on_drift_restored(self) -> None:
        """Restore default sampling rate when drift subsides."""
        self._elevated_families.clear()
        self._multiplier = 1.0

    def get_sample_multiplier(self, rule_family: str = "") -> float:
        """Return current sampling multiplier.

        Returns elevated multiplier if rule_family is in affected set,
        or if no specific family is queried and any family is elevated.
        """
        if not self._elevated_families:
            return 1.0
        if rule_family and rule_family not in self._elevated_families:
            return 1.0
        return self._multiplier

    @property
    def elevated_families(self) -> set[str]:
        """Return the set of rule families with elevated sampling."""
        return set(self._elevated_families)
