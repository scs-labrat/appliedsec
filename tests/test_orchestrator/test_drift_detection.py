"""Tests for concept drift detection — Story 14.5."""

from __future__ import annotations

import pytest

from orchestrator.drift_detection import (
    DEFAULT_DRIFT_THRESHOLD,
    DriftDetector,
    DriftSamplingCallback,
    DriftState,
    ELEVATED_THRESHOLD,
    NORMAL_THRESHOLD,
    ThresholdAdjuster,
)


# ---------------------------------------------------------------------------
# TestDriftDetector (Task 1)
# ---------------------------------------------------------------------------

class TestDriftDetector:
    """AC-1,3: Distribution drift detection across three dimensions."""

    def test_identical_distributions_zero_drift(self):
        """Identical distributions produce 0 drift."""
        dd = DriftDetector()
        dist = {"sentinel": 100, "crowdstrike": 50}
        assert dd.compute_source_drift(dist, dist) == pytest.approx(0.0)

    def test_completely_different_distributions_high_drift(self):
        """Completely different distributions produce high drift."""
        dd = DriftDetector()
        current = {"sentinel": 100}
        baseline = {"crowdstrike": 100}
        drift = dd.compute_source_drift(current, baseline)
        assert drift > 0.5  # JSD for non-overlapping = 1.0

    def test_partial_shift_medium_drift(self):
        """Partial shift produces moderate drift."""
        dd = DriftDetector()
        current = {"sentinel": 70, "crowdstrike": 30}
        baseline = {"sentinel": 50, "crowdstrike": 50}
        drift = dd.compute_source_drift(current, baseline)
        assert 0.0 < drift < 0.5

    def test_technique_drift_computes(self):
        """Technique drift is computed correctly."""
        dd = DriftDetector()
        current = {"T1078": 80, "T1059": 20}
        baseline = {"T1078": 50, "T1059": 50}
        drift = dd.compute_technique_drift(current, baseline)
        assert drift > 0.0

    def test_entity_drift_computes(self):
        """Entity drift is computed correctly."""
        dd = DriftDetector()
        current = {"ip": 90, "domain": 10}
        baseline = {"ip": 50, "domain": 50}
        drift = dd.compute_entity_drift(current, baseline)
        assert drift > 0.0

    def test_overall_weighted_correctly(self):
        """Overall drift is weighted average of three dimensions."""
        dd = DriftDetector()
        overall = dd.compute_overall_drift(0.5, 0.3, 0.2)
        expected = 0.4 * 0.5 + 0.35 * 0.3 + 0.25 * 0.2
        assert overall == pytest.approx(expected)

    def test_empty_distributions_zero_drift(self):
        """Empty distributions produce 0 drift."""
        dd = DriftDetector()
        assert dd.compute_source_drift({}, {}) == pytest.approx(0.0)

    def test_detect_returns_drift_state(self):
        """Full detect() returns a DriftState with all fields."""
        dd = DriftDetector(drift_threshold=0.01)
        current = {"sentinel": 100}
        baseline = {"crowdstrike": 100}
        state = dd.detect(
            current, baseline,
            current, baseline,
            current, baseline,
        )
        assert isinstance(state, DriftState)
        assert state.threshold_exceeded is True
        assert state.detected_at != ""

    def test_detect_no_drift_below_threshold(self):
        """detect() with identical distributions → threshold not exceeded."""
        dd = DriftDetector()
        dist = {"sentinel": 100, "crowdstrike": 50}
        state = dd.detect(dist, dist, dist, dist, dist, dist)
        assert state.threshold_exceeded is False
        assert state.overall_drift == pytest.approx(0.0)

    def test_drift_state_dataclass(self):
        """DriftState defaults are sensible."""
        state = DriftState()
        assert state.source_drift == 0.0
        assert state.threshold_exceeded is False
        assert state.detected_at == ""

    def test_default_drift_threshold(self):
        """Default drift threshold is 0.3."""
        assert DEFAULT_DRIFT_THRESHOLD == 0.3


# ---------------------------------------------------------------------------
# TestThresholdAdjuster (Task 2)
# ---------------------------------------------------------------------------

class TestThresholdAdjuster:
    """AC-1,4: Confidence threshold adjusts with drift."""

    def test_drift_exceeded_returns_elevated(self):
        """When drift exceeded, threshold is 0.95."""
        adj = ThresholdAdjuster()
        state = DriftState(threshold_exceeded=True)
        assert adj.get_threshold(state) == ELEVATED_THRESHOLD

    def test_no_drift_returns_normal(self):
        """When no drift, threshold is 0.90."""
        adj = ThresholdAdjuster()
        state = DriftState(threshold_exceeded=False)
        assert adj.get_threshold(state) == NORMAL_THRESHOLD

    def test_transition_back_to_normal(self):
        """Threshold returns to normal when drift subsides."""
        adj = ThresholdAdjuster()

        # Drift detected
        elevated = DriftState(threshold_exceeded=True)
        adj.update(elevated)
        assert adj.is_elevated() is True
        assert adj.get_threshold() == ELEVATED_THRESHOLD

        # Drift subsides
        normal = DriftState(threshold_exceeded=False)
        adj.update(normal)
        assert adj.is_elevated() is False
        assert adj.get_threshold() == NORMAL_THRESHOLD

    def test_no_state_returns_normal(self):
        """With no drift state set, returns normal threshold."""
        adj = ThresholdAdjuster()
        assert adj.get_threshold() == NORMAL_THRESHOLD
        assert adj.is_elevated() is False

    def test_threshold_constants(self):
        """Normal and elevated thresholds are correct."""
        assert NORMAL_THRESHOLD == 0.90
        assert ELEVATED_THRESHOLD == 0.95

    def test_threshold_adjuster_in_fp_shortcircuit(self):
        """FPShortCircuit uses ThresholdAdjuster when provided."""
        from unittest.mock import AsyncMock
        from orchestrator.fp_shortcircuit import FPShortCircuit, FP_CONFIDENCE_THRESHOLD
        from shared.schemas.investigation import GraphState

        adj = ThresholdAdjuster()
        elevated = DriftState(threshold_exceeded=True)
        adj.update(elevated)

        # Pattern with confidence 0.92 — above 0.90 but below 0.95
        redis = AsyncMock()
        redis.list_fp_patterns = AsyncMock(return_value=["fp:pat-1"])
        redis.get_fp_pattern = AsyncMock(return_value={
            "status": "approved",
            "alert_name_regex": ".*Brute.*",
            "entity_patterns": [],
        })

        sc = FPShortCircuit(redis, threshold_adjuster=adj)
        # The _get_effective_threshold should return 0.95
        assert sc._get_effective_threshold() == 0.95

    def test_no_threshold_adjuster_uses_default(self):
        """FPShortCircuit without adjuster uses FP_CONFIDENCE_THRESHOLD."""
        from unittest.mock import AsyncMock
        from orchestrator.fp_shortcircuit import FPShortCircuit, FP_CONFIDENCE_THRESHOLD

        redis = AsyncMock()
        sc = FPShortCircuit(redis)
        assert sc._get_effective_threshold() == FP_CONFIDENCE_THRESHOLD


# ---------------------------------------------------------------------------
# TestDriftMetrics (Task 3)
# ---------------------------------------------------------------------------

class TestDriftMetrics:
    """AC-3: Prometheus drift metrics defined."""

    def test_drift_metrics_defined(self):
        from ops.metrics import DRIFT_DETECTION_METRICS
        names = {m.name for m in DRIFT_DETECTION_METRICS}
        assert "aluskort_fp_drift_score" in names
        assert "aluskort_fp_confidence_threshold" in names

    def test_drift_score_has_labels(self):
        from ops.metrics import DRIFT_DETECTION_METRICS, MetricType
        drift_score = next(
            m for m in DRIFT_DETECTION_METRICS
            if m.name == "aluskort_fp_drift_score"
        )
        assert drift_score.metric_type == MetricType.GAUGE
        assert "rule_family" in drift_score.labels
        assert "dimension" in drift_score.labels

    def test_drift_metrics_in_all_metrics(self):
        from ops.metrics import ALL_METRICS
        names = {m.name for m in ALL_METRICS}
        assert "aluskort_fp_drift_score" in names
        assert "aluskort_fp_confidence_threshold" in names


# ---------------------------------------------------------------------------
# TestDriftIntegration (Task 4)
# ---------------------------------------------------------------------------

class TestDriftIntegration:
    """AC-2: Drift triggers increased sampling rate."""

    def test_drift_triggers_increased_sampling(self):
        """on_drift_detected raises sampling multiplier to 2x."""
        cb = DriftSamplingCallback()
        cb.on_drift_detected(["brute_force", "impossible_travel"])
        assert cb.get_sample_multiplier("brute_force") == 2.0
        assert cb.get_sample_multiplier("impossible_travel") == 2.0

    def test_normal_drift_restores_default_sampling(self):
        """on_drift_restored resets multiplier to 1.0."""
        cb = DriftSamplingCallback()
        cb.on_drift_detected(["brute_force"])
        assert cb.get_sample_multiplier("brute_force") == 2.0

        cb.on_drift_restored()
        assert cb.get_sample_multiplier("brute_force") == 1.0
        assert len(cb.elevated_families) == 0

    def test_unaffected_family_normal_multiplier(self):
        """Rule families not in drift set have normal multiplier."""
        cb = DriftSamplingCallback()
        cb.on_drift_detected(["brute_force"])
        assert cb.get_sample_multiplier("phishing") == 1.0

    def test_no_drift_default_multiplier(self):
        """Default multiplier is 1.0 when no drift."""
        cb = DriftSamplingCallback()
        assert cb.get_sample_multiplier() == 1.0
