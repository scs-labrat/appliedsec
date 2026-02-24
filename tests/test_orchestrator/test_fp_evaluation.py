"""Tests for FP evaluation framework — Story 14.2."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from orchestrator.fp_evaluation import (
    FNR_CEILING,
    PRECISION_TARGET,
    RECALL_TARGET,
    AutonomyGuard,
    DailyFNDetector,
    FPEvaluationFramework,
    FPEvaluationResult,
    StratumConfig,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_closure(
    rule_family: str = "brute_force",
    severity: str = "HIGH",
    asset_criticality: str = "high",
    alert_id: str = "alert-001",
    pattern_id: str = "pat-001",
    pattern_created_at: str = "",
) -> dict:
    return {
        "alert_id": alert_id,
        "rule_family": rule_family,
        "severity": severity,
        "asset_criticality": asset_criticality,
        "pattern_id": pattern_id,
        "pattern_created_at": pattern_created_at,
    }


def _recent_date(days_ago: int = 5) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.isoformat()


def _old_date(days_ago: int = 60) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# TestFPEvaluationModels (Task 1)
# ---------------------------------------------------------------------------

class TestFPEvaluationModels:
    """AC-1,4: Precision/recall computed correctly, targets defined."""

    def test_precision_computed_correctly(self):
        result = FPEvaluationResult(
            rule_family="brute_force",
            total_closures=100,
            true_positives=98,
            false_positives=2,
            false_negatives=1,
        )
        result.compute_metrics()
        assert result.precision == pytest.approx(0.98)

    def test_recall_computed_correctly(self):
        result = FPEvaluationResult(
            rule_family="brute_force",
            true_positives=95,
            false_positives=2,
            false_negatives=5,
        )
        result.compute_metrics()
        assert result.recall == pytest.approx(0.95)

    def test_fnr_computed_correctly(self):
        result = FPEvaluationResult(
            rule_family="brute_force",
            true_positives=199,
            false_positives=0,
            false_negatives=1,
        )
        result.compute_metrics()
        assert result.fnr == pytest.approx(0.005)

    def test_target_constants_defined(self):
        assert PRECISION_TARGET == 0.98
        assert RECALL_TARGET == 0.95
        assert FNR_CEILING == 0.005

    def test_zero_denominator_precision(self):
        """Zero predictions → precision defaults to 1.0."""
        result = FPEvaluationResult(rule_family="empty")
        result.compute_metrics()
        assert result.precision == 1.0
        assert result.recall == 1.0
        assert result.fnr == 0.0

    def test_stratum_config_defaults(self):
        s = StratumConfig(rule_family="test", severity="HIGH", asset_criticality="high")
        assert s.min_sample_size == 30


# ---------------------------------------------------------------------------
# TestStratifiedSampling (Task 2)
# ---------------------------------------------------------------------------

class TestStratifiedSampling:
    """AC-1,2: Strata grouped, min 30 per stratum, novel 100% review."""

    def test_strata_grouped_correctly(self):
        """Closures grouped by (rule_family:severity:asset_criticality)."""
        fw = FPEvaluationFramework()
        closures = [
            _make_closure("brute_force", "HIGH", "high"),
            _make_closure("brute_force", "HIGH", "high"),
            _make_closure("impossible_travel", "MEDIUM", "low"),
        ]
        strata = fw.compute_strata(closures)
        assert len(strata) == 2
        assert len(strata["brute_force:HIGH:high"]) == 2
        assert len(strata["impossible_travel:MEDIUM:low"]) == 1

    def test_sample_min_30_per_stratum(self):
        """Sample selects at least 30 per stratum (when available)."""
        fw = FPEvaluationFramework()
        closures = [
            _make_closure("bf", "HIGH", "high", alert_id=f"a-{i}",
                          pattern_created_at=_old_date())
            for i in range(50)
        ]
        strata = fw.compute_strata(closures)
        sample = fw.select_sample(strata, min_per_stratum=30)
        assert len(sample) >= 30

    def test_novel_patterns_100_percent_review(self):
        """Novel patterns (< 30 days) get 100% of closures reviewed."""
        fw = FPEvaluationFramework()
        novel_closures = [
            _make_closure("bf", "HIGH", "high", alert_id=f"novel-{i}",
                          pattern_id="new-pat", pattern_created_at=_recent_date(5))
            for i in range(10)
        ]
        strata = fw.compute_strata(novel_closures)
        sample = fw.select_sample(strata, min_per_stratum=30)
        # All 10 novel closures should be in sample
        assert len(sample) == 10

    def test_is_novel_pattern_true(self):
        fw = FPEvaluationFramework()
        assert fw.is_novel_pattern("p1", _recent_date(5)) is True

    def test_is_novel_pattern_false(self):
        fw = FPEvaluationFramework()
        assert fw.is_novel_pattern("p1", _old_date(60)) is False

    def test_is_novel_pattern_empty_date(self):
        fw = FPEvaluationFramework()
        assert fw.is_novel_pattern("p1", "") is False

    def test_empty_strata_handled(self):
        """Empty strata produce empty sample."""
        fw = FPEvaluationFramework()
        sample = fw.select_sample({}, min_per_stratum=30)
        assert sample == []

    def test_stratum_with_fewer_than_min(self):
        """Stratum with < 30 closures returns all available."""
        fw = FPEvaluationFramework()
        closures = [
            _make_closure("bf", "HIGH", "high", alert_id=f"a-{i}",
                          pattern_created_at=_old_date())
            for i in range(10)
        ]
        strata = fw.compute_strata(closures)
        sample = fw.select_sample(strata, min_per_stratum=30)
        assert len(sample) == 10


# ---------------------------------------------------------------------------
# TestDailyFNDetector (Task 3)
# ---------------------------------------------------------------------------

class TestDailyFNDetector:
    """AC-3: Auto-closed alerts later escalated are flagged."""

    def test_escalated_closure_flagged(self):
        """Alert auto-closed then escalated is flagged as potential FN."""
        detector = DailyFNDetector()
        closures = [_make_closure(alert_id="alert-100")]
        escalations = [{"alert_id": "alert-100", "source": "external"}]

        flagged = detector.check_auto_closed_escalated(closures, escalations)
        assert len(flagged) == 1
        assert flagged[0]["fn_flagged"] is True
        assert flagged[0]["review_status"] == "pending_review"

    def test_non_escalated_not_flagged(self):
        """Alert auto-closed but NOT escalated is not flagged."""
        detector = DailyFNDetector()
        closures = [_make_closure(alert_id="alert-200")]
        escalations = [{"alert_id": "alert-999", "source": "external"}]

        flagged = detector.check_auto_closed_escalated(closures, escalations)
        assert len(flagged) == 0

    def test_multiple_escalations(self):
        """Multiple escalated closures are all flagged."""
        detector = DailyFNDetector()
        closures = [
            _make_closure(alert_id="a-1"),
            _make_closure(alert_id="a-2"),
            _make_closure(alert_id="a-3"),
        ]
        escalations = [
            {"alert_id": "a-1"},
            {"alert_id": "a-3"},
        ]
        flagged = detector.check_auto_closed_escalated(closures, escalations)
        assert len(flagged) == 2

    def test_flag_adds_timestamp(self):
        """Flagged closure includes fn_flagged_at timestamp."""
        detector = DailyFNDetector()
        flagged = detector.flag_potential_false_negative({"alert_id": "a-1"})
        assert "fn_flagged_at" in flagged


# ---------------------------------------------------------------------------
# TestAutonomyGuard (Task 3)
# ---------------------------------------------------------------------------

class TestAutonomyGuard:
    """AC-5: Autonomy adjusts when targets not met."""

    def test_targets_met_no_reduction(self):
        """When precision and FNR targets are met, no reduction."""
        guard = AutonomyGuard()
        result = FPEvaluationResult(
            rule_family="test",
            true_positives=99,
            false_positives=1,
            false_negatives=0,
        )
        result.compute_metrics()
        assert guard.should_reduce_autonomy(result) is False

    def test_precision_below_target_reduces(self):
        """Precision < 98% → should reduce autonomy."""
        guard = AutonomyGuard()
        result = FPEvaluationResult(
            rule_family="test",
            true_positives=90,
            false_positives=10,
            false_negatives=0,
        )
        result.compute_metrics()
        assert result.precision < PRECISION_TARGET
        assert guard.should_reduce_autonomy(result) is True

    def test_fnr_above_ceiling_reduces(self):
        """FNR > 0.5% → should reduce autonomy."""
        guard = AutonomyGuard()
        result = FPEvaluationResult(
            rule_family="test",
            true_positives=95,
            false_positives=0,
            false_negatives=5,
        )
        result.compute_metrics()
        assert result.fnr > FNR_CEILING
        assert guard.should_reduce_autonomy(result) is True

    def test_threshold_raised_when_targets_not_met(self):
        """Threshold is raised by 0.02-0.04 when targets not met."""
        guard = AutonomyGuard()
        result = FPEvaluationResult(
            rule_family="test",
            true_positives=90,
            false_positives=10,
            false_negatives=0,
        )
        result.compute_metrics()
        new_threshold = guard.get_adjusted_threshold(0.90, result)
        assert new_threshold > 0.90

    def test_threshold_unchanged_when_targets_met(self):
        """Threshold stays same when targets are met."""
        guard = AutonomyGuard()
        result = FPEvaluationResult(
            rule_family="test",
            true_positives=99,
            false_positives=1,
            false_negatives=0,
        )
        result.compute_metrics()
        new_threshold = guard.get_adjusted_threshold(0.90, result)
        assert new_threshold == 0.90

    def test_threshold_capped_at_099(self):
        """Threshold cannot exceed 0.99."""
        guard = AutonomyGuard()
        result = FPEvaluationResult(
            rule_family="test",
            true_positives=80,
            false_positives=10,
            false_negatives=10,
        )
        result.compute_metrics()
        new_threshold = guard.get_adjusted_threshold(0.98, result)
        assert new_threshold <= 0.99


# ---------------------------------------------------------------------------
# TestFPMetrics (Task 4)
# ---------------------------------------------------------------------------

class TestFPMetrics:
    """AC-4: Prometheus metrics defined with correct labels."""

    def test_fp_metrics_defined(self):
        from ops.metrics import FP_EVALUATION_METRICS
        names = {m.name for m in FP_EVALUATION_METRICS}
        assert "aluskort_fp_precision" in names
        assert "aluskort_fp_recall" in names
        assert "aluskort_fp_false_negative_rate" in names
        assert "aluskort_fp_evaluation_sample_size" in names

    def test_fp_metrics_labels(self):
        from ops.metrics import FP_EVALUATION_METRICS, MetricType
        for m in FP_EVALUATION_METRICS:
            assert m.metric_type == MetricType.GAUGE
            assert "rule_family" in m.labels

    def test_fp_metrics_in_all_metrics(self):
        from ops.metrics import ALL_METRICS
        names = {m.name for m in ALL_METRICS}
        assert "aluskort_fp_precision" in names
