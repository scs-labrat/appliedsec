"""Tests for EvaluationFeedbackLoop — REM-H02."""

import pytest
from unittest.mock import MagicMock

from orchestrator.fp_evaluation import (
    AutonomyGuard,
    EvaluationFeedbackLoop,
    FPEvaluationResult,
    PRECISION_TARGET,
    FNR_CEILING,
)
from orchestrator.drift_detection import ThresholdAdjuster


class TestEvaluationFeedbackLoop:
    @pytest.fixture
    def adjuster(self):
        return ThresholdAdjuster(normal_threshold=0.90, elevated_threshold=0.95)

    @pytest.fixture
    def guard(self):
        return AutonomyGuard()

    @pytest.fixture
    def loop(self, guard, adjuster):
        return EvaluationFeedbackLoop(guard, adjuster)

    def test_no_adjustment_when_targets_met(self, loop, adjuster):
        evaluation = FPEvaluationResult(
            rule_family="test",
            true_positives=100,
            false_positives=1,
            false_negatives=0,
        )
        evaluation.compute_metrics()
        assert evaluation.precision >= PRECISION_TARGET

        result = loop.on_evaluation_complete(evaluation)
        assert result == 0.90  # unchanged
        assert len(loop.adjustment_history) == 0

    def test_raises_threshold_on_low_precision(self, loop, adjuster):
        evaluation = FPEvaluationResult(
            rule_family="noisy_rule",
            true_positives=90,
            false_positives=10,
            false_negatives=0,
        )
        evaluation.compute_metrics()
        assert evaluation.precision < PRECISION_TARGET

        result = loop.on_evaluation_complete(evaluation)
        assert result == 0.92  # +0.02
        assert len(loop.adjustment_history) == 1
        assert loop.adjustment_history[0]["rule_family"] == "noisy_rule"

    def test_raises_threshold_on_high_fnr(self, loop, adjuster):
        evaluation = FPEvaluationResult(
            rule_family="leaky_rule",
            true_positives=90,
            false_positives=0,
            false_negatives=5,
        )
        evaluation.compute_metrics()
        assert evaluation.fnr > FNR_CEILING

        result = loop.on_evaluation_complete(evaluation)
        assert result == 0.92  # +0.02

    def test_double_violation_raises_by_004(self, loop, adjuster):
        evaluation = FPEvaluationResult(
            rule_family="bad_rule",
            true_positives=80,
            false_positives=15,
            false_negatives=5,
        )
        evaluation.compute_metrics()

        result = loop.on_evaluation_complete(evaluation)
        assert result == pytest.approx(0.94)  # +0.04 (two violations)

    def test_threshold_persists_for_fp_shortcircuit(self, loop, adjuster):
        """After adjustment, ThresholdAdjuster.get_threshold() returns new value."""
        evaluation = FPEvaluationResult(
            rule_family="test",
            true_positives=90,
            false_positives=10,
        )
        evaluation.compute_metrics()

        loop.on_evaluation_complete(evaluation)
        # The adjuster that FPShortCircuit uses should reflect the new threshold
        assert adjuster.get_threshold() == 0.92

    def test_successive_adjustments_accumulate(self, loop, adjuster):
        for _ in range(3):
            evaluation = FPEvaluationResult(
                rule_family="degrading",
                true_positives=90,
                false_positives=10,
            )
            evaluation.compute_metrics()
            loop.on_evaluation_complete(evaluation)

        # 0.90 + 0.02 + 0.02 + 0.02 = 0.96
        assert adjuster.get_threshold() == pytest.approx(0.96)

    def test_capped_at_099(self, loop, adjuster):
        for _ in range(10):
            evaluation = FPEvaluationResult(
                rule_family="terrible",
                true_positives=50,
                false_positives=50,
                false_negatives=10,
            )
            evaluation.compute_metrics()
            loop.on_evaluation_complete(evaluation)

        assert adjuster.get_threshold() <= 0.99
