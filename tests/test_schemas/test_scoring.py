"""Tests for IncidentScore and score_incident — AC-1.1.7."""

import math

from shared.schemas.scoring import (
    ALPHA,
    BETA,
    DELTA,
    GAMMA,
    LAMBDA,
    IncidentScore,
    score_incident,
)


class TestDecayCalculation:
    """AC-1.1.7: 30-day decay is approximately 0.5."""

    def test_decay_at_30_days(self):
        result = score_incident(
            vector_similarity=1.0,
            age_days=30,
            same_tenant=True,
            technique_overlap=1.0,
        )
        assert abs(result.recency_decay - 0.5) < 0.01

    def test_decay_at_0_days_is_one(self):
        result = score_incident(
            vector_similarity=1.0,
            age_days=0,
            same_tenant=True,
            technique_overlap=1.0,
        )
        assert result.recency_decay == 1.0

    def test_decay_at_60_days_is_quarter(self):
        result = score_incident(
            vector_similarity=1.0,
            age_days=60,
            same_tenant=True,
            technique_overlap=1.0,
        )
        expected = math.exp(-LAMBDA * 60)
        assert abs(result.recency_decay - expected) < 0.001


class TestCompositeScore:
    """AC-1.1.7: Composite formula is correct."""

    def test_composite_30day_all_ones(self):
        result = score_incident(
            vector_similarity=1.0,
            age_days=30,
            same_tenant=True,
            technique_overlap=1.0,
        )
        expected = (
            ALPHA * 1.0
            + BETA * result.recency_decay
            + GAMMA * 1.0
            + DELTA * 1.0
        )
        assert abs(result.composite - expected) < 0.001

    def test_same_tenant_boosts_score(self):
        with_tenant = score_incident(
            vector_similarity=0.8,
            age_days=10,
            same_tenant=True,
            technique_overlap=0.5,
        )
        without_tenant = score_incident(
            vector_similarity=0.8,
            age_days=10,
            same_tenant=False,
            technique_overlap=0.5,
        )
        assert with_tenant.composite > without_tenant.composite
        assert abs(with_tenant.composite - without_tenant.composite - GAMMA) < 0.001

    def test_zero_inputs_produce_zero_composite(self):
        result = score_incident(
            vector_similarity=0.0,
            age_days=0,
            same_tenant=False,
            technique_overlap=0.0,
        )
        # Only BETA * 1.0 (decay at 0 days = 1.0)
        assert abs(result.composite - BETA) < 0.001


class TestIncidentScoreModel:
    def test_model_fields(self):
        score = IncidentScore(
            vector_similarity=0.9,
            recency_decay=0.5,
            tenant_match=1.0,
            technique_overlap=0.7,
            composite=0.85,
        )
        assert score.vector_similarity == 0.9
        assert score.composite == 0.85

    def test_default_composite_is_zero(self):
        score = IncidentScore(
            vector_similarity=0.9,
            recency_decay=0.5,
            tenant_match=1.0,
            technique_overlap=0.7,
        )
        assert score.composite == 0.0


class TestConstants:
    def test_weights_sum_to_one(self):
        assert abs(ALPHA + BETA + GAMMA + DELTA - 1.0) < 0.001

    def test_lambda_produces_half_life_at_30_days(self):
        assert abs(math.exp(-LAMBDA * 30) - 0.5) < 0.01
