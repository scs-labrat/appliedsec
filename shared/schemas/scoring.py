"""Incident similarity scoring with time-decayed composite formula."""

from __future__ import annotations

import math

from pydantic import BaseModel

# Weights (tune based on operational feedback)
ALPHA = 0.4   # vector similarity
BETA = 0.3    # recency
GAMMA = 0.15  # tenant match
DELTA = 0.15  # technique overlap

# Decay constant: exp(-0.023 * 30) ~ 0.5, so ~30 day half-life
LAMBDA = 0.023


class IncidentScore(BaseModel):
    """Composite score for ranking past incidents by relevance."""

    vector_similarity: float
    recency_decay: float
    tenant_match: float
    technique_overlap: float
    composite: float = 0.0


def score_incident(
    vector_similarity: float,
    age_days: float,
    same_tenant: bool,
    technique_overlap: float,
) -> IncidentScore:
    """Compute composite relevance score for a past incident.

    score = ALPHA * vector_similarity
          + BETA  * recency_decay
          + GAMMA * tenant_match
          + DELTA * technique_overlap

    recency_decay = exp(-LAMBDA * age_days)
    """
    recency_decay = math.exp(-LAMBDA * age_days)
    tenant_match = 1.0 if same_tenant else 0.0

    composite = (
        ALPHA * vector_similarity
        + BETA * recency_decay
        + GAMMA * tenant_match
        + DELTA * technique_overlap
    )

    return IncidentScore(
        vector_similarity=vector_similarity,
        recency_decay=recency_decay,
        tenant_match=tenant_match,
        technique_overlap=technique_overlap,
        composite=composite,
    )
