"""Risk classification models — never conflate absent data with 'safe'."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class RiskState(str, Enum):
    """Explicit risk states. NO_BASELINE means data is absent, not low."""

    NO_BASELINE = "no_baseline"
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskSignal(BaseModel):
    """A single risk signal from UEBA, IAM, endpoint, or CTEM."""

    entity_id: str
    signal_type: str
    risk_state: RiskState
    risk_score: Optional[float] = None
    data_freshness_hours: float
    source: str


def classify_risk(
    investigation_priority: Optional[int],
    data_freshness_hours: float,
    max_stale_hours: float = 24.0,
    entity_id: str = "",
    source: str = "",
) -> RiskSignal:
    """Classify risk from UEBA or equivalent signal.

    Key rule: absent data is NO_BASELINE, not LOW.
    """
    if investigation_priority is None:
        return RiskSignal(
            entity_id=entity_id,
            signal_type="ueba",
            risk_state=RiskState.NO_BASELINE,
            risk_score=None,
            data_freshness_hours=data_freshness_hours,
            source=source,
        )

    if data_freshness_hours > max_stale_hours:
        return RiskSignal(
            entity_id=entity_id,
            signal_type="ueba",
            risk_state=RiskState.UNKNOWN,
            risk_score=float(investigation_priority),
            data_freshness_hours=data_freshness_hours,
            source=source,
        )

    if investigation_priority < 3:
        state = RiskState.LOW
    elif investigation_priority < 6:
        state = RiskState.MEDIUM
    else:
        state = RiskState.HIGH

    return RiskSignal(
        entity_id=entity_id,
        signal_type="ueba",
        risk_state=state,
        risk_score=float(investigation_priority),
        data_freshness_hours=data_freshness_hours,
        source=source,
    )
