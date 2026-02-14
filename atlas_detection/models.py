"""ATLAS detection data models — Story 9.1.

DetectionRule ABC and DetectionResult dataclass.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass
class DetectionResult:
    """Output of a triggered detection rule."""

    rule_id: str
    triggered: bool
    alert_title: str = ""
    alert_severity: str = "Medium"
    atlas_technique: str = ""
    attack_technique: str = ""
    threat_model_ref: str = ""
    confidence: float = 0.0
    evidence: dict[str, Any] = field(default_factory=dict)
    entities: list[dict[str, Any]] = field(default_factory=list)
    requires_immediate_action: bool = False
    safety_relevant: bool = False
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# Safety confidence floors — cannot be lowered below these
SAFETY_CONFIDENCE_FLOORS: dict[str, float] = {
    "ATLAS-DETECT-005": 0.7,   # Physics oracle DoS
    "ATLAS-DETECT-009": 0.7,   # Sensor spoofing
}

# Rules whose alerts cannot be classified as false_positive by the LLM
SAFETY_RELEVANT_RULES: frozenset[str] = frozenset({
    "ATLAS-DETECT-004",  # Adversarial evasion
    "ATLAS-DETECT-005",  # Physics oracle DoS
    "ATLAS-DETECT-009",  # Sensor spoofing
})


class DetectionRule(ABC):
    """Abstract base class for all ATLAS detection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier, e.g. 'ATLAS-DETECT-001'."""
        ...

    @property
    @abstractmethod
    def frequency(self) -> timedelta:
        """How often this rule should execute."""
        ...

    @property
    @abstractmethod
    def lookback(self) -> timedelta:
        """How far back to query telemetry data."""
        ...

    @property
    def is_safety_relevant(self) -> bool:
        """Whether alerts from this rule cannot be dismissed as FP."""
        return self.rule_id in SAFETY_RELEVANT_RULES

    @abstractmethod
    async def evaluate(
        self,
        db: Any,
        now: datetime | None = None,
    ) -> list[DetectionResult]:
        """Execute the rule and return any triggered detections."""
        ...

    def _apply_confidence_floor(self, confidence: float) -> float:
        """Enforce safety confidence floors."""
        floor = SAFETY_CONFIDENCE_FLOORS.get(self.rule_id, 0.0)
        return max(confidence, floor)
