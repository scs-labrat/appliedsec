"""Detection runner — Story 9.4.

Executes detection rules at configured frequencies and publishes
triggered detections as CanonicalAlerts to ``alerts.raw``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from atlas_detection.models import DetectionResult, DetectionRule, SAFETY_RELEVANT_RULES
from shared.schemas.alert import CanonicalAlert

logger = logging.getLogger(__name__)

ALERT_TOPIC = "alerts.raw"


def detection_to_alert(result: DetectionResult) -> CanonicalAlert:
    """Convert a DetectionResult to a CanonicalAlert for the pipeline."""
    techniques = []
    if result.atlas_technique:
        techniques.append(result.atlas_technique)
    if result.attack_technique:
        techniques.append(result.attack_technique)

    raw_payload: dict[str, Any] = {
        "rule_id": result.rule_id,
        "confidence": result.confidence,
        "evidence": result.evidence,
        "threat_model_ref": result.threat_model_ref,
        "requires_immediate_action": result.requires_immediate_action,
        "safety_relevant": result.safety_relevant,
    }

    return CanonicalAlert(
        alert_id=f"{result.rule_id}-{result.timestamp}",
        source="atlas",
        timestamp=result.timestamp,
        title=result.alert_title,
        description=f"ATLAS detection: {result.alert_title}",
        severity=result.alert_severity.lower(),
        techniques=techniques,
        raw_payload=raw_payload,
    )


class DetectionRunner:
    """Executes detection rules and publishes alerts."""

    def __init__(
        self,
        rules: list[DetectionRule],
        db: Any,
        kafka_producer: Any | None = None,
        audit_producer: Any | None = None,
    ) -> None:
        self._rules = rules
        self._db = db
        self._producer = kafka_producer
        self._audit = audit_producer

    @property
    def rules(self) -> list[DetectionRule]:
        return list(self._rules)

    async def run_rule(self, rule: DetectionRule) -> list[DetectionResult]:
        """Execute a single rule and publish any triggered results."""
        try:
            results = await rule.evaluate(self._db)
        except Exception as exc:
            logger.error(
                "Rule %s failed: %s", rule.rule_id, exc, exc_info=True,
            )
            return []

        for result in results:
            if result.triggered:
                # Mark safety-relevant
                if rule.rule_id in SAFETY_RELEVANT_RULES:
                    result.safety_relevant = True

                alert = detection_to_alert(result)
                await self._publish(alert)
                self._emit_detection_fired(result)

        return results

    async def run_all(self) -> dict[str, list[DetectionResult]]:
        """Execute all rules and return results keyed by rule_id."""
        all_results: dict[str, list[DetectionResult]] = {}
        for rule in self._rules:
            results = await self.run_rule(rule)
            all_results[rule.rule_id] = results
        return all_results

    def _emit_detection_fired(self, result: DetectionResult) -> None:
        """Emit atlas.detection_fired audit event."""
        if self._audit is None:
            return
        try:
            self._audit.emit(
                tenant_id="system",
                event_type="atlas.detection_fired",
                event_category="decision",
                actor_type="system",
                actor_id="atlas-detection",
                context={
                    "rule_id": result.rule_id,
                    "alert_title": result.alert_title,
                    "confidence": result.confidence,
                },
            )
        except Exception:
            logger.warning("Audit emit failed for atlas.detection_fired", exc_info=True)

    async def _publish(self, alert: CanonicalAlert) -> None:
        """Publish alert to Kafka alerts.raw topic."""
        if self._producer is None:
            return
        try:
            await self._producer.produce(
                ALERT_TOPIC, alert.model_dump(),
            )
            logger.info("Published ATLAS alert: %s", alert.alert_id)
        except Exception:
            logger.warning(
                "Failed to publish alert %s", alert.alert_id,
                exc_info=True,
            )
