"""Tests for AuditProducer integration in ATLAS Detection — Story 13.8, Task 6.2."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from atlas_detection.runner import DetectionRunner
from atlas_detection.models import DetectionResult, DetectionRule


class TestATLASDetectionAudit:
    """atlas.detection_fired emitted when detection rule triggers."""

    @pytest.mark.asyncio
    async def test_detection_fired_emitted(self):
        """When a detection triggers, atlas.detection_fired is emitted."""
        audit = MagicMock()
        db = AsyncMock()
        producer = AsyncMock()
        producer.produce = AsyncMock()

        rule = MagicMock(spec=DetectionRule)
        rule.rule_id = "ATLAS-001"
        result = DetectionResult(
            rule_id="ATLAS-001",
            triggered=True,
            alert_title="Model Poisoning Detected",
            alert_severity="high",
            confidence=0.95,
            evidence={"detail": "test"},
            timestamp="2026-02-24T00:00:00Z",
        )
        rule.evaluate = AsyncMock(return_value=[result])

        runner = DetectionRunner(
            rules=[rule], db=db, kafka_producer=producer, audit_producer=audit,
        )
        results = await runner.run_rule(rule)

        fired_calls = [c for c in audit.emit.call_args_list
                       if c[1].get("event_type") == "atlas.detection_fired"]
        assert len(fired_calls) == 1
        assert fired_calls[0][1]["context"]["rule_id"] == "ATLAS-001"

    @pytest.mark.asyncio
    async def test_no_event_when_not_triggered(self):
        """No audit event when detection doesn't trigger."""
        audit = MagicMock()
        rule = MagicMock(spec=DetectionRule)
        rule.rule_id = "ATLAS-002"
        result = DetectionResult(
            rule_id="ATLAS-002",
            triggered=False,
            alert_title="",
            alert_severity="info",
            confidence=0.0,
            evidence={},
            timestamp="2026-02-24T00:00:00Z",
        )
        rule.evaluate = AsyncMock(return_value=[result])

        runner = DetectionRunner(
            rules=[rule], db=AsyncMock(), audit_producer=audit,
        )
        await runner.run_rule(rule)

        fired_calls = [c for c in audit.emit.call_args_list
                       if c[1].get("event_type") == "atlas.detection_fired"]
        assert len(fired_calls) == 0

    @pytest.mark.asyncio
    async def test_no_exception_when_audit_producer_is_none(self):
        """Backward compat: works without audit_producer."""
        rule = MagicMock(spec=DetectionRule)
        rule.rule_id = "ATLAS-003"
        rule.evaluate = AsyncMock(return_value=[])

        runner = DetectionRunner(rules=[rule], db=AsyncMock())
        results = await runner.run_all()
        assert "ATLAS-003" in results
