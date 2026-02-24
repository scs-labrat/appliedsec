"""Tests for AuditProducer integration in Entity Parser — Story 13.8, Task 1."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from entity_parser.service import EntityParserService


class TestEntityParserAudit:
    """AC-1: alert.classified and injection.detected events emitted."""

    def _make_service(self, audit_producer=None):
        """Create EntityParserService with mocked Kafka and optional AuditProducer."""
        with patch("entity_parser.service.Consumer"), \
             patch("entity_parser.service.Producer"):
            svc = EntityParserService("localhost:9092")
            svc.audit_producer = audit_producer
            return svc

    def test_alert_classified_emitted_on_process(self):
        """After successful entity extraction, alert.classified is emitted."""
        audit = MagicMock()
        svc = self._make_service(audit_producer=audit)

        alert_data = {
            "alert_id": "alert-1",
            "source": "sentinel",
            "timestamp": "2026-02-24T00:00:00Z",
            "title": "Brute force",
            "description": "Multiple failed logins",
            "severity": "high",
            "raw_payload": {"test": True},
            "tenant_id": "t1",
        }

        with patch.object(svc, "process_message", return_value=alert_data):
            svc._emit_audit_classified(alert_data)

        audit.emit.assert_called_once()
        call_kwargs = audit.emit.call_args[1]
        assert call_kwargs["event_type"] == "alert.classified"
        assert call_kwargs["tenant_id"] == "t1"
        assert call_kwargs["alert_id"] == "alert-1"
        assert call_kwargs["event_category"] == "decision"
        assert call_kwargs["actor_type"] == "agent"

    def test_injection_detected_emitted(self):
        """When injection is detected, injection.detected event is emitted."""
        audit = MagicMock()
        svc = self._make_service(audit_producer=audit)

        svc._emit_audit_injection("t1", "alert-2", 3)

        audit.emit.assert_called_once()
        call_kwargs = audit.emit.call_args[1]
        assert call_kwargs["event_type"] == "injection.detected"
        assert call_kwargs["tenant_id"] == "t1"
        assert call_kwargs["severity"] == "warning"
        assert call_kwargs["event_category"] == "security"
        assert call_kwargs["context"]["detection_count"] == 3

    def test_no_exception_when_audit_producer_is_none(self):
        """Backward compat: no error when audit_producer is None."""
        svc = self._make_service(audit_producer=None)
        # Should not raise
        svc._emit_audit_classified({
            "alert_id": "a1", "tenant_id": "t1",
        })
        svc._emit_audit_injection("t1", "a1", 1)

    def test_audit_emit_failure_does_not_block(self):
        """Fire-and-forget: audit emit failure doesn't propagate."""
        audit = MagicMock()
        audit.emit.side_effect = Exception("Kafka down")
        svc = self._make_service(audit_producer=audit)
        # Should not raise
        svc._emit_audit_classified({
            "alert_id": "a1", "tenant_id": "t1",
        })
