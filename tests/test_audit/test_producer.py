"""Tests for AuditProducer, fail-open handling, and convenience helpers — Story 13.2."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from confluent_kafka import KafkaException

from shared.audit.producer import (
    AUDIT_TOPIC,
    AuditProducer,
    build_llm_context,
    create_audit_producer,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_producer(service_name: str = "test-service") -> AuditProducer:
    """Create an AuditProducer with a mocked Kafka Producer."""
    with patch("shared.audit.producer.Producer") as mock_cls:
        mock_cls.return_value = MagicMock()
        producer = AuditProducer("localhost:9092", service_name)
    return producer


def _emit_default(producer: AuditProducer, **overrides) -> tuple[str, dict]:
    """Emit a default event and return (audit_id, produced_event_dict)."""
    defaults = dict(
        tenant_id="tenant-1",
        event_type="alert.classified",
        event_category="decision",
        actor_type="agent",
        actor_id="reasoning_agent",
    )
    defaults.update(overrides)
    audit_id = producer.emit(**defaults)

    # Extract the event dict from the produce() call
    call_args = producer._producer.produce.call_args
    payload = call_args.kwargs.get("value") or call_args[1].get("value") if call_args.kwargs else call_args[0][2] if len(call_args[0]) > 2 else None
    if payload is None:
        # Try positional args with keyword mix
        for arg in call_args:
            if isinstance(arg, dict) and "value" in arg:
                payload = arg["value"]
                break
        if payload is None:
            payload = call_args.kwargs["value"]

    event = json.loads(payload.decode("utf-8"))
    return audit_id, event


# ---------------------------------------------------------------------------
# TestAuditProducer (AC: 1, 2, 3)
# ---------------------------------------------------------------------------

class TestAuditProducer:
    """AC-1,2,3: AuditProducer emits structured events to audit.events."""

    def test_emit_returns_audit_id(self):
        producer = _make_producer()
        audit_id = producer.emit(
            tenant_id="t1", event_type="alert.classified",
            event_category="decision", actor_type="agent", actor_id="test",
        )
        assert isinstance(audit_id, str)
        assert len(audit_id) > 0

    def test_event_has_correct_fields(self):
        producer = _make_producer("orchestrator")
        audit_id, event = _emit_default(producer)
        assert event["audit_id"] == audit_id
        assert event["tenant_id"] == "tenant-1"
        assert event["event_type"] == "alert.classified"
        assert event["event_category"] == "decision"
        assert event["severity"] == "info"
        assert event["actor_type"] == "agent"
        assert event["actor_id"] == "reasoning_agent"
        assert event["source_service"] == "orchestrator"
        assert "timestamp" in event

    def test_tenant_id_is_message_key(self):
        producer = _make_producer()
        _emit_default(producer, tenant_id="my-tenant")
        call_kwargs = producer._producer.produce.call_args
        key = call_kwargs.kwargs.get("key")
        assert key == b"my-tenant"

    def test_topic_is_audit_events(self):
        producer = _make_producer()
        _emit_default(producer)
        call_args = producer._producer.produce.call_args
        topic = call_args[0][0] if call_args[0] else call_args.kwargs.get("topic")
        assert topic == AUDIT_TOPIC

    def test_no_sequence_number_or_hash(self):
        producer = _make_producer()
        _, event = _emit_default(producer)
        assert "sequence_number" not in event
        assert "previous_hash" not in event
        assert "record_hash" not in event

    def test_event_type_validated(self):
        producer = _make_producer()
        with pytest.raises(ValueError, match="Invalid event_type"):
            producer.emit(
                tenant_id="t1", event_type="invalid.type",
                event_category="decision", actor_type="agent", actor_id="test",
            )

    def test_optional_fields_included_when_provided(self):
        producer = _make_producer()
        _, event = _emit_default(
            producer,
            investigation_id="inv-1",
            alert_id="alert-1",
            entity_ids=["e1", "e2"],
            context={"llm_provider": "anthropic"},
            decision={"decision_type": "classify"},
            outcome={"outcome_status": "success"},
        )
        assert event["investigation_id"] == "inv-1"
        assert event["alert_id"] == "alert-1"
        assert event["entity_ids"] == ["e1", "e2"]
        assert event["context"]["llm_provider"] == "anthropic"
        assert event["decision"]["decision_type"] == "classify"
        assert event["outcome"]["outcome_status"] == "success"

    def test_optional_fields_absent_when_empty(self):
        producer = _make_producer()
        _, event = _emit_default(producer)
        assert "investigation_id" not in event
        assert "alert_id" not in event
        assert "entity_ids" not in event
        assert "context" not in event


# ---------------------------------------------------------------------------
# TestAuditProducerFailOpen (AC: 4)
# ---------------------------------------------------------------------------

class TestAuditProducerFailOpen:
    """AC-4: Kafka failures logged but not raised."""

    def test_kafka_error_does_not_raise(self):
        producer = _make_producer()
        producer._producer.produce.side_effect = KafkaException(
            KafkaException(None)  # type: ignore[arg-type]
        )
        # Should not raise
        audit_id = producer.emit(
            tenant_id="t1", event_type="alert.classified",
            event_category="decision", actor_type="agent", actor_id="test",
        )
        assert isinstance(audit_id, str)

    def test_buffer_error_does_not_raise(self):
        producer = _make_producer()
        producer._producer.produce.side_effect = BufferError("queue full")
        audit_id = producer.emit(
            tenant_id="t1", event_type="alert.classified",
            event_category="decision", actor_type="agent", actor_id="test",
        )
        assert isinstance(audit_id, str)

    def test_delivery_callback_logs_error(self):
        with patch("shared.audit.producer.logger") as mock_logger:
            AuditProducer._delivery_callback("some-error", None)
            mock_logger.warning.assert_called_once()


# ---------------------------------------------------------------------------
# TestConvenienceHelpers (AC: 1)
# ---------------------------------------------------------------------------

class TestConvenienceHelpers:
    """Factory and build_llm_context helpers."""

    def test_factory_creates_producer(self):
        with patch("shared.audit.producer.Producer"):
            p = create_audit_producer("localhost:9092", "my-service")
            assert isinstance(p, AuditProducer)

    def test_build_llm_context_returns_dict(self):
        ctx = build_llm_context(
            provider="anthropic",
            model_id="claude-sonnet-4-5-20250929",
            tier="tier_1",
            input_tokens=5000,
            output_tokens=1200,
            cost_usd=0.024,
            latency_ms=850,
        )
        assert ctx["llm_provider"] == "anthropic"
        assert ctx["llm_model_id"] == "claude-sonnet-4-5-20250929"
        assert ctx["llm_input_tokens"] == 5000
        assert ctx["llm_cost_usd"] == 0.024
        assert ctx["llm_system_prompt_hash"] == ""

    def test_build_llm_context_with_hashes(self):
        ctx = build_llm_context(
            provider="openai", model_id="gpt-4o", tier="tier_1",
            input_tokens=1000, output_tokens=500, cost_usd=0.01,
            latency_ms=200, prompt_hash="abc123", response_hash="def456",
        )
        assert ctx["llm_system_prompt_hash"] == "abc123"
        assert ctx["llm_raw_response_hash"] == "def456"
