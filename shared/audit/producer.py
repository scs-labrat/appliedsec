"""AuditProducer shared library — Story 13.2.

Publishes structured audit events to the ``audit.events`` Kafka topic.
All services import this single interface to emit audit events.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from confluent_kafka import KafkaException, Producer

from shared.schemas.event_taxonomy import EventTaxonomy

logger = logging.getLogger(__name__)

AUDIT_TOPIC = "audit.events"


class AuditProducer:
    """Fire-and-forget audit event producer.

    Validates event_type against :class:`EventTaxonomy`, assigns a UUID
    audit_id and UTC timestamp, then publishes to Kafka.  Failures are
    logged but never raised (fail-open semantics).
    """

    def __init__(self, kafka_bootstrap: str, service_name: str) -> None:
        self._service_name = service_name
        self._producer = Producer({"bootstrap.servers": kafka_bootstrap})

    def emit(
        self,
        *,
        tenant_id: str,
        event_type: str,
        event_category: str,
        severity: str = "info",
        actor_type: str,
        actor_id: str,
        investigation_id: str = "",
        alert_id: str = "",
        entity_ids: list[str] | None = None,
        context: dict[str, Any] | None = None,
        decision: dict[str, Any] | None = None,
        outcome: dict[str, Any] | None = None,
    ) -> str:
        """Emit an audit event and return the generated audit_id.

        Raises :class:`ValueError` if *event_type* is not a valid
        :class:`EventTaxonomy` member.
        """
        # Validate event_type against taxonomy
        valid_types = {e.value for e in EventTaxonomy}
        if event_type not in valid_types:
            msg = f"Invalid event_type '{event_type}'. Must be a valid EventTaxonomy value."
            raise ValueError(msg)

        audit_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        event: dict[str, Any] = {
            "audit_id": audit_id,
            "tenant_id": tenant_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "event_category": event_category,
            "severity": severity,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "source_service": self._service_name,
        }

        if investigation_id:
            event["investigation_id"] = investigation_id
        if alert_id:
            event["alert_id"] = alert_id
        if entity_ids:
            event["entity_ids"] = entity_ids
        if context is not None:
            event["context"] = context
        if decision is not None:
            event["decision"] = decision
        if outcome is not None:
            event["outcome"] = outcome

        payload = json.dumps(event).encode("utf-8")
        key = tenant_id.encode("utf-8")

        try:
            self._producer.produce(
                AUDIT_TOPIC,
                key=key,
                value=payload,
                callback=self._delivery_callback,
            )
            self._producer.poll(0)
        except (KafkaException, BufferError) as exc:
            logger.warning("Audit event emit failed (fire-and-forget): %s", exc)

        return audit_id

    def flush(self, timeout: float = 5.0) -> None:
        """Flush pending messages.  Call on service shutdown."""
        self._producer.flush(timeout)

    @staticmethod
    def _delivery_callback(err: Any, msg: Any) -> None:
        """Async delivery report callback — logs errors at WARNING."""
        if err is not None:
            logger.warning("Audit event delivery failed: %s", err)


def create_audit_producer(kafka_bootstrap: str, service_name: str) -> AuditProducer:
    """Factory function to create an AuditProducer."""
    return AuditProducer(kafka_bootstrap, service_name)


def build_llm_context(
    *,
    provider: str,
    model_id: str,
    tier: str,
    input_tokens: int,
    output_tokens: int,
    cost_usd: float,
    latency_ms: int,
    prompt_hash: str = "",
    response_hash: str = "",
) -> dict[str, Any]:
    """Build an AuditContext-compatible dict for LLM audit events."""
    return {
        "llm_provider": provider,
        "llm_model_id": model_id,
        "llm_model_tier": tier,
        "llm_input_tokens": input_tokens,
        "llm_output_tokens": output_tokens,
        "llm_cost_usd": cost_usd,
        "llm_latency_ms": latency_ms,
        "llm_system_prompt_hash": prompt_hash,
        "llm_raw_response_hash": response_hash,
    }
