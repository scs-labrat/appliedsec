"""Audit service — Kafka consumer, chain manager, Postgres writer — Story 13.4.

Single-writer microservice that consumes from ``audit.events``, assigns
per-tenant sequence numbers, computes SHA-256 hash chains, and writes to
Postgres ``audit_records``.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from services.audit_service.chain import ChainStateManager, chain_event

logger = logging.getLogger(__name__)

CONSUMER_GROUP = "aluskort.audit-service"
AUDIT_TOPIC = "audit.events"
SERVICE_PORT = 8040
BATCH_SIZE = 100

_INSERT_SQL = """
INSERT INTO audit_records (
    audit_id, tenant_id, sequence_number, previous_hash, timestamp, ingested_at,
    event_type, event_category, severity, actor_type, actor_id, actor_permissions,
    investigation_id, alert_id, entity_ids, context, decision, outcome,
    record_hash, record_version
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11, $12,
    $13, $14, $15, $16, $17, $18,
    $19, $20
)
"""


class AuditService:
    """Kafka consumer → chain → Postgres writer."""

    def __init__(self, kafka_bootstrap: str, postgres_client: Any) -> None:
        self._kafka_bootstrap = kafka_bootstrap
        self._db = postgres_client
        self._chain_mgr = ChainStateManager(postgres_client)
        self._running = False

    async def process_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Process a single audit event: ensure chain, chain it, write to DB."""
        tenant_id = event.get("tenant_id", "")
        chain_state = await self._chain_mgr.ensure_genesis(tenant_id)
        record = chain_event(event, chain_state)
        await self._write_record(record)
        await self._chain_mgr.update_state(
            tenant_id,
            record["sequence_number"],
            record["record_hash"],
            record.get("timestamp", ""),
        )
        return record

    async def process_batch(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Process a batch of events sequentially (chain order matters)."""
        records = []
        for event in events:
            record = await self.process_event(event)
            records.append(record)
        return records

    async def _write_record(self, record: dict[str, Any]) -> None:
        """INSERT a chained record into audit_records."""
        await self._db.execute(
            _INSERT_SQL,
            record.get("audit_id", ""),
            record.get("tenant_id", ""),
            record.get("sequence_number", 0),
            record.get("previous_hash", ""),
            record.get("timestamp", ""),
            record.get("ingested_at", ""),
            record.get("event_type", ""),
            record.get("event_category", ""),
            record.get("severity", "info"),
            record.get("actor_type", ""),
            record.get("actor_id", ""),
            record.get("actor_permissions", []),
            record.get("investigation_id", ""),
            record.get("alert_id", ""),
            record.get("entity_ids", []),
            json.dumps(record.get("context", {})),
            json.dumps(record.get("decision", {})),
            json.dumps(record.get("outcome", {})),
            record.get("record_hash", ""),
            record.get("record_version", "1.0"),
        )

    async def health_check(self) -> dict[str, str]:
        """GET /health response."""
        return {"status": "ok", "service": "audit-service", "port": str(SERVICE_PORT)}
