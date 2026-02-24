"""Tests for AuditService (consumer, chain, writer) — Story 13.4."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from services.audit_service.chain import compute_record_hash, verify_chain
from services.audit_service.service import AuditService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(tenant_id: str = "t1", event_type: str = "alert.classified", **extra) -> dict:
    defaults = {
        "audit_id": f"evt-{id(extra) % 1000}",
        "tenant_id": tenant_id,
        "timestamp": "2026-02-21T12:00:00.000Z",
        "event_type": event_type,
        "event_category": "decision",
        "severity": "info",
        "actor_type": "agent",
        "actor_id": "reasoning_agent",
        "source_service": "orchestrator",
    }
    defaults.update(extra)
    return defaults


def _make_service() -> AuditService:
    """Create AuditService with mocked Kafka and Postgres."""
    db = AsyncMock()
    db.fetch_one = AsyncMock(return_value=None)  # no existing chain state
    db.execute = AsyncMock()
    svc = AuditService("localhost:9092", db)
    return svc


# ---------------------------------------------------------------------------
# TestAuditService
# ---------------------------------------------------------------------------

class TestAuditService:
    """AC-1,2,3,4: Event processing, chaining, tenant isolation."""

    @pytest.mark.asyncio
    async def test_process_single_event(self):
        svc = _make_service()
        event = _make_event()
        record = await svc.process_event(event)
        assert record["sequence_number"] == 1  # genesis=0, first event=1
        assert record["record_hash"] != ""
        assert record["previous_hash"] != ""

    @pytest.mark.asyncio
    async def test_chain_10_events(self):
        svc = _make_service()
        records = []
        for i in range(10):
            event = _make_event(audit_id=f"evt-{i}")
            record = await svc.process_event(event)
            records.append(record)
        # Sequences 1-10 (genesis is 0)
        seqs = [r["sequence_number"] for r in records]
        assert seqs == list(range(1, 11))

    @pytest.mark.asyncio
    async def test_new_tenant_gets_genesis(self):
        svc = _make_service()
        event = _make_event(tenant_id="new-tenant")
        record = await svc.process_event(event)
        # ensure_genesis was called, so sequence starts at 1
        assert record["sequence_number"] == 1

    @pytest.mark.asyncio
    async def test_two_tenants_independent(self):
        svc = _make_service()
        r_a = await svc.process_event(_make_event(tenant_id="tenant-a", audit_id="a1"))
        r_b = await svc.process_event(_make_event(tenant_id="tenant-b", audit_id="b1"))
        r_a2 = await svc.process_event(_make_event(tenant_id="tenant-a", audit_id="a2"))
        # tenant-a: seq 1, 2; tenant-b: seq 1
        assert r_a["sequence_number"] == 1
        assert r_b["sequence_number"] == 1
        assert r_a2["sequence_number"] == 2

    @pytest.mark.asyncio
    async def test_record_hash_is_valid(self):
        svc = _make_service()
        record = await svc.process_event(_make_event())
        expected = compute_record_hash(record)
        assert record["record_hash"] == expected

    @pytest.mark.asyncio
    async def test_health_check(self):
        svc = _make_service()
        health = await svc.health_check()
        assert health["status"] == "ok"
        assert health["service"] == "audit-service"


# ---------------------------------------------------------------------------
# TestBatchProcessing
# ---------------------------------------------------------------------------

class TestBatchProcessing:
    """AC-3: Batch processing with no sequence gaps."""

    @pytest.mark.asyncio
    async def test_100_events_no_gaps(self):
        svc = _make_service()
        events = [_make_event(audit_id=f"evt-{i}") for i in range(100)]
        records = await svc.process_batch(events)
        seqs = [r["sequence_number"] for r in records]
        assert seqs == list(range(1, 101))

    @pytest.mark.asyncio
    async def test_batch_chain_valid(self):
        svc = _make_service()
        events = [_make_event(audit_id=f"evt-{i}") for i in range(10)]
        records = await svc.process_batch(events)
        valid, errors = verify_chain(records)
        assert valid is True
        assert errors == []

    @pytest.mark.asyncio
    async def test_batch_writes_to_db(self):
        svc = _make_service()
        events = [_make_event(audit_id=f"evt-{i}") for i in range(5)]
        await svc.process_batch(events)
        # ensure_genesis + 5 writes + 6 state updates (genesis + 5) = multiple calls
        assert svc._db.execute.call_count > 5
