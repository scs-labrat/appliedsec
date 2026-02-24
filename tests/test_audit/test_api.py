"""Tests for audit service FastAPI endpoints — Story 13.6."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from services.audit_service import api
from services.audit_service.chain import chain_event, create_genesis_record


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_chained_records(tenant_id: str = "t1", count: int = 3) -> list[dict]:
    genesis = create_genesis_record(tenant_id)
    state = {"last_sequence": 0, "last_hash": genesis["record_hash"]}
    records = []
    for i in range(count):
        event = {
            "audit_id": f"evt-{i}",
            "tenant_id": tenant_id,
            "timestamp": "2026-02-21T12:00:00.000Z",
            "event_type": "alert.classified",
            "event_category": "decision",
            "severity": "info",
            "actor_type": "agent",
            "actor_id": "test",
            "investigation_id": "inv-1",
            "context": {},
            "decision": {},
            "outcome": {},
        }
        record = chain_event(event, state)
        records.append(record)
        state = {"last_sequence": record["sequence_number"], "last_hash": record["record_hash"]}
    return records


@pytest.fixture(autouse=True)
def init_api():
    """Initialize API with mocked deps for each test."""
    db = AsyncMock()
    db.fetch_many = AsyncMock(return_value=_make_chained_records())
    db.fetch_one = AsyncMock(return_value={"audit_id": "evt-0", "tenant_id": "t1", "event_type": "alert.classified"})
    api.init_api(db)
    yield
    api._db = None
    api._builder = None


# ---------------------------------------------------------------------------
# TestAuditAPI
# ---------------------------------------------------------------------------

class TestAuditAPI:
    """AC-1,3,4: API endpoint tests."""

    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        transport = ASGITransport(app=api.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_evidence_package_endpoint(self):
        transport = ASGITransport(app=api.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/v1/audit/evidence-package/inv-1?tenant_id=t1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["investigation_id"] == "inv-1"
        assert "events" in data
        assert "chain_verified" in data

    @pytest.mark.asyncio
    async def test_list_events_endpoint(self):
        transport = ASGITransport(app=api.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/v1/audit/events?tenant_id=t1")
        assert resp.status_code == 200
        assert "events" in resp.json()

    @pytest.mark.asyncio
    async def test_single_event_endpoint(self):
        transport = ASGITransport(app=api.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/v1/audit/events/evt-0?tenant_id=t1")
        assert resp.status_code == 200
        assert resp.json()["audit_id"] == "evt-0"

    @pytest.mark.asyncio
    async def test_verify_endpoint(self):
        transport = ASGITransport(app=api.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/v1/audit/verify?tenant_id=t1")
        assert resp.status_code == 200
        data = resp.json()
        assert "chain_valid" in data

    @pytest.mark.asyncio
    async def test_tenant_required(self):
        transport = ASGITransport(app=api.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/v1/audit/events")
        assert resp.status_code == 422  # missing tenant_id

    @pytest.mark.asyncio
    async def test_export_endpoint(self):
        transport = ASGITransport(app=api.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/v1/audit/export", json={"tenant_id": "t1", "format": "json"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "accepted"

    @pytest.mark.asyncio
    async def test_event_not_found(self):
        api._db.fetch_one = AsyncMock(return_value=None)
        transport = ASGITransport(app=api.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/v1/audit/events/nonexistent?tenant_id=t1")
        assert resp.status_code == 404
