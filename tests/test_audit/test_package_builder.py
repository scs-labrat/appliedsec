"""Tests for EvidencePackageBuilder — Story 13.6."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from services.audit_service.chain import chain_event, create_genesis_record
from services.audit_service.models import EvidencePackage
from services.audit_service.package_builder import EvidencePackageBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_chained_records(tenant_id: str = "t1", count: int = 3) -> list[dict]:
    """Create a valid chain of audit records."""
    genesis = create_genesis_record(tenant_id)
    state = {"last_sequence": 0, "last_hash": genesis["record_hash"]}
    records = []
    for i in range(count):
        event = {
            "audit_id": f"evt-{i}",
            "tenant_id": tenant_id,
            "timestamp": "2026-02-21T12:00:00.000Z",
            "event_type": "alert.classified" if i == 0 else "investigation.state_changed",
            "event_category": "decision",
            "severity": "info",
            "actor_type": "agent",
            "actor_id": "reasoning_agent",
            "investigation_id": "inv-1",
            "context": {},
            "decision": {"classification": "true_positive", "confidence": 0.9, "reasoning_summary": f"step {i}"},
            "outcome": {},
        }
        record = chain_event(event, state)
        records.append(record)
        state = {"last_sequence": record["sequence_number"], "last_hash": record["record_hash"]}
    return records


# ---------------------------------------------------------------------------
# TestEvidencePackage
# ---------------------------------------------------------------------------

class TestEvidencePackageModel:
    """EvidencePackage model tests."""

    def test_creates_with_defaults(self):
        pkg = EvidencePackage()
        assert pkg.investigation_id == ""
        assert pkg.chain_verified is False
        assert pkg.events == []

    def test_package_hash_computable(self):
        pkg = EvidencePackage(investigation_id="inv-1", tenant_id="t1")
        assert pkg.package_hash == ""  # not yet computed

    def test_model_dump_works(self):
        pkg = EvidencePackage(investigation_id="inv-1", events=[{"a": 1}])
        d = pkg.model_dump()
        assert d["investigation_id"] == "inv-1"
        assert len(d["events"]) == 1


# ---------------------------------------------------------------------------
# TestEvidencePackageBuilder
# ---------------------------------------------------------------------------

class TestEvidencePackageBuilder:
    """AC-1,2: Builds packages from audit records."""

    @pytest.fixture()
    def mock_db(self):
        db = AsyncMock()
        records = _make_chained_records()
        db.fetch_many = AsyncMock(return_value=records)
        return db

    @pytest.mark.asyncio
    async def test_builds_package(self, mock_db):
        builder = EvidencePackageBuilder(mock_db)
        pkg = await builder.build_package("inv-1", "t1")
        assert isinstance(pkg, EvidencePackage)
        assert pkg.investigation_id == "inv-1"
        assert pkg.tenant_id == "t1"
        assert len(pkg.events) == 3

    @pytest.mark.asyncio
    async def test_categorizes_events(self, mock_db):
        builder = EvidencePackageBuilder(mock_db)
        pkg = await builder.build_package("inv-1", "t1")
        assert len(pkg.state_transitions) > 0  # investigation.state_changed events

    @pytest.mark.asyncio
    async def test_verifies_chain(self, mock_db):
        builder = EvidencePackageBuilder(mock_db)
        pkg = await builder.build_package("inv-1", "t1")
        assert pkg.chain_verified is True
        assert pkg.chain_verification_errors == []

    @pytest.mark.asyncio
    async def test_package_hash_computed(self, mock_db):
        builder = EvidencePackageBuilder(mock_db)
        pkg = await builder.build_package("inv-1", "t1")
        assert len(pkg.package_hash) == 64

    @pytest.mark.asyncio
    async def test_reasoning_chain_extracted(self, mock_db):
        builder = EvidencePackageBuilder(mock_db)
        pkg = await builder.build_package("inv-1", "t1")
        assert len(pkg.reasoning_chain) > 0

    @pytest.mark.asyncio
    async def test_empty_investigation(self):
        db = AsyncMock()
        db.fetch_many = AsyncMock(return_value=[])
        builder = EvidencePackageBuilder(db)
        pkg = await builder.build_package("inv-nonexistent", "t1")
        assert pkg.events == []
        assert pkg.chain_verified is True  # empty chain is valid
