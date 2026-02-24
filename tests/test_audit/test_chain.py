"""Tests for hash chain computation and ChainStateManager — Story 13.4."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from services.audit_service.chain import (
    GENESIS_HASH,
    ChainStateManager,
    chain_event,
    compute_record_hash,
    create_genesis_record,
    verify_chain,
)


# ---------------------------------------------------------------------------
# TestComputeRecordHash
# ---------------------------------------------------------------------------

class TestComputeRecordHash:
    """Hash computation: deterministic, excludes record_hash, sorted keys."""

    def test_deterministic(self):
        rec = {"a": 1, "b": "hello", "c": [1, 2]}
        h1 = compute_record_hash(rec)
        h2 = compute_record_hash(rec)
        assert h1 == h2

    def test_excludes_record_hash_field(self):
        rec = {"a": 1, "b": 2}
        h_without = compute_record_hash(rec)
        rec_with = {"a": 1, "b": 2, "record_hash": "old-hash"}
        h_with = compute_record_hash(rec_with)
        assert h_without == h_with

    def test_sorted_keys(self):
        rec1 = {"z": 1, "a": 2}
        rec2 = {"a": 2, "z": 1}
        assert compute_record_hash(rec1) == compute_record_hash(rec2)

    def test_returns_64_char_hex(self):
        h = compute_record_hash({"test": True})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
# TestGenesisRecord
# ---------------------------------------------------------------------------

class TestGenesisRecord:
    """Genesis record for new tenants."""

    def test_genesis_has_correct_fields(self):
        genesis = create_genesis_record("tenant-1")
        assert genesis["tenant_id"] == "tenant-1"
        assert genesis["sequence_number"] == 0
        assert genesis["previous_hash"] == GENESIS_HASH
        assert genesis["event_type"] == "system.genesis"
        assert genesis["event_category"] == "system"
        assert genesis["actor_type"] == "system"
        assert genesis["record_hash"] != ""

    def test_genesis_hash_is_valid(self):
        genesis = create_genesis_record("t1")
        expected = compute_record_hash(genesis)
        assert genesis["record_hash"] == expected


# ---------------------------------------------------------------------------
# TestChainEvent
# ---------------------------------------------------------------------------

class TestChainEvent:
    """Event chaining: sequence increments, previous_hash linked."""

    def test_sequence_increments(self):
        event = {"audit_id": "e1", "tenant_id": "t1", "event_type": "alert.classified"}
        state = {"last_sequence": 5, "last_hash": "abc123"}
        record = chain_event(event, state)
        assert record["sequence_number"] == 6

    def test_previous_hash_linked(self):
        event = {"audit_id": "e1", "tenant_id": "t1"}
        state = {"last_sequence": 0, "last_hash": "genesis-hash"}
        record = chain_event(event, state)
        assert record["previous_hash"] == "genesis-hash"

    def test_record_hash_computed(self):
        event = {"audit_id": "e1", "tenant_id": "t1"}
        state = {"last_sequence": 0, "last_hash": GENESIS_HASH}
        record = chain_event(event, state)
        expected = compute_record_hash(record)
        assert record["record_hash"] == expected

    def test_ingested_at_set(self):
        event = {"audit_id": "e1", "tenant_id": "t1"}
        state = {"last_sequence": 0, "last_hash": GENESIS_HASH}
        record = chain_event(event, state)
        assert "ingested_at" in record
        assert record["ingested_at"].endswith("Z")


# ---------------------------------------------------------------------------
# TestVerifyChain
# ---------------------------------------------------------------------------

class TestVerifyChain:
    """Chain verification."""

    def test_valid_chain(self):
        genesis = create_genesis_record("t1")
        state = {"last_sequence": 0, "last_hash": genesis["record_hash"]}
        r1 = chain_event({"audit_id": "e1", "tenant_id": "t1"}, state)
        state = {"last_sequence": 1, "last_hash": r1["record_hash"]}
        r2 = chain_event({"audit_id": "e2", "tenant_id": "t1"}, state)

        valid, errors = verify_chain([genesis, r1, r2])
        assert valid is True
        assert errors == []

    def test_tampered_hash_detected(self):
        genesis = create_genesis_record("t1")
        genesis["record_hash"] = "tampered"
        valid, errors = verify_chain([genesis])
        assert valid is False
        assert len(errors) > 0

    def test_empty_chain_valid(self):
        valid, errors = verify_chain([])
        assert valid is True


# ---------------------------------------------------------------------------
# TestChainStateManager
# ---------------------------------------------------------------------------

class TestChainStateManager:
    """ChainStateManager with mocked Postgres."""

    @pytest.fixture()
    def mock_db(self):
        db = AsyncMock()
        db.fetch_one = AsyncMock(return_value=None)
        db.execute = AsyncMock()
        return db

    @pytest.mark.asyncio
    async def test_get_state_new_tenant_returns_none(self, mock_db):
        mgr = ChainStateManager(mock_db)
        state = await mgr.get_state("new-tenant")
        assert state is None

    @pytest.mark.asyncio
    async def test_ensure_genesis_creates_state(self, mock_db):
        mgr = ChainStateManager(mock_db)
        state = await mgr.ensure_genesis("new-tenant")
        assert state["tenant_id"] == "new-tenant"
        assert state["last_sequence"] == 0
        assert state["last_hash"] != ""

    @pytest.mark.asyncio
    async def test_ensure_genesis_returns_existing(self, mock_db):
        existing = {"tenant_id": "t1", "last_sequence": 10, "last_hash": "abc", "last_timestamp": "2026-01-01T00:00:00Z"}
        mock_db.fetch_one = AsyncMock(return_value=existing)
        mgr = ChainStateManager(mock_db)
        state = await mgr.ensure_genesis("t1")
        assert state["last_sequence"] == 10

    @pytest.mark.asyncio
    async def test_update_state_calls_execute(self, mock_db):
        mgr = ChainStateManager(mock_db)
        await mgr.update_state("t1", 5, "hash123", "2026-01-01T00:00:00Z")
        mock_db.execute.assert_called_once()
