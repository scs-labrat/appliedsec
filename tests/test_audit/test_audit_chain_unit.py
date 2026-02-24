"""Unit tests for audit hash chain integrity — TC-AUD-001 through TC-AUD-007.

Maps to SOC 2 CC6.8 / ISO 27001 A.8.15 / NIST 800-53 AU-3, AU-9, AU-10.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone

import pytest

from services.audit_service.chain import (
    GENESIS_HASH,
    chain_event,
    compute_record_hash,
    create_genesis_record,
    verify_chain,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_base_record(**overrides) -> dict:
    """Create a minimal audit record dict for hashing tests."""
    rec = {
        "audit_id": "aud-001",
        "tenant_id": "t1",
        "sequence_number": 0,
        "previous_hash": GENESIS_HASH,
        "timestamp": "2026-02-20T10:00:00.000Z",
        "ingested_at": "2026-02-20T10:00:00.100Z",
        "event_type": "alert.classified",
        "event_category": "decision",
        "severity": "info",
        "actor_type": "agent",
        "actor_id": "test-agent",
        "actor_permissions": [],
        "investigation_id": "inv-001",
        "alert_id": "alert-001",
        "entity_ids": [],
        "context": {},
        "decision": {},
        "outcome": {},
        "record_version": "1.0",
        "source_service": "test",
    }
    rec.update(overrides)
    return rec


def _build_chain(tenant_id: str = "t1", count: int = 10) -> list[dict]:
    """Build a valid hash chain of *count* records."""
    genesis = create_genesis_record(tenant_id)
    chain = [genesis]

    state = {
        "last_sequence": genesis["sequence_number"],
        "last_hash": genesis["record_hash"],
    }

    for i in range(1, count):
        event = {
            "audit_id": f"aud-{i:04d}",
            "tenant_id": tenant_id,
            "timestamp": f"2026-02-20T10:{i:02d}:00.000Z",
            "event_type": "alert.classified",
            "event_category": "decision",
            "severity": "info",
            "actor_type": "agent",
            "actor_id": "test-agent",
            "actor_permissions": [],
            "investigation_id": "inv-001",
            "alert_id": "alert-001",
            "entity_ids": [],
            "context": {},
            "decision": {},
            "outcome": {},
            "record_version": "1.0",
            "source_service": "test",
        }
        rec = chain_event(event, state)
        chain.append(rec)
        state = {
            "last_sequence": rec["sequence_number"],
            "last_hash": rec["record_hash"],
        }

    return chain


# ---------------------------------------------------------------------------
# TC-AUD-001: Deterministic hash computation
# ---------------------------------------------------------------------------

class TestTCAUD001:
    """TC-AUD-001: Compute hash of AuditRecord — deterministic SHA-256."""

    def test_same_input_produces_same_hash(self):
        """Same record dict always produces identical SHA-256."""
        rec = _make_base_record()
        h1 = compute_record_hash(rec)
        h2 = compute_record_hash(rec)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_different_input_produces_different_hash(self):
        """Changing any field changes the hash."""
        rec1 = _make_base_record()
        rec2 = _make_base_record(audit_id="aud-002")
        assert compute_record_hash(rec1) != compute_record_hash(rec2)

    def test_record_hash_field_excluded_from_computation(self):
        """The ``record_hash`` field itself is excluded from hash input."""
        rec = _make_base_record()
        h_without = compute_record_hash(rec)
        rec["record_hash"] = "some_existing_hash"
        h_with = compute_record_hash(rec)
        assert h_without == h_with


# ---------------------------------------------------------------------------
# TC-AUD-002: Valid chain verification
# ---------------------------------------------------------------------------

class TestTCAUD002:
    """TC-AUD-002: Verify valid chain (10 records) → (True, [])."""

    def test_valid_chain_passes(self):
        """A properly constructed 10-record chain verifies successfully."""
        chain = _build_chain(count=10)
        is_valid, errors = verify_chain(chain)
        assert is_valid is True
        assert errors == []

    def test_empty_chain_passes(self):
        """An empty chain is vacuously valid."""
        is_valid, errors = verify_chain([])
        assert is_valid is True
        assert errors == []


# ---------------------------------------------------------------------------
# TC-AUD-003: Tamper detection
# ---------------------------------------------------------------------------

class TestTCAUD003:
    """TC-AUD-003: Detect tampered record in chain → (False, [error])."""

    def test_tampered_record_detected(self):
        """Modifying a record's field causes hash mismatch."""
        chain = _build_chain(count=5)
        # Tamper with record at index 2
        chain[2]["severity"] = "critical"  # was "info"
        is_valid, errors = verify_chain(chain)
        assert is_valid is False
        assert any("hash mismatch" in e for e in errors)

    def test_tampered_hash_detected(self):
        """Replacing record_hash with a wrong value is detected."""
        chain = _build_chain(count=5)
        chain[3]["record_hash"] = "a" * 64
        is_valid, errors = verify_chain(chain)
        assert is_valid is False
        assert len(errors) >= 1


# ---------------------------------------------------------------------------
# TC-AUD-004: Sequence gap detection
# ---------------------------------------------------------------------------

class TestTCAUD004:
    """TC-AUD-004: Detect sequence gap → (False, [gap error])."""

    def test_gap_detected(self):
        """Removing a record from the middle creates a sequence gap."""
        chain = _build_chain(count=5)
        # Remove record at index 2 (sequence=2)
        del chain[2]
        is_valid, errors = verify_chain(chain)
        assert is_valid is False
        assert any("gap" in e.lower() or "previous_hash" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# TC-AUD-005: Genesis record
# ---------------------------------------------------------------------------

class TestTCAUD005:
    """TC-AUD-005: Genesis record has correct previous_hash == '0' * 64."""

    def test_genesis_previous_hash(self):
        """Genesis record's previous_hash is 64 zeros."""
        genesis = create_genesis_record("t1")
        assert genesis["previous_hash"] == "0" * 64

    def test_genesis_sequence_zero(self):
        """Genesis record has sequence_number 0."""
        genesis = create_genesis_record("t1")
        assert genesis["sequence_number"] == 0

    def test_genesis_event_type(self):
        """Genesis record has event_type 'system.genesis'."""
        genesis = create_genesis_record("t1")
        assert genesis["event_type"] == "system.genesis"

    def test_genesis_hash_valid(self):
        """Genesis record_hash matches computed hash."""
        genesis = create_genesis_record("t1")
        assert genesis["record_hash"] == compute_record_hash(genesis)


# ---------------------------------------------------------------------------
# TC-AUD-006: Immutability trigger blocks UPDATE
# ---------------------------------------------------------------------------

class TestTCAUD006:
    """TC-AUD-006: Immutability trigger blocks UPDATE (DDL-level).

    Since we test without a live Postgres, we validate the DDL contains the
    trigger definition and test the conceptual behaviour via chain verification.
    """

    def test_ddl_contains_immutability_trigger(self):
        """Migration SQL defines the immutability guard trigger."""
        import os
        ddl_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "infra", "migrations",
            "006_audit_records.sql",
        )
        with open(ddl_path) as f:
            ddl = f.read()
        assert "audit_immutable_guard" in ddl
        assert "BEFORE UPDATE OR DELETE" in ddl

    def test_update_simulated_breaks_chain(self):
        """Simulating an UPDATE (field change) breaks chain verification."""
        chain = _build_chain(count=3)
        # Simulate UPDATE on record 1
        chain[1]["actor_id"] = "attacker"
        is_valid, errors = verify_chain(chain)
        assert is_valid is False


# ---------------------------------------------------------------------------
# TC-AUD-007: Immutability trigger blocks DELETE
# ---------------------------------------------------------------------------

class TestTCAUD007:
    """TC-AUD-007: Immutability trigger blocks DELETE (DDL-level).

    Validates trigger definition exists and simulates DELETE impact.
    """

    def test_ddl_trigger_covers_delete(self):
        """Trigger SQL covers DELETE operations."""
        import os
        ddl_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "infra", "migrations",
            "006_audit_records.sql",
        )
        with open(ddl_path) as f:
            ddl = f.read()
        assert "DELETE" in ddl
        assert "append-only" in ddl

    def test_delete_simulated_breaks_chain(self):
        """Simulating a DELETE (removing record) breaks chain."""
        chain = _build_chain(count=5)
        del chain[3]  # Delete record at index 3
        is_valid, errors = verify_chain(chain)
        assert is_valid is False
