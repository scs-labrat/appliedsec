"""Integration tests for audit pipeline — TC-AUD-010 through TC-AUD-014.

Maps to SOC 2 CC7.2, CC6.1, CC7.3 / ISO 27001 A.8.15, A.5.28 /
NIST 800-53 AU-2, AU-3, AU-6, AU-9.
"""

from __future__ import annotations

import hashlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.audit_service.chain import (
    GENESIS_HASH,
    ChainStateManager,
    chain_event,
    compute_record_hash,
    create_genesis_record,
    verify_chain,
)
from services.audit_service.evidence import EvidenceStore
from services.audit_service.package_builder import EvidencePackageBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_db():
    """Create a mock Postgres client."""
    db = AsyncMock()
    db.fetch_many = AsyncMock(return_value=[])
    db.fetch_one = AsyncMock(return_value=None)
    db.execute = AsyncMock()
    return db


def _mock_s3():
    """Create a mock S3 client that stores and returns uploaded content."""
    s3 = MagicMock()
    stored = {}

    def put_object(**kwargs):
        stored[kwargs["Key"]] = kwargs["Body"]

    def get_object(**kwargs):
        body = MagicMock()
        body.read.return_value = stored.get(kwargs["Key"], b"")
        return {"Body": body}

    s3.put_object = MagicMock(side_effect=put_object)
    s3.get_object = MagicMock(side_effect=get_object)
    s3._stored = stored
    return s3


def _build_chain_with_state(tenant_id: str, count: int):
    """Build a chain and return (records, final_state)."""
    genesis = create_genesis_record(tenant_id)
    chain = [genesis]
    state = {
        "last_sequence": genesis["sequence_number"],
        "last_hash": genesis["record_hash"],
    }

    for i in range(1, count):
        event = {
            "audit_id": f"aud-{tenant_id}-{i:04d}",
            "tenant_id": tenant_id,
            "timestamp": f"2026-02-20T10:{i:02d}:00.000Z",
            "event_type": "alert.classified",
            "event_category": "decision",
            "severity": "info",
            "actor_type": "agent",
            "actor_id": "test-agent",
            "actor_permissions": [],
            "investigation_id": f"inv-{tenant_id}",
            "alert_id": f"alert-{tenant_id}",
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

    return chain, state


# ---------------------------------------------------------------------------
# TC-AUD-010: End-to-end pipeline — emit → chain → verify
# ---------------------------------------------------------------------------

class TestTCAUD010:
    """TC-AUD-010: Emit event via AuditProducer, verify in Postgres.

    Record appears with valid hash and chain link.
    """

    @pytest.mark.asyncio
    async def test_emit_and_verify_chain(self):
        """Simulated end-to-end: event → chain → store → verify."""
        # Build a properly chained set of records
        records, _ = _build_chain_with_state("t1", count=4)

        # Verify entire chain
        is_valid, errors = verify_chain(records)
        assert is_valid is True
        assert errors == []

        # Verify each record hash is correct
        for rec in records:
            assert rec["record_hash"] == compute_record_hash(rec)

        # Verify chain state manager works with mocked DB
        db = _mock_db()
        chain_mgr = ChainStateManager(db)
        db.fetch_one = AsyncMock(return_value=None)
        state = await chain_mgr.ensure_genesis("t1")
        assert state["last_sequence"] == 0
        assert len(state["last_hash"]) == 64


# ---------------------------------------------------------------------------
# TC-AUD-011: Throughput — 100 events, chain intact
# ---------------------------------------------------------------------------

class TestTCAUD011:
    """TC-AUD-011: Emit 100 events rapidly, verify chain integrity."""

    def test_100_event_chain_integrity(self):
        """100 chained records verify with no gaps or hash errors."""
        chain, _ = _build_chain_with_state("t1", count=100)
        assert len(chain) == 100

        is_valid, errors = verify_chain(chain)
        assert is_valid is True
        assert errors == []

    def test_sequence_numbers_contiguous(self):
        """All 100 records have contiguous sequence numbers."""
        chain, _ = _build_chain_with_state("t1", count=100)
        sequences = [r["sequence_number"] for r in chain]
        for i in range(1, len(sequences)):
            assert sequences[i] == sequences[i - 1] + 1


# ---------------------------------------------------------------------------
# TC-AUD-012: Tenant isolation — concurrent chains
# ---------------------------------------------------------------------------

class TestTCAUD012:
    """TC-AUD-012: Two tenants emit concurrently — independent chains."""

    def test_two_tenant_chains_independent(self):
        """Each tenant has an independent valid chain, no cross-contamination."""
        chain_a, _ = _build_chain_with_state("tenant-a", count=20)
        chain_b, _ = _build_chain_with_state("tenant-b", count=20)

        # Both chains valid
        valid_a, errors_a = verify_chain(chain_a)
        valid_b, errors_b = verify_chain(chain_b)
        assert valid_a is True
        assert valid_b is True
        assert errors_a == []
        assert errors_b == []

    def test_mixed_tenant_chain_invalid(self):
        """Interleaving records from two tenants breaks chain."""
        chain_a, _ = _build_chain_with_state("tenant-a", count=5)
        chain_b, _ = _build_chain_with_state("tenant-b", count=5)

        # Interleave
        mixed = [chain_a[0], chain_b[1], chain_a[2]]
        valid, errors = verify_chain(mixed)
        assert valid is False

    def test_tenant_id_preserved_in_all_records(self):
        """All records in a tenant chain have the correct tenant_id."""
        chain_a, _ = _build_chain_with_state("tenant-a", count=10)
        for rec in chain_a:
            assert rec["tenant_id"] == "tenant-a"


# ---------------------------------------------------------------------------
# TC-AUD-013: Evidence artifact stored in S3
# ---------------------------------------------------------------------------

class TestTCAUD013:
    """TC-AUD-013: store_evidence returns valid hash and URI, artifact retrievable."""

    @pytest.mark.asyncio
    async def test_store_and_retrieve_evidence(self):
        """Evidence stored → retrievable with matching hash."""
        s3 = _mock_s3()
        store = EvidenceStore(s3)
        content = json.dumps({"prompt": "Analyse this alert..."})

        content_hash, s3_uri = await store.store_evidence(
            tenant_id="t1",
            audit_id="aud-001",
            evidence_type="llm_prompt",
            content=content,
        )

        assert len(content_hash) == 64  # SHA-256 hex
        assert s3_uri.startswith("s3://")

        # Verify retrieval
        retrieved = await store.retrieve_evidence(s3_uri)
        assert retrieved == content.encode("utf-8")

    @pytest.mark.asyncio
    async def test_evidence_hash_matches_content(self):
        """Stored content hash matches SHA-256 of content."""
        s3 = _mock_s3()
        store = EvidenceStore(s3)
        content = "test evidence content"

        content_hash, _ = await store.store_evidence(
            tenant_id="t1",
            audit_id="aud-002",
            evidence_type="llm_response",
            content=content,
        )

        expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
        assert content_hash == expected

    @pytest.mark.asyncio
    async def test_evidence_verification_passes(self):
        """verify_evidence succeeds for correctly stored artifact."""
        s3 = _mock_s3()
        store = EvidenceStore(s3)
        content = "verify me"

        content_hash, s3_uri = await store.store_evidence(
            tenant_id="t1",
            audit_id="aud-003",
            evidence_type="raw_alert",
            content=content,
        )

        verified = await store.verify_evidence(s3_uri, content_hash)
        assert verified is True


# ---------------------------------------------------------------------------
# TC-AUD-014: Evidence package for investigation
# ---------------------------------------------------------------------------

class TestTCAUD014:
    """TC-AUD-014: Generate evidence package — contains all events, transitions, LLM."""

    @pytest.mark.asyncio
    async def test_evidence_package_contains_all_events(self):
        """Package includes all audit events for the investigation."""
        db = _mock_db()
        records = [
            {
                "audit_id": "aud-001", "tenant_id": "t1",
                "sequence_number": 0, "previous_hash": GENESIS_HASH,
                "timestamp": "2026-02-20T10:00:00.000Z",
                "ingested_at": "2026-02-20T10:00:00.100Z",
                "event_type": "investigation.state_changed",
                "event_category": "system", "severity": "info",
                "actor_type": "agent", "actor_id": "orchestrator",
                "actor_permissions": [],
                "investigation_id": "inv-001", "alert_id": "alert-001",
                "entity_ids": [],
                "context": {}, "decision": {}, "outcome": {},
                "record_version": "1.0",
            },
            {
                "audit_id": "aud-002", "tenant_id": "t1",
                "sequence_number": 1,
                "previous_hash": compute_record_hash({
                    "audit_id": "aud-001", "tenant_id": "t1",
                    "sequence_number": 0, "previous_hash": GENESIS_HASH,
                    "timestamp": "2026-02-20T10:00:00.000Z",
                    "ingested_at": "2026-02-20T10:00:00.100Z",
                    "event_type": "investigation.state_changed",
                    "event_category": "system", "severity": "info",
                    "actor_type": "agent", "actor_id": "orchestrator",
                    "actor_permissions": [],
                    "investigation_id": "inv-001", "alert_id": "alert-001",
                    "entity_ids": [],
                    "context": {}, "decision": {}, "outcome": {},
                    "record_version": "1.0",
                }),
                "timestamp": "2026-02-20T10:01:00.000Z",
                "ingested_at": "2026-02-20T10:01:00.100Z",
                "event_type": "approval.requested",
                "event_category": "human", "severity": "info",
                "actor_type": "agent", "actor_id": "response-agent",
                "actor_permissions": [],
                "investigation_id": "inv-001", "alert_id": "alert-001",
                "entity_ids": [],
                "context": {"llm_model_id": "claude-opus-4-6"},
                "decision": {}, "outcome": {},
                "record_version": "1.0",
            },
        ]
        # Set record_hash for each
        for rec in records:
            rec["record_hash"] = compute_record_hash(rec)

        db.fetch_many = AsyncMock(return_value=records)

        builder = EvidencePackageBuilder(db)
        pkg = await builder.build_package("inv-001", "t1")

        assert pkg.investigation_id == "inv-001"
        assert pkg.tenant_id == "t1"
        assert len(pkg.events) == 2
        assert len(pkg.state_transitions) >= 1
        assert len(pkg.approvals) >= 1
        assert pkg.chain_verified is True

    @pytest.mark.asyncio
    async def test_package_has_llm_interactions(self):
        """Package categorizes LLM interaction events correctly."""
        db = _mock_db()
        records = [
            {
                "audit_id": "aud-010", "tenant_id": "t1",
                "sequence_number": 0, "previous_hash": GENESIS_HASH,
                "timestamp": "2026-02-20T10:00:00.000Z",
                "ingested_at": "2026-02-20T10:00:00.100Z",
                "event_type": "investigation.state_changed",
                "event_category": "system", "severity": "info",
                "actor_type": "agent", "actor_id": "gateway",
                "actor_permissions": [],
                "investigation_id": "inv-002", "alert_id": "",
                "entity_ids": [],
                "context": {
                    "llm_model_id": "claude-opus-4-6",
                    "llm_input_tokens": 1500,
                    "llm_output_tokens": 300,
                },
                "decision": {}, "outcome": {},
                "record_version": "1.0",
            },
        ]
        for rec in records:
            rec["record_hash"] = compute_record_hash(rec)

        db.fetch_many = AsyncMock(return_value=records)

        builder = EvidencePackageBuilder(db)
        pkg = await builder.build_package("inv-002", "t1")

        assert len(pkg.llm_interactions) >= 1

    @pytest.mark.asyncio
    async def test_package_chain_verified(self):
        """Package verifies the hash chain of included events."""
        db = _mock_db()

        # Build chain with investigation_id baked in from the start
        genesis = create_genesis_record("t1")
        genesis["investigation_id"] = "inv-003"
        genesis["record_hash"] = compute_record_hash(genesis)
        records = [genesis]
        state = {"last_sequence": 0, "last_hash": genesis["record_hash"]}

        for i in range(1, 5):
            event = {
                "audit_id": f"aud-pkg-{i:04d}",
                "tenant_id": "t1",
                "timestamp": f"2026-02-20T10:{i:02d}:00.000Z",
                "event_type": "alert.classified",
                "event_category": "decision",
                "severity": "info",
                "actor_type": "agent",
                "actor_id": "test-agent",
                "actor_permissions": [],
                "investigation_id": "inv-003",
                "alert_id": "alert-003",
                "entity_ids": [],
                "context": {},
                "decision": {},
                "outcome": {},
                "record_version": "1.0",
                "source_service": "test",
            }
            rec = chain_event(event, state)
            records.append(rec)
            state = {"last_sequence": rec["sequence_number"], "last_hash": rec["record_hash"]}

        db.fetch_many = AsyncMock(return_value=records)

        builder = EvidencePackageBuilder(db)
        pkg = await builder.build_package("inv-003", "t1")

        assert pkg.chain_verified is True
        assert pkg.chain_verification_errors == []
        assert len(pkg.package_id) > 0
        assert len(pkg.package_hash) == 64
