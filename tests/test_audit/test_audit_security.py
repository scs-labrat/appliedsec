"""Security tests for audit trail — TC-AUD-020 through TC-AUD-022.

Maps to SOC 2 CC6.1 / ISO 27001 A.8.15, A.5.33 / NIST 800-53 AU-9.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from services.audit_service.evidence import EvidenceStore


# ---------------------------------------------------------------------------
# TC-AUD-020: Direct Postgres INSERT blocked
# ---------------------------------------------------------------------------

class TestTCAUD020:
    """TC-AUD-020: Direct INSERT validation — only Audit Service should write.

    Without a live Postgres, we validate the DDL constraints that enforce this:
    - Primary key constraint requires (tenant_id, sequence_number, timestamp)
    - The hash chain ensures only records with correct previous_hash are valid
    - The immutability trigger prevents post-hoc modification
    """

    def test_ddl_has_primary_key_constraint(self):
        """audit_records PK constraint prevents duplicate writes."""
        import os
        ddl_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "infra", "migrations",
            "006_audit_records.sql",
        )
        with open(ddl_path) as f:
            ddl = f.read()
        assert "PRIMARY KEY" in ddl
        assert "tenant_id" in ddl
        assert "sequence_number" in ddl

    def test_hash_chain_detects_rogue_insert(self):
        """An injected record without correct previous_hash breaks the chain."""
        from services.audit_service.chain import (
            GENESIS_HASH,
            chain_event,
            compute_record_hash,
            create_genesis_record,
            verify_chain,
        )

        genesis = create_genesis_record("t1")
        state = {"last_sequence": 0, "last_hash": genesis["record_hash"]}

        legit = chain_event({
            "audit_id": "aud-legit",
            "tenant_id": "t1",
            "timestamp": "2026-02-20T10:01:00.000Z",
            "event_type": "alert.classified",
            "event_category": "decision",
            "severity": "info",
            "actor_type": "agent",
            "actor_id": "test",
            "actor_permissions": [],
            "investigation_id": "",
            "alert_id": "",
            "entity_ids": [],
            "context": {},
            "decision": {},
            "outcome": {},
            "record_version": "1.0",
            "source_service": "test",
        }, state)

        # Rogue record with wrong previous_hash
        rogue = {
            "audit_id": "aud-rogue",
            "tenant_id": "t1",
            "sequence_number": 2,
            "previous_hash": "bad" * 21 + "b",  # wrong hash
            "timestamp": "2026-02-20T10:02:00.000Z",
            "event_type": "alert.classified",
            "event_category": "decision",
            "severity": "info",
            "actor_type": "attacker",
            "actor_id": "rogue",
            "actor_permissions": [],
            "investigation_id": "",
            "alert_id": "",
            "entity_ids": [],
            "context": {},
            "decision": {},
            "outcome": {},
            "record_version": "1.0",
            "source_service": "rogue",
        }
        rogue["record_hash"] = compute_record_hash(rogue)

        chain = [genesis, legit, rogue]
        is_valid, errors = verify_chain(chain)
        assert is_valid is False
        assert any("previous_hash" in e for e in errors)

    def test_unique_index_on_tenant_sequence(self):
        """DDL has unique index on (tenant_id, sequence_number)."""
        import os
        ddl_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "infra", "migrations",
            "006_audit_records.sql",
        )
        with open(ddl_path) as f:
            ddl = f.read()
        assert "idx_audit_tenant_seq" in ddl
        assert "UNIQUE" in ddl


# ---------------------------------------------------------------------------
# TC-AUD-021: Tenant isolation — cross-tenant read blocked
# ---------------------------------------------------------------------------

class TestTCAUD021:
    """TC-AUD-021: Tenant A cannot read Tenant B's audit records.

    Validates that:
    - Chain verification is per-tenant (tenant_id in records)
    - Evidence packages filter by tenant_id
    - DB queries always include tenant_id parameter
    """

    def test_chain_is_per_tenant(self):
        """Two tenant chains are completely independent."""
        from services.audit_service.chain import (
            chain_event,
            create_genesis_record,
            verify_chain,
        )

        # Build chain for tenant A
        gen_a = create_genesis_record("tenant-a")
        state_a = {"last_sequence": 0, "last_hash": gen_a["record_hash"]}
        rec_a = chain_event({
            "audit_id": "a-1", "tenant_id": "tenant-a",
            "timestamp": "2026-02-20T10:00:00.000Z",
            "event_type": "alert.classified", "event_category": "decision",
            "severity": "info", "actor_type": "agent", "actor_id": "test",
            "actor_permissions": [], "investigation_id": "", "alert_id": "",
            "entity_ids": [], "context": {}, "decision": {}, "outcome": {},
            "record_version": "1.0", "source_service": "test",
        }, state_a)

        # Build chain for tenant B
        gen_b = create_genesis_record("tenant-b")
        state_b = {"last_sequence": 0, "last_hash": gen_b["record_hash"]}
        rec_b = chain_event({
            "audit_id": "b-1", "tenant_id": "tenant-b",
            "timestamp": "2026-02-20T10:00:00.000Z",
            "event_type": "alert.classified", "event_category": "decision",
            "severity": "info", "actor_type": "agent", "actor_id": "test",
            "actor_permissions": [], "investigation_id": "", "alert_id": "",
            "entity_ids": [], "context": {}, "decision": {}, "outcome": {},
            "record_version": "1.0", "source_service": "test",
        }, state_b)

        # Each chain valid independently
        valid_a, _ = verify_chain([gen_a, rec_a])
        valid_b, _ = verify_chain([gen_b, rec_b])
        assert valid_a is True
        assert valid_b is True

        # Mixing chains is invalid
        valid_mixed, errors = verify_chain([gen_a, rec_b])
        assert valid_mixed is False

    def test_evidence_query_includes_tenant_filter(self):
        """EvidencePackageBuilder queries always include tenant_id."""
        import inspect
        from services.audit_service.package_builder import EvidencePackageBuilder
        source = inspect.getsource(EvidencePackageBuilder.build_package)
        assert "tenant_id" in source

    def test_verification_query_includes_tenant_filter(self):
        """verify_tenant_chain queries always include tenant_id."""
        import inspect
        from services.audit_service.verification import verify_tenant_chain
        source = inspect.getsource(verify_tenant_chain)
        assert "tenant_id" in source


# ---------------------------------------------------------------------------
# TC-AUD-022: S3 evidence objects encrypted (SSE-KMS)
# ---------------------------------------------------------------------------

class TestTCAUD022:
    """TC-AUD-022: Verify S3 evidence objects use SSE-KMS encryption."""

    @pytest.mark.asyncio
    async def test_evidence_store_uses_sse_kms(self):
        """EvidenceStore passes ServerSideEncryption='aws:kms' on put_object."""
        s3 = MagicMock()
        store = EvidenceStore(s3)

        await store.store_evidence(
            tenant_id="t1",
            audit_id="aud-001",
            evidence_type="llm_prompt",
            content="test prompt content",
        )

        s3.put_object.assert_called_once()
        call_kwargs = s3.put_object.call_args
        # Check both positional and keyword args
        if call_kwargs.kwargs:
            assert call_kwargs.kwargs.get("ServerSideEncryption") == "aws:kms"
        else:
            assert call_kwargs[1].get("ServerSideEncryption") == "aws:kms"

    @pytest.mark.asyncio
    async def test_evidence_store_batch_uses_sse_kms(self):
        """Batch storage also uses SSE-KMS for each item."""
        s3 = MagicMock()
        store = EvidenceStore(s3)

        await store.store_evidence_batch(
            tenant_id="t1",
            audit_id="aud-002",
            items=[
                {"evidence_type": "llm_prompt", "content": "prompt 1"},
                {"evidence_type": "llm_response", "content": "response 1"},
            ],
        )

        assert s3.put_object.call_count == 2
        for call in s3.put_object.call_args_list:
            if call.kwargs:
                assert call.kwargs.get("ServerSideEncryption") == "aws:kms"
            else:
                assert call[1].get("ServerSideEncryption") == "aws:kms"

    def test_retention_export_uses_sse_kms(self):
        """RetentionLifecycle Parquet upload uses ServerSideEncryption."""
        import inspect
        from services.audit_service.retention import RetentionLifecycle
        source = inspect.getsource(RetentionLifecycle.run_monthly_export)
        assert "ServerSideEncryption" in source
        assert "aws:kms" in source
