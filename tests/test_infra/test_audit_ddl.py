"""Tests for audit DDL migration files — Story 13.3."""

from __future__ import annotations

from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent.parent.parent / "infra" / "migrations"


def _read_migration(filename: str) -> str:
    return (MIGRATIONS_DIR / filename).read_text()


class TestAuditRecordsDDL:
    """AC-1,4: audit_records table with partitioning and indexes."""

    def test_file_exists(self):
        assert (MIGRATIONS_DIR / "006_audit_records.sql").is_file()

    def test_creates_audit_records_table(self):
        sql = _read_migration("006_audit_records.sql")
        assert "CREATE TABLE IF NOT EXISTS audit_records" in sql

    def test_partition_by_range(self):
        sql = _read_migration("006_audit_records.sql")
        assert "PARTITION BY RANGE" in sql
        assert "timestamp" in sql

    def test_monthly_partitions_defined(self):
        sql = _read_migration("006_audit_records.sql")
        assert "PARTITION OF audit_records" in sql
        assert "FOR VALUES FROM" in sql

    def test_all_required_columns(self):
        sql = _read_migration("006_audit_records.sql")
        required = [
            "audit_id", "tenant_id", "sequence_number", "previous_hash",
            "timestamp", "ingested_at", "event_type", "event_category",
            "severity", "actor_type", "actor_id", "actor_permissions",
            "investigation_id", "alert_id", "entity_ids",
            "context", "decision", "outcome",
            "record_hash", "record_version",
        ]
        for col in required:
            assert col in sql, f"Missing column: {col}"

    def test_all_indexes_defined(self):
        sql = _read_migration("006_audit_records.sql")
        indexes = [
            "idx_audit_tenant_ts",
            "idx_audit_investigation",
            "idx_audit_alert",
            "idx_audit_event_type",
            "idx_audit_category",
            "idx_audit_actor",
            "idx_audit_severity",
            "idx_audit_tenant_seq",
        ]
        for idx in indexes:
            assert idx in sql, f"Missing index: {idx}"

    def test_primary_key_includes_timestamp(self):
        sql = _read_migration("006_audit_records.sql")
        assert "PRIMARY KEY (tenant_id, sequence_number, timestamp)" in sql


class TestImmutabilityTrigger:
    """AC-2,3: Append-only immutability trigger."""

    def test_trigger_function_defined(self):
        sql = _read_migration("006_audit_records.sql")
        assert "audit_immutable_guard()" in sql
        assert "RETURNS TRIGGER" in sql

    def test_trigger_raises_on_update_delete(self):
        sql = _read_migration("006_audit_records.sql")
        assert "RAISE EXCEPTION" in sql
        assert "append-only" in sql

    def test_trigger_declaration(self):
        sql = _read_migration("006_audit_records.sql")
        assert "enforce_audit_immutability" in sql
        assert "BEFORE UPDATE OR DELETE" in sql
        assert "FOR EACH ROW" in sql


class TestChainStateDDL:
    """AC-1: audit_chain_state and audit_verification_log tables."""

    def test_file_exists(self):
        assert (MIGRATIONS_DIR / "007_audit_chain_state.sql").is_file()

    def test_creates_chain_state_table(self):
        sql = _read_migration("007_audit_chain_state.sql")
        assert "CREATE TABLE IF NOT EXISTS audit_chain_state" in sql
        assert "tenant_id" in sql
        assert "last_sequence" in sql
        assert "last_hash" in sql

    def test_creates_verification_log_table(self):
        sql = _read_migration("007_audit_chain_state.sql")
        assert "CREATE TABLE IF NOT EXISTS audit_verification_log" in sql
        assert "chain_valid" in sql
        assert "records_checked" in sql

    def test_verification_log_index(self):
        sql = _read_migration("007_audit_chain_state.sql")
        assert "idx_verify_tenant" in sql

    def test_idempotent_statements(self):
        sql006 = _read_migration("006_audit_records.sql")
        sql007 = _read_migration("007_audit_chain_state.sql")
        assert "IF NOT EXISTS" in sql006
        assert "IF NOT EXISTS" in sql007
