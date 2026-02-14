"""Tests for Postgres DDL migration files — Story 2.2."""

from __future__ import annotations

from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent.parent.parent / "infra" / "migrations"


def _read_migration(filename: str) -> str:
    return (MIGRATIONS_DIR / filename).read_text()


class TestMigration001CoreTables:
    def test_file_exists(self):
        assert (MIGRATIONS_DIR / "001_core_tables.sql").is_file()

    def test_creates_mitre_techniques(self):
        sql = _read_migration("001_core_tables.sql")
        assert "CREATE TABLE IF NOT EXISTS mitre_techniques" in sql

    def test_creates_taxonomy_ids(self):
        sql = _read_migration("001_core_tables.sql")
        assert "CREATE TABLE IF NOT EXISTS taxonomy_ids" in sql
        assert "framework" in sql
        assert "deprecated" in sql

    def test_creates_threat_intel_iocs(self):
        sql = _read_migration("001_core_tables.sql")
        assert "CREATE TABLE IF NOT EXISTS threat_intel_iocs" in sql
        assert "confidence" in sql

    def test_creates_playbooks(self):
        sql = _read_migration("001_core_tables.sql")
        assert "CREATE TABLE IF NOT EXISTS playbooks" in sql
        assert "CREATE TABLE IF NOT EXISTS playbook_steps" in sql

    def test_creates_incident_memory(self):
        sql = _read_migration("001_core_tables.sql")
        assert "CREATE TABLE IF NOT EXISTS incident_memory" in sql

    def test_creates_fp_patterns(self):
        sql = _read_migration("001_core_tables.sql")
        assert "CREATE TABLE IF NOT EXISTS fp_patterns" in sql

    def test_creates_org_context(self):
        sql = _read_migration("001_core_tables.sql")
        assert "CREATE TABLE IF NOT EXISTS org_context" in sql

    def test_all_tables_idempotent(self):
        sql = _read_migration("001_core_tables.sql")
        # Every CREATE TABLE should be IF NOT EXISTS
        create_count = sql.count("CREATE TABLE")
        if_not_exists_count = sql.count("CREATE TABLE IF NOT EXISTS")
        assert create_count == if_not_exists_count

    def test_indexes_created(self):
        sql = _read_migration("001_core_tables.sql")
        assert "CREATE INDEX" in sql
        assert "idx_mitre_technique_id" in sql


class TestMigration002CtemTables:
    def test_file_exists(self):
        assert (MIGRATIONS_DIR / "002_ctem_tables.sql").is_file()

    def test_creates_ctem_exposures(self):
        sql = _read_migration("002_ctem_tables.sql")
        assert "CREATE TABLE IF NOT EXISTS ctem_exposures" in sql

    def test_exposure_key_unique(self):
        sql = _read_migration("002_ctem_tables.sql")
        assert "exposure_key" in sql
        assert "UNIQUE" in sql

    def test_creates_ctem_validations(self):
        sql = _read_migration("002_ctem_tables.sql")
        assert "CREATE TABLE IF NOT EXISTS ctem_validations" in sql

    def test_creates_ctem_remediations(self):
        sql = _read_migration("002_ctem_tables.sql")
        assert "CREATE TABLE IF NOT EXISTS ctem_remediations" in sql


class TestMigration003AtlasTables:
    def test_file_exists(self):
        assert (MIGRATIONS_DIR / "003_atlas_tables.sql").is_file()

    def test_creates_inference_logs(self):
        sql = _read_migration("003_atlas_tables.sql")
        assert "orbital_inference_logs" in sql

    def test_creates_edge_telemetry(self):
        sql = _read_migration("003_atlas_tables.sql")
        assert "edge_node_telemetry" in sql

    def test_creates_investigation_state(self):
        sql = _read_migration("003_atlas_tables.sql")
        assert "investigation_state" in sql

    def test_creates_inference_cost_tracking(self):
        sql = _read_migration("003_atlas_tables.sql")
        assert "inference_logs" in sql
        assert "cost_usd" in sql
        assert "input_tokens" in sql
