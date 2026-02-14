# Story 2.2: Create Postgres DDL Migration Scripts

## Status: done

## Description
DDL migration scripts for all Postgres tables covering core, CTEM, and ATLAS schemas.

## Tasks
- [x] Create `infra/migrations/001_core_tables.sql` — mitre_techniques, mitre_groups, taxonomy_ids, threat_intel_iocs, playbooks, playbook_steps, incident_memory, fp_patterns, org_context
- [x] Create `infra/migrations/002_ctem_tables.sql` — ctem_exposures (with exposure_key UNIQUE), ctem_validations, ctem_remediations
- [x] Create `infra/migrations/003_atlas_tables.sql` — orbital_inference_logs, edge_node_telemetry, databricks_audit, model_registry, investigation_state, inference_logs
- [x] All tables use `CREATE TABLE IF NOT EXISTS` for idempotency
- [x] Add GIN indexes for JSONB columns and B-tree indexes for lookups
- [x] Write tests in `tests/test_infra/test_ddl_migrations.py`
- [x] All 20 tests pass

## Completion Notes
- 3 migration files in `infra/migrations/`
- All `CREATE TABLE` statements are idempotent
- 20/20 tests pass
