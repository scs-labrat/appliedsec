# Story 2.5: Create Neo4j Schema Constraints and Indexes

## Status: done

## Description
Cypher scripts that create uniqueness constraints, indexes, and sample data for the Neo4j graph database.

## Tasks
- [x] Create `infra/scripts/init_neo4j.py` with schema definitions
- [x] 5 uniqueness constraints: Asset.id, Zone.id, Model.id, Finding.id, Tenant.id
- [x] 4+ indexes for query performance
- [x] Sample data with Tenant, Zones, Assets, Model, Finding, and relationships (RESIDES_IN, DEPLOYS_TO, AFFECTS, OWNED_BY, CONNECTS_TO)
- [x] All constraints/indexes use `IF NOT EXISTS` for idempotency
- [x] `init_schema()` function with `load_sample_data` flag
- [x] Write tests in `tests/test_infra/test_neo4j_schema.py`
- [x] All 9 tests pass

## Completion Notes
- Script is both CLI-runnable and importable
- `init_schema()` returns dict with counts of constraints, indexes, and sample_records applied
- 9/9 tests pass
