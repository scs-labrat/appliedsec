# Story 13.3: Audit DDL and Immutability Enforcement

Status: review

## Story

As a platform operator provisioning the audit database,
I want DDL migration scripts for `audit_records` (partitioned by month), `audit_chain_state`, and `audit_verification_log` tables with an append-only immutability trigger,
so that the audit store is tamper-evident and lifecycle-managed.

## Acceptance Criteria

1. **Given** an empty database, **When** migration runs, **Then** `audit_records`, `audit_chain_state`, and `audit_verification_log` tables are created with all indexes.
2. **Given** `audit_records`, **When** an UPDATE is attempted, **Then** `audit_immutable_guard()` trigger raises an exception.
3. **Given** `audit_records`, **When** a DELETE is attempted, **Then** `audit_immutable_guard()` trigger raises an exception.
4. **Given** `audit_records`, **When** created, **Then** it is partitioned by `RANGE (timestamp)` with monthly partitions.

## Tasks / Subtasks

- [x] Task 1: Create audit_records DDL with partitioning (AC: 1, 4)
  - [x] 1.1: Create `infra/migrations/006_audit_records.sql` with partitioned audit_records table
  - [x] 1.2: All 8 indexes defined (tenant_ts, investigation, alert, event_type, category, actor, severity, tenant_seq)
- [x] Task 2: Create immutability trigger (AC: 2, 3)
  - [x] 2.1: audit_immutable_guard() trigger function raises on UPDATE/DELETE
  - [x] 2.2: enforce_audit_immutability trigger attached to audit_records
- [x] Task 3: Create audit_chain_state and audit_verification_log tables (AC: 1)
  - [x] 3.1: `infra/migrations/007_audit_chain_state.sql` with both tables and index
- [x] Task 4: Add DDL tests (AC: 1-4)
  - [x] 4.1: TestAuditRecordsDDL (7), TestImmutabilityTrigger (3), TestChainStateDDL (5) = 15 tests
  - [x] 4.2: No Postgres in test env — DDL syntax validation via string matching
- [x] Task 5: Run full regression (AC: 1-4)
  - [x] 5.1: Full project test suite: 1520 tests pass (zero regressions)
  - [x] 5.2: Existing migrations 001-005 not modified

## Dev Notes

### Critical Architecture Constraints

- **This can start in parallel with Story 13.1** — no Python code dependencies.
- **Migration numbering**: 006 follows existing 005_taxonomy_seed_data.sql (Story 12.1). Use 007 for chain state tables.
- **Partition by timestamp** — monthly partitions enable the retention lifecycle (Story 13.9) to drop old months.
- **Immutability trigger is the SOC 2 CC6.8 control** — provides tamper evidence. The trigger must fire on both UPDATE and DELETE.
- **DO NOT modify existing migrations 001-005** — they are already deployed.
- **PRIMARY KEY includes timestamp** — required for partitioned tables in PostgreSQL (partition key must be part of the primary key).

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| Migration 001 | `infra/migrations/001_core_tables.sql` | Core tables pattern. **Follow same DDL style.** |
| Migration 005 | `infra/migrations/005_taxonomy_seed_data.sql` | Latest migration. **006 comes next.** |
| Kafka topic | `infra/scripts/create_kafka_topics.py:27` | `audit.events` topic already exists. **DDL complements this.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Audit records DDL (NEW) | `infra/migrations/006_audit_records.sql` |
| Chain state DDL (NEW) | `infra/migrations/007_audit_chain_state.sql` |
| DDL tests (NEW) | `tests/test_infra/test_audit_ddl.py` |
| Existing migration 001 | `infra/migrations/001_core_tables.sql` |
| Existing migration 005 | `infra/migrations/005_taxonomy_seed_data.sql` |

### Table Relationships

```
audit_records (partitioned, append-only)
    │
    ├── tenant_id ──► audit_chain_state (per-tenant chain head)
    │                     │
    │                     └── last_sequence, last_hash (updated on each insert)
    │
    └── verification ──► audit_verification_log (periodic checks)
```

### Compliance Mapping

| Control | Requirement | How DDL Satisfies |
|---|---|---|
| SOC 2 CC6.8 | Tamper evidence | `audit_immutable_guard()` trigger blocks UPDATE/DELETE |
| ISO 27001 A.5.33 | Protection of records | Append-only with 3-tier retention |
| NIST AU-9 | Audit record protection | Immutability trigger + separate access controls |

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_infra/ (existing tests):**
- All migration-related tests unchanged

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**
- DDL tests: parse SQL files, verify table/trigger definitions exist
- If Postgres available: run DDL, attempt UPDATE/DELETE, verify exception
- No async needed

### Dependencies on Other Stories

- **None.** Can start immediately in parallel with Stories 13.1 and 13.2.

### References

- [Source: docs/audit-architecture.md Section 10] — Database schema specification
- [Source: docs/audit-architecture.md Section 4] — Hash chain design (chain_state table)
- [Source: docs/prd.md#NFR-CMP-001] — Immutable audit trail requirement
- [Source: docs/prd.md#NFR-CMP-002] — Monthly partitioning for data retention

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- All 15 tests passed on first run
- Full regression: 1520 tests passed

### Completion Notes List

- 006_audit_records.sql: partitioned table (RANGE on timestamp), 4 monthly partitions, 8 indexes, immutability trigger
- 007_audit_chain_state.sql: chain_state + verification_log tables
- SOC 2 CC6.8 control: audit_immutable_guard blocks UPDATE/DELETE

### File List

**Created:**
- `infra/migrations/006_audit_records.sql` — audit_records partitioned table, 8 indexes, immutability trigger
- `infra/migrations/007_audit_chain_state.sql` — audit_chain_state, audit_verification_log
- `tests/test_infra/test_audit_ddl.py` — 15 DDL validation tests

**Modified:**
- None (existing migrations unchanged)

### Change Log

- 2026-02-21: Story implemented — 15 new tests, 1520 total regression clean
