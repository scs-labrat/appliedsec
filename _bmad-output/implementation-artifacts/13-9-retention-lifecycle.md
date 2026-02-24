# Story 13.9: Retention Lifecycle (Warm-to-Cold Export)

Status: review

## Story

As a platform managing long-term audit retention,
I want a monthly job that exports Postgres audit partitions to S3 as Parquet, verifies integrity, and drops old partitions per the 3-tier retention policy (30d hot, 12m warm, 7y cold),
so that audit data is retained for 7 years at minimal cost.

## Acceptance Criteria

1. **Given** the monthly export job, **When** run, **Then** the partition from 2 months ago is exported to Parquet, uploaded to S3, and hash-verified.
2. **Given** a legal hold on a tenant, **When** the export job runs, **Then** that tenant's data is NOT dropped from Postgres.
3. **Given** cold storage objects, **When** older than 1 year, **Then** S3 lifecycle transitions them to Glacier/Deep Archive.
4. **Given** a partition with verified export, **When** the Postgres partition is dropped, **Then** at least 1 month buffer remains in warm tier.

## Tasks / Subtasks

- [x] Task 1: Create retention job framework (AC: 1, 4)
  - [x] 1.1: Create `services/audit_service/retention.py` with `RetentionLifecycle` class:
    - `__init__(self, postgres_client, s3_client, bucket: str = "aluskort-audit-cold")`
    - `async run_monthly_export() -> dict` — main entry point:
      1. Identify partition from 2 months ago (e.g., current month is Feb → export December)
      2. Export partition records to Parquet format
      3. Upload to S3 at path `cold/{tenant_id}/{YYYY-MM}/audit_records.parquet`
      4. Compute SHA-256 of Parquet file, store as sidecar `audit_records.parquet.sha256`
      5. Verify uploaded file hash matches
      6. Return `{exported_count, partition_name, verified}`
    - `async drop_old_partition(partition_name: str, verified: bool) -> bool` — drops Postgres partition ONLY if export was verified. Maintains 1-month buffer.
  - [x] 1.2: Add Parquet export using `pyarrow` or `pandas` — convert audit_records rows to Parquet with schema preservation.
  - [x] 1.3: Add unit tests in `tests/test_audit/test_retention.py` — `TestRetentionLifecycle` class: export generates Parquet, hash verified, partition identified correctly, 1-month buffer enforced. (~6 tests)
- [x] Task 2: Add legal hold enforcement (AC: 2)
  - [x] 2.1: Add `legal_hold_tenants: set[str]` parameter (loaded from config or database).
  - [x] 2.2: Before dropping any partition, check if any records belong to a tenant with legal hold. If so, skip the drop and log.
  - [x] 2.3: Add unit tests — `TestLegalHold` class: tenant with legal hold data is NOT dropped, other tenants are dropped normally. (~3 tests)
- [x] Task 3: Create S3 lifecycle configuration (AC: 3)
  - [x] 3.1: Create `infra/s3-lifecycle/audit-cold-lifecycle.json` with S3 lifecycle rules:
    - Transition to Glacier after 365 days
    - Transition to Deep Archive after 730 days (2 years)
    - Expire (delete) after 2555 days (7 years)
  - [x] 3.2: Add unit tests — `TestLifecycleConfig` class: JSON is valid, transition days correct, expiry at 7 years. (~2 tests)
- [x] Task 4: Add partition management utilities (AC: 1, 4)
  - [x] 4.1: Add `create_next_partitions(count: int = 3) -> list[str]` — creates monthly partitions for upcoming months (prevents write failures when a new month starts).
  - [x] 4.2: Add `list_partitions() -> list[dict]` — returns all current partitions with row counts and date ranges.
  - [x] 4.3: Add unit tests — `TestPartitionManagement` class: next partitions created, list returns correct info. (~3 tests)
- [x] Task 5: Run full regression (AC: 1-4)
  - [x] 5.1: Run full project test suite (`pytest tests/`) — all 1646 tests pass (zero regressions)

## Dev Notes

### Critical Architecture Constraints

- **3-tier retention**: Hot (Kafka 30d) → Warm (Postgres 12m) → Cold (S3/Parquet 7y).
- **Export BEFORE drop** — never drop a partition without a verified S3 export. The 1-month buffer provides safety margin.
- **Legal hold blocks drops** — compliance requirement. If a tenant is under legal hold, their data stays in Postgres regardless of age.
- **Parquet format** — columnar format enables efficient analytical queries on cold data. Preserves full schema including JSONB columns.
- **Hash verification** — every exported file gets a SHA-256 sidecar for integrity verification on retrieval.
- **DO NOT modify the audit_records table or immutability trigger** — partition management is DDL-level (CREATE/DROP partition), not row-level.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `EvidenceStore` | `services/audit_service/evidence.py` (Story 13.5) | S3 client pattern. **Follow same S3 usage.** |
| DDL partitioning | `infra/migrations/006_audit_records.sql` (Story 13.3) | Monthly partitions. **Manage via DDL.** |
| `PostgresClient` | `shared/db/postgres.py` | DB client. **Use for queries and DDL.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Retention lifecycle (NEW) | `services/audit_service/retention.py` |
| S3 lifecycle config (NEW) | `infra/s3-lifecycle/audit-cold-lifecycle.json` |
| Retention tests (NEW) | `tests/test_audit/test_retention.py` |

### Retention Timeline

```
Month 0 (now)     Month -1        Month -2         Month -12        Month -84 (7yr)
    │                │                │                │                │
    ├── Hot (Kafka)──┤                │                │                │
    │    30 days     │                │                │                │
    │                ├── Warm (PG) ───┤── Export ──────┤                │
    │                │   12 months    │  to Parquet    │                │
    │                │                │                ├── Cold (S3) ───┤
    │                │                │                │   Glacier 1yr  │
    │                │                │                │   Deep 2yr     │
    │                │                │                │   Delete 7yr   │
```

### Existing Test Classes That MUST Still Pass (Unchanged)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**, **pytest-asyncio**
- Mock S3 client for upload/download verification
- Mock PostgresClient for partition DDL operations
- Verify Parquet file structure (mock or use in-memory Parquet)
- Test legal hold enforcement: set hold, verify partition not dropped

### Dependencies on Other Stories

- **Story 13.3** (DDL): partitioned `audit_records` table
- **Story 13.4** (Audit Service): writes records to partitions
- **Story 13.5** (Evidence Store): S3 client pattern

### References

- [Source: docs/audit-architecture.md Section 6] — 3-tier retention policy
- [Source: docs/prd.md#NFR-CMP-002] — Monthly partitioning and cold storage
- [Source: docs/audit-architecture.md Section 11] — Compliance mapping (NIST AU-11)

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- No regressions detected. All 1646 tests passed on first run.

### Completion Notes List

- **Task 1 (Retention Framework):** Created `RetentionLifecycle` class with `run_monthly_export()` that identifies partition from 2 months ago, exports records to Parquet (pyarrow with JSON-Lines fallback), uploads to S3 with SHA-256 sidecar, and verifies upload integrity. `drop_old_partition()` enforces 1-month buffer and requires verified export. 6 tests in `TestRetentionLifecycle`.
- **Task 2 (Legal Hold):** Added `legal_hold_tenants: set[str]` constructor param. `_has_legal_hold_data()` checks partition for tenant records under hold. Partition drops blocked when legal hold data found. 3 tests in `TestLegalHold`.
- **Task 3 (S3 Lifecycle):** Created `audit-cold-lifecycle.json` with Glacier at 365d, Deep Archive at 730d, expire at 2555d (7yr). Prefix filter `cold/` matches export path. 2 tests in `TestLifecycleConfig`.
- **Task 4 (Partition Management):** `create_next_partitions(count)` creates future monthly partitions via DDL. `list_partitions()` returns all partitions with row counts. Helper functions for date arithmetic (`_subtract_months`, `_add_months`, `_next_month`, `_partition_name`, `_parse_partition_date`). 3 tests in `TestPartitionManagement`, 6 tests in `TestHelperFunctions`.
- **Task 5 (Regression):** 1646 tests passed, 0 failures. No existing tests modified.

### File List

**Created:**
- `services/audit_service/retention.py` — RetentionLifecycle class: export, legal hold, partition management, date helpers
- `infra/s3-lifecycle/audit-cold-lifecycle.json` — S3 lifecycle rules (Glacier/Deep Archive/Expire)
- `tests/test_audit/test_retention.py` — 20 tests across 5 classes

**Modified:**
- None (all existing files unchanged)

### Change Log

- 2026-02-24: Story 13.9 implemented — RetentionLifecycle with monthly Parquet export to S3, SHA-256 verification, legal hold enforcement, partition management, and S3 lifecycle configuration. 20 new tests, 1646 total tests passing.
