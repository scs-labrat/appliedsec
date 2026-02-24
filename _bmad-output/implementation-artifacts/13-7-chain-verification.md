# Story 13.7: Chain Verification and Integrity Checks

Status: review

## Story

As a compliance officer monitoring audit integrity,
I want scheduled chain verification (every 5 minutes for last 100 records, daily full, hourly Kafka-vs-Postgres cross-check, weekly cold spot-check) with Prometheus alerting,
so that any tampering or data loss is detected promptly.

## Acceptance Criteria

1. **Given** the 5-minute check, **When** a hash mismatch or sequence gap is found, **Then** `AluskortAuditChainBroken` alert fires.
2. **Given** the hourly cross-check, **When** Kafka offset exceeds Postgres `max(sequence_number)` by > 1,000, **Then** `AluskortAuditLagHigh` alert fires.
3. **Given** each verification run, **When** completed, **Then** results are recorded in `audit_verification_log` table.
4. **Given** a tampered record, **When** `verify_chain()` runs, **Then** it returns `(False, [error details])`.

## Tasks / Subtasks

- [x] Task 1: Create chain verification functions (AC: 1, 4)
  - [x] 1.1: Create `services/audit_service/verification.py` with:
    - `async verify_chain(postgres_client, tenant_id: str, from_sequence: int | None = None, to_sequence: int | None = None) -> tuple[bool, list[str]]`:
      - Queries `audit_records` for tenant, ordered by sequence_number
      - For each record: recompute hash, verify matches `record_hash`
      - Verify `previous_hash` matches prior record's `record_hash`
      - Verify `sequence_number` is monotonically increasing, no gaps
      - Returns `(True, [])` or `(False, [list of error descriptions])`
    - `async verify_recent(postgres_client, tenant_id: str, count: int = 100) -> tuple[bool, list[str]]` — verifies last N records
  - [x] 1.2: Add unit tests in `tests/test_audit/test_verification.py` — `TestVerifyChain` class: valid chain passes, tampered record detected, sequence gap detected, hash mismatch detected, empty chain returns True. (~6 tests)
- [x] Task 2: Create scheduled verification jobs (AC: 1, 2, 3)
  - [x] 2.1: Add `VerificationScheduler` class to `services/audit_service/verification.py`:
    - `async run_continuous_check()` — every 5 minutes, verify last 100 records for all tenants
    - `async run_daily_full_check()` — daily at 03:00 UTC, full chain verification for all tenants
    - `async run_hourly_lag_check()` — hourly, compare Kafka topic offset vs Postgres max(sequence_number)
    - `async run_weekly_cold_check()` — weekly, random sample 100 records from S3 cold storage, verify hashes
  - [x] 2.2: Each check writes results to `audit_verification_log` table with: `tenant_id`, `verification_type`, `records_checked`, `from_sequence`, `to_sequence`, `chain_valid`, `errors`, `duration_ms`.
  - [x] 2.3: Add unit tests — `TestVerificationScheduler` class: continuous check runs verify_recent, daily check runs full verify, lag check computes offset difference, results written to verification_log. (~6 tests)
- [x] Task 3: Add Prometheus metrics and alerting (AC: 1, 2)
  - [x] 3.1: Add Prometheus metrics to `ops/metrics.py`:
    - `aluskort_audit_chain_valid` (gauge, labels: tenant_id, check_type) — 1 if valid, 0 if broken
    - `aluskort_audit_kafka_lag` (gauge, labels: tenant_id) — Kafka offset minus Postgres max sequence
    - `aluskort_audit_verification_duration_seconds` (histogram, labels: check_type)
  - [x] 3.2: Add alerting rules to `ops/alerting_rules.yml`:
    - `AluskortAuditChainBroken` — fires when `aluskort_audit_chain_valid == 0` for > 0 minutes (immediate)
    - `AluskortAuditLagHigh` — fires when `aluskort_audit_kafka_lag > 1000` for > 5 minutes
    - `AluskortAuditIntegrityFailed` — fires when daily full check fails
    - `AluskortAuditColdCorruption` — fires when weekly cold check fails
  - [x] 3.3: Add unit tests — `TestVerificationMetrics` class: valid chain sets gauge to 1, broken chain sets to 0, lag metric exported. (~4 tests)
- [x] Task 4: Run full regression (AC: 1-4)
  - [x] 4.1: Run full project test suite (`pytest tests/`) — all 1594 tests pass (zero regressions)

## Dev Notes

### Critical Architecture Constraints

- **Verification is the integrity proof** — without it, the hash chain is just data. Verification proves the chain has not been tampered with.
- **4-tier verification schedule**: 5-min (hot), daily (full), hourly (cross-check), weekly (cold). Each serves a different detection window.
- **Results are persisted** — `audit_verification_log` table provides a verifiable history of checks for compliance auditors.
- **Prometheus metrics drive alerts** — the verification system publishes metrics; the alerting layer (Story 11.2) fires alerts.
- **DO NOT modify the chain computation** (Story 13.4). Verification reads and verifies, it does not write audit records.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `compute_record_hash()` | `services/audit_service/chain.py` (Story 13.4) | Hash computation. **Reuse to verify.** |
| `EvidenceStore` | `services/audit_service/evidence.py` (Story 13.5) | S3 access. **For cold spot-checks.** |
| DDL tables | `infra/migrations/007_audit_chain_state.sql` (Story 13.3) | `audit_verification_log`. **Write results to.** |
| Alerting rules | `ops/alerting_rules.yml` | Existing alert definitions. **Add audit alerts.** |
| Metrics | `ops/metrics.py` | Metric definitions. **Add audit metrics.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Verification logic (NEW) | `services/audit_service/verification.py` |
| Verification tests (NEW) | `tests/test_audit/test_verification.py` |
| Metrics definitions | `ops/metrics.py` |
| Alerting rules | `ops/alerting_rules.yml` |
| Chain logic | `services/audit_service/chain.py` |

### Verification Schedule

| Check | Frequency | Scope | Alert on Failure |
|---|---|---|---|
| Continuous (last 100) | Every 5 minutes | Per-tenant, last 100 records | `AluskortAuditChainBroken` |
| Full chain | Daily 03:00 UTC | Per-tenant, entire hot tier | `AluskortAuditIntegrityFailed` |
| Kafka-vs-Postgres lag | Hourly | All tenants | `AluskortAuditLagHigh` |
| Cold spot-check | Weekly | Random 100 records from S3 | `AluskortAuditColdCorruption` |

### Existing Test Classes That MUST Still Pass (Unchanged)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**, **pytest-asyncio**
- Chain verification: construct valid and tampered chains in memory, verify detection
- Scheduler: mock time, verify checks run at correct intervals
- Metrics: mock Prometheus gauge, verify set calls
- No real Kafka or Postgres needed for unit tests

### Dependencies on Other Stories

- **Story 13.4** (Audit Service Core): `compute_record_hash()` for verification
- **Story 13.5** (Evidence Store): cold storage spot-check

### References

- [Source: docs/audit-architecture.md Section 4.3] — Verification schedule specification
- [Source: docs/audit-architecture.md Section 12] — Alerting requirements
- [Source: docs/prd.md#NFR-CMP-001] — Audit trail integrity

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

No issues encountered. All existing implementation verified correct on first pass.

### Completion Notes List

- **Task 1:** `verify_tenant_chain()` and `verify_recent()` implemented in `services/audit_service/verification.py`. Reuses `compute_record_hash()` and `verify_chain()` from `chain.py` (Story 13.4). 8 unit tests in `TestVerifyTenantChain` + `TestVerifyRecent` — all pass.
- **Task 2:** `VerificationScheduler` class with 4-tier checks: `run_continuous_check()` (5-min, last 100), `run_daily_full_check()` (daily full chain), `run_hourly_lag_check()` (Kafka vs Postgres lag), `run_weekly_cold_check()` (random S3 sample). All results persisted to `audit_verification_log`. 6 tests in `TestVerificationScheduler` — all pass.
- **Task 3:** 3 Prometheus metrics added to `ops/metrics.py` (`aluskort_audit_chain_valid`, `aluskort_audit_kafka_lag`, `aluskort_audit_verification_duration_seconds`). 4 alerting rules added to `ops/alerting_rules.yml` (`AluskortAuditChainBroken`, `AluskortAuditLagHigh`, `AluskortAuditIntegrityFailed`, `AluskortAuditColdCorruption`). 4 tests in `TestVerificationMetrics` — all pass.
- **Task 4:** Full regression suite: 1594 tests passed, zero failures (24.33s).

### File List

**Created:**
- `services/audit_service/verification.py` — verify_tenant_chain, verify_recent, VerificationScheduler
- `tests/test_audit/test_verification.py` — 18 verification tests (TestVerifyTenantChain, TestVerifyRecent, TestVerificationScheduler, TestVerificationMetrics)

**Modified:**
- `ops/metrics.py` — added AUDIT_VERIFICATION_METRICS (3 metrics: chain_valid gauge, kafka_lag gauge, verification_duration histogram)
- `ops/alerting_rules.yml` — added 4 audit chain alerting rules (ChainBroken, LagHigh, IntegrityFailed, ColdCorruption)

### Change Log

- 2026-02-24: Story 13.7 verified and completed — chain verification functions, 4-tier scheduled verification, Prometheus metrics, alerting rules. 18 new tests, 1594 total tests passing.
