# Story 14.4: FP Pattern Governance

Status: review

## Story

As a platform with auditable FP pattern management,
I want two-person approval for auto-close patterns, 90-day expiry, blast-radius scoping ({rule_family, tenant, asset_class}), and a rollback workflow that re-opens closures from revoked patterns,
so that FP patterns have proper governance and can be safely revoked.

## Acceptance Criteria

1. **Given** a new FP pattern enabling auto-close, **When** submitted for approval, **Then** it requires two distinct approvers.
2. **Given** an approved pattern, **When** 90 days pass without reaffirmation, **Then** it expires and is deactivated.
3. **Given** a revoked pattern, **When** rolled back, **Then** all alerts closed by that pattern are re-opened for review.
4. **Given** pattern metadata, **When** stored, **Then** it includes `approved_by_1`, `approved_by_2`, `expiry_date`, `scope`, `reaffirmed_date`.
5. **Given** a blast-radius scope, **When** pattern applies, **Then** it only matches alerts within {rule_family, tenant, asset_class} scope.

## Tasks / Subtasks

- [x] Task 1: Extend FPPattern with governance fields (AC: 4)
  - [x] 1.1: Add governance fields to `FPPattern` in `batch_scheduler/models.py`:
    - `approved_by_1: str = ""`, `approved_by_2: str = ""`
    - `expiry_date: str = ""` (ISO 8601, 90 days from second approval)
    - `reaffirmed_date: str = ""`, `reaffirmed_by: str = ""`
    - `scope_rule_family: str = ""`, `scope_tenant_id: str = ""`, `scope_asset_class: str = ""`
  - [x] 1.2: Add `EXPIRED = "expired"` and `REVOKED = "revoked"` to `FPPatternStatus` enum.
  - [x] 1.3: Add DDL migration `infra/migrations/008_fp_governance.sql`:
    - `ALTER TABLE fp_patterns ADD COLUMN approved_by_2 TEXT DEFAULT ''`
    - `ALTER TABLE fp_patterns ADD COLUMN expiry_date TIMESTAMPTZ`
    - `ALTER TABLE fp_patterns ADD COLUMN reaffirmed_date TIMESTAMPTZ`
    - `ALTER TABLE fp_patterns ADD COLUMN reaffirmed_by TEXT DEFAULT ''`
    - `ALTER TABLE fp_patterns ADD COLUMN scope_rule_family TEXT DEFAULT ''`
    - `ALTER TABLE fp_patterns ADD COLUMN scope_tenant_id TEXT DEFAULT ''`
    - `ALTER TABLE fp_patterns ADD COLUMN scope_asset_class TEXT DEFAULT ''`
  - [x] 1.4: Add unit tests — `TestFPPatternGovernanceFields` class: new fields default correctly, expired/revoked statuses valid. (~4 tests)
- [x] Task 2: Create FPGovernanceManager (AC: 1, 2, 3)
  - [x] 2.1: Create `orchestrator/fp_governance.py` with `FPGovernanceManager` class:
    - `approve(pattern_id: str, approver: str) -> dict` — records approval. If first approver, sets `approved_by_1`. If second (distinct) approver, sets `approved_by_2`, computes `expiry_date = now + 90 days`, sets status to `approved`. Same person twice → raises `GovernanceError`.
    - `check_expiry(patterns: list[dict]) -> list[str]` — returns pattern_ids that have expired (expiry_date < now and not reaffirmed).
    - `reaffirm(pattern_id: str, reaffirmed_by: str) -> None` — extends expiry by 90 days, records reaffirmed_date.
    - `revoke(pattern_id: str, revoked_by: str) -> list[str]` — sets status to `revoked`, returns list of investigation_ids closed by this pattern for re-opening.
  - [x] 2.2: Add `GovernanceError(Exception)` for governance violations.
  - [x] 2.3: Add unit tests in `tests/test_orchestrator/test_fp_governance.py` — `TestFPGovernanceManager` class: two-person approval works, same-person twice rejected, expired patterns detected, reaffirmation extends expiry, revoke returns closed investigations. (~8 tests)
- [x] Task 3: Add blast-radius scope enforcement (AC: 5)
  - [x] 3.1: Add `matches_scope(pattern: dict, alert_rule_family: str, alert_tenant_id: str, alert_asset_class: str) -> bool` function — returns True only if pattern scope matches (empty scope = global).
  - [x] 3.2: Integrate scope check into `FPShortCircuit.check()` — after status and kill switch checks, verify scope match before confidence computation.
  - [x] 3.3: Add unit tests — `TestBlastRadiusScope` class: scoped pattern only matches within scope, global pattern matches everything, scope with wrong tenant rejected. (~4 tests)
- [x] Task 4: Add rollback workflow (AC: 3)
  - [x] 4.1: Add `rollback_pattern(pattern_id: str, postgres_client) -> int` method:
    - Query `investigations` table for entries with `decision_chain` containing `{"action": "auto_close_fp", "pattern_id": pattern_id}`
    - Re-open those investigations by setting `state` to `PARSING` (re-enter pipeline)
    - Return count of re-opened investigations
  - [x] 4.2: Emit `fp_pattern.revoked` audit event with `outcome.state_before` and `outcome.state_after`.
  - [x] 4.3: Add unit tests — `TestRollbackWorkflow` class: revoked pattern re-opens closed investigations, count returned correctly, audit event emitted. (~4 tests)
- [x] Task 5: Run full regression (AC: 1-5)
  - [x] 5.1: Run full project test suite (`pytest tests/`) — all 1795 tests pass (zero regressions)

## Dev Notes

### Critical Architecture Constraints

- **REM-H02 Part C + NFR-CMP-003** — FP patterns SHALL record `approved_by` and `approval_date`. Patterns SHALL have status lifecycle: `active | expired | revoked`.
- **Two-person approval** — same person cannot be both approver_1 and approver_2. This is a SOC 2 segregation-of-duties control.
- **90-day expiry** — patterns must be reaffirmed every 90 days or they auto-expire. Prevents stale patterns from running indefinitely.
- **Blast-radius scoping** — limits which alerts a pattern can close. Empty scope = global (existing behavior).
- **Rollback is disruptive** — re-opening closed investigations triggers re-processing. Use only when a pattern is confirmed incorrect.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `FPPattern` | `batch_scheduler/models.py:94-118` | Pattern model. **Extend with governance fields.** |
| `FPPatternStatus` | `batch_scheduler/models.py:33-39` | Status enum. **Add expired, revoked.** |
| `FPShortCircuit.check()` | `orchestrator/fp_shortcircuit.py:36-68` | Pattern matching. **Add scope check.** |
| `fp_patterns` table | `infra/migrations/001_core_tables.sql:164-177` | DB table. **Alter with new columns.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| FP governance (NEW) | `orchestrator/fp_governance.py` |
| DDL migration (NEW) | `infra/migrations/008_fp_governance.sql` |
| Governance tests (NEW) | `tests/test_orchestrator/test_fp_governance.py` |
| FP pattern model | `batch_scheduler/models.py` |
| FP short-circuit | `orchestrator/fp_shortcircuit.py` |

### Existing Test Classes That MUST Still Pass (Unchanged)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**, **pytest-asyncio**
- Test two-person approval with different and same approver strings
- Test expiry with time mocking (freeze time, advance 91 days)
- Test rollback with mocked Postgres queries

### Dependencies on Other Stories

- **Story 14.2** (FP Evaluation): provides accuracy data that informs revocation decisions
- **Story 14.3** (Kill Switches): kill switches complement governance (emergency disable)

### References

- [Source: docs/remediation-backlog.md#REM-H02 Part C] — FP pattern governance requirements
- [Source: docs/prd.md#NFR-CMP-003] — FP pattern status lifecycle
- [Source: docs/prd.md#FR-RSN-006] — FP pattern accuracy
- [Source: docs/prd.md#FR-CSM-004] — Compliance requirements

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- Updated `tests/test_orchestrator/test_fp_canary.py::TestShadowStatus::test_fp_pattern_status_has_five_values` → renamed to `test_fp_pattern_status_has_seven_values` and updated assertion from 5 to 7 (added EXPIRED, REVOKED).

### Completion Notes List

- **Task 1 (Governance Fields):** Added 8 governance fields to `FPPattern` dataclass: `approved_by_1`, `approved_by_2`, `expiry_date`, `reaffirmed_date`, `reaffirmed_by`, `scope_rule_family`, `scope_tenant_id`, `scope_asset_class`. Added `EXPIRED` and `REVOKED` to `FPPatternStatus` (now 7 values). DDL migration `008_fp_governance.sql` adds corresponding columns. 4 tests in `TestFPPatternGovernanceFields`.
- **Task 2 (FPGovernanceManager):** Created `orchestrator/fp_governance.py` with `FPGovernanceManager`. `approve()` implements two-person approval (same person raises `GovernanceError`). `check_expiry()` finds expired patterns. `reaffirm()` extends expiry by 90 days. `revoke()` sets status to revoked and returns investigation IDs. 9 tests in `TestFPGovernanceManager`.
- **Task 3 (Blast-Radius Scope):** Added `matches_scope()` function checking `scope_rule_family`, `scope_tenant_id`, `scope_asset_class` (empty = global). Integrated into `FPShortCircuit.check()` after kill switch check and before confidence computation. Added `alert_rule_family` and `alert_asset_class` parameters to `check()`. 7 tests in `TestBlastRadiusScope`.
- **Task 4 (Rollback Workflow):** `rollback_pattern()` queries Postgres for investigations closed by a pattern, re-opens them to PARSING state, emits `fp_pattern.revoked` audit events. 4 tests in `TestRollbackWorkflow`.
- **Task 5 (Regression):** 1795 tests passed, 0 failures. Existing canary test updated for new enum count.

### File List

**Created:**
- `orchestrator/fp_governance.py` — FPGovernanceManager, GovernanceError, matches_scope
- `infra/migrations/008_fp_governance.sql` — ALTER TABLE for governance columns
- `tests/test_orchestrator/test_fp_governance.py` — 24 tests across 4 classes

**Modified:**
- `batch_scheduler/models.py` — added 8 governance fields to FPPattern, added EXPIRED/REVOKED to FPPatternStatus
- `orchestrator/fp_shortcircuit.py` — added scope check via matches_scope(), added alert_rule_family/alert_asset_class params
- `tests/test_orchestrator/test_fp_canary.py` — updated enum count test (5 → 7)

### Change Log

- 2026-02-24: Story 14.4 implemented — FP pattern governance with two-person approval, 90-day expiry, blast-radius scoping, and rollback workflow. 24 new tests, 1795 total tests passing.
