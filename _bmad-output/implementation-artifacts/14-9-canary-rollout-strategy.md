# Story 14.9: Canary Rollout Strategy

Status: review

## Story

As a platform safely promoting autonomy,
I want canary slicing options (by tenant, severity band, rule family, data source) with automated promotion criteria (7 days no missed TPs, precision >= 98%) and automatic rollback when precision drops below 95%,
so that autonomy is expanded incrementally with automatic safety nets.

## Acceptance Criteria

1. **Given** canary rollout for a rule family, **When** 7 days pass with no missed TPs and precision >= 98%, **Then** the canary is automatically promoted.
2. **Given** a precision drop below 95% in canary, **When** detected, **Then** automatic rollback to shadow mode occurs.
3. **Given** a missed TP in canary, **When** detected, **Then** automatic rollback and `kill_switch.activated` audit event is emitted.
4. **Given** rollout history, **When** queried, **Then** all promotion/rollback events are visible in audit trail.

## Tasks / Subtasks

- [x] Task 1: Create CanarySlice configuration (AC: 1)
  - [x] 1.1: Created `orchestrator/canary.py` with `CanarySlice` and `CanaryConfig` dataclasses.
  - [x] 1.2: Added `TestCanarySlice` — 3 tests.
- [x] Task 2: Create CanaryRolloutManager (AC: 1, 2, 3, 4)
  - [x] 2.1: Added `CanaryRolloutManager` with `check_promotion()`, `promote()`, `rollback()`, `get_rollout_history()`.
  - [x] 2.2: Rollback activates kill switch via KillSwitchManager (Story 14.3).
  - [x] 2.3: Rollback reverts dimension to shadow via KillSwitchManager.
  - [x] 2.4: All promotion and rollback events emitted to audit trail.
  - [x] 2.5: Added `TestCanaryRolloutManager` — 10 tests.
- [x] Task 3: Create canary evaluation loop (AC: 1, 2, 3)
  - [x] 3.1: Added `CanaryEvaluator` with `evaluate_all_slices()`.
  - [x] 3.2: Integration with FPEvaluationFramework for per-slice precision data.
  - [x] 3.3: Added `TestCanaryEvaluator` — 4 tests.
- [x] Task 4: Run full regression (AC: 1-4)
  - [x] 4.1: Run full project test suite — all 1906 tests pass (zero regressions)

## Dev Notes

### Critical Architecture Constraints

- **REM-H05 Part B** — canary rollout is the safe path from shadow mode to full autonomy. Autonomy is expanded slice-by-slice, not all-at-once.
- **4 slicing dimensions**: tenant, severity band, rule family, data source. Start with least-risk slices (low severity, well-understood rule families).
- **Automatic promotion** — no human intervention needed when criteria are met for 7 days. This incentivizes good system behavior.
- **Automatic rollback** — precision drop below 95% OR any missed TP triggers immediate rollback. This is the safety net.
- **Rollback activates kill switch** — ensures the affected slice is immediately disabled via the kill switch infrastructure (Story 14.3).
- **Full audit trail** — every promotion and rollback is logged for compliance.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `KillSwitchManager` | `orchestrator/kill_switch.py` (Story 14.3) | Emergency disable. **Activate on rollback.** |
| `ShadowModeManager` | `orchestrator/shadow_mode.py` (Story 14.8) | Shadow mode. **Revert to on rollback.** |
| `FPEvaluationFramework` | `orchestrator/fp_evaluation.py` (Story 14.2) | Precision/recall. **Source of promotion data.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Canary rollout (NEW) | `orchestrator/canary.py` |
| Canary tests (NEW) | `tests/test_orchestrator/test_canary.py` |
| Kill switch manager | `orchestrator/kill_switch.py` |
| Shadow mode manager | `orchestrator/shadow_mode.py` |
| FP evaluation | `orchestrator/fp_evaluation.py` |

### Canary Lifecycle

```
New Tenant / New Rule Family
    │
    ▼
SHADOW MODE (Story 14.8)
    │ (agreement >= 95% for 2 weeks)
    ▼
CANARY SLICE (this story)
    │ (7 days, precision >= 98%, 0 missed TPs)
    ├──── promote → ACTIVE AUTONOMY
    └──── rollback → SHADOW MODE + KILL SWITCH
              (precision < 95% or missed TP)
```

### Existing Test Classes That MUST Still Pass (Unchanged)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**, **pytest-asyncio**
- Mock KillSwitchManager, ShadowModeManager for rollback tests
- Mock FPEvaluationFramework for precision data
- Test time-based promotion with frozen time (7 days elapsed)
- Test rollback triggers (precision < 95%, missed TP)

### Dependencies on Other Stories

- **Story 14.8** (Shadow Mode): canary starts after shadow
- **Story 14.3** (Kill Switches): rollback activates kill switch
- **Story 14.2** (FP Evaluation): provides precision/recall data
- **Epic 12 (12.2-12.10)**: multi-provider + injection hardening

### References

- [Source: docs/remediation-backlog.md#REM-H05 Part B] — Canary rollout requirements
- [Source: docs/ai-system-design.md Section 10] — Deployment safety

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- No regressions. Clean first-pass implementation.

### Completion Notes List

- **Task 1 (CanarySlice):** `CanarySlice` dataclass with `slice_id`, `dimension` (tenant/severity/rule_family/datasource), `value`, `status` (active/promoted/rolled_back), `age_days` property. `CanaryConfig` with promotion_days=7, min_precision=0.98, rollback_precision=0.95. 3 tests.
- **Task 2 (CanaryRolloutManager):** `check_promotion()` returns "promote"/"rollback"/"continue" based on age, precision, missed TPs. `promote()` marks slice as promoted + audit. `rollback()` marks slice as rolled_back, activates kill switch via KillSwitchManager, emits audit. `get_rollout_history()` returns all events. 10 tests.
- **Task 3 (CanaryEvaluator):** `evaluate_all_slices()` iterates active slices, gets precision from FPEvaluationFramework, triggers promote/rollback/continue. 4 tests.
- **Task 4 (Regression):** 1906 tests passed, 0 failures. Zero regressions — story only creates new files.

### File List

**Created:**
- `orchestrator/canary.py` — CanarySlice, CanaryConfig, CanaryRolloutManager, CanaryEvaluator
- `tests/test_orchestrator/test_canary.py` — 17 tests (3 slice + 10 manager + 4 evaluator)

**Modified:**
- None (uses interfaces from Stories 14.2, 14.3, 14.8)

### Change Log

- 2026-02-24: Story 14.9 implemented — Canary rollout strategy with 4 slicing dimensions, automatic promotion (7 days, precision >= 98%, 0 missed TPs), automatic rollback (precision < 95% or missed TP → kill switch), full audit trail. 17 new tests, 1906 total tests passing.
