# Story 15.2: Dual-Decay Incident Memory Scoring

Status: review

## Story

As a platform remembering recurring APT campaigns,
I want a composite recency score blending short-term exponential decay (30-day half-life) with long-term logarithmic decay, and a "rare-but-important" floor for flagged incidents,
so that seasonally recurring threats are not forgotten.

## Acceptance Criteria

1. **Given** the composite score formula, **When** computed, **Then** `recency = 0.7 * exp(-0.023 * age_days) + 0.3 * (1.0 / (1.0 + log(1.0 + age_days / 365.0)))`.
2. **Given** a flagged "rare-but-important" incident, **When** scored, **Then** recency never drops below 0.1 regardless of age.
3. **Given** a 1-year-old incident with matching techniques, **When** scored, **Then** it ranks higher than a non-matching 1-week-old incident.

## Tasks / Subtasks

- [x] Task 1: Replace single decay with dual-decay formula (AC: 1)
  - [x] 1.1: Replaced single exponential with dual-decay formula in `score_incident()`.
  - [x] 1.2: Added `SHORT_TERM_WEIGHT = 0.7` and `LONG_TERM_WEIGHT = 0.3` constants.
  - [x] 1.3: Updated docstring with full dual-decay formula documentation.
  - [x] 1.4: Added `TestDualDecay` — 4 tests (age 0, 30, 365, 730).
- [x] Task 2: Add rare-but-important floor (AC: 2)
  - [x] 2.1: Added `is_rare_important: bool = False` parameter to `score_incident()`.
  - [x] 2.2: Added `RARE_IMPORTANT_FLOOR = 0.1` constant.
  - [x] 2.3: Applied floor after dual-decay computation.
  - [x] 2.4: Added `TestRareImportantFloor` — 3 tests (flagged old, unflagged old, flagged young).
- [x] Task 3: Add rare_important flag to incident memory (AC: 2)
  - [x] 3.1: Created `infra/migrations/010_incident_memory_rare.sql`.
  - [x] 3.2: Added `TestMigration` — 1 test (SQL validity).
- [x] Task 4: Verify ranking behavior (AC: 3)
  - [x] 4.1: Added `TestRankingBehavior` — 3 tests (technique match ranking, dual vs single at 365d, rare-important extreme age).
- [x] Task 5: Run full regression (AC: 1-3)
  - [x] 5.1: Run full project test suite — all 1939 tests pass (zero regressions)
  - [x] 5.2: Updated existing `test_scoring.py` tests for new dual-decay formula (expected value adjustments, not regressions)

## Dev Notes

### Critical Architecture Constraints

- **REM-M02** — the current single exponential decay (`exp(-0.023 * age_days)`) effectively forgets incidents after 60-90 days. APT campaigns recur seasonally (90-365 day cycles). The logarithmic component preserves long-term memory.
- **Effort: S (< 1 day)** — this is a surgical change to one function. Do not over-engineer.
- **Existing tests may need value updates** — the composite formula changes recency_decay values. Existing tests in `test_scoring.py` that assert specific composite values will need adjustment.
- **DO NOT change the weight constants (ALPHA, BETA, GAMMA, DELTA)** — only the recency_decay computation changes.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `score_incident()` | `shared/schemas/scoring.py:29-60` | Scoring function. **Modify recency computation.** |
| `LAMBDA = 0.023` | `shared/schemas/scoring.py:16` | Decay constant. **Keep for short-term.** |
| `IncidentScore` | `shared/schemas/scoring.py:19-26` | Score model. **recency_decay field stays.** |
| `ALPHA, BETA, GAMMA, DELTA` | `shared/schemas/scoring.py:10-13` | Weights. **Do NOT modify.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Scoring module | `shared/schemas/scoring.py` |
| Dual-decay tests (NEW) | `tests/test_schemas/test_scoring_dual_decay.py` |
| Migration (NEW) | `infra/migrations/010_incident_memory_rare.sql` |
| Existing scoring tests | `tests/test_schemas/test_scoring.py` |

### Formula Comparison

```
OLD:  recency = exp(-0.023 * age_days)
      At 30d: 0.50,  At 90d: 0.13,  At 365d: 0.0002

NEW:  recency = 0.7 * exp(-0.023 * age) + 0.3 * (1 / (1 + log(1 + age/365)))
      At 30d: 0.63,  At 90d: 0.35,  At 365d: 0.18

RARE: max(recency, 0.1) — floor for flagged incidents
```

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_schemas/test_scoring.py (4 tests):**
- These tests assert specific composite values. They will need value updates since recency_decay changes. This is an EXPECTED modification, not a regression.

**Total existing: 1169 tests — ALL must pass (some may need value adjustments).**

### Testing Patterns

- Test framework: **pytest**
- Pure synchronous math tests
- Test boundary values (age=0, age=30, age=365, age=1000)
- Test rare-but-important floor at extreme ages
- Verify long-term component preserves memory beyond 90 days

### Dependencies on Other Stories

- **None.** Can start immediately. Fully independent.

### References

- [Source: docs/remediation-backlog.md#REM-M02] — Dual-decay incident memory
- [Source: docs/prd.md#FR-RSN-004] — Incident memory scoring

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- 2 test failures on first pass: logarithmic decay slower than expected — unflagged recency at 1000 days was 0.129 (above 0.1 floor). Fixed by using 3000/5000 day ages where natural decay actually drops below floor.

### Completion Notes List

- **Task 1 (Dual-decay):** Replaced `recency = exp(-λ*t)` with `recency = 0.7 * exp(-λ*t) + 0.3 * (1/(1+log(1+t/365)))`. At 365 days: 0.18 (vs old 0.0002) — 900x better long-term memory. 4 tests.
- **Task 2 (Rare floor):** `is_rare_important=True` enforces `recency >= 0.1`. Floor only activates at extreme ages (~2300+ days) due to effective logarithmic decay. 3 tests.
- **Task 3 (Migration):** `ALTER TABLE incident_memory ADD COLUMN IF NOT EXISTS rare_important BOOLEAN DEFAULT FALSE`. 1 test.
- **Task 4 (Ranking):** Verified dual-decay provides meaningfully higher recency than single exponential at 365 days, and rare-important flag improves ranking at extreme ages. 3 tests.
- **Task 5 (Regression):** 1939 tests passed, 0 failures. Updated 2 existing tests in `test_scoring.py` for new formula (expected value adjustments, not regressions).

### File List

**Created:**
- `tests/test_schemas/test_scoring_dual_decay.py` — 11 tests (4 dual-decay + 3 rare floor + 1 migration + 3 ranking)
- `infra/migrations/010_incident_memory_rare.sql` — rare_important column

**Modified:**
- `shared/schemas/scoring.py` — dual-decay formula, SHORT_TERM_WEIGHT, LONG_TERM_WEIGHT, RARE_IMPORTANT_FLOOR, is_rare_important parameter
- `tests/test_schemas/test_scoring.py` — updated 2 decay tests for new dual-decay expected values, added imports

### Change Log

- 2026-02-24: Story 15.2 implemented — Dual-decay incident memory scoring with logarithmic long-term component, rare-but-important floor (0.1), DDL migration. 11 new tests, 1939 total tests passing.
