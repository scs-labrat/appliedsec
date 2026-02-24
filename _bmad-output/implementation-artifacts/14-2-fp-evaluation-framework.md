# Story 14.2: FP Evaluation Framework

Status: review

## Story

As a platform measuring auto-closure accuracy,
I want precision/recall targets (precision >= 98%, recall >= 95%, FNR < 0.5%) with stratified sampling (by rule family, severity, asset criticality, novelty) and continuous monitoring,
so that FP auto-closure quality is measured rigorously and continuously.

## Acceptance Criteria

1. **Given** weekly sampling, **When** stratified, **Then** minimum 30 alerts per stratum are reviewed.
2. **Given** new FP patterns (first 30 days), **When** sampled, **Then** 100% of their closures are reviewed.
3. **Given** daily monitoring, **When** an auto-closed alert is later escalated by another source, **Then** it is automatically flagged as a potential false negative.
4. **Given** precision/recall metrics, **When** exported to Prometheus, **Then** `aluskort_fp_precision` and `aluskort_fp_recall` per rule family are available.
5. **Given** precision >= 98% and FNR < 0.5%, **When** both satisfied continuously, **Then** autonomy thresholds remain at defaults.

## Tasks / Subtasks

- [x] Task 1: Create FP evaluation data models (AC: 1, 4)
  - [x] 1.1: Create `orchestrator/fp_evaluation.py` with:
    - `FPEvaluationResult` dataclass: `rule_family: str`, `total_closures: int`, `true_positives: int`, `false_positives: int`, `false_negatives: int`, `precision: float`, `recall: float`, `fnr: float`
    - `StratumConfig` dataclass: `rule_family: str`, `severity: str`, `asset_criticality: str`, `min_sample_size: int = 30`
    - `PRECISION_TARGET = 0.98`, `RECALL_TARGET = 0.95`, `FNR_CEILING = 0.005`
  - [x] 1.2: Add unit tests — `TestFPEvaluationModels` class: precision/recall computed correctly, FNR computed correctly, target constants defined. (~4 tests)
- [x] Task 2: Create stratified sampling (AC: 1, 2)
  - [x] 2.1: Add `FPEvaluationFramework` class with:
    - `compute_strata(closures: list[dict]) -> dict[str, list[dict]]` — groups closures by (rule_family, severity, asset_criticality)
    - `select_sample(strata: dict, min_per_stratum: int = 30) -> list[dict]` — selects minimum 30 per stratum, 100% for patterns < 30 days old
    - `is_novel_pattern(pattern_id: str, pattern_created_at: str, cutoff_days: int = 30) -> bool` — returns True if pattern is < 30 days old
  - [x] 2.2: Novel patterns (< 30 days) get 100% review — all closures from that pattern are included in the sample.
  - [x] 2.3: Add unit tests — `TestStratifiedSampling` class: strata grouped correctly, sample >= 30 per stratum, novel patterns get 100% review, empty strata handled. (~6 tests)
- [x] Task 3: Create continuous monitoring (AC: 3, 5)
  - [x] 3.1: Add `DailyFNDetector` class:
    - `check_auto_closed_escalated(closures: list[dict], escalations: list[dict]) -> list[dict]` — finds alerts that were auto-closed but later escalated by another source
    - `flag_potential_false_negative(closure: dict) -> dict` — marks closure for review
  - [x] 3.2: Add `AutonomyGuard`:
    - `should_reduce_autonomy(evaluation: FPEvaluationResult) -> bool` — returns True if precision < 98% or FNR > 0.5%
    - `get_adjusted_threshold(current_threshold: float, evaluation: FPEvaluationResult) -> float` — returns raised threshold if targets not met
  - [x] 3.3: Add unit tests — `TestDailyFNDetector` class: escalated closure flagged, non-escalated not flagged. `TestAutonomyGuard` class: targets met → no change, precision below 98% → reduce autonomy. (~6 tests)
- [x] Task 4: Add Prometheus metrics (AC: 4)
  - [x] 4.1: Add to `ops/metrics.py`:
    - `aluskort_fp_precision` (gauge, labels: rule_family) — current precision per rule family
    - `aluskort_fp_recall` (gauge, labels: rule_family) — current recall per rule family
    - `aluskort_fp_false_negative_rate` (gauge, labels: rule_family) — current FNR per rule family
    - `aluskort_fp_evaluation_sample_size` (gauge, labels: rule_family, stratum) — sample size per stratum
  - [x] 4.2: Add unit tests — `TestFPMetrics` class: metrics defined with correct labels. (~2 tests)
- [x] Task 5: Run full regression (AC: 1-5)
  - [x] 5.1: Run full project test suite (`pytest tests/`) — all 1743 tests pass (zero regressions)

## Dev Notes

### Critical Architecture Constraints

- **REM-H02 Part A** — the current FP evaluation is "weekly analyst audit sample" with no defined sample size, stratification, or continuous monitoring.
- **Stratified sampling prevents bias** — sampling only from common strata would miss rare but important FP categories.
- **100% review for novel patterns** — new patterns (< 30 days) have no track record. All closures must be reviewed until confidence is established.
- **Daily monitoring catches false negatives** — an auto-closed alert later escalated by another source is a potential missed TP.
- **DO NOT modify `FPShortCircuit`** — this story measures accuracy, it does not change the FP matching logic.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `FPShortCircuit` | `orchestrator/fp_shortcircuit.py` | FP matching. **Source of closures to evaluate.** |
| `FP_CONFIDENCE_THRESHOLD` | `orchestrator/fp_shortcircuit.py:18` | `0.90`. **Reference for autonomy threshold.** |
| `aluskort_fp_shortcircuit_total` | `ops/metrics.py:144-148` | Existing FP counter. **Complements new precision/recall.** |
| `FPPattern` | `batch_scheduler/models.py:94-118` | Pattern model. **Has `created_at` for novelty check.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| FP evaluation (NEW) | `orchestrator/fp_evaluation.py` |
| FP evaluation tests (NEW) | `tests/test_orchestrator/test_fp_evaluation.py` |
| FP short-circuit | `orchestrator/fp_shortcircuit.py` |
| FP pattern model | `batch_scheduler/models.py` |
| Metrics | `ops/metrics.py` |

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_orchestrator/ (17 tests for response agent, 6 integration):**
- All unchanged

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**
- Pure synchronous tests (precision/recall math, sampling logic)
- Test stratified sampling with crafted closure data
- Test novelty detection with pattern created_at timestamps
- Mock Prometheus gauges for metric tests

### Dependencies on Other Stories

- **None.** Can start immediately.

### References

- [Source: docs/remediation-backlog.md#REM-H02 Part A] — FP evaluation framework requirements
- [Source: docs/prd.md#FR-RSN-006] — FP pattern accuracy requirement
- [Source: docs/prd.md#NFR-OBS-001] — Observability requirement

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- 1 regression in `test_ops/test_metrics.py::TestAllMetrics::test_total_count` — expected 32 metrics but found 36 after adding 4 FP evaluation metrics. Fixed by updating expected count to include +4 FP evaluation metrics.

### Completion Notes List

- **Task 1 (Data Models):** Created `FPEvaluationResult` dataclass with `compute_metrics()` for precision/recall/FNR computation. `StratumConfig` with default `min_sample_size=30`. Target constants: `PRECISION_TARGET=0.98`, `RECALL_TARGET=0.95`, `FNR_CEILING=0.005`. 6 tests in `TestFPEvaluationModels`.
- **Task 2 (Stratified Sampling):** `FPEvaluationFramework` with `compute_strata()` grouping by `(rule_family:severity:asset_criticality)`, `select_sample()` ensuring min 30 per stratum with 100% review for novel patterns (< 30 days old), `is_novel_pattern()` date check. 8 tests in `TestStratifiedSampling`.
- **Task 3 (Continuous Monitoring):** `DailyFNDetector` with `check_auto_closed_escalated()` cross-referencing closures and escalations, `flag_potential_false_negative()` adding review metadata. `AutonomyGuard` with `should_reduce_autonomy()` checking precision/FNR targets, `get_adjusted_threshold()` raising by 0.02 per violation (capped at 0.99). 10 tests across `TestDailyFNDetector` (4) and `TestAutonomyGuard` (6).
- **Task 4 (Prometheus Metrics):** Added 4 gauge metrics to `ops/metrics.py`: `aluskort_fp_precision`, `aluskort_fp_recall`, `aluskort_fp_false_negative_rate`, `aluskort_fp_evaluation_sample_size`. All labelled by `rule_family`. 3 tests in `TestFPMetrics`.
- **Task 5 (Regression):** 1743 tests passed, 0 failures. 1 existing test updated for new metric count.

### File List

**Created:**
- `orchestrator/fp_evaluation.py` — FPEvaluationResult, StratumConfig, FPEvaluationFramework, DailyFNDetector, AutonomyGuard
- `tests/test_orchestrator/test_fp_evaluation.py` — 27 tests across 6 classes

**Modified:**
- `ops/metrics.py` — added FP_EVALUATION_METRICS (4 gauges), added to ALL_METRICS
- `tests/test_ops/test_metrics.py` — updated expected total metric count (+4)

### Change Log

- 2026-02-24: Story 14.2 implemented — FP evaluation framework with stratified sampling, daily FN detection, autonomy guardrails, and 4 Prometheus metrics. 27 new tests, 1743 total tests passing.
