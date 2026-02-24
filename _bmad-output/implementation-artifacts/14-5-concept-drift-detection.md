# Story 14.5: Concept Drift Detection

Status: review

## Story

As a platform adapting to changing threat landscapes,
I want monitoring of distribution shifts in alert source mix, technique frequency, and entity patterns, with automatic autonomy reduction (raise confidence threshold from 0.90 to 0.95) when drift is detected,
so that the system degrades safely when the data distribution changes.

## Acceptance Criteria

1. **Given** a shift in alert source distribution, **When** drift score exceeds threshold, **Then** auto-close confidence threshold is raised from 0.90 to 0.95 within 1 hour.
2. **Given** drift detection triggering, **When** triggered, **Then** review sampling rate is increased (from Story 14.2 FP evaluation framework).
3. **Given** Prometheus metrics, **When** scraped, **Then** `aluskort_fp_drift_score{rule_family}` is available.
4. **Given** drift restoration, **When** distribution normalizes, **Then** confidence threshold returns to 0.90.

## Tasks / Subtasks

- [x] Task 1: Create drift detection engine (AC: 1, 3)
  - [x] 1.1: Create `orchestrator/drift_detection.py` with `DriftDetector` class:
    - `__init__(self, window_days: int = 7, baseline_days: int = 30, drift_threshold: float = 0.3)`
    - `compute_source_drift(current_distribution: dict[str, int], baseline_distribution: dict[str, int]) -> float` — Jensen-Shannon divergence between current and baseline alert source distributions
    - `compute_technique_drift(current_frequencies: dict[str, int], baseline_frequencies: dict[str, int]) -> float` — distribution shift in technique frequency
    - `compute_entity_drift(current_patterns: dict[str, int], baseline_patterns: dict[str, int]) -> float` — shift in entity type distribution
    - `compute_overall_drift(source: float, technique: float, entity: float) -> float` — weighted average of three dimensions
  - [x] 1.2: Add `DriftState` dataclass: `source_drift: float`, `technique_drift: float`, `entity_drift: float`, `overall_drift: float`, `threshold_exceeded: bool`, `detected_at: str`.
  - [x] 1.3: Add unit tests in `tests/test_orchestrator/test_drift_detection.py` — `TestDriftDetector` class: identical distributions → 0 drift, completely different → high drift, partial shift → medium drift, overall weighted correctly. (~6 tests)
- [x] Task 2: Create confidence threshold adjuster (AC: 1, 4)
  - [x] 2.1: Add `ThresholdAdjuster` class:
    - `__init__(self, normal_threshold: float = 0.90, elevated_threshold: float = 0.95)`
    - `get_threshold(drift_state: DriftState) -> float` — returns `elevated_threshold` if `drift_state.threshold_exceeded`, else `normal_threshold`
    - `is_elevated() -> bool` — returns current state
  - [x] 2.2: Make `FP_CONFIDENCE_THRESHOLD` in `orchestrator/fp_shortcircuit.py` configurable — added `threshold_adjuster` parameter and `_get_effective_threshold()` method.
  - [x] 2.3: Add unit tests — `TestThresholdAdjuster` class: drift exceeded → 0.95, drift normal → 0.90, transition back to normal. (~4 tests)
- [x] Task 3: Add Prometheus metrics (AC: 3)
  - [x] 3.1: Add to `ops/metrics.py`:
    - `aluskort_fp_drift_score` (gauge, labels: rule_family, dimension) — drift score per dimension
    - `aluskort_fp_confidence_threshold` (gauge) — current effective threshold
  - [x] 3.2: Add unit tests — metrics defined with correct labels. (~2 tests)
- [x] Task 4: Integrate drift → evaluation framework (AC: 2)
  - [x] 4.1: When drift is detected, signal `FPEvaluationFramework` (Story 14.2) to increase sampling rate for affected rule families.
  - [x] 4.2: Add `DriftSamplingCallback` with `on_drift_detected(rule_families)` and `on_drift_restored()`.
  - [x] 4.3: Add unit tests — `TestDriftIntegration` class: drift triggers increased sampling, normal drift restores default sampling. (~3 tests)
- [x] Task 5: Run full regression (AC: 1-4)
  - [x] 5.1: Run full project test suite (`pytest tests/`) — all 1820 tests pass (zero regressions)

## Dev Notes

### Critical Architecture Constraints

- **REM-H02 Part D** — concept drift detection is the automated safety net for changing data distributions.
- **Three dimensions monitored**: alert source mix, technique frequency, entity patterns. Each has independent drift scores.
- **Confidence threshold change is automatic** — no human intervention needed. When drift is detected, threshold rises from 0.90 to 0.95 (fewer auto-closes, more human review).
- **Threshold returns to normal when drift subsides** — this is not a one-way ratchet.
- **DO NOT change FP matching logic** — only the confidence threshold changes. The matching algorithm remains the same.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `FP_CONFIDENCE_THRESHOLD` | `orchestrator/fp_shortcircuit.py:18` | `0.90` constant. **Made configurable via ThresholdAdjuster.** |
| `FPShortCircuit.check()` | `orchestrator/fp_shortcircuit.py:61` | Uses threshold. **Reads from adjuster.** |
| `FPEvaluationFramework` | `orchestrator/fp_evaluation.py` (Story 14.2) | Sampling. **Signal to increase rate via DriftSamplingCallback.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Drift detection (NEW) | `orchestrator/drift_detection.py` |
| Drift tests (NEW) | `tests/test_orchestrator/test_drift_detection.py` |
| FP short-circuit | `orchestrator/fp_shortcircuit.py` |
| Metrics | `ops/metrics.py` |

### Existing Test Classes That MUST Still Pass (Unchanged)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**
- Pure synchronous tests (distribution math, threshold logic)
- Craft known distributions to verify drift computation
- Mock time for threshold transition tests

### Dependencies on Other Stories

- **Story 14.2** (FP Evaluation): sampling rate increase on drift
- **Story 14.3** (Kill Switches): threshold adjustment complements kill switches

### References

- [Source: docs/remediation-backlog.md#REM-H02 Part D] — Concept drift detection requirements
- [Source: docs/prd.md#NFR-OBS-001] — Observability requirement

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- No regressions. All tests passed on first run.

### Completion Notes List

- **Task 1 (Drift Detection Engine):** Created `DriftDetector` with Jensen-Shannon divergence for source, technique, and entity distributions. `detect()` runs all three dimensions and returns `DriftState` with `threshold_exceeded` flag. Weighted average: source 0.4, technique 0.35, entity 0.25. 11 tests in `TestDriftDetector`.
- **Task 2 (Threshold Adjuster):** `ThresholdAdjuster` with `get_threshold()` returning 0.95 when drift exceeded, 0.90 when normal. `update()` stores latest DriftState. `is_elevated()` returns current status. Integrated into `FPShortCircuit` via `threshold_adjuster` parameter and `_get_effective_threshold()`. Backward compat: None default uses static `FP_CONFIDENCE_THRESHOLD`. 7 tests in `TestThresholdAdjuster`.
- **Task 3 (Prometheus Metrics):** Added `DRIFT_DETECTION_METRICS` with 2 gauges: `aluskort_fp_drift_score` (labels: rule_family, dimension) and `aluskort_fp_confidence_threshold`. Added to `ALL_METRICS`. 3 tests in `TestDriftMetrics`.
- **Task 4 (Drift Integration):** `DriftSamplingCallback` with `on_drift_detected()` raising multiplier to 2x for affected rule families, `on_drift_restored()` resetting to 1x. `get_sample_multiplier()` checks per-family or global. 4 tests in `TestDriftIntegration`.
- **Task 5 (Regression):** 1820 tests passed, 0 failures. Updated expected metric count (+2).

### File List

**Created:**
- `orchestrator/drift_detection.py` — DriftDetector, DriftState, ThresholdAdjuster, DriftSamplingCallback
- `tests/test_orchestrator/test_drift_detection.py` — 25 tests across 4 classes

**Modified:**
- `orchestrator/fp_shortcircuit.py` — added threshold_adjuster parameter, _get_effective_threshold() method
- `ops/metrics.py` — added DRIFT_DETECTION_METRICS (2 gauges), added to ALL_METRICS
- `tests/test_ops/test_metrics.py` — updated expected total metric count (+2)

### Change Log

- 2026-02-24: Story 14.5 implemented — Concept drift detection with JSD divergence, automatic threshold adjustment (0.90 → 0.95), drift sampling callback, and 2 Prometheus metrics. 25 new tests, 1820 total tests passing.
