# Story 14.1: Resolve Neo4j / CTEM Fallback

Status: review

## Story

As a platform ensuring CTEM scoring works without Neo4j,
I want `ZONE_CONSEQUENCE_FALLBACK` promoted to a first-class YAML-driven module with full zone coverage and unit tests,
so that CTEM consequence scoring produces correct results when Neo4j is unavailable.

## Acceptance Criteria

1. **Given** Neo4j is down, **When** CTEM consequence scoring runs, **Then** it produces correct severity for every `asset_zone` value using the YAML fallback config.
2. **Given** every `asset_zone` in test fixtures, **When** checked, **Then** each has a fallback consequence mapping.
3. **Given** the YAML config, **When** loaded, **Then** it covers all `asset_zone` values that appear in CTEM findings.
4. **Given** the two existing hardcoded fallback dicts, **When** consolidated, **Then** a single YAML config replaces both.

## Tasks / Subtasks

- [x] Task 1: Create YAML fallback configuration (AC: 1, 3, 4)
  - [x] 1.1: Create `shared/config/zone_consequences.yaml` with full zone-to-consequence-to-severity mapping:
    ```yaml
    zone_consequence:
      Zone0_PhysicalProcess: {consequence_class: "safety_life", severity: "CRITICAL"}
      Zone1_EdgeInference: {consequence_class: "equipment", severity: "HIGH"}
      Zone2_Operations: {consequence_class: "downtime", severity: "MEDIUM"}
      Zone3_Enterprise: {consequence_class: "data_loss", severity: "LOW"}
      Zone4_External: {consequence_class: "data_loss", severity: "LOW"}
    default_consequence_class: "data_loss"
    default_severity: "LOW"
    ```
  - [x] 1.2: Add additional zones if referenced elsewhere in codebase (scan for `asset_zone` usage).
- [x] Task 2: Create YAML loader module (AC: 1, 3)
  - [x] 2.1: Create `shared/config/zone_config.py` with:
    - `load_zone_consequences(path: str | None = None) -> dict` — loads YAML, returns structured dict
    - `get_consequence_class(asset_zone: str) -> str` — returns consequence class for zone, defaults to `"data_loss"`
    - `get_severity(asset_zone: str) -> str` — returns severity string for zone, defaults to `"LOW"`
    - `get_consequence_for_zone(asset_zone: str) -> tuple[str, str]` — returns `(consequence_class, severity)` tuple
  - [x] 2.2: Cache loaded config (load once, reuse). Config is read at startup.
  - [x] 2.3: Add unit tests in `tests/test_config/test_zone_config.py` — `TestZoneConfig` class: YAML loads, all zones return correct values, unknown zone returns default, caching works. (~6 tests)
- [x] Task 3: Replace hardcoded dicts in CTEM normaliser (AC: 1, 4)
  - [x] 3.1: In `ctem_normaliser/models.py`, remove `ZONE_CONSEQUENCE_FALLBACK` dict (lines 71-77). Import `get_consequence_class` from `shared/config/zone_config.py`.
  - [x] 3.2: In `ctem_normaliser/wiz.py`, replace `ZONE_CONSEQUENCE_FALLBACK.get(asset_zone, "data_loss")` (line 97) with `get_consequence_class(asset_zone)`.
  - [x] 3.3: In `shared/db/neo4j_graph.py`, remove `ZONE_CONSEQUENCE_FALLBACK` dict (lines 13-18). Import `get_severity` from `shared/config/zone_config.py`.
  - [x] 3.4: Update any tests that reference the old hardcoded dicts.
- [x] Task 4: Add full coverage tests (AC: 2)
  - [x] 4.1: Add `TestZoneCoverage` class: every zone in CTEM test fixtures has a mapping in YAML config.
  - [x] 4.2: Add `TestFallbackBehavior` class: Neo4j unavailable → YAML fallback produces correct severity for all zones. (~4 tests)
- [x] Task 5: Run full regression (AC: 1-4)
  - [x] 5.1: Run full project test suite (`pytest tests/`) — all 1716 tests pass (zero regressions)
  - [x] 5.2: Verify CTEM normaliser tests still pass: `pytest tests/test_ctem_normaliser/ -v`

## Dev Notes

### Critical Architecture Constraints

- **REM-H01 finding**: `ZONE_CONSEQUENCE_FALLBACK` is currently duplicated in TWO places with DIFFERENT semantics:
  - `ctem_normaliser/models.py:71-77` — maps zone names → consequence classes (e.g., "Zone0_PhysicalProcess" → "safety_life")
  - `shared/db/neo4j_graph.py:13-18` — maps consequence classes → severity strings (e.g., "safety_life" → "CRITICAL")
- **Consolidate into single YAML** — the YAML config provides the full chain: zone → consequence_class → severity.
- **Effort: S (1 day)** — this is a small, surgical change. Do not over-engineer.
- **DO NOT modify Neo4j query logic** — only the fallback behavior changes. When Neo4j is available, it remains the primary source.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `ZONE_CONSEQUENCE_FALLBACK` (1) | `ctem_normaliser/models.py:71-77` | Zone → consequence class. **Replace with YAML.** |
| `ZONE_CONSEQUENCE_FALLBACK` (2) | `shared/db/neo4j_graph.py:13-18` | Consequence class → severity. **Replace with YAML.** |
| Wiz normaliser | `ctem_normaliser/wiz.py:97` | Uses fallback dict. **Update import.** |
| CTEM correlator | `orchestrator/agents/ctem_correlator.py` | Uses Neo4j graph. **Verify still works.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| YAML config (NEW) | `shared/config/zone_consequences.yaml` |
| YAML loader (NEW) | `shared/config/zone_config.py` |
| Config tests (NEW) | `tests/test_config/test_zone_config.py` |
| CTEM models | `ctem_normaliser/models.py` |
| Wiz normaliser | `ctem_normaliser/wiz.py` |
| Neo4j graph | `shared/db/neo4j_graph.py` |

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_ctem_normaliser/ (16 tests):**
- `test_models.py` — model tests (update references to removed dict)
- `test_wiz.py` — Wiz normaliser tests

**test_db/test_neo4j_graph.py:**
- Neo4j graph tests (update references to removed dict)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**
- Pure synchronous tests (YAML loading, dict lookups)
- Test YAML coverage: every zone in test fixtures has a config entry
- Test fallback: mock Neo4j as unavailable, verify YAML-driven results

### Dependencies on Other Stories

- **None.** Can start immediately. Independent of all other Sprint 2 stories.

### References

- [Source: docs/remediation-backlog.md#REM-H01] — Neo4j fallback finding
- [Source: docs/prd.md#FR-CTM-005] — CTEM scoring requirement
- [Source: docs/prd.md#NFR-REL-005] — Reliability requirement

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- No regressions. All 1716 tests passed. Existing tests for `ZONE_CONSEQUENCE_FALLBACK` in both `test_models.py` and `test_neo4j_graph.py` pass unchanged because the backward-compatible `ZONE_CONSEQUENCE_FALLBACK` module-level dicts are now populated from YAML at import time.

### Completion Notes List

- **Task 1 (YAML Config):** Created `zone_consequences.yaml` with 5 zones mapping to consequence_class and severity. Defaults: `data_loss` / `LOW`. Scanned codebase — no additional zones beyond the 5 standard ones.
- **Task 2 (Loader Module):** Created `zone_config.py` with `load_zone_consequences()`, `get_consequence_class()`, `get_severity()`, `get_consequence_for_zone()`. Module-level cache via `_config` global. `_reset_cache()` for testing. 15 tests in `TestZoneConfig`.
- **Task 3 (Replace Hardcoded):** In `models.py`, replaced static dict with `_get_zone_consequence_fallback()` that loads from YAML. In `wiz.py`, replaced `ZONE_CONSEQUENCE_FALLBACK.get()` with `get_consequence_class()`. In `neo4j_graph.py`, replaced static dict with `_get_zone_consequence_fallback()` that extracts consequence-class-to-severity from YAML. Both modules still export `ZONE_CONSEQUENCE_FALLBACK` for backward compat.
- **Task 4 (Coverage Tests):** `TestZoneCoverage` (2 tests): verifies all wiz `_ZONE_MAP` zones and standard 5 zones have YAML entries. `TestFallbackBehavior` (6 tests): verifies correct severity for all zones, and that both `neo4j_graph` and `models` fallback dicts are YAML-driven.
- **Task 5 (Regression):** 1716 tests passed, 0 failures. All 152 CTEM tests pass. All 19 Neo4j graph tests pass.

### File List

**Created:**
- `shared/config/__init__.py` — Package init
- `shared/config/zone_consequences.yaml` — Zone-to-consequence-to-severity YAML config
- `shared/config/zone_config.py` — YAML loader with caching, get_consequence_class, get_severity
- `tests/test_config/__init__.py` — Package init
- `tests/test_config/test_zone_config.py` — 23 tests across 3 classes

**Modified:**
- `ctem_normaliser/models.py` — replaced hardcoded ZONE_CONSEQUENCE_FALLBACK with YAML-driven function
- `ctem_normaliser/wiz.py` — replaced dict import with get_consequence_class() from zone_config
- `shared/db/neo4j_graph.py` — replaced hardcoded ZONE_CONSEQUENCE_FALLBACK with YAML-driven function

### Change Log

- 2026-02-24: Story 14.1 implemented — consolidated two hardcoded ZONE_CONSEQUENCE_FALLBACK dicts into single YAML config with loader module. 23 new tests, 1716 total tests passing. Backward-compatible: existing imports still work.
