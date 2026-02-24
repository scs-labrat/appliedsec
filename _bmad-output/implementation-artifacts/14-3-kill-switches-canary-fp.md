# Story 14.3: Kill Switches and Canary for FP Patterns

Status: review

## Story

As a SOC operator with emergency controls,
I want kill switches (disable auto-close) at per-tenant, per-FP-pattern, per-technique, per-data-source granularity, and canary rollout for new FP patterns (shadow mode → 50 correct decisions → active),
so that auto-close can be disabled instantly and new patterns are validated before activation.

## Acceptance Criteria

1. **Given** a kill switch activation, **When** triggered for a specific tenant, **Then** auto-close is disabled for that tenant within 1 minute.
2. **Given** a new FP pattern, **When** created, **Then** it starts in shadow mode and requires 50 correct decisions (configurable) before promotion.
3. **Given** shadow decisions disagree with analyst action > 5%, **When** evaluated, **Then** the pattern is NOT promoted.
4. **Given** kill switch activation, **When** logged, **Then** `kill_switch.activated` audit event is emitted to `audit.events`.
5. **Given** a kill switch at per-technique granularity, **When** triggered, **Then** auto-close is disabled for all alerts matching that technique ID.

## Tasks / Subtasks

- [x] Task 1: Create KillSwitchManager (AC: 1, 4, 5)
  - [x] 1.1: Create `orchestrator/kill_switch.py` with `KillSwitchManager` class:
    - `__init__(self, redis_client, audit_producer=None)`
    - `async activate(dimension: str, value: str, activated_by: str) -> None` — sets Redis key `kill_switch:{dimension}:{value}`, emits `kill_switch.activated` audit event
    - `async deactivate(dimension: str, value: str, deactivated_by: str) -> None` — removes Redis key, emits `kill_switch.deactivated`
    - `async is_killed(tenant_id: str, pattern_id: str = "", technique_id: str = "", data_source: str = "") -> bool` — checks all 4 dimensions, returns True if ANY kill switch is active
    - Dimensions: `tenant`, `pattern`, `technique`, `datasource`
  - [x] 1.2: Redis key pattern: `kill_switch:{dimension}:{value}` with metadata JSON (activated_by, activated_at, reason).
  - [x] 1.3: Add unit tests in `tests/test_orchestrator/test_kill_switch.py` — `TestKillSwitchManager` class: activate sets Redis key, is_killed returns True for active switch, deactivate removes key, audit event emitted on activate, per-technique kill switch blocks matching alerts. (~8 tests)
- [x] Task 2: Create FPCanaryManager (AC: 2, 3)
  - [x] 2.1: Create `orchestrator/fp_canary.py` with `FPCanaryManager` class:
    - `__init__(self, redis_client, promotion_threshold: int = 50, max_disagreement_rate: float = 0.05)`
    - `async record_shadow_decision(pattern_id: str, pattern_decision: str, analyst_decision: str) -> None` — records whether shadow decision agrees with analyst
    - `async get_canary_stats(pattern_id: str) -> dict` — returns `{total_decisions, agreements, disagreements, agreement_rate}`
    - `async should_promote(pattern_id: str) -> bool` — True if total >= promotion_threshold AND disagreement_rate <= max_disagreement_rate
    - `async promote(pattern_id: str) -> None` — changes pattern status from `shadow` to `active`
  - [x] 2.2: Shadow decision tracking stored in Redis: `canary:{pattern_id}:total`, `canary:{pattern_id}:agree`, `canary:{pattern_id}:disagree`.
  - [x] 2.3: Add unit tests — `TestFPCanaryManager` class: record increments counters, promotes after 50 agreements, does NOT promote if disagreement > 5%, does NOT promote if total < 50. (~6 tests)
- [x] Task 3: Integrate kill switches into FPShortCircuit (AC: 1, 5)
  - [x] 3.1: Add `kill_switch_manager: KillSwitchManager | None = None` parameter to `FPShortCircuit.__init__()`.
  - [x] 3.2: In `FPShortCircuit.check()`, before matching, call `kill_switch_manager.is_killed(tenant_id, pattern_id, technique_id, data_source)`. If killed, skip match and return `FPMatchResult(matched=False)`.
  - [x] 3.3: Add unit tests — `TestKillSwitchIntegration` class: kill switch active → pattern not matched, kill switch inactive → pattern matched normally. (~4 tests)
- [x] Task 4: Add `shadow` status to FPPatternStatus (AC: 2)
  - [x] 4.1: Add `SHADOW = "shadow"` to `FPPatternStatus` enum in `batch_scheduler/models.py`.
  - [x] 4.2: In `FPShortCircuit.check()`, skip patterns with `status == "shadow"` from active matching (they run in canary only).
  - [x] 4.3: Add unit tests — `TestShadowStatus` class: shadow patterns skipped in active matching, shadow status valid enum value. (~3 tests)
- [x] Task 5: Run full regression (AC: 1-5)
  - [x] 5.1: Run full project test suite (`pytest tests/`) — all 1771 tests pass (zero regressions)
  - [x] 5.2: Verify existing FP short-circuit tests still pass (backward compat via None defaults)

## Dev Notes

### Critical Architecture Constraints

- **REM-H02 Part B** — kill switches are the emergency brake for autonomous auto-close.
- **4 kill switch dimensions**: tenant, pattern, technique, data_source. Any active switch in any dimension blocks auto-close.
- **Redis-backed** — kill switches must take effect within 1 Redis round trip (< 1 minute at worst with caching).
- **Canary threshold of 50** is configurable — different deployments may need higher thresholds.
- **Backward compat** — `FPShortCircuit()` with no `kill_switch_manager` parameter works identically to before.
- **Audit events** — kill switch activation/deactivation must emit events to `audit.events` for compliance trail.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `FPShortCircuit` | `orchestrator/fp_shortcircuit.py:30-68` | FP matching. **Extend with kill switch check.** |
| `FPPatternStatus` | `batch_scheduler/models.py:33-39` | Status enum. **Add SHADOW value.** |
| `RedisClient` | `shared/db/redis_cache.py` | Redis wrapper. **Use for kill switch state.** |
| `FP_CONFIDENCE_THRESHOLD` | `orchestrator/fp_shortcircuit.py:18` | `0.90`. **Not modified.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Kill switch manager (NEW) | `orchestrator/kill_switch.py` |
| FP canary manager (NEW) | `orchestrator/fp_canary.py` |
| Kill switch tests (NEW) | `tests/test_orchestrator/test_kill_switch.py` |
| Canary tests (NEW) | `tests/test_orchestrator/test_fp_canary.py` |
| FP short-circuit | `orchestrator/fp_shortcircuit.py` |
| FP pattern status | `batch_scheduler/models.py` |
| Redis client | `shared/db/redis_cache.py` |

### Kill Switch Redis Keys

```
kill_switch:tenant:{tenant_id}     → {"activated_by": "analyst@org", "activated_at": "...", "reason": "..."}
kill_switch:pattern:{pattern_id}   → {"activated_by": "...", ...}
kill_switch:technique:{technique_id} → {"activated_by": "...", ...}
kill_switch:datasource:{source}    → {"activated_by": "...", ...}
```

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_orchestrator/ (all existing tests):**
- FP short-circuit tests unchanged (backward compat)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**, **pytest-asyncio**
- Mock `RedisClient` for kill switch and canary state
- Mock `AuditProducer` for audit event verification
- Test backward compat: `FPShortCircuit()` with no kill_switch_manager

### Dependencies on Other Stories

- **Story 14.2** (FP Evaluation): provides precision/recall data canary uses for promotion decisions

### References

- [Source: docs/remediation-backlog.md#REM-H02 Part B] — Kill switch and canary requirements
- [Source: docs/prd.md#FR-RSN-006] — FP pattern accuracy requirement

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- Initial run: 13 failures from (1) MagicMock vs AsyncMock in `_get_client()` pattern and (2) missing `investigation_id` in `GraphState` constructor. Fixed by adding `_get_client()` helper and providing required field in tests.

### Completion Notes List

- **Task 1 (KillSwitchManager):** Created `orchestrator/kill_switch.py` with `KillSwitchManager` class supporting 4 dimensions (tenant, pattern, technique, datasource). Uses `_get_client()` helper to resolve underlying async Redis client from `RedisClient` wrapper. `activate()` stores JSON metadata and emits `kill_switch.activated` audit event. `deactivate()` removes key and emits `kill_switch.deactivated`. `is_killed()` checks all applicable dimensions — returns True if ANY switch active. 12 tests in `TestKillSwitchManager`.
- **Task 2 (FPCanaryManager):** Created `orchestrator/fp_canary.py` with shadow decision tracking via Redis counters (`canary:{pattern_id}:total/agree/disagree`). `should_promote()` requires total >= threshold (default 50) AND disagreement <= 5%. `promote()` updates pattern status in Redis from `shadow` to `active`. 9 tests in `TestFPCanaryManager`.
- **Task 3 (Integration):** Extended `FPShortCircuit.__init__()` with `kill_switch_manager: Any | None = None`. In `check()`, tenant-level kill switch checked before any pattern evaluation; per-pattern kill switch checked per pattern. Also accepts `tenant_id`, `technique_id`, `data_source` parameters. Backward compat: None default means no kill switch checking. 4 tests in `TestKillSwitchIntegration`.
- **Task 4 (Shadow Status):** Added `SHADOW = "shadow"` to `FPPatternStatus` enum (now 5 values). `FPShortCircuit.check()` skips patterns with `status == "shadow"`. Also accepts `status == "active"` in addition to existing `"approved"`. 3 tests in `TestShadowStatus`.
- **Task 5 (Regression):** 1771 tests passed, 0 failures. All existing FP short-circuit tests pass unchanged (backward compat via None defaults).

### File List

**Created:**
- `orchestrator/kill_switch.py` — KillSwitchManager with 4-dimension Redis-backed kill switches
- `orchestrator/fp_canary.py` — FPCanaryManager with shadow decision tracking and promotion logic
- `tests/test_orchestrator/test_kill_switch.py` — 16 tests (12 KillSwitchManager + 4 integration)
- `tests/test_orchestrator/test_fp_canary.py` — 12 tests (9 canary + 3 shadow status)

**Modified:**
- `orchestrator/fp_shortcircuit.py` — added kill_switch_manager parameter, kill switch check before matching, shadow pattern exclusion, accepts "active" status
- `batch_scheduler/models.py` — added SHADOW to FPPatternStatus enum

### Change Log

- 2026-02-24: Story 14.3 implemented — Kill switches (4 dimensions) and FP canary rollout (shadow → 50 correct → active). 28 new tests, 1771 total tests passing.
