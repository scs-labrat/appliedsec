# Story 12.4: Provider Outage Playbook

Status: review

## Story

As a SOC operator responding to provider outages,
I want documented RTO/RPO per outage scenario with degradation policies, auto-close authority rules, and confidence threshold adjustments per provider state,
so that the team knows exactly what happens and what degrades during each failure mode.

## Acceptance Criteria

1. **Given** Anthropic down + secondary (OpenAI) up, **When** the playbook is consulted, **Then** it specifies: continue with secondary provider, confidence threshold raised to 0.95, no extended thinking available.
2. **Given** all LLM providers down, **When** the playbook is consulted, **Then** it specifies: deterministic-only mode, no auto-close, all alerts queued for human review.
3. **Given** degradation level tracking, **When** provider state changes, **Then** `DegradationLevel` enum reflects current system capability and is available to all routing decisions.
4. **Given** the playbook, **When** added to runbook, **Then** it is linked from `docs/runbook.md` and includes per-scenario RTO/RPO tables.

## Tasks / Subtasks

- [x] Task 1: Create DegradationLevel enum and provider state tracker (AC: 3)
  - [x] 1.1: Add `DegradationLevel(str, Enum)` to `llm_router/models.py` — `FULL_CAPABILITY`, `SECONDARY_ACTIVE`, `DETERMINISTIC_ONLY`, `PASSTHROUGH`. Ordered by severity (FULL is 0, PASSTHROUGH is 3).
  - [x] 1.2: Add `DegradationPolicy` dataclass to `llm_router/models.py` with fields: `confidence_threshold_override: float | None = None`, `auto_close_allowed: bool = True`, `extended_thinking_available: bool = True`, `max_tier: ModelTier | None = None`.
  - [x] 1.3: Add `DEGRADATION_POLICIES: dict[DegradationLevel, DegradationPolicy]` mapping:
    - `FULL_CAPABILITY` → default (no overrides)
    - `SECONDARY_ACTIVE` → confidence_threshold_override=0.95, extended_thinking_available=False
    - `DETERMINISTIC_ONLY` → auto_close_allowed=False, max_tier=None (no LLM calls)
    - `PASSTHROUGH` → auto_close_allowed=False, max_tier=None
  - [x] 1.4: Add unit tests in `tests/test_llm_router/test_models.py` — `TestDegradationLevel` class: enum values, ordering, all levels present. `TestDegradationPolicy` class: default values, secondary active overrides, deterministic mode constraints. (~8 tests)
- [x] Task 2: Add degradation level computation to ProviderHealthRegistry (AC: 1, 2, 3)
  - [x] 2.1: Add `compute_degradation_level() -> DegradationLevel` method to `ProviderHealthRegistry` in `llm_router/circuit_breaker.py`:
    - All providers healthy → `FULL_CAPABILITY`
    - Primary (Anthropic) down, any secondary up → `SECONDARY_ACTIVE`
    - All LLM providers down → `DETERMINISTIC_ONLY`
  - [x] 2.2: Add `get_policy() -> DegradationPolicy` convenience method that returns `DEGRADATION_POLICIES[self.compute_degradation_level()]`
  - [x] 2.3: Add unit tests in `tests/test_llm_router/test_circuit_breaker.py` — `TestDegradationComputation` class: all healthy → FULL, primary down → SECONDARY_ACTIVE, all down → DETERMINISTIC_ONLY, recovery back to FULL. (~6 tests)
- [x] Task 3: Integrate degradation policy into LLMRouter.route() (AC: 1, 2)
  - [x] 3.1: In `LLMRouter.route()`, after step 9 (metrics recording), add step 10: if `self._health` is not None, compute degradation level and attach `DegradationPolicy` fields to `RoutingDecision` metadata.
  - [x] 3.2: Add `degradation_level: str = "full_capability"` field to `RoutingDecision` dataclass in `llm_router/models.py` (default preserves backward compat).
  - [x] 3.3: Add unit tests in `tests/test_llm_router/test_router.py` — `TestDegradationRouting` class: verify degradation_level field is set, secondary active raises confidence context, no health registry defaults to full. (~5 tests)
- [x] Task 4: Write provider outage playbook documentation (AC: 4)
  - [x] 4.1: Create `docs/provider-outage-playbook.md` with:
    - Scenario table: provider state → degradation level → system behavior → RTO/RPO
    - Per-scenario details: FULL_CAPABILITY, SECONDARY_ACTIVE, DETERMINISTIC_ONLY, PASSTHROUGH
    - Auto-close authority rules per degradation level
    - Confidence threshold adjustments per provider
    - Cost behavior: per-provider cost tracking during failover
    - Monitoring: which Prometheus metrics to watch, alerting thresholds
    - Recovery procedures: how to verify provider recovery, expected timeline
  - [x] 4.2: Add link from `docs/runbook.md` to `docs/provider-outage-playbook.md` (create `docs/runbook.md` if it does not exist)
- [x] Task 5: Update exports and run full regression (AC: 1-4)
  - [x] 5.1: Update `llm_router/__init__.py` — add `DegradationLevel`, `DegradationPolicy`, `DEGRADATION_POLICIES` to imports and `__all__`
  - [x] 5.2: Run full project test suite (`pytest tests/`) — all 1190 tests pass (zero regressions, 21 new tests)

## Dev Notes

### Critical Architecture Constraints

- **This is Part C of REM-C02.** Stories 12.2 (Part A — Provider Abstraction) and 12.3 (Part B — Secondary Registration) are COMPLETE. Reuse `ProviderHealthRegistry`, `CircuitBreaker`, `FALLBACK_REGISTRY`, `LLMProvider`.
- **DO NOT implement actual degradation enforcement** in the gateway or orchestrator. This story adds the data model, computation, and documentation. Enforcement (blocking auto-close in DETERMINISTIC_ONLY mode) is the orchestrator's responsibility and will reference these policies.
- **DO NOT modify the 5-level override chain** in `LLMRouter.route()`. Degradation level is informational metadata on `RoutingDecision`, not a routing override.
- **Zero regression is mandatory.** All existing 1169 tests must pass. `RoutingDecision` default value for `degradation_level` preserves backward compat.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `ProviderHealthRegistry` | `llm_router/circuit_breaker.py:80-106` | Per-provider CircuitBreaker management. **Extend with `compute_degradation_level()`.** |
| `CircuitBreaker` | `llm_router/circuit_breaker.py:23-77` | Three-state machine. **Use `is_available` to determine provider health.** |
| `LLMProvider` | `shared/schemas/routing.py:14-20` | Provider enum (ANTHROPIC, OPENAI, LOCAL, GROQ). **Use for provider iteration.** |
| `FALLBACK_REGISTRY` | `llm_router/models.py:74-99` | Fallback configs per tier. **Reference for which tiers have secondary providers.** |
| `RoutingDecision` | `llm_router/models.py:117-128` | Output dataclass. **Extend with `degradation_level` field.** |
| `LLMRouter` | `llm_router/router.py:147-264` | Routing logic. **Extend route() with degradation metadata.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Circuit breaker | `llm_router/circuit_breaker.py` |
| Routing models | `llm_router/models.py` |
| Router logic | `llm_router/router.py` |
| Router exports | `llm_router/__init__.py` |
| Model tests | `tests/test_llm_router/test_models.py` |
| Circuit breaker tests | `tests/test_llm_router/test_circuit_breaker.py` |
| Router tests | `tests/test_llm_router/test_router.py` |
| Playbook doc (NEW) | `docs/provider-outage-playbook.md` |
| Runbook doc (NEW or EXISTING) | `docs/runbook.md` |

### Degradation Level Design

```
Provider State                    → Degradation Level
─────────────────────────────────────────────────────
All healthy                       → FULL_CAPABILITY
Primary (Anthropic) down,         → SECONDARY_ACTIVE
  secondary (OpenAI) up
All LLM providers down            → DETERMINISTIC_ONLY
All infrastructure down           → PASSTHROUGH
```

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_models.py (30 tests):**
- `TestModelTier` — 4 tests
- `TestAnthropicModelConfig` — 7 tests
- `TestTaskContext` — 2 tests
- `TestRoutingDecision` — 2 tests
- `TestTierDefaults` — 4 tests
- `TestSeverityQueueMap` — 4 tests
- `TestFallbackRegistry` — 7 tests

**test_circuit_breaker.py (21 tests):**
- `TestCircuitBreakerState` — 3 tests
- `TestCircuitBreaker` — 13 tests
- `TestProviderHealthRegistry` — 5 tests

**test_router.py (36 tests):**
- `TestTaskTierMap` — 4 tests
- `TestBaseRouting` — 5 tests
- `TestTimeBudgetOverride` — 3 tests
- `TestSeverityOverride` — 4 tests
- `TestContextSizeOverride` — 3 tests
- `TestEscalationOverride` — 5 tests
- `TestOverrideInteractions` — 4 tests
- `TestFallbackRouting` — 8 tests

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**
- `DegradationLevel` tests: simple enum value checks
- `DegradationPolicy` tests: verify default values and per-level overrides
- `compute_degradation_level()` tests: mock provider health states via `record_failure()` calls
- No time mocking needed for degradation tests (circuit breaker handles that internally)

### References

- [Source: docs/remediation-backlog.md#REM-C02 Part C] — Provider outage playbook requirements
- [Source: docs/ai-system-design.md Section 11.1-11.2] — 5-level degradation strategy
- [Source: docs/prd.md#NFR-REL-001] — Documented degradation strategy requirement
- [Source: docs/prd.md#NFR-REL-003] — LLM Router unreachable behavior
- [Source: docs/audit-architecture.md] — provider_health in AuditContext

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

### Completion Notes List

- Implemented DegradationLevel enum (4 levels) and DegradationPolicy dataclass in llm_router/models.py
- Added DEGRADATION_POLICIES mapping with per-level constraints (confidence override, auto-close, extended thinking)
- Added degradation_level field to RoutingDecision with "full_capability" default for backward compat
- Added compute_degradation_level() and get_policy() to ProviderHealthRegistry
- Integrated degradation metadata into LLMRouter.route() step 10
- Created comprehensive provider outage playbook with RTO/RPO tables
- Linked playbook from existing runbook.md
- 21 new tests added (10 model + 6 circuit breaker + 5 router), all 1190 tests pass

### File List

**Created:**
- `docs/provider-outage-playbook.md` — Provider outage playbook with per-scenario RTO/RPO, degradation policies, auto-close rules

**Modified:**
- `llm_router/models.py` — add DegradationLevel, DegradationPolicy, DEGRADATION_POLICIES, extend RoutingDecision with degradation_level
- `llm_router/circuit_breaker.py` — add compute_degradation_level(), get_policy() to ProviderHealthRegistry
- `llm_router/router.py` — add degradation metadata to route() step 10
- `llm_router/__init__.py` — export DegradationLevel, DegradationPolicy, DEGRADATION_POLICIES
- `tests/test_llm_router/test_models.py` — add TestDegradationLevel (4 tests), TestDegradationPolicy (6 tests)
- `tests/test_llm_router/test_circuit_breaker.py` — add TestDegradationComputation (6 tests)
- `tests/test_llm_router/test_router.py` — add TestDegradationRouting (5 tests)
- `docs/runbook.md` — add link to provider outage playbook in LLM Degradation section

### Change Log

- 2026-02-21: Story 12.4 implemented — DegradationLevel enum, DegradationPolicy, compute_degradation_level(), provider outage playbook. 21 new tests, 1190 total passing.
