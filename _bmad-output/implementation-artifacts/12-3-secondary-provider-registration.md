# Story 12.3: Secondary Provider Registration

Status: review

## Story

As a platform with LLM provider redundancy,
I want secondary model entries in MODEL_REGISTRY with fallback_chain per tier and circuit breaker health checks per provider,
so that Tier 0/1 tasks failover to a secondary provider within 30 seconds of primary outage.

## Acceptance Criteria

1. **Given** Anthropic returns 5xx for 5 consecutive calls, **When** circuit breaker opens, **Then** Tier 0/1 tasks route to secondary provider within 30 seconds.
2. **Given** secondary provider (e.g., OpenAI) registered for Tier 0, **When** selected by the router, **Then** the `ModelConfig` meets all `TaskCapabilities` for every Tier 0 task type (validated via `_matches_capabilities`).
3. **Given** Prometheus metrics are scraped, **When** metrics are collected, **Then** `aluskort_llm_provider_selections_total{provider="anthropic"}` and `{provider="openai"}` are distinguished.
4. **Given** secondary provider is active, **When** cost is computed, **Then** costs reflect secondary pricing (e.g., OpenAI gpt-4o-mini at $0.15/$0.60 per Mtok, not Anthropic Haiku at $0.80/$4.0).

## Tasks / Subtasks

- [x] Task 1: Create CircuitBreaker and ProviderHealthRegistry (AC: 1)
  - [x] 1.1: Create `llm_router/circuit_breaker.py` with `CircuitBreakerState(str, Enum)` — `CLOSED`, `OPEN`, `HALF_OPEN`
  - [x] 1.2: Add `CircuitBreaker` class with `failure_threshold: int = 5`, `recovery_timeout_seconds: float = 30.0`, state tracking, `record_success()`, `record_failure()`, `is_available` property. State machine: CLOSED→OPEN on threshold breach, OPEN→HALF_OPEN after recovery_timeout, HALF_OPEN→CLOSED on success, HALF_OPEN→OPEN on failure
  - [x] 1.3: Add `ProviderHealthRegistry` class — maps `LLMProvider → CircuitBreaker`, auto-creates breaker on first access, exposes `is_available(provider)`, `record_success(provider)`, `record_failure(provider)`
  - [x] 1.4: Add unit tests in `tests/test_llm_router/test_circuit_breaker.py` — `TestCircuitBreakerState` (enum values), `TestCircuitBreaker` (state transitions, threshold, recovery timeout, half-open→closed on success, half-open→open on failure, consecutive counting resets on success, half-open is_available returns True for probe), `TestProviderHealthRegistry` (auto-creation, per-provider isolation, availability check)
- [x] Task 2: Add FALLBACK_REGISTRY with secondary provider entries (AC: 1, 2, 4)
  - [x] 2.1: Add `FALLBACK_REGISTRY: dict[ModelTier, list[ModelConfig]]` to `llm_router/models.py` — each value is an ordered list of fallback configs (primary is NOT included; primary comes from existing `MODEL_REGISTRY`)
  - [x] 2.2: Tier 0 fallback: `[ModelConfig(provider=LLMProvider.OPENAI, model_id="gpt-4o-mini", max_context_tokens=128_000, cost_per_mtok_input=0.15, cost_per_mtok_output=0.60, supports_prompt_caching=False)]`
  - [x] 2.3: Tier 1 fallback: `[ModelConfig(provider=LLMProvider.OPENAI, model_id="gpt-4o", max_context_tokens=128_000, cost_per_mtok_input=2.50, cost_per_mtok_output=10.0, supports_prompt_caching=False)]`
  - [x] 2.4: Tier 1+ fallback: `[]` (accept degradation — Opus escalation is < 1% of volume)
  - [x] 2.5: Tier 2 fallback: `[]` (batch can wait for primary recovery)
  - [x] 2.6: Add unit tests in `tests/test_llm_router/test_models.py` — `TestFallbackRegistry` class: all 4 tiers present, Tier 0/1 have exactly 1 fallback each, Tier 1+/2 have empty lists, fallback configs are valid ModelConfig with correct provider
  - [x] 2.7: Add tests in `TestFallbackRegistry` that verify every Tier 0 fallback passes `_matches_capabilities` for ALL 6 Tier 0 tasks and every Tier 1 fallback passes for ALL 6 Tier 1 tasks. Import: `from llm_router.router import _matches_capabilities, TASK_CAPABILITIES, TASK_TIER_MAP` (underscore prefix is intentional; direct import is acceptable in tests)
- [x] Task 3: Extend RoutingDecision with fallback support (AC: 1, 4)
  - [x] 3.1: Add `fallback_configs: list[ModelConfig] = field(default_factory=list)` to `RoutingDecision` in `llm_router/models.py`
  - [x] 3.2: Run ALL existing `tests/test_llm_router/` — MUST pass without modification (new field has default value, existing tests unaffected)
- [x] Task 4: Add health-aware fallback routing to LLMRouter (AC: 1, 2)
  - [x] 4.1: Add `LLMRouter.__init__(self, health_registry: ProviderHealthRegistry | None = None, metrics: RoutingMetrics | None = None)`. Store as `self._health` and `self._metrics`. Note: `LLMRouter` currently has NO `__init__`; Python uses `object.__init__` by default. Adding `__init__` with all-optional params preserves `LLMRouter()` backward compat
  - [x] 4.2: In `route()`, AFTER existing step 6 (capability validation), add step 7: if `self._health` is not None and primary provider is unavailable, select first available fallback from `FALLBACK_REGISTRY[tier]` that passes `_matches_capabilities`
  - [x] 4.3: Populate `RoutingDecision.fallback_configs` with remaining healthy options (regardless of health_registry presence — always populate from FALLBACK_REGISTRY)
  - [x] 4.4: When primary is replaced by fallback, update `reason` field: append `"primary_unavailable→fallback({provider})"`
  - [x] 4.5: Add unit tests in `tests/test_llm_router/test_router.py` — `TestFallbackRouting` class: healthy primary unchanged, unhealthy primary selects fallback, no fallback available keeps primary with warning, fallback_configs always populated for Tier 0/1, capability mismatch skips to next fallback, no health_registry means no health check (backward compat)
- [x] Task 5: Add provider dimension to RoutingMetrics (AC: 3)
  - [x] 5.1: Add `self._provider_selections: dict[tuple[str, str, str], int] = {}` to `RoutingMetrics.__init__()`, then add `record_provider_selection(provider: str, tier: str, is_fallback: bool)` method to `RoutingMetrics` in `llm_router/metrics.py`
  - [x] 5.2: Track counter `aluskort_llm_provider_selections_total` with labels `{provider, tier, is_fallback}` — use same mock-Prometheus pattern as existing metrics
  - [x] 5.3: Call `self._metrics.record_provider_selection(...)` from `LLMRouter.route()` after final provider decision, guarded by `if self._metrics is not None`
  - [x] 5.4: Add unit tests in `tests/test_llm_router/test_metrics.py` — `TestProviderMetrics` class: primary selection recorded, fallback selection recorded with is_fallback=true, provider label matches model_config.provider.value
- [x] Task 6: Update exports and run full regression (AC: 1-4)
  - [x] 6.1: Update `llm_router/__init__.py` — add `CircuitBreaker`, `CircuitBreakerState`, `ProviderHealthRegistry`, `FALLBACK_REGISTRY` to imports and `__all__`
  - [x] 6.2: Run full project test suite (`pytest tests/`) — all 1167 tests pass (zero regressions, +37 new)
  - [x] 6.3: Verify backward compat: `LLMRouter()` without health_registry works identically to current behavior

## Dev Notes

### Critical Architecture Constraints

- **This is Part B of REM-C02.** Story 12.2 (Part A — Provider Abstraction) is COMPLETE. DO NOT re-implement `LLMProvider`, `ModelConfig`, or `TaskCapabilities` — they exist in `shared/schemas/routing.py`.
- **DO NOT implement actual provider API clients** (OpenAI SDK, Groq SDK). Story 12.3 adds routing infrastructure and registry entries. Story 12.5 adds prompt adaptation and contract tests. The gateway client abstraction is a follow-up concern.
- **DO NOT modify the 5-level override chain** in `LLMRouter.route()`. Steps 1-5 (base→time→severity→context→escalation) are frozen. Fallback logic is step 7, AFTER step 6 (capability validation).
- **DO NOT modify `ContextGateway`** in this story. Gateway changes (abstract provider client, fallback retry loop) are deferred until the actual secondary provider clients are implemented.
- **Zero regression is mandatory.** All existing 1130 tests must pass. The `LLMRouter()` constructor with no arguments must behave identically to today.
- **RoutingDecision MUST remain `@dataclass`** (NOT Pydantic). The identity assertion `decision.model_config is MODEL_REGISTRY[decision.tier]` must pass when all providers are healthy.
- **Use stdlib `@dataclass`** for `CircuitBreaker`, `ProviderHealthRegistry` — they live in `llm_router/` alongside other dataclasses.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `LLMProvider` | `shared/schemas/routing.py:14-20` | `str, Enum` with ANTHROPIC, OPENAI, LOCAL, GROQ. **Use for provider keys.** |
| `ModelConfig` | `shared/schemas/routing.py:33-45` | Pydantic model with provider, model_id, pricing, capabilities. **Use for fallback entries.** |
| `TaskCapabilities` | `shared/schemas/routing.py:23-30` | Pydantic model for task requirements. **Already in `TASK_CAPABILITIES` dict.** |
| `_matches_capabilities` | `llm_router/router.py:116-124` | Validates model meets task caps. **Reuse for fallback capability validation.** |
| `MODEL_REGISTRY` | `llm_router/models.py:40-71` | `dict[ModelTier, ModelConfig]` with 4 Anthropic entries. **Primary configs — DO NOT modify.** |
| `TASK_CAPABILITIES` | `llm_router/router.py:52-113` | 18 tasks with capability requirements. **Use to validate fallback compatibility.** |
| `TASK_TIER_MAP` | `llm_router/router.py:26-48` | 18 tasks → tier mapping. **DO NOT modify.** |
| `RoutingDecision` | `llm_router/models.py:89-99` | Output `@dataclass`. **Extend with `fallback_configs` field.** |
| `LLMRouter.route()` | `llm_router/router.py:140-207` | 5-level override + capability check. **Extend with step 7 (fallback selection).** |
| `RoutingMetrics` | `llm_router/metrics.py` | Prometheus-style metrics. **Extend with provider dimension.** |
| `ModelTier` | `llm_router/models.py:15-21` | 4-tier enum. **DO NOT modify.** |

### Exact File Paths (Verified Against Codebase — NO `services/` prefix)

| Target | Correct Path |
|---|---|
| Circuit breaker (NEW) | `llm_router/circuit_breaker.py` |
| Circuit breaker tests (NEW) | `tests/test_llm_router/test_circuit_breaker.py` |
| Routing models | `llm_router/models.py` |
| Router logic | `llm_router/router.py` |
| Routing metrics | `llm_router/metrics.py` |
| Router exports | `llm_router/__init__.py` |
| Shared schemas | `shared/schemas/routing.py` |
| Router tests | `tests/test_llm_router/test_router.py` |
| Model tests | `tests/test_llm_router/test_models.py` |
| Metrics tests | `tests/test_llm_router/test_metrics.py` |

### CircuitBreaker State Machine (Task 1)

```
          ┌─────────────────────────────────┐
          │          CLOSED                  │
          │   (all good, counting failures)  │
          └──────────┬──────────────────────┘
                     │ 5 consecutive failures
                     ▼
          ┌─────────────────────────────────┐
          │           OPEN                   │
          │   (provider considered down)     │
          │   wait recovery_timeout (30s)    │
          └──────────┬──────────────────────┘
                     │ recovery_timeout elapsed
                     ▼
          ┌─────────────────────────────────┐
          │        HALF_OPEN                 │
          │   (allow ONE probe request)      │
          └──────┬──────────────┬───────────┘
                 │ success      │ failure
                 ▼              ▼
              CLOSED          OPEN
```

**Key implementation details:**
- Use `time.monotonic()` for timing (not wall clock)
- `failure_count` resets to 0 on any success in CLOSED state
- `is_available` returns True for CLOSED and HALF_OPEN, False for OPEN
- OPEN→HALF_OPEN transition happens automatically when `time.monotonic() - opened_at > recovery_timeout_seconds`

### FALLBACK_REGISTRY Design (Task 2)

```python
FALLBACK_REGISTRY: dict[ModelTier, list[ModelConfig]] = {
    ModelTier.TIER_0: [
        ModelConfig(
            provider=LLMProvider.OPENAI,
            model_id="gpt-4o-mini",
            max_context_tokens=128_000,
            cost_per_mtok_input=0.15,
            cost_per_mtok_output=0.60,
            supports_prompt_caching=False,
        ),
    ],
    ModelTier.TIER_1: [
        ModelConfig(
            provider=LLMProvider.OPENAI,
            model_id="gpt-4o",
            max_context_tokens=128_000,
            cost_per_mtok_input=2.50,
            cost_per_mtok_output=10.0,
            supports_prompt_caching=False,
        ),
    ],
    ModelTier.TIER_1_PLUS: [],  # Accept degradation (< 1% volume)
    ModelTier.TIER_2: [],       # Batch can wait
}
```

**Critical:** The list order defines fallback preference. Primary is always from `MODEL_REGISTRY[tier]`. Fallbacks are tried in list order.

**Capability validation:** ALL Tier 0 fallbacks MUST pass `_matches_capabilities` for ALL 6 Tier 0 tasks. The OpenAI gpt-4o-mini has 128K context (exceeds max 8192 needed for Tier 0) and supports tool use (True by default). Same logic for Tier 1 fallbacks vs Tier 1 tasks.

### LLMRouter.route() Extension (Task 4)

Current step flow (from Story 12.2):
```
1. Base tier from TASK_TIER_MAP
2. Time budget < 3s → force TIER_0
3. Critical severity + requires_reasoning → min TIER_1
4. Context > 100K tokens → min TIER_1
5. Low confidence < 0.6 on critical/high → TIER_1_PLUS
6. Capability validation (log-only)
```

New steps to ADD (do not change 1-6):
```
7. Populate fallback_configs from FALLBACK_REGISTRY[tier]
   - Filter through _matches_capabilities against TASK_CAPABILITIES
8. Health-aware primary selection (only if self._health is not None)
   - If primary provider unhealthy: swap model_config with first healthy fallback
   - Append reason: "primary_unavailable→fallback({provider})"
```

**Backward compatibility:** When `self._health is None` (default), steps 7-8 just populate fallback_configs but never swap the primary. Existing tests pass unchanged.

### Identity Assertion Protection

`test_router.py::TestBaseRouting::test_model_config_matches_tier` checks:
```python
assert decision.model_config is MODEL_REGISTRY[decision.tier]
```

This PASSES when:
- `health_registry` is None (default) — primary is never swapped
- All providers are healthy — primary is used

This FAILS when:
- Primary is swapped to fallback — model_config is from FALLBACK_REGISTRY

**Solution:** New fallback tests create `LLMRouter(health_registry=registry)` with specific unhealthy providers. Existing tests create `LLMRouter()` with no registry. No conflict.

### RoutingMetrics Extension (Task 5)

Current `RoutingMetrics` tracks tier selections and latency. Add provider dimension.

**`__init__` must be extended** (current `__init__` only has `self._outcomes`):
```python
def __init__(self) -> None:
    self._outcomes: dict[str, TierOutcome] = {}
    self._provider_selections: dict[tuple[str, str, str], int] = {}  # NEW
```

**New method:**
```python
def record_provider_selection(
    self, provider: str, tier: str, is_fallback: bool
) -> None:
    """Record which provider was selected for a routing decision."""
    key = (provider, tier, str(is_fallback).lower())
    self._provider_selections[key] = self._provider_selections.get(key, 0) + 1
```

Counter name: `aluskort_llm_provider_selections_total`
Labels: `{provider="anthropic", tier="tier_0", is_fallback="false"}`

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_models.py (23 tests):**
- `TestModelTier` — 4 tests
- `TestAnthropicModelConfig` — 7 tests
- `TestTaskContext` — 2 tests
- `TestRoutingDecision` — 2 tests
- `TestTierDefaults` — 4 tests
- `TestSeverityQueueMap` — 4 tests

**test_router.py (28 tests):**
- `TestTaskTierMap` — 4 tests
- `TestBaseRouting` — 5 tests (includes identity assertion)
- `TestTimeBudgetOverride` — 3 tests
- `TestSeverityOverride` — 4 tests
- `TestContextSizeOverride` — 3 tests
- `TestEscalationOverride` — 5 tests
- `TestOverrideInteractions` — 4 tests

**test_routing.py (21 schema tests):**
- `TestLLMProvider` — 4 tests
- `TestTaskCapabilities` — 3 tests
- `TestModelConfig` — 5 tests
- `TestTaskCapabilitiesMapping` — 4 tests
- `TestCapabilityMatching` — 5 tests

**test_metrics.py (20 tests):**
- `TestTierOutcome` — 9 tests
- `TestRoutingMetrics` — 6 tests
- `TestSummary` — 4 tests
- `TestMetricsIntegration` — 1 test

**Also in test_llm_router/ (must pass, not directly modified):**
- `test_concurrency.py` — ~25 tests
- `test_escalation.py` — ~24 tests

**Total existing: 1130 tests — ALL must pass unchanged.**

### New Test Classes (Estimated Counts)

| File | Class | Tests | What It Validates |
|---|---|---|---|
| `test_circuit_breaker.py` (NEW) | `TestCircuitBreakerState` | 3 | Enum values |
| `test_circuit_breaker.py` (NEW) | `TestCircuitBreaker` | ~10 | State transitions, threshold, recovery, counters |
| `test_circuit_breaker.py` (NEW) | `TestProviderHealthRegistry` | ~5 | Auto-creation, isolation, availability |
| `test_models.py` (EXTEND) | `TestFallbackRegistry` | ~5 | Structure, capabilities, coverage |
| `test_router.py` (EXTEND) | `TestFallbackRouting` | ~8 | Health-aware selection, backward compat |
| `test_metrics.py` (EXTEND) | `TestProviderMetrics` | ~3 | Provider selection tracking |
| **Total new** | | **~34** | |

### Testing Patterns

- Test framework: **pytest**
- `CircuitBreaker` tests need time mocking — use `unittest.mock.patch("time.monotonic")` to control timeout transitions
- `ProviderHealthRegistry` tests: create registry, record failures to open breaker, verify `is_available` changes
- Fallback routing tests: create `LLMRouter(health_registry=registry)`, open Anthropic breaker, verify `route()` returns OpenAI fallback
- Import patterns: `from llm_router.circuit_breaker import CircuitBreaker, CircuitBreakerState, ProviderHealthRegistry`

### Previous Story Intelligence (12.1, 12.2)

- **File path corrections**: Epic `services/` prefix is WRONG — use root-level paths (`llm_router/`, NOT `services/llm_router/`)
- **Pydantic v2 for schemas** in `shared/schemas/`. Stdlib `@dataclass` for `llm_router/` types.
- **Red-green-refactor** cycle works well: failing tests first, minimal implementation, verify regressions
- **`RoutingDecision` is @dataclass** — identity assertion (`is`) is critical. Do NOT convert to Pydantic.
- **`MODEL_REGISTRY` uses `ModelConfig`** (Pydantic) since Story 12.2. Works fine with `@dataclass` `RoutingDecision` because dataclass stores object references directly.
- **Full test suite is 1130 tests** (1109 after 12.1, +21 from 12.2)
- **`AnthropicModelConfig` still exists** in `llm_router/models.py` for backward compat — do NOT delete

### Architecture References

- Circuit breaker thresholds: Anthropic API 5 failures/1min, open 30s [Source: docs/architecture.md Section 8]
- 5-level degradation: Full → Deterministic Only → Structured Search → Static Consequence → Passthrough [Source: docs/ai-system-design.md Section 11.2]
- Audit events: `circuit_breaker.opened` and `circuit_breaker.closed` event types [Source: docs/audit-architecture.md]
- Provider metrics: `aluskort_llm_calls_total{provider=...}` [Source: _bmad-output/planning-artifacts/epics.md:1365]
- NFR-REL-001, NFR-REL-007 [Source: docs/prd.md]

### What Story 12.4-12.5 Will Build On

Story 12.3 creates the infrastructure that 12.4 and 12.5 extend:
- **12.4 (Outage Playbook):** Documents RTO/RPO policies, auto-close thresholds per degradation level. Uses `ProviderHealthRegistry` state to determine current degradation level.
- **12.5 (Prompt Compatibility):** Adds `prompt_adapter` per provider, contract tests validating secondary produces compatible output. Uses `FALLBACK_REGISTRY` entries to test against.

### Project Structure Notes

- All source modules at repo root: `context_gateway/`, `shared/`, `llm_router/`, `orchestrator/`
- Tests mirror source: `tests/test_llm_router/`, `tests/test_schemas/`
- New file: `llm_router/circuit_breaker.py` (alongside existing `concurrency.py`, `escalation.py`)
- New test: `tests/test_llm_router/test_circuit_breaker.py`

### References

- [Source: docs/remediation-backlog.md#REM-C02 Part B] — Secondary provider registration requirements
- [Source: docs/architecture.md Section 8] — Circuit breaker thresholds (5 failures/1min, 30s open)
- [Source: docs/prd.md#NFR-REL-001] — 5-level degradation strategy
- [Source: docs/prd.md#NFR-REL-007] — Provider failover/resilience
- [Source: docs/audit-architecture.md] — circuit_breaker.opened/closed event types
- [Source: _bmad-output/planning-artifacts/epics.md:1355-1372] — Story 12.3 specification
- [Source: llm_router/router.py:191] — "Story 12.3 will use for fallback" comment
- [Source: _bmad-output/implementation-artifacts/12-2-provider-abstraction-layer.md] — Previous story learnings

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

### Completion Notes List

- All 6 tasks completed via red-green-refactor cycle — tests written first, then minimal implementation
- 37 new tests added (19 circuit breaker + 7 fallback registry + 8 fallback routing + 3 provider metrics)
- Total project test count: 1167/1167 passed (up from 1130)
- Zero regressions — all pre-existing tests pass unchanged
- Backward compat verified: `LLMRouter()` with no args works identically to pre-12.3 behavior
- Identity assertion `decision.model_config is MODEL_REGISTRY[decision.tier]` preserved when all providers healthy
- TYPE_CHECKING guard used for circular import prevention (ProviderHealthRegistry, RoutingMetrics in router.py)
- Code review fix: `record_success()`/`record_failure()` now use `self.state` property (not `self._state`) to ensure timeout-based OPEN→HALF_OPEN promotion is triggered even without prior `is_available` call
- Code review fix: Added 2 tests for direct record_success/record_failure after timeout without prior state check
- Code review fix: `test_provider_opens_and_recovers` now tests full recovery cycle (OPEN→HALF_OPEN→CLOSED)
- Final test count: 1169/1169 passed (39 new tests total)

### AC Validation

| AC | Status | Evidence |
|---|---|---|
| AC 1: Circuit breaker opens after 5 failures, routes to secondary within 30s | PASS | `test_circuit_breaker.py::TestCircuitBreaker::test_opens_on_threshold_breach`, `test_router.py::TestFallbackRouting::test_unhealthy_primary_selects_fallback` |
| AC 2: Secondary provider ModelConfig meets TaskCapabilities for all tier tasks | PASS | `test_models.py::TestFallbackRegistry::test_tier0_fallbacks_meet_all_tier0_capabilities`, `test_tier1_fallbacks_meet_all_tier1_capabilities` |
| AC 3: Provider selections distinguished in metrics (anthropic vs openai) | PASS | `test_metrics.py::TestProviderMetrics::test_primary_selection_recorded`, `test_fallback_selection_recorded` |
| AC 4: Secondary pricing reflected in fallback ModelConfig | PASS | `test_models.py::TestFallbackRegistry::test_fallback_pricing_differs_from_primary` — gpt-4o-mini $0.15/$0.60 vs Haiku $0.80/$4.0 |

### File List

**Created:**
- `llm_router/circuit_breaker.py` — CircuitBreakerState, CircuitBreaker, ProviderHealthRegistry
- `tests/test_llm_router/test_circuit_breaker.py` — circuit breaker and health registry tests

**Modified:**
- `llm_router/models.py` — add FALLBACK_REGISTRY, extend RoutingDecision with fallback_configs
- `llm_router/router.py` — add fallback population + health-aware primary selection to route()
- `llm_router/metrics.py` — add record_provider_selection with provider dimension
- `llm_router/__init__.py` — export new types
- `tests/test_llm_router/test_models.py` — add TestFallbackRegistry
- `tests/test_llm_router/test_router.py` — add TestFallbackRouting
- `tests/test_llm_router/test_metrics.py` — add TestProviderMetrics

### Change Log

- **Task 1**: Created `llm_router/circuit_breaker.py` — CircuitBreakerState enum (CLOSED/OPEN/HALF_OPEN), CircuitBreaker class (3-state machine with configurable threshold=5 and recovery_timeout=30s), ProviderHealthRegistry (per-provider CircuitBreaker management). 19 tests in `test_circuit_breaker.py`.
- **Task 2**: Added FALLBACK_REGISTRY to `llm_router/models.py` — Tier 0: gpt-4o-mini (OpenAI), Tier 1: gpt-4o (OpenAI), Tier 1+/2: empty. 7 tests in TestFallbackRegistry including capability validation against all 12 tier 0/1 tasks.
- **Task 3**: Extended RoutingDecision with `fallback_configs: list[ModelConfig]` field (default empty list). All existing tests pass unchanged.
- **Task 4**: Rewrote LLMRouter with `__init__` accepting optional health_registry and metrics. Extended route() with steps 7 (fallback population), 8 (health-aware primary swap), 9 (metrics recording). 8 tests in TestFallbackRouting.
- **Task 5**: Extended RoutingMetrics with `_provider_selections` dict, `record_provider_selection()` and `get_provider_selections()` methods. Router step 9 calls metrics. 3 tests in TestProviderMetrics.
- **Task 6**: Updated `llm_router/__init__.py` with CircuitBreaker, CircuitBreakerState, ProviderHealthRegistry, FALLBACK_REGISTRY exports. Full regression: 1167/1167 passed.
- **Code Review**: Fixed critical bug — `record_success()`/`record_failure()` read `self._state` directly, bypassing OPEN→HALF_OPEN timeout promotion. Changed to `self.state` (property). Added 2 regression tests. Fixed incomplete `test_provider_opens_and_recovers`. Final regression: 1169/1169 passed.
