# Story 12.2: Provider Abstraction Layer

Status: review

## Story

As a platform resilient to single-vendor LLM outages,
I want a generic `ModelConfig` with `LLMProvider` enum and `TaskCapabilities` dataclass replacing the Anthropic-only `MODEL_REGISTRY`,
so that the router selects models by matching capabilities, not just tier name.

## Acceptance Criteria

1. **Given** `LLMProvider` enum, **When** imported, **Then** it includes `ANTHROPIC`, `OPENAI`, `LOCAL`, `GROQ`.
2. **Given** a task definition, **When** routed, **Then** `TaskCapabilities` (`requires_tool_use`, `requires_json_reliability`, `max_context_tokens`, `latency_slo_seconds`, `requires_extended_thinking`) determines eligible models.
3. **Given** the refactored `MODEL_REGISTRY` using `ModelConfig`, **When** `pytest tests/test_llm_router/` is run, **Then** all 28 router tests and all 23 model tests pass without any modification to the test files.

## Tasks / Subtasks

- [x] Task 1: Create `LLMProvider` enum and `TaskCapabilities` dataclass (AC: 1, 2)
  - [x] 1.1: Create `shared/schemas/routing.py` with `LLMProvider(str, Enum)` containing `ANTHROPIC`, `OPENAI`, `LOCAL`, `GROQ`
  - [x] 1.2: Add `TaskCapabilities` Pydantic model: `requires_tool_use: bool = False`, `requires_json_reliability: bool = False`, `max_context_tokens: int = 8192`, `latency_slo_seconds: int = 30`, `requires_extended_thinking: bool = False`
  - [x] 1.3: Confirm `tests/test_schemas/__init__.py` exists, then add unit tests in `tests/test_schemas/test_routing.py` — `TestLLMProvider` (4 members, correct values), `TestTaskCapabilities` (defaults, custom values)
  - [x] 1.4: Export `LLMProvider` and `TaskCapabilities` from `shared/schemas/__init__.py`
- [x] Task 2: Create generic `ModelConfig` extending current capabilities (AC: 1, 2)
  - [x] 2.1: Add `ModelConfig` Pydantic model to `shared/schemas/routing.py` with fields: `provider: LLMProvider`, `model_id: str`, `max_context_tokens: int`, `cost_per_mtok_input: float`, `cost_per_mtok_output: float`, `supports_extended_thinking: bool = False`, `supports_tool_use: bool = True`, `supports_prompt_caching: bool = True`, `batch_eligible: bool = False`, `capabilities: TaskCapabilities = TaskCapabilities()`
  - [x] 2.2: Keep existing `AnthropicModelConfig` dataclass in `llm_router/models.py` for backward compat — no factory needed since `ModelConfig` directly replaces registry entries
  - [x] 2.3: Add unit tests: `TestModelConfig` (construction, provider field, capabilities field, serialisation round-trip)
  - [x] 2.4: Export `ModelConfig` from `shared/schemas/__init__.py`
- [x] Task 3: Refactor `MODEL_REGISTRY` to use `ModelConfig` (AC: 3)
  - [x] 3.1: Update `llm_router/models.py` to import `LLMProvider`, `ModelConfig`, `TaskCapabilities` from `shared.schemas.routing`
  - [x] 3.2: Convert `MODEL_REGISTRY` entries from `AnthropicModelConfig` to `ModelConfig` with `provider=LLMProvider.ANTHROPIC` — preserve **exact same** model_id, cost, and capability values
  - [x] 3.3: Keep `AnthropicModelConfig` as original dataclass — existing imports still work
  - [x] 3.4: Update `RoutingDecision.model_config` type hint from `AnthropicModelConfig` to `ModelConfig`
  - [x] 3.5: All 23 `tests/test_llm_router/test_models.py` tests pass without modification
- [x] Task 4: Add `TaskCapabilities` to task definitions and capability matching (AC: 2, 3)
  - [x] 4.1: Add `TASK_CAPABILITIES: dict[str, TaskCapabilities]` mapping in `llm_router/router.py` — all 18 tasks with values from reference table
  - [x] 4.2: Add `_matches_capabilities(model: ModelConfig, caps: TaskCapabilities) -> bool` helper in `llm_router/router.py`
  - [x] 4.3: Integrate log-only capability check into `LLMRouter.route()` after existing override chain (step 6)
  - [x] 4.4: Add unit tests: `TestTaskCapabilitiesMapping` (4 tests), `TestCapabilityMatching` (5 tests)
  - [x] 4.5: All 120 `tests/test_llm_router/` tests pass — zero regressions
- [x] Task 5: Update exports and verify full regression (AC: 1, 2, 3)
  - [x] 5.1: Update `llm_router/__init__.py` — added `LLMProvider`, `ModelConfig`, `TaskCapabilities`, `TASK_CAPABILITIES` to `__all__`; `AnthropicModelConfig` retained
  - [x] 5.2: Full project test suite: **1130/1130 passed** (net +21 new tests from Story 12.2)
  - [x] 5.3: All import paths verified: `shared.schemas.routing`, `shared.schemas`, `llm_router` — all resolve to same identity

## Dev Notes

### Critical Architecture Constraints

- **This is Part A ONLY of REM-C02.** DO NOT implement circuit breaker, fallback chain, secondary providers, prompt adapter, or outage playbook — those are Stories 12.3-12.5.
- **Zero regression is mandatory.** The existing `TASK_TIER_MAP` + 5-level override chain in `LLMRouter.route()` must produce identical `RoutingDecision` outputs for all existing inputs. Run `tests/test_llm_router/test_router.py` (28 tests) after every change.
- **Use Pydantic v2** for new schemas in `shared/schemas/routing.py`. Existing `llm_router/models.py` uses `@dataclass` — the bridge between dataclass `AnthropicModelConfig` and Pydantic `ModelConfig` must be clean.
- **Do NOT move existing types out of `llm_router/models.py`** prematurely. `ModelTier`, `TaskContext`, `RoutingDecision`, `TIER_DEFAULTS`, `SEVERITY_QUEUE_MAP` stay where they are. Only ADD new types in `shared/schemas/routing.py`.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `AnthropicModelConfig` | `llm_router/models.py:22-33` | Dataclass with model_id, pricing, capability booleans. **Keep as backward-compat alias; do NOT delete.** |
| `MODEL_REGISTRY` | `llm_router/models.py:38-65` | 4-tier Anthropic-only registry. **Convert entries to `ModelConfig`; preserve exact values.** |
| `ModelTier` | `llm_router/models.py:12-17` | `str, Enum` with TIER_0, TIER_1, TIER_1_PLUS, TIER_2. **Do NOT modify.** |
| `TASK_TIER_MAP` | `llm_router/router.py:23-45` | 18 tasks → tier mapping. **Do NOT modify values; add parallel `TASK_CAPABILITIES` map.** |
| `LLMRouter.route()` | `llm_router/router.py:60-120` | 5-level override chain. **Add capability validation AFTER existing logic; do NOT change override order.** |
| `TaskContext` | `llm_router/models.py:70-80` | Input dataclass for routing. **Do NOT modify.** |
| `RoutingDecision` | `llm_router/models.py:83-94` | Output dataclass. **Change `model_config` type hint from `AnthropicModelConfig` to `ModelConfig`.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path | Epic Said (WRONG) |
|---|---|---|
| LLM Router service | `llm_router/` | `services/llm_router/` |
| Routing models | `llm_router/models.py` | `shared/schemas/routing.py` (doesn't exist yet) |
| Router logic | `llm_router/router.py` | `services/llm_router/router.py` |
| Context Gateway | `context_gateway/gateway.py` | `services/context_gateway/gateway.py` |
| Router tests | `tests/test_llm_router/` | (correct in epic) |
| Shared schemas | `shared/schemas/` | (correct in epic) |

### Current `AnthropicModelConfig` (llm_router/models.py:22-33)

```python
@dataclass
class AnthropicModelConfig:
    model_id: str
    max_context_tokens: int
    cost_per_mtok_input: float
    cost_per_mtok_output: float
    supports_extended_thinking: bool = False
    supports_tool_use: bool = True
    supports_prompt_caching: bool = True
    batch_eligible: bool = False
```

### Current `MODEL_REGISTRY` (llm_router/models.py:38-65)

```python
MODEL_REGISTRY: dict[ModelTier, AnthropicModelConfig] = {
    ModelTier.TIER_0: AnthropicModelConfig(
        model_id="claude-haiku-4-5-20251001",
        max_context_tokens=200_000,
        cost_per_mtok_input=0.80,
        cost_per_mtok_output=4.0,
    ),
    ModelTier.TIER_1: AnthropicModelConfig(
        model_id="claude-sonnet-4-5-20250929",
        max_context_tokens=200_000,
        cost_per_mtok_input=3.0,
        cost_per_mtok_output=15.0,
    ),
    ModelTier.TIER_1_PLUS: AnthropicModelConfig(
        model_id="claude-opus-4-6",
        max_context_tokens=200_000,
        cost_per_mtok_input=15.0,
        cost_per_mtok_output=75.0,
        supports_extended_thinking=True,
    ),
    ModelTier.TIER_2: AnthropicModelConfig(
        model_id="claude-sonnet-4-5-20250929",
        max_context_tokens=200_000,
        cost_per_mtok_input=1.5,
        cost_per_mtok_output=7.5,
        batch_eligible=True,
    ),
}
```

### Current `TASK_TIER_MAP` (llm_router/router.py:23-45)

18 tasks across 3 active tiers (6 per tier):
- **Tier 0** (Haiku): ioc_extraction, log_summarisation, entity_normalisation, fp_suggestion, alert_classification, severity_assessment
- **Tier 1** (Sonnet): investigation, ctem_correlation, atlas_reasoning, attack_path_analysis, incident_report, playbook_selection
- **Tier 2** (Batch): fp_pattern_training, playbook_generation, agent_red_team, detection_rule_generation, retrospective_analysis, threat_landscape_summary

### TaskCapabilities Reference Table (for Task 4.1)

All 18 tasks MUST have entries in `TASK_CAPABILITIES`. Use these values:

| Task | requires_tool_use | requires_json_reliability | max_context_tokens | latency_slo_seconds | requires_extended_thinking |
|---|---|---|---|---|---|
| **Tier 0 tasks** |
| `ioc_extraction` | False | True | 4096 | 3 | False |
| `log_summarisation` | False | False | 8192 | 3 | False |
| `entity_normalisation` | False | True | 4096 | 3 | False |
| `fp_suggestion` | False | True | 4096 | 3 | False |
| `alert_classification` | False | True | 4096 | 3 | False |
| `severity_assessment` | False | True | 4096 | 3 | False |
| **Tier 1 tasks** |
| `investigation` | True | True | 100000 | 30 | False |
| `ctem_correlation` | True | True | 50000 | 30 | False |
| `atlas_reasoning` | True | True | 50000 | 30 | False |
| `attack_path_analysis` | True | True | 100000 | 30 | False |
| `incident_report` | False | True | 50000 | 30 | False |
| `playbook_selection` | True | True | 50000 | 30 | False |
| **Tier 2 tasks (batch)** |
| `fp_pattern_training` | False | True | 200000 | 86400 | False |
| `playbook_generation` | True | True | 100000 | 86400 | False |
| `agent_red_team` | True | True | 200000 | 86400 | False |
| `detection_rule_generation` | True | True | 100000 | 86400 | False |
| `retrospective_analysis` | False | True | 200000 | 86400 | False |
| `threat_landscape_summary` | False | False | 200000 | 86400 | False |

**Notes:** Tier 0 tasks have `latency_slo_seconds=3` matching the route() time budget override. Tier 2 batch tasks use `86400` (24h). `requires_extended_thinking` is always False (escalation to Opus is handled dynamically by `EscalationManager`, not by capability matching).

### `LLMRouter.route()` Override Chain (llm_router/router.py:60-120)

```
1. Base tier from TASK_TIER_MAP (default TIER_1 if unknown)
2. Time budget < 3s → force TIER_0
3. Critical severity + requires_reasoning → min TIER_1
4. Context > 100K tokens → min TIER_1
5. Low confidence < 0.6 on critical/high → TIER_1_PLUS
```

### Task 2 Design Decision: `ModelConfig` vs `AnthropicModelConfig` Bridge

**Recommended approach:** Create `ModelConfig` as a Pydantic `BaseModel` in `shared/schemas/routing.py` with ALL fields from `AnthropicModelConfig` PLUS `provider: LLMProvider` and `capabilities: TaskCapabilities`. Then in `llm_router/models.py`:
1. Keep `AnthropicModelConfig` dataclass definition (unchanged)
2. Add `ModelConfig.from_anthropic(config: AnthropicModelConfig) -> ModelConfig` classmethod
3. Update `MODEL_REGISTRY` type to `dict[ModelTier, ModelConfig]` and convert entries
4. `RoutingDecision.model_config` → type `ModelConfig`

This approach:
- Does NOT break any `AnthropicModelConfig` imports
- Allows `MODEL_REGISTRY` to hold mixed-provider configs (preparation for 12.3)
- Existing tests that check `model_config.model_id` etc. still work because `ModelConfig` has the same fields

**CIRCULAR IMPORT WARNING:** The `from_anthropic` classmethod MUST NOT import `AnthropicModelConfig` from `llm_router.models` inside `shared/schemas/routing.py` — this creates a circular import (`shared` → `llm_router` → `shared`). Instead, either: (a) place the `from_anthropic` factory in `llm_router/models.py` (not in shared), or (b) accept a `dict` / use `TYPE_CHECKING` guard with `Any` for the parameter type. **Option (a) is recommended** — the factory lives alongside the legacy type it converts.

**ROUTING DECISION IDENTITY CONSTRAINT:** `RoutingDecision` MUST remain a stdlib `@dataclass` (NOT Pydantic BaseModel) so that `test_router.py::TestBaseRouting::test_model_config_matches_tier` identity assertion (`decision.model_config is MODEL_REGISTRY[decision.tier]`) continues to pass. Pydantic BaseModel would copy/coerce on assignment, breaking `is` identity.

### Existing Test Classes That MUST Still Pass

**test_models.py (23 tests):**
- `TestModelTier` — 4 tests
- `TestAnthropicModelConfig` — 7 tests
- `TestTaskContext` — 2 tests
- `TestRoutingDecision` — 2 tests
- `TestTierDefaults` — 4 tests
- `TestSeverityQueueMap` — 4 tests

**test_router.py (28 tests):**
- `TestTaskTierMap` — 4 tests
- `TestBaseRouting` — 5 tests
- `TestTimeBudgetOverride` — 3 tests
- `TestSeverityOverride` — 4 tests
- `TestContextSizeOverride` — 3 tests
- `TestEscalationOverride` — 5 tests
- `TestOverrideInteractions` — 4 tests

**test_concurrency.py, test_escalation.py, test_metrics.py** — must all pass (no changes expected)

### Testing Patterns

- Test framework: **pytest**
- Import style: `from llm_router.models import ModelTier, AnthropicModelConfig`
- New schema tests: `from shared.schemas.routing import LLMProvider, ModelConfig, TaskCapabilities`
- Test file naming: `test_<module>.py` in `tests/test_<service>/`
- Run frequently: `pytest tests/test_llm_router/ -v` after every change

### Project Structure Notes

- All source modules at repo root level: `context_gateway/`, `shared/`, `llm_router/`, `orchestrator/` — NOT inside `services/`
- Tests mirror source: `tests/test_llm_router/`, `tests/test_schemas/`
- Shared schemas: `shared/schemas/` (Pydantic v2 BaseModel)
- LLM Router models: `llm_router/models.py` (stdlib dataclass)
- This story creates: `shared/schemas/routing.py` (NEW) and `tests/test_schemas/test_routing.py` (NEW)

### Previous Story Intelligence (12.1)

- File path corrections: Epic `services/` prefix is WRONG — use root-level paths
- `shared/schemas/__init__.py` already exports `DecisionEntry`, `AgentRole`, `GraphState`, etc.
- Full test suite was 1109 tests passing at end of 12.1
- Red-green-refactor cycle worked well: write failing tests first, implement minimal code
- Pydantic v2 `BaseModel` with `from __future__ import annotations` is the pattern
- `AnthropicModelConfig` in `llm_router/models.py` uses stdlib `@dataclass`, NOT Pydantic

### References

- [Source: docs/remediation-backlog.md#REM-C02 Part A] — Provider abstraction requirements
- [Source: docs/prd.md#NFR-REL-001] — 5-level degradation strategy
- [Source: docs/prd.md#FR-ING-005] — LLM work queue routing
- [Source: _bmad-output/planning-artifacts/architecture.md Section 3.4] — 4-tier LLM routing
- [Source: llm_router/models.py:22-65] — Current AnthropicModelConfig + MODEL_REGISTRY
- [Source: llm_router/router.py:23-120] — Current TASK_TIER_MAP + LLMRouter.route()
- [Source: docs/research-notes.md] — Trusted Autonomy framework validates degradation-level mapping

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

### Completion Notes List

- All 5 tasks complete with zero regressions against existing 1109-test baseline
- Net +21 new tests (7 LLMProvider/TaskCapabilities + 5 ModelConfig + 4 mapping + 5 capability matching)
- `AnthropicModelConfig` dataclass preserved unchanged for backward compatibility
- `RoutingDecision` remains stdlib `@dataclass` — identity assertion (`is`) still works
- Capability matching integrated as log-only (Story 12.3 will use for fallback routing)
- All 18 tasks have `TASK_CAPABILITIES` entries matching reference table values

### File List

**Modified:**
- `llm_router/models.py` — import shared types, convert MODEL_REGISTRY to ModelConfig, keep AnthropicModelConfig compat
- `llm_router/router.py` — add TASK_CAPABILITIES map, capability matching helper, integrate into route()
- `llm_router/__init__.py` — add new exports
- `shared/schemas/__init__.py` — export LLMProvider, ModelConfig, TaskCapabilities

**Created:**
- `shared/schemas/routing.py` — LLMProvider enum, TaskCapabilities model, ModelConfig model
- `tests/test_schemas/test_routing.py` — unit tests for new schema types

### Change Log

- Task 1: Created `shared/schemas/routing.py` with `LLMProvider` enum and `TaskCapabilities` model; 7 tests green
- Task 2: Added `ModelConfig` Pydantic model to `shared/schemas/routing.py`; 12 tests green
- Task 3: Converted `MODEL_REGISTRY` to `ModelConfig` entries; 23/23 model tests + 120/120 router tests pass
- Task 4: Added `TASK_CAPABILITIES` (18 entries), `_matches_capabilities` helper, log-only check in `route()`; 21/21 schema tests + 120/120 router tests pass
- Task 5: Updated `llm_router/__init__.py` exports; 1130/1130 full project tests pass; all import paths verified
