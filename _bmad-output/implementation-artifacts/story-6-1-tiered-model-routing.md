# Story 6.1 — Tiered Model Routing

## Status: Done

## Implementation

### Files Created
- `llm_router/models.py` — ModelTier enum (TIER_0/1/1+/2), AnthropicModelConfig, MODEL_REGISTRY, TaskContext, RoutingDecision, TIER_DEFAULTS, SEVERITY_QUEUE_MAP
- `llm_router/router.py` — LLMRouter with TASK_TIER_MAP (18 task types) and 5-step override chain
- `llm_router/__init__.py` — Package exports

### Key Decisions
- **Four-tier architecture**: Tier 0 (Haiku), Tier 1 (Sonnet), Tier 1+ (Opus), Tier 2 (Sonnet Batch)
- **Override chain**: base → time_budget<3s→T0 → critical+reasoning→T1 → context>100K→T1 → low_confidence→T1+
- **18 task types mapped**: 6 per tier (T0, T1, T2); unknown tasks default to Tier 1
- **SEVERITY_QUEUE_MAP**: Maps 5 severity levels to priority Kafka queues

### Test Coverage
- `tests/test_llm_router/test_models.py` — 22 tests (enum, configs, registry, defaults, queue map)
- `tests/test_llm_router/test_router.py` — 22 tests (base routing, all 4 overrides, interactions)
