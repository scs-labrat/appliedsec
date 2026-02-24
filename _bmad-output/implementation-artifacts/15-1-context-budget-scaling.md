# Story 15.1: Context Budget Scaling

Status: review

## Story

As a platform handling complex multi-technique investigations,
I want hierarchical retrieval (first pass candidates → structured case facts → second pass deep context) with tier-based context budgets (Tier 0: 4,096, Tier 1: 8,192, Tier 1+: 16,384 tokens),
so that complex investigations get adequate context without wasting tokens on simple triage.

## Acceptance Criteria

1. **Given** a Tier 0 task, **When** context is assembled, **Then** the budget is 4,096 tokens.
2. **Given** a Tier 1 task, **When** context is assembled, **Then** the budget is 8,192 tokens.
3. **Given** a Tier 1+ task, **When** context is assembled, **Then** the budget is 16,384 tokens.
4. **Given** hierarchical retrieval, **When** first pass completes, **Then** case facts are structured (entities, IOCs, techniques, timeline) before second-pass retrieval.
5. **Given** structured case memory, **When** stored, **Then** token tax is not re-paid across investigation steps.

## Tasks / Subtasks

- [x] Task 1: Define tier-based context budgets (AC: 1, 2, 3)
  - [x] 1.1: Added `CONTEXT_BUDGET_BY_TIER` dict to `context_gateway/prompt_builder.py`.
  - [x] 1.2: Added `get_context_budget(tier: str) -> int` function.
  - [x] 1.3: Added `truncate_to_budget(text: str, budget_tokens: int) -> str` function.
  - [x] 1.4: Added `TestContextBudget` — 8 tests.
- [x] Task 2: Create structured case facts (AC: 4, 5)
  - [x] 2.1: Added `CaseFacts` dataclass to `orchestrator/agents/context_enricher.py`.
  - [x] 2.2: Added `extract_case_facts(state: GraphState) -> CaseFacts` function.
  - [x] 2.3: Added `case_facts: dict[str, Any] = {}` field to `GraphState`.
  - [x] 2.4: Added `TestCaseFacts` — 5 tests.
- [x] Task 3: Implement hierarchical retrieval (AC: 4)
  - [x] 3.1: Two-pass retrieval in `ContextEnricherAgent.execute()` — first pass broad, structure case facts, second pass deep.
  - [x] 3.2: Second pass only for Tier 1+ (tier_1, tier_1_plus, tier_2).
  - [x] 3.3: Added `tier: str = "tier_0"` keyword parameter (backward compat).
  - [x] 3.4: Added `TestHierarchicalRetrieval` — 4 tests.
- [x] Task 4: Integrate budget enforcement into prompt assembly (AC: 1, 2, 3, 5)
  - [x] 4.1: Added `build_request_with_budget()` to `context_gateway/prompt_builder.py`.
  - [x] 4.2: Backward compat: existing `build_system_prompt()` unchanged.
  - [x] 4.3: Added `TestBudgetEnforcement` — 5 tests.
- [x] Task 5: Run full regression (AC: 1-5)
  - [x] 5.1: Run full project test suite — all 1928 tests pass (zero regressions)
  - [x] 5.2: Existing context enricher tests pass unchanged

## Dev Notes

### Critical Architecture Constraints

- **REM-M01** — current FR-RAG-008 sets a flat 4,096-token budget for all tiers. Complex multi-technique investigations need more context.
- **Tier-based scaling** — simple triage (Tier 0) gets 4K tokens; complex reasoning (Tier 1+) gets 16K tokens.
- **Hierarchical retrieval** — two-pass retrieval prevents wasting the full budget on broad, shallow results.
- **Case facts prevent re-retrieval** — structured intermediate representation stored in GraphState avoids re-paying token costs across investigation steps.
- **Backward compat** — `ContextEnricherAgent()` with no `tier` parameter defaults to Tier 0 (existing behavior).
- **DO NOT change the LLM routing tier logic** — only the context assembly budget changes. Tier selection in `LLMRouter` is unchanged.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `ContextEnricherAgent` | `orchestrator/agents/context_enricher.py` | Context enrichment. **Add hierarchical retrieval.** |
| `build_system_prompt()` | `context_gateway/prompt_builder.py:21-23` | Prompt builder. **Do NOT modify; add new function.** |
| `SYSTEM_PREFIX` | `context_gateway/prompt_builder.py:12-18` | Safety prefix. **Always prepended.** |
| `GraphState` | `shared/schemas/investigation.py` | Investigation state. **Add case_facts field.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Budget tests (NEW) | `tests/test_context_gateway/test_context_budget.py` |
| Prompt builder | `context_gateway/prompt_builder.py` |
| Context enricher | `orchestrator/agents/context_enricher.py` |
| Investigation schemas | `shared/schemas/investigation.py` |

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_context_gateway/test_prompt_builder.py (7 tests):**
- All unchanged

**test_orchestrator/ (existing enricher tests):**
- All unchanged (backward compat via default tier)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**, **pytest-asyncio**
- Test budget math: verify token counts per tier
- Test truncation: long text → fits within budget
- Test hierarchical retrieval with mocked data stores
- Test case_facts persistence in GraphState

### Dependencies on Other Stories

- **None.** Can start immediately.

### References

- [Source: docs/remediation-backlog.md#REM-M01] — Context budget scaling requirement
- [Source: docs/prd.md#FR-RAG-008] — Token budget requirement
- [Source: docs/prd.md#NFR-PRF-002] — Performance requirement

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- No regressions. Clean implementation.

### Completion Notes List

- **Task 1 (Budget constants):** `CONTEXT_BUDGET_BY_TIER` (T0: 4096, T1: 8192, T1+/T2: 16384), `get_context_budget()`, `truncate_to_budget()` using 4 chars ≈ 1 token estimator. 8 tests.
- **Task 2 (CaseFacts):** `CaseFacts` dataclass with entities, iocs, techniques, timeline, similar_incidents, token_estimate. `extract_case_facts()` structures first-pass results. `case_facts: dict` added to GraphState. 5 tests.
- **Task 3 (Hierarchical retrieval):** Two-pass retrieval — first pass: existing parallel lookups (IOC, UEBA, similar). After first pass, `extract_case_facts()` structures results. Second pass (Tier 1+ only): `_deep_retrieval()` fetches technique intel and deep entity context. `tier` parameter defaults to `"tier_0"` for backward compat. 4 tests.
- **Task 4 (Budget enforcement):** `build_request_with_budget()` assembles prompt with tier-based budget enforcement. Reserves overhead for system prefix + instructions + evidence, then truncates retrieval context to fit remaining budget. 5 tests.
- **Task 5 (Regression):** 1928 tests passed, 0 failures. Zero regressions — all existing tests pass unchanged.

### File List

**Created:**
- `tests/test_context_gateway/test_context_budget.py` — 22 tests (8 budget + 5 case facts + 4 hierarchical + 5 enforcement)

**Modified:**
- `context_gateway/prompt_builder.py` — added CONTEXT_BUDGET_BY_TIER, DEFAULT_CONTEXT_BUDGET, get_context_budget, truncate_to_budget, build_request_with_budget
- `orchestrator/agents/context_enricher.py` — added CaseFacts dataclass, extract_case_facts(), two-pass hierarchical retrieval, tier parameter, _deep_retrieval(), _fetch_technique_intel(), _fetch_deep_entity_context()
- `shared/schemas/investigation.py` — added case_facts: dict[str, Any] = {} to GraphState

### Change Log

- 2026-02-24: Story 15.1 implemented — Context budget scaling with tier-based budgets (T0: 4096, T1: 8192, T1+: 16384), hierarchical two-pass retrieval, structured CaseFacts, budget-enforced prompt assembly. 22 new tests, 1928 total tests passing.
