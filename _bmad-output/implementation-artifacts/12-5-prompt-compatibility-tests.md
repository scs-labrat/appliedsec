# Story 12.5: Prompt Compatibility Tests

Status: review

## Story

As a platform using multiple LLM providers,
I want a prompt adapter per provider and contract tests proving primary and secondary produce structurally compatible output,
so that failover does not break downstream processing.

## Acceptance Criteria

1. **Given** an ALUSKORT internal prompt, **When** adapted for OpenAI, **Then** system prompt, message format, and JSON output directives are correctly translated.
2. **Given** the Anthropic prompt adapter, **When** adapting a prompt, **Then** it produces the existing `cache_control` block format unchanged (backward compat).
3. **Given** all Tier 0 and Tier 1 task types, **When** contract tests run against both adapters, **Then** output schema structure is compatible for each task type.
4. **Given** the adapter abstraction, **When** used in `ContextGateway`, **Then** it replaces the hardcoded `build_cached_system_blocks()` call with a provider-dispatched adapter.

## Tasks / Subtasks

- [x] Task 1: Create PromptAdapter abstract base and AnthropicPromptAdapter (AC: 2, 4)
  - [x] 1.1: Create `context_gateway/prompt_adapter.py` with `PromptAdapter` ABC defining `adapt_system(task_prompt: str) -> list[dict[str, Any]]`, `adapt_messages(user_content: str) -> list[dict[str, Any]]`, `adapt_output_schema(schema: dict | None) -> dict | None`, `provider: LLMProvider` property.
  - [x] 1.2: Add `AnthropicPromptAdapter(PromptAdapter)` that wraps existing `build_cached_system_blocks()` and `build_system_prompt()` from `context_gateway/prompt_builder.py`. System: `[{"type": "text", "text": full_prompt, "cache_control": {"type": "ephemeral"}}]`. Messages: `[{"role": "user", "content": user_content}]`. Output schema: pass through unchanged.
  - [x] 1.3: Add unit tests in `tests/test_context_gateway/test_prompt_adapter.py` — `TestAnthropicAdapter` class: produces cache_control blocks, includes safety prefix, message format correct, output schema passthrough. (~6 tests)
- [x] Task 2: Create OpenAIPromptAdapter (AC: 1)
  - [x] 2.1: Add `OpenAIPromptAdapter(PromptAdapter)` to `context_gateway/prompt_adapter.py`. System: `[{"role": "system", "content": full_prompt}]` (no cache_control). Messages: `[{"role": "user", "content": user_content}]`. Output schema: if schema provided, wrap as `{"response_format": {"type": "json_object"}}` directive.
  - [x] 2.2: Safety prefix MUST be included in OpenAI system prompt (same `SYSTEM_PREFIX` from `prompt_builder.py`).
  - [x] 2.3: Add unit tests in `tests/test_context_gateway/test_prompt_adapter.py` — `TestOpenAIAdapter` class: no cache_control, includes safety prefix, JSON mode directive when schema provided, message format correct. (~6 tests)
- [x] Task 3: Create PromptAdapterFactory (AC: 4)
  - [x] 3.1: Add `PromptAdapterFactory` class or `get_adapter(provider: LLMProvider) -> PromptAdapter` function to `context_gateway/prompt_adapter.py`. Maps `LLMProvider.ANTHROPIC` → `AnthropicPromptAdapter`, `LLMProvider.OPENAI` → `OpenAIPromptAdapter`. Raises `ValueError` for unsupported providers.
  - [x] 3.2: Add unit tests — `TestAdapterFactory` class: returns correct adapter type for each provider, raises on unsupported. (~4 tests)
- [x] Task 4: Contract tests for prompt schema compatibility (AC: 3)
  - [x] 4.1: Create `tests/test_context_gateway/test_prompt_contract.py` with `TestPromptSchemaContract` class. For each Tier 0 and Tier 1 task type (12 tasks total), verify that both Anthropic and OpenAI adapters produce:
    - System prompt containing the same safety prefix text
    - Message list with at least one user message
    - Structurally valid output (list of dicts for system, list of dicts for messages)
  - [x] 4.2: Test that adapted prompts for the same input are structurally equivalent (same information content, different format). (~12 tests — one per task type for both adapters)
- [x] Task 5: Update exports and run full regression (AC: 1-4)
  - [x] 5.1: Update `context_gateway/__init__.py` — add `PromptAdapter`, `AnthropicPromptAdapter`, `OpenAIPromptAdapter`, `get_adapter` to exports.
  - [x] 5.2: Run full project test suite (`pytest tests/`) — all 1243 tests pass (zero regressions, 53 new tests)
  - [x] 5.3: Verify existing `build_cached_system_blocks()` still works (not removed, AnthropicPromptAdapter wraps it)

## Dev Notes

### Critical Architecture Constraints

- **This is Part D of REM-C02.** Stories 12.2 (Provider Abstraction) and 12.3 (Secondary Registration) are COMPLETE. Reuse `LLMProvider`, `ModelConfig`.
- **DO NOT modify `ContextGateway.complete()`** pipeline in this story. The gateway still uses `build_cached_system_blocks()` directly. Future story will swap to adapter dispatch. This story creates the adapters and proves compatibility via contract tests.
- **DO NOT implement actual OpenAI API client.** This story creates prompt format adapters only. The OpenAI client implementation is a follow-up concern.
- **Preserve existing `prompt_builder.py`** — `AnthropicPromptAdapter` wraps existing functions, does not replace them.
- **Safety prefix is mandatory** for ALL providers — `SYSTEM_PREFIX` from `prompt_builder.py` must appear in every adapted prompt.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `SYSTEM_PREFIX` | `context_gateway/prompt_builder.py:12-18` | Safety instruction prefix. **MUST appear in all adapted prompts.** |
| `build_system_prompt()` | `context_gateway/prompt_builder.py:21-23` | Prepends safety prefix. **Wrap in AnthropicPromptAdapter.** |
| `build_cached_system_blocks()` | `context_gateway/prompt_builder.py:26-40` | Anthropic cache format. **Wrap in AnthropicPromptAdapter.** |
| `LLMProvider` | `shared/schemas/routing.py:14-20` | Provider enum. **Use as adapter dispatch key.** |
| `TASK_TIER_MAP` | `llm_router/router.py:33-55` | Task → tier mapping. **Use to enumerate Tier 0/1 tasks for contract tests.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Prompt builder | `context_gateway/prompt_builder.py` |
| Gateway | `context_gateway/gateway.py` |
| Anthropic client | `context_gateway/anthropic_client.py` |
| Shared schemas | `shared/schemas/routing.py` |
| Prompt adapter (NEW) | `context_gateway/prompt_adapter.py` |
| Adapter tests (NEW) | `tests/test_context_gateway/test_prompt_adapter.py` |
| Contract tests (NEW) | `tests/test_context_gateway/test_prompt_contract.py` |
| Prompt builder tests | `tests/test_context_gateway/test_prompt_builder.py` |

### Prompt Format Comparison

**Anthropic format (current):**
```python
system = [{"type": "text", "text": "SAFETY PREFIX + task prompt", "cache_control": {"type": "ephemeral"}}]
messages = [{"role": "user", "content": "redacted content"}]
```

**OpenAI format (target):**
```python
system = [{"role": "system", "content": "SAFETY PREFIX + task prompt"}]
messages = [{"role": "user", "content": "redacted content"}]
# If JSON output needed:
response_format = {"type": "json_object"}
```

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_prompt_builder.py (7 tests):**
- `TestBuildSystemPrompt` — 3 tests
- `TestBuildCachedSystemBlocks` — 4 tests

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**
- Adapter tests: construct adapter, call methods, verify output structure
- Contract tests: iterate TASK_TIER_MAP for Tier 0 and Tier 1 tasks, call both adapters with same input, verify structural equivalence
- No mocking needed (pure function adapters)

### References

- [Source: docs/remediation-backlog.md#REM-C02 Part D] — Prompt compatibility test requirements
- [Source: docs/ai-system-design.md Section 7.4-7.5] — Prompt injection detection and safety prefix
- [Source: docs/prd.md#NFR-REL-001] — 5-level degradation strategy (secondary provider must work)
- [Source: context_gateway/prompt_builder.py:12-18] — SYSTEM_PREFIX constant

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

### Completion Notes List

- Created PromptAdapter ABC with adapt_system(), adapt_messages(), adapt_output_schema() interface
- AnthropicPromptAdapter wraps existing build_cached_system_blocks() — preserves cache_control format
- OpenAIPromptAdapter produces role-based system format without cache_control, adds json_object response_format when schema provided
- get_adapter() factory dispatches by LLMProvider enum, raises ValueError for unsupported providers
- 36 contract tests verify structural compatibility across all 12 Tier 0/1 task types for both providers
- Safety prefix (SYSTEM_PREFIX) verified present in both provider formats across all task types
- Existing build_cached_system_blocks() and build_system_prompt() unchanged — backward compat preserved
- 53 new tests, 1243 total passing

### File List

**Created:**
- `context_gateway/prompt_adapter.py` — PromptAdapter ABC, AnthropicPromptAdapter, OpenAIPromptAdapter, get_adapter factory
- `tests/test_context_gateway/test_prompt_adapter.py` — Adapter unit tests (6 Anthropic + 7 OpenAI + 4 factory = 17 tests)
- `tests/test_context_gateway/test_prompt_contract.py` — Cross-provider contract tests (36 parametrized tests)

**Modified:**
- `context_gateway/__init__.py` — export PromptAdapter, AnthropicPromptAdapter, OpenAIPromptAdapter, get_adapter

### Change Log

- 2026-02-21: Story 12.5 implemented — PromptAdapter ABC, Anthropic/OpenAI adapters, factory, 36 contract tests. 53 new tests, 1243 total passing.
