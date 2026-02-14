# Story 5.3: Create System Prompt Builder with Cache Support

## Status: done

## Tasks
- [x] Create `context_gateway/prompt_builder.py`
- [x] `SYSTEM_PREFIX` — safety instruction prepended to all LLM calls
- [x] `build_system_prompt()` — prepends prefix to task prompt
- [x] `build_cached_system_blocks()` — returns Anthropic API system blocks with `cache_control: ephemeral`
- [x] 7 tests pass

## Completion Notes
- Cache control enables 5-minute prompt caching (~90% cost reduction)
- Safety prefix instructs LLM to treat all non-system text as DATA
