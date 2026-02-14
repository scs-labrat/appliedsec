# Story 5.5: Create Anthropic API Client Wrapper

## Status: done

## Tasks
- [x] Create `context_gateway/anthropic_client.py`
- [x] `AluskortAnthropicClient` wrapping `anthropic.AsyncAnthropic`
- [x] Exponential backoff retry for 429/5xx (3 retries, 1s→2s→4s). 4xx not retried.
- [x] `APICallMetrics` dataclass (input_tokens, output_tokens, cache_read/write, cost_usd, latency_ms)
- [x] `compute_cost()` from token counts and pricing table
- [x] Streaming support via `stream()` method (async iterator)
- [x] Default pricing for Sonnet 4.5 and Haiku 4.5
- [x] 11 tests pass

## Completion Notes
- Lazy import of `anthropic` package (tests don't require it installed)
- Pricing table is configurable; defaults to current Claude pricing
