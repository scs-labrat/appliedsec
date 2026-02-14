# Story 7.2 — IOC Extractor Agent

## Status: Done

## Implementation

### Files
- `orchestrator/agents/ioc_extractor.py` — IOCExtractorAgent (Tier 0 Haiku via Context Gateway + Redis enrichment)

### Key Decisions
- Calls Context Gateway with task_type="ioc_extraction" for Haiku routing
- Enriches each IOC from Redis cache (fail-open on miss)
- Tracks llm_calls, total_cost_usd, queries_executed
- State transition: RECEIVED → PARSING

### Test Coverage
- `tests/test_orchestrator/test_ioc_extractor.py` — 13 tests (extraction, enrichment, cost tracking, JSON parsing)
