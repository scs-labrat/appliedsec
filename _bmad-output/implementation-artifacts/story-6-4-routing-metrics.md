# Story 6.4 — Routing Metrics

## Status: Done

## Implementation

### Files Created
- `llm_router/metrics.py` — RoutingMetrics collector with TierOutcome aggregation

### Key Decisions
- **Keying**: `task_type:tier` composite key for outcome tracking
- **Aggregated metrics**: success_rate, avg_cost, avg_latency_ms, avg_confidence
- **Summary method**: Returns dict suitable for dashboard display
- **Zero-safe**: All computed properties return 0.0 when total is 0

### Test Coverage
- `tests/test_llm_router/test_metrics.py` — 20 tests (TierOutcome properties, record/get, summary, integration scenario)
