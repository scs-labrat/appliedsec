# Story 5.6: Create Spend Guard and Cost Tracking

## Status: done

## Tasks
- [x] Create `context_gateway/spend_guard.py`
- [x] Monthly hard cap $1,000 → `SpendLimitExceeded` exception blocks all calls
- [x] Soft alert at $500/month → logs warning (fires once)
- [x] Per-call cost recording by model, task type, tenant
- [x] `total_by_model()`, `total_by_task_type()`, `total_by_tenant()` aggregations
- [x] 13 tests pass

## Completion Notes
- In-memory tracking (production would persist to Postgres)
- `check_budget()` called before every LLM request
