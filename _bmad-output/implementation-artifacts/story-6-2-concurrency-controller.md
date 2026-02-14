# Story 6.2 — Concurrency Controller

## Status: Done

## Implementation

### Files Created
- `llm_router/concurrency.py` — ConcurrencyController with priority-based rate limits and tenant quotas

### Key Decisions
- **Per-priority concurrency limits**: critical=8, high=6, normal=4, low=2
- **Per-priority RPM limits**: critical=200, high=100, normal=50, low=20
- **Tenant quotas**: premium=500/hr, standard=100/hr, trial=20/hr
- **Sliding window**: Timestamps older than 60s (RPM) or 3600s (quota) are pruned
- **QuotaExceeded exception** raised when tenant over hourly limit

### Test Coverage
- `tests/test_llm_router/test_concurrency.py` — 25 tests (slots, RPM, utilisation, tenant quotas)
