# Story 7.6 — CTEM Correlator Agent

## Status: Done

## Implementation

### Files
- `orchestrator/agents/ctem_correlator.py` — CTEMCorrelatorAgent

### Key Decisions
- Queries Postgres ctem_exposures by asset_id (hosts + IPs)
- Excludes Verified/Closed statuses
- Staleness detection: updated_at > 24 hours → stale flag
- SLA deadlines: CRITICAL=24h, HIGH=72h, MEDIUM=14d, LOW=30d
- Non-blocking: empty result on no entities, no crash on missing data

### Test Coverage
- `tests/test_orchestrator/test_ctem_correlator.py` — 12 tests (correlation, staleness, SLA, constants)
