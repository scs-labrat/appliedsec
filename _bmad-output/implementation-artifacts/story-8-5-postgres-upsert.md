# Story 8.5 — Postgres Upsert Logic

## Status: Done

## Implementation

### Files
- `ctem_normaliser/upsert.py` — CTEMRepository with parameterised ON CONFLICT upsert

### Key Decisions
- 22-param parameterised SQL ($1–$22), zero string interpolation
- ON CONFLICT (exposure_key) updates ts, severity, ctem_score, updated_at
- Status preserved if current is Verified or Closed (CASE expression)
- Fetch by asset_id excludes Verified/Closed, ordered by ctem_score DESC

### Test Coverage
- `tests/test_ctem_normaliser/test_upsert.py` — 11 tests (upsert params, SQL safety, fetch)
