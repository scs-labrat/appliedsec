# Story 8.1 — Wiz Normaliser

## Status: Done

## Implementation

### Files
- `ctem_normaliser/wiz.py` — WizNormaliser with zone classification and consequence mapping

### Key Decisions
- Severity → exploitability: CRITICAL/HIGH → high(0.9), MEDIUM → medium(0.5), LOW/INFO → low(0.2)
- Zone classification: edge/orbital → Zone1, demo/public → Zone4, default → Zone3
- Consequence from ZONE_CONSEQUENCE_FALLBACK (Neo4j fallback path)
- Deterministic exposure_key via sha256(wiz:title:asset_id)[:16]

### Test Coverage
- `tests/test_ctem_normaliser/test_wiz.py` — 13 tests
