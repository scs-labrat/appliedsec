# Story 8.2 — Snyk Normaliser

## Status: Done

## Implementation

### Files
- `ctem_normaliser/snyk.py` — SnykNormaliser with CVSS mapping and ML package escalation

### Key Decisions
- CVSS exploitability sub-score ÷ 10 → exploitability_score (0–1)
- ML packages (torch, tensorflow, sklearn, etc.) → safety_life consequence
- Non-ML packages → data_loss consequence
- Zone always Zone3_Enterprise (SCA findings are enterprise-scoped)

### Test Coverage
- `tests/test_ctem_normaliser/test_snyk.py` — 15 tests
