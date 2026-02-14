# Story 8.4 — ART Normaliser

## Status: Done

## Implementation

### Files
- `ctem_normaliser/art.py` — ARTNormaliser with attack type → ATLAS/consequence mapping

### Key Decisions
- Attack types: poisoning → safety_life + AML.T0020, evasion → equipment + AML.T0015, extraction → data_loss + AML.T0044
- Success rate → exploitability (same thresholds as Garak)
- Preserves both ATLAS and ATT&CK technique IDs
- Poisoning at high rate → CRITICAL (highest risk path)

### Test Coverage
- `tests/test_ctem_normaliser/test_art.py` — 16 tests
