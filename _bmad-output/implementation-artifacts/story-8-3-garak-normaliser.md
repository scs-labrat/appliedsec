# Story 8.3 — Garak Normaliser

## Status: Done

## Implementation

### Files
- `ctem_normaliser/garak.py` — GarakNormaliser with probe type → ATLAS mapping

### Key Decisions
- 7 probe types mapped: escalation, tool_use, prompt_injection, extraction, exfiltration, jailbreak, encoding
- Escalation/tool_use/jailbreak → safety_life + AML.T0051
- Extraction/exfiltration → data_loss + AML.T0044.001
- Success rate → exploitability level (≥0.7 high, ≥0.3 medium, <0.3 low)
- Asset type always "llm_model"

### Test Coverage
- `tests/test_ctem_normaliser/test_garak.py` — 17 tests
