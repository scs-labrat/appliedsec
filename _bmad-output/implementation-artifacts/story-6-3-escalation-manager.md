# Story 6.3 — Escalation Manager

## Status: Done

## Implementation

### Files Created
- `llm_router/escalation.py` — EscalationManager with configurable EscalationPolicy

### Key Decisions
- **Confidence threshold**: 0.6 — below triggers escalation consideration
- **Applicable severities**: critical, high only
- **Budget**: Max 10 escalations per hour (sliding window)
- **Extended thinking**: 8192 token budget for Opus escalations
- **Target tier**: Always escalates to TIER_1_PLUS (Opus)

### Test Coverage
- `tests/test_llm_router/test_escalation.py` — 24 tests (policy defaults, should_escalate, budget enforcement, custom policies)
