# Story 7.8 — Investigation Graph Wiring

## Status: Done

## Implementation

### Files
- `orchestrator/graph.py` — InvestigationGraph state machine

### Key Decisions
- Full pipeline: RECEIVED → PARSING → FP_CHECK → ENRICHING (parallel) → REASONING → RESPONDING/AWAITING_HUMAN → CLOSED
- Parallel enrichment via asyncio.gather (ContextEnricher + CTEM + ATLAS)
- Merge results from parallel agents, tolerating individual failures
- Human approval: AWAITING_HUMAN pauses pipeline; resume_from_approval() continues or closes
- Error handling: unrecoverable errors → FAILED state with error in decision_chain
- UUID generation for investigation_id

### Test Coverage
- `tests/test_orchestrator/test_graph.py` — 12 tests (happy path, FP short-circuit, approval, errors, no-FP)
