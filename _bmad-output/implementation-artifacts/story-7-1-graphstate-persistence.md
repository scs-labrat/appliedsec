# Story 7.1 — GraphState & Investigation Persistence

## Status: Done

## Implementation

### Files
- `shared/schemas/investigation.py` — InvestigationState (8 states), AgentRole (6 roles), GraphState (20 fields) — from Epic 1
- `orchestrator/persistence.py` — InvestigationRepository (save, load, transition, list_by_state)
- `orchestrator/agents/base.py` — AgentNode protocol

### Key Decisions
- GraphState is a Pydantic BaseModel for JSON serialisation
- Postgres upsert with ON CONFLICT for idempotent saves
- Each transition appends immutable decision_chain entry with timestamp
- Load supports both dict and JSON string from Postgres JSONB

### Test Coverage
- `tests/test_orchestrator/test_state.py` — 9 tests (enums, defaults, serialisation)
- `tests/test_orchestrator/test_persistence.py` — 13 tests (save, load, transition, list)
