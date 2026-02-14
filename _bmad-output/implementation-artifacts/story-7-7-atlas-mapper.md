# Story 7.7 — ATLAS Mapper Agent

## Status: Done

## Implementation

### Files
- `orchestrator/agents/atlas_mapper.py` — ATLASMapperAgent

### Key Decisions
- Two-path mapping: Postgres taxonomy_ids + Qdrant semantic search
- Deduplication by atlas_id, keeping highest confidence
- Taxonomy results get confidence=1.0, semantic uses Qdrant score
- Graceful on Qdrant failure; skips semantic search if no embedding

### Test Coverage
- `tests/test_orchestrator/test_atlas_mapper.py` — 8 tests (taxonomy, semantic, dedup, graceful failure)
