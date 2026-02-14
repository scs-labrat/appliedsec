# Story 2.4: Create Qdrant Collection Initialisation

## Status: done

## Description
Initialisation script that creates all Qdrant collections with correct vector config.

## Tasks
- [x] Create `infra/scripts/init_qdrant.py` with 4 collection definitions
- [x] Collections: aluskort-mitre, aluskort-threat-intel, aluskort-playbooks, aluskort-incident-memory
- [x] Vector size 1024, Cosine distance, HNSW m=16, ef_construct=200
- [x] Idempotent: skip existing collections
- [x] Write tests in `tests/test_infra/test_qdrant_init.py`
- [x] All 7 tests pass

## Completion Notes
- Script is both CLI-runnable and importable
- `init_collections()` returns dict mapping collection name to "created" or "already_exists"
- 7/7 tests pass
