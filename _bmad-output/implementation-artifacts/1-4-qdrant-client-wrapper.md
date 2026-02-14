---
story_id: "1.4"
story_key: "1-4-qdrant-client-wrapper"
title: "Create Qdrant Client Wrapper"
epic: "Epic 1: Foundation"
status: "done"
priority: "high"
---

# Story 1.4: Create Qdrant Client Wrapper

## Story

As a developer building ALUSKORT services,
I want a Qdrant vector database client wrapper with collection management, HNSW-tuned configuration, upsert/search operations, and error handling for circuit breaker integration,
so that all services interact with the vector store for semantic retrieval through a consistent, resilient interface.

## Acceptance Criteria

### AC-1.4.1: Client Initialization
**Given** valid Qdrant connection parameters (host, port, api_key)
**When** QdrantWrapper is instantiated
**Then** a qdrant_client.QdrantClient is created with the connection parameters

### AC-1.4.2: Collection Creation with HNSW Config
**Given** an active QdrantWrapper
**When** ensure_collection(name="incident_embeddings", vector_size=1536) is called and the collection does not exist
**Then** a new collection is created with HNSW config (m=16, ef_construct=200) and Cosine distance metric

### AC-1.4.3: Collection Already Exists
**Given** an active QdrantWrapper
**When** ensure_collection() is called for a collection that already exists
**Then** the method returns without error (idempotent)

### AC-1.4.4: Vector Upsert
**Given** an active QdrantWrapper with an existing collection
**When** upsert_vectors(collection="incident_embeddings", points=[{id, vector, payload}]) is called
**Then** the vectors are upserted into the collection with their associated payloads

### AC-1.4.5: Semantic Search
**Given** an active QdrantWrapper with a collection containing indexed vectors
**When** search(collection="incident_embeddings", query_vector=[...], limit=10) is called
**Then** the top-k most similar vectors are returned with scores and payloads

### AC-1.4.6: Search with Metadata Filter
**Given** an active QdrantWrapper
**When** search() is called with a filter (e.g., tenant_id="tenant-a")
**Then** only vectors matching the filter are considered in the search

### AC-1.4.7: Retriable Exception Handling
**Given** an active QdrantWrapper
**When** a transient error occurs during a Qdrant operation (connection timeout, server unavailable)
**Then** a custom RetriableQdrantError is raised that upstream circuit breakers can catch and retry

### AC-1.4.8: Non-Retriable Exception Handling
**Given** an active QdrantWrapper
**When** a non-transient error occurs (invalid collection name, malformed vector)
**Then** the original exception propagates without wrapping (non-retriable)

## Tasks/Subtasks

- [ ] Task 1: Create QdrantWrapper class
  - [ ] Subtask 1.1: Create shared/db/vector.py
  - [ ] Subtask 1.2: Define QdrantWrapper with __init__ accepting host, port (default 6333), grpc_port (default 6334), api_key (Optional[str]), prefer_grpc (default True)
  - [ ] Subtask 1.3: Instantiate qdrant_client.QdrantClient in __init__
- [ ] Task 2: Implement collection management
  - [ ] Subtask 2.1: Implement ensure_collection(name: str, vector_size: int) that checks if collection exists and creates it if not
  - [ ] Subtask 2.2: Configure HNSW index with m=16 and ef_construct=200 via HnswConfigDiff
  - [ ] Subtask 2.3: Set distance metric to Cosine via models.Distance.COSINE
  - [ ] Subtask 2.4: Implement ensure_all_collections() that creates all 4 ALUSKORT collections: incident_embeddings, technique_embeddings, playbook_embeddings, ti_report_embeddings
- [ ] Task 3: Implement upsert operations
  - [ ] Subtask 3.1: Implement upsert_vectors(collection: str, points: list[dict]) that converts dicts to qdrant_client.models.PointStruct and calls client.upsert()
  - [ ] Subtask 3.2: Support batch upsert with configurable batch_size (default 100)
  - [ ] Subtask 3.3: Accept points as list of dicts with keys: id (str|int), vector (list[float]), payload (dict)
- [ ] Task 4: Implement search operations
  - [ ] Subtask 4.1: Implement search(collection: str, query_vector: list[float], limit: int = 10, score_threshold: Optional[float] = None) -> list[dict]
  - [ ] Subtask 4.2: Implement filter support via search_filter parameter accepting a dict that maps to qdrant_client.models.Filter
  - [ ] Subtask 4.3: Convert search results (ScoredPoint) to dicts with keys: id, score, payload
  - [ ] Subtask 4.4: Implement search_by_id(collection: str, point_id: str|int) -> Optional[dict] for exact retrieval
- [ ] Task 5: Implement error handling for circuit breaker
  - [ ] Subtask 5.1: Define RetriableQdrantError(Exception) in shared/db/vector.py
  - [ ] Subtask 5.2: Define NonRetriableQdrantError(Exception) in shared/db/vector.py
  - [ ] Subtask 5.3: Wrap transient errors (ConnectionError, TimeoutError, grpc errors with UNAVAILABLE status) in RetriableQdrantError
  - [ ] Subtask 5.4: Let non-transient errors (ValueError, invalid collection) propagate as-is or wrap in NonRetriableQdrantError
  - [ ] Subtask 5.5: Add logging for all caught exceptions
- [ ] Task 6: Implement health check and cleanup
  - [ ] Subtask 6.1: Implement health_check() -> bool that calls client.get_collections() and returns True/False
  - [ ] Subtask 6.2: Implement delete_collection(name: str) for test cleanup
  - [ ] Subtask 6.3: Implement close() for graceful shutdown
- [ ] Task 7: Write unit tests
  - [ ] Subtask 7.1: Create tests/test_db/test_vector.py
  - [ ] Subtask 7.2: Mock qdrant_client.QdrantClient and test ensure_collection creates collection with correct HNSW params
  - [ ] Subtask 7.3: Test ensure_collection is idempotent (does not error if collection exists)
  - [ ] Subtask 7.4: Test upsert_vectors converts dicts to PointStruct correctly
  - [ ] Subtask 7.5: Test search returns list of dicts with id, score, payload keys
  - [ ] Subtask 7.6: Test search with filter passes correct Filter object to client
  - [ ] Subtask 7.7: Test transient connection error raises RetriableQdrantError
  - [ ] Subtask 7.8: Test non-transient error raises NonRetriableQdrantError or propagates
  - [ ] Subtask 7.9: Test health_check returns True on success, False on exception

## Dev Notes

### Architecture Requirements
- Use qdrant-client >= 1.8.0
- HNSW index configuration: m=16, ef_construct=200 (tuned for security embedding workloads)
- Distance metric: Cosine (models.Distance.COSINE)
- 4 collections used by ALUSKORT:
  - incident_embeddings: past incident vectors for similar-incident retrieval (used by orchestrator Context Enricher)
  - technique_embeddings: ATT&CK/ATLAS technique description vectors (used by ATLAS Mapper)
  - playbook_embeddings: playbook description vectors (used by orchestrator for playbook selection)
  - ti_report_embeddings: threat intelligence report vectors (used by Context Enricher)
- Prefer gRPC transport for performance (prefer_grpc=True)
- Error classification is critical for circuit breaker integration: the orchestrator wraps DB calls in a circuit breaker that retries on RetriableQdrantError but fails fast on NonRetriableQdrantError
- See docs/ai-system-design.md Section 5.1: Vector DB stores embeddings for semantic retrieval
- See docs/ai-system-design.md Section 11.1: "Vector DB down -> Fall back to Postgres full-text search"

### Technical Specifications
- Class: QdrantWrapper in shared/db/vector.py
- Constructor params: host (str, default "localhost"), port (int, default 6333), grpc_port (int, default 6334), api_key (Optional[str], default None), prefer_grpc (bool, default True)
- Collection config: VectorParams(size=vector_size, distance=Distance.COSINE), HnswConfigDiff(m=16, ef_construct=200)
- Upsert batch_size: 100 (configurable)
- Search results format: list[dict] where each dict has keys: id (str|int), score (float), payload (dict)
- Filter format: dict with keys matching Qdrant filter syntax, converted internally to models.Filter
- Embedding dimensions vary by model: OpenAI text-embedding-3-large = 3072, bge-large-en-v1.5 = 1024; collections must be created with the correct vector_size
- Exception classes: RetriableQdrantError, NonRetriableQdrantError (both in shared/db/vector.py)
- Logging: use standard Python logging (logging.getLogger(__name__))

### Testing Strategy
- pytest (synchronous tests, qdrant-client is sync by default)
- Mock qdrant_client.QdrantClient (do not require a live Qdrant instance)
- Use unittest.mock.MagicMock for sync method mocks
- Test HNSW config values explicitly (m=16, ef_construct=200, Cosine distance)
- Test error classification (retriable vs non-retriable)
- Test point conversion (dict -> PointStruct)
- Test search result conversion (ScoredPoint -> dict)
- All tests must pass before story is marked done

## Dev Agent Record

### Implementation Plan
<!-- Dev agent fills this during implementation -->

### Debug Log
<!-- Dev agent logs issues here -->

### Completion Notes
<!-- Dev agent summarizes what was done -->

## File List
<!-- Dev agent tracks files here -->

## Change Log
<!-- Dev agent tracks changes here -->

## Status

ready-for-dev
