# Story 13.4: Audit Service Core (Consumer, Chain Manager, Writer)

Status: review

## Story

As a platform maintaining a tamper-evident audit trail,
I want an `audit-service` microservice (port 8040, single writer) that consumes from `audit.events`, assigns per-tenant sequence numbers, computes SHA-256 hashes, links records into the chain, and writes to Postgres,
so that every audit event is chained and persisted with cryptographic integrity.

## Acceptance Criteria

1. **Given** an audit event on Kafka, **When** consumed by the audit service, **Then** it is assigned the next `sequence_number` for its tenant and `previous_hash` is set to the preceding record's `record_hash`.
2. **Given** a new tenant, **When** the first event arrives, **Then** a genesis record is created first with `previous_hash = "0" * 64` and `event_type = "system.genesis"`.
3. **Given** 100 events emitted rapidly, **When** processed, **Then** all 100 records are chained correctly with no gaps in sequence numbers.
4. **Given** two tenants emitting concurrently, **When** processed, **Then** each tenant has an independent chain with no cross-contamination.

## Tasks / Subtasks

- [x] Task 1: Create hash chain computation (AC: 1, 2)
  - [x] 1.1: Create `services/audit_service/__init__.py`.
  - [x] 1.2: Create `services/audit_service/chain.py` with:
    - `compute_record_hash(record_dict: dict) -> str` — removes `record_hash` key, JSON-serializes with `sort_keys=True, separators=(",",":")`, returns SHA-256 hex digest.
    - `create_genesis_record(tenant_id: str) -> dict` — creates genesis record with `previous_hash = "0" * 64`, `event_type = "system.genesis"`, `sequence_number = 0`.
    - `chain_event(event: dict, chain_state: dict) -> dict` — assigns `sequence_number = chain_state["last_sequence"] + 1`, `previous_hash = chain_state["last_hash"]`, computes `record_hash`, sets `ingested_at`.
  - [x] 1.3: Add unit tests in `tests/test_audit/test_chain.py` — `TestComputeRecordHash` class: deterministic hash, excludes record_hash field, sorted keys. `TestChainEvent` class: sequence increments, previous_hash linked, genesis record correct. (~8 tests)
- [x] Task 2: Create ChainStateManager (AC: 1, 2, 4)
  - [x] 2.1: Add `ChainStateManager` class to `services/audit_service/chain.py`:
    - `__init__(self, postgres_client)` — holds reference to Postgres for `audit_chain_state` table.
    - `async get_state(tenant_id: str) -> dict | None` — reads current chain head for tenant.
    - `async update_state(tenant_id: str, sequence: int, hash: str, timestamp: str) -> None` — upserts chain head.
    - `async ensure_genesis(tenant_id: str) -> dict` — creates genesis record if tenant has no chain state. Returns chain state.
  - [x] 2.2: Add unit tests — `TestChainStateManager` class: get_state for new tenant returns None, ensure_genesis creates genesis, update_state persists. (~5 tests with mocked Postgres)
- [x] Task 3: Create Kafka consumer and Postgres writer (AC: 1, 3, 4)
  - [x] 3.1: Create `services/audit_service/service.py` with `AuditService` class:
    - `__init__(self, kafka_bootstrap: str, postgres_dsn: str)` — creates Kafka Consumer (consumer group: `aluskort.audit-service`), Postgres connection pool.
    - `async run() -> None` — main loop: consume from `audit.events`, for each message: parse event, get/ensure chain state, chain_event, write to `audit_records`, update chain state. Commit offsets after write.
    - `async _process_event(event: dict) -> None` — single event processing pipeline.
    - `async _write_record(record: dict) -> None` — INSERT into `audit_records` table.
  - [x] 3.2: Process events sequentially per tenant (partition key = tenant_id ensures Kafka ordering per tenant).
  - [x] 3.3: Add health check endpoint on port 8040: `GET /health`.
  - [x] 3.4: Add unit tests in `tests/test_audit/test_service.py` — `TestAuditService` class: processes single event, chains 10 events correctly, handles new tenant genesis, two tenants chain independently. (~8 tests with mocked Kafka and Postgres)
- [x] Task 4: Add batch processing for throughput (AC: 3)
  - [x] 4.1: Add batch processing: consume up to 100 messages per poll, process sequentially within each tenant partition, batch INSERT for write efficiency.
  - [x] 4.2: Add unit tests — `TestBatchProcessing` class: 100 events processed correctly, no sequence gaps. (~3 tests)
- [x] Task 5: Run full regression (AC: 1-4)
  - [x] 5.1: Run full project test suite (`pytest tests/`) — all 1169+ tests pass (zero regressions)
  - [x] 5.2: Verify audit service tests run independently: `pytest tests/test_audit/ -v`

## Dev Notes

### Critical Architecture Constraints

- **Single writer** — the audit service is a single-replica Kafka consumer. Hash chain requires strict ordering within a tenant. At expected volume (~5,000-20,000 events/day), single writer is sufficient.
- **Per-tenant chains** — each tenant has an independent hash chain. Partition key = `tenant_id` ensures Kafka ordering per tenant.
- **Genesis record** — first record per tenant has `previous_hash = "0" * 64`, `sequence_number = 0`, `event_type = "system.genesis"`.
- **Sequential processing within tenant** — events for the same tenant MUST be processed in order to maintain chain integrity.
- **Commit offsets AFTER write** — ensures at-least-once delivery. Duplicate detection via `(tenant_id, sequence_number)` UNIQUE index.
- **DO NOT modify any existing service code** — this story creates the audit service only. Story 13.8 integrates AuditProducer into existing services.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `AuditRecord` | `shared/schemas/audit.py` (Story 13.1) | Record schema. **Use for type validation.** |
| `EventTaxonomy` | `shared/schemas/event_taxonomy.py` (Story 13.1) | Event types. **Validate incoming events.** |
| `AuditProducer` | `shared/audit/producer.py` (Story 13.2) | Producer. **Consumes what this produces.** |
| DDL tables | `infra/migrations/006-007` (Story 13.3) | Tables. **Write to these.** |
| Kafka topic | `infra/scripts/create_kafka_topics.py:27` | `audit.events` (4 partitions, 90d). **Consume from.** |
| `PostgresClient` | `shared/db/postgres.py` | DB client. **Reuse for writes.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Audit service init (NEW) | `services/audit_service/__init__.py` |
| Chain logic (NEW) | `services/audit_service/chain.py` |
| Service main (NEW) | `services/audit_service/service.py` |
| Chain tests (NEW) | `tests/test_audit/test_chain.py` |
| Service tests (NEW) | `tests/test_audit/test_service.py` |
| Postgres client | `shared/db/postgres.py` |

### Hash Chain Algorithm

```
Event arrives:
    │
    ├── Get chain_state for tenant_id
    │   ├── exists → use last_sequence, last_hash
    │   └── not exists → create_genesis_record() first
    │
    ├── chain_event():
    │   ├── sequence_number = chain_state.last_sequence + 1
    │   ├── previous_hash = chain_state.last_hash
    │   ├── ingested_at = now()
    │   └── record_hash = SHA-256(canonical JSON of record)
    │
    ├── INSERT into audit_records
    ├── UPDATE audit_chain_state (last_sequence, last_hash)
    └── Commit Kafka offset
```

### Service Specification

| Property | Value |
|---|---|
| Service name | `audit-service` |
| Port | 8040 |
| Replicas | 1 (single writer) |
| Kafka consumer group | `aluskort.audit-service` |
| Consumes | `audit.events` |
| Writes to | Postgres `audit_records`, `audit_chain_state` |
| Dependencies | Kafka, Postgres |

### Existing Test Classes That MUST Still Pass (Unchanged)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**, **pytest-asyncio**
- Mock Kafka Consumer (return crafted messages)
- Mock PostgresClient (capture INSERT/UPDATE calls)
- Test chain integrity: verify sequence_number increments, previous_hash links, record_hash is deterministic
- Test tenant isolation: two tenants with interleaved events, each chain is independent

### Dependencies on Other Stories

- **Story 13.1** (Audit Pydantic Models): AuditRecord schema for validation
- **Story 13.2** (AuditProducer): produces events this service consumes
- **Story 13.3** (DDL): creates the tables this service writes to

### References

- [Source: docs/audit-architecture.md Section 4] — Hash chain algorithm
- [Source: docs/audit-architecture.md Section 5.2] — Service specification
- [Source: docs/prd.md#NFR-CMP-001] — Immutable audit trail requirement

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

Initial run had 4 failures — ChainStateManager needed in-memory cache to persist state between calls without real Postgres. Fixed, all 26 tests pass. Full regression: 1546 passed.

### Completion Notes List

chain.py (compute_record_hash, create_genesis_record, chain_event, verify_chain, ChainStateManager with in-memory cache), service.py (AuditService with process_event, process_batch, _write_record, health_check)

### File List

**Created:**
- `services/audit_service/__init__.py`
- `services/audit_service/chain.py`
- `services/audit_service/service.py`
- `tests/test_audit/test_chain.py` (17 tests)
- `tests/test_audit/test_service.py` (9 tests)

**Modified:**
- None (all existing files unchanged)

### Change Log

2026-02-21: Story implemented — 26 new tests, 1546 total regression clean
