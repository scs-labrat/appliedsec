# Story 13.6: Evidence Package API

Status: review

## Story

As an auditor investigating a past decision,
I want a `GET /v1/audit/evidence-package/{investigation_id}` endpoint that produces a complete, self-contained evidence package,
so that any investigation can be fully explained from the audit trail alone within 60 seconds.

## Acceptance Criteria

1. **Given** an `investigation_id`, **When** the evidence package API is called, **Then** it returns all audit records, state transitions, LLM interactions, retrieval context, actions, and approvals for that investigation.
2. **Given** the evidence package, **When** generated, **Then** the hash chain is verified for all included records and `chain_verified` is set accordingly.
3. **Given** an investigation within the 12-month warm window, **When** the package is requested, **Then** it is generated within 60 seconds.
4. **Given** `include_raw_prompts=true`, **When** requested, **Then** full LLM prompts are fetched from S3 and included.

## Tasks / Subtasks

- [x] Task 1: Create EvidencePackage data model (AC: 1)
  - [x] 1.1: Add `EvidencePackage` Pydantic model to `shared/schemas/audit.py` (or `services/audit_service/models.py`):
    - `package_id: str`, `investigation_id: str`, `tenant_id: str`, `generated_at: str`, `generated_by: str = "aluskort-audit-service v1.0"`
    - `source_alert: dict = {}`, `raw_alert_payload: dict = {}`
    - `events: list[dict] = []` — all audit records for investigation, ordered by sequence
    - `state_transitions: list[dict] = []`, `retrieval_context: list[dict] = []`, `llm_interactions: list[dict] = []`
    - `final_classification: str = ""`, `final_confidence: float = 0.0`, `final_severity: str = ""`
    - `reasoning_chain: list[str] = []`, `techniques_mapped: list[str] = []`
    - `actions_recommended: list[str] = []`, `actions_executed: list[dict] = []`, `actions_pending: list[dict] = []`
    - `approvals: list[dict] = []`, `analyst_feedback: list[dict] = []`
    - `chain_verified: bool = False`, `chain_verification_errors: list[str] = []`
    - `package_hash: str = ""` — SHA-256 of entire package
  - [x] 1.2: Add unit tests — `TestEvidencePackage` class: model creates with defaults, package_hash computable. (~3 tests)
- [x] Task 2: Create evidence package builder (AC: 1, 2, 4)
  - [x] 2.1: Create `services/audit_service/package_builder.py` with `EvidencePackageBuilder` class:
    - `__init__(self, postgres_client, evidence_store: EvidenceStore)`
    - `async build_package(investigation_id: str, tenant_id: str, include_raw_prompts: bool = False) -> EvidencePackage`
    - Queries `audit_records` WHERE `investigation_id = ?` ORDER BY `sequence_number`
    - Categorizes events into state_transitions, llm_interactions, actions, approvals
    - If `include_raw_prompts`, fetches evidence from S3 via `evidence_store.retrieve_evidence()`
    - Runs `verify_chain()` on included records, sets `chain_verified`
    - Computes `package_hash`
  - [x] 2.2: Add unit tests — `TestEvidencePackageBuilder` class: builds from audit records, categorizes events correctly, verifies chain, includes raw prompts when requested. (~6 tests)
- [x] Task 3: Create FastAPI audit endpoints (AC: 1, 3, 4)
  - [x] 3.1: Create `services/audit_service/api.py` with FastAPI app (port 8040):
    - `GET /v1/audit/evidence-package/{investigation_id}` — query params: `include_raw_prompts=false`, `format=json`
    - `GET /v1/audit/events` — query params: `tenant_id`, `event_type`, `from`, `to`, `limit=100`
    - `GET /v1/audit/events/{audit_id}` — single event lookup
    - `GET /v1/audit/verify` — query params: `tenant_id`, `from`, `to` — runs chain verification
    - `GET /v1/audit/reports/compliance` — query params: `tenant_id`, `month=YYYY-MM`
    - `POST /v1/audit/export` — body: `{tenant_id, from, to, format: json|csv|parquet}`
  - [x] 3.2: Add `tenant_id` header or query param validation for all endpoints (multi-tenancy isolation).
  - [x] 3.3: Add unit tests in `tests/test_audit/test_api.py` — `TestAuditAPI` class: evidence package endpoint returns correct structure, events listing works, single event lookup, verify endpoint calls chain verification, tenant isolation enforced. (~8 tests with httpx TestClient)
- [x] Task 4: Run full regression (AC: 1-4)
  - [x] 4.1: Run full project test suite (`pytest tests/`) — all 1169+ tests pass (zero regressions)

## Dev Notes

### Critical Architecture Constraints

- **Evidence packages are the primary audit artifact** — when an auditor or compliance officer needs to understand a decision, they request an evidence package.
- **60-second SLO** — packages for investigations within the 12-month warm window must generate in under 60 seconds.
- **Chain verification is included** — the package builder runs `verify_chain()` on all included records to prove integrity.
- **S3 fetches are optional** — `include_raw_prompts=false` (default) skips S3 calls for faster generation. Full prompts are only needed for deep investigation.
- **All endpoints require tenant_id** — multi-tenancy isolation is enforced at the API layer.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `verify_chain()` | `services/audit_service/chain.py` (Story 13.4) | Chain verification. **Call in package builder.** |
| `EvidenceStore` | `services/audit_service/evidence.py` (Story 13.5) | S3 evidence. **Retrieve raw prompts.** |
| `AuditRecord` | `shared/schemas/audit.py` (Story 13.1) | Record model. **Deserialize from Postgres.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Package builder (NEW) | `services/audit_service/package_builder.py` |
| API endpoints (NEW) | `services/audit_service/api.py` |
| API tests (NEW) | `tests/test_audit/test_api.py` |
| Package builder tests (NEW) | `tests/test_audit/test_package_builder.py` |
| Chain logic | `services/audit_service/chain.py` |
| Evidence store | `services/audit_service/evidence.py` |

### API Endpoints Summary

| Method | Path | Description |
|---|---|---|
| GET | `/v1/audit/evidence-package/{investigation_id}` | Full evidence package |
| GET | `/v1/audit/events` | List/filter audit events |
| GET | `/v1/audit/events/{audit_id}` | Single event detail |
| GET | `/v1/audit/verify` | Run chain verification |
| GET | `/v1/audit/reports/compliance` | Monthly compliance report |
| POST | `/v1/audit/export` | Bulk export (JSON/CSV/Parquet) |

### Existing Test Classes That MUST Still Pass (Unchanged)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**, **pytest-asyncio**, **httpx** (TestClient)
- Mock Postgres for record queries
- Mock EvidenceStore for S3 retrieval
- Verify response JSON structure matches EvidencePackage model
- Performance: verify package builds within timeout for 100-event investigation

### Dependencies on Other Stories

- **Story 13.4** (Audit Service Core): chain.py verify_chain()
- **Story 13.5** (Evidence Store): S3 retrieval for raw prompts

### References

- [Source: docs/audit-architecture.md Section 8.3] — API endpoint specification
- [Source: docs/audit-architecture.md Section 7] — Evidence package schema
- [Source: docs/prd.md#FR-CSM-003] — Compliance audit trail requirement

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

All 17 tests passed on first run. Full regression: 1576 passed.

### Completion Notes List

EvidencePackage model, EvidencePackageBuilder (categorizes events, verifies chain, computes package hash), FastAPI endpoints (evidence-package, events listing, single event, verify, compliance reports, export).

### File List

**Created:**
- `services/audit_service/models.py` — EvidencePackage model
- `services/audit_service/package_builder.py` — EvidencePackageBuilder
- `services/audit_service/api.py` — FastAPI audit endpoints
- `tests/test_audit/test_package_builder.py` — Package builder tests (9 tests)
- `tests/test_audit/test_api.py` — API endpoint tests (8 tests)

**Modified:**
- None

### Change Log

- 2026-02-21: Story implemented — 17 new tests, 1576 total regression clean
