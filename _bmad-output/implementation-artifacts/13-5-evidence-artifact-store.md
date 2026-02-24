# Story 13.5: Evidence Artifact Store

Status: review

## Story

As a platform preserving full audit artifacts,
I want an `EvidenceStore` class that stores large audit payloads (LLM prompts, responses, retrieval context) in S3/MinIO with SHA-256 content hashing and server-side encryption,
so that audit records reference full-size evidence without bloating the database.

## Acceptance Criteria

1. **Given** evidence content, **When** `store_evidence()` is called, **Then** content is stored at path `{tenant}/{YYYY/MM/DD}/{audit_id}/{evidence_type}.json` with SSE-KMS encryption.
2. **Given** stored evidence, **When** retrieved by URI, **Then** content matches the original `content_hash`.
3. **Given** the evidence store, **When** used by the Context Gateway, **Then** full LLM prompts and responses are stored as evidence with hashes in the audit record.
4. **Given** a storage failure, **When** `store_evidence()` fails, **Then** the failure is logged but does NOT block the audit pipeline (fail-open).

## Tasks / Subtasks

- [x] Task 1: Create EvidenceStore class (AC: 1, 2)
  - [x] 1.1: Create `services/audit_service/evidence.py` with `EvidenceStore` class:
    ```python
    class EvidenceStore:
        def __init__(self, s3_client, bucket: str = "aluskort-audit-evidence"):
            self.s3 = s3_client
            self.bucket = bucket

        async def store_evidence(self, tenant_id: str, audit_id: str,
                                 evidence_type: str, content: str | bytes) -> tuple[str, str]:
            # evidence_type: "llm_prompt", "llm_response", "retrieval_context", "raw_alert"
            # Path: {tenant}/{YYYY/MM/DD}/{audit_id}/{evidence_type}.json
            # Computes SHA-256 content_hash
            # Uploads with SSE-KMS encryption (ServerSideEncryption='aws:kms')
            # Returns: (content_hash, s3_uri)

        async def retrieve_evidence(self, s3_uri: str) -> bytes:
            # Downloads object from S3 URI
            # Returns raw content

        async def verify_evidence(self, s3_uri: str, expected_hash: str) -> bool:
            # Retrieves content, computes hash, compares
            # Returns True if match
    ```
  - [x] 1.2: Evidence types supported: `llm_prompt`, `llm_response`, `retrieval_context`, `raw_alert`, `investigation_state`.
  - [x] 1.3: S3 path format: `{tenant_id}/{YYYY}/{MM}/{DD}/{audit_id}/{evidence_type}.json` — organized by date for lifecycle management.
  - [x] 1.4: Add unit tests in `tests/test_audit/test_evidence.py` — `TestEvidenceStore` class: store returns hash and URI, path format correct, SSE-KMS header set, retrieve returns original content, verify matches hash, verify fails on tampered content. (~8 tests with mocked S3 client)
- [x] Task 2: Add fail-open error handling (AC: 4)
  - [x] 2.1: Wrap all S3 operations in try/except. On `ClientError` or connection error, log warning and return `("", "")` tuple.
  - [x] 2.2: Add unit tests — `TestEvidenceStoreFailOpen` class: S3 error returns empty tuple, no exception raised. (~2 tests)
- [x] Task 3: Add batch evidence storage (AC: 3)
  - [x] 3.1: Add `store_evidence_batch(items: list[dict]) -> list[tuple[str, str]]` method that stores multiple evidence items for the same audit event.
  - [x] 3.2: Add `build_evidence_refs(content_hashes: list[tuple[str, str]]) -> list[str]` helper that formats S3 URIs as `evidence_refs` for AuditContext.
  - [x] 3.3: Add unit tests — `TestBatchEvidence` class: batch stores all items, builds evidence_refs list. (~3 tests)
- [x] Task 4: Run full regression (AC: 1-4)
  - [x] 4.1: Run full project test suite (`pytest tests/`) — all 1169+ tests pass (zero regressions)

## Dev Notes

### Critical Architecture Constraints

- **Evidence is stored in S3/MinIO, NOT in Postgres** — audit records contain `evidence_refs` (S3 URIs) and `content_hash` values, not the full payloads.
- **SSE-KMS encryption is mandatory** — all evidence objects must be encrypted at rest using server-side encryption.
- **Fail-open semantics** — evidence storage failure must NOT block the audit pipeline. The audit record is still written to Postgres; evidence_refs will be empty.
- **Content hashing with SHA-256** — every stored artifact gets a hash that can be verified later (chain of custody).
- **DO NOT modify the audit service main loop** (Story 13.4). The evidence store is called from the service but is a separate module.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `AuditContext.evidence_refs` | `shared/schemas/audit.py` (Story 13.1) | List of S3 URIs. **Populate with evidence store results.** |
| `AuditService` | `services/audit_service/service.py` (Story 13.4) | Main service. **Calls evidence store.** |
| MinIO config | `docker-compose.yml` | MinIO service at port 9000. **Use for local dev.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Evidence store (NEW) | `services/audit_service/evidence.py` |
| Evidence tests (NEW) | `tests/test_audit/test_evidence.py` |
| Audit service | `services/audit_service/service.py` |
| Docker compose | `docker-compose.yml` |

### S3 Path Structure

```
aluskort-audit-evidence/
    └── {tenant_id}/
        └── {YYYY}/
            └── {MM}/
                └── {DD}/
                    └── {audit_id}/
                        ├── llm_prompt.json
                        ├── llm_response.json
                        ├── retrieval_context.json
                        └── raw_alert.json
```

### Evidence Types

| Type | Content | Typical Size |
|---|---|---|
| `llm_prompt` | Full system + user prompt sent to LLM | 2-16 KB |
| `llm_response` | Full LLM response text | 1-8 KB |
| `retrieval_context` | Retrieved documents used in prompt | 4-32 KB |
| `raw_alert` | Original SIEM alert payload | 1-4 KB |
| `investigation_state` | Full GraphState snapshot | 2-8 KB |

### Existing Test Classes That MUST Still Pass (Unchanged)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**, **pytest-asyncio**
- Mock `boto3` S3 client (or `moto` library for S3 mocking)
- Verify `put_object` call args: Bucket, Key (path format), Body, ServerSideEncryption
- Verify content hash is SHA-256 of content
- Test verify_evidence with matching and mismatching hashes

### Dependencies on Other Stories

- **Story 13.4** (Audit Service Core): the service that calls this evidence store
- **Story 13.1** (Audit Models): AuditContext.evidence_refs field

### References

- [Source: docs/audit-architecture.md Section 5.5] — Evidence store specification
- [Source: docs/audit-architecture.md Section 6] — Retention tiers (cold = S3)
- [Source: docs/prd.md#NFR-CMP-001] — Audit trail completeness

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

All 13 tests passed on first run. Full regression: 1576 passed.

### Completion Notes List

EvidenceStore: store_evidence (SHA-256 + SSE-KMS), retrieve_evidence, verify_evidence, store_evidence_batch, build_evidence_refs. Fail-open on S3 errors.

### File List

**Created:**
- `services/audit_service/evidence.py` — EvidenceStore class
- `tests/test_audit/test_evidence.py` — Evidence store tests (13 tests)

**Modified:**
- None (all existing files unchanged)

### Change Log

- 2026-02-21: Story implemented — 13 new tests, 1576 total regression clean
