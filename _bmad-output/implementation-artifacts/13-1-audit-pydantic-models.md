# Story 13.1: Audit Pydantic Models and Event Taxonomy

Status: review

## Story

As a developer building the audit trail,
I want Pydantic v2 models for AuditRecord, AuditContext, AuditDecision, AuditOutcome, and a controlled vocabulary EventTaxonomy enum,
so that all audit events have a consistent, validated schema.

## Acceptance Criteria

1. **Given** an AuditRecord, **When** created, **Then** all required fields (audit_id, tenant_id, sequence_number, previous_hash, timestamp, event_type, event_category, severity, actor_type, actor_id) are present and typed.
2. **Given** an `event_type` value, **When** validated, **Then** it must be a member of the EventTaxonomy controlled vocabulary (~40 event types across 5 categories).
3. **Given** AuditContext, **When** populated for an LLM decision, **Then** all LLM context fields (provider, model_id, tier, prompt hash, token counts, cost) are captured.
4. **Given** AuditDecision, **When** populated, **Then** it captures decision_type, classification, confidence, reasoning_summary, and constraints_applied.
5. **Given** AuditOutcome, **When** populated, **Then** it captures outcome_status, action_taken, approval details, and analyst feedback.

## Tasks / Subtasks

- [x] Task 1: Create EventTaxonomy enum and event categories (AC: 2)
  - [x] 1.1: Create `shared/schemas/event_taxonomy.py` with `EventCategory(str, Enum)` — 5 categories
  - [x] 1.2: Add `EventTaxonomy(str, Enum)` with 45 event types (12 decision, 11 action, 8 approval, 6 security, 8 system)
  - [x] 1.3: Add `EVENT_CATEGORY_MAP` mapping all 45 event types to their categories
  - [x] 1.4: Add unit tests — `TestEventTaxonomy` class (11 tests): values valid, minimum 40, no duplicates, str-based, category map complete, per-category counts
- [x] Task 2: Create AuditContext model (AC: 3)
  - [x] 2.1: Add `AuditContext` Pydantic v2 BaseModel with LLM, retrieval, taxonomy, risk, and environment fields
  - [x] 2.2: Add unit tests — `TestAuditContext` class (4 tests): defaults, LLM fields, evidence_refs, retrieval fields
- [x] Task 3: Create AuditDecision and AuditOutcome models (AC: 4, 5)
  - [x] 3.1: Add `AuditDecision` Pydantic v2 BaseModel with decision_type, classification, confidence, reasoning, constraints
  - [x] 3.2: Add `AuditOutcome` Pydantic v2 BaseModel with outcome_status, action, approval, and analyst feedback fields
  - [x] 3.3: Add unit tests — `TestAuditDecision` (3 tests), `TestAuditOutcome` (3 tests)
- [x] Task 4: Create AuditRecord model (AC: 1)
  - [x] 4.1: Add `AuditRecord` Pydantic v2 BaseModel with identity, time, event, actor, references, nested models, integrity
  - [x] 4.2: Add `@field_validator("event_type")` validating against EventTaxonomy
  - [x] 4.3: Add `@field_validator("severity")` validating against {"info", "warning", "critical"}
  - [x] 4.4: Add unit tests — `TestAuditRecord` class (10 tests): required fields, validators, nested models, round-trip
- [x] Task 5: Run full regression (AC: 1-5)
  - [x] 5.1: Full project test suite: 1491 tests pass (zero regressions)
  - [x] 5.2: Existing schema models in `shared/schemas/` unchanged

## Dev Notes

### Critical Architecture Constraints

- **This is the foundation of Epic 13.** All other audit stories depend on these models. Get the schema right first.
- **Use Pydantic v2 BaseModel** — consistent with all other schemas in `shared/schemas/` (alert.py, entity.py, investigation.py, risk.py, routing.py, scoring.py).
- **EventTaxonomy is the controlled vocabulary** — every audit event type MUST come from this enum. No freeform strings.
- **DO NOT create database tables** — that's Story 13.3. This story defines only the Python models.
- **DO NOT create the AuditProducer** — that's Story 13.2. This story defines only the data models.
- **Nested models (AuditContext, AuditDecision, AuditOutcome) default to empty** — callers populate only the fields relevant to their event type.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `CanonicalAlert` | `shared/schemas/alert.py` | Pydantic v2 model pattern. **Follow same style.** |
| `GraphState` | `shared/schemas/investigation.py` | Investigation model. **Reference for investigation_id.** |
| `DecisionEntry` | `shared/schemas/investigation.py` | Decision chain entry. **Audit complements this.** |
| `IncidentScore` | `shared/schemas/scoring.py` | Pydantic model pattern. **Follow same style.** |
| `ModelTier` | `shared/schemas/routing.py` | Enum pattern. **Follow for EventTaxonomy.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Event taxonomy (NEW) | `shared/schemas/event_taxonomy.py` |
| Audit models (NEW) | `shared/schemas/audit.py` |
| Taxonomy tests (NEW) | `tests/test_schemas/test_event_taxonomy.py` |
| Audit model tests (NEW) | `tests/test_schemas/test_audit.py` |
| Existing alert schema | `shared/schemas/alert.py` |
| Existing investigation schema | `shared/schemas/investigation.py` |

### Event Taxonomy Structure

```
EventTaxonomy (~40 types)
    │
    ├── DECISION (12 types) — agent autonomous decisions
    ├── ACTION (11 types)   — executed actions
    ├── APPROVAL (8 types)  — human approval workflow
    ├── SECURITY (6 types)  — security events
    └── SYSTEM (8 types)    — system lifecycle events
```

### AuditRecord Schema Overview

```
AuditRecord
    ├── Identity: audit_id, tenant_id, sequence_number, previous_hash
    ├── Time: timestamp, ingested_at
    ├── Event: event_type (EventTaxonomy), event_category, severity
    ├── Actor: actor_type, actor_id, actor_permissions
    ├── References: investigation_id, alert_id, entity_ids
    ├── Context: AuditContext (LLM, retrieval, taxonomy, risk, env)
    ├── Decision: AuditDecision (type, classification, confidence)
    ├── Outcome: AuditOutcome (status, action, approval, feedback)
    └── Integrity: record_hash, record_version
```

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_schemas/ (42 tests):**
- `test_alert.py` — 8 tests
- `test_entity.py` — 10 tests
- `test_investigation.py` — 10 tests
- `test_risk.py` — 6 tests
- `test_routing.py` — 4 tests
- `test_scoring.py` — 4 tests

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**
- Model tests: construct with valid/invalid data, assert field types and defaults
- Enum tests: verify all members exist, no duplicates, str-based
- Validator tests: invalid event_type and severity raise `ValidationError`
- No async, no mocking needed (pure Pydantic model validation)

### Dependencies on Other Stories

- **None.** This is the foundation story — can start immediately, parallel to Epic 12.

### References

- [Source: docs/audit-architecture.md Section 2] — AuditRecord schema specification
- [Source: docs/audit-architecture.md Section 3] — Event taxonomy (~40 types)
- [Source: docs/prd.md#NFR-CMP-001] — Immutable audit trail requirement
- [Source: docs/prd.md#FR-CSM-003] — Compliance audit trail requirement

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- All 31 new tests passed on first run — no fixes needed
- Full regression: 1491 tests passed (zero failures)

### Completion Notes List

- EventTaxonomy: 45 event types across 5 categories (12 decision, 11 action, 8 approval, 6 security, 8 system)
- EVENT_CATEGORY_MAP: complete mapping for all 45 types, tested for completeness
- AuditContext: 38 fields covering LLM, retrieval, taxonomy, risk, and environment context
- AuditDecision: 9 fields for decision_type, classification, confidence, reasoning, constraints
- AuditOutcome: 14 fields for outcome_status, action, approval workflow, and analyst feedback
- AuditRecord: top-level model with identity, time, event, actor, references, 3 nested models, integrity; field_validators for event_type and severity
- All models use Pydantic v2 BaseModel, consistent with existing shared/schemas/ patterns
- No production code modified — only new files created

### File List

**Created:**
- `shared/schemas/event_taxonomy.py` — EventCategory enum (5 categories), EventTaxonomy enum (45 event types), EVENT_CATEGORY_MAP
- `shared/schemas/audit.py` — AuditContext, AuditDecision, AuditOutcome, AuditRecord Pydantic v2 models
- `tests/test_schemas/test_event_taxonomy.py` — TestEventTaxonomy (11 tests)
- `tests/test_schemas/test_audit.py` — TestAuditContext (4), TestAuditDecision (3), TestAuditOutcome (3), TestAuditRecord (10) = 20 tests

**Modified:**
- None (all existing files unchanged)

### Change Log

- 2026-02-21: Story implemented — 31 new tests (11 taxonomy + 20 audit), all passing, 1491 total regression clean
