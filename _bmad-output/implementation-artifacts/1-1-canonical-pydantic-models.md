---
story_id: "1.1"
story_key: "1-1-canonical-pydantic-models"
title: "Create Canonical Pydantic Models"
epic: "Epic 1: Foundation"
status: "done"
priority: "high"
---

# Story 1.1: Create Canonical Pydantic Models

## Story

As a developer building ALUSKORT services,
I want shared Pydantic v2 models for CanonicalAlert, GraphState, InvestigationState, IncidentScore, RiskSignal, RiskState, EntityType, NormalizedEntity, and AlertEntities,
so that all services use the same data contracts for inter-service communication.

## Acceptance Criteria

### AC-1.1.1: CanonicalAlert Validation
**Given** a raw alert dict from any source
**When** it is validated against CanonicalAlert
**Then** all required fields (alert_id, source, timestamp, title, description, severity, tactics, techniques, entities_raw, product, tenant_id, raw_payload) are present and typed correctly

### AC-1.1.2: CanonicalAlert Rejection on Missing Fields
**Given** a raw alert dict missing one or more required fields
**When** it is validated against CanonicalAlert
**Then** a Pydantic ValidationError is raised with a descriptive message identifying the missing field(s)

### AC-1.1.3: Severity Enum Enforcement
**Given** a CanonicalAlert with a severity value not in ("critical", "high", "medium", "low", "informational")
**When** it is validated
**Then** a Pydantic ValidationError is raised indicating the invalid severity value

### AC-1.1.4: GraphState Defaults
**Given** a new GraphState created with only investigation_id
**When** inspected
**Then** state defaults to InvestigationState.RECEIVED, all list fields default to empty lists, confidence defaults to 0.0, requires_human_approval defaults to False, risk_state defaults to "unknown", llm_calls defaults to 0, total_cost_usd defaults to 0.0

### AC-1.1.5: InvestigationState Enum Coverage
**Given** the InvestigationState enum
**When** its members are inspected
**Then** it contains exactly: RECEIVED, PARSING, ENRICHING, REASONING, AWAITING_HUMAN, RESPONDING, CLOSED, FAILED

### AC-1.1.6: RiskSignal NO_BASELINE for Missing Data
**Given** an entity with no UEBA data (investigation_priority is None)
**When** classify_risk() is called
**Then** the returned RiskSignal has risk_state=RiskState.NO_BASELINE and risk_score=None

### AC-1.1.7: IncidentScore Decay Calculation
**Given** an incident with vector_similarity=1.0, age_days=30, same_tenant=True, technique_overlap=1.0
**When** score_incident() is called
**Then** recency_decay is approximately 0.5 (within 0.01 tolerance) and composite score reflects ALPHA*1.0 + BETA*~0.5 + GAMMA*1.0 + DELTA*1.0

### AC-1.1.8: Entity Model Validation
**Given** a NormalizedEntity with entity_type, primary_value, and properties
**When** it is validated
**Then** entity_type must be a valid EntityType enum member and confidence defaults to 1.0

## Tasks/Subtasks

- [x] Task 1: Create shared/schemas/ directory structure
  - [x] Subtask 1.1: Create shared/__init__.py
  - [x] Subtask 1.2: Create shared/schemas/__init__.py with all model exports
- [x] Task 2: Create CanonicalAlert model
  - [x] Subtask 2.1: Create shared/schemas/alert.py
  - [x] Subtask 2.2: Define SeverityLevel as Literal["critical", "high", "medium", "low", "informational"]
  - [x] Subtask 2.3: Implement CanonicalAlert with all 12 fields from ai-system-design.md Section 6.2
  - [x] Subtask 2.4: Add field validators for timestamp (ISO 8601) and severity
- [x] Task 3: Create GraphState and InvestigationState models
  - [x] Subtask 3.1: Create shared/schemas/investigation.py
  - [x] Subtask 3.2: Implement InvestigationState enum with 8 states
  - [x] Subtask 3.3: Implement AgentRole enum with 6 roles
  - [x] Subtask 3.4: Implement GraphState Pydantic model with all fields from ai-system-design.md Section 4.1
  - [x] Subtask 3.5: Set defaults: state=RECEIVED, empty lists, confidence=0.0, risk_state="unknown"
- [x] Task 4: Create RiskState and RiskSignal models
  - [x] Subtask 4.1: Create shared/schemas/risk.py
  - [x] Subtask 4.2: Implement RiskState enum: NO_BASELINE, UNKNOWN, LOW, MEDIUM, HIGH
  - [x] Subtask 4.3: Implement RiskSignal model with entity_id, signal_type, risk_state, risk_score (Optional[float]), data_freshness_hours, source
  - [x] Subtask 4.4: Implement classify_risk() function matching ai-system-design.md Section 9.1 logic
- [x] Task 5: Create IncidentScore and score_incident models
  - [x] Subtask 5.1: Create shared/schemas/scoring.py
  - [x] Subtask 5.2: Implement IncidentScore model with vector_similarity, recency_decay, tenant_match, technique_overlap, composite
  - [x] Subtask 5.3: Define constants: ALPHA=0.4, BETA=0.3, GAMMA=0.15, DELTA=0.15, LAMBDA=0.023
  - [x] Subtask 5.4: Implement score_incident() function with exponential decay formula
- [x] Task 6: Create entity models
  - [x] Subtask 6.1: Create shared/schemas/entity.py
  - [x] Subtask 6.2: Implement EntityType enum with all 15 types (ACCOUNT, HOST, IP, FILE, PROCESS, URL, DNS, FILEHASH, MAILBOX, MAILMESSAGE, REGISTRY_KEY, REGISTRY_VALUE, SECURITY_GROUP, CLOUD_APPLICATION, MALWARE)
  - [x] Subtask 6.3: Implement NormalizedEntity model with entity_type, primary_value, properties, confidence, source_id
  - [x] Subtask 6.4: Implement AlertEntities model with typed lists for each entity category plus raw_iocs and parse_errors
- [x] Task 7: Create __init__.py exports
  - [x] Subtask 7.1: Export all models from shared/schemas/__init__.py
  - [x] Subtask 7.2: Export convenience imports from shared/__init__.py
- [x] Task 8: Write unit tests
  - [x] Subtask 8.1: Create tests/test_schemas/ directory structure
  - [x] Subtask 8.2: Test CanonicalAlert validation (valid dict creates model, missing field raises ValidationError)
  - [x] Subtask 8.3: Test CanonicalAlert rejects invalid severity values
  - [x] Subtask 8.4: Test GraphState defaults to RECEIVED with empty lists and zero counters
  - [x] Subtask 8.5: Test InvestigationState enum has all 8 members
  - [x] Subtask 8.6: Test RiskSignal: classify_risk(None, ...) returns NO_BASELINE
  - [x] Subtask 8.7: Test RiskSignal: classify_risk with stale data returns UNKNOWN
  - [x] Subtask 8.8: Test IncidentScore: decay at 30 days produces recency_decay approx 0.5
  - [x] Subtask 8.9: Test IncidentScore: same_tenant=True boosts composite score vs same_tenant=False
  - [x] Subtask 8.10: Test EntityType enum has all 15 members
  - [x] Subtask 8.11: Test NormalizedEntity defaults confidence to 1.0
  - [x] Subtask 8.12: Test AlertEntities defaults all lists to empty

## Dev Notes

### Architecture Requirements
- Use Pydantic v2 (BaseModel) for all schemas — version >=2.6.0
- All models in shared/schemas/ directory
- Export all models from shared/schemas/__init__.py
- Use Python 3.12+ type hints (list[str] not List[str], dict not Dict, Optional from typing)
- Severity enum: Literal["critical", "high", "medium", "low", "informational"]
- RiskState enum values: NO_BASELINE = "no_baseline", UNKNOWN = "unknown", LOW = "low", MEDIUM = "medium", HIGH = "high"
- InvestigationState enum values: RECEIVED = "received", PARSING = "parsing", ENRICHING = "enriching", REASONING = "reasoning", AWAITING_HUMAN = "awaiting_human", RESPONDING = "responding", CLOSED = "closed", FAILED = "failed"
- AgentRole enum values: IOC_EXTRACTOR, CONTEXT_ENRICHER, REASONING_AGENT, RESPONSE_AGENT, CTEM_CORRELATOR, ATLAS_MAPPER
- IncidentScore weights: ALPHA=0.4, BETA=0.3, GAMMA=0.15, DELTA=0.15, LAMBDA=0.023
- See docs/ai-system-design.md Sections 4, 5, 9 for complete field definitions
- See docs/architecture.md Section 3.2.3 for EntityType and NormalizedEntity definitions

### Technical Specifications
- CanonicalAlert fields: alert_id (str), source (str), timestamp (str ISO8601), title (str), description (str), severity (Literal), tactics (list[str]), techniques (list[str]), entities_raw (str), product (str), tenant_id (str), raw_payload (dict)
- GraphState fields: investigation_id (str), state (InvestigationState), alert_id (str), tenant_id (str), entities (dict), ioc_matches (list), ueba_context (list), ctem_exposures (list), atlas_techniques (list), similar_incidents (list), playbook_matches (list), decision_chain (list), classification (str), confidence (float), severity (str), recommended_actions (list), requires_human_approval (bool), risk_state (str), llm_calls (int), total_cost_usd (float), queries_executed (int)
- RiskSignal fields: entity_id (str), signal_type (str), risk_state (RiskState), risk_score (Optional[float] 0.0-10.0), data_freshness_hours (float), source (str)
- IncidentScore fields: vector_similarity (float 0.0-1.0), recency_decay (float 0.0-1.0), tenant_match (float 0.0 or 1.0), technique_overlap (float 0.0-1.0), composite (float)
- score_incident formula: composite = ALPHA * vector_similarity + BETA * exp(-LAMBDA * age_days) + GAMMA * (1.0 if same_tenant else 0.0) + DELTA * technique_overlap
- classify_risk thresholds: priority None -> NO_BASELINE, stale > max_stale_hours -> UNKNOWN, priority < 3 -> LOW, < 6 -> MEDIUM, >= 6 -> HIGH
- EntityType: 15 members covering ACCOUNT, HOST, IP, FILE, PROCESS, URL, DNS, FILEHASH, MAILBOX, MAILMESSAGE, REGISTRY_KEY, REGISTRY_VALUE, SECURITY_GROUP, CLOUD_APPLICATION, MALWARE
- NormalizedEntity fields: entity_type (EntityType), primary_value (str), properties (dict), confidence (float default 1.0), source_id (Optional[str])
- AlertEntities fields: accounts, hosts, ips, files, processes, urls, dns_records, file_hashes, mailboxes, other (all list[NormalizedEntity]), raw_iocs (list[str]), parse_errors (list[str])

### Testing Strategy
- pytest with pytest-asyncio
- Test valid CanonicalAlert creation from dict
- Test CanonicalAlert rejects missing required fields (ValidationError)
- Test GraphState defaults to RECEIVED with empty lists
- Test RiskState.NO_BASELINE when investigation_priority is None
- Test IncidentScore: decay at 30 days is approximately 0.5 (within 0.01 tolerance)
- Test IncidentScore: same_tenant=True boosts score
- Test EntityType enum completeness
- Test NormalizedEntity default confidence
- All tests must pass before story is marked done

## Dev Agent Record

### Implementation Plan
All Pydantic v2 models implemented in shared/schemas/ with full test coverage.

### Debug Log
No issues encountered. All 52 tests passed on first run.

### Completion Notes
- Created 5 schema modules: alert.py, investigation.py, risk.py, scoring.py, entity.py
- All models use Pydantic v2 BaseModel with Python 3.12+ type hints
- CanonicalAlert has ISO 8601 timestamp validator and Literal severity enforcement
- classify_risk() correctly returns NO_BASELINE for absent data, UNKNOWN for stale data
- score_incident() implements exponential decay formula with ~30 day half-life
- 52 unit tests cover all 8 acceptance criteria

## File List
- `pyproject.toml` — Project config with pydantic + pytest deps
- `shared/__init__.py` — Convenience re-exports
- `shared/schemas/__init__.py` — All model exports
- `shared/schemas/alert.py` — CanonicalAlert, SeverityLevel
- `shared/schemas/investigation.py` — InvestigationState, AgentRole, GraphState
- `shared/schemas/risk.py` — RiskState, RiskSignal, classify_risk()
- `shared/schemas/scoring.py` — IncidentScore, score_incident(), constants
- `shared/schemas/entity.py` — EntityType, NormalizedEntity, AlertEntities
- `tests/__init__.py`
- `tests/test_schemas/__init__.py`
- `tests/test_schemas/test_alert.py` — 15 tests (AC-1.1.1, AC-1.1.2, AC-1.1.3)
- `tests/test_schemas/test_investigation.py` — 7 tests (AC-1.1.4, AC-1.1.5)
- `tests/test_schemas/test_risk.py` — 11 tests (AC-1.1.6)
- `tests/test_schemas/test_scoring.py` — 10 tests (AC-1.1.7)
- `tests/test_schemas/test_entity.py` — 9 tests (AC-1.1.8)

## Change Log
- 2026-02-14: Story 1.1 implemented — 52/52 tests passing

## Status

done
