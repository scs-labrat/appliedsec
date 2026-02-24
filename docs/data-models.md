# ALUSKORT — Data Models Reference

**Project:** ALUSKORT - Cloud-Neutral Security Reasoning Control Plane
**Generated:** 2026-02-21

---

## 1. Database Schema Overview

PostgreSQL 16 with 7 migrations defining 30+ tables.

| Migration | Tables | Purpose |
|-----------|--------|---------|
| 001 | 9 | Core: MITRE, taxonomy, IOCs, playbooks, incidents, FP patterns |
| 002 | 3 | CTEM: exposures, validations, remediations |
| 003 | 6 | Investigation state, inference logs, orbital telemetry |
| 004 | 10 | Extended ATLAS telemetry (physics, NL, API, CI/CD, OPC-UA) |
| 005 | 1+ | Taxonomy seed data (53 ATT&CK + ATLAS techniques) |
| 006 | 1 | Immutable audit_records (partitioned, SOC 2 CC6.8) |
| 007 | 2 | Audit chain state + verification log |

---

## 2. Core Tables (Migration 001)

### mitre_techniques
MITRE ATT&CK framework reference data.

| Column | Type | Notes |
|--------|------|-------|
| doc_id | TEXT PK | |
| technique_id | TEXT UNIQUE | e.g., T1059.001 |
| technique_name | TEXT | |
| parent_technique | TEXT | For sub-techniques |
| tactic | TEXT[] | GIN indexed |
| description | TEXT | |
| platforms | TEXT[] | GIN indexed |
| groups_using | TEXT[] | GIN indexed |
| severity_baseline | TEXT | Default 'medium' |

### taxonomy_ids
Controlled vocabulary for ATT&CK + ATLAS technique IDs (deny-by-default validation).

| Column | Type | Notes |
|--------|------|-------|
| technique_id | TEXT PK | e.g., T1059 or AML.T0043 |
| framework | TEXT | 'attack' or 'atlas' |
| name | TEXT | |
| is_subtechnique | BOOLEAN | |
| parent_id | TEXT | FK to self |
| deprecated | BOOLEAN | Excluded from validation |

### threat_intel_iocs
IOC database for correlation.

| Column | Type | Notes |
|--------|------|-------|
| doc_id | TEXT PK | |
| indicator_type | TEXT | |
| indicator_value | TEXT | UNIQUE with type |
| confidence | INTEGER | 0-100, constrained |
| mitre_techniques | TEXT[] | GIN indexed |
| expiry | TIMESTAMPTZ | Indexed |

### playbooks + playbook_steps
Response playbooks with ordered steps.

| Column (playbooks) | Type | Notes |
|---------------------|------|-------|
| doc_id | TEXT PK | |
| title | TEXT | |
| mitre_techniques | TEXT[] | NOT NULL |
| review_status | TEXT | draft/approved |

| Column (playbook_steps) | Type | Notes |
|---------------------------|------|-------|
| playbook_id | TEXT FK | → playbooks.doc_id |
| step_number | INTEGER | Composite PK |
| automated | BOOLEAN | |
| requires_approval | BOOLEAN | |

### investigation_state (Migration 003)
Persistent GraphState for investigations.

| Column | Type | Notes |
|--------|------|-------|
| investigation_id | TEXT PK | |
| state | TEXT | 8 states (see InvestigationState enum) |
| graph_state | JSONB | Full GraphState serialised |
| confidence | REAL | |
| llm_calls | INTEGER | |
| total_cost_usd | REAL | |

### fp_patterns
False positive patterns for auto-close.

| Column | Type | Notes |
|--------|------|-------|
| pattern_id | TEXT PK | |
| alert_names | TEXT[] | GIN indexed |
| conditions | JSONB | |
| confidence_threshold | FLOAT | Default 0.90 |
| approved_by | TEXT | NOT NULL |

---

## 3. CTEM Tables (Migration 002)

### ctem_exposures
Normalised threat exposures from all vendor feeds.

| Column | Type | Notes |
|--------|------|-------|
| id | BIGSERIAL PK | |
| exposure_key | TEXT UNIQUE | sha256(source:title:asset) |
| source_tool | TEXT | wiz, snyk, garak, art |
| severity | TEXT | Consequence-weighted |
| exploitability_score | REAL | 0.0-1.0 |
| physical_consequence | TEXT | safety_life, equipment, downtime, data_loss |
| ctem_score | REAL | 0.0-10.0 |
| sla_deadline | TIMESTAMPTZ | Indexed (open/in-progress only) |

---

## 4. Audit Tables (Migrations 006-007)

### audit_records (PARTITIONED)
Immutable append-only audit trail.

| Column | Type | Notes |
|--------|------|-------|
| audit_id | TEXT | |
| tenant_id | TEXT | Part of composite PK |
| sequence_number | BIGINT | Part of composite PK, unique per tenant |
| previous_hash | TEXT | Hash chain link |
| timestamp | TIMESTAMPTZ | Partition key |
| event_type | TEXT | Validated against EventTaxonomy (45 types) |
| event_category | TEXT | decision, action, approval, security, system |
| context | JSONB | LLM metrics, retrieval, taxonomy, risk |
| decision | JSONB | Classification, confidence, reasoning |
| outcome | JSONB | Status, actions, approvals, feedback |
| record_hash | TEXT | Integrity hash |

**Partitions:** Monthly (2026-02 through 2026-05)
**Immutability:** Trigger `audit_immutable_guard()` blocks UPDATE/DELETE

### audit_chain_state
Per-tenant hash chain head tracking.

| Column | Type | Notes |
|--------|------|-------|
| tenant_id | TEXT PK | |
| last_sequence | BIGINT | |
| last_hash | TEXT | 64-char hex |

---

## 5. Pydantic Models (Application Layer)

### Core Schemas (`shared/schemas/`)

#### CanonicalAlert (`alert.py`)
```python
class CanonicalAlert(BaseModel):
    alert_id: str
    source: str
    timestamp: str              # ISO 8601 validated
    title: str
    description: str
    severity: SeverityLevel     # critical|high|medium|low|informational
    tactics: list[str]
    techniques: list[str]
    entities_raw: str
    tenant_id: str
    raw_payload: dict
```

#### GraphState (`investigation.py`)
```python
class GraphState(BaseModel):
    investigation_id: str
    state: InvestigationState   # 8 states
    taxonomy_version: str
    entities: dict
    ioc_matches: list
    ctem_exposures: list
    atlas_techniques: list
    similar_incidents: list
    decision_chain: list[DecisionEntry]
    classification: str
    confidence: float
    severity: str
    recommended_actions: list
    llm_calls: int
    total_cost_usd: float
```

#### AuditRecord (`audit.py`)
```python
class AuditRecord(BaseModel):
    audit_id: str
    tenant_id: str
    sequence_number: int
    previous_hash: str
    timestamp: str
    event_type: str             # Validated against EventTaxonomy
    actor_type: str
    actor_id: str
    context: AuditContext       # 70+ fields (LLM, retrieval, taxonomy, risk)
    decision: AuditDecision
    outcome: AuditOutcome
    record_hash: str
```

### Routing Schemas (`routing.py`)
```python
class LLMProvider(str, Enum):  # anthropic, openai, local, groq
class ModelConfig(BaseModel):  # provider, model_id, pricing, capabilities
class TaskCapabilities(BaseModel):  # tool_use, json, context, latency, thinking
```

### Risk Schema (`risk.py`)
```python
class RiskState(str, Enum):    # no_baseline, unknown, low, medium, high
# Key rule: absent data → NO_BASELINE, never LOW
```

### Scoring Schema (`scoring.py`)
```python
# Composite: α(0.4)*similarity + β(0.3)*recency + γ(0.15)*tenant + δ(0.15)*technique
# Decay: exp(-0.023 * age_days) → ~30-day half-life
```

---

## 6. Dataclass Models (Process Layer)

### CTEMExposure (`ctem_normaliser/models.py`)
22-field normalised exposure with consequence-weighted severity matrix (12 combinations) and SLA deadlines (CRITICAL: 24h → LOW: 30d).

### DetectionResult (`atlas_detection/models.py`)
Detection rule output with safety confidence floors (0.7 for physics oracle and sensor spoofing rules).

### ModelTier + RoutingDecision (`llm_router/models.py`)
4-tier model registry (Haiku → Sonnet → Opus → Batch) with degradation policies and fallback chains.

### BatchTask + BatchJob (`batch_scheduler/models.py`)
Batch LLM processing with dual-trigger (count=50, time=6h) and 24h SLA.

---

## 7. Enums & Controlled Vocabularies

| Enum | Values | Location |
|------|--------|----------|
| SeverityLevel | critical, high, medium, low, informational | `alert.py` |
| InvestigationState | received, parsing, enriching, reasoning, awaiting_human, responding, closed, failed | `investigation.py` |
| AgentRole | ioc_extractor, context_enricher, reasoning_agent, response_agent, ctem_correlator, atlas_mapper | `investigation.py` |
| EntityType | 15 types (account, host, ip, file, process, url, dns, filehash, mailbox, etc.) | `entity.py` |
| EventTaxonomy | 45 event types across 5 categories | `event_taxonomy.py` |
| EventCategory | decision, action, approval, security, system | `event_taxonomy.py` |
| RiskState | no_baseline, unknown, low, medium, high | `risk.py` |
| LLMProvider | anthropic, openai, local, groq | `routing.py` |
| ModelTier | tier_0, tier_1, tier_1+, tier_2 | `llm_router/models.py` |
| DegradationLevel | full_capability, secondary_active, deterministic_only, passthrough | `llm_router/models.py` |
| BatchJobStatus | pending, submitted, in_progress, completed, failed, expired | `batch_scheduler/models.py` |

---

## 8. Indexing Strategy

| Type | Columns | Purpose |
|------|---------|---------|
| **GIN** | tactic, platforms, groups_using, campaigns, alert_names | Array/JSONB search |
| **UNIQUE** | technique_id, (indicator_type, indicator_value), exposure_key | Deduplication |
| **Composite** | (status, severity), (tenant_id, timestamp), (event_type, timestamp) | Filtered queries |
| **Partial** | sla_deadline WHERE status IN ('Open', 'InProgress') | Active-only scans |
| **Range partition** | audit_records by month on timestamp | Time-window queries |

---

## 9. Multi-Tenancy

All tables include `tenant_id` (default: 'default'). Used in:
- Composite keys: `(tenant_id, sequence_number)` in audit
- All major indexes include tenant filtering
- Audit chain state is per-tenant
- Investigation state indexed by tenant
