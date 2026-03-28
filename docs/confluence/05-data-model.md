# Data Model Reference

## Entity-Relationship Overview

```
+------------------+      +-------------------+      +------------------+
| mitre_techniques |      | threat_intel_iocs |      | mitre_groups     |
| (technique_id PK)|      | (doc_id PK)       |      | (doc_id PK)      |
| technique_name   |      | indicator_type    |      | group_name       |
| tactic[]         |<-----| mitre_techniques[]|      | techniques_used  |
| platforms[]      |      | confidence        |      | target_sectors[] |
+------------------+      +-------------------+      +------------------+
        |
        v
+------------------+      +-------------------+      +------------------+
| taxonomy_ids     |      | investigations    |      | fp_patterns      |
| (technique_id PK)|      | (investigation_id)|      | (pattern_id PK)  |
| framework        |      | state             |      | alert_names[]    |
| is_subtechnique  |      | alert_id          |      | conditions       |
+------------------+      | tenant_id         |      | confidence_thresh|
                          | classification    |      | approved_by      |
                          | decision_chain    |      +------------------+
                          +--------+----------+
                                   |
              +--------------------+--------------------+
              |                    |                    |
   +----------v------+  +---------v--------+  +-------v----------+
   | incident_memory  |  | playbooks        |  | org_context       |
   | (doc_id PK)      |  | (doc_id PK)      |  | (doc_id PK)       |
   | incident_id      |  | title            |  | entity_type       |
   | alert_ids[]      |  | category         |  | entity_name       |
   | entities JSONB   |  | mitre_techniques[]| | criticality       |
   | decision_chain   |  +--------+---------+  | tenant_id         |
   | outcome          |           |             +------------------+
   +------------------+  +--------v---------+
                         | playbook_steps   |
                         | (playbook_id FK) |
                         | step_number      |
                         | action           |
                         | automated        |
                         +------------------+

+------------------+      +-------------------+      +------------------+
| ctem_exposures   |      | ctem_validations  |      | ctem_remediations|
| (id BIGSERIAL)   |      | (id BIGSERIAL)    |      | (id BIGSERIAL)   |
| exposure_key UQ  |      | validation_id UQ  |      | remediation_id UQ|
| source_tool      |      | exposure_id       |      | exposure_id      |
| severity         |      | exploitable       |      | status           |
| asset_id         |      | exploit_complexity|      | assigned_to      |
| asset_zone       |      | attack_path       |      | sla_deadline     |
| ctem_score       |      +-------------------+      | sla_breached     |
| sla_deadline     |                                  +------------------+
+------------------+

+------------------+      +-------------------+
| audit_records    |      | audit_chain_state |
| (audit_id PK)    |      | (tenant_id PK)    |
| tenant_id        |      | last_sequence     |
| sequence_number  |      | last_hash         |
| previous_hash    |      | last_timestamp    |
| record_hash      |      +-------------------+
| event_type       |
| event_category   |
+------------------+

+-------------------+     +-------------------+
| fp_governance     |     | dashboard_sessions|
| (pattern_id,      |     | (session_id PK)   |
|  tenant_id PK)    |     | user_id           |
| decision          |     | role              |
| reviewer          |     | expires_at        |
+-------------------+     +-------------------+

+-------------------+     +-------------------+
| connectors        |     | atlas_telemetry   |
| (connector_id PK) |     | (id BIGSERIAL)    |
| connector_type    |     | rule_id           |
| config JSONB      |     | detection_result  |
| status            |     | confidence        |
| last_poll_at      |     | evidence JSONB    |
+-------------------+     +-------------------+
```

---

## SQL Migrations

All migrations live in `infra/migrations/` and are applied automatically on PostgreSQL container startup.

| # | File | Tables Created | Purpose |
|---|------|---------------|---------|
| 001 | `001_core_tables.sql` | `mitre_techniques`, `mitre_groups`, `taxonomy_ids`, `threat_intel_iocs`, `playbooks`, `playbook_steps`, `incident_memory`, `fp_patterns`, `org_context` | Core investigation and knowledge base tables |
| 002 | `002_ctem_tables.sql` | `ctem_exposures`, `ctem_validations`, `ctem_remediations` | CTEM exposure management |
| 003 | `003_atlas_tables.sql` | `atlas_detections`, `atlas_techniques_ref` | MITRE ATLAS detection storage |
| 004 | `004_atlas_telemetry.sql` | `atlas_telemetry` | ATLAS detection telemetry and trust levels |
| 005 | `005_taxonomy_seed_data.sql` | -- (data only) | Seed MITRE ATT&CK and ATLAS technique IDs into `taxonomy_ids` |
| 006 | `006_audit_records.sql` | `audit_records` | Audit trail storage with hash chain fields |
| 007 | `007_audit_chain_state.sql` | `audit_chain_state` | Per-tenant hash chain head tracking |
| 008 | `008_fp_governance.sql` | `fp_governance` | FP pattern governance and approval tracking |
| 009 | `009_embedding_migration.sql` | `embedding_migration_log` | Vector embedding migration tracking |
| 010 | `010_incident_memory_rare.sql` | -- (alter) | Add rare entity columns to incident_memory |
| 011 | `011_dashboard_sessions.sql` | `dashboard_sessions` | Dashboard user session management |
| 012 | `012_connectors.sql` | `connectors` | SIEM connector configuration and state |

---

## Key Pydantic Models

### CanonicalAlert (`shared/schemas/alert.py`)

The single source of truth for ingested alerts. Every SIEM adapter must map source-specific alerts into this schema.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alert_id` | `str` | Yes | Unique alert identifier from source SIEM |
| `source` | `str` | Yes | Source SIEM name (sentinel, elastic, splunk) |
| `timestamp` | `str` | Yes | ISO 8601 timestamp (validated) |
| `title` | `str` | Yes | Alert title/name |
| `description` | `str` | Yes | Full alert description text |
| `severity` | `SeverityLevel` | Yes | critical, high, medium, low, informational |
| `tactics` | `list[str]` | No | MITRE ATT&CK tactics |
| `techniques` | `list[str]` | No | MITRE ATT&CK technique IDs |
| `entities_raw` | `str` | No | Raw entity JSON from SIEM |
| `product` | `str` | No | Source product name |
| `tenant_id` | `str` | No | Multi-tenant identifier |
| `raw_payload` | `dict` | No | Original raw alert payload |

### GraphState (`shared/schemas/investigation.py`)

The central state object persisted to PostgreSQL for each investigation. Passed through every agent in the pipeline.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `investigation_id` | `str` | -- | UUID for this investigation |
| `state` | `InvestigationState` | `RECEIVED` | Current FSM state |
| `alert_id` | `str` | `""` | Source alert ID |
| `tenant_id` | `str` | `""` | Tenant identifier |
| `entities` | `dict[str, Any]` | `{}` | Parsed entities |
| `ioc_matches` | `list[Any]` | `[]` | Threat intel IOC matches |
| `ueba_context` | `list[Any]` | `[]` | User/entity behaviour analytics |
| `ctem_exposures` | `list[Any]` | `[]` | CTEM exposure matches |
| `atlas_techniques` | `list[Any]` | `[]` | MITRE ATLAS technique matches |
| `similar_incidents` | `list[Any]` | `[]` | Historically similar investigations |
| `playbook_matches` | `list[Any]` | `[]` | Matched response playbooks |
| `decision_chain` | `list[Any]` | `[]` | Ordered list of DecisionEntry records |
| `classification` | `str` | `""` | Alert classification label |
| `confidence` | `float` | `0.0` | Classification confidence (0.0-1.0) |
| `severity` | `str` | `""` | Alert severity level |
| `recommended_actions` | `list[Any]` | `[]` | Ordered response actions |
| `requires_human_approval` | `bool` | `False` | Whether human approval is needed |
| `risk_state` | `str` | `"unknown"` | Aggregate risk assessment |
| `llm_calls` | `int` | `0` | Number of LLM API calls made |
| `total_cost_usd` | `float` | `0.0` | Total LLM cost for this investigation |
| `queries_executed` | `int` | `0` | Number of database queries executed |
| `case_facts` | `dict[str, Any]` | `{}` | Structured case facts for reasoning |

### NormalizedEntity (`shared/schemas/entity.py`)

| Field | Type | Description |
|-------|------|-------------|
| `entity_type` | `EntityType` | account, host, ip, file, process, url, dns, filehash, etc. (15 types) |
| `primary_value` | `str` | Primary identifier value |
| `properties` | `dict[str, Any]` | Additional entity properties |
| `confidence` | `float` | Extraction confidence (default 1.0) |
| `source_id` | `str` (optional) | Source alert/system identifier |

### DecisionEntry (`shared/schemas/investigation.py`)

| Field | Type | Description |
|-------|------|-------------|
| `step` | `str` | Pipeline step name |
| `agent` | `str` | Agent that made the decision |
| `action` | `str` | Action taken |
| `reasoning` | `str` | Human-readable explanation |
| `confidence` | `float` | Confidence at this decision point |
| `attestation_status` | `str` | Telemetry trust level |
| `taxonomy_version` | `str` | Event taxonomy version |

### RiskState (`shared/schemas/risk.py`)

| Value | Description |
|-------|-------------|
| `no_baseline` | Data is absent (NOT equivalent to low risk) |
| `unknown` | Data is stale (> 24 hours old) |
| `low` | Investigation priority < 3 |
| `medium` | Investigation priority 3-5 |
| `high` | Investigation priority >= 6 |

### EventTaxonomy (`shared/schemas/event_taxonomy.py`)

40 controlled audit event types across 5 categories:

| Category | Count | Examples |
|----------|-------|---------|
| Decision | 12 | `alert.classified`, `alert.auto_closed`, `routing.tier_selected` |
| Action | 11 | `response.executed`, `fp_pattern.created`, `embedding.reindexed` |
| Approval | 8 | `approval.granted`, `approval.denied`, `approval.escalated` |
| Security | 6 | `injection.detected`, `technique.quarantined`, `spend.hard_limit` |
| System | 8 | `kill_switch.activated`, `circuit_breaker.opened`, `degradation.entered` |

---

## Kafka Topic Reference

### Core Pipeline Topics (9)

| Topic | Partitions | Retention | Schema | Producer | Consumer |
|-------|-----------|-----------|--------|----------|----------|
| `alerts.raw` | 4 | 7 days | Raw SIEM alert JSON | SIEM Adapters | Entity Parser |
| `alerts.normalized` | 4 | 7 days | `CanonicalAlert` | Entity Parser | Orchestrator |
| `incidents.enriched` | 4 | 7 days | Enriched `GraphState` | Orchestrator | Dashboard |
| `jobs.llm.priority.critical` | 4 | 3 days | LLM job payload | Orchestrator | Context Gateway |
| `jobs.llm.priority.high` | 4 | 3 days | LLM job payload | Orchestrator | Context Gateway |
| `jobs.llm.priority.normal` | 4 | 7 days | LLM job payload | Orchestrator | Context Gateway |
| `jobs.llm.priority.low` | 2 | 14 days | Batch LLM payload | Batch Scheduler | Context Gateway |
| `actions.pending` | 2 | 7 days | Response action payload | Orchestrator | Response executor |
| `audit.events` | 4 | 90 days | Audit event JSON | All services | Audit Service |

### CTEM Topics (9)

| Topic | Partitions | Retention | Schema | Producer | Consumer |
|-------|-----------|-----------|--------|----------|----------|
| `ctem.raw.wiz` | 4 | 30 days | Wiz vulnerability JSON | External/Connector | CTEM Normaliser |
| `ctem.raw.snyk` | 2 | 30 days | Snyk vulnerability JSON | External/Connector | CTEM Normaliser |
| `ctem.raw.garak` | 2 | 30 days | Garak probe results | External/Connector | CTEM Normaliser |
| `ctem.raw.art` | 2 | 30 days | ART robustness results | External/Connector | CTEM Normaliser |
| `ctem.raw.burp` | 2 | 30 days | Burp Suite scan results | External/Connector | CTEM Normaliser |
| `ctem.raw.custom` | 2 | 30 days | Custom scanner results | External/Connector | CTEM Normaliser |
| `ctem.raw.validation` | 2 | 90 days | Validation campaign results | External | CTEM Normaliser |
| `ctem.raw.remediation` | 2 | 90 days | Remediation status updates | External | CTEM Normaliser |
| `ctem.normalized` | 4 | 30 days | `CTEMExposure` JSON | CTEM Normaliser | Orchestrator |

### DLQ Topics (6)

| Topic | Partitions | Retention | Purpose |
|-------|-----------|-----------|---------|
| `alerts.raw.dlq` | 2 | 30 days | Failed raw alert parsing |
| `jobs.llm.priority.critical.dlq` | 2 | 30 days | Failed critical LLM jobs |
| `jobs.llm.priority.high.dlq` | 2 | 30 days | Failed high-priority LLM jobs |
| `jobs.llm.priority.normal.dlq` | 2 | 30 days | Failed normal LLM jobs |
| `jobs.llm.priority.low.dlq` | 2 | 30 days | Failed low-priority LLM jobs |
| `ctem.normalized.dlq` | 2 | 30 days | Failed CTEM normalisation |

### Knowledge Update Topics (6)

| Topic | Partitions | Retention | Purpose |
|-------|-----------|-----------|---------|
| `knowledge.mitre.updated` | 1 | 7 days | MITRE ATT&CK/ATLAS data refresh |
| `knowledge.ti.ioc.new` | 2 | 7 days | New threat intel IOCs ingested |
| `knowledge.ti.report.new` | 2 | 7 days | New threat intel reports |
| `knowledge.playbook.updated` | 1 | 7 days | Playbook creation/update |
| `knowledge.incident.stored` | 2 | 7 days | Closed investigation stored |
| `knowledge.fp.approved` | 1 | 7 days | FP pattern approved/revoked |

**Total: 30 topics** (9 core + 9 CTEM + 6 DLQ + 6 knowledge)
