# ALUSKORT — Audit Trail Architecture

**Project:** ALUSKORT - Cloud-Neutral Security Reasoning Control Plane
**Version:** 1.0
**Generated:** 2026-02-15
**Author:** Omeriko (CR + Audit Design)
**Status:** Phase 1 — Architecture Design
**Classification:** CONFIDENTIAL

> This document defines the unified audit trail for ALUSKORT. It replaces the
> scattered audit references in `ai-system-design.md` Section 6.1,
> `rag-design.md` Section 5.5, and `ctem-integration.md` Section 2.1 with a
> single, coherent audit architecture that satisfies SOC 2, ISO 27001, and
> general regulatory evidence requirements.

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Audit Record Schema](#2-audit-record-schema)
3. [Event Taxonomy](#3-event-taxonomy)
4. [Immutability & Tamper Evidence](#4-immutability--tamper-evidence)
5. [Audit Service Architecture](#5-audit-service-architecture)
6. [Retention Tiers & Lifecycle](#6-retention-tiers--lifecycle)
7. [Evidence Reconstruction](#7-evidence-reconstruction)
8. [Export & Reporting](#8-export--reporting)
9. [Integration Points](#9-integration-points)
10. [Database Schema](#10-database-schema)
11. [Compliance Mapping](#11-compliance-mapping)
12. [Operational Runbook](#12-operational-runbook)
13. [Validation Tests](#13-validation-tests)

---

## 1. Design Principles

### 1.1 Core Requirements

| Principle | Meaning | Consequence |
|---|---|---|
| **Completeness** | Every autonomous decision is recorded with full provenance | No decision exists without an audit record |
| **Immutability** | Records cannot be altered after creation | Hash chain + append-only storage |
| **Reconstructability** | Any past decision can be fully explained from the audit trail alone | Evidence packages are self-contained |
| **Independence** | Audit trail is not dependent on the system that generated the decisions | Separate storage, separate access controls |
| **Timeliness** | Audit records are written synchronously with (or immediately after) the decision | No "write audit later" patterns |
| **Least privilege** | Audit data has stricter access controls than operational data | Separate roles, read-only for most users |

### 1.2 What Gets Audited

Every action in this list produces an audit record:

- Alert auto-classified (with or without LLM)
- Alert auto-closed (FP pattern match or LLM decision)
- Investigation state transition (every edge in the investigation graph)
- LLM call made (prompt sent, response received, model used, cost incurred)
- Retrieval context assembled (what was retrieved, from which stores, what was included/excluded)
- Human approval requested
- Human approval granted or denied
- Human approval timed out
- Response action prepared
- Response action executed
- FP pattern created, approved, activated, expired, or revoked
- Playbook selected, executed, or generated
- CTEM exposure scored, assigned, remediated, or verified
- ATLAS detection rule fired
- Kill switch activated or deactivated
- Degradation mode entered or exited
- Spend guard triggered
- Accumulation guard triggered
- Injection attempt detected
- Technique ID quarantined (hallucination)
- Provider failover (primary -> secondary LLM)
- Configuration change (tier thresholds, confidence thresholds, timeouts)

### 1.3 What Does NOT Get Audited (Operational Telemetry Only)

- Individual Kafka message offsets
- Database connection pool events
- Health check pings
- Prometheus metric scrapes
- Container lifecycle events (handled by Kubernetes audit logs)

These belong in operational telemetry (Prometheus + Grafana), not the audit trail.

---

## 2. Audit Record Schema

### 2.1 Core Record

Every audit event conforms to this schema. The schema is intentionally flat at the
top level (no nested required fields) to enable efficient querying and indexing.

```python
@dataclass
class AuditRecord:
    """
    Single audit event. Every autonomous decision, human action,
    and system event that affects security outcomes is recorded here.

    Immutable after creation. Hash chain provides tamper evidence.
    """

    # --- Identity ---
    audit_id: str                    # UUIDv7 (time-sortable)
    tenant_id: str                   # Tenant isolation
    sequence_number: int             # Per-tenant monotonic counter (gap-free)
    previous_hash: str               # SHA-256 of the previous record in this tenant's chain

    # --- Temporal ---
    timestamp: str                   # ISO 8601 UTC, nanosecond precision
    ingested_at: str                 # When the audit service received this event

    # --- Classification ---
    event_type: str                  # From EventTaxonomy (Section 3)
    event_category: str              # "decision", "action", "approval", "system", "security"
    severity: str                    # "info", "warning", "critical"

    # --- Actor ---
    actor_type: str                  # "agent", "human", "system", "scheduler"
    actor_id: str                    # Agent role, analyst username, or service name
    actor_permissions: list[str]     # Permissions held at time of action

    # --- Subject ---
    investigation_id: str            # Links to GraphState (empty for non-investigation events)
    alert_id: str                    # Source alert (empty for non-alert events)
    entity_ids: list[str]            # Entities involved (users, hosts, IPs)

    # --- Decision Context ---
    # What information was available when the decision was made
    context: AuditContext             # See Section 2.2

    # --- Decision ---
    decision: AuditDecision           # See Section 2.3

    # --- Outcome ---
    outcome: AuditOutcome             # See Section 2.4

    # --- Integrity ---
    record_hash: str                 # SHA-256 of this entire record (excluding record_hash itself)
    record_version: str              # Schema version (e.g., "1.0")
```

### 2.2 AuditContext — What Was Known

```python
@dataclass
class AuditContext:
    """
    Captures the complete decision context at the time of the event.
    An auditor should be able to understand WHY the decision was made
    from this context alone.
    """

    # --- LLM Context (populated for LLM-involving decisions) ---
    llm_provider: str = ""           # "anthropic", "openai", "local"
    llm_model_id: str = ""           # e.g., "claude-sonnet-4-5-20250929"
    llm_model_tier: str = ""         # "tier_0", "tier_1", "tier_1_plus", "tier_2"
    llm_system_prompt_hash: str = "" # SHA-256 of the system prompt sent
    llm_user_content_hash: str = ""  # SHA-256 of the user content sent
    llm_prompt_template_id: str = "" # Versioned prompt template identifier
    llm_prompt_template_version: str = ""
    llm_input_tokens: int = 0
    llm_output_tokens: int = 0
    llm_cache_read_tokens: int = 0
    llm_cache_write_tokens: int = 0
    llm_cost_usd: float = 0.0
    llm_latency_ms: int = 0
    llm_raw_response_hash: str = ""  # SHA-256 of the raw LLM response
    llm_extended_thinking_used: bool = False
    llm_tool_use_schema: str = ""    # Which tool schema was used (if any)

    # --- Retrieval Context (populated for RAG-involving decisions) ---
    retrieval_stores_queried: list[str] = field(default_factory=list)  # ["qdrant", "postgres", "redis"]
    retrieval_query_hashes: list[str] = field(default_factory=list)    # Hash of each query
    retrieval_results_count: int = 0
    retrieval_results_used: int = 0      # After reranking/filtering
    retrieval_token_budget: int = 0
    retrieval_token_used: int = 0
    retrieval_sources: list[str] = field(default_factory=list)  # Doc IDs of retrieved context

    # --- Taxonomy Context ---
    taxonomy_version_attack: str = ""    # ATT&CK version active (e.g., "16.1")
    taxonomy_version_atlas: str = ""     # ATLAS version active
    techniques_identified: list[str] = field(default_factory=list)
    techniques_validated: list[str] = field(default_factory=list)   # Passed taxonomy check
    techniques_quarantined: list[str] = field(default_factory=list) # Failed taxonomy check

    # --- Risk Context ---
    risk_state: str = ""                 # "no_baseline", "unknown", "low", "medium", "high"
    risk_data_freshness_hours: float = 0.0
    ctem_exposures_matched: int = 0
    similar_incidents_found: int = 0
    fp_patterns_checked: int = 0
    fp_pattern_matched: str = ""         # Pattern ID if matched, empty if not

    # --- Environment ---
    degradation_level: str = "full"      # "full", "deterministic_only", "structured_search", "static_consequence", "passthrough"
    provider_health: dict = field(default_factory=dict)  # {"anthropic": "healthy", "openai": "circuit_open"}

    # --- Raw Evidence References ---
    # Pointers to full-size artifacts in object store (not inline, to keep audit records small)
    evidence_refs: list[str] = field(default_factory=list)  # S3/MinIO URIs
```

### 2.3 AuditDecision — What Was Decided

```python
@dataclass
class AuditDecision:
    """
    The actual decision made. Structured so that an auditor can
    evaluate whether the decision was reasonable given the context.
    """
    decision_type: str               # "classify", "escalate", "auto_close", "request_approval",
                                     # "execute_playbook", "approve", "reject", "quarantine",
                                     # "short_circuit", "degrade", "failover"
    classification: str = ""         # "true_positive", "false_positive", "benign_true_positive"
    confidence: float = 0.0          # 0.0 - 1.0
    confidence_basis: str = ""       # Human-readable explanation of confidence derivation
    severity_assigned: str = ""      # "critical", "high", "medium", "low", "informational"
    recommended_actions: list[str] = field(default_factory=list)
    reasoning_summary: str = ""      # 1-3 sentence summary of the reasoning chain
    constraints_applied: list[str] = field(default_factory=list)  # Which guardrails/constraints fired
    alternatives_considered: list[str] = field(default_factory=list)  # What else was considered
```

### 2.4 AuditOutcome — What Happened

```python
@dataclass
class AuditOutcome:
    """
    The result of executing the decision.
    Written after the action completes (or fails).
    """
    outcome_status: str              # "success", "failed", "pending_approval", "timed_out",
                                     # "blocked_by_guardrail", "rolled_back"
    action_taken: str = ""           # What was actually done
    action_target: str = ""          # What it was done to (incident ID, endpoint, account)
    error_details: str = ""          # If failed, why
    duration_ms: int = 0             # How long the action took
    state_before: str = ""           # Investigation state before this event
    state_after: str = ""            # Investigation state after this event
    cost_incurred_usd: float = 0.0   # Total cost of this decision (LLM + compute)

    # --- Human Interaction ---
    approval_requested_from: str = ""    # Analyst username (if approval requested)
    approval_received_from: str = ""     # Analyst username (if approved)
    approval_channel: str = ""           # "teams", "slack", "ui", "api"
    approval_latency_ms: int = 0         # Time from request to response
    approval_comment: str = ""           # Analyst's comment (if any)

    # --- Feedback (populated later if analyst provides correction) ---
    analyst_feedback_correct: bool | None = None  # None = no feedback yet
    analyst_feedback_rating: int | None = None     # 1-5
    analyst_feedback_comment: str = ""
    analyst_feedback_timestamp: str = ""
```

---

## 3. Event Taxonomy

Every `event_type` is a controlled vocabulary value. This prevents free-text drift
and enables reliable querying.

### 3.1 Decision Events

| event_type | event_category | Description | Actor |
|---|---|---|---|
| `alert.classified` | decision | Alert classified by LLM or deterministic rule | agent |
| `alert.auto_closed` | decision | Alert auto-closed (FP match or LLM confidence) | agent |
| `alert.escalated` | decision | Alert escalated to higher tier or human | agent |
| `alert.short_circuited` | decision | Alert closed by FP pattern without LLM call | agent |
| `investigation.state_changed` | decision | Investigation moved to new state | agent |
| `investigation.enriched` | decision | Context enrichment completed | agent |
| `playbook.selected` | decision | Playbook chosen for this investigation | agent |
| `playbook.generated` | decision | New playbook auto-generated from investigation pattern | agent |
| `ctem.exposure_scored` | decision | CTEM finding scored with consequence weighting | agent |
| `atlas.detection_fired` | decision | ATLAS detection rule triggered | agent |
| `routing.tier_selected` | decision | LLM model tier chosen for a task | agent |
| `routing.provider_failover` | decision | Primary provider failed, using secondary | system |

### 3.2 Action Events

| event_type | event_category | Description | Actor |
|---|---|---|---|
| `response.prepared` | action | Response action prepared for approval | agent |
| `response.executed` | action | Response action executed (after approval) | agent |
| `response.rolled_back` | action | Response action reversed | human / agent |
| `ioc.enriched` | action | IOC looked up in TI cache | agent |
| `fp_pattern.created` | action | New FP pattern created (pending approval) | agent |
| `fp_pattern.activated` | action | FP pattern promoted from shadow to active | system |
| `ctem.remediation_assigned` | action | CTEM finding assigned to owner | agent |
| `ctem.remediation_verified` | action | CTEM remediation verified | human |
| `knowledge.indexed` | action | Knowledge base updated (MITRE, TI, playbook) | system |
| `embedding.reindexed` | action | Collection re-embedded with new model | system |

### 3.3 Approval Events

| event_type | event_category | Description | Actor |
|---|---|---|---|
| `approval.requested` | approval | Human approval requested for an action | agent |
| `approval.granted` | approval | Human approved the action | human |
| `approval.denied` | approval | Human denied the action | human |
| `approval.timed_out` | approval | Approval window expired without response | system |
| `approval.escalated` | approval | Approval re-routed to secondary reviewer | system |
| `fp_pattern.approved` | approval | FP pattern approved by analyst (requires 2 approvers) | human |
| `fp_pattern.revoked` | approval | FP pattern revoked | human |
| `shadow.go_live_approved` | approval | Shadow mode results approved for production | human |

### 3.4 Security Events

| event_type | event_category | Description | Actor |
|---|---|---|---|
| `injection.detected` | security | Prompt injection pattern detected in alert data | system |
| `injection.quarantined` | security | Malicious injection quarantined (not sent to LLM) | system |
| `technique.quarantined` | security | Hallucinated technique ID blocked from automation | system |
| `accumulation.threshold_breached` | security | Agent accessed too many distinct entities | system |
| `spend.soft_limit` | security | API spend approaching limit | system |
| `spend.hard_limit` | security | API spend hard cap hit, non-critical calls blocked | system |

### 3.5 System Events

| event_type | event_category | Description | Actor |
|---|---|---|---|
| `degradation.entered` | system | System entered a degradation level | system |
| `degradation.exited` | system | System recovered to higher capability | system |
| `kill_switch.activated` | system | Auto-close disabled for scope | human |
| `kill_switch.deactivated` | system | Auto-close re-enabled for scope | human |
| `config.changed` | system | Configuration parameter changed | human |
| `circuit_breaker.opened` | system | Circuit breaker tripped for a dependency | system |
| `circuit_breaker.closed` | system | Circuit breaker recovered | system |

---

## 4. Immutability & Tamper Evidence

### 4.1 Hash Chain Design

Each tenant maintains an independent hash chain. This ensures:
- Tenant A's audit integrity is not affected by Tenant B's volume
- Multi-tenant deployments can provide per-tenant audit exports
- Chain verification is parallelizable

```python
"""
ALUSKORT Audit Hash Chain
Each audit record includes the hash of the previous record,
forming a tamper-evident chain per tenant.
"""

import hashlib
import json
from dataclasses import asdict


def compute_record_hash(record: AuditRecord) -> str:
    """
    Compute SHA-256 hash of an audit record.

    The hash covers ALL fields except record_hash itself.
    Fields are serialized in deterministic order (sorted keys).
    """
    record_dict = asdict(record)
    record_dict.pop("record_hash", None)

    # Deterministic serialization: sorted keys, no whitespace variance
    canonical = json.dumps(record_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_chain(records: list[AuditRecord]) -> tuple[bool, list[str]]:
    """
    Verify the integrity of a sequence of audit records.

    Returns (valid, errors).
    - valid: True if the entire chain is intact
    - errors: list of human-readable integrity violations
    """
    errors = []

    for i, record in enumerate(records):
        # Verify record's own hash
        expected_hash = compute_record_hash(record)
        if record.record_hash != expected_hash:
            errors.append(
                f"Record {record.audit_id}: hash mismatch "
                f"(expected {expected_hash[:16]}..., got {record.record_hash[:16]}...)"
            )

        # Verify chain linkage (skip first record — its previous_hash is "genesis")
        if i > 0:
            expected_previous = records[i - 1].record_hash
            if record.previous_hash != expected_previous:
                errors.append(
                    f"Record {record.audit_id}: chain break "
                    f"(previous_hash does not match record {records[i-1].audit_id})"
                )

        # Verify sequence number is monotonically increasing
        if i > 0 and record.sequence_number != records[i - 1].sequence_number + 1:
            errors.append(
                f"Record {record.audit_id}: sequence gap "
                f"(expected {records[i-1].sequence_number + 1}, "
                f"got {record.sequence_number})"
            )

    return (len(errors) == 0, errors)
```

### 4.2 Genesis Record

Each tenant's chain starts with a genesis record:

```python
GENESIS_RECORD = AuditRecord(
    audit_id="00000000-0000-0000-0000-000000000000",
    tenant_id="{tenant_id}",
    sequence_number=0,
    previous_hash="0" * 64,  # 64 zeros — no predecessor
    timestamp="{tenant_creation_timestamp}",
    ingested_at="{tenant_creation_timestamp}",
    event_type="system.genesis",
    event_category="system",
    severity="info",
    actor_type="system",
    actor_id="aluskort-audit-service",
    actor_permissions=[],
    investigation_id="",
    alert_id="",
    entity_ids=[],
    context=AuditContext(),
    decision=AuditDecision(decision_type="genesis"),
    outcome=AuditOutcome(outcome_status="success", action_taken="Audit chain initialized"),
    record_hash="",  # Computed after creation
    record_version="1.0",
)
```

### 4.3 Integrity Verification Schedule

| Check | Frequency | Method | Alert |
|---|---|---|---|
| Chain continuity (no gaps in sequence) | Every 5 minutes | `verify_chain()` on last 100 records | `AluskortAuditChainBroken` |
| Full chain verification | Daily at 03:00 UTC | `verify_chain()` on entire hot tier | `AluskortAuditIntegrityFailed` |
| Cross-check Kafka vs Postgres | Hourly | Compare `audit.events` topic offset with Postgres `max(sequence_number)` | `AluskortAuditLagHigh` |
| Cold storage spot check | Weekly | Random sample of 100 records from S3, verify hashes | `AluskortAuditColdCorruption` |

### 4.4 Append-Only Enforcement

```sql
-- Postgres: prevent UPDATE and DELETE on audit table
-- Applied via row-level security + trigger

CREATE OR REPLACE FUNCTION audit_immutable_guard()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'Audit records are immutable. UPDATE is not permitted on audit_records table.';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Audit records are immutable. DELETE is not permitted on audit_records table.';
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_audit_immutability
    BEFORE UPDATE OR DELETE ON audit_records
    FOR EACH ROW
    EXECUTE FUNCTION audit_immutable_guard();

-- The ONLY way to remove audit records is via partition drop
-- during the retention lifecycle (Section 6), which requires
-- DBA-level access and is itself audited by Postgres audit logging.
```

---

## 5. Audit Service Architecture

### 5.1 Service Design

The Audit Service is a dedicated microservice, independent from the operational
pipeline. It has **write** access to the audit store and **read** access to
operational stores (for evidence enrichment).

```
                    ALUSKORT Services
    ┌─────────────────────────────────────────────┐
    │  Entity Parser  │  Orchestrator  │  Context  │
    │  CTEM Normaliser │  LLM Router   │  Gateway  │
    └────────┬────────────────┬───────────┬───────┘
             │                │           │
             │   audit.events Kafka topic │
             └────────────────┼───────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  AUDIT SERVICE   │
                    │                  │
                    │  1. Consume from │
                    │     audit.events │
                    │  2. Assign seq#  │
                    │  3. Compute hash │
                    │  4. Chain link   │
                    │  5. Write to PG  │
                    │  6. Archive to   │
                    │     object store │
                    └────────┬─────────┘
                             │
                ┌────────────┼────────────┐
                │            │            │
                ▼            ▼            ▼
           ┌─────────┐ ┌─────────┐ ┌──────────┐
           │Postgres │ │ S3 /    │ │Prometheus│
           │(hot +   │ │ MinIO   │ │(metrics) │
           │ warm)   │ │ (cold)  │ │          │
           └─────────┘ └─────────┘ └──────────┘
```

### 5.2 Service Specification

| Property | Value |
|---|---|
| **Service name** | `audit-service` |
| **Port** | 8040 |
| **Replicas** | 1 (single writer to maintain chain ordering; HA via Kafka consumer group rebalance) |
| **Kafka consumer group** | `aluskort.audit-service` |
| **Consumes** | `audit.events` |
| **Writes to** | Postgres `audit_records` table, S3/MinIO (cold archive) |
| **Dependencies** | Kafka, Postgres |
| **Resource requests** | 0.25 vCPU, 256Mi memory |

### 5.3 Why Single Writer

The hash chain requires strict ordering within a tenant. Running multiple writers
would require distributed consensus on sequence numbers. For the expected audit
volume (~5,000-20,000 events/day for a small SOC), a single writer with Kafka
consumer group failover provides sufficient throughput and simple correctness.

If throughput becomes a bottleneck (> 100,000 events/day), partition the chain
by tenant AND event_category, allowing parallel writers per partition.

### 5.4 Event Production Pattern

Every ALUSKORT service produces audit events by publishing to the `audit.events`
Kafka topic. This is the **only** way to create audit records. No service writes
directly to the audit Postgres table.

```python
"""
ALUSKORT Audit Event Producer
Used by all services to emit audit events.
"""

import json
import uuid
from datetime import datetime, timezone
from confluent_kafka import Producer


class AuditProducer:
    """Publishes audit events to the audit.events Kafka topic."""

    def __init__(self, kafka_bootstrap: str, service_name: str):
        self.producer = Producer({"bootstrap.servers": kafka_bootstrap})
        self.service_name = service_name
        self.topic = "audit.events"

    def emit(
        self,
        tenant_id: str,
        event_type: str,
        event_category: str,
        severity: str,
        actor_type: str,
        actor_id: str,
        investigation_id: str = "",
        alert_id: str = "",
        context: dict | None = None,
        decision: dict | None = None,
        outcome: dict | None = None,
    ) -> str:
        """
        Emit an audit event. Returns the audit_id.

        The Audit Service will assign sequence_number, compute hashes,
        and link into the chain. The producer only needs to provide
        the event content.
        """
        audit_id = str(uuid.uuid7())

        event = {
            "audit_id": audit_id,
            "tenant_id": tenant_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "event_category": event_category,
            "severity": severity,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "investigation_id": investigation_id,
            "alert_id": alert_id,
            "context": context or {},
            "decision": decision or {},
            "outcome": outcome or {},
            "source_service": self.service_name,
        }

        self.producer.produce(
            self.topic,
            key=tenant_id.encode("utf-8"),
            value=json.dumps(event).encode("utf-8"),
        )
        self.producer.flush()

        return audit_id
```

### 5.5 Evidence Artifact Storage

For events that involve large artifacts (full LLM prompts, full LLM responses,
raw alert payloads, retrieval result sets), the audit record stores a **hash**
inline and a **reference** to the full artifact in object store.

```python
"""
Evidence artifact storage for large audit payloads.
"""

import hashlib
import json
from datetime import datetime, timezone


class EvidenceStore:
    """Stores large audit artifacts in object store (S3/MinIO)."""

    def __init__(self, s3_client, bucket: str = "aluskort-audit-evidence"):
        self.s3 = s3_client
        self.bucket = bucket

    def store_evidence(
        self,
        tenant_id: str,
        audit_id: str,
        evidence_type: str,      # "llm_prompt", "llm_response", "retrieval_context", "raw_alert"
        content: str | dict,
    ) -> tuple[str, str]:
        """
        Store evidence artifact. Returns (content_hash, s3_uri).
        """
        if isinstance(content, dict):
            content = json.dumps(content, sort_keys=True)

        content_bytes = content.encode("utf-8")
        content_hash = hashlib.sha256(content_bytes).hexdigest()

        # Path: tenant/YYYY/MM/DD/audit_id/evidence_type.json
        now = datetime.now(timezone.utc)
        key = (
            f"{tenant_id}/{now.strftime('%Y/%m/%d')}/"
            f"{audit_id}/{evidence_type}.json"
        )

        self.s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=content_bytes,
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
            Metadata={
                "audit_id": audit_id,
                "tenant_id": tenant_id,
                "evidence_type": evidence_type,
                "content_hash": content_hash,
            },
        )

        return content_hash, f"s3://{self.bucket}/{key}"
```

---

## 6. Retention Tiers & Lifecycle

### 6.1 Three-Tier Retention

| Tier | Storage | Retention | Query Latency | Use Case |
|---|---|---|---|---|
| **Hot** | Kafka `audit.events` topic | 30 days | < 100ms (consumer offset) | Real-time streaming, recent investigations |
| **Warm** | Postgres `audit_records` table (partitioned by month) | 12 months | < 50ms (indexed queries) | Operational queries, dashboard, evidence packages |
| **Cold** | S3 / MinIO (Parquet export) | 7 years | Minutes (S3 Select or download) | Regulatory compliance, legal hold, long-term audit |

### 6.2 Lifecycle Automation

```python
RETENTION_POLICY = {
    "hot": {
        "store": "kafka",
        "topic": "audit.events",
        "retention_days": 30,
        "enforcement": "Kafka topic config (retention.ms)",
    },
    "warm": {
        "store": "postgres",
        "table": "audit_records",
        "retention_months": 12,
        "enforcement": "Monthly partition drop via pg_cron",
        "partition_scheme": "RANGE (timestamp) — one partition per month",
    },
    "cold": {
        "store": "s3",
        "bucket": "aluskort-audit-archive",
        "retention_years": 7,
        "format": "Parquet (columnar, compressed)",
        "enforcement": "S3 lifecycle policy (transition to Glacier after 1 year)",
        "export_schedule": "Monthly — export previous month's partition to Parquet before drop",
    },
}
```

### 6.3 Warm-to-Cold Export

```sql
-- Monthly export job (runs on 1st of each month at 02:00 UTC)
-- Exports the partition from 2 months ago to Parquet via pg_dump or COPY

-- Step 1: Verify chain integrity for the partition being archived
-- Step 2: Export to Parquet (via external tool or Postgres COPY + conversion)
-- Step 3: Upload to S3 with server-side encryption
-- Step 4: Verify S3 object hash matches Postgres export hash
-- Step 5: Drop the Postgres partition

-- The partition from 1 month ago is NEVER dropped (always keep at least 1 month buffer)
```

### 6.4 Legal Hold

When a legal hold is placed on a tenant (e.g., litigation, regulatory investigation):
1. Mark tenant in Postgres: `UPDATE tenants SET legal_hold = TRUE WHERE tenant_id = $1`
2. Suspend all retention lifecycle operations for that tenant
3. Cold storage objects for that tenant are moved from lifecycle-managed to hold bucket
4. Hold remains until explicitly released by authorized personnel
5. Legal hold activation/deactivation is itself an audit event (`config.changed`)

---

## 7. Evidence Reconstruction

### 7.1 Evidence Package

Given any `investigation_id`, the Audit Service can produce a complete, self-contained
evidence package that explains everything that happened and why.

```python
@dataclass
class EvidencePackage:
    """
    Complete audit evidence for a single investigation.
    Self-contained: an auditor can review this without access
    to any other system.
    """

    # --- Header ---
    package_id: str                  # UUIDv7
    investigation_id: str
    tenant_id: str
    generated_at: str                # ISO 8601 UTC
    generated_by: str                # "aluskort-audit-service v1.0"

    # --- Input ---
    source_alert: dict               # Full CanonicalAlert that started the investigation
    raw_alert_payload: dict          # Original SIEM alert (before canonicalization)

    # --- Timeline ---
    events: list[AuditRecord]        # All audit records for this investigation, ordered by timestamp
    state_transitions: list[dict]    # [{from_state, to_state, timestamp, agent, reason}]

    # --- Context Used ---
    retrieval_context: list[dict]    # All retrieved documents/IOCs/incidents used
    llm_interactions: list[dict]     # All LLM calls: {prompt_hash, response_hash, model, cost, evidence_ref}

    # --- Decision ---
    final_classification: str
    final_confidence: float
    final_severity: str
    reasoning_chain: list[str]       # Human-readable decision chain
    techniques_mapped: list[str]     # ATT&CK + ATLAS technique IDs (validated)
    techniques_quarantined: list[str] # IDs that failed validation

    # --- Actions ---
    actions_recommended: list[str]
    actions_executed: list[dict]     # [{action, target, timestamp, approved_by}]
    actions_pending: list[dict]      # [{action, target, requested_at, timeout_at}]

    # --- Human Interactions ---
    approvals: list[dict]            # [{requested_at, responded_at, responder, decision, comment}]
    analyst_feedback: list[dict]     # [{timestamp, analyst, correct, rating, comment}]

    # --- Integrity ---
    chain_verified: bool             # Was the hash chain verified for all records in this package?
    chain_verification_errors: list[str]
    package_hash: str                # SHA-256 of the entire package
```

### 7.2 Reconstruction API

```
GET /v1/audit/evidence-package/{investigation_id}

Response: EvidencePackage JSON

Query parameters:
  - include_raw_prompts=true   (default false — includes full LLM prompts from S3)
  - include_raw_responses=true (default false — includes full LLM responses from S3)
  - format=json|pdf            (default json — PDF adds formatted human-readable report)
```

### 7.3 Reconstruction Guarantee

**Claim:** For any investigation completed within the warm retention window (12 months),
the Audit Service can produce a complete evidence package within 60 seconds.

**For investigations older than 12 months:** Evidence packages can still be produced
from cold storage, but with higher latency (minutes) and potentially without
full LLM prompt/response content if those artifacts have been lifecycle-managed.

---

## 8. Export & Reporting

### 8.1 Standard Reports

| Report | Frequency | Audience | Content |
|---|---|---|---|
| **Daily Operations Summary** | Daily 06:00 UTC | SOC Manager | Auto-close count, escalation count, missed TPs (if any), cost, degradation events |
| **Weekly Audit Sample** | Weekly Monday 08:00 UTC | SOC Lead | Stratified sample of auto-closed alerts for analyst review (per REM-H02) |
| **Monthly Compliance Report** | Monthly 1st | CISO / Auditor | Chain integrity status, retention compliance, total decisions, approval stats, FP pattern changes |
| **Incident Evidence Package** | On demand | Analyst / Auditor | Full evidence package for specific investigation (Section 7) |
| **Configuration Change Log** | On demand | Auditor | All `config.changed` events with before/after values |

### 8.2 Export Formats

| Format | Use Case | Content |
|---|---|---|
| **JSON** | Machine consumption, API response | Full structured data |
| **Parquet** | Cold archive, bulk analysis | Columnar, compressed, S3-native |
| **CSV** | Analyst spreadsheet review | Flattened records, one row per event |
| **PDF** | Human-readable audit report | Formatted with headers, tables, decision chain narrative |

### 8.3 Audit Query API

```
# List audit events with filtering
GET /v1/audit/events?tenant_id={tid}&event_type={type}&from={iso}&to={iso}&limit=100

# Get single audit record
GET /v1/audit/events/{audit_id}

# Verify chain integrity for a time range
GET /v1/audit/verify?tenant_id={tid}&from={iso}&to={iso}

# Generate evidence package for an investigation
GET /v1/audit/evidence-package/{investigation_id}

# Generate compliance report for a period
GET /v1/audit/reports/compliance?tenant_id={tid}&month={YYYY-MM}

# Export audit records in bulk
POST /v1/audit/export
Body: {tenant_id, from, to, format: "json|csv|parquet"}
```

All audit API endpoints require the `audit_reader` role. Write access to the
audit store is restricted to the Audit Service process only.

---

## 9. Integration Points

### 9.1 Service Integration

Every ALUSKORT service integrates with the audit trail via the `AuditProducer` class.
Here is where each service emits audit events:

| Service | Events Emitted | Integration Point |
|---|---|---|
| **Entity Parser** | `alert.classified`, `injection.detected` | After entity extraction, before publishing to `alerts.normalized` |
| **Orchestrator** | `investigation.state_changed`, `investigation.enriched`, `alert.auto_closed`, `alert.escalated`, `alert.short_circuited` | At every graph edge transition |
| **Context Gateway** | `routing.tier_selected`, all LLM context events | Before and after every LLM call |
| **LLM Router** | `routing.tier_selected`, `routing.provider_failover`, `spend.soft_limit`, `spend.hard_limit` | On every routing decision |
| **Response Agent** | `response.prepared`, `approval.requested`, `response.executed` | Before and after response actions |
| **CTEM Normaliser** | `ctem.exposure_scored`, `ctem.remediation_assigned` | After scoring and upsert |
| **ATLAS Detection** | `atlas.detection_fired` | When a detection rule triggers |
| **Batch Scheduler** | `playbook.generated`, `fp_pattern.created` | After batch results processed |
| **Approval Handler** | `approval.granted`, `approval.denied`, `approval.timed_out`, `approval.escalated` | On every approval state change |
| **Admin API** | `config.changed`, `kill_switch.activated`, `kill_switch.deactivated`, `fp_pattern.approved`, `fp_pattern.revoked` | On every admin action |

### 9.2 Context Gateway Audit Integration

The Context Gateway is the richest audit event source because it handles all LLM
interactions. For every LLM call:

```python
# Before LLM call:
prompt_hash, prompt_ref = evidence_store.store_evidence(
    tenant_id, audit_id, "llm_prompt",
    {"system": system_prompt, "user": sanitised_content}
)

# After LLM call:
response_hash, response_ref = evidence_store.store_evidence(
    tenant_id, audit_id, "llm_response",
    {"content": raw_response, "model": model_id, "tokens": token_count}
)

# Emit audit event with hashes and references
audit_producer.emit(
    tenant_id=tenant_id,
    event_type="routing.tier_selected",
    event_category="decision",
    severity="info",
    actor_type="agent",
    actor_id=agent_id,
    investigation_id=investigation_id,
    context={
        "llm_provider": "anthropic",
        "llm_model_id": model_id,
        "llm_system_prompt_hash": prompt_hash,
        "llm_raw_response_hash": response_hash,
        "llm_input_tokens": input_tokens,
        "llm_output_tokens": output_tokens,
        "llm_cost_usd": cost,
        "llm_latency_ms": latency,
        "llm_prompt_template_id": template_id,
        "llm_prompt_template_version": template_version,
    },
    decision={
        "decision_type": "classify",
        "classification": classification,
        "confidence": confidence,
        "reasoning_summary": summary,
    },
    outcome={
        "outcome_status": "success",
        "evidence_refs": [prompt_ref, response_ref],
    },
)
```

### 9.3 Existing audit.events Migration

The current `audit.events` Kafka topic (defined in `ai-system-design.md` Section 6.1)
is preserved as the transport layer. The Audit Service is a **new consumer** on this
topic that enriches, chains, and persists events. Existing producers continue to work
unchanged. The only addition is that producers should include the fields defined in
Section 2 when emitting events.

---

## 10. Database Schema

### 10.1 Postgres: Audit Records

```sql
-- ============================================================
-- Audit Records — Append-Only, Hash-Chained
-- Partitioned by month for retention lifecycle management.
-- ============================================================

CREATE TABLE audit_records (
    -- Identity
    audit_id            TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    sequence_number     BIGINT NOT NULL,
    previous_hash       TEXT NOT NULL,

    -- Temporal
    timestamp           TIMESTAMPTZ NOT NULL,
    ingested_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Classification
    event_type          TEXT NOT NULL,
    event_category      TEXT NOT NULL,
    severity            TEXT NOT NULL DEFAULT 'info',

    -- Actor
    actor_type          TEXT NOT NULL,
    actor_id            TEXT NOT NULL,
    actor_permissions   TEXT[] DEFAULT '{}',

    -- Subject
    investigation_id    TEXT DEFAULT '',
    alert_id            TEXT DEFAULT '',
    entity_ids          TEXT[] DEFAULT '{}',

    -- Decision context, decision, outcome stored as JSONB
    -- (flexible schema within a versioned envelope)
    context             JSONB NOT NULL DEFAULT '{}',
    decision            JSONB NOT NULL DEFAULT '{}',
    outcome             JSONB NOT NULL DEFAULT '{}',

    -- Integrity
    record_hash         TEXT NOT NULL,
    record_version      TEXT NOT NULL DEFAULT '1.0',

    -- Composite primary key: tenant + sequence ensures uniqueness and ordering
    PRIMARY KEY (tenant_id, sequence_number, timestamp)
) PARTITION BY RANGE (timestamp);

-- Create monthly partitions (automated via pg_cron or migration script)
-- CREATE TABLE audit_records_2026_02 PARTITION OF audit_records
--     FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

-- Indexes
CREATE INDEX idx_audit_tenant_ts ON audit_records (tenant_id, timestamp DESC);
CREATE INDEX idx_audit_investigation ON audit_records (investigation_id, timestamp)
    WHERE investigation_id != '';
CREATE INDEX idx_audit_alert ON audit_records (alert_id, timestamp)
    WHERE alert_id != '';
CREATE INDEX idx_audit_event_type ON audit_records (event_type, timestamp);
CREATE INDEX idx_audit_category ON audit_records (event_category, timestamp);
CREATE INDEX idx_audit_actor ON audit_records (actor_id, timestamp);
CREATE INDEX idx_audit_severity ON audit_records (severity, timestamp)
    WHERE severity IN ('warning', 'critical');

-- Immutability enforcement (Section 4.4)
CREATE TRIGGER enforce_audit_immutability
    BEFORE UPDATE OR DELETE ON audit_records
    FOR EACH ROW
    EXECUTE FUNCTION audit_immutable_guard();

-- Sequence number uniqueness per tenant (gap-free)
CREATE UNIQUE INDEX idx_audit_tenant_seq ON audit_records (tenant_id, sequence_number);
```

### 10.2 Postgres: Chain State

```sql
-- ============================================================
-- Audit Chain State
-- Tracks the latest sequence number and hash per tenant.
-- Used by the Audit Service to assign sequence numbers
-- and link new records into the chain.
-- ============================================================

CREATE TABLE audit_chain_state (
    tenant_id           TEXT PRIMARY KEY,
    last_sequence       BIGINT NOT NULL DEFAULT 0,
    last_hash           TEXT NOT NULL DEFAULT REPEAT('0', 64),
    last_timestamp      TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 10.3 Postgres: Audit Verification Log

```sql
-- ============================================================
-- Audit Verification Log
-- Records the results of periodic integrity checks.
-- ============================================================

CREATE TABLE audit_verification_log (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    verified_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verification_type   TEXT NOT NULL,    -- "continuous", "daily_full", "cold_spot_check"
    records_checked     BIGINT NOT NULL,
    from_sequence       BIGINT NOT NULL,
    to_sequence         BIGINT NOT NULL,
    chain_valid         BOOLEAN NOT NULL,
    errors              JSONB DEFAULT '[]',
    duration_ms         INTEGER NOT NULL
);

CREATE INDEX idx_verify_tenant ON audit_verification_log (tenant_id, verified_at DESC);
```

---

## 11. Compliance Mapping

### 11.1 SOC 2 Trust Services Criteria

| Criteria | How Audit Trail Satisfies It |
|---|---|
| **CC6.1** — Logical access controls | `actor_permissions` recorded per event; `ROLE_PERMISSIONS` enforced |
| **CC6.8** — Prevention of unauthorized changes | Append-only table with immutability trigger; hash chain tamper evidence |
| **CC7.1** — Detection of unauthorized activity | `injection.detected`, `accumulation.threshold_breached`, `technique.quarantined` events |
| **CC7.2** — Monitoring of system components | Full event taxonomy covers all decision-making components |
| **CC7.3** — Evaluation of security events | Evidence packages provide complete decision context for evaluation |
| **CC8.1** — Change management | `config.changed`, `kill_switch.*`, `fp_pattern.*` events with before/after |

### 11.2 ISO 27001 Controls

| Control | How Audit Trail Satisfies It |
|---|---|
| **A.8.15** — Logging | Complete event taxonomy; all autonomous decisions logged |
| **A.8.16** — Monitoring activities | Continuous chain verification; degradation detection |
| **A.8.17** — Clock synchronization | UTC timestamps with nanosecond precision; `ingested_at` for drift detection |
| **A.5.33** — Protection of records | Append-only with hash chain; 3-tier retention with lifecycle |
| **A.5.28** — Collection of evidence | Evidence packages with full provenance; S3 evidence store |

### 11.3 NIST 800-53 Controls

| Control | How Audit Trail Satisfies It |
|---|---|
| **AU-2** — Audit events | Event taxonomy defines auditable events |
| **AU-3** — Content of audit records | AuditRecord schema with actor, subject, context, decision, outcome |
| **AU-6** — Audit review, analysis, and reporting | Weekly/monthly reports; evidence package API |
| **AU-9** — Protection of audit information | Immutability trigger; separate access controls; hash chain |
| **AU-10** — Non-repudiation | Hash chain with per-record integrity; human approvals with identity |
| **AU-11** — Audit record retention | 3-tier lifecycle: 30d hot, 12m warm, 7y cold |

### 11.4 AI Governance

| Concern | How Audit Trail Satisfies It |
|---|---|
| **Explainability** | Evidence packages include reasoning chain, retrieval context, LLM prompts |
| **Reproducibility** | Prompt template versions + model versions + retrieval sources = reproducible decision |
| **Accountability** | Every autonomous action has an `actor_id`; human approvals tracked with identity |
| **Bias/drift monitoring** | `analyst_feedback_*` fields enable systematic quality tracking over time |
| **Model governance** | `llm_model_id`, `llm_prompt_template_version` tracked per decision |

---

## 12. Operational Runbook

### 12.1 Audit Chain Break

**Alert:** `AluskortAuditChainBroken`

**Symptoms:** Gap in sequence numbers or hash mismatch detected.

**Steps:**
1. Identify the break point:
   ```sql
   SELECT tenant_id, sequence_number, record_hash, previous_hash
   FROM audit_records
   WHERE tenant_id = $1
   ORDER BY sequence_number DESC
   LIMIT 20;
   ```
2. Check Audit Service logs for errors during the gap period
3. Check Kafka `audit.events` consumer lag — were events lost?
4. If events exist in Kafka but not Postgres: replay from offset
5. If events are missing from Kafka: this is a data loss event — escalate
6. After repair: re-run `verify_chain()` to confirm integrity restored
7. Document the incident in `audit_verification_log`

**Severity:** CRITICAL — an audit chain break undermines the entire integrity claim.

### 12.2 Audit Lag

**Alert:** `AluskortAuditLagHigh`

**Symptoms:** Kafka consumer lag > 1,000 on `audit.events`.

**Steps:**
1. Check Audit Service pod health
2. Check Postgres write latency (is the DB slow?)
3. If Audit Service is healthy but slow: check for long-running transactions
4. If Audit Service is down: Kafka retains events; restart service
5. After recovery: verify no sequence gaps

### 12.3 Cold Archive Failure

**Alert:** `AluskortAuditColdExportFailed`

**Steps:**
1. Check S3/MinIO connectivity
2. Verify the monthly export job logs
3. Do NOT drop the Postgres partition until export is confirmed
4. Re-run export manually if needed
5. Verify uploaded object hash matches source data hash

---

## 13. Validation Tests

### 13.1 Unit Tests

| ID | Test | Expected | Validates |
|---|---|---|---|
| TC-AUD-001 | Compute hash of AuditRecord | Deterministic SHA-256 for same input | Hash computation |
| TC-AUD-002 | Verify valid chain (10 records) | `verify_chain()` returns `(True, [])` | Chain verification |
| TC-AUD-003 | Detect tampered record in chain | `verify_chain()` returns `(False, [error])` | Tamper detection |
| TC-AUD-004 | Detect sequence gap in chain | `verify_chain()` returns `(False, [gap error])` | Gap detection |
| TC-AUD-005 | Genesis record has correct previous_hash | `previous_hash == "0" * 64` | Genesis initialization |
| TC-AUD-006 | Immutability trigger blocks UPDATE | `UPDATE audit_records SET ...` raises exception | Append-only enforcement |
| TC-AUD-007 | Immutability trigger blocks DELETE | `DELETE FROM audit_records WHERE ...` raises exception | Append-only enforcement |

### 13.2 Integration Tests

| ID | Test | Expected | Validates |
|---|---|---|---|
| TC-AUD-010 | Emit event via AuditProducer, verify in Postgres | Record appears in `audit_records` with valid hash and chain link | End-to-end pipeline |
| TC-AUD-011 | Emit 100 events rapidly, verify chain integrity | All 100 records chained correctly, no gaps | Throughput + ordering |
| TC-AUD-012 | Two tenants emit concurrently | Each tenant has independent chain, no cross-contamination | Tenant isolation |
| TC-AUD-013 | Evidence artifact stored in S3 | `store_evidence()` returns valid hash and URI; artifact retrievable | Evidence storage |
| TC-AUD-014 | Generate evidence package for investigation | Package contains all events, state transitions, LLM interactions | Reconstruction |

### 13.3 Security Tests

| ID | Test | Expected | Validates |
|---|---|---|---|
| TC-AUD-020 | Attempt direct Postgres INSERT to audit_records | Blocked (only Audit Service has write permission) | Access control |
| TC-AUD-021 | Attempt to read Tenant B's audit from Tenant A's API key | 403 Forbidden | Tenant isolation |
| TC-AUD-022 | Verify S3 evidence objects are encrypted | SSE-KMS headers present on all objects | Encryption at rest |

### 13.4 Compliance Tests

| ID | Test | Expected | Validates |
|---|---|---|---|
| TC-AUD-030 | Auto-close decision produces complete audit record | Record contains: context (LLM model, prompt hash, retrieval sources, confidence basis), decision, outcome | Explainability |
| TC-AUD-031 | Approval workflow produces audit trail | `approval.requested` + `approval.granted` records with timestamps and analyst identity | Accountability |
| TC-AUD-032 | FP pattern approval produces 2-person audit trail | Two distinct `fp_pattern.approved` events from different actors | Segregation of duties |
| TC-AUD-033 | Config change produces before/after audit | `config.changed` event with `state_before` and `state_after` | Change management |
| TC-AUD-034 | 12-month-old investigation is reconstructable | Evidence package generated from warm storage within 60 seconds | Retention compliance |
| TC-AUD-035 | Cold storage spot check passes | Random sample of cold records matches original hashes | Archive integrity |

---

## 14. Microservice Addition

### 14.1 Service Registry Update

Add to the service registry in `architecture.md` Section 3.1:

| Service | Purpose | Port | Replicas | Dependencies |
|---|---|---|---|---|
| `audit_service` | Consume audit events, chain, persist, verify | 8040 | 1 | Kafka, Postgres, S3/MinIO |

### 14.2 Build Sequence Update

Insert after Step 2 (Kafka topic provisioning) and before Step 3 (Entity Parser):

> **Step 2.5: Audit Service**
>
> **Dependencies:** Steps 1-2 (schemas, Kafka).
> **Effort:** 3-4 days.
> **What to build:**
> - `services/audit_service/service.py` — Kafka consumer, chain manager, Postgres writer
> - `services/audit_service/chain.py` — `compute_record_hash()`, `verify_chain()`
> - `services/audit_service/evidence.py` — S3 evidence store
> - `services/audit_service/api.py` — FastAPI: `/v1/audit/events`, `/v1/audit/evidence-package`, `/v1/audit/verify`
> - `shared/audit/producer.py` — `AuditProducer` class used by all other services
> - Postgres migration: `audit_records`, `audit_chain_state`, `audit_verification_log` tables
> - Immutability trigger
> - Genesis record creation per tenant
>
> **Definition of done:** Events emitted by a test producer appear in Postgres
> with valid hash chain. `verify_chain()` passes. Evidence package API returns
> complete package for a test investigation. Immutability trigger blocks UPDATE/DELETE.

### 14.3 Docker Compose Addition

```yaml
  audit-service:
    build: ./services/audit_service
    environment:
      KAFKA_BOOTSTRAP_SERVERS: kafka:9092
      POSTGRES_DSN: postgresql://aluskort:localdev@postgres:5432/aluskort
      S3_ENDPOINT: http://minio:9000
      S3_ACCESS_KEY: minioadmin
      S3_SECRET_KEY: minioadmin
      S3_AUDIT_BUCKET: aluskort-audit-evidence
    ports:
      - "8040:8040"
    depends_on: [kafka, postgres, minio]
```

### 14.4 Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: audit-service
  namespace: aluskort
spec:
  replicas: 1  # Single writer for chain ordering
  selector:
    matchLabels:
      app: audit-service
  template:
    metadata:
      labels:
        app: audit-service
    spec:
      containers:
      - name: audit-service
        image: aluskort/audit-service:latest
        ports:
        - containerPort: 8040
        resources:
          requests:
            cpu: "250m"
            memory: "256Mi"
          limits:
            cpu: "500m"
            memory: "512Mi"
        env:
        - name: KAFKA_BOOTSTRAP_SERVERS
          valueFrom:
            configMapKeyRef:
              name: aluskort-config
              key: kafka_bootstrap
        - name: POSTGRES_DSN
          valueFrom:
            secretKeyRef:
              name: aluskort-db
              key: dsn
        - name: S3_AUDIT_BUCKET
          value: "aluskort-audit-evidence"
        livenessProbe:
          httpGet:
            path: /health
            port: 8040
          initialDelaySeconds: 10
          periodSeconds: 15
        readinessProbe:
          httpGet:
            path: /ready
            port: 8040
          initialDelaySeconds: 5
          periodSeconds: 10
```

---

## 15. Document References

| Document | Relationship |
|---|---|
| `docs/ai-system-design.md` Section 6.1 | `audit.events` Kafka topic (transport layer — preserved) |
| `docs/ai-system-design.md` Section 4.1 | `GraphState.decision_chain` (operational state — audit trail is the authoritative record) |
| `docs/rag-design.md` Section 5.5 | FP pattern approval tracking (now covered by `fp_pattern.*` audit events) |
| `docs/ctem-integration.md` Section 2.1 | CTEM remediation lifecycle (now covered by `ctem.*` audit events) |
| `docs/remediation-backlog.md` | REM-C01 (technique validation), REM-H02 (FP governance), REM-H05 (shadow mode) all emit audit events |
| `docs/inference-optimization.md` | LLM cost tracking (now part of `AuditContext.llm_cost_usd`) |
| `docs/runbook.md` | Add Section 12 runbook items to operational runbook |

---

*Document generated by Omeriko (CR + Audit Architecture) for ALUSKORT project.*
