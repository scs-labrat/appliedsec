# Audit Trail Technical Specification

**Document ID:** ALUSKORT-ISMS-13
**Version:** 1.0
**Classification:** Confidential
**Owner:** Security Architect
**Approved by:** CISO, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Annex A.8.15 (Logging), A.8.17 (Clock Synchronisation), A.5.33 (Protection of Records)

---

## 1. Purpose

This document provides the complete technical specification for the ALUSKORT SOC Platform's immutable hash-chain audit trail. The audit trail is a foundational security control that provides cryptographic proof of integrity for all platform actions, supporting accountability, compliance, forensic investigation, and tamper detection.

---

## 2. Design Principles

| Principle | Implementation |
|---|---|
| **Immutability** | Append-only design; no update or delete operations; hash-chain provides tamper evidence |
| **Completeness** | Every security-relevant action recorded; no blind spots in platform operations |
| **Integrity** | SHA-256 hash chain links every record; any modification detectable |
| **Per-tenant isolation** | Separate hash chain per tenant; independent genesis blocks; no cross-tenant chain dependencies |
| **Non-repudiation** | Actor identity cryptographically bound to actions via authenticated session and hash chain |
| **Availability** | Write-ahead to Kafka for durability; PostgreSQL for persistence; backup for recovery |
| **Performance** | Asynchronous audit writing via Kafka; < 5ms overhead per audited action |
| **Verifiability** | Full chain verification available on-demand; automated daily verification |

---

## 3. Hash-Chain Design

### 3.1 Chain Structure

```
Genesis Block (Tenant A)           Record 1                   Record 2
┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│ hash[0] = SHA-256(   │    │ hash[1] = SHA-256(   │    │ hash[2] = SHA-256(   │
│   "GENESIS" ||       │    │   hash[0] ||         │    │   hash[1] ||         │
│   tenant_id ||       │    │   tenant_id ||       │    │   tenant_id ||       │
│   creation_ts ||     │    │   event_type ||      │    │   event_type ||      │
│   "ALUSKORT-SOC-     │    │   timestamp ||       │    │   timestamp ||       │
│    AUDIT-CHAIN-v1"   │    │   actor_id ||        │    │   actor_id ||        │
│ )                    │    │   action ||          │    │   action ||          │
│                      │    │   resource ||        │    │   resource ||        │
│ prev_hash: null      │    │   payload_hash       │    │   payload_hash       │
│ sequence: 0          │    │ )                    │    │ )                    │
└──────────┬───────────┘    │                      │    │                      │
           │                │ prev_hash: hash[0]   │    │ prev_hash: hash[1]   │
           └───────────────►│ sequence: 1          │    │ sequence: 2          │
                            └──────────┬───────────┘    └──────────────────────┘
                                       │                          ▲
                                       └──────────────────────────┘
```

### 3.2 Genesis Block

Each tenant's hash chain begins with a genesis block created during tenant onboarding:

```json
{
  "record_id": "uuid-v4",
  "tenant_id": "tenant-uuid",
  "sequence_number": 0,
  "event_type": "CHAIN_GENESIS",
  "timestamp": "2026-03-29T00:00:00.000Z",
  "actor_id": "system",
  "actor_role": "system",
  "action": "CREATE_CHAIN",
  "resource_type": "audit_chain",
  "resource_id": "tenant-uuid",
  "payload": {
    "chain_version": "1",
    "hash_algorithm": "SHA-256",
    "tenant_name": "Example Tenant",
    "tenant_tier": "premium"
  },
  "payload_hash": "SHA-256(canonical_json(payload))",
  "previous_hash": null,
  "record_hash": "SHA-256('GENESIS' || tenant_id || timestamp || 'ALUSKORT-SOC-AUDIT-CHAIN-v1')",
  "metadata": {
    "source_service": "audit-service",
    "chain_version": "1"
  }
}
```

### 3.3 Hash Computation Algorithm

```python
import hashlib
import json

def compute_record_hash(record: dict, previous_hash: str) -> str:
    """
    Compute the SHA-256 hash for an audit record.

    The hash links to the previous record (chain integrity)
    and covers all security-relevant fields (record integrity).
    """
    hash_input = (
        (previous_hash or "GENESIS") +
        record["tenant_id"] +
        record["event_type"] +
        record["timestamp"] +
        record["actor_id"] +
        record["action"] +
        record["resource_type"] +
        record["resource_id"] +
        record["payload_hash"]
    )

    return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

def compute_payload_hash(payload: dict) -> str:
    """
    Compute SHA-256 hash of the payload using canonical JSON
    serialisation (sorted keys, no whitespace).
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def compute_genesis_hash(tenant_id: str, timestamp: str) -> str:
    """
    Compute the genesis block hash for a new tenant chain.
    """
    hash_input = (
        "GENESIS" +
        tenant_id +
        timestamp +
        "ALUSKORT-SOC-AUDIT-CHAIN-v1"
    )
    return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
```

---

## 4. Audit Record Schema

### 4.1 Record Fields (20 Fields)

| # | Field | Type | Required | Description |
|---|---|---|---|---|
| 1 | `record_id` | UUID v4 | Yes | Globally unique identifier for this audit record |
| 2 | `tenant_id` | UUID | Yes | Tenant that this record belongs to |
| 3 | `sequence_number` | BIGINT | Yes | Monotonically increasing sequence within tenant chain |
| 4 | `event_type` | ENUM | Yes | Category of audited event (see §4.2) |
| 5 | `timestamp` | TIMESTAMPTZ | Yes | UTC timestamp of the event (ISO 8601, microsecond precision) |
| 6 | `actor_id` | UUID / STRING | Yes | Identifier of the user or service that performed the action |
| 7 | `actor_role` | ENUM | Yes | Role of the actor at time of action (`analyst`, `senior_analyst`, `admin`, `system`, `agent:{id}`) |
| 8 | `action` | STRING | Yes | Specific action performed (e.g., `APPROVE_RECOMMENDATION`, `ACTIVATE_KILL_SWITCH`) |
| 9 | `resource_type` | STRING | Yes | Type of resource acted upon (e.g., `alert`, `investigation`, `fp_pattern`, `system_config`) |
| 10 | `resource_id` | STRING | Yes | Identifier of the specific resource |
| 11 | `payload` | JSONB | Yes | Structured event details (content varies by event type) |
| 12 | `payload_hash` | CHAR(64) | Yes | SHA-256 hash of canonical JSON payload |
| 13 | `previous_hash` | CHAR(64) | Conditional | SHA-256 hash of previous record in chain (null for genesis only) |
| 14 | `record_hash` | CHAR(64) | Yes | SHA-256 hash of this record (chain link) |
| 15 | `source_ip` | INET | No | IP address of the actor (if applicable) |
| 16 | `user_agent` | STRING | No | User agent string (browser / API client) |
| 17 | `correlation_id` | UUID | No | Correlation ID linking related audit records across services |
| 18 | `investigation_id` | UUID | No | Associated investigation (if applicable) |
| 19 | `metadata` | JSONB | No | Additional metadata (service version, deployment ID, etc.) |
| 20 | `verification_status` | ENUM | Yes | `VERIFIED`, `PENDING`, `FAILED` -- result of hash verification on insert |

### 4.2 Event Types

| Event Type | Description | Actor Type |
|---|---|---|
| `CHAIN_GENESIS` | New tenant chain created | System |
| `AUTH_LOGIN` | User authentication event | User |
| `AUTH_LOGOUT` | User logout | User |
| `AUTH_FAILED` | Failed authentication attempt | System |
| `ALERT_INGESTED` | New alert ingested from SIEM | System |
| `ALERT_TRIAGED` | Alert triaged by AI agent | Agent |
| `ALERT_UPDATED` | Alert status or metadata updated | User/Agent |
| `INVESTIGATION_STARTED` | New investigation initiated | Agent/User |
| `INVESTIGATION_STEP` | Investigation step completed by agent | Agent |
| `INVESTIGATION_COMPLETED` | Investigation concluded | Agent |
| `RECOMMENDATION_GENERATED` | AI recommendation produced | Agent |
| `RECOMMENDATION_APPROVED` | Human approved AI recommendation | User |
| `RECOMMENDATION_REJECTED` | Human rejected AI recommendation | User |
| `RESPONSE_EXECUTED` | Response action executed | System |
| `FP_PATTERN_PROPOSED` | False positive pattern proposed | User |
| `FP_PATTERN_APPROVED` | FP pattern approved (two-person) | User |
| `FP_PATTERN_REJECTED` | FP pattern rejected | User |
| `FP_PATTERN_EXPIRED` | FP pattern expired (90-day) | System |
| `FP_PATTERN_REAFFIRMED` | FP pattern reaffirmed for new 90-day period | User |
| `CASE_CREATED` | New case created | User/Agent |
| `CASE_UPDATED` | Case status or details updated | User |
| `CASE_CLOSED` | Case closed | User |
| `EVIDENCE_EXPORTED` | Evidence package exported | User |
| `CONFIG_CHANGED` | Platform configuration changed | User (admin) |
| `USER_CREATED` | New user account created | User (admin) |
| `USER_UPDATED` | User account modified (role change, etc.) | User (admin) |
| `USER_DISABLED` | User account disabled | User (admin) |
| `TENANT_CREATED` | New tenant onboarded | User (admin) |
| `TENANT_UPDATED` | Tenant configuration changed | User (admin) |
| `KILL_SWITCH_ACTIVATED` | Emergency kill switch activated | User (admin) |
| `KILL_SWITCH_DEACTIVATED` | Kill switch deactivated | User (admin) |
| `INJECTION_DETECTED` | Prompt injection attempt detected | System |
| `PII_REDACTED` | PII detected and redacted | System |
| `OUTPUT_VALIDATION_FAILED` | LLM output failed validation | System |
| `LLM_INFERENCE` | LLM API call made (summary, no PII) | Agent |
| `ATLAS_RULE_TRIGGERED` | MITRE ATLAS detection rule triggered | System |
| `CHAIN_VERIFIED` | Full chain verification completed | System/User |
| `CHAIN_VERIFICATION_FAILED` | Chain verification detected anomaly | System |
| `DATA_PURGED` | Data deleted per retention policy | System |
| `DEANON_ACCESSED` | Deanonymisation map accessed | User |
| `SPEND_GUARD_TRIGGERED` | Tenant quota exhausted | System |

---

## 5. Evidence Block Format

### 5.1 Evidence Package Structure

Evidence packages are exportable bundles that provide cryptographic proof of investigation integrity:

```json
{
  "package_id": "uuid-v4",
  "package_version": "1.0",
  "created_at": "2026-03-29T12:00:00.000Z",
  "created_by": "user-uuid",
  "tenant_id": "tenant-uuid",
  "investigation_id": "investigation-uuid",

  "chain_proof": {
    "first_record_sequence": 1042,
    "last_record_sequence": 1087,
    "first_record_hash": "sha256-hex...",
    "last_record_hash": "sha256-hex...",
    "genesis_hash": "sha256-hex...",
    "chain_length": 46,
    "chain_verified": true,
    "verification_timestamp": "2026-03-29T12:00:01.000Z"
  },

  "audit_records": [
    {
      "record_id": "uuid-v4",
      "sequence_number": 1042,
      "event_type": "INVESTIGATION_STARTED",
      "timestamp": "2026-03-29T10:30:00.000Z",
      "actor_id": "agent-04",
      "actor_role": "agent:investigation",
      "action": "START_INVESTIGATION",
      "resource_type": "investigation",
      "resource_id": "investigation-uuid",
      "payload": { "...": "..." },
      "payload_hash": "sha256-hex...",
      "previous_hash": "sha256-hex...",
      "record_hash": "sha256-hex..."
    }
  ],

  "evidence_items": [
    {
      "item_id": "uuid-v4",
      "type": "alert",
      "content_hash": "sha256-hex...",
      "content": { "...": "..." }
    },
    {
      "item_id": "uuid-v4",
      "type": "investigation_report",
      "content_hash": "sha256-hex...",
      "content": { "...": "..." }
    }
  ],

  "package_hash": "SHA-256(canonical_json(chain_proof + audit_records + evidence_items))"
}
```

### 5.2 Package Integrity

| Verification Step | Check |
|---|---|
| Package hash | Recompute `package_hash` from contents; compare to stored value |
| Chain continuity | Verify each `previous_hash` links to the prior record's `record_hash` |
| Record integrity | Recompute each `record_hash` from fields; compare to stored value |
| Payload integrity | Recompute each `payload_hash` from `payload` content; compare |
| Genesis linkage | Verify the chain traces back to the tenant's genesis block |
| Completeness | Verify no sequence numbers are missing in the chain segment |
| Timestamp ordering | Verify timestamps are monotonically non-decreasing |

---

## 6. Verification Algorithm

### 6.1 Full Chain Verification

```python
def verify_chain(tenant_id: str, records: list[dict]) -> VerificationResult:
    """
    Verify the integrity of a tenant's complete audit trail hash chain.

    Returns VerificationResult with status and any discrepancies found.
    """
    errors = []

    if not records:
        return VerificationResult(status="EMPTY", errors=["No records found"])

    # Sort by sequence number
    records.sort(key=lambda r: r["sequence_number"])

    # Step 1: Verify genesis block
    genesis = records[0]
    if genesis["sequence_number"] != 0:
        errors.append(f"First record sequence is {genesis['sequence_number']}, expected 0")

    if genesis["event_type"] != "CHAIN_GENESIS":
        errors.append(f"First record type is {genesis['event_type']}, expected CHAIN_GENESIS")

    if genesis["previous_hash"] is not None:
        errors.append("Genesis block has non-null previous_hash")

    expected_genesis_hash = compute_genesis_hash(
        genesis["tenant_id"], genesis["timestamp"]
    )
    if genesis["record_hash"] != expected_genesis_hash:
        errors.append(f"Genesis hash mismatch at sequence 0")

    # Step 2: Verify each subsequent record
    for i in range(1, len(records)):
        record = records[i]
        prev_record = records[i - 1]

        # Check sequence continuity
        if record["sequence_number"] != prev_record["sequence_number"] + 1:
            errors.append(
                f"Sequence gap: {prev_record['sequence_number']} -> "
                f"{record['sequence_number']}"
            )

        # Check chain linkage
        if record["previous_hash"] != prev_record["record_hash"]:
            errors.append(
                f"Chain break at sequence {record['sequence_number']}: "
                f"previous_hash does not match prior record_hash"
            )

        # Check payload hash
        expected_payload_hash = compute_payload_hash(record["payload"])
        if record["payload_hash"] != expected_payload_hash:
            errors.append(
                f"Payload hash mismatch at sequence {record['sequence_number']}"
            )

        # Check record hash
        expected_hash = compute_record_hash(record, prev_record["record_hash"])
        if record["record_hash"] != expected_hash:
            errors.append(
                f"Record hash mismatch at sequence {record['sequence_number']}"
            )

        # Check timestamp ordering
        if record["timestamp"] < prev_record["timestamp"]:
            errors.append(
                f"Timestamp regression at sequence {record['sequence_number']}: "
                f"{record['timestamp']} < {prev_record['timestamp']}"
            )

        # Check tenant consistency
        if record["tenant_id"] != tenant_id:
            errors.append(
                f"Tenant ID mismatch at sequence {record['sequence_number']}"
            )

    # Step 3: Return result
    if errors:
        return VerificationResult(
            status="FAILED",
            records_checked=len(records),
            errors=errors,
            first_failure_sequence=_extract_sequence(errors[0])
        )

    return VerificationResult(
        status="VERIFIED",
        records_checked=len(records),
        chain_start=records[0]["record_hash"],
        chain_end=records[-1]["record_hash"],
        errors=[]
    )
```

### 6.2 Incremental Verification

For real-time verification of newly appended records:

```python
def verify_new_record(new_record: dict, latest_record: dict) -> bool:
    """
    Verify a new record against the latest record in the chain.
    Called before every insert to maintain chain integrity.
    """
    # Verify chain linkage
    if new_record["previous_hash"] != latest_record["record_hash"]:
        return False

    # Verify sequence continuity
    if new_record["sequence_number"] != latest_record["sequence_number"] + 1:
        return False

    # Verify payload hash
    expected_payload_hash = compute_payload_hash(new_record["payload"])
    if new_record["payload_hash"] != expected_payload_hash:
        return False

    # Verify record hash
    expected_hash = compute_record_hash(new_record, latest_record["record_hash"])
    if new_record["record_hash"] != expected_hash:
        return False

    # Verify timestamp ordering
    if new_record["timestamp"] < latest_record["timestamp"]:
        return False

    return True
```

---

## 7. Retention Policy

### 7.1 Retention by Tenant Tier

| Tenant Tier | Audit Trail Retention | Evidence Package Retention | Regulatory Minimum |
|---|---|---|---|
| Premium | 365 days | 365 days | 1 year |
| Standard | 365 days | 180 days | 1 year |
| Trial | 90 days | 30 days | 90 days |

### 7.2 Retention Enforcement

| Aspect | Implementation |
|---|---|
| Automated purging | Daily job identifies records beyond retention; purges oldest records first |
| Chain integrity on purge | When oldest records are purged, a new "chain continuation" record is created that references the hash of the last purged record, maintaining verifiability of the remaining chain |
| Purge audit | Purge action itself is recorded as a `DATA_PURGED` event in the audit trail |
| Legal hold | Records under legal hold exempt from automated purging; hold flag checked before purge |
| Backup retention | Backups containing audit data follow the same retention schedule |

### 7.3 Chain Continuation After Purge

```json
{
  "event_type": "CHAIN_CONTINUATION",
  "action": "PURGE_CONTINUATION",
  "payload": {
    "purged_records_count": 1000,
    "purged_from_sequence": 0,
    "purged_to_sequence": 999,
    "last_purged_hash": "sha256-hex-of-last-purged-record",
    "purge_reason": "retention_policy",
    "retention_days": 365
  }
}
```

---

## 8. Tamper Detection

### 8.1 Detection Mechanisms

| Mechanism | Frequency | Detection Capability |
|---|---|---|
| **Insert-time verification** | Every record | Detects chain breaks at write time; prevents insertion of records that break the chain |
| **Daily full verification** | Daily (off-peak hours) | Detects any historical tampering; hash recomputation of full chain |
| **On-demand verification** | Admin-triggered | Same as daily; for incident investigation or audit |
| **Sequence gap detection** | Continuous (on read) | Detects deleted records (missing sequence numbers) |
| **Timestamp regression detection** | Every record | Detects records inserted out of temporal order |
| **Cross-reference verification** | Weekly | Compare audit trail records against application logs for consistency |

### 8.2 Tamper Response

| Detection | Severity | Automatic Action | Manual Action |
|---|---|---|---|
| Hash-chain break | P1 -- Critical | Alert all on-call; create incident record | Immediate investigation; forensic analysis; determine scope of tampering |
| Sequence gap | P1 -- Critical | Alert all on-call; create incident record | Investigate deletion; restore from backup if possible |
| Timestamp regression | P2 -- High | Alert Security Architect | Investigate clock synchronisation; assess record validity |
| Payload hash mismatch | P1 -- Critical | Alert all on-call; create incident record | Investigate record modification; compare with backup |
| Cross-reference discrepancy | P3 -- Medium | Alert Security Architect | Investigate logging gap; assess impact |

### 8.3 Tamper Prevention

| Control | Implementation |
|---|---|
| Append-only table | PostgreSQL table with no UPDATE or DELETE permissions for application service accounts |
| Database triggers | Trigger prevents UPDATE/DELETE on audit records table (defence in depth) |
| Application-level controls | Audit Service code has no update/delete functions |
| Separate service account | Audit Service uses a dedicated database user with INSERT-only privileges on audit table |
| Network isolation | Only Audit Service can write to audit table; enforced by K8s network policy |
| Backup immutability | Audit trail backups stored in write-once storage (MinIO object lock) |

---

## 9. Audit Package Builder

### 9.1 Package Generation Process

```
1. Request      2. Extract        3. Verify         4. Assemble      5. Sign
   (User/API)      Records           Chain             Package          & Store

┌──────────┐   ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  ┌──────────┐
│ User      │   │ Query audit  │  │ Verify hash  │  │ Combine     │  │ Compute  │
│ requests  │──►│ records for  │─►│ chain for    │─►│ records +   │─►│ package  │
│ package   │   │ investigation│  │ extracted    │  │ evidence +  │  │ hash;    │
│ for inv.  │   │ + time range │  │ segment      │  │ chain proof │  │ store in │
│ ID        │   │              │  │              │  │             │  │ MinIO    │
└──────────┘   └──────────────┘  └──────────────┘  └─────────────┘  └──────────┘
```

### 9.2 Package Contents

| Component | Description | Integrity Check |
|---|---|---|
| Chain proof | Genesis hash, first/last sequence, first/last hash, chain length, verification result | Included in package hash |
| Audit records | All audit records related to the investigation (chronological) | Individual record hashes verified; chain integrity verified |
| Evidence items | Alert data, investigation reports, AI decision chains, response actions | Per-item content hash |
| Metadata | Package creation time, creator, tenant, investigation summary | Included in package hash |
| Package hash | SHA-256 of entire package contents (canonical JSON) | Independently verifiable |

### 9.3 Package Access Control

| Control | Implementation |
|---|---|
| Generation | `senior_analyst` or `admin` role required |
| Download | `senior_analyst` or `admin` role required; logged in audit trail |
| Storage | Encrypted in MinIO with per-tenant key; object-lock enabled (WORM) |
| Retention | Same as evidence package retention per tenant tier |
| External sharing | Requires `admin` approval; logged in audit trail |

---

## 10. Clock Synchronisation (A.8.17)

### 10.1 Time Synchronisation Architecture

| Component | NTP Source | Sync Interval | Drift Tolerance |
|---|---|---|---|
| K8s control plane nodes | Cloud provider NTP (e.g., `169.254.169.123` on AWS) | 64 seconds (chrony default) | < 1 ms |
| K8s worker nodes | Cloud provider NTP | 64 seconds | < 1 ms |
| Application services | Inherit node time (container shares host clock) | N/A | < 1 ms |
| Database servers | Cloud provider NTP | 64 seconds | < 1 ms |
| Audit timestamp generation | `datetime.utcnow()` with microsecond precision | Per-event | < 1 ms |

### 10.2 Time Verification

| Control | Implementation |
|---|---|
| NTP monitoring | Prometheus alert on NTP offset > 10 ms |
| Timestamp format | ISO 8601 UTC with microsecond precision: `2026-03-29T12:00:00.123456Z` |
| Timezone policy | All internal timestamps in UTC; timezone conversion only at presentation layer |
| Clock skew detection | Audit trail timestamp regression detection identifies clock issues |
| Leap second handling | Handled by NTP (smearing); no application-level action required |

---

## 11. Database Schema

### 11.1 PostgreSQL Table Definition

```sql
CREATE TABLE audit_records (
    record_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    sequence_number     BIGINT NOT NULL,
    event_type          VARCHAR(64) NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id            VARCHAR(255) NOT NULL,
    actor_role          VARCHAR(64) NOT NULL,
    action              VARCHAR(128) NOT NULL,
    resource_type       VARCHAR(64) NOT NULL,
    resource_id         VARCHAR(255) NOT NULL,
    payload             JSONB NOT NULL DEFAULT '{}',
    payload_hash        CHAR(64) NOT NULL,
    previous_hash       CHAR(64),
    record_hash         CHAR(64) NOT NULL,
    source_ip           INET,
    user_agent          TEXT,
    correlation_id      UUID,
    investigation_id    UUID,
    metadata            JSONB DEFAULT '{}',
    verification_status VARCHAR(16) NOT NULL DEFAULT 'VERIFIED',

    -- Constraints
    CONSTRAINT uq_tenant_sequence UNIQUE (tenant_id, sequence_number),
    CONSTRAINT chk_verification_status CHECK (
        verification_status IN ('VERIFIED', 'PENDING', 'FAILED')
    ),
    CONSTRAINT chk_hash_format CHECK (
        record_hash ~ '^[a-f0-9]{64}$' AND
        payload_hash ~ '^[a-f0-9]{64}$' AND
        (previous_hash IS NULL OR previous_hash ~ '^[a-f0-9]{64}$')
    ),
    CONSTRAINT chk_genesis CHECK (
        (sequence_number = 0 AND previous_hash IS NULL AND event_type = 'CHAIN_GENESIS')
        OR
        (sequence_number > 0 AND previous_hash IS NOT NULL)
    )
);

-- Indexes for efficient querying
CREATE INDEX idx_audit_tenant_sequence ON audit_records (tenant_id, sequence_number);
CREATE INDEX idx_audit_tenant_timestamp ON audit_records (tenant_id, timestamp);
CREATE INDEX idx_audit_event_type ON audit_records (event_type);
CREATE INDEX idx_audit_actor ON audit_records (actor_id);
CREATE INDEX idx_audit_investigation ON audit_records (investigation_id) WHERE investigation_id IS NOT NULL;
CREATE INDEX idx_audit_correlation ON audit_records (correlation_id) WHERE correlation_id IS NOT NULL;

-- Prevent UPDATE and DELETE via trigger (defence in depth)
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit records cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_audit_update
    BEFORE UPDATE ON audit_records
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

CREATE TRIGGER trg_prevent_audit_delete
    BEFORE DELETE ON audit_records
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

-- Row-Level Security for tenant isolation
ALTER TABLE audit_records ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON audit_records
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);
```

### 11.2 Database Permissions

| Role | SELECT | INSERT | UPDATE | DELETE | TRUNCATE |
|---|---|---|---|---|---|
| `audit_service_writer` | Yes | Yes | No | No | No |
| `audit_service_reader` | Yes | No | No | No | No |
| `audit_service_verifier` | Yes | No | No | No | No |
| `app_services` (other services) | No | No | No | No | No |
| `dba_admin` (break-glass) | Yes | Yes | No | No | No |

---

## 12. Performance Considerations

| Aspect | Design Decision | Impact |
|---|---|---|
| Write path | Asynchronous via Kafka `audit.events` topic; Audit Service consumes and writes to PostgreSQL | < 5 ms overhead per audited action; eventual consistency (typically < 100 ms) |
| Read path | Direct PostgreSQL query with tenant isolation | Index-optimised; < 50 ms for recent records |
| Verification | Background process; does not block writes | Full chain verification for 1M records: ~30 seconds |
| Storage | JSONB payload with TOAST compression | ~500 bytes per record average; 1M records ≈ 500 MB |
| Partitioning | Range partitioning by month on `timestamp` (planned) | Efficient purging; improved query performance for time-range queries |
| Archival | Old partitions archived to MinIO before purge | Reduces active table size; maintains long-term verifiability |

---

## 13. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | Security Architect | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed annually or upon changes to the audit trail architecture, hash algorithm, or record schema.*
