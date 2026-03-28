# Business Continuity

**Document ID:** ALUSKORT-ISMS-09
**Version:** 1.0
**Classification:** Confidential
**Owner:** Platform Engineering Lead
**Approved by:** CISO, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Annex A.5.29--5.30

---

## 1. Purpose

This document defines the Business Continuity Plan (BCP) and Disaster Recovery (DR) procedures for the ALUSKORT SOC Platform, ensuring continuity of security operations for tenants during disruptive events.

---

## 2. Business Impact Analysis

### 2.1 Critical Business Processes

| Process | Description | Impact of Disruption | Maximum Tolerable Downtime |
|---|---|---|---|
| Alert ingestion | Receiving security alerts from tenant SIEMs | Security alerts unmonitored; potential threats undetected | 15 minutes |
| AI triage and investigation | Automated analysis and investigation of alerts | Alert backlog grows; manual triage required | 1 hour |
| Human approval workflow | Analyst review and approval of AI recommendations | Automated responses queued but not blocked; can operate manually | 4 hours |
| Automated response execution | Executing approved containment and remediation actions | Approved actions delayed; manual execution possible | 2 hours |
| Audit trail recording | Immutable logging of all platform actions | Compliance gap; investigation integrity compromised | 30 minutes |
| Dashboard and analyst interface | Real-time visibility for SOC analysts | Analysts lose real-time visibility; can use direct API or backlog review | 2 hours |
| Case management | Tracking investigation lifecycle | Operational inconvenience; investigations continue without case tracking | 8 hours |

### 2.2 RPO and RTO Targets

| Component | RPO (Recovery Point Objective) | RTO (Recovery Time Objective) | Justification |
|---|---|---|---|
| **Alert Ingestion Service** | 0 (no data loss) | 5 minutes | Critical path; Kafka buffering provides message durability |
| **Triage Service** | 0 (Kafka replay) | 10 minutes | Stateless; Kafka messages can be replayed |
| **Investigation Service** | < 1 minute (in-flight state) | 15 minutes | Active investigations may need restart; state in PostgreSQL |
| **Context Gateway** | 0 (stateless) | 5 minutes | Stateless service; immediate pod replacement |
| **LLM Router** | 0 (stateless) | 5 minutes | Stateless; includes automatic failover to OpenAI |
| **Response Service** | 0 (Kafka replay) | 10 minutes | Pending actions durable in Kafka |
| **Case Management Service** | < 1 minute | 15 minutes | State in PostgreSQL |
| **Dashboard Service** | 0 (stateless) | 5 minutes | Stateless; WebSocket reconnection automatic |
| **Audit Service** | 0 (no audit data loss) | 10 minutes | Critical for compliance; write-ahead to Kafka |
| **PostgreSQL 16** | < 1 minute (WAL) | 30 minutes | Point-in-time recovery from WAL archive |
| **Redis 7** | < 6 hours (RDB) | 10 minutes | Cache reconstruction acceptable; session re-auth |
| **Qdrant** | < 24 hours | 30 minutes | Vectors can be rebuilt from source data |
| **Neo4j 5** | < 24 hours | 30 minutes | Graph can be rebuilt from source data |
| **Kafka / Redpanda** | 0 (replicated) | 10 minutes | Replicated partitions; automatic leader election |
| **MinIO** | 0 (replicated) | 15 minutes | Cross-site replication |

---

## 3. Continuity Strategy

### 3.1 Architecture for Resilience

```
                    Region A (Primary)              Region B (DR)
                ┌──────────────────────┐    ┌──────────────────────┐
                │  K8s Cluster         │    │  K8s Cluster         │
                │                      │    │  (Standby/Warm)      │
                │  ┌────────────────┐  │    │  ┌────────────────┐  │
                │  │ App Services   │  │    │  │ App Services   │  │
                │  │ (Active)       │  │    │  │ (Scaled down)  │  │
                │  └────────────────┘  │    │  └────────────────┘  │
                │                      │    │                      │
                │  ┌────────────────┐  │    │  ┌────────────────┐  │
                │  │ PostgreSQL     │──────────│ PostgreSQL     │  │
                │  │ (Primary)      │  │Async│  │ (Standby)      │  │
                │  └────────────────┘  │Repl.│  └────────────────┘  │
                │                      │    │                      │
                │  ┌────────────────┐  │    │  ┌────────────────┐  │
                │  │ Kafka          │──────────│ Kafka          │  │
                │  │ (Primary)      │  │Mirror│ │ (Mirror)       │  │
                │  └────────────────┘  │Maker│  └────────────────┘  │
                │                      │    │                      │
                │  ┌────────────────┐  │    │  ┌────────────────┐  │
                │  │ MinIO          │──────────│ MinIO          │  │
                │  │ (Primary)      │  │Cross│  │ (Replica)      │  │
                │  └────────────────┘  │Site │  └────────────────┘  │
                └──────────────────────┘Repl.└──────────────────────┘
```

### 3.2 Resilience Levels

| Level | Strategy | Components | Failover Time |
|---|---|---|---|
| **Level 1: Pod resilience** | Kubernetes auto-restart; HPA scaling | All stateless services | < 2 minutes |
| **Level 2: Node resilience** | Pod rescheduling across nodes; PDB (Pod Disruption Budget) | All services | < 5 minutes |
| **Level 3: AZ resilience** | Multi-AZ deployment; database replicas across AZs | K8s cluster, PostgreSQL, Kafka | < 15 minutes |
| **Level 4: Region resilience** | Warm standby in DR region; async replication | Full platform | < 4 hours |

---

## 4. Disaster Recovery Procedures

### 4.1 Scenario: Single Service Failure

| Step | Action | Actor | Time |
|---|---|---|---|
| 1 | Kubernetes detects pod failure (health check) | K8s (automatic) | 30 seconds |
| 2 | Pod automatically restarted | K8s (automatic) | 30--60 seconds |
| 3 | Readiness check passes; traffic resumed | K8s (automatic) | 30 seconds |
| 4 | Kafka consumer group rebalances; message processing resumes | Kafka (automatic) | < 1 minute |
| **Total** | | | **< 2 minutes** |

### 4.2 Scenario: PostgreSQL Primary Failure

| Step | Action | Actor | Time |
|---|---|---|---|
| 1 | Primary failure detected (health check / replication lag) | Monitoring | 30 seconds |
| 2 | Promote standby to primary (Patroni / cloud managed) | Automatic / DevOps | 1--5 minutes |
| 3 | Update service connection strings (DNS or K8s Service) | Automatic | < 1 minute |
| 4 | Verify data integrity (recent WAL applied) | DevOps Lead | 5 minutes |
| 5 | Establish new standby replica | DevOps Lead | 30 minutes |
| **Total (service restoration)** | | | **< 10 minutes** |

### 4.3 Scenario: Kafka Cluster Failure

| Step | Action | Actor | Time |
|---|---|---|---|
| 1 | Broker failure detected | Monitoring | 30 seconds |
| 2 | Partition leaders rebalanced to surviving brokers | Kafka (automatic) | 1--5 minutes |
| 3 | Producers and consumers reconnect | Services (automatic) | < 1 minute |
| 4 | If total cluster loss: restore from MirrorMaker 2 replica | DevOps Lead | 30--60 minutes |
| **Total (partial)** | | | **< 10 minutes** |
| **Total (full cluster loss)** | | | **< 1 hour** |

### 4.4 Scenario: LLM Provider Outage

| Step | Action | Actor | Time |
|---|---|---|---|
| 1 | Anthropic API errors exceed 5% threshold | LLM Router (automatic) | < 1 minute |
| 2 | LLM Router activates OpenAI fallback | LLM Router (automatic) | Immediate |
| 3 | Alert sent to operations team | Monitoring | < 2 minutes |
| 4 | Verify fallback is functioning (response quality check) | AI Security Lead | 15 minutes |
| 5 | Monitor Anthropic status page for resolution | Operations | Ongoing |
| 6 | Revert to Anthropic when service restored | LLM Router (manual) | 5 minutes |
| **Total (failover)** | | | **< 5 minutes** |

### 4.5 Scenario: Full Region Failure

| Step | Action | Actor | Time |
|---|---|---|---|
| 1 | Region failure detected (monitoring + cloud status) | Monitoring / DevOps | 5 minutes |
| 2 | Decision to failover (CISO + Platform Eng Lead) | CISO | 15 minutes |
| 3 | Scale up DR region K8s cluster | DevOps Lead | 15 minutes |
| 4 | Promote PostgreSQL standby in DR region | DevOps Lead | 10 minutes |
| 5 | Switch Kafka consumers to MirrorMaker replica | DevOps Lead | 10 minutes |
| 6 | Update DNS to point to DR region ingress | DevOps Lead | 5 minutes (+ DNS propagation) |
| 7 | Verify all services healthy in DR region | Platform Eng Lead | 30 minutes |
| 8 | Verify audit trail hash-chain integrity | Security Architect | 15 minutes |
| 9 | Notify tenants of DR activation | Communications Lead | 30 minutes |
| **Total** | | | **< 4 hours** |

### 4.6 Scenario: Ransomware / Destructive Attack

| Step | Action | Actor | Time |
|---|---|---|---|
| 1 | Activate kill switch (halt all autonomous actions) | CISO | Immediate |
| 2 | Isolate affected systems (network policies) | DevOps Lead | 15 minutes |
| 3 | Assess scope of damage | Security Architect | 1 hour |
| 4 | Restore from immutable backups (off-site) | DevOps Lead | 2--4 hours |
| 5 | Verify data integrity (hash-chain, checksums) | Security Architect | 1 hour |
| 6 | Rebuild compromised infrastructure from GitOps | DevOps Lead | 1--2 hours |
| 7 | Restore services in order of criticality | Platform Eng Lead | 1--2 hours |
| 8 | Gradual service restoration with monitoring | Platform Eng Lead | 2 hours |
| **Total** | | | **4--12 hours** |

---

## 5. Data Replication Strategy

| Data Store | Replication Method | Replication Target | Lag Tolerance | Consistency |
|---|---|---|---|---|
| PostgreSQL | Streaming replication (async) | DR region standby | < 1 minute | Eventual (async); strong (sync option for critical tables) |
| Kafka | MirrorMaker 2 | DR region Kafka cluster | < 5 minutes | Eventual (best effort) |
| MinIO | Cross-site replication | DR region MinIO | < 15 minutes | Eventual |
| Redis | No cross-region replication | Rebuilt from scratch in DR | N/A | Cache reconstruction |
| Qdrant | Snapshot-based replication | DR region (daily snapshot) | < 24 hours | Snapshot consistency |
| Neo4j | Snapshot-based replication | DR region (daily snapshot) | < 24 hours | Snapshot consistency |

---

## 6. Kafka Replay for Message Recovery

### 6.1 Replay Capability

| Aspect | Details |
|---|---|
| Retention period | 7 days (configurable per topic) |
| Replay mechanism | Consumer group offset reset to specific timestamp |
| Idempotency | All consumers implement idempotent processing (deduplication by message ID) |
| Ordering | Per-partition ordering guaranteed; tenant-key partitioning ensures per-tenant ordering |
| Replay procedure | Reset consumer group offset → consumers replay from offset → skip already-processed messages |

### 6.2 Replay Scenarios

| Scenario | Replay Strategy |
|---|---|
| Service restart after failure | Automatic: consumer resumes from last committed offset |
| Data corruption in downstream service | Manual: reset consumer offset to before corruption; reprocess |
| Investigation pipeline failure | Manual: replay `alerts.triaged` topic from failure point |
| Audit trail gap | Manual: replay `audit.events` from gap start; hash-chain rebuilds |

---

## 7. Database Point-in-Time Recovery

### 7.1 PostgreSQL PITR

| Aspect | Details |
|---|---|
| WAL archiving | Continuous WAL archiving to MinIO (encrypted) |
| Base backups | Daily full backup (pg_basebackup) |
| Recovery granularity | Any point in time within WAL retention (7 days) |
| Recovery procedure | Restore base backup → replay WAL to target timestamp |
| Verification | Hash-chain verification on audit records after recovery |

### 7.2 PITR Procedure

| Step | Action | Actor | Time |
|---|---|---|---|
| 1 | Identify target recovery timestamp | Security Architect | 15 minutes |
| 2 | Provision new PostgreSQL instance | DevOps Lead | 10 minutes |
| 3 | Restore latest base backup before target time | DevOps Lead | 15--30 minutes |
| 4 | Replay WAL to target timestamp | DevOps Lead | 5--30 minutes |
| 5 | Verify data integrity (hash-chain, application checks) | Security Architect | 15 minutes |
| 6 | Switch application to recovered instance | DevOps Lead | 5 minutes |
| 7 | Verify service restoration | Platform Eng Lead | 15 minutes |

---

## 8. BCP Testing

### 8.1 Test Schedule

| Test Type | Frequency | Scope | Owner |
|---|---|---|---|
| Component failover test | Monthly | Individual service pod kill; DB failover; Kafka broker kill | DevOps Lead |
| LLM provider failover test | Quarterly | Simulate Anthropic outage; verify OpenAI fallback | AI/ML Eng Lead |
| Backup restoration test | Quarterly | Full PostgreSQL PITR; Kafka replay; MinIO restore | DevOps Lead |
| DR region failover test | Semi-annually | Full failover to DR region; verify all services | Platform Eng Lead |
| Tabletop exercise | Annually | Scenario-based walkthrough with full team | CISO |
| Full DR test | Annually | Unannounced full region failover (planned maintenance window) | CISO |

### 8.2 Test Acceptance Criteria

| Criterion | Target |
|---|---|
| All services restored within RTO | 100% |
| Data loss within RPO | 100% |
| Audit trail hash-chain verified post-recovery | Pass |
| Tenant data isolation maintained post-recovery | Verified |
| LLM provider failover functional | Verified |
| Kill switch operational in DR environment | Verified |

### 8.3 Test Documentation

Each BCP/DR test shall produce:
1. Test plan (scope, objectives, scenarios)
2. Test execution log (timestamped actions and results)
3. Deviations and issues encountered
4. RTO/RPO achievement measurement
5. Corrective actions for any failures
6. Sign-off by test owner and CISO

---

## 9. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | Platform Engineering Lead | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed annually, after every DR test, and upon significant changes to platform architecture or infrastructure.*
