# Operations Security

**Document ID:** ALUSKORT-ISMS-05
**Version:** 1.0
**Classification:** Internal
**Owner:** Platform Engineering Lead
**Approved by:** CISO, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Annex A.8.9--8.12, A.8.15--8.16, A.8.32

---

## 1. Purpose

This document defines the operational security controls for the ALUSKORT SOC Platform, covering change management, capacity management, environment separation, backup and recovery, logging and monitoring, and vulnerability management.

---

## 2. Change Management (A.8.32)

### 2.1 Change Classification

| Category | Description | Approval | Lead Time | Examples |
|---|---|---|---|---|
| **Standard** | Pre-approved, low-risk, repeatable changes | Auto-approved via CI/CD | Immediate | Dependency updates (patch), config value tuning |
| **Normal** | Planned changes with moderate risk | Peer review + Platform Eng Lead | 2 business days | New feature deployment, prompt template update, schema migration |
| **Emergency** | Urgent changes to restore service or address critical vulnerability | CISO or Platform Eng Lead (retrospective review) | Immediate | Security patch, kill switch activation, rollback |
| **Significant** | High-risk changes affecting multiple services, AI behaviour, or tenant data | CISO + Platform Eng Lead + Security Architect | 5 business days | Architecture changes, LLM tier configuration, ATLAS rule changes, RBAC model changes |

### 2.2 Change Management Process

```
1. Request    →  2. Assess    →  3. Approve   →  4. Implement  →  5. Verify    →  6. Close
   (Jira)         (Impact,         (Per            (CI/CD,          (Smoke          (Audit
                   Risk,            category)        Canary)          tests,          trail
                   Rollback                                          Monitor)        entry)
                   plan)
```

### 2.3 Deployment Strategy

| Strategy | Usage | Details |
|---|---|---|
| **Canary rollout** | All production deployments | New version deployed to 5% of traffic → 25% → 50% → 100%; automated rollback on error rate threshold |
| **Blue/green** | Database schema migrations | Parallel deployment; switch traffic after validation; old version retained for rollback |
| **Rolling update** | Kubernetes pod updates | One pod at a time; health check validation before proceeding |
| **Automatic rollback** | Canary failures | If error rate > 1% or latency > 2x baseline during canary, automatic rollback to previous version |

### 2.4 Canary Rollout Metrics

| Metric | Rollback Threshold |
|---|---|
| HTTP error rate (5xx) | > 1% |
| P99 latency | > 2x baseline |
| AI agent error rate | > 0.5% |
| Hash-chain verification failure | Any failure |
| Prompt injection detection anomaly | > 2 std dev from baseline |

---

## 3. Capacity Management (A.8.6)

### 3.1 Resource Monitoring

| Resource | Monitoring Tool | Warning Threshold | Critical Threshold | Scaling Action |
|---|---|---|---|---|
| CPU utilisation (per service) | Prometheus + Grafana | 70% sustained 10 min | 85% sustained 5 min | Horizontal Pod Autoscaler (HPA) |
| Memory utilisation (per service) | Prometheus + Grafana | 75% sustained 10 min | 90% sustained 5 min | HPA / Vertical Pod Autoscaler |
| PostgreSQL connections | pg_stat_activity | 70% of max_connections | 85% of max_connections | Connection pool tuning; scale read replicas |
| PostgreSQL disk usage | node_exporter | 70% capacity | 85% capacity | Volume expansion; archival |
| Redis memory | Redis INFO | 70% maxmemory | 85% maxmemory | Eviction policy review; scale cluster |
| Kafka partition lag | Kafka exporter | > 10,000 messages | > 100,000 messages | Add consumers; partition rebalance |
| Qdrant vector count | Qdrant metrics | 70% capacity | 85% capacity | Scale cluster; index optimisation |
| Neo4j heap usage | Neo4j metrics | 70% max heap | 85% max heap | Increase heap; query optimisation |
| MinIO disk usage | MinIO metrics | 70% capacity | 85% capacity | Volume expansion; lifecycle policies |
| LLM API rate | Spend guard metrics | 80% of tier quota | 95% of tier quota | Tenant notification; tier upgrade offer |

### 3.2 Per-Tenant Quota Enforcement

| Tier | LLM Calls/Hour | Max Investigations | Storage Limit | Enforcement |
|---|---|---|---|---|
| Premium | 500 | 50 concurrent | 100 GB | Spend guard; Redis counter; HTTP 429 on exceed |
| Standard | 100 | 20 concurrent | 25 GB | Spend guard; Redis counter; HTTP 429 on exceed |
| Trial | 20 | 5 concurrent | 5 GB | Spend guard; Redis counter; HTTP 429 on exceed |

---

## 4. Separation of Environments (A.8.31)

### 4.1 Environment Inventory

| Environment | Purpose | Infrastructure | Data | Access |
|---|---|---|---|---|
| **Development** | Feature development and unit testing | Docker Compose (local) | Synthetic data only; no tenant data | Developers |
| **CI/Test** | Automated testing in CI pipeline | Docker Compose (ephemeral) | Synthetic data; mock LLM responses | CI system (automated) |
| **Staging** | Pre-production validation; integration testing | Kubernetes (dedicated namespace) | Anonymised sample data; sandbox LLM API key | Platform Eng team |
| **Production** | Live service for tenants | Kubernetes (production cluster) | Real tenant data; production LLM API key | Operations team (restricted) |

### 4.2 Environment Isolation Controls

| Control | Implementation |
|---|---|
| Network isolation | Separate K8s namespaces; no network connectivity between staging and production |
| Credential isolation | Separate API keys, database credentials, and certificates per environment |
| Data isolation | Production data never copied to lower environments; synthetic data generators for testing |
| Deployment isolation | Separate CI/CD pipelines per environment; production deployment requires additional approval |
| LLM API isolation | Separate Anthropic API keys per environment; staging uses lower-tier models |
| Access isolation | Production access restricted to operations team; developers cannot access production |

### 4.3 Promotion Process

```
Development → CI/Test → Staging → Production
    │            │          │          │
    │ Push       │ Auto     │ Manual   │ Canary
    │ commit     │ trigger  │ promote  │ rollout
    │            │          │          │
    ▼            ▼          ▼          ▼
  Unit tests   Integration  Smoke     Canary metrics
  Lint/format  Security     tests     Error rate
  Type check   scan         E2E       Latency
               SAST/DAST    tests     AI accuracy
               Image scan   Perf      Hash-chain OK
```

---

## 5. Backup and Recovery (A.8.13)

### 5.1 Backup Schedule

| Component | Backup Method | Frequency | Retention | Storage | Encryption |
|---|---|---|---|---|---|
| PostgreSQL | pg_dump (logical) + WAL archiving (continuous) | Full: daily; Incremental: continuous (WAL) | 30 days (full); 7 days (WAL) | MinIO (separate bucket) + off-site | AES-256-GCM |
| Redis | RDB snapshots + AOF | RDB: every 6 hours; AOF: continuous | 7 days | MinIO + off-site | AES-256-GCM |
| Qdrant | Collection snapshots | Daily | 14 days | MinIO + off-site | AES-256-GCM |
| Neo4j | neo4j-admin dump | Daily | 14 days | MinIO + off-site | AES-256-GCM |
| Kafka | Topic mirroring (MirrorMaker 2) | Continuous | 7 days (topic retention) | Replica cluster | AES-256-GCM |
| MinIO | Cross-site replication | Continuous | Same as source | Remote MinIO | AES-256-GCM |
| Kubernetes config | etcd snapshot + GitOps (Flux/ArgoCD) | etcd: daily; GitOps: continuous | 30 days | Off-site + Git repository | AES-256-GCM |
| Audit trail | PostgreSQL backup (included) + evidence package export | Included in PostgreSQL; packages: on-demand | Per tenant retention policy | MinIO + off-site | AES-256-GCM |

### 5.2 Recovery Procedures

| Scenario | RPO | RTO | Procedure |
|---|---|---|---|
| PostgreSQL corruption | < 1 minute (WAL) | < 1 hour | Point-in-time recovery from WAL archive |
| PostgreSQL full loss | < 24 hours | < 2 hours | Restore from latest full backup + WAL replay |
| Redis data loss | < 6 hours (RDB) | < 30 minutes | Restore from latest RDB snapshot |
| Kafka partition loss | 0 (replicated) | < 15 minutes | Partition reassignment from ISR |
| Kafka cluster loss | < 1 minute | < 1 hour | Restore from MirrorMaker 2 replica |
| MinIO data loss | 0 (replicated) | < 30 minutes | Failover to cross-site replica |
| Full cluster loss | < 1 hour | < 4 hours | Rebuild cluster from etcd backup + GitOps + data restore |
| Single service failure | 0 | < 2 minutes | Kubernetes pod auto-restart |

### 5.3 Backup Testing

| Test | Frequency | Owner | Acceptance Criteria |
|---|---|---|---|
| PostgreSQL restore test | Monthly | DevOps Lead | Full restore within RTO; data integrity verified |
| Kafka replay test | Quarterly | DevOps Lead | Messages replayed in order; no data loss |
| Full DR test | Semi-annually | Platform Eng Lead | All services restored within RTO; hash-chain verified |
| Audit trail restoration | Quarterly | Security Architect | Hash-chain integrity verified post-restore |

---

## 6. Logging and Monitoring (A.8.15, A.8.16)

### 6.1 Logging Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Application Services                    │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────┐   │
│  │ Service  │ │ Service  │ │ Context │ │ LLM Router  │   │
│  │  Logs    │ │  Logs    │ │ Gateway │ │   Logs      │   │
│  │         │ │         │ │  Logs   │ │             │   │
│  └────┬────┘ └────┬────┘ └────┬────┘ └──────┬──────┘   │
│       └────────────┴──────────┴──────────────┘           │
│                         │                                 │
│                    ┌────┴─────┐                           │
│                    │  Kafka   │                           │
│                    │ (logs    │                           │
│                    │  topic)  │                           │
│                    └────┬─────┘                           │
│                         │                                 │
│           ┌─────────────┼─────────────┐                  │
│           │             │             │                   │
│     ┌─────┴─────┐ ┌────┴─────┐ ┌────┴──────┐           │
│     │ Audit     │ │ ELK /    │ │ Prometheus │           │
│     │ Service   │ │ Loki     │ │ + Grafana  │           │
│     │(Hash-chain│ │(Search)  │ │(Metrics +  │           │
│     │ immutable)│ │          │ │ Alerting)  │           │
│     └───────────┘ └──────────┘ └────────────┘           │
└──────────────────────────────────────────────────────────┘
```

### 6.2 Log Categories

| Category | Content | Retention | Classification |
|---|---|---|---|
| **Audit trail** (hash-chain) | All security-relevant events: authentication, authorisation, AI decisions, configuration changes, approvals | Per-tenant (trial: 30d, standard: 180d, premium: 365d) | Restricted |
| **Application logs** | Service operational logs: requests, errors, performance data | 90 days | Confidential |
| **LLM inference logs** | All LLM API calls: prompt summary (PII-redacted), model tier, token count, cost, latency | 180 days | Confidential |
| **Infrastructure logs** | K8s events, container logs, system logs | 30 days | Internal |
| **Security logs** | Context Gateway events: injection attempts, PII detections, output validation failures, ATLAS rule triggers | 365 days | Restricted |
| **Access logs** | HTTP request logs, authentication events, RBAC decisions | 180 days | Confidential |

### 6.3 Prometheus Alerting Rules

| Rule # | Alert Name | Condition | Severity | Action |
|---|---|---|---|---|
| 1 | HighAlertIngestionLatency | P99 latency > 5s for 5 min | Warning | Investigate ingestion pipeline |
| 2 | InvestigationPipelineDown | No investigations completed in 15 min | Critical | Page on-call; check all services |
| 3 | HashChainVerificationFailure | Any chain break detected | Critical | Immediate investigation; potential incident |
| 4 | PromptInjectionRateAnomaly | Injection rate > 2 std dev above baseline | High | Security team review; potential attack |
| 5 | LLMProviderError | Anthropic API error rate > 5% for 5 min | High | Check provider status; consider failover |
| 6 | SpendGuardBudgetExhausted | Tenant budget > 95% utilised | Warning | Notify tenant; throttle requests |
| 7 | DatabaseConnectionPoolExhausted | Available connections < 10% | Critical | Scale connections; investigate leaks |
| 8 | KafkaConsumerLagHigh | Consumer lag > 100,000 messages | High | Scale consumers; check processing |
| 9 | CertificateExpiryImminent | Certificate expires < 1 hour | Critical | Investigate cert-manager; manual renewal |
| 10 | MemoryUtilisationCritical | Pod memory > 90% for 5 min | Critical | HPA scale; investigate memory leak |
| 11 | KillSwitchActivated | Kill switch state changed to active | Critical | Page all on-call; incident response |
| 12 | CrossTenantAccessAttempt | Any cross-tenant query detected | Critical | Immediate investigation; potential breach |

### 6.4 Log Protection

| Control | Implementation |
|---|---|
| Immutability | Audit trail: hash-chain provides tamper detection; application logs: append-only storage |
| Access control | Log access restricted by role (see ALUSKORT-ISMS-03) |
| PII sanitisation | PII redacted from all logs before storage; API keys and credentials never logged |
| Integrity | Audit trail integrity verified via hash-chain; application log integrity via storage checksums |
| Clock synchronisation (A.8.17) | All K8s nodes synchronised via NTP (chrony); < 1ms drift tolerance; UTC timestamps |
| Centralisation | All logs forwarded to centralised logging infrastructure; no local-only logs in production |

---

## 7. Vulnerability Management (A.8.8)

### 7.1 CTEM Integration

The ALUSKORT platform integrates with Continuous Threat Exposure Management (CTEM) for continuous vulnerability assessment:

| Phase | Activity | Tool / Process | Frequency |
|---|---|---|---|
| **Scoping** | Define platform attack surface including AI components | Manual + automated asset discovery | Quarterly |
| **Discovery** | Identify vulnerabilities in platform components | Container image scanning, dependency scanning, DAST | Continuous |
| **Prioritisation** | Rank vulnerabilities by exploitability and impact | CVSS + platform context (data sensitivity, exposure) | On discovery |
| **Validation** | Verify vulnerabilities are exploitable in ALUSKORT context | Penetration testing, red team exercises | Quarterly |
| **Mobilisation** | Remediate or mitigate validated vulnerabilities | Patch management, configuration hardening | Per SLA |

### 7.2 Vulnerability Scanning

| Scan Type | Tool | Target | Frequency | SLA |
|---|---|---|---|---|
| Container image scan | Trivy / Snyk | All container images | Every build + daily | Critical: 24h; High: 7d; Medium: 30d |
| Dependency scan (SCA) | Snyk / Dependabot | Python, Node.js dependencies | Every build + daily | Critical: 24h; High: 7d; Medium: 30d |
| Static analysis (SAST) | Semgrep / SonarQube | Source code | Every PR | Block merge on critical/high findings |
| Dynamic analysis (DAST) | OWASP ZAP | Running services (staging) | Weekly | Critical: 24h; High: 7d |
| Infrastructure scan | kube-bench / Falco | Kubernetes configuration | Weekly | Critical: 48h; High: 14d |
| Secret scanning | Gitleaks / TruffleHog | Git repositories | Every commit (pre-commit hook) | Immediate remediation |
| AI-specific testing | Custom adversarial tests | Context Gateway, LLM prompts | Monthly | Per risk assessment |

### 7.3 Patch Management

| Component | Patch Source | Testing | Deployment |
|---|---|---|---|
| Base container images | OS vendor | CI pipeline automated tests | Canary rollout |
| Application dependencies | Package managers (pip, npm) | CI pipeline automated tests | Canary rollout |
| Kubernetes | K8s release channel | Staging environment testing | Rolling update (control plane first) |
| Databases | Vendor releases | Staging environment testing; backup before upgrade | Maintenance window |
| AI model updates | Anthropic model releases | Shadow mode testing | Canary rollout with performance monitoring |

---

## 8. Malware Protection (A.8.7)

| Control | Implementation |
|---|---|
| Container image scanning | Scan for malware and known vulnerabilities before deployment |
| Read-only root filesystem | Container root filesystems mounted read-only |
| Non-root execution | All containers run as non-root user |
| Network policies | Restrict outbound connections to known destinations only |
| Runtime monitoring | Falco rules for anomalous container behaviour |
| Supply chain verification | Container image signatures verified before deployment |

---

## 9. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | Platform Engineering Lead | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed annually or upon significant changes to operational procedures, infrastructure, or monitoring capabilities.*
