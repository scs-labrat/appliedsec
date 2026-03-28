# Communications Security

**Document ID:** ALUSKORT-ISMS-06
**Version:** 1.0
**Classification:** Internal
**Owner:** Security Architect
**Approved by:** CISO, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Annex A.8.20--8.22

---

## 1. Purpose

This document defines the communications security controls for the ALUSKORT SOC Platform, covering network segmentation, service mesh policies, message bus security, external API security, WebSocket security, and DDoS protection.

---

## 2. Network Architecture Overview

```
                         Internet
                            │
                    ┌───────┴───────┐
                    │  DDoS         │
                    │  Protection   │
                    │  (Cloud WAF)  │
                    └───────┬───────┘
                            │
                    ┌───────┴───────┐
                    │  Ingress      │
                    │  Controller   │
                    │  (TLS term.)  │
                    └───────┬───────┘
                            │
         ┌──────────────────┼──────────────────┐
         │           K8s Cluster                │
         │                                      │
         │  ┌─────────────────────────────┐     │
         │  │ Namespace: aluskort-app     │     │
         │  │                             │     │
         │  │  ┌─────┐ ┌─────┐ ┌─────┐  │     │
         │  │  │Ingest│ │Triage│ │Invest│ │     │
         │  │  └──┬──┘ └──┬──┘ └──┬──┘  │     │
         │  │     │  mTLS  │  mTLS │     │     │
         │  │  ┌──┴──┐ ┌──┴──┐ ┌──┴──┐  │     │
         │  │  │Ctx GW│ │LLM R│ │Resp │  │     │
         │  │  └─────┘ └──┬──┘ └─────┘  │     │
         │  │             │              │     │
         │  │  ┌─────┐ ┌──┴──┐ ┌─────┐  │     │
         │  │  │Case │ │Dashb│ │Audit│   │     │
         │  │  └─────┘ └─────┘ └─────┘  │     │
         │  └─────────────────────────────┘     │
         │                                      │
         │  ┌─────────────────────────────┐     │
         │  │ Namespace: aluskort-data    │     │
         │  │                             │     │
         │  │  ┌────┐ ┌─────┐ ┌──────┐   │     │
         │  │  │ PG │ │Redis│ │Qdrant│   │     │
         │  │  └────┘ └─────┘ └──────┘   │     │
         │  │  ┌─────┐ ┌─────┐ ┌─────┐   │     │
         │  │  │Neo4j│ │Kafka│ │MinIO│   │     │
         │  │  └─────┘ └─────┘ └─────┘   │     │
         │  └─────────────────────────────┘     │
         │                                      │
         │  ┌─────────────────────────────┐     │
         │  │ Namespace: aluskort-monitor │     │
         │  │                             │     │
         │  │  ┌──────┐ ┌───────┐        │     │
         │  │  │Prom. │ │Grafana│        │     │
         │  │  └──────┘ └───────┘        │     │
         │  └─────────────────────────────┘     │
         │                                      │
         └──────────────────────────────────────┘
                            │
                   External APIs
                   (Anthropic, SIEM)
```

---

## 3. Network Segmentation (A.8.22)

### 3.1 Kubernetes Namespace Isolation

| Namespace | Purpose | Components | Access Policy |
|---|---|---|---|
| `aluskort-app` | Application microservices | Alert Ingestion, Triage, Investigation, Context Gateway, LLM Router, Response, Case Management, Dashboard, Audit | Inter-service mTLS; ingress from controller only |
| `aluskort-data` | Data stores | PostgreSQL, Redis, Qdrant, Neo4j, Kafka/Redpanda, MinIO | Access from `aluskort-app` only; no direct external access |
| `aluskort-monitor` | Monitoring and observability | Prometheus, Grafana, Alertmanager, Loki | Scrape access from all namespaces; dashboard access restricted |
| `aluskort-system` | Platform infrastructure | cert-manager, ingress controller, external-dns | Cluster-wide access for certificate and DNS management |
| `kube-system` | Kubernetes core | K8s core components | Default K8s access; hardened per CIS benchmark |

### 3.2 Network Policies

#### 3.2.1 Default Deny Policy

All namespaces implement a default-deny ingress and egress policy:

```yaml
# Applied to all namespaces
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

#### 3.2.2 Application Namespace Policies

| Source | Destination | Port(s) | Protocol | Purpose |
|---|---|---|---|---|
| Ingress controller | Dashboard Service | 8080 | TCP (mTLS) | External user access |
| Ingress controller | Alert Ingestion | 8080 | TCP (mTLS) | SIEM alert submission |
| Alert Ingestion | Kafka | 9092 | TCP (mTLS) | Publish incoming alerts |
| Triage Service | Kafka | 9092 | TCP (mTLS) | Consume/produce alerts |
| Triage Service | Context Gateway | 8080 | TCP (mTLS) | LLM request pre-processing |
| Investigation Service | Context Gateway | 8080 | TCP (mTLS) | LLM request pre-processing |
| Context Gateway | LLM Router | 8080 | TCP (mTLS) | Forward validated LLM requests |
| LLM Router | Anthropic API | 443 | TCP (TLS) | Outbound LLM inference |
| LLM Router | OpenAI API | 443 | TCP (TLS) | Fallback LLM inference |
| All app services | PostgreSQL | 5432 | TCP (TLS) | Database access |
| All app services | Redis | 6379 | TCP (TLS) | Cache and session access |
| Investigation Service | Qdrant | 6333 | TCP (TLS) | Vector similarity search |
| Investigation Service | Neo4j | 7687 | TCP (TLS) | Graph queries |
| All app services | Audit Service | 8080 | TCP (mTLS) | Audit trail writes |
| Prometheus | All pods | /metrics | TCP | Metrics scraping |
| All pods | DNS (kube-dns) | 53 | TCP/UDP | DNS resolution |

#### 3.2.3 Data Namespace Policies

| Source | Destination | Port(s) | Protocol | Purpose |
|---|---|---|---|---|
| `aluskort-app` pods | PostgreSQL | 5432 | TCP (TLS) | Application database access |
| `aluskort-app` pods | Redis | 6379 | TCP (TLS) | Application cache access |
| `aluskort-app` pods | Qdrant | 6333, 6334 | TCP (TLS) | Vector DB access |
| `aluskort-app` pods | Neo4j | 7687 | TCP (TLS) | Graph DB access |
| `aluskort-app` pods | Kafka | 9092 | TCP (mTLS) | Message bus access |
| `aluskort-app` pods | MinIO | 9000 | TCP (TLS) | Object storage access |
| Kafka | Kafka (inter-broker) | 9093 | TCP (mTLS) | Broker replication |
| `aluskort-monitor` | All data pods | /metrics | TCP | Metrics scraping |
| **Deny** | All other traffic | -- | -- | Default deny |

### 3.3 Egress Controls

| Service | Allowed External Destinations | Port | Purpose |
|---|---|---|---|
| LLM Router | `api.anthropic.com` | 443 | Claude API |
| LLM Router | `api.openai.com` | 443 | Fallback LLM |
| Alert Ingestion | Configured SIEM endpoints | 443 | SIEM adapter polling |
| cert-manager | ACME CA endpoint | 443 | Certificate issuance |
| All pods | Internal DNS only | 53 | DNS resolution |
| **Deny** | All other external destinations | -- | Default deny egress |

---

## 4. Kafka Topic Security (A.8.20)

### 4.1 Topic Inventory

| Topic | Producers | Consumers | Data Classification | Partitions |
|---|---|---|---|---|
| `alerts.ingested` | Alert Ingestion | Triage Service | Confidential | Per-tenant key partitioning |
| `alerts.triaged` | Triage Service | Investigation Service | Confidential | Per-tenant key partitioning |
| `investigations.started` | Investigation Service | Case Management | Confidential | Per-tenant key partitioning |
| `investigations.completed` | Investigation Service | Response Service, Dashboard | Confidential | Per-tenant key partitioning |
| `responses.pending` | Response Service | Dashboard (approval) | Confidential | Per-tenant key partitioning |
| `responses.executed` | Response Service | Audit Service, Case Mgmt | Confidential | Per-tenant key partitioning |
| `audit.events` | All services | Audit Service | Restricted | Per-tenant key partitioning |
| `llm.requests` | Context Gateway | LLM Router | Confidential | Round-robin |
| `llm.responses` | LLM Router | Context Gateway | Confidential | Correlated to request |
| `platform.health` | All services | Monitoring | Internal | Per-service partitioning |

### 4.2 Kafka ACLs

| Principal | Topic Pattern | Operation | Permission |
|---|---|---|---|
| `svc-alert-ingestion` | `alerts.ingested` | Write | Allow |
| `svc-triage` | `alerts.ingested` | Read | Allow |
| `svc-triage` | `alerts.triaged` | Write | Allow |
| `svc-investigation` | `alerts.triaged` | Read | Allow |
| `svc-investigation` | `investigations.*` | Write | Allow |
| `svc-response` | `investigations.completed` | Read | Allow |
| `svc-response` | `responses.*` | Write | Allow |
| `svc-case-mgmt` | `investigations.*` | Read | Allow |
| `svc-case-mgmt` | `responses.*` | Read | Allow |
| `svc-dashboard` | `investigations.*` | Read | Allow |
| `svc-dashboard` | `responses.*` | Read | Allow |
| `svc-context-gateway` | `llm.requests` | Write | Allow |
| `svc-context-gateway` | `llm.responses` | Read | Allow |
| `svc-llm-router` | `llm.requests` | Read | Allow |
| `svc-llm-router` | `llm.responses` | Write | Allow |
| `svc-audit` | `audit.events` | Read | Allow |
| `ALL` (services) | `audit.events` | Write | Allow |
| `ALL` (services) | `platform.health` | Write | Allow |
| `svc-monitoring` | `platform.health` | Read | Allow |
| **Default** | **All topics** | **All operations** | **Deny** |

### 4.3 Kafka Security Configuration

| Setting | Value |
|---|---|
| `security.inter.broker.protocol` | SSL (mTLS) |
| `ssl.client.auth` | required |
| `authorizer.class.name` | `kafka.security.authorizer.AclAuthorizer` |
| `super.users` | `User:svc-kafka-admin` (break-glass only) |
| `auto.create.topics.enable` | false |
| `message.max.bytes` | 10 MB (prevent oversized messages) |
| `log.retention.hours` | 168 (7 days) |
| Topic replication factor | 3 (production) |
| Min in-sync replicas | 2 |

---

## 5. External API Security (A.8.20)

### 5.1 SIEM Adapter Security

| SIEM Integration | Authentication | Transport | Rate Limiting | Data Flow |
|---|---|---|---|---|
| Microsoft Sentinel | OAuth 2.0 client credentials | TLS 1.3 | 100 req/min | Pull (polling) |
| Elastic SIEM | API key + IP allowlist | TLS 1.3 | 100 req/min | Pull (polling) |
| Splunk | HEC token + IP allowlist | TLS 1.3 | 100 req/min | Push (webhook) |

### 5.2 Inbound API Security

| Control | Implementation |
|---|---|
| Authentication | OIDC JWT validation (production); API key (SIEM adapters) |
| Authorisation | RBAC enforcement at middleware level |
| Rate limiting | Per-tenant, per-endpoint rate limits enforced via Redis |
| Input validation | JSON schema validation on all request bodies |
| Request size limit | 1 MB maximum request body |
| CORS policy | Restrict to approved dashboard origins only |
| Content-Type validation | Reject requests with unexpected Content-Type |
| API versioning | Version prefix in URL path (`/api/v1/`) |

### 5.3 Outbound API Security

| Destination | Authentication | Transport | Controls |
|---|---|---|---|
| Anthropic Claude API | API key (Bearer token) | TLS 1.3 | Spend guard; PII-redacted payloads; response validation |
| OpenAI API (fallback) | API key (Bearer token) | TLS 1.3 | Same controls as Anthropic |
| SIEM polling endpoints | Per-SIEM credentials | TLS 1.3 | Credential rotation; response validation |

---

## 6. WebSocket Security

### 6.1 Dashboard WebSocket Controls

| Control | Implementation |
|---|---|
| Transport | WSS (WebSocket over TLS 1.3) |
| Authentication | JWT token validated on connection establishment |
| Re-authentication | Token refresh required every 15 minutes; connection closed on failure |
| Authorisation | Messages filtered by tenant_id and user role |
| Message validation | Server-side JSON schema validation on all messages |
| Rate limiting | Max 100 messages/second per connection |
| Connection limit | Max 3 concurrent WebSocket connections per user |
| Idle timeout | Connection closed after 30 minutes of inactivity |
| Heartbeat | Ping/pong every 30 seconds; disconnection after 3 missed pongs |
| Origin validation | Check `Origin` header against approved list |

### 6.2 Real-Time Event Filtering

| Event Type | `analyst` | `senior_analyst` | `admin` |
|---|---|---|---|
| New alert (own tenant) | Yes | Yes | Yes |
| Investigation update (own tenant) | Yes | Yes | Yes |
| Approval request | No | Yes | Yes |
| System health event | No | No | Yes |
| Cross-tenant events | No | No | Yes |
| Kill switch status | No | Yes | Yes |

---

## 7. DDoS Protection

### 7.1 Multi-Layer DDoS Defence

| Layer | Control | Implementation |
|---|---|---|
| L3/L4 (Network) | Cloud provider DDoS protection | Cloud WAF / Shield (cloud-provider managed) |
| L4 (Transport) | SYN flood protection | Cloud load balancer; connection rate limiting |
| L7 (Application) | HTTP rate limiting | Ingress controller rate limiting (100 req/s per IP) |
| L7 (Application) | Per-tenant rate limiting | Redis-based rate limiter in application middleware |
| L7 (Application) | Payload size limits | 1 MB request body limit; 10 MB for evidence uploads |
| L7 (Application) | Slowloris protection | Request timeout: 30 seconds; header timeout: 10 seconds |
| Application | LLM cost protection | Spend guard budget enforcement prevents cost amplification |
| Application | Investigation throttling | Max concurrent investigations per tenant tier |

### 7.2 DDoS Response Procedure

1. **Detection** -- Monitoring alerts on traffic anomalies (Prometheus + cloud WAF)
2. **Classification** -- Determine attack type (volumetric, protocol, application-layer)
3. **Mitigation** -- Apply appropriate countermeasures (cloud WAF rules, IP blocking, rate limit tightening)
4. **Communication** -- Notify affected tenants if service degradation occurs
5. **Recovery** -- Restore normal operations; remove temporary mitigations
6. **Review** -- Post-incident review; update DDoS defence rules

---

## 8. Information Transfer Security (A.8.21)

| Transfer Type | Controls |
|---|---|
| Alert data (SIEM → Platform) | TLS 1.3; authenticated API; input validation; rate limited |
| LLM data (Platform → Anthropic) | TLS 1.3; PII redacted; output validated; logged |
| Evidence packages (export) | Encrypted at rest; access-controlled; audit logged |
| Audit trail (export) | Hash-chain verified; encrypted; access-controlled |
| Configuration (CI/CD → K8s) | Git-signed commits; encrypted secrets; mTLS deployment |
| Backup data (Platform → Storage) | Encrypted in transit and at rest; access-controlled |

---

## 9. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | Security Architect | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed annually or upon changes to network architecture, integration points, or communication protocols.*
