# ALUSKORT — Codebase Architecture Reference

**Project:** ALUSKORT - Cloud-Neutral Security Reasoning Control Plane
**Generated:** 2026-02-21
**Source:** Automated deep scan of codebase (document-project workflow)
**Complements:** `docs/architecture.md` (design-time architecture v2.0)

---

## 1. Executive Summary

ALUSKORT is a cloud-neutral autonomous SOC agent that ingests security alerts from SIEM platforms, enriches them with threat intelligence, reasons about them using LLM-powered agents, and orchestrates response actions — all tracked by an immutable audit trail.

**Architecture Style:** Event-driven microservices with polyglot persistence
**Language:** Python 3.12+ (async throughout)
**Deployment:** Docker Compose (dev) → Kubernetes (prod) via GHCR

---

## 2. Technology Stack

| Category | Technology | Version | Purpose |
|----------|-----------|---------|---------|
| Language | Python | >=3.12 | Primary runtime |
| Validation | Pydantic | >=2.6.0 | Schema contracts |
| Relational DB | PostgreSQL | 16-alpine | Core state, CTEM, audit, telemetry |
| DB Driver | asyncpg | >=0.29.0 | Async pooled connections |
| Cache | Redis | 7-alpine | IOC cache, FP patterns (fail-open) |
| Cache Driver | redis[hiredis] | >=5.0.0 | Async with hiredis acceleration |
| Vector DB | Qdrant | latest | Semantic search (4 HNSW collections) |
| Vector Driver | qdrant-client | >=1.8.0 | gRPC-preferred, circuit-breaker errors |
| Graph DB | Neo4j | 5-community | Consequence reasoning, asset-zone graph |
| Graph Driver | neo4j | >=5.17.0 | Async with static fallback |
| Object Store | MinIO | latest | S3-compatible evidence/artifact storage |
| Message Bus | Kafka (Redpanda) | latest | Event-driven inter-service messaging |
| Kafka Driver | confluent-kafka | >=2.3.0 | High-performance producer/consumer |
| LLM Provider | Anthropic (Claude) | >=0.39.0 | AI reasoning and classification |
| Embedding | text-embedding-3-small | — | 1536-dim vectors for RAG |
| Auth (External) | OIDC / JWT (RS256) | — | Token validation via JWKS |
| Auth (Internal) | mTLS | TLS 1.3 | Inter-service mutual TLS |
| Testing | pytest + pytest-asyncio | >=8.0 | 91 test files, 90% coverage gate |
| CI/CD | GitHub Actions | — | Test + matrix build → GHCR |
| Orchestration | Kubernetes | — | 8 Deployments in `aluskort` namespace |
| Monitoring | Prometheus | — | 12 alert rules |

---

## 3. Architecture Pattern

### 3.1 High-Level Data Flow

```
┌─────────────────┐     ┌─────────────────┐
│ Microsoft        │     │ ATLAS Detection  │
│ Sentinel         │     │ Engine           │
│ (EventHub/API)   │     │ (10 stat rules)  │
└────────┬────────┘     └────────┬────────┘
         │                       │
         ▼                       ▼
    ┌─────────────────────────────────┐
    │        alerts.raw (Kafka)       │
    └────────────────┬────────────────┘
                     ▼
    ┌─────────────────────────────────┐
    │         Entity Parser           │
    │  (normalise, validate, IOC)     │
    └────────────────┬────────────────┘
                     ▼
    ┌─────────────────────────────────┐
    │     alerts.normalized (Kafka)    │
    └────────────────┬────────────────┘
                     ▼
    ┌─────────────────────────────────┐
    │       Orchestrator              │
    │  ┌──────────────────────────┐   │
    │  │ IOC Extractor (Haiku)    │   │     ┌──────────────┐
    │  │         ↓                │   │     │ Context      │
    │  │ FP Short-Circuit         │   │◄───►│ Gateway      │
    │  │         ↓                │   │     │ (sanitise,   │
    │  │ Context Enricher ────────│───│────►│  redact,     │
    │  │ CTEM Correlator  (parallel)  │     │  prompt,     │
    │  │ ATLAS Mapper             │   │     │  validate)   │
    │  │         ↓                │   │     └──────┬───────┘
    │  │ Reasoning Agent (Sonnet) │   │            │
    │  │         ↓                │   │            ▼
    │  │ Response Agent           │   │     ┌──────────────┐
    │  └──────────────────────────┘   │     │ LLM Router   │
    └────────────────┬────────────────┘     │ (4-tier,     │
                     │                       │  circuit     │
                     ▼                       │  breaker)    │
    ┌─────────────────────────────────┐     └──────┬───────┘
    │      audit.events (Kafka)        │            │
    └────────────────┬────────────────┘            ▼
                     ▼                       ┌──────────────┐
    ┌─────────────────────────────────┐     │ Anthropic    │
    │        Audit Service            │     │ Claude API   │
    │  (immutable, hash-chain,        │     └──────────────┘
    │   evidence packages)            │
    └─────────────────────────────────┘
```

### 3.2 Polyglot Persistence

```
┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
│ PostgreSQL │  │   Redis    │  │   Qdrant   │  │   Neo4j    │  │   MinIO    │
│            │  │            │  │            │  │            │  │            │
│ State      │  │ IOC Cache  │  │ Embeddings │  │ Asset-Zone │  │ Evidence   │
│ CTEM       │  │ FP Patterns│  │ Incidents  │  │ Graphs     │  │ Artifacts  │
│ Audit      │  │ (fail-open)│  │ Techniques │  │ Consequence│  │ Packages   │
│ Telemetry  │  │            │  │ Playbooks  │  │ Reasoning  │  │            │
│ Taxonomy   │  │            │  │ TI Reports │  │ (fallback) │  │            │
└────────────┘  └────────────┘  └────────────┘  └────────────┘  └────────────┘
```

### 3.3 Resilience Patterns

| Pattern | Implementation | Location |
|---------|---------------|----------|
| **Circuit Breaker** | Per-provider state machine (CLOSED→OPEN→HALF_OPEN) | `llm_router/circuit_breaker.py` |
| **Fail-Open Cache** | Redis ops swallow errors, return None | `shared/db/redis_cache.py` |
| **Static Fallback** | Zone-consequence map when Neo4j unavailable | `shared/db/neo4j_graph.py` |
| **Degradation Levels** | 4 levels: full→secondary→deterministic→passthrough | `llm_router/models.py` |
| **DLQ** | Failed messages routed to `*.dlq` topics | entity_parser, ctem_normaliser |
| **Spend Guard** | Hard cap ($1000/mo) blocks new LLM calls | `context_gateway/spend_guard.py` |
| **Injection Detection** | 14+ regex patterns + LLM-as-judge second opinion | `context_gateway/injection_*.py` |
| **Deny-by-Default** | Unknown technique IDs quarantined, not passed through | `context_gateway/output_validator.py` |

---

## 4. Service Catalog

### 4.1 Deployable Services (8)

| Service | Replicas | CPU | Memory | Entry Point | Kafka Topics |
|---------|----------|-----|--------|-------------|-------------|
| entity-parser | 2 | 250m/500m | 256Mi/512Mi | `entity_parser/service.py` | C: `alerts.raw` P: `alerts.normalized` |
| context-gateway | 2 | 500m/1Gi | 512Mi/1Gi | `context_gateway/gateway.py` | P: `audit.events` |
| llm-router | 1 | 250m/500m | 256Mi/512Mi | `llm_router/router.py` | — |
| orchestrator | 2 | 500m/1Gi | 512Mi/1Gi | `orchestrator/graph.py` | C: `alerts.normalized` P: `audit.events` |
| ctem-normaliser | 2 | 250m/500m | 256Mi/512Mi | `ctem_normaliser/service.py` | C: `ctem.raw.*` P: `ctem.normalized` |
| atlas-detection | 1 | 250m/500m | 256Mi/512Mi | `atlas_detection/runner.py` | P: `alerts.raw` |
| batch-scheduler | 1 | 250m/500m | 256Mi/512Mi | `batch_scheduler/scheduler.py` | C: priority queues P: `audit.events` |
| sentinel-adapter | 2 | 250m/500m | 256Mi/512Mi | `sentinel_adapter/connector.py` | P: `alerts.raw` |

### 4.2 Shared Libraries

| Package | Files | Purpose |
|---------|-------|---------|
| `shared/schemas/` | 9 | Pydantic v2 data contracts (20+ models, 45 event types) |
| `shared/db/` | 5 | Async DB clients (PG, Redis, Qdrant, Neo4j) |
| `shared/auth/` | 4 | OIDC validator + mTLS context + error codes |
| `shared/audit/` | 2 | AuditProducer (fire-and-forget to Kafka) |
| `shared/adapters/` | 2 | IngestAdapter ABC for SIEM connectors |

### 4.3 Support Services

| Service | Files | Purpose |
|---------|-------|---------|
| `services/audit_service/` | 7 | Immutable audit trail, hash-chain verification, evidence packages |
| `ops/` | 4 | Health probes, metrics registry, 12 alert rules |

---

## 5. Investigation Pipeline

### 5.1 State Machine

```
RECEIVED → PARSING → ENRICHING → REASONING → RESPONDING → CLOSED
                         ↑            │             │
                         │            ▼             ▼
                    FP Short-circuit  AWAITING_HUMAN
                    (skip to CLOSED   (4h timeout)
                     if match ≥0.90)       │
                                           ▼
                                       FAILED (on error/timeout)
```

### 5.2 Agent Roles

| Agent | LLM Tier | Purpose | Data Sources |
|-------|----------|---------|-------------|
| IOC Extractor | Tier 0 (Haiku) | Extract IOCs from alert | Context Gateway |
| Context Enricher | — | Parallel enrichment | Redis IOC, PG UEBA, Qdrant similar |
| CTEM Correlator | — | Exposure correlation | PG ctem_exposures by asset_id |
| ATLAS Mapper | — | Technique mapping | PG taxonomy + Qdrant semantic |
| Reasoning Agent | Tier 1 (Sonnet) → Tier 1+ (Opus) | Classification + confidence | Context Gateway |
| Response Agent | — | Playbook selection + action tiering | PG playbooks |

### 5.3 Executor Constraints

- **Allowlisted playbooks only** — LLM cannot invent actions
- **Min confidence for auto-close**: configurable threshold
- **FP match required for auto-close**: optional gate
- **Cannot modify routing policy** or **disable guardrails**
- **Role-based permissions**: each agent has explicit action whitelist

---

## 6. LLM Routing Architecture

### 6.1 Model Registry

| Tier | Model | Context | Input $/Mtok | Output $/Mtok | Use Case |
|------|-------|---------|-------------|--------------|----------|
| Tier 0 | claude-haiku-4-5 | 200K | $0.80 | $4.00 | IOC extraction, classification |
| Tier 1 | claude-sonnet-4-5 | 200K | $3.00 | $15.00 | Investigation, reasoning |
| Tier 1+ | claude-opus-4-6 | 200K | $15.00 | $75.00 | Complex escalation |
| Tier 2 | claude-sonnet-4-5 (batch) | 200K | $1.50 | $7.50 | FP patterns, playbooks |

### 6.2 Fallback Chain

```
Primary: ANTHROPIC (all tiers)
    ↓ (circuit breaker open)
Secondary: OPENAI (Tier 0: gpt-4o-mini, Tier 1: gpt-4o)
    ↓ (both unavailable)
Deterministic: Rule-based only (no LLM)
    ↓ (all degraded)
Passthrough: Forward alert without enrichment
```

### 6.3 Task-to-Tier Mapping

**Tier 0** (fast, cheap): ioc_extraction, log_summarisation, entity_normalisation, fp_suggestion, alert_classification, severity_assessment

**Tier 1** (deep reasoning): investigation, ctem_correlation, atlas_reasoning, attack_path_analysis, incident_report, playbook_selection

**Tier 2** (batch, offline): fp_pattern_training, playbook_generation, agent_red_team, detection_rule_generation, retrospective_analysis

---

## 7. Data Architecture

### 7.1 PostgreSQL Schema (30+ tables, 7 migrations)

**Core (001):** mitre_techniques, mitre_groups, taxonomy_ids, threat_intel_iocs, playbooks, playbook_steps, incident_memory, fp_patterns, org_context

**CTEM (002):** ctem_exposures, ctem_validations, ctem_remediations

**Investigation (003):** investigation_state, inference_logs, orbital_inference_logs, edge_node_telemetry, databricks_audit, model_registry

**Telemetry (004):** 10 extended telemetry tables (physics oracle, NL queries, API logs, CI/CD, partner, OPC-UA)

**Taxonomy (005):** taxonomy_metadata, seed data (53 ATT&CK + ATLAS techniques)

**Audit (006):** audit_records (partitioned by month, immutable trigger, SOC 2 CC6.8)

**Chain (007):** audit_chain_state (per-tenant hash chain), audit_verification_log

### 7.2 Qdrant Vector Collections

| Collection | Vector Size | Purpose |
|-----------|-------------|---------|
| `incident_embeddings` | 1536 | Similar incident search |
| `technique_embeddings` | 1536 | MITRE technique semantic search |
| `playbook_embeddings` | 1536 | Playbook matching |
| `ti_report_embeddings` | 1536 | Threat intel report search |

### 7.3 Neo4j Graph Model

```
(Finding)-[:AFFECTS]->(Asset)-[:RESIDES_IN]->(Zone)
(Asset)<-[:DEPLOYS_TO]-(Model)-[:DEPLOYS_TO]->(Asset)
(Asset)-[:OWNED_BY]->(Tenant)
(Zone) has consequence_class: safety_life|equipment|downtime|data_loss
```

### 7.4 Kafka Topics (31 total)

**Core Pipeline (9):** alerts.raw, alerts.normalized, incidents.enriched, actions.pending, audit.events, jobs.llm.priority.{critical,high,normal,low}

**CTEM Sources (6):** ctem.raw.{wiz,snyk,garak,art,burp,custom}, ctem.normalized

**Knowledge (6):** knowledge.{mitre.updated, ti.ioc.new, ti.report.new, playbook.updated, incident.stored, fp.approved}

**DLQ (8+):** alerts.raw.dlq, ctem.normalized.dlq, jobs.llm.priority.*.dlq

---

## 8. Security Architecture

### 8.1 Authentication

| Layer | Method | Implementation |
|-------|--------|---------------|
| External (API) | OIDC/JWT | `shared/auth/oidc.py` — RS256 via JWKS endpoint |
| Inter-service | mTLS | `shared/auth/mtls.py` — TLS 1.3 mutual auth |

### 8.2 LLM Safety

| Control | Description | File |
|---------|-------------|------|
| Injection Detection | 14+ regex patterns for jailbreak/role-change | `injection_detector.py` |
| LLM-as-Judge | Haiku second opinion on suspicious inputs | `injection_classifier.py` |
| PII Redaction | Reversible anonymisation (IP_SRC_001, USER_001) | `pii_redactor.py` |
| Output Validation | Schema check + technique ID quarantine | `output_validator.py` |
| Deny-by-Default | Unknown technique IDs stripped, not passed | `gateway.py` |
| Spend Guard | $500 soft / $1000 hard monthly cap | `spend_guard.py` |
| Executor Constraints | Allowlist playbooks, confidence floors | `executor_constraints.py` |

### 8.3 Audit Trail

- **Immutable**: PostgreSQL trigger blocks UPDATE/DELETE
- **Hash Chain**: Per-tenant `sequence_number` + `previous_hash` = tamper-evident
- **Partitioned**: Monthly partitions (range on timestamp)
- **44 Event Types**: Decision, action, approval, security, system
- **Verification**: Daily full + weekly cold chain integrity checks
- **Compliance**: SOC 2 CC6.8 control

---

## 9. Monitoring & Alerting

### 9.1 Critical Alerts

| Alert | Threshold | Severity |
|-------|-----------|----------|
| LLM Circuit Breaker Open | state == open | CRITICAL |
| Kafka Consumer Lag | >10,000 (5m) | CRITICAL |
| Investigation Stuck | awaiting_human >3h | CRITICAL |
| Monthly Spend Hard Cap | >$1,000 | CRITICAL |
| Audit Chain Broken | chain_valid == 0 | CRITICAL |
| Audit Integrity Failed | daily full check fails | CRITICAL |

### 9.2 Health Probes

All services expose `/health` (liveness) and `/ready` (readiness) with dependency checks for: PostgreSQL, Redis, Kafka, Qdrant, Neo4j.

---

## 10. Development Setup

```bash
# Prerequisites: Python >=3.12, Docker, Docker Compose

# Install
pip install -e ".[dev]"

# Start infrastructure
docker-compose up -d  # PG, Redis, Qdrant, Neo4j, Kafka, MinIO

# Initialize databases
python infra/scripts/create_kafka_topics.py
python infra/scripts/init_neo4j.py
python infra/scripts/init_qdrant.py
# SQL migrations auto-run via docker-entrypoint-initdb.d

# Test (requires PG + Redis running)
python -m pytest tests/ --cov=shared --cov-fail-under=90 -v

# CI/CD: GitHub Actions → GHCR (8-service matrix build)
```

---

## 11. Known Gaps

| Gap | Impact | Recommendation |
|-----|--------|---------------|
| No root `Dockerfile` | CI references `./Dockerfile` but file not committed | Create multi-stage Dockerfile with SERVICE build arg |
| No project-level `README.md` | Onboarding friction | Generate from this architecture reference |
| No `Makefile` | Repeated manual commands | Add common targets (dev, test, lint, build) |
| No `CONTRIBUTING.md` | Contribution process unclear | Document PR process, code style, test requirements |
| Audit service not in docker-compose | Can't run audit locally | Add audit-service to docker-compose services profile |

---

## 12. Cross-References

| Document | Path | Relationship |
|----------|------|-------------|
| Architecture (design-time) | `docs/architecture.md` | Design intent, complements this implementation reference |
| AI System Design | `docs/ai-system-design.md` | Agent reasoning architecture |
| Data Pipeline | `docs/data-pipeline.md` | Ingestion/enrichment flow design |
| ATLAS Integration | `docs/atlas-integration.md` | MITRE ATT&CK/ATLAS detection layer |
| CTEM Integration | `docs/ctem-integration.md` | CTEM program integration design |
| RAG Design | `docs/rag-design.md` | Vector search and knowledge base |
| Audit Architecture | `docs/audit-architecture.md` | Immutable audit trail design |
| Testing Requirements | `docs/testing-requirements.md` | Test plan (T1-T12) |
| Runbook | `docs/runbook.md` | Operational procedures |
| Provider Outage Playbook | `docs/provider-outage-playbook.md` | LLM degradation procedures |
| Source Tree Analysis | `docs/source-tree-analysis.md` | Annotated directory structure |
