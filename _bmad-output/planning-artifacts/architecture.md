---
stepsCompleted: [1, 2, 3, 4, 5, 6, 7, 8]
inputDocuments:
  - "docs/prd.md"
  - "docs/architecture.md"
  - "docs/ai-system-design.md"
  - "docs/inference-optimization.md"
  - "docs/rag-design.md"
  - "docs/data-pipeline.md"
  - "docs/atlas-integration.md"
  - "docs/ctem-integration.md"
workflowType: 'architecture'
project_name: 'ALUSKORT'
user_name: 'd8rh8r'
date: '2026-02-14'
lastStep: 8
status: 'complete'
completedAt: '2026-02-14'
---

# ALUSKORT Architecture Planning Artifact

## 1. Project Context Analysis

### 1.1 Requirements Overview

ALUSKORT is a cloud-neutral security reasoning and orchestration control plane that replaces the L1-L3 SOC analyst workflow. It triages alerts, investigates incidents, hunts threats proactively, and executes response actions with human approval gates on all destructive operations.

**Functional requirements:** 44 FRs across 8 domains:

- **FR-ING-001 to FR-ING-008** -- Alert ingestion from multiple SIEM/XDR sources via adapter pattern, canonical normalisation, Kafka topic routing, priority queues with per-severity concurrency limits.
- **FR-ENR-001 to FR-ENR-007** -- Entity extraction and enrichment: structured entity parsing, source-aware parsing, IOC validation, Redis exact-match lookup, UEBA/risk context, CTEM exposure correlation, TI semantic search.
- **FR-RSN-001 to FR-RSN-007** -- LLM-powered reasoning: multi-hop investigation, ATT&CK/ATLAS mapping, attack path analysis via Neo4j, time-decayed incident memory scoring, confidence scoring with escalation, FP short-circuit, GraphState persistence.
- **FR-RSP-001 to FR-RSP-006** -- Response and remediation: three remediation tiers, mandatory human approval for destructive actions, 4-hour timeout on approval gates, immutable audit trail, playbook selection, confidence thresholds.
- **FR-RAG-001 to FR-RAG-008** -- Knowledge base and RAG: split retrieval across four stores, five knowledge domains, MITRE technique storage, TI report chunking, FP pattern store, vendor-neutral embeddings, playbook auto-generation, token budget enforcement.
- **FR-ATL-001 to FR-ATL-006** -- ATLAS threat model: 17 TM-IDs via 10 detection rules, Postgres telemetry tables, scheduled detection frequencies, exact statistical thresholds, cross-framework correlation, self-protection with confidence floors.
- **FR-CTM-001 to FR-CTM-008** -- CTEM integration: 5-phase pipeline, multi-source ingestion, per-tool normalisation, consequence-weighted scoring, Neo4j graph traversal, SLA enforcement, idempotent upsert, auto-discovery.
- **FR-CSM-001 to FR-CSM-004** -- Case management: investigation timeline, analyst UI, immutable audit events, analyst feedback loop.

**Non-functional requirements:** 28 NFRs across 6 domains:

- **NFR-PRF-001 to NFR-PRF-008** -- Performance: pipeline latency targets, per-tier LLM latency budgets, 2,000 alerts/day throughput, sub-millisecond Redis IOC lookup.
- **NFR-SEC-001 to NFR-SEC-008** -- Security: Context Gateway enforcement, injection detection, safety prompt prefix, output validation, role-based agent permissions, accumulation guards, parameterised SQL, entity sanitisation.
- **NFR-REL-001 to NFR-REL-007** -- Reliability: 5-level degradation strategy, Kafka retention, deterministic fallback, Vector DB fallback, Neo4j fallback, Kubernetes HA, exponential backoff retry.
- **NFR-SCL-001 to NFR-SCL-004** -- Scalability: multi-tenant ready, horizontal scaling via Kubernetes, configurable per-tenant quotas, sub-10 GB/day per tenant.
- **NFR-OBS-001 to NFR-OBS-005** -- Observability: Prometheus metrics, per-task LLM tracking, cost dashboard, CTEM staleness flags, UEBA freshness monitoring.
- **NFR-CMP-001 to NFR-CMP-004** -- Compliance: immutable audit trail, incident memory partitioning, FP pattern approval lifecycle, CTEM remediation tracking.

### 1.2 Scale Assessment

- **Target:** Small SOC deployment, median 1,200 alerts/day, capacity for 2,000 alerts/day.
- **LLM volume:** ~960 Tier 0 (Haiku), ~180 Tier 1 (Sonnet), <1% Tier 1+ (Opus), ~60 Tier 2 (Batch) per day.
- **Monthly API cost:** $250-$400 with prompt caching (~$277/month optimised).
- **Infrastructure:** ~7.5 vCPU, ~13 GB RAM total. No GPU nodes required.
- **Data volume:** < 10 GB/day per tenant.

### 1.3 Technical Constraints

- Internet connectivity required for Anthropic API calls.
- Anthropic API availability is an external dependency; mitigated by 5-level degradation strategy.
- Single tenant initially; multi-tenant architecture designed but deferred.
- English-only processing in v1.
- CPU-only Kubernetes cluster; no GPU, no model serving, no VRAM.
- Embedding model version pinned in config; quarterly MITRE re-indexing.

---

## 2. Starter Template Evaluation

**Not applicable.** ALUSKORT is a custom microservices system, not built on a framework starter template.

### 2.1 Technology Choices

| Component | Technology | Version |
|---|---|---|
| Language | Python | 3.12+ |
| Web Framework | FastAPI | 0.110+ |
| Orchestration | LangGraph | 0.1+ |
| LLM Provider | Anthropic Claude API | Haiku 4.5 / Sonnet 4.5 / Opus 4 |
| LLM SDK | anthropic | >= 0.40.0 |
| Message Bus | Kafka / Redpanda | 3.6+ / 23.3+ |
| Kafka Client | confluent-kafka | >= 2.3.0 |
| Relational DB | PostgreSQL | 16+ |
| DB Driver | asyncpg | >= 0.29.0 |
| Vector DB | Qdrant | 1.8+ |
| Vector Client | qdrant-client | >= 1.8.0 |
| Cache | Redis | 7+ |
| Cache Client | redis[hiredis] | >= 5.0.0 |
| Graph DB | Neo4j | 5.x |
| Graph Client | neo4j | >= 5.17.0 |
| Object Store | S3 / MinIO | -- |
| Container Runtime | Docker | 24+ |
| Container Orchestration | Kubernetes | 1.28+ |
| CI/CD | GitHub Actions | -- |
| Auth | OIDC / mTLS / API Keys | python-jose, cryptography |
| Serialisation | Pydantic | >= 2.6.0 |
| Embeddings | Configurable (OpenAI / Cohere / sentence-transformers) | 1024 dimensions |

---

## 3. Core Architectural Decisions

### 3.1 Data Layer -- Split by Purpose

Each storage technology handles a specific query pattern. No single store does multiple jobs.

| Store | Purpose | Query Pattern |
|---|---|---|
| **PostgreSQL** | Incidents, alerts, exposures, UEBA, playbooks, investigation state, taxonomy IDs, ATLAS telemetry, CTEM records | Structured queries, JOINs, ON CONFLICT upserts |
| **Qdrant** | Semantic retrieval: past incidents, ATT&CK/ATLAS descriptions, playbooks, TI reports | Cosine similarity, top-k with metadata filtering |
| **Redis** | IOC exact match, FP pattern hot cache, rate limit counters | O(1) key-value lookup, LRU/TTL eviction |
| **Neo4j** | Asset/zone graph for consequence reasoning | Graph traversal, N-hop consequence paths |
| **S3/MinIO** | Raw alert payloads, TI report PDFs, forensic artifacts | Bulk read/write, lifecycle policies |

Reference: `docs/ai-system-design.md` Section 5, `docs/rag-design.md` Section 1.

### 3.2 Authentication and Authorisation

- **Service-to-service:** mTLS within the Kubernetes cluster (Istio/Linkerd or manual cert management via `shared/auth/mtls.py`).
- **Analyst UI:** OIDC via any IdP (Entra ID, Okta, Keycloak). JWT validation at API gateway.
- **Anthropic API:** API key stored in Kubernetes Secret, held exclusively by Context Gateway. Rotation every 90 days. Spend limits: hard cap $1,000/month.
- **Agent permissions:** Role-based per agent (IOC Extractor: QUERY_DATA + CALL_LLM; Context Enricher adds QUERY_GRAPH; Reasoning Agent adds ANALYSE + COMMENT_INCIDENT; Response Agent adds UPDATE_INCIDENT + EXECUTE_PLAYBOOK).

Reference: `docs/ai-system-design.md` Section 10, `docs/architecture.md` Section 7.

### 3.3 API Design

- **Internal REST (FastAPI):** Context Gateway exposes `/v1/llm/complete` and `/v1/llm/stream`. LLM Router exposes `/v1/route` and `/v1/route/record`. All services expose `/health`, `/ready`, `/metrics`.
- **Inter-service messaging:** Kafka topics for async pipeline flow. Topic naming: dot-notation (`alerts.raw`, `jobs.llm.priority.critical`, `ctem.raw.wiz`).
- **External integrations:** SIEM adapters consume from source-native protocols (Event Hub, webhooks, polling) and produce to Kafka `alerts.raw`.

Reference: `docs/architecture.md` Section 4.3.

### 3.4 LLM Strategy -- Anthropic-Only, 4-Tier Routing

| Tier | Model | Model ID | Use Cases | Latency Budget |
|---|---|---|---|---|
| Tier 0 | Haiku 4.5 | claude-haiku-4-5-20251001 | IOC extraction, classification, FP check | < 3s |
| Tier 1 | Sonnet 4.5 | claude-sonnet-4-5-20250929 | Investigation, CTEM correlation, ATLAS reasoning | < 30s |
| Tier 1+ | Opus 4 | claude-opus-4-6 | Low-confidence critical escalation | < 60s |
| Tier 2 | Sonnet 4.5 Batch | claude-sonnet-4-5-20250929 | FP generation, playbook creation, offline analysis | 24h SLA |

**Routing overrides:** Critical severity forces Tier 1 minimum. Confidence < 0.6 on critical/high escalates to Opus. Time budget < 3s forces Tier 0. Context > 100K tokens forces Tier 1.

**API features used:** Prompt caching (5-min lifetime, 90% cost reduction), tool use, extended thinking (Tier 1/1+), streaming (Tier 1), Batch API (Tier 2, 50% discount).

Reference: `docs/inference-optimization.md` Sections 1-3, `docs/ai-system-design.md` Section 3.

### 3.5 Orchestration -- LangGraph State Machine

Investigation workflow modelled as an explicit graph with `GraphState` persisted to Postgres:

```
RECEIVED --> PARSING (IOC Extractor)
  PARSING --> ENRICHING (Context Enricher)
           |-> CLOSED (FP pattern short-circuit)
  ENRICHING --> REASONING (Reasoning Agent)
             + parallel: [CTEM Correlator, ATLAS Mapper]
  REASONING --> RESPONDING (auto-closeable)
             |-> AWAITING_HUMAN (needs approval)
  AWAITING_HUMAN --> RESPONDING (on approve)
                  |-> CLOSED (on reject / 4-hour timeout)
  RESPONDING --> CLOSED (Response Agent)
```

Each node is an agent role. State transitions are explicit, persisted, and replayable.

Reference: `docs/ai-system-design.md` Section 4.1.

### 3.6 No Frontend Framework (API-Only Initially)

Layer 5 (Analyst UI) is deferred to v1.2+. All v1.0 interaction is via API endpoints, Kafka topics, and notification channels (Teams, Slack, PagerDuty). The system is API-first.

### 3.7 Infrastructure -- Kubernetes, Docker, GitHub Actions

- **Deployment:** Kubernetes with namespace `aluskort`. Each pipeline stage as independent Deployment.
- **Local dev:** Docker Compose with Redpanda, Postgres, Qdrant, Redis, Neo4j, MinIO.
- **CI/CD:** GitHub Actions with unit tests, contract tests, integration tests, Docker image builds.
- **No GPU nodes required.** All LLM inference via Anthropic API over HTTPS.

Reference: `docs/architecture.md` Sections 6, 9.

---

## 4. Implementation Patterns and Consistency Rules

### 4.1 Adapter Pattern for All Integrations

Every SIEM/XDR/CTEM source implements the `IngestAdapter` ABC with `source_name()`, `subscribe()`, and `to_canonical()` methods. Source-specific SDKs are confined to the adapter only -- the core never imports Azure SDK, Elastic SDK, etc.

Reference: `docs/ai-system-design.md` Section 6.2.

### 4.2 Canonical Schemas (Pydantic v2)

All inter-service data contracts use Pydantic v2 models in `shared/schemas/`:

- `CanonicalAlert` -- ingested alert representation
- `AlertEntities` / `NormalizedEntity` -- parsed entity output
- `GraphState` / `InvestigationState` -- investigation state machine
- `IncidentScore` -- time-decayed incident ranking
- `RiskSignal` / `RiskState` -- UEBA risk context
- `GatewayRequest` / `GatewayResponse` -- LLM interface
- `RoutingDecision` / `TaskContext` / `ModelTier` -- routing interface

Reference: `docs/architecture.md` Section 4.1.

### 4.3 Kafka Topic Naming Conventions

- Dot-notation: `{domain}.{subdomain}` (e.g., `alerts.raw`, `ctem.raw.wiz`, `jobs.llm.priority.critical`)
- Core pipeline: `alerts.raw`, `alerts.normalized`, `incidents.enriched`
- Priority queues: `jobs.llm.priority.{critical,high,normal,low}`
- CTEM sources: `ctem.raw.{wiz,snyk,garak,art,burp,custom,validation,remediation}`
- Knowledge events: `knowledge.{domain}.{event}` (e.g., `knowledge.mitre.updated`, `knowledge.fp.approved`)
- ATLAS telemetry: `telemetry.{source}.{type}` (e.g., `telemetry.orbital.inference`)
- Audit: `audit.events` (immutable, 90-day retention)

Reference: `docs/architecture.md` Section 4.2.

### 4.4 Error Handling -- Structured Exceptions with Audit Trail

- **Retry policies:** Anthropic API: 3 retries, exponential backoff (1s, 2s, 4s). Kafka produce: 5 retries (librdkafka built-in). Postgres: 3 retries (0.5s, 1s, 2s). Qdrant: 2 retries (1s). Redis: fail-open (no cache).
- **Circuit breakers:** Anthropic: 5 failures/1min -> open 30s. Vector DB: 3/1min -> 15s. Neo4j: 3/1min -> 15s. Redis: 3/1min -> 10s.
- **Dead letter queues:** `alerts.raw.dlq`, `jobs.llm.priority.*.dlq`, `ctem.normalized.dlq`. DLQ messages include original payload + error details.
- **5-level degradation:** Full Capability -> Deterministic Only (LLM down) -> Structured Search (Vector DB down) -> Static Consequence (Graph DB down) -> Passthrough (everything down).

Reference: `docs/architecture.md` Section 8, `docs/ai-system-design.md` Section 11.

### 4.5 Async Everywhere

- All database access via async drivers: `asyncpg` (Postgres), async `qdrant-client`, `redis.asyncio`.
- Kafka consumers use the confluent-kafka consumer with manual offset commits.
- FastAPI endpoints are async.
- Anthropic SDK uses `anthropic.AsyncAnthropic`.
- Parallel enrichment during `ENRICHING` state: Redis IOC + Postgres UEBA + Qdrant similar incidents + CTEM correlation + ATLAS mapping run concurrently via `asyncio.gather`.

### 4.6 Naming Conventions

| Context | Convention | Examples |
|---|---|---|
| Python modules/variables | snake_case | `entity_parser`, `graph_state`, `ioc_matches` |
| Python classes | PascalCase | `CanonicalAlert`, `ContextGateway`, `LLMRouter` |
| Kubernetes services/deployments | kebab-case | `entity-parser`, `context-gateway`, `llm-router` |
| Kafka topics | dot-notation | `alerts.raw`, `jobs.llm.priority.critical` |
| Docker images | kebab-case | `aluskort/entity-parser`, `aluskort/context-gateway` |
| Redis keys | colon-separated | `ioc:ipv4:10.0.0.1`, `fp:hot:pat-001` |
| Postgres tables | snake_case | `ctem_exposures`, `incident_memory`, `mitre_techniques` |
| Neo4j nodes | PascalCase labels | `:Asset`, `:Zone`, `:Model`, `:Finding` |

---

## 5. Project Structure

Full directory tree from `docs/ai-system-design.md` Section 14:

```
aluskort/
+-- services/
|   +-- entity_parser/          # Dedicated entity extraction service
|   |   +-- parser.py           # Structured + regex + ML-assisted extraction
|   |   +-- validators.py       # Input validation and sanitisation
|   |   +-- tests/
|   |   |   +-- test_sentinel_entities.py
|   |   |   +-- test_elastic_entities.py
|   |   |   +-- test_injection.py
|   |   +-- Dockerfile
|   |
|   +-- ctem_normaliser/        # Per-source CTEM normalisation
|   |   +-- normalisers/
|   |   |   +-- wiz.py, snyk.py, garak.py, art.py
|   |   +-- upsert.py           # Postgres ON CONFLICT upsert
|   |   +-- tests/
|   |   +-- Dockerfile
|   |
|   +-- orchestrator/           # LangGraph-based investigation orchestrator
|   |   +-- graph.py            # Investigation state machine
|   |   +-- agents/
|   |   |   +-- ioc_extractor.py
|   |   |   +-- context_enricher.py
|   |   |   +-- reasoning_agent.py
|   |   |   +-- response_agent.py
|   |   +-- tests/
|   |   +-- Dockerfile
|   |
|   +-- context_gateway/        # Centralised LLM sanitisation
|   |   +-- gateway.py
|   |   +-- injection_detector.py
|   |   +-- output_validator.py
|   |   +-- tests/
|   |   +-- Dockerfile
|   |
|   +-- llm_router/             # Model tier routing
|   |   +-- router.py
|   |   +-- metrics.py
|   |   +-- tests/
|   |   +-- Dockerfile
|   |
|   +-- batch_scheduler/        # Tier 2 batch processing
|   |   +-- scheduler.py
|   |   +-- tests/
|   |   +-- Dockerfile
|   |
|   +-- adapters/               # SIEM/XDR/CTEM ingest adapters
|       +-- sentinel/
|       +-- elastic/
|       +-- splunk/
|       +-- wiz/
|
+-- shared/
|   +-- schemas/                # Canonical schemas (Pydantic v2)
|   |   +-- alert.py            # CanonicalAlert, AlertEntities, NormalizedEntity
|   |   +-- incident.py         # GraphState, InvestigationState, IncidentScore
|   |   +-- exposure.py         # CTEM exposure schemas
|   |   +-- entity.py           # EntityType, RiskSignal, RiskState
|   |   +-- gateway.py          # GatewayRequest, GatewayResponse
|   |   +-- routing.py          # RoutingDecision, TaskContext, ModelTier
|   +-- db/                     # Database client wrappers
|   |   +-- postgres.py         # asyncpg connection pool, query helpers
|   |   +-- vector.py           # Qdrant client wrapper
|   |   +-- redis_cache.py      # Redis IOC cache + FP pattern store
|   |   +-- neo4j_graph.py      # Neo4j driver, consequence queries
|   +-- auth/                   # Platform-neutral auth
|       +-- oidc.py             # OIDC token validation
|       +-- mtls.py             # mTLS certificate management
|
+-- deploy/
|   +-- kubernetes/             # K8s manifests (Deployments, Services, ConfigMaps, Secrets)
|   +-- docker-compose.yml      # Local dev with Redpanda, Postgres, Qdrant, Redis, Neo4j, MinIO
|
+-- docs/
|   +-- ai-system-design.md
|   +-- inference-optimization.md
|   +-- rag-design.md
|   +-- data-pipeline.md
|   +-- atlas-integration.md
|   +-- ctem-integration.md
|   +-- operations.md
|
+-- tests/
|   +-- contract/               # Sample payloads -> canonical output validation
|   |   +-- test_sentinel_contract.py
|   |   +-- test_elastic_contract.py
|   |   +-- test_wiz_contract.py
|   +-- integration/
|   +-- e2e/
|
+-- .github/
    +-- workflows/
        +-- ci.yml              # Unit + contract + integration tests
        +-- deploy.yml          # Docker build + K8s deploy
```

---

## 6. Validation

### 6.1 Architecture Review

This architecture was validated through the Omeriko Critical Review (CR) process. Key validation points:

1. **Cloud neutrality confirmed.** No cloud-specific SDK in core services. All SIEM/CTEM specifics confined to adapters. Deployable on Azure, AWS, GCP, or on-prem Kubernetes.

2. **LLM strategy validated.** 4-tier Anthropic routing with priority queues prevents alert flood attacks. Cost projections validated: $250-$400/month for small SOC (1,200 alerts/day). Prompt caching and batch API reduce costs by ~30%.

3. **Security architecture reviewed.** Context Gateway as single choke point for all LLM traffic. Injection detection (14+ patterns), PII redaction, output validation, safety prompt prefix. Parameterised SQL everywhere. Role-based agent permissions with accumulation guards.

4. **Resilience validated.** 5-level degradation strategy covers all failure modes. Kafka retention ensures no alert loss. Circuit breakers with fallbacks for every external dependency. Dead letter queues for failed processing.

5. **Scalability path confirmed.** Single-tenant v1 with multi-tenant architecture ready. Kafka partitioned by tenant_id. Postgres partitioned by tenant_id + time. Each pipeline stage independently scalable via Kubernetes Deployments.

6. **Data architecture reviewed.** Split retrieval avoids single-store bottleneck. Each store handles its optimal query pattern. Redis for sub-ms exact match, Qdrant for semantic search, Postgres for structured queries, Neo4j for graph traversal.

### 6.2 Build Sequence Validation

The 11-step build sequence (from `docs/architecture.md` Section 10) follows a correct dependency order:

1. **Step 1:** shared/ schemas and DB clients (foundation, no dependencies)
2. **Step 2:** Kafka + DB infrastructure setup (depends on Step 1)
3. **Step 3:** Entity Parser service (depends on Steps 1-2)
4. **Step 4:** Sentinel adapter (depends on Steps 1-3)
5. **Step 5:** Context Gateway (depends on Steps 1-2)
6. **Step 6:** LLM Router (depends on Step 5)
7. **Step 7:** Orchestrator / LangGraph (depends on Steps 1-6)
8. **Step 8:** CTEM Normaliser (depends on Steps 1-2)
9. **Step 9:** ATLAS Detection Rules (depends on Steps 1-2)
10. **Step 10:** Batch Scheduler (depends on Steps 5-6)
11. **Step 11:** Analyst UI (depends on Steps 1-10, deferred)

Steps 3-4 (ingest pipeline) and Steps 5-6 (LLM pipeline) can proceed in parallel. Steps 8-9 (intelligence) and Step 10 (batch) can also proceed in parallel after their dependencies are met.

### 6.3 Requirements Traceability

All 44 FRs and 28 NFRs from the PRD are addressable by the architecture:

- Ingest FRs (FR-ING-*) -> Adapters + Entity Parser + Kafka topics + Priority queues
- Enrichment FRs (FR-ENR-*) -> Entity Parser + Redis + Postgres + Qdrant + CTEM tables
- Reasoning FRs (FR-RSN-*) -> Orchestrator + Context Gateway + LLM Router + Neo4j
- Response FRs (FR-RSP-*) -> Orchestrator Response Agent + Human approval gates + Audit topic
- RAG FRs (FR-RAG-*) -> Split retrieval (Postgres + Qdrant + Redis + S3)
- ATLAS FRs (FR-ATL-*) -> ATLAS detection rules + Postgres telemetry tables
- CTEM FRs (FR-CTM-*) -> CTEM Normaliser + Postgres + Neo4j
- Case FRs (FR-CSM-*) -> Postgres investigation state + Audit topic + (deferred) Analyst UI
- Performance NFRs -> Async architecture + Priority queues + Redis caching
- Security NFRs -> Context Gateway + mTLS + OIDC + Parameterised SQL
- Reliability NFRs -> 5-level degradation + Circuit breakers + DLQs + Kafka retention
- Scalability NFRs -> Kubernetes + Kafka partitioning + Postgres partitioning
- Observability NFRs -> Prometheus metrics + Cost tracking + Staleness monitoring
- Compliance NFRs -> Immutable audit.events + Monthly partitioning + Approval lifecycle

---

*Architecture planning artifact generated for ALUSKORT project, 2026-02-14.*
