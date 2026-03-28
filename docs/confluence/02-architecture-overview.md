# Architecture Overview

## 5-Layer Architecture

ALUSKORT is structured as a 5-layer microservices architecture. Each layer has a clear responsibility boundary and communicates with adjacent layers through well-defined Kafka topics and REST APIs.

```
 Layer 5: PRESENTATION
 +---------------------------------------------------------+
 | Dashboard (FastAPI+HTMX) | WebSocket | REST API         |
 | Port 8080                | /ws/investigations            |
 +---------------------------------------------------------+
        |                          |
        v                          v
 Layer 4: REASONING
 +---------------------------------------------------------+
 | Orchestrator        | Context Gateway  | LLM Router     |
 | (State Machine,     | Port 8030        | Port 8031      |
 |  6 Agents,          | (Sanitise,       | (4-Tier Model  |
 |  FP Short-Circuit)  |  Redact, Validate)|  Routing)      |
 +---------------------------------------------------------+
        |                |                 |
        v                v                 v
 Layer 3: DATA
 +---------------------------------------------------------+
 | PostgreSQL 16 | Redis 7  | Qdrant    | Neo4j 5 | MinIO |
 | Port 5432     | Port 6379| Port 6333 | Port 7687| 9000 |
 | (State, MITRE,| (Cache,  | (Vector   | (Entity  |(Audit|
 |  CTEM, Audit) |  Kill SW)|  Search)  |  Graphs) | Cold)|
 +---------------------------------------------------------+
        ^                ^                 ^
        |                |                 |
 Layer 2: NORMALISATION
 +---------------------------------------------------------+
 | Entity Parser       | CTEM Normaliser  | ATLAS Detection|
 | (IOC/Entity Extract)| (Wiz,Snyk,Garak,| (11 Rules,     |
 |                     |  ART scoring)    |  6 Techniques) |
 +---------------------------------------------------------+
        ^                ^                 ^
        |                |                 |
 Layer 1: INGEST
 +---------------------------------------------------------+
 | Sentinel Adapter | Elastic Adapter | Splunk Adapter     |
 | (Microsoft       | (Elastic SIEM)  | (Splunk ES)        |
 |  Sentinel)       |                 |                     |
 +-------------------+-----------------+-------------------+
 | Kafka / Redpanda  (31 topics, 4 categories)             |
 | Port 9092                                                |
 +---------------------------------------------------------+
```

---

## Component Interaction Diagram

```
                    +-------------+
                    |  SIEM       |
                    | (Sentinel/  |
                    |  Elastic/   |
                    |  Splunk)    |
                    +------+------+
                           |
                    alerts.raw (Kafka)
                           |
                    +------v------+
                    | Entity      |
                    | Parser      |
                    +------+------+
                           |
                  alerts.normalized (Kafka)
                           |
                    +------v------+
                    | Orchestrator|
                    | (Graph FSM) |
                    +------+------+
                           |
              +------------+------------+
              |            |            |
        +-----v----+ +----v-----+ +---v--------+
        | Context  | | CTEM     | | ATLAS      |
        | Enricher | | Correlator| | Mapper    |
        +-----+----+ +----+-----+ +---+--------+
              |            |            |
              +------------+------------+
                           |
                    +------v------+
                    | Reasoning   |-----> Context Gateway
                    | Agent       |       (sanitise+LLM+validate)
                    +------+------+           |
                           |            +-----v-----+
                    +------v------+     | LLM Router|
                    | Response    |     | (Tier 0-2)|
                    | Agent       |     +-----------+
                    +------+------+
                           |
              +------------+------------+
              |                         |
       auto-respond            AWAITING_HUMAN
       (CLOSED)                (Dashboard approval)
```

---

## Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| Relational DB | PostgreSQL | 16-alpine | Investigation state, MITRE data, CTEM exposures, audit records, FP patterns |
| Cache / Kill Switch | Redis | 7-alpine | Caching, kill switch state, session data, rate limiting |
| Vector Store | Qdrant | latest | Semantic similarity search for incidents, IOCs, playbooks |
| Graph Database | Neo4j | 5-community | Entity relationship graphs, attack path analysis |
| Message Broker | Redpanda | latest | Kafka-compatible event streaming (31 topics) |
| Object Storage | MinIO | latest | Audit evidence cold storage, S3-compatible |
| Language | Python | 3.12 | All services |
| Web Framework | FastAPI | latest | REST APIs and Dashboard |
| Frontend | HTMX + Jinja2 | latest | Server-rendered reactive dashboard |
| LLM Provider (Primary) | Anthropic | Claude Haiku/Sonnet/Opus | Tiered reasoning (Tier 0/1/1+/2) |
| LLM Provider (Fallback) | OpenAI | GPT-4o / GPT-4o-mini | Health-aware fallback |
| Embeddings | OpenAI | text-embedding-3-small | 1536-dimension vectors for similarity |
| Container Runtime | Docker / Docker Compose | 3.9 | Local development |
| Container Orchestration | Kubernetes | latest | Production deployment |

---

## Data Flow: Alert Lifecycle

### 1. Ingestion
A SIEM adapter (Sentinel, Elastic, or Splunk) polls or receives alerts and publishes raw payloads to the `alerts.raw` Kafka topic.

### 2. Entity Parsing
The Entity Parser consumes `alerts.raw`, extracts structured entities (IPs, hosts, accounts, file hashes, URLs, etc.), normalises them into a `CanonicalAlert` schema, and publishes to `alerts.normalized`.

### 3. Investigation Orchestration
The Orchestrator consumes `alerts.normalized` and creates a `GraphState` object that flows through the state machine:

1. **RECEIVED** -- Alert received, investigation created
2. **PARSING** -- IOC Extractor runs, extracts indicators
3. **FP_CHECK** -- FP Short-Circuit checks against known patterns
   - If matched: auto-close (CLOSED), emit `alert.auto_closed` audit event
4. **ENRICHING** -- Three agents run in parallel:
   - Context Enricher (UEBA, IOC matching, similar incidents)
   - CTEM Correlator (exposure matching, consequence scoring)
   - ATLAS Mapper (adversarial AI technique mapping)
5. **REASONING** -- Reasoning Agent analyses all evidence, classifies the alert
6. **AWAITING_HUMAN** or **RESPONDING** -- Based on confidence and severity
7. **CLOSED** -- Investigation complete

### 4. LLM Interaction
Every LLM call flows through the Context Gateway pipeline:
`sanitise -> classify -> transform -> redact PII -> build prompt -> call LLM -> validate output -> strip quarantined IDs -> deanonymise`

### 5. Human Approval
High-severity or low-confidence investigations land in the AWAITING_HUMAN state. Analysts approve or reject via the Dashboard. Severity-aware timeout behaviour escalates critical/high alerts rather than auto-closing them.

### 6. Response Execution
Approved actions are executed by the Response Agent, and the investigation transitions to CLOSED with a full audit trail.

---

## Deployment Architecture

### Development (Docker Compose)

All infrastructure and application services run via `docker-compose.yml`:

- **Infrastructure services**: kafka, postgres, redis, qdrant, neo4j, minio (always running)
- **Application services**: entity-parser, context-gateway, llm-router, orchestrator, ctem-normaliser, dashboard (profile: `services`)

```bash
# Start infrastructure only
docker compose up -d

# Start everything including app services
docker compose --profile services up -d
```

### Production (Kubernetes)

Kubernetes manifests in `infra/k8s/`:

| Manifest | Purpose |
|----------|---------|
| `namespace.yaml` | `aluskort` namespace |
| `configmap.yaml` | Shared configuration (Kafka, Redis, Qdrant, Neo4j endpoints) |
| `secrets.yaml` | API keys, database credentials |
| `deployments.yaml` | 8 Deployment resources with health probes |
| `services.yaml` | ClusterIP services for inter-service communication |

---

## Service Catalogue Summary

| # | Service | Purpose | Port | Health Endpoint |
|---|---------|---------|------|-----------------|
| 1 | Entity Parser | Extract and normalise entities from raw alerts | -- (Kafka consumer) | `/health` |
| 2 | Orchestrator | State machine execution, investigation lifecycle | -- (Kafka consumer) | `/health` |
| 3 | Context Gateway | LLM sanitisation, PII redaction, output validation | 8030 | `/health` |
| 4 | LLM Router | 4-tier model selection, fallback routing | 8031 | `/health` |
| 5 | CTEM Normaliser | Normalise vulnerability/exposure data from scanners | -- (Kafka consumer) | `/health` |
| 6 | Dashboard | Analyst web UI (HTMX) | 8080 | `/health` |
| 7 | Audit Service | Hash-chain audit trail, evidence packaging | -- (Kafka consumer) | `/health` |
| 8 | Batch Scheduler | Offline LLM jobs (FP training, retrospectives) | -- (scheduled) | `/health` |
| 9 | SIEM Adapters | Sentinel, Elastic, Splunk connectors | -- (pollers) | `/health` |
| -- | Shared Libraries | `shared/` -- schemas, DB clients, auth, adapters | -- | -- |
